"""Policy configuration loader and validator.

Uses yaml.safe_load exclusively — never yaml.load.
Rejects invalid configurations with actionable error messages.
Never silently defaults to unsafe values.
"""

from pathlib import Path
from typing import Union

import yaml
from pydantic import ValidationError

from pipelineshield.models import (
    EnforcementMode,
    GateDecision,
    PolicyConfig,
    PolicyExemptions,
    PolicyThresholds,
    ScannerConfig,
    ScannersConfig,
)

# Valid top-level YAML keys — unknown keys are rejected to prevent misconfiguration
_KNOWN_TOP_LEVEL_KEYS = frozenset(
    {"version", "metadata", "enforcement", "thresholds", "scanners", "exemptions"}
)
_KNOWN_ENFORCEMENT_KEYS = frozenset({"mode", "fail_on_block", "fail_on_warn"})
_KNOWN_THRESHOLD_KEYS = frozenset({"critical", "high", "medium", "low", "info"})
_KNOWN_EXEMPTION_KEYS = frozenset({"findings", "paths"})


def _reject_unknown_keys(data: dict, known: frozenset, context: str) -> None:
    """Raise ValueError for any key not in the known set."""
    unknown = set(data.keys()) - known
    if unknown:
        raise ValueError(
            f"Unknown configuration keys in '{context}': {sorted(unknown)}. "
            f"Expected keys: {sorted(known)}"
        )


def load_policy(path: Union[str, Path]) -> PolicyConfig:
    """Load and validate policy configuration from a YAML file.

    Args:
        path: Filepath to policy YAML file.

    Returns:
        Validated PolicyConfig instance.

    Raises:
        FileNotFoundError: If the policy file does not exist.
        ValueError: If YAML syntax is invalid, schema fails validation,
                    unknown keys are present, or values are out of range.
        TypeError: If the YAML document root is not a mapping.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Policy file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML syntax in policy file '{file_path}': {e}") from e

    if data is None:
        raise ValueError(f"Policy file '{file_path}' is empty.")
    if not isinstance(data, dict):
        raise TypeError(
            f"Policy file '{file_path}' must be a YAML mapping at its root. "
            f"Got: {type(data).__name__}"
        )

    # Reject unknown top-level keys
    _reject_unknown_keys(data, _KNOWN_TOP_LEVEL_KEYS, "policy root")

    # --- enforcement ---
    enforcement = data.get("enforcement", {})
    if not isinstance(enforcement, dict):
        raise TypeError("'enforcement' must be a YAML mapping.")
    _reject_unknown_keys(enforcement, _KNOWN_ENFORCEMENT_KEYS, "enforcement")

    raw_mode = enforcement.get("mode", EnforcementMode.STRICT.value)
    fail_on_block = enforcement.get("fail_on_block", True)
    fail_on_warn = enforcement.get("fail_on_warn", False)

    if not isinstance(fail_on_block, bool):
        raise TypeError(f"'enforcement.fail_on_block' must be a boolean. Got: {type(fail_on_block).__name__}")
    if not isinstance(fail_on_warn, bool):
        raise TypeError(f"'enforcement.fail_on_warn' must be a boolean. Got: {type(fail_on_warn).__name__}")

    # --- thresholds ---
    raw_thresholds = data.get("thresholds", {})
    if not isinstance(raw_thresholds, dict):
        raise TypeError("'thresholds' must be a YAML mapping.")
    _reject_unknown_keys(raw_thresholds, _KNOWN_THRESHOLD_KEYS, "thresholds")

    parsed_thresholds: dict = {}
    for key, val in raw_thresholds.items():
        if not isinstance(val, str):
            raise TypeError(
                f"'thresholds.{key}' must be a string (BLOCK, WARN, or PASS). "
                f"Got: {type(val).__name__}"
            )
        upper = val.strip().upper()
        if upper not in {d.value for d in GateDecision}:
            raise ValueError(
                f"'thresholds.{key}' has invalid value '{val}'. "
                f"Must be one of: BLOCK, WARN, PASS."
            )
        parsed_thresholds[key.lower()] = upper

    # --- scanners ---
    raw_scanners = data.get("scanners", {})
    if not isinstance(raw_scanners, dict):
        raise TypeError("'scanners' must be a YAML mapping.")

    _KNOWN_SCANNERS = frozenset({"trivy", "semgrep", "dependency_review"})
    _reject_unknown_keys(raw_scanners, _KNOWN_SCANNERS, "scanners")

    for s_name, s_val in raw_scanners.items():
        if s_val is not None and not isinstance(s_val, dict):
            raise TypeError(f"'scanners.{s_name}' must be a YAML mapping.")

    try:
        scanners_obj = ScannersConfig.model_validate(raw_scanners)
    except ValidationError as e:
        raise ValueError(f"Invalid scanner configuration: {e}") from e

    # --- exemptions ---
    raw_exemptions = data.get("exemptions", {})
    if not isinstance(raw_exemptions, dict):
        raise TypeError("'exemptions' must be a YAML mapping.")
    _reject_unknown_keys(raw_exemptions, _KNOWN_EXEMPTION_KEYS, "exemptions")

    # --- assemble and validate ---
    try:
        thresholds_obj = PolicyThresholds.model_validate(parsed_thresholds)
    except ValidationError as e:
        raise ValueError(f"Invalid threshold configuration: {e}") from e

    try:
        exemptions_obj = PolicyExemptions.model_validate(raw_exemptions)
    except ValidationError as e:
        raise ValueError(f"Invalid exemptions configuration: {e}") from e

    try:
        return PolicyConfig(
            version=str(data.get("version", "1.0")),
            metadata=dict(data.get("metadata") or {}),
            mode=raw_mode,
            fail_on_block=fail_on_block,
            fail_on_warn=fail_on_warn,
            thresholds=thresholds_obj,
            scanners=scanners_obj,
            exemptions=exemptions_obj,
        )
    except (ValidationError, ValueError) as e:
        raise ValueError(f"Policy configuration is invalid: {e}") from e
