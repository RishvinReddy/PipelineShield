"""Policy configuration loader and validator."""

from pathlib import Path
from typing import Union
import yaml

from pipelineshield.models import PolicyConfig


def load_policy(path: Union[str, Path]) -> PolicyConfig:
    """Load and validate policy configuration from a YAML file.

    Args:
        path: Filepath to policy YAML file.

    Returns:
        Validated PolicyConfig instance.

    Raises:
        FileNotFoundError: If the policy file does not exist.
        ValueError: If YAML syntax is invalid or schema fails validation.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Policy file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML syntax in policy file {file_path}: {e}") from e

    # Extract nested sections if present
    enforcement = data.get("enforcement", {})
    thresholds = data.get("thresholds", {})
    scanners = data.get("scanners", {})
    exemptions = data.get("exemptions", {})

    parsed_data = {
        "version": data.get("version", "1.0"),
        "mode": enforcement.get("mode", "strict"),
        "fail_on_block": enforcement.get("fail_on_block", True),
        "fail_on_warn": enforcement.get("fail_on_warn", False),
        "thresholds": {k.lower(): v.upper() for k, v in thresholds.items()},
        "scanners": scanners,
        "exemptions": exemptions,
    }

    return PolicyConfig.model_validate(parsed_data)
