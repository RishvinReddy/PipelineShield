"""Tests for policy configuration loading and validation."""

import textwrap
from pathlib import Path

import pytest

from pipelineshield.config import load_policy
from pipelineshield.models import EnforcementMode, GateDecision, PolicyConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def policy_yaml_path() -> Path:
    """Path to the root config/policy.yaml file."""
    return Path(__file__).resolve().parent.parent.parent / "config" / "policy.yaml"


@pytest.fixture
def write_yaml(tmp_path: Path):
    """Helper to write a YAML file to tmp_path and return its path."""
    def _write(content: str, filename: str = "policy.yaml") -> Path:
        p = tmp_path / filename
        p.write_text(textwrap.dedent(content), encoding="utf-8")
        return p
    return _write


# ---------------------------------------------------------------------------
# Root policy.yaml
# ---------------------------------------------------------------------------

class TestRootPolicy:
    def test_root_policy_loads(self, policy_yaml_path):
        policy = load_policy(policy_yaml_path)
        assert policy.version == "1.0"
        assert policy.mode == EnforcementMode.STRICT
        assert policy.fail_on_block is True
        assert policy.thresholds.critical == GateDecision.BLOCK
        assert policy.thresholds.high == GateDecision.BLOCK
        assert policy.thresholds.medium == GateDecision.WARN
        assert policy.thresholds.low == GateDecision.PASS


# ---------------------------------------------------------------------------
# File-not-found
# ---------------------------------------------------------------------------

class TestFileNotFound:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="Policy file not found"):
            load_policy(tmp_path / "nonexistent.yaml")


# ---------------------------------------------------------------------------
# Invalid YAML syntax
# ---------------------------------------------------------------------------

class TestInvalidYAML:
    def test_invalid_syntax_raises(self, write_yaml):
        path = write_yaml("version: {unclosed bracket")
        with pytest.raises(ValueError, match="Invalid YAML syntax"):
            load_policy(path)

    def test_empty_file_raises(self, write_yaml):
        path = write_yaml("")
        with pytest.raises(ValueError, match="empty"):
            load_policy(path)

    def test_non_mapping_root_raises(self, write_yaml):
        path = write_yaml("- item1\n- item2\n")
        with pytest.raises(TypeError, match="YAML mapping"):
            load_policy(path)


# ---------------------------------------------------------------------------
# Unknown keys
# ---------------------------------------------------------------------------

class TestUnknownKeys:
    def test_unknown_top_level_key_raises(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            rogue_key: this_should_not_be_here
        """)
        with pytest.raises(ValueError, match="Unknown configuration keys"):
            load_policy(path)

    def test_unknown_enforcement_key_raises(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            enforcement:
              mode: strict
              unknown_flag: true
        """)
        with pytest.raises(ValueError, match="Unknown configuration keys"):
            load_policy(path)

    def test_unknown_threshold_key_raises(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            thresholds:
              critical: BLOCK
              ultra: BLOCK
        """)
        with pytest.raises(ValueError, match="Unknown configuration keys"):
            load_policy(path)


# ---------------------------------------------------------------------------
# Invalid modes
# ---------------------------------------------------------------------------

class TestInvalidModes:
    def test_invalid_enforcement_mode_raises(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            enforcement:
              mode: aggressive
        """)
        with pytest.raises(ValueError, match="Invalid enforcement mode"):
            load_policy(path)

    def test_valid_modes(self, write_yaml):
        for mode in ("strict", "permissive", "monitor"):
            content = f"""
                version: "1.0"
                enforcement:
                  mode: {mode}
            """
            path = write_yaml(content)
            policy = load_policy(path)
            assert policy.mode.value == mode


# ---------------------------------------------------------------------------
# Invalid thresholds
# ---------------------------------------------------------------------------

class TestInvalidThresholds:
    def test_invalid_threshold_value_raises(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            thresholds:
              critical: ALLOW
        """)
        with pytest.raises(ValueError, match="invalid value"):
            load_policy(path)

    def test_error_as_threshold_raises(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            thresholds:
              critical: ERROR
        """)
        with pytest.raises(ValueError):
            load_policy(path)

    def test_non_string_threshold_raises(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            thresholds:
              critical: 1
        """)
        with pytest.raises(TypeError, match="must be a string"):
            load_policy(path)


# ---------------------------------------------------------------------------
# Invalid type checks
# ---------------------------------------------------------------------------

class TestTypeChecks:
    def test_non_bool_fail_on_block_raises(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            enforcement:
              mode: strict
              fail_on_block: "yes"
        """)
        with pytest.raises(TypeError, match="fail_on_block"):
            load_policy(path)

    def test_non_bool_fail_on_warn_raises(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            enforcement:
              mode: strict
              fail_on_warn: 1
        """)
        with pytest.raises(TypeError, match="fail_on_warn"):
            load_policy(path)

    def test_non_mapping_scanners_raises(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            scanners:
              - trivy
        """)
        with pytest.raises(TypeError, match="'scanners' must be a YAML mapping"):
            load_policy(path)

    def test_non_mapping_exemptions_raises(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            exemptions: "invalid"
        """)
        with pytest.raises(TypeError, match="'exemptions' must be a YAML mapping"):
            load_policy(path)


# ---------------------------------------------------------------------------
# Valid configurations
# ---------------------------------------------------------------------------

class TestValidConfigurations:
    def test_minimal_valid_policy(self, write_yaml):
        path = write_yaml("""version: "1.0" """)
        policy = load_policy(path)
        assert policy.version == "1.0"
        assert policy.mode == EnforcementMode.STRICT

    def test_permissive_mode_policy(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            enforcement:
              mode: permissive
              fail_on_block: false
        """)
        policy = load_policy(path)
        assert policy.mode == EnforcementMode.PERMISSIVE
        assert policy.fail_on_block is False

    def test_exemptions_load_correctly(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            exemptions:
              findings:
                - CVE-2024-001
              paths:
                - tests/**
        """)
        policy = load_policy(path)
        assert "CVE-2024-001" in policy.exemptions.findings
        assert "tests/**" in policy.exemptions.paths

    def test_scanner_config_loads(self, write_yaml):
        path = write_yaml("""
            version: "1.0"
            scanners:
              trivy:
                enabled: true
        """)
        policy = load_policy(path)
        assert "trivy" in policy.scanners
        assert policy.scanners["trivy"].enabled is True
