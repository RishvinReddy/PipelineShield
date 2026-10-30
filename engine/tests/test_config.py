"""Test loading and validating policy configuration."""

from pathlib import Path
from pipelineshield.config import load_policy
from pipelineshield.models import GateDecision


def test_load_root_policy():
    """Verify config/policy.yaml loads and passes schema validation."""
    root_policy = Path(__file__).resolve().parent.parent.parent / "config" / "policy.yaml"
    assert root_policy.exists(), f"Expected policy at {root_policy}"

    policy = load_policy(root_policy)
    assert policy.version == "1.0"
    assert policy.mode == "strict"
    assert policy.fail_on_block is True
    assert policy.thresholds.critical == GateDecision.BLOCK
    assert policy.thresholds.high == GateDecision.BLOCK
    assert policy.thresholds.medium == GateDecision.WARN
    assert policy.thresholds.low == GateDecision.PASS
