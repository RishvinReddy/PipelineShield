"""Shared pytest fixtures and configuration.

This file is automatically loaded by pytest for all tests in the engine/tests directory.
"""

from pathlib import Path
import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PROJECT_ROOT = Path(__file__).parent.parent.parent


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Return the fixtures directory path."""
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def root_policy_path() -> Path:
    """Return the root config/policy.yaml path."""
    return PROJECT_ROOT / "config" / "policy.yaml"
