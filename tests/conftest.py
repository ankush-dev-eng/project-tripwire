"""Pytest Configuration and Global Fixtures."""

import pytest

from backend.safety.kill_switch import KillSwitch


@pytest.fixture(autouse=True)
def reset_global_safety_state() -> None:
    """Reset singleton kill switch state before and after every test."""
    ks = KillSwitch.get_instance()
    ks.reset()
    yield
    ks.reset()
