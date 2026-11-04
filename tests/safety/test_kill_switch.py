"""Tests for Global Kill Switch."""

from pathlib import Path
import pytest
from backend.safety.kill_switch import KillSwitch, KillSwitchTrippedError


def test_kill_switch_lifecycle(tmp_path: Path) -> None:
    trigger_file = tmp_path / ".test_kill"
    ks = KillSwitch(trigger_file=trigger_file)

    assert not ks.is_tripped()
    ks.check_or_raise()

    # Trip switch
    ks.trip("Emergency stop due to target latency spike")
    assert ks.is_tripped()
    assert trigger_file.exists()
    assert "latency spike" in trigger_file.read_text(encoding="utf-8")

    with pytest.raises(KillSwitchTrippedError) as exc_info:
        ks.check_or_raise()
    assert "latency spike" in str(exc_info.value)

    # Reset switch
    ks.reset()
    assert not ks.is_tripped()
    assert not trigger_file.exists()
    ks.check_or_raise()


def test_kill_switch_detects_disk_file(tmp_path: Path) -> None:
    trigger_file = tmp_path / ".external_kill"
    trigger_file.write_text("External operator halt", encoding="utf-8")

    ks = KillSwitch(trigger_file=trigger_file)
    assert ks.is_tripped()
    assert "External operator halt" in (ks.get_trip_reason() or "")

    with pytest.raises(KillSwitchTrippedError):
        ks.check_or_raise()
