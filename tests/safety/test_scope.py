"""Tests for Scope Allowlist Enforcement and Tampering Detection."""

from pathlib import Path
import pytest
from backend.safety.kill_switch import KillSwitch
from backend.safety.scope import OutOfScopeError, ScopeManager, ScopeTamperingError


def test_allowed_lab_targets() -> None:
    scope = ScopeManager(scope_path="scope.yaml")

    # Allowed targets
    ok, _ = scope.is_in_scope("http://127.0.0.1:8000/api/search")
    assert ok

    ok, _ = scope.is_in_scope("http://localhost:8080/v1/flights")
    assert ok

    scope.check_url_or_raise("http://127.0.0.1:8000/flights/search")


def test_blocked_external_targets() -> None:
    ks = KillSwitch()
    ks.reset()
    scope = ScopeManager(scope_path="scope.yaml", kill_switch=ks)

    # External domain
    ok, reason = scope.is_in_scope("https://example.com/api")
    assert not ok
    assert "not in approved" in reason

    # Out of scope port on localhost
    ok, reason = scope.is_in_scope("http://127.0.0.1:4444/admin")
    assert not ok
    assert "not in approved" in reason

    # Cloud metadata endpoint
    ok, reason = scope.is_in_scope("http://169.254.169.254/latest/meta-data/")
    assert not ok

    # Calling check_url_or_raise trips kill switch
    with pytest.raises(OutOfScopeError):
        scope.check_url_or_raise("http://192.168.1.100:8000/admin")

    assert ks.is_tripped()
    assert "Out of scope request attempt" in (ks.get_trip_reason() or "")


def test_scope_tampering_detection(tmp_path: Path) -> None:
    test_scope_file = tmp_path / "scope.yaml"
    test_scope_file.write_text(
        """
allowed_targets:
  - host: "127.0.0.1"
    ports: [8000]
    protocol: "http"
""",
        encoding="utf-8",
    )

    ks = KillSwitch()
    ks.reset()
    scope = ScopeManager(scope_path=test_scope_file, kill_switch=ks)
    assert scope.verify_file_integrity()

    # Modify file externally
    test_scope_file.write_text(
        """
allowed_targets:
  - host: "evil.com"
    ports: [80]
""",
        encoding="utf-8",
    )

    with pytest.raises(ScopeTamperingError):
        scope.is_in_scope("http://127.0.0.1:8000")

    assert ks.is_tripped()
    assert "tampering detected" in (ks.get_trip_reason() or "")
