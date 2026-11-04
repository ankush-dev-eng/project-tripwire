"""Tests for Human-in-the-Loop Approval Gate."""

import pytest
from backend.safety.approval_gate import ApprovalGate, ApprovalRequiredError


def test_auto_approved_get_request() -> None:
    gate = ApprovalGate(policy_path="config/approval_policy.yaml")
    # Read-only idempotent probes need no approval
    gate.check_approval("GET", "http://127.0.0.1:8000/flights/search")
    gate.check_approval("GET", "http://127.0.0.1:8000/bookings/101")


def test_state_change_requires_approval() -> None:
    gate = ApprovalGate(policy_path="config/approval_policy.yaml")

    # Payment probe
    with pytest.raises(ApprovalRequiredError) as exc_info:
        gate.check_approval("POST", "http://127.0.0.1:8000/api/bookings/101/pay")

    err = exc_info.value
    assert err.action_type == "state_change"
    req_id = err.request_id

    # Pending approvals queue reflects the request
    pending = gate.get_pending_approvals()
    assert len(pending) == 1
    assert pending[0]["id"] == req_id
    assert pending[0]["path"] == "/api/bookings/101/pay"

    # Human operator grants approval
    token = gate.approve_request(req_id, operator_id="security_lead")
    assert token.startswith("tok_")

    # Now the probe succeeds when passing the token
    gate.check_approval(
        "POST",
        "http://127.0.0.1:8000/api/bookings/101/pay",
        approval_token=token,
    )

    # Attempting to use the same token on a different guarded path fails
    with pytest.raises(ApprovalRequiredError):
        gate.check_approval(
            "POST",
            "http://127.0.0.1:8000/api/bookings/101/cancel",
            approval_token=token,
        )


def test_destructive_delete_requires_approval() -> None:
    gate = ApprovalGate(policy_path="config/approval_policy.yaml")

    with pytest.raises(ApprovalRequiredError) as exc_info:
        gate.check_approval("DELETE", "http://127.0.0.1:8000/users/42")

    assert exc_info.value.action_type == "destructive"
