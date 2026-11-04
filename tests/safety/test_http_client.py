"""Comprehensive Integration Tests for SafeHttpClient."""

from pathlib import Path

import pytest

from backend.safety.approval_gate import ApprovalGate, ApprovalRequiredError
from backend.safety.audit_logger import AuditLogger
from backend.safety.http_client import SafeHttpClient
from backend.safety.kill_switch import KillSwitch, KillSwitchTrippedError
from backend.safety.rate_limiter import RateLimiter
from backend.safety.scope import OutOfScopeError, ScopeManager


@pytest.fixture
def test_safety_stack(tmp_path: Path):
    audit_path = tmp_path / "audit.jsonl"
    kill_switch = KillSwitch(trigger_file=tmp_path / ".kill")
    kill_switch.reset()
    scope_mgr = ScopeManager(scope_path="scope.yaml", kill_switch=kill_switch)
    rate_limiter = RateLimiter(config_path="config/rate_limits.yaml", kill_switch=kill_switch)
    approval_gate = ApprovalGate(policy_path="config/approval_policy.yaml")
    audit_logger = AuditLogger(log_path=audit_path)

    client = SafeHttpClient(
        scope_manager=scope_mgr,
        kill_switch=kill_switch,
        rate_limiter=rate_limiter,
        approval_gate=approval_gate,
        audit_logger=audit_logger,
    )
    return client, kill_switch, audit_path, approval_gate


@pytest.mark.asyncio
async def test_safe_http_client_blocks_out_of_scope(test_safety_stack) -> None:
    client, kill_switch, _, _ = test_safety_stack

    # Out of scope domain
    with pytest.raises(OutOfScopeError) as exc_info:
        await client.get("https://unauthorized-domain.com/secret")

    assert "unauthorized-domain.com" in str(exc_info.value)
    # Automatic kill switch tripping
    assert kill_switch.is_tripped()

    # Subsequent request is blocked by kill switch
    with pytest.raises(KillSwitchTrippedError):
        await client.get("http://127.0.0.1:8000/api")

    await client.close()


@pytest.mark.asyncio
async def test_safe_http_client_blocks_when_kill_switch_active(
    test_safety_stack,
) -> None:
    client, kill_switch, _, _ = test_safety_stack
    kill_switch.trip("Manual stop by operator")

    with pytest.raises(KillSwitchTrippedError) as exc_info:
        await client.get("http://127.0.0.1:8000/test")

    assert "Manual stop by operator" in str(exc_info.value)
    await client.close()


@pytest.mark.asyncio
async def test_safe_http_client_approval_flow(test_safety_stack) -> None:
    client, _, _, approval_gate = test_safety_stack

    # Attempt state-changing payment probe without token
    with pytest.raises(ApprovalRequiredError) as exc_info:
        await client.post("http://127.0.0.1:8000/bookings/1/pay")

    req_id = exc_info.value.request_id

    # Human approves
    token = approval_gate.approve_request(req_id, operator_id="admin_sec")

    # In mock context, let's verify gate passes with token
    approval_gate.check_approval(
        "POST", "http://127.0.0.1:8000/bookings/1/pay", approval_token=token
    )

    await client.close()


@pytest.mark.asyncio
async def test_safe_http_client_live_local_request(test_safety_stack, monkeypatch) -> None:
    """Test full dispatch, response wrapping, and hash-chained audit logging."""
    client, _, audit_path, _ = test_safety_stack

    # Monkeypatch the internal httpx client request to return a synthetic response
    import httpx

    async def mock_send(self, request, *args, **kwargs):
        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "application/json", "X-Custom": "Safe"},
            content=b'{"status": "CONFIRMED", "pnr": "TBO-XYZ"}',
            request=request,
        )

    monkeypatch.setattr(httpx.AsyncClient, "send", mock_send)

    res = await client.get("http://127.0.0.1:8000/api/bookings/B-101")

    assert res.status_code == 200
    assert res.json()["status"] == "CONFIRMED"
    assert res.json()["pnr"] == "TBO-XYZ"
    assert res.elapsed_ms >= 0

    # Verify audit log was recorded and hash chain is mathematically sound
    valid, msg, count = AuditLogger.verify_chain(audit_path)
    assert valid, f"Audit chain verification error: {msg}"
    assert count == 1

    await client.close()
