"""Integration tests for TripwireOrchestrator."""

import asyncio

import httpx
import pytest

from backend.orchestrator import OrchestratorStatus, TripwireOrchestrator
from backend.safety.approval_gate import ApprovalGate
from backend.safety.audit_logger import AuditLogger
from backend.safety.http_client import SafeHttpClient
from backend.safety.kill_switch import KillSwitch
from backend.safety.rate_limiter import RateLimiter
from backend.safety.scope import ScopeManager
from lab.app import app
from lab.models import PatchRegistry


@pytest.fixture(autouse=True)
def reset_lab() -> None:
    PatchRegistry.reset_all()
    yield
    PatchRegistry.reset_all()


@pytest.fixture
def orchestrator_instance() -> TripwireOrchestrator:
    ks = KillSwitch()
    transport = httpx.ASGITransport(app=app)
    client = SafeHttpClient(
        scope_manager=ScopeManager(kill_switch=ks),
        rate_limiter=RateLimiter(kill_switch=ks),
        approval_gate=ApprovalGate(mode="permissive"),
        audit_logger=AuditLogger(),
        kill_switch=ks,
        transport=transport,
    )
    return TripwireOrchestrator(
        safe_client=client,
        kill_switch=ks,
        approval_gate=ApprovalGate(mode="permissive"),
    )


@pytest.mark.asyncio
async def test_orchestrator_subscriber_event_emission(
    orchestrator_instance: TripwireOrchestrator,
) -> None:
    queue: asyncio.Queue = asyncio.Queue()
    orchestrator_instance.add_subscriber(queue)

    await orchestrator_instance.emit_event("TEST_EVENT", {"detail": "unit_test"})
    event = await asyncio.wait_for(queue.get(), timeout=2.0)

    assert event["type"] == "TEST_EVENT"
    assert event["data"]["detail"] == "unit_test"
    assert "timestamp" in event

    orchestrator_instance.remove_subscriber(queue)
    assert queue not in orchestrator_instance._subscribers


@pytest.mark.asyncio
async def test_orchestrator_end_to_end_scan(
    orchestrator_instance: TripwireOrchestrator,
) -> None:
    events_received = []
    queue: asyncio.Queue = asyncio.Queue()
    orchestrator_instance.add_subscriber(queue)

    async def listener() -> None:
        try:
            while True:
                ev = await queue.get()
                events_received.append(ev["type"])
        except asyncio.CancelledError:
            pass

    task = asyncio.create_task(listener())

    # Execute full scan pipeline against in-memory lab
    findings = await orchestrator_instance.run_scan(
        target_base_url="http://127.0.0.1:8000",
        traffic_log_path="data/gateway_30d.log",
        js_bundle_url="http://127.0.0.1:8000/static/bundle.js",
    )

    task.cancel()
    await asyncio.sleep(0.05)

    # Drain any remaining events in queue
    while not queue.empty():
        ev = queue.get_nowait()
        events_received.append(ev["type"])

    assert orchestrator_instance.status == OrchestratorStatus.COMPLETED
    assert orchestrator_instance.progress == 100
    assert len(findings) > 0
    assert orchestrator_instance.kg.get_endpoint_count() > 0
    assert len(orchestrator_instance.inventory_records) > 0

    # Verify event stream sequencing
    assert "STATUS_CHANGED" in events_received
    assert "GRAPH_UPDATED" in events_received
    assert "INVENTORY_UPDATED" in events_received
    assert "PLAN_GENERATED" in events_received
    assert "FINDING_DISCOVERED" in events_received
    assert "FINDING_TRIAGED" in events_received

    # Verify state serialization
    state = orchestrator_instance.get_state()
    assert state["status"] == "COMPLETED"
    assert state["findings_count"] == len(findings)
    assert state["severity_breakdown"]["CRITICAL"] >= 1

    # Verify inventory and graph export
    inv = orchestrator_instance.get_inventory()
    assert len(inv["active"]) > 0
    assert len(inv["zombie"]) > 0

    graph = orchestrator_instance.get_graph()
    assert len(graph["nodes"]) > 0
    assert len(graph["edges"]) > 0
