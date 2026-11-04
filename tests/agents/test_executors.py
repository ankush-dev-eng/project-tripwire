"""End-to-End Tests for Specialist Attack Executors against Voyager Lab Target."""

import httpx
import pytest

from backend.agents.attack_engine import AttackEngine
from backend.agents.models import AttackPlanItem, VulnerabilityCategory
from backend.graph.knowledge_graph import KnowledgeGraph
from backend.safety.approval_gate import ApprovalGate
from backend.safety.http_client import SafeHttpClient
from backend.safety.kill_switch import KillSwitch
from backend.safety.rate_limiter import RateLimiter
from backend.safety.scope import ScopeManager
from lab.app import app
from lab.data_store import db


@pytest.fixture(autouse=True)
def setup_lab() -> None:
    db.reset()


@pytest.fixture
def safe_client() -> SafeHttpClient:
    ks = KillSwitch.get_instance()
    ks.reset()
    transport = httpx.ASGITransport(app=app)
    # Scope manager loads authorized targets from scope.yaml
    sm = ScopeManager(kill_switch=ks)
    rl = RateLimiter(kill_switch=ks)
    # Permissive approval gate for test harness so automated attack vectors execute
    gate = ApprovalGate(mode="permissive")
    return SafeHttpClient(
        scope_manager=sm,
        kill_switch=ks,
        rate_limiter=rl,
        approval_gate=gate,
        transport=transport,
    )


@pytest.mark.asyncio
async def test_access_control_executor_bola(safe_client: SafeHttpClient) -> None:
    kg = KnowledgeGraph()
    ep = kg.add_endpoint("GET", "/api/v3/bookings/{booking_id}", declared=True)
    kg.add_parameter(ep, "booking_id", location="path")

    engine = AttackEngine(
        knowledge_graph=kg,
        client=safe_client,
        base_url="http://127.0.0.1:8000",
    )
    plan_item = AttackPlanItem(
        plan_id="test-bola",
        category=VulnerabilityCategory.BOLA,
        target_endpoint_id=ep,
        target_path="/api/v3/bookings/{booking_id}",
        method="GET",
        target_params=["booking_id"],
        context={"sample_ids": ["BKG-BETA-001", "BKG-ALPHA-001"]},
    )

    findings = await engine.executors[VulnerabilityCategory.BOLA].execute(
        plan_item, "http://127.0.0.1:8000"
    )
    assert len(findings) > 0
    f = findings[0]
    assert f.category == VulnerabilityCategory.BOLA
    assert f.proof.is_verified() is True
    assert f.proof.confidence_score == 1.0
    assert "curl" in f.proof.reproduction_curl


@pytest.mark.asyncio
async def test_access_control_executor_bopla(safe_client: SafeHttpClient) -> None:
    kg = KnowledgeGraph()
    ep = kg.add_endpoint("PUT", "/api/v3/agency/profile", declared=True)
    kg.add_parameter(ep, "credit_limit", location="body")

    engine = AttackEngine(
        knowledge_graph=kg,
        client=safe_client,
        base_url="http://127.0.0.1:8000",
    )
    plan_item = AttackPlanItem(
        plan_id="test-bopla",
        category=VulnerabilityCategory.BOPLA,
        target_endpoint_id=ep,
        target_path="/api/v3/agency/profile",
        method="PUT",
        target_params=["credit_limit", "is_verified"],
    )

    findings = await engine.executors[VulnerabilityCategory.BOPLA].execute(
        plan_item, "http://127.0.0.1:8000"
    )
    assert len(findings) > 0
    f = findings[0]
    assert f.category == VulnerabilityCategory.BOPLA
    assert f.proof.is_verified() is True


@pytest.mark.asyncio
async def test_business_logic_fare_tampering(safe_client: SafeHttpClient) -> None:
    kg = KnowledgeGraph()
    ep = kg.add_endpoint("POST", "/api/v3/bookings/hold", declared=True)
    kg.add_parameter(ep, "total_amount", location="body")

    engine = AttackEngine(
        knowledge_graph=kg,
        client=safe_client,
        base_url="http://127.0.0.1:8000",
    )
    plan_item = AttackPlanItem(
        plan_id="test-bl-fare",
        category=VulnerabilityCategory.BUSINESS_LOGIC,
        target_endpoint_id=ep,
        target_path="/api/v3/bookings/hold",
        method="POST",
        target_params=["total_amount", "flight_id"],
        context={"sample_ids": ["FL-101", "BKG-ALPHA-001"]},
    )

    findings = await engine.executors[VulnerabilityCategory.BUSINESS_LOGIC].execute(
        plan_item, "http://127.0.0.1:8000"
    )
    assert len(findings) > 0
    f = findings[0]
    assert f.category == VulnerabilityCategory.BUSINESS_LOGIC
    assert f.proof.is_verified() is True


@pytest.mark.asyncio
async def test_business_logic_double_refund(safe_client: SafeHttpClient) -> None:
    kg = KnowledgeGraph()
    ep = kg.add_endpoint("POST", "/api/v3/bookings/{booking_id}/cancel", declared=True)
    kg.add_parameter(ep, "booking_id", location="path")

    engine = AttackEngine(
        knowledge_graph=kg,
        client=safe_client,
        base_url="http://127.0.0.1:8000",
    )
    plan_item = AttackPlanItem(
        plan_id="test-bl-refund",
        category=VulnerabilityCategory.BUSINESS_LOGIC,
        target_endpoint_id=ep,
        target_path="/api/v3/bookings/{booking_id}/cancel",
        method="POST",
        target_params=["booking_id"],
        context={"sample_ids": ["BKG-ALPHA-001"]},
    )

    findings = await engine.executors[VulnerabilityCategory.BUSINESS_LOGIC].execute(
        plan_item, "http://127.0.0.1:8000"
    )
    assert len(findings) > 0
    f = findings[0]
    assert "Double Refund" in f.title
    assert f.proof.is_verified() is True


@pytest.mark.asyncio
async def test_auth_session_jwt_bypass(safe_client: SafeHttpClient) -> None:
    kg = KnowledgeGraph()
    ep = kg.add_endpoint("GET", "/api/v3/agency/profile", auth_required=True)

    engine = AttackEngine(
        knowledge_graph=kg,
        client=safe_client,
        base_url="http://127.0.0.1:8000",
    )
    plan_item = AttackPlanItem(
        plan_id="test-jwt-none",
        category=VulnerabilityCategory.AUTH_SESSION,
        target_endpoint_id=ep,
        target_path="/api/v3/agency/profile",
        method="GET",
    )

    findings = await engine.executors[VulnerabilityCategory.AUTH_SESSION].execute(
        plan_item, "http://127.0.0.1:8000"
    )
    assert len(findings) > 0
    f = findings[0]
    assert f.category == VulnerabilityCategory.AUTH_SESSION
    assert f.proof.is_verified() is True


@pytest.mark.asyncio
async def test_injection_executor_sqli(safe_client: SafeHttpClient) -> None:
    kg = KnowledgeGraph()
    ep = kg.add_endpoint("GET", "/api/v3/flights/search", declared=True)
    kg.add_parameter(ep, "airline", location="query")

    engine = AttackEngine(
        knowledge_graph=kg,
        client=safe_client,
        base_url="http://127.0.0.1:8000",
    )
    plan_item = AttackPlanItem(
        plan_id="test-sqli",
        category=VulnerabilityCategory.INJECTION,
        target_endpoint_id=ep,
        target_path="/api/v3/flights/search",
        method="GET",
        target_params=["airline"],
    )

    findings = await engine.executors[VulnerabilityCategory.INJECTION].execute(
        plan_item, "http://127.0.0.1:8000"
    )
    assert len(findings) > 0
    f = findings[0]
    assert f.category == VulnerabilityCategory.INJECTION
    assert f.proof.is_verified() is True


@pytest.mark.asyncio
async def test_data_exposure_executor(safe_client: SafeHttpClient) -> None:
    kg = KnowledgeGraph()
    ep = kg.add_endpoint("GET", "/v1/bookings/{booking_id}", declared=True)
    kg.add_parameter(ep, "booking_id", location="path")

    engine = AttackEngine(
        knowledge_graph=kg,
        client=safe_client,
        base_url="http://127.0.0.1:8000",
    )
    plan_item = AttackPlanItem(
        plan_id="test-pci-exposure",
        category=VulnerabilityCategory.DATA_EXPOSURE,
        target_endpoint_id=ep,
        target_path="/v1/bookings/{booking_id}",
        method="GET",
        context={"sample_ids": ["BKG-ALPHA-001"]},
    )

    findings = await engine.executors[VulnerabilityCategory.DATA_EXPOSURE].execute(
        plan_item, "http://127.0.0.1:8000"
    )
    assert len(findings) > 0
    f = findings[0]
    assert f.category == VulnerabilityCategory.DATA_EXPOSURE
    assert f.proof.is_verified() is True


@pytest.mark.asyncio
async def test_server_side_ssrf(safe_client: SafeHttpClient) -> None:
    kg = KnowledgeGraph()
    ep = kg.add_endpoint("POST", "/api/v3/supplier/webhook", declared=True)
    kg.add_parameter(ep, "callback_url", location="body")

    engine = AttackEngine(
        knowledge_graph=kg,
        client=safe_client,
        base_url="http://127.0.0.1:8000",
    )
    plan_item = AttackPlanItem(
        plan_id="test-ssrf",
        category=VulnerabilityCategory.SSRF,
        target_endpoint_id=ep,
        target_path="/api/v3/supplier/webhook",
        method="POST",
        target_params=["callback_url"],
    )

    findings = await engine.executors[VulnerabilityCategory.SSRF].execute(
        plan_item, "http://127.0.0.1:8000"
    )
    assert len(findings) > 0
    f = findings[0]
    assert f.category == VulnerabilityCategory.SSRF
    assert f.proof.is_verified() is True


@pytest.mark.asyncio
async def test_hygiene_debug_and_traceback(safe_client: SafeHttpClient) -> None:
    kg = KnowledgeGraph()
    ep1 = kg.add_endpoint("GET", "/debug/env", declared=False)
    ep2 = kg.add_endpoint("GET", "/api/v3/bookings/error-probe", declared=True)

    engine = AttackEngine(
        knowledge_graph=kg,
        client=safe_client,
        base_url="http://127.0.0.1:8000",
    )

    plan_item1 = AttackPlanItem(
        plan_id="test-debug-env",
        category=VulnerabilityCategory.API_HYGIENE,
        target_endpoint_id=ep1,
        target_path="/debug/env",
        method="GET",
    )
    findings1 = await engine.executors[VulnerabilityCategory.API_HYGIENE].execute(
        plan_item1, "http://127.0.0.1:8000"
    )
    assert len(findings1) > 0
    assert "Debug" in findings1[0].title
    assert findings1[0].proof.is_verified() is True

    plan_item2 = AttackPlanItem(
        plan_id="test-stack-trace",
        category=VulnerabilityCategory.API_HYGIENE,
        target_endpoint_id=ep2,
        target_path="/api/v3/bookings/error-probe",
        method="GET",
    )
    findings2 = await engine.executors[VulnerabilityCategory.API_HYGIENE].execute(
        plan_item2, "http://127.0.0.1:8000"
    )
    assert len(findings2) > 0
    assert "Traceback" in findings2[0].title
    assert findings2[0].proof.is_verified() is True
