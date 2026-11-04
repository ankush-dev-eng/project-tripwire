"""Tests for Targeted Attack Planner."""

from backend.agents.attack_planner import AttackPlanner
from backend.agents.models import VulnerabilityCategory
from backend.graph.knowledge_graph import KnowledgeGraph


def test_attack_planner_generates_targeted_vectors() -> None:
    kg = KnowledgeGraph()

    # 1. BOLA target
    ep1 = kg.add_endpoint("GET", "/api/v3/bookings/{booking_id}", declared=True)
    kg.add_parameter(ep1, "booking_id", location="path", param_type="string")

    # 2. BOPLA target
    ep2 = kg.add_endpoint("POST", "/api/v3/agency/profile", declared=True)
    kg.add_parameter(ep2, "name", location="body", param_type="string")

    # 3. SSRF target
    ep3 = kg.add_endpoint("POST", "/api/v3/webhooks/register", declared=True)
    kg.add_parameter(ep3, "webhook_url", location="body", param_type="string")

    # 4. Business logic target
    ep4 = kg.add_endpoint("POST", "/api/v3/bookings/pay", declared=True)
    kg.add_parameter(ep4, "amount", location="body", param_type="number")

    # 5. Injection target
    ep5 = kg.add_endpoint("GET", "/api/v3/flights/search", declared=True)
    kg.add_parameter(ep5, "origin", location="query", param_type="string")

    # 6. Auth session target
    kg.add_endpoint("GET", "/api/v3/admin/metrics", auth_required=True)

    planner = AttackPlanner(kg)
    plan = planner.generate_plan()

    assert len(plan) >= 6
    categories = {item.category for item in plan}

    assert VulnerabilityCategory.BOLA in categories
    assert VulnerabilityCategory.BOPLA in categories
    assert VulnerabilityCategory.SSRF in categories
    assert VulnerabilityCategory.BUSINESS_LOGIC in categories
    assert VulnerabilityCategory.INJECTION in categories
    assert VulnerabilityCategory.AUTH_SESSION in categories

    # Check prioritization: high priority items have priority <= 2
    bola_item = next(i for i in plan if i.category == VulnerabilityCategory.BOLA)
    assert bola_item.priority <= 2
    assert "booking_id" in bola_item.target_params or "{" in bola_item.target_path
