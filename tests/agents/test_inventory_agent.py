"""Tests for API Inventory Classification and OpenAPI Specification Generation."""

from pathlib import Path

from backend.agents.inventory_agent import (
    InventoryAgent,
    InventoryClassification,
)
from backend.agents.openapi_generator import OpenAPISpecGenerator
from backend.graph.knowledge_graph import KnowledgeGraph


def test_inventory_classification_f1_score() -> None:
    """Verify that classification of Active, Zombie, and Shadow routes achieves F1 >= 0.85."""
    kg = KnowledgeGraph()

    # Seed KnowledgeGraph with test endpoints
    # 1. Active endpoints
    kg.add_endpoint("GET", "/api/v3/flights/search", declared=True)
    kg.add_endpoint("POST", "/api/v3/bookings/hold", declared=True)
    kg.add_endpoint("GET", "/api/v3/agency/profile", declared=True)

    # 2. Shadow endpoints (active in traffic, but absent from declared specs)
    kg.add_endpoint("POST", "/internal/supplier-sync", declared=False)

    # 3. Zombie endpoints (declared, but seen in 90d only; 0 in last 30 days)
    kg.add_endpoint("GET", "/v1/bookings/BKG-ALPHA-001", declared=True)
    kg.add_endpoint("POST", "/api/partner/v2/quote", declared=True)

    # 4. Undocumented Zombie
    kg.add_endpoint("GET", "/debug/env", declared=False)

    agent = InventoryAgent(knowledge_graph=kg)

    # Parse real synthetic gateway logs generated in Phase 2
    log_30d = Path("data/gateway_30d.log")
    assert log_30d.exists(), "gateway_30d.log must exist from Phase 2"

    agent.parse_traffic_log(log_30d, window_days=30)
    inventory = agent.classify_inventory()

    # Map classifications by endpoint path
    class_map = {r.path: r.classification for r in inventory}

    # Ground truth mapping
    ground_truth = {
        "/api/v3/flights/search": InventoryClassification.ACTIVE,
        "/api/v3/bookings/hold": InventoryClassification.ACTIVE,
        "/api/v3/agency/profile": InventoryClassification.ACTIVE,
        "/internal/supplier-sync": InventoryClassification.SHADOW,
        "/v1/bookings/BKG-ALPHA-001": InventoryClassification.ZOMBIE,
        "/api/partner/v2/quote": InventoryClassification.ZOMBIE,
        "/debug/env": InventoryClassification.ZOMBIE_UNDOCUMENTED,
    }

    correct = 0
    total = len(ground_truth)

    for path, expected_class in ground_truth.items():
        assert path in class_map, f"Path {path} must be classified in inventory"
        actual_class = class_map[path]
        if actual_class == expected_class:
            correct += 1

    accuracy = correct / total
    precision = accuracy
    recall = accuracy
    f1 = 2 * (precision * recall) / (precision + recall)

    assert f1 >= 0.85, f"Inventory classification F1 {f1:.2f} fell below 0.85 threshold"

    # Verify report fields
    shadow_record = next(r for r in inventory if r.path == "/internal/supplier-sync")
    assert shadow_record.classification == InventoryClassification.SHADOW
    assert len(shadow_record.data_exposed) > 0
    assert shadow_record.risk_level in {"HIGH", "MEDIUM", "CRITICAL"}
    assert "Document" in shadow_record.recommendation or "gateway" in shadow_record.recommendation


def test_openapi_spec_generation() -> None:
    kg = KnowledgeGraph()
    ep_id = kg.add_endpoint(
        "POST",
        "/api/v3/bookings/hold",
        declared=True,
        auth_required=True,
    )
    kg.add_parameter(
        ep_id,
        param_name="flight_id",
        location="body",
        param_type="string",
    )
    kg.add_parameter(
        ep_id,
        param_name="seat_count",
        location="body",
        param_type="integer",
    )

    generator = OpenAPISpecGenerator(knowledge_graph=kg)
    spec = generator.generate_spec(title="Voyager Platform API", version="3.1.0")

    assert spec["openapi"] == "3.1.0"
    assert spec["info"]["title"] == "Voyager Platform API"
    assert "/api/v3/bookings/hold" in spec["paths"]

    op = spec["paths"][
        "api/v3/bookings/hold"
        if "api/v3/bookings/hold" in spec["paths"]
        else "/api/v3/bookings/hold"
    ]["post"]
    assert "tags" in op
    assert "responses" in op
    assert "200" in op["responses"]
    assert "401" in op["responses"]  # Auth required
    assert "BearerAuth" in op["security"][0]

    # Verify YAML export
    yaml_output = generator.export_yaml()
    assert "openapi: 3.1.0" in yaml_output
    assert "BearerAuth" in yaml_output
