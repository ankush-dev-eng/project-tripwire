"""Tests for Change Detection, JS Route Extraction, Knowledge Graph, and Recon Crawler."""

from pathlib import Path

import httpx
import pytest

from backend.agents.change_detector import ChangeDetector
from backend.agents.js_extractor import JSRouteExtractor
from backend.agents.recon_crawler import ReconCrawler
from backend.graph.knowledge_graph import KnowledgeGraph
from backend.safety.http_client import SafeHttpClient
from lab.app import app


def test_knowledge_graph_structure() -> None:
    kg = KnowledgeGraph()
    host_id = kg.add_host("127.0.0.1", 8000)
    ep_id = kg.add_endpoint("GET", "/api/v3/flights/search", declared=True, host_id=host_id)
    kg.add_parameter(ep_id, "origin", location="query", observed_value="DXB")

    kg.add_role_access("admin", ep_id)
    kg.add_flow_step("search_flow", ep_id, step_order=1)

    assert kg.get_endpoint_count() == 1
    params = kg.get_parameters_for_endpoint(ep_id)
    assert len(params) == 1
    assert params[0]["name"] == "origin"

    ui_export = kg.export_topology_for_ui()
    assert len(ui_export["nodes"]) >= 4  # host, endpoint, param, role, flow
    assert len(ui_export["edges"]) >= 3


def test_js_route_extractor() -> None:
    sample_js = """
    const API = {
        search: "/api/v3/flights/search",
        booking: "/api/v3/bookings/{booking_id}",
        invoice: "/api/v3/bookings/${id}/invoice",
        legacy: "/v1/bookings/old",
        internal: "/internal/supplier-sync"
    };
    fetch("/api/v3/agency/profile");
    axios.post(`/api/v3/wallet/topup`);
    """
    routes = JSRouteExtractor.extract_routes(sample_js)
    assert "/api/v3/flights/search" in routes
    assert "/api/v3/bookings/{booking_id}" in routes
    assert "/api/v3/agency/profile" in routes
    assert "/v1/bookings/old" in routes
    assert "/internal/supplier-sync" in routes


def test_change_detector_events(tmp_path: Path) -> None:
    detector = ChangeDetector()

    # Deploy webhook
    event = detector.handle_deploy_webhook(
        {"service": "voyager", "changed_endpoints": ["/api/v3/flights/search"]}
    )
    assert event.change_type == "DEPLOY_WEBHOOK"
    assert "/api/v3/flights/search" in event.impacted_endpoints

    # JS bundle diff
    url = "http://127.0.0.1:8000/static/bundle.js"
    assert detector.check_bundle_diff(url, "console.log('v1')") is None
    diff_event = detector.check_bundle_diff(url, "console.log('v2-changed')")
    assert diff_event is not None
    assert diff_event.change_type == "JS_BUNDLE_DIFF"

    # Traffic diff
    log_file = tmp_path / "traffic.log"
    log_file.write_text(
        '2026-11-05T00:00:00Z 10.0.0.1 "POST /api/v3/bookings/hold HTTP/1.1" 200 45ms\n',
        encoding="utf-8",
    )
    events = detector.ingest_traffic_diff(log_file)
    assert len(events) == 1
    assert "POST /api/v3/bookings/hold" in events[0].impacted_endpoints


@pytest.mark.asyncio
async def test_recon_crawler_autonomous_discovery(tmp_path: Path) -> None:
    """Run ReconCrawler through SafeHttpClient against the Voyager app to test endpoint discovery recall."""
    kg = KnowledgeGraph()
    safe_client = SafeHttpClient()

    # Route SafeHttpClient directly through ASGITransport to the in-process Voyager FastAPI app
    transport = httpx.ASGITransport(app=app)
    safe_client._async_client = httpx.AsyncClient(
        transport=transport,
        base_url="http://127.0.0.1:8000",
    )

    crawler = ReconCrawler(http_client=safe_client, knowledge_graph=kg)

    # Run discovery using bundle discovery, pattern probes, and the sample HAR
    har_path = Path("data/voyager_journey.har")
    await crawler.run_discovery(
        target_base_url="http://127.0.0.1:8000",
        har_path=har_path if har_path.exists() else None,
    )

    endpoints = kg.get_endpoints()
    discovered_paths = {ep["path"] for ep in endpoints}

    # Verify that core workflows, zombie, shadow, and debug endpoints were all discovered
    assert "/api/v3/flights/search" in discovered_paths
    assert "/api/v3/bookings/hold" in discovered_paths
    assert "/api/v3/agency/profile" in discovered_paths
    assert "/api/v3/wallet/balance" in discovered_paths
    assert "/internal/supplier-sync" in discovered_paths
    assert "/debug/env" in discovered_paths
    assert any("/v1/bookings" in p for p in discovered_paths)

    # Core target endpoints in Voyager
    target_core_paths = [
        "/api/v3/auth/login",
        "/api/v3/auth/reset-password",
        "/api/v3/agency/profile",
        "/api/v3/agency/users",
        "/api/v3/flights/search",
        "/api/v3/bookings/hold",
        "/api/v3/wallet/balance",
        "/internal/supplier-sync",
        "/debug/env",
        "/static/bundle.js",
    ]

    matched = sum(1 for p in target_core_paths if p in discovered_paths)
    recall = matched / len(target_core_paths)

    # Gate requirement: Endpoint discovery recall at least 90%
    assert recall >= 0.90, f"Discovery recall was {recall:.2%}, expected >= 90%"

    await safe_client.close()
