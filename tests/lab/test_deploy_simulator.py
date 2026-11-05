"""Tests for Deploy Simulator and Spec-Free Mutated Held-Out Targets."""

import httpx
import pytest

from backend.agents.recon_crawler import ReconCrawler
from backend.graph.knowledge_graph import KnowledgeGraph
from backend.safety.approval_gate import ApprovalGate
from backend.safety.http_client import SafeHttpClient
from backend.safety.kill_switch import KillSwitch
from backend.safety.rate_limiter import RateLimiter
from backend.safety.scope import ScopeManager
from lab.simulator.deploy_simulator import DeploySimulator


@pytest.mark.asyncio
async def test_create_mutated_app_spec_free() -> None:
    """Verify mutated app has no openapi or docs endpoints."""
    sim = DeploySimulator(seed=101)
    spec = sim.generate_held_out_spec()
    app = sim.create_mutated_app(spec)

    assert app.openapi_url is None
    assert app.docs_url is None
    assert app.redoc_url is None

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. openapi.json must return 404
        resp_openapi = await client.get("/openapi.json")
        assert resp_openapi.status_code == 404

        # 2. /static/bundle.js must return valid JS route manifest
        resp_bundle = await client.get("/static/bundle.js")
        assert resp_bundle.status_code == 200
        assert "application/javascript" in resp_bundle.headers["content-type"]
        assert "routes:" in resp_bundle.text


@pytest.mark.asyncio
async def test_recon_from_scratch_on_mutated_app() -> None:
    """Verify ReconCrawler discovers routes from scratch with NO spec handed to it."""
    sim = DeploySimulator(seed=101)
    spec = sim.generate_held_out_spec()
    app = sim.create_mutated_app(spec)

    ks = KillSwitch()
    sm = ScopeManager(kill_switch=ks)
    rl = RateLimiter(kill_switch=ks)
    ag = ApprovalGate(mode="permissive")
    transport = httpx.ASGITransport(app=app)
    safe_client = SafeHttpClient(
        scope_manager=sm,
        rate_limiter=rl,
        approval_gate=ag,
        kill_switch=ks,
        transport=transport,
    )

    kg = KnowledgeGraph()
    crawler = ReconCrawler(http_client=safe_client, knowledge_graph=kg)

    count = await crawler.run_discovery("http://127.0.0.1:8000")
    assert count > 0

    discovered_paths = {ep["path"] for ep in kg.get_all_endpoints()}
    # Verify spec endpoints were discovered from scratch via JS bundle / probes
    spec_endpoints = [item["endpoint"] for item in spec]
    matched = [
        ep for ep in spec_endpoints if any(ep.split("{")[0] in dp for dp in discovered_paths)
    ]
    discovery_recall = len(matched) / len(spec_endpoints)
    assert discovery_recall >= 0.80
