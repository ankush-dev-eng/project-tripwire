"""Verification and exit-gate test suite for Voyager-B independent lab target."""

import json
from pathlib import Path

import httpx
import pytest

from lab_b.app import app_b
from lab_b.data_store import db_b
from lab_b.models import PatchRegistryB


@pytest.fixture(autouse=True)
def reset_lab_b() -> None:
    db_b.reset()
    PatchRegistryB.reset()


@pytest.mark.asyncio
async def test_voyager_b_manifest_integrity() -> None:
    manifest_path = Path("lab_b/ground_truth/voyager_b_manifest.json")
    assert manifest_path.exists(), "Voyager-B ground truth manifest must exist"
    with open(manifest_path, encoding="utf-8") as f:
        data = json.load(f)

    assert data["total_vulnerabilities"] >= 20
    assert len(data["vulnerabilities"]) >= 20
    classes = {v["class"] for v in data["vulnerabilities"]}
    assert len(classes) >= 6, "Must span multiple OWASP API security classes"


@pytest.mark.asyncio
async def test_voyager_b_routes_and_patches() -> None:
    transport = httpx.ASGITransport(app=app_b)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Healthcheck
        res = await client.get("/v2/ops/ping")
        assert res.status_code == 200

        # 2. BOLA on partner ticket
        # Unpatched cross-agency access succeeds
        auth_beacon = {"Authorization": "Bearer tok_usr_beacon_coord"}
        res = await client.get("/v2/travel/tickets/TCK-APEX-8801", headers=auth_beacon)
        assert res.status_code == 200
        assert res.json()["agency_id"] == "AGY_APEX"

        # Apply patch and verify blocked
        PatchRegistryB.set_patched("VULN-B-AC-01", True)
        res_patched = await client.get("/v2/travel/tickets/TCK-APEX-8801", headers=auth_beacon)
        assert res_patched.status_code == 403

        # 3. Command injection in DNS lookup
        res_cmd = await client.get("/v2/supplier/dns-lookup?domain=127.0.0.1;id")
        assert res_cmd.status_code == 200
        assert res_cmd.json()["command_executed"] is True
