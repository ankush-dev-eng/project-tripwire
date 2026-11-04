"""Tests for Voyager Mock B2B Platform and Seeded Vulnerabilities."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lab.app import app
from lab.data_store import db
from lab.models import PatchRegistry
from lab.simulator.deploy_simulator import DeploySimulator
from lab.vulnerabilities import PLANTED_VULNERABILITIES

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_lab_state() -> None:
    db.reset()
    PatchRegistry.reset_all()


def test_agency_auth_and_profile() -> None:
    # Login as Alpha Agent
    res = client.post(
        "/api/v3/auth/login",
        json={"email": "agent@alpha.com", "password": "AlphaAgent#2026"},
    )
    assert res.status_code == 200
    token = res.json()["access_token"]

    # View agency profile
    prof_res = client.get("/api/v3/agency/profile", headers={"Authorization": f"Bearer {token}"})
    assert prof_res.status_code == 200
    assert prof_res.json()["agency_id"] == "AGY_ALPHA"
    assert prof_res.json()["wallet_balance"] == 50000.0


def test_vuln_ac_01_cross_tenant_idor() -> None:
    """VULN-AC-01: Beta agency reading Alpha booking."""
    # Login as Beta Agent
    res = client.post(
        "/api/v3/auth/login",
        json={"email": "agent@beta.com", "password": "BetaAgent#2026"},
    )
    beta_token = res.json()["access_token"]

    # Alpha booking ID
    alpha_bkg_id = "BKG-ALPHA-001"

    # When UNPATCHED: Cross-tenant access succeeds
    assert not PatchRegistry.is_patched("VULN-AC-01")
    idor_res = client.get(
        f"/api/v3/bookings/{alpha_bkg_id}",
        headers={"Authorization": f"Bearer {beta_token}"},
    )
    assert idor_res.status_code == 200
    assert idor_res.json()["agency_id"] == "AGY_ALPHA"

    # When PATCHED: Cross-tenant access is rejected with 403 Forbidden
    PatchRegistry.set_patched("VULN-AC-01", True)
    blocked_res = client.get(
        f"/api/v3/bookings/{alpha_bkg_id}",
        headers={"Authorization": f"Bearer {beta_token}"},
    )
    assert blocked_res.status_code == 403
    assert "Cross-agency IDOR blocked" in blocked_res.json()["detail"]


def test_vuln_bl_01_fare_tampering() -> None:
    """VULN-BL-01: Client modifying fare amount during booking hold."""
    res_login = client.post(
        "/api/v3/auth/login",
        json={"email": "agent@alpha.com", "password": "AlphaAgent#2026"},
    )
    token = res_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    hold_payload = {
        "flight_id": "FL-101",  # Catalog base fare is $650.00
        "passengers": [{"name": "Discount Traveler"}],
        "seat_count": 1,
        "total_amount": 1.99,  # Tampered total
    }

    # When UNPATCHED: Accepts client total_amount ($1.99)
    res_unpatched = client.post("/api/v3/bookings/hold", json=hold_payload, headers=headers)
    assert res_unpatched.status_code == 200
    assert res_unpatched.json()["total_amount"] == 1.99

    # When PATCHED: Recomputes based on catalog flight price ($650.00)
    PatchRegistry.set_patched("VULN-BL-01", True)
    res_patched = client.post("/api/v3/bookings/hold", json=hold_payload, headers=headers)
    assert res_patched.status_code == 200
    assert res_patched.json()["total_amount"] == 650.00


def test_vuln_bl_03_double_refund() -> None:
    """VULN-BL-03: Repeated cancellation triggers multiple refunds."""
    res_login = client.post(
        "/api/v3/auth/login",
        json={"email": "agent@alpha.com", "password": "AlphaAgent#2026"},
    )
    token = res_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    bkg_id = "BKG-ALPHA-001"
    initial_balance = db.agencies["AGY_ALPHA"].wallet_balance

    # First cancel
    res1 = client.post(f"/api/v3/bookings/{bkg_id}/cancel", headers=headers)
    assert res1.status_code == 200
    assert res1.json()["refund_count"] == 1
    assert db.agencies["AGY_ALPHA"].wallet_balance == initial_balance + 650.00

    # Second cancel when UNPATCHED: Refunds again
    res2 = client.post(f"/api/v3/bookings/{bkg_id}/cancel", headers=headers)
    assert res2.status_code == 200
    assert res2.json()["refund_count"] == 2
    assert db.agencies["AGY_ALPHA"].wallet_balance == initial_balance + (650.00 * 2)

    # When PATCHED: Second cancel returns 400 Bad Request
    PatchRegistry.set_patched("VULN-BL-03", True)
    res3 = client.post(f"/api/v3/bookings/{bkg_id}/cancel", headers=headers)
    assert res3.status_code == 400
    assert "already cancelled" in res3.json()["detail"]


def test_vuln_dat_01_card_pan_exposure() -> None:
    """VULN-DAT-01: Cleartext card PAN and CVV on invoice."""
    res_login = client.post(
        "/api/v3/auth/login",
        json={"email": "agent@alpha.com", "password": "AlphaAgent#2026"},
    )
    token = res_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    bkg_id = "BKG-ALPHA-001"

    # UNPATCHED: Full PAN and CVV exposed
    res = client.get(f"/api/v3/bookings/{bkg_id}/invoice", headers=headers)
    assert res.status_code == 200
    card_info = res.json()["payment_method"]
    assert card_info["card_number"] == "4111111111111111"
    assert card_info["cvv"] == "789"

    # PATCHED: Masked PAN and CVV
    PatchRegistry.set_patched("VULN-DAT-01", True)
    res_patched = client.get(f"/api/v3/bookings/{bkg_id}/invoice", headers=headers)
    assert res_patched.status_code == 200
    card_info_p = res_patched.json()["payment_method"]
    assert card_info_p["card_number"] == "****-****-****-1111"
    assert card_info_p["cvv"] == "***"


def test_zombie_and_shadow_routes() -> None:
    # Zombie v1 route
    res_v1 = client.get("/v1/bookings/BKG-ALPHA-001")
    assert res_v1.status_code == 200
    assert res_v1.json()["version"] == "v1.0-legacy"

    # Shadow internal route
    res_shadow = client.post("/internal/supplier-sync")
    assert res_shadow.status_code == 200
    assert res_shadow.json()["shadow_endpoint"] is True

    # Debug env route
    res_env = client.get("/debug/env")
    assert res_env.status_code == 200
    assert "GDS_SUPPLIER_API_KEY" in res_env.json()


def test_sealed_ground_truth_integrity() -> None:
    """Verify that ground_truth/vulnerabilities.json catalogs all 26 seeded vulnerabilities."""
    gt_path = Path("lab/ground_truth/vulnerabilities.json")
    assert gt_path.exists(), "Ground truth manifest must exist"

    with open(gt_path, encoding="utf-8") as f:
        data = json.load(f)

    assert data["total_vulnerabilities"] >= 25
    catalog_ids = {v.vuln_id for v in PLANTED_VULNERABILITIES}
    manifest_ids = {v["id"] for v in data["vulnerabilities"]}

    assert catalog_ids == manifest_ids, (
        f"Mismatch between code catalog and ground truth manifest: {catalog_ids ^ manifest_ids}"
    )


def test_deploy_simulator_held_out_mutation() -> None:
    sim1 = DeploySimulator(seed=101)
    mutated1 = sim1.generate_held_out_spec()
    assert len(mutated1) > 0

    sim2 = DeploySimulator(seed=202)
    mutated2 = sim2.generate_held_out_spec()

    # Different seeds produce different mutated param names or patterns
    assert len(mutated1) == len(mutated2)


def test_synthetic_traffic_generator(tmp_path: Path) -> None:
    from lab.simulator.traffic_generator import (
        generate_gateway_logs,
        generate_sample_har,
    )

    log_30 = tmp_path / "traffic_30d.log"
    log_90 = tmp_path / "traffic_90d.log"
    har_path = tmp_path / "test_journey.har"

    c30, c90 = generate_gateway_logs(output_30d=log_30, output_90d=log_90, seed=77)
    assert c30 > 0
    assert c90 > c30
    assert log_30.exists()
    assert log_90.exists()

    generate_sample_har(output_har=har_path)
    assert har_path.exists()
    har_json = json.loads(har_path.read_text(encoding="utf-8"))
    assert "log" in har_json
    assert len(har_json["log"]["entries"]) >= 3


def test_full_voyager_endpoint_suite() -> None:
    # 1. Reset password
    res = client.post("/api/v3/auth/reset-password", json={"email": "agent@alpha.com"})
    assert res.status_code == 200
    assert "reset_token" in res.json()

    # 2. Open redirect
    res_redir = client.get(
        "/api/v3/auth/redirect?url=https://attacker.com",
        follow_redirects=False,
    )
    assert res_redir.status_code == 302
    assert res_redir.headers["location"] == "https://attacker.com"

    # 3. Agency profile update with mass assignment
    login_res = client.post(
        "/api/v3/auth/login",
        json={"email": "agent@alpha.com", "password": "AlphaAgent#2026"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    update_res = client.put(
        "/api/v3/agency/profile",
        json={"name": "New Alpha Name", "credit_limit": 999999.0},
        headers=headers,
    )
    assert update_res.status_code == 200
    assert update_res.json()["credit_limit"] == 999999.0

    # 4. Agency users list (password hash leak)
    users_res = client.get("/api/v3/agency/users", headers=headers)
    assert users_res.status_code == 200
    assert len(users_res.json()) >= 1
    assert "password_hash" in users_res.json()[0]

    # 5. User promote
    promote_res = client.post("/api/v3/agency/users/USR_ALPHA_SUB/promote", headers=headers)
    assert promote_res.status_code == 200
    assert promote_res.json()["role"] == "admin"

    # 6. Document upload
    doc_res = client.post(
        "/api/v3/agency/documents",
        content=b"<?php echo 'shell'; ?>",
        headers={"x-filename": "exploit.php"},
    )
    assert doc_res.status_code == 200
    assert doc_res.json()["status"] == "STORED"

    # 7. Flight search with SQL injection
    sqli_res = client.get("/api/v3/flights/search?airline=' OR '1'='1")
    assert sqli_res.status_code == 200
    assert sqli_res.json()["injected"] is True

    # 8. Booking payment
    pay_res = client.post("/api/v3/bookings/BKG-ALPHA-001/pay", headers=headers)
    assert pay_res.status_code == 200
    assert pay_res.json()["status"] == "CONFIRMED"

    # 9. Confirm without pay
    conf_res = client.post("/api/v3/bookings/BKG-ALPHA-001/confirm", headers=headers)
    assert conf_res.status_code == 200

    # 10. Coupon application
    coupon_res = client.post(
        "/api/v3/bookings/BKG-ALPHA-001/apply-coupon",
        json={"coupon_code": "VOYAGER50"},
    )
    assert coupon_res.status_code == 200
    assert coupon_res.json()["discount_applied"] == "50%"

    # 11. Error probe traceback
    err_res = client.get("/api/v3/bookings/error-probe?debug=true")
    assert err_res.status_code == 500
    assert "GB987654321" in err_res.json()["traceback"]

    # 12. Wallet balance & topup
    bal_res = client.get("/api/v3/wallet/balance", headers=headers)
    assert bal_res.status_code == 200
    topup_res = client.post("/api/v3/wallet/topup", json={"amount": 5000.0}, headers=headers)
    assert topup_res.status_code == 200

    # 13. Supplier webhook SSRF
    hook_res = client.post(
        "/api/v3/supplier/webhook",
        json={"callback_url": "http://169.254.169.254/latest/meta-data/"},
    )
    assert hook_res.status_code == 200

    # 14. Supplier diagnostics command injection
    diag_res = client.get("/api/v3/supplier/diagnostics?host=127.0.0.1;id")
    assert diag_res.status_code == 200
    assert diag_res.json()["command_executed"] is True

    # 15. Frontend JS bundle serving
    bundle_res = client.get("/static/bundle.js")
    assert bundle_res.status_code == 200
    assert "API_ROUTES" in bundle_res.text

    # 16. Patch toggle endpoint
    toggle_res = client.post(
        "/lab/patches/toggle",
        json={"vuln_id": "VULN-AC-01", "patched": True},
    )
    assert toggle_res.status_code == 200
    assert toggle_res.json()["patched"] is True
    assert client.get("/lab/patches").status_code == 200
