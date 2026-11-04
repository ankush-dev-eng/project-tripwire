"""Tests for Double-Proof Verifier and Curl Reproduction Generator."""

import httpx

from backend.agents.verifier import DoubleProofVerifier


def test_build_curl_command_redaction() -> None:
    curl = DoubleProofVerifier.build_curl(
        method="POST",
        url="http://127.0.0.1:8000/api/v3/bookings/hold",
        headers={
            "Authorization": "Bearer sensitive_secret_token_abc",
            "X-Agency-ID": "Agency_Alpha",
        },
        json_body={"flight_id": "FL-101", "passengers": [{"name": "Test"}]},
    )

    assert "curl -s -X POST" in curl
    assert "http://127.0.0.1:8000/api/v3/bookings/hold" in curl
    assert "<TOKEN_REDACTED>" in curl
    assert "sensitive_secret_token_abc" not in curl
    assert "FL-101" in curl


def test_double_proof_confidence_calculation() -> None:
    # Scenario A: Both primary and negative control succeed -> Verified (confidence 1.0)
    p_req = {
        "method": "GET",
        "url": "http://127.0.0.1:8000/api/v3/bookings/BKG-BETA-001",
    }
    p_resp = httpx.Response(200, text='{"booking_id": "BKG-BETA-001"}')
    c_req = {
        "method": "GET",
        "url": "http://127.0.0.1:8000/api/v3/bookings/NONEXISTENT",
    }
    c_resp = httpx.Response(404, text='{"detail": "Not found"}')

    proof = DoubleProofVerifier.verify(
        primary_req=p_req,
        primary_resp=p_resp,
        primary_succeeded=True,
        control_req=c_req,
        control_resp=c_resp,
        control_succeeded=True,
    )
    assert proof.is_verified() is True
    assert proof.confidence_score == 1.0

    # Scenario B: Primary succeeds but control fails (e.g. static 200 on nonexistent) -> Not verified
    c_resp_broken = httpx.Response(200, text='{"status": "ok"}')
    proof_broken = DoubleProofVerifier.verify(
        primary_req=p_req,
        primary_resp=p_resp,
        primary_succeeded=True,
        control_req=c_req,
        control_resp=c_resp_broken,
        control_succeeded=False,
    )
    assert proof_broken.is_verified() is False
    assert proof_broken.confidence_score == 0.0
