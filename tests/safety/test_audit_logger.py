"""Tests for Cryptographic Hash-Chained Audit Logger."""

import json
from pathlib import Path
from backend.safety.audit_logger import AuditLogger


def test_audit_logger_hash_chain(tmp_path: Path) -> None:
    log_file = tmp_path / "test_audit.jsonl"
    logger = AuditLogger(log_path=log_file)

    # Log 3 sample requests
    logger.log_interaction(
        method="GET",
        url="http://127.0.0.1:8000/api/flights",
        request_headers={"User-Agent": "Tripwire/1.0"},
        request_body=None,
        status_code=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"flights": []}',
        latency_ms=45.2,
    )

    logger.log_interaction(
        method="POST",
        url="http://127.0.0.1:8000/api/bookings/hold",
        request_headers={"Authorization": "Bearer eyJfake.token.here"},
        request_body={"flight_id": "FL-101", "passenger": {"card": "4111111111111111"}},
        status_code=201,
        response_headers={"Content-Type": "application/json"},
        response_body={"booking_id": "B-999", "status": "HELD"},
        latency_ms=112.5,
    )

    logger.log_interaction(
        method="GET",
        url="http://127.0.0.1:8000/api/bookings/B-999",
        request_headers={"User-Agent": "Tripwire/1.0"},
        request_body=None,
        status_code=200,
        response_headers={"Content-Type": "application/json"},
        response_body={"booking_id": "B-999"},
        latency_ms=32.1,
    )

    # Verify chain integrity
    valid, msg, count = AuditLogger.verify_chain(log_file)
    assert valid, f"Audit chain verification failed: {msg}"
    assert count == 3


def test_audit_chain_tampering_detection(tmp_path: Path) -> None:
    log_file = tmp_path / "tampered_audit.jsonl"
    logger = AuditLogger(log_path=log_file)

    logger.log_interaction(
        method="GET",
        url="http://127.0.0.1:8000/v1",
        request_headers={},
        request_body=None,
        status_code=200,
        response_headers={},
        response_body="OK",
        latency_ms=10.0,
    )

    logger.log_interaction(
        method="GET",
        url="http://127.0.0.1:8000/v2",
        request_headers={},
        request_body=None,
        status_code=200,
        response_headers={},
        response_body="OK",
        latency_ms=12.0,
    )

    # Corrupt line 2
    lines = log_file.read_text(encoding="utf-8").splitlines()
    corrupted_entry = json.loads(lines[1])
    corrupted_entry["response"]["status_code"] = 500  # Altered!
    lines[1] = json.dumps(corrupted_entry)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Verify should detect mismatch
    valid, msg, line_no = AuditLogger.verify_chain(log_file)
    assert not valid
    assert "Entry hash mismatch" in msg
    assert line_no == 2
