"""Tests for Evidence Redactor."""

from backend.safety.redactor import redact_data, redact_text


def test_redact_credit_cards() -> None:
    raw = "Customer card 4111111111111111 paid for booking."
    redacted = redact_text(raw)
    assert "4111111111111111" not in redacted
    assert "[REDACTED_CARD]" in redacted


def test_redact_jwt() -> None:
    sample_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4B_fake_signature"
    )
    raw = f"Header: Bearer {sample_jwt}"
    redacted = redact_text(raw)
    assert sample_jwt not in redacted
    assert "[REDACTED_TOKEN]" in redacted or "[REDACTED_JWT]" in redacted


def test_redact_json_dictionary() -> None:
    payload = {
        "agency_id": "AGY-101",
        "user_email": "agent@travel.com",
        "password": "SuperSecretPassword123!",
        "payment": {
            "card_number": "5500000000000004",
            "cvv": "999",
            "amount": 450.00,
        },
        "passengers": [
            {"name": "Jane Doe", "passport_number": "A12345678"},
        ],
    }
    redacted = redact_data(payload)

    assert redacted["password"] == "[REDACTED]"
    assert redacted["payment"]["card_number"] == "[REDACTED]"
    assert redacted["payment"]["cvv"] == "[REDACTED]"
    assert redacted["payment"]["amount"] == 450.00
    assert redacted["passengers"][0]["passport_number"] == "[REDACTED]"
    assert redacted["agency_id"] == "AGY-101"
