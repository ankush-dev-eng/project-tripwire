"""Evidence Redactor for PII and Secret Sanitization."""

from collections.abc import Mapping
import re
from typing import Any

# Patterns for sensitive data redaction
CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"
)
PASSPORT_PATTERN = re.compile(r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b", re.IGNORECASE)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b")
AUTH_HEADER_PATTERN = re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)

SENSITIVE_JSON_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "cvv",
    "cvc",
    "card_number",
    "credit_card",
    "passport",
    "passport_number",
    "refresh_token",
}


def redact_text(text: str) -> str:
    """Redact sensitive patterns from a raw text string."""
    if not text:
        return text

    # Redact Authorization tokens
    text = AUTH_HEADER_PATTERN.sub(r"\1[REDACTED_TOKEN]", text)
    # Redact JWTs
    text = JWT_PATTERN.sub("[REDACTED_JWT]", text)
    # Redact Credit Cards
    text = CREDIT_CARD_PATTERN.sub("[REDACTED_CARD]", text)
    # Redact Passports
    text = PASSPORT_PATTERN.sub("[REDACTED_PASSPORT]", text)

    return text


def redact_data(data: Any) -> Any:
    """Recursively redact dictionary, list, or primitive data."""
    if isinstance(data, str):
        return redact_text(data)
    elif isinstance(data, Mapping):
        redacted_dict: dict[str, Any] = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            if any(sensitive in key_lower for sensitive in SENSITIVE_JSON_KEYS):
                redacted_dict[key] = "[REDACTED]"
            else:
                redacted_dict[key] = redact_data(value)
        return redacted_dict
    elif isinstance(data, list):
        return [redact_data(item) for item in data]
    return data
