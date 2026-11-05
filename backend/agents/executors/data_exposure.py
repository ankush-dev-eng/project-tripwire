"""Data Exposure Attack Executor (Raw Card PAN, CVV, Passwords, Secrets)."""

import re

from backend.agents.executors.base import BaseAttackExecutor
from backend.agents.models import (
    AttackPlanItem,
    SeverityLevel,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from backend.agents.verifier import DoubleProofVerifier


# Standard Luhn check
def is_valid_luhn(card_number: str) -> bool:
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


# PAN Regex: Visa, MasterCard, Amex, Discover
PAN_REGEX = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
)
CVV_REGEX = re.compile(
    r'["\']?(?:cvv|cvc|security_code)["\']?\s*:\s*["\']?([0-9]{3,4})["\']?', re.IGNORECASE
)
SECRET_REGEX = re.compile(
    r'["\']?(?:api_key|secret|password|supplier_token)["\']?\s*:\s*["\']([^"\'\s]{8,})["\']',
    re.IGNORECASE,
)


class DataExposureExecutor(BaseAttackExecutor):
    """Executes sensitive data exposure audits across endpoint responses."""

    async def execute(self, plan_item: AttackPlanItem, base_url: str) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path
        method = plan_item.method
        target_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

        # Resolve path parameter if templated (e.g. {booking_id})
        sample_ids = plan_item.context.get("sample_ids") or []
        test_ids = list(sample_ids) + [
            "1",
            "100",
            "test-item-01",
        ]
        resolved_urls: list[str] = []
        if "{" in path:
            for tid in test_ids:
                resolved_urls.append(
                    f"{base_url.rstrip('/')}/{re.sub(r'\{[^}]+\}', str(tid), path).lstrip('/')}"
                )
        else:
            resolved_urls.append(target_url)

        # Also probe error-probe endpoints with debug=true
        if "error" in path.lower() or "probe" in path.lower():
            resolved_urls.append(f"{target_url}?debug=true")

        for url in resolved_urls:
            primary_req = {"method": method, "url": url}
            try:
                primary_resp = await self.client.request(method=method, url=url)
            except Exception:
                continue

            if primary_resp.status_code not in {200, 500}:
                continue

            resp_text = primary_resp.text

            # Check for unmasked PAN, CVV, secret, or PII leak in tracebacks
            pan_matches = PAN_REGEX.findall(resp_text)
            valid_pans = [m for m in pan_matches if is_valid_luhn(m)]
            cvv_match = CVV_REGEX.search(resp_text)
            secret_match = SECRET_REGEX.search(resp_text)
            has_pii_leak = (
                any(k in resp_text.lower() for k in ["passport", "passenger_name", "local_vars"])
                and "traceback" in resp_text.lower()
            )

            has_exposure = bool(valid_pans or cvv_match or secret_match or has_pii_leak)

            if has_exposure:
                # Negative control: Verify that a clean or 404 response doesn't leak data
                control_url = f"{url}-nonexistent-test"
                control_req = {"method": method, "url": control_url}
                try:
                    control_resp = await self.client.request(method=method, url=control_url)
                except Exception:
                    continue

                control_succeeded = control_resp.status_code in {
                    200,
                    404,
                    400,
                    422,
                } and not PAN_REGEX.search(control_resp.text)

                details: list[str] = []
                if valid_pans:
                    masked_pan = valid_pans[0][:4] + "********" + valid_pans[0][-4:]
                    details.append(f"Unmasked Credit Card PAN ({masked_pan})")
                if cvv_match:
                    details.append("Card Security Code (CVV)")
                if secret_match:
                    details.append("Plaintext Supplier/API Secret")
                if has_pii_leak:
                    details.append("PII and Traveller Passport Number in Error Traceback")

                proof = DoubleProofVerifier.verify(
                    primary_req=primary_req,
                    primary_resp=primary_resp,
                    primary_succeeded=True,
                    control_req=control_req,
                    control_resp=control_resp,
                    control_succeeded=control_succeeded,
                    notes=f"Detected sensitive exposure in response: {', '.join(details)}.",
                )

                if proof.is_verified():
                    findings.append(
                        VulnerabilityFinding(
                            title=f"Excessive Sensitive Data Exposure ({', '.join(details)}) on {method} {path}",
                            category=VulnerabilityCategory.DATA_EXPOSURE,
                            severity=SeverityLevel.HIGH,
                            target_endpoint=path,
                            method=method,
                            description=(
                                f"Endpoint {method} {path} returns sensitive financial/PII data ({', '.join(details)}) "
                                f"in cleartext without masking or field-level redaction."
                            ),
                            proof=proof,
                            cwe_id="CWE-200",
                            remediation=(
                                "Mask all Payment Card Industry (PCI) data according to PCI-DSS standards (mask all but first 6 and last 4 digits). "
                                "Never persist or return CVV codes after transaction authorization."
                            ),
                        )
                    )
                    break

        return findings
