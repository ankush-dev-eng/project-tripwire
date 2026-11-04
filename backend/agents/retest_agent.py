"""Retest Automation Engine for TRIPWIRE.

Replays verified exploit vectors against target endpoints, verifies patch effectiveness,
and automates finding lifecycle transitions (VERIFIED -> FIXED -> REGRESSION).
Strictly uses SafeHttpClient for all outbound traffic.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from backend.agents.models import (
    FindingStatus,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from backend.safety.http_client import SafeHttpClient


@dataclass
class RetestResult:
    """Outcome of an automated retest verification."""

    finding_id: str
    target_endpoint: str
    method: str
    previous_status: FindingStatus
    new_status: FindingStatus
    is_fixed: bool
    status_code: int
    response_preview: str
    rationale: str
    retested_at: str


class RetestAgent:
    """Automates re-execution of reproduction vectors to verify patches and regressions."""

    def __init__(self, client: SafeHttpClient) -> None:
        self.client = client

    async def retest_finding(
        self,
        finding: VulnerabilityFinding,
        custom_headers: dict[str, str] | None = None,
    ) -> RetestResult:
        """Replay reproduction request and evaluate whether the vulnerability remains active."""
        prev_status = finding.status
        primary_req = finding.proof.primary_request or {}

        method = primary_req.get("method") or finding.method or "GET"
        url = primary_req.get("url") or finding.target_endpoint
        headers = dict(primary_req.get("headers") or {})
        if custom_headers:
            headers.update(custom_headers)

        json_data = primary_req.get("body") or primary_req.get("json")
        params = primary_req.get("params")

        # Execute replay via SafeHttpClient
        status_code = 0
        resp_text = ""
        try:
            resp = await self.client.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data,
                params=params,
            )
            status_code = resp.status_code
            resp_text = resp.text
        except Exception as e:
            resp_text = f"Retest execution error: {e}"

        # Evaluate fix criteria
        is_fixed, rationale = self._evaluate_fix(
            finding=finding,
            status_code=status_code,
            resp_text=resp_text,
            json_payload=json_data,
        )

        if is_fixed:
            new_status = FindingStatus.FIXED
        else:
            if prev_status == FindingStatus.FIXED:
                new_status = FindingStatus.REGRESSION
            else:
                new_status = finding.status

        now_iso = datetime.now(UTC).isoformat()
        result = RetestResult(
            finding_id=finding.finding_id,
            target_endpoint=finding.target_endpoint,
            method=method,
            previous_status=prev_status,
            new_status=new_status,
            is_fixed=is_fixed,
            status_code=status_code,
            response_preview=resp_text[:300] if resp_text else "",
            rationale=rationale,
            retested_at=now_iso,
        )

        # Update finding status and history in metadata
        finding.status = new_status
        history = finding.metadata.setdefault("retest_history", [])
        history.append(
            {
                "timestamp": now_iso,
                "status_code": status_code,
                "is_fixed": is_fixed,
                "previous_status": prev_status.value,
                "new_status": new_status.value,
                "rationale": rationale,
            }
        )

        return result

    async def retest_all(
        self,
        findings: list[VulnerabilityFinding],
        custom_headers: dict[str, str] | None = None,
    ) -> list[RetestResult]:
        """Batch retest a collection of findings."""
        results: list[RetestResult] = []
        for finding in findings:
            res = await self.retest_finding(finding, custom_headers=custom_headers)
            results.append(res)
        return results

    def _evaluate_fix(
        self,
        finding: VulnerabilityFinding,
        status_code: int,
        resp_text: str,
        json_payload: Any = None,
    ) -> tuple[bool, str]:
        """Determine if exploit was blocked or remediated."""
        cat = finding.category

        # Standard access control & auth fixes reject unauthorized payloads with 4xx
        if cat in {
            VulnerabilityCategory.BOLA,
            VulnerabilityCategory.BOPLA,
            VulnerabilityCategory.AUTH_SESSION,
            VulnerabilityCategory.SSRF,
        }:
            if status_code in {400, 401, 403, 404, 422}:
                return (
                    True,
                    f"Exploit rejected with HTTP {status_code} (proper authorization/validation enforced)",
                )
            return (
                False,
                f"Endpoint still accepted unauthorized request with HTTP {status_code}",
            )

        # Business logic: fare tampering, seat count, state machine violations
        if cat == VulnerabilityCategory.BUSINESS_LOGIC:
            if status_code in {400, 403, 422}:
                return (
                    True,
                    f"Tampered business logic rejected with HTTP {status_code}",
                )
            if status_code in {200, 201}:
                # Check if price tampering was ignored (e.g. recalculated correctly)
                if json_payload and isinstance(json_payload, dict):
                    tampered_amt = json_payload.get("total_amount")
                    if tampered_amt is not None:
                        try:
                            import json

                            data = json.loads(resp_text)
                            resp_amt = data.get("total_amount")
                            if (
                                resp_amt is not None
                                and abs(float(resp_amt) - float(tampered_amt)) < 1e-4
                            ):
                                return (
                                    False,
                                    f"Business logic violation accepted with HTTP {status_code} (tampered total_amount={tampered_amt})",
                                )
                            elif resp_amt is not None:
                                return (
                                    True,
                                    f"Tampered amount {tampered_amt} was rejected/recalculated by server to {resp_amt}",
                                )
                        except Exception:
                            pass
                return (
                    False,
                    f"Business logic violation accepted with HTTP {status_code}",
                )
            return (False, f"Unexpected response status HTTP {status_code}")

        # Data exposure: sensitive PAN, CVV, or internal keys
        if cat == VulnerabilityCategory.DATA_EXPOSURE:
            if status_code in {403, 404}:
                return True, f"Exposed resource restricted with HTTP {status_code}"
            # Check for masking (e.g. **** or missing raw card numbers)
            if "****" in resp_text or "REDACTED" in resp_text:
                return (
                    True,
                    "Sensitive fields properly masked in response body",
                )
            # If original unmasked card sequence is no longer found
            p_resp = finding.proof.primary_response.get("body_preview", "")
            if "card_pan" in p_resp and "4111" in p_resp and "4111111111111111" not in resp_text:
                return True, "Raw unmasked PAN removed or masked"
            return (
                False,
                f"Data exposure remains active with HTTP {status_code}",
            )

        # Injection: SQLi, command, SSTI
        if cat == VulnerabilityCategory.INJECTION:
            if status_code in {400, 403, 422}:
                return True, f"Injection payload blocked with HTTP {status_code}"
            # If input was escaped or sanitized rather than executing injected syntax
            if "syntax error" not in resp_text.lower() and "sqlite" not in resp_text.lower():
                return True, "No injection syntax errors or execution detected"
            return (
                False,
                f"Injection vulnerability active with HTTP {status_code}",
            )

        # API Hygiene: stack traces, debug envs, retired endpoints
        if cat == VulnerabilityCategory.API_HYGIENE:
            if status_code in {403, 404}:
                return (
                    True,
                    f"Exposed hygiene endpoint disabled or protected with HTTP {status_code}",
                )
            if "Traceback" not in resp_text and "password" not in resp_text.lower():
                return True, "Sensitive debug/error details no longer exposed"
            return (
                False,
                f"Hygiene issue persists with HTTP {status_code}",
            )

        # Default fallback: 4xx indicates request rejection
        if status_code in {400, 401, 403, 404, 422}:
            return True, f"Request rejected with HTTP {status_code}"
        return False, f"Request succeeded with HTTP {status_code}"
