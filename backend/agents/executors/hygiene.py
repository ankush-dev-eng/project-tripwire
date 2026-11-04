"""API Hygiene Attack Executor (Debug Endpoints and Stack Trace Disclosure)."""

import re

from backend.agents.executors.base import BaseAttackExecutor
from backend.agents.models import (
    AttackPlanItem,
    SeverityLevel,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from backend.agents.verifier import DoubleProofVerifier

STACK_TRACE_PATTERNS = [
    re.compile(r"traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r'file ".*?", line \d+', re.IGNORECASE),
    re.compile(r"fastapi\.exceptions", re.IGNORECASE),
    re.compile(r"starlette\.middleware", re.IGNORECASE),
    re.compile(r"internal server error", re.IGNORECASE),
]


class HygieneExecutor(BaseAttackExecutor):
    """Executes API hygiene and information disclosure auditing vectors."""

    async def execute(self, plan_item: AttackPlanItem, base_url: str) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path
        method = plan_item.method
        target_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        path_lower = path.lower()

        # 1. Debug / Secret Environment Endpoint Exposure
        if any(k in path_lower for k in ["debug", "env", "metrics", "secret"]):
            primary_req = {"method": method, "url": target_url}
            try:
                primary_resp = await self.client.request(method=method, url=target_url)
            except Exception:
                primary_resp = None

            if primary_resp and primary_resp.status_code == 200:
                resp_text = primary_resp.text
                if any(
                    k in resp_text.lower()
                    for k in [
                        "database_url",
                        "secret_key",
                        "api_key",
                        "password",
                        "jwt_secret",
                    ]
                ):
                    # Negative control: Nonexistent route returns 404 (not open 200)
                    control_url = f"{base_url.rstrip('/')}/nonexistent_debug_probe_404"
                    control_req = {"method": "GET", "url": control_url}
                    try:
                        control_resp = await self.client.request(method="GET", url=control_url)
                    except Exception:
                        control_resp = None

                    control_succeeded = control_resp is not None and control_resp.status_code in {
                        404,
                        400,
                    }

                    proof = DoubleProofVerifier.verify(
                        primary_req=primary_req,
                        primary_resp=primary_resp,
                        primary_succeeded=True,
                        control_req=control_req,
                        control_resp=control_resp,
                        control_succeeded=control_succeeded,
                        notes="Debug endpoint returned environment secrets; control confirmed non-existent route returns 404.",
                    )

                    if proof.is_verified():
                        findings.append(
                            VulnerabilityFinding(
                                title=f"Exposed Debug / Environment Variables Endpoint on {method} {path}",
                                category=VulnerabilityCategory.API_HYGIENE,
                                severity=SeverityLevel.CRITICAL,
                                target_endpoint=path,
                                method=method,
                                description=(
                                    f"Endpoint {method} {path} publicly exposes environment variables, secrets, "
                                    f"and internal infrastructure configuration details."
                                ),
                                proof=proof,
                                cwe_id="CWE-215",
                                remediation=(
                                    "Disable debug and environment diagnostic routes in production environments. "
                                    "Restrict administrative inspection endpoints behind network-level controls."
                                ),
                            )
                        )

        # 2. Stack Trace / Verbose Error Disclosure Probe
        if any(k in path_lower for k in ["error", "probe", "booking"]):
            error_probe_url = f"{base_url.rstrip('/')}/api/v3/bookings/error-probe?debug=1"
            primary_req = {"method": "GET", "url": error_probe_url}
            try:
                primary_resp = await self.client.request(method="GET", url=error_probe_url)
            except Exception:
                primary_resp = None

            if primary_resp and primary_resp.status_code == 500:
                resp_text = primary_resp.text
                has_traceback = any(p.search(resp_text) for p in STACK_TRACE_PATTERNS)

                if has_traceback:
                    # Negative control: Normal GET /api/v3/flights/search returns clean response without traceback
                    control_url = f"{base_url.rstrip('/')}/api/v3/flights/search"
                    control_req = {"method": "GET", "url": control_url}
                    try:
                        control_resp = await self.client.request(method="GET", url=control_url)
                    except Exception:
                        control_resp = None

                    control_succeeded = (
                        control_resp is not None
                        and control_resp.status_code == 200
                        and not any(p.search(control_resp.text) for p in STACK_TRACE_PATTERNS)
                    )

                    proof = DoubleProofVerifier.verify(
                        primary_req=primary_req,
                        primary_resp=primary_resp,
                        primary_succeeded=True,
                        control_req=control_req,
                        control_resp=control_resp,
                        control_succeeded=control_succeeded,
                        notes="Error probe returned full Python exception traceback and file paths.",
                    )

                    if proof.is_verified():
                        findings.append(
                            VulnerabilityFinding(
                                title="Verbose Error Traceback / Stack Trace Disclosure",
                                category=VulnerabilityCategory.API_HYGIENE,
                                severity=SeverityLevel.LOW,
                                target_endpoint="/api/v3/bookings/error-probe",
                                method="GET",
                                description=(
                                    "Application returns raw exception tracebacks and runtime internal source paths "
                                    "upon encountering unhandled server errors."
                                ),
                                proof=proof,
                                cwe_id="CWE-209",
                                remediation=(
                                    "Configure a global exception handler that returns standardized, generic JSON error envelopes "
                                    "and logs internal tracebacks securely to central logging."
                                ),
                            )
                        )

        return findings
