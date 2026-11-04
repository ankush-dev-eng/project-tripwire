"""Server-Side Attack Executor (SSRF, Webhook Injection, and Open Redirect)."""

from backend.agents.executors.base import BaseAttackExecutor
from backend.agents.models import (
    AttackPlanItem,
    SeverityLevel,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from backend.agents.verifier import DoubleProofVerifier


class ServerSideExecutor(BaseAttackExecutor):
    """Executes SSRF and Webhook Injection vulnerability vectors."""

    async def execute(self, plan_item: AttackPlanItem, base_url: str) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path
        method = plan_item.method
        target_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

        # Target parameters that accept URLs or destinations
        url_params = list(plan_item.target_params) if plan_item.target_params else []
        for default_p in ["callback_url", "webhook_url", "url", "sync_url", "target"]:
            if default_p not in url_params:
                url_params.append(default_p)

        # Probe internal targets within scope (e.g. localhost internal API)
        internal_payloads = [
            "http://127.0.0.1:8000/internal/supplier-sync",
            "http://localhost:8000/internal/metrics",
            "http://169.254.169.254/latest/meta-data/",
        ]

        for param in url_params:
            for probe_url in internal_payloads:
                primary_payload = {
                    param: probe_url,
                    "event": "booking.confirmed",
                }
                primary_req = {
                    "method": method,
                    "url": target_url,
                    "json": primary_payload,
                }

                try:
                    primary_resp = await self.client.request(
                        method=method,
                        url=target_url,
                        json=primary_payload if method != "GET" else None,
                        params=primary_payload if method == "GET" else None,
                    )
                except Exception:
                    continue

                # Primary exploit succeeds if internal URL or external destination was accepted or redirected
                if primary_resp.status_code in {200, 201, 202, 301, 302, 307, 308}:
                    # Negative control: Send empty payload (missing required parameter)
                    control_payload = {}
                    control_req = {
                        "method": method,
                        "url": target_url,
                        "json": control_payload,
                    }

                    try:
                        control_resp = await self.client.request(
                            method=method,
                            url=target_url,
                            json=control_payload if method != "GET" else None,
                            params=control_payload if method == "GET" else None,
                        )
                    except Exception:
                        continue

                    control_succeeded = control_resp.status_code in {
                        400,
                        422,
                    }

                    proof = DoubleProofVerifier.verify(
                        primary_req=primary_req,
                        primary_resp=primary_resp,
                        primary_succeeded=True,
                        control_req=control_req,
                        control_resp=control_resp,
                        control_succeeded=control_succeeded,
                        notes=f"Accepted internal loopback/metadata target on parameter '{param}'. Negative control rejected invalid URL format.",
                    )

                    if proof.is_verified():
                        findings.append(
                            VulnerabilityFinding(
                                title=f"Server-Side Request Forgery (SSRF) / Insecure Webhook on {method} {path}",
                                category=VulnerabilityCategory.SSRF,
                                severity=SeverityLevel.CRITICAL,
                                target_endpoint=path,
                                method=method,
                                description=(
                                    f"Endpoint {method} {path} accepts arbitrary server-side destination URLs on parameter '{param}', "
                                    f"permitting internal port scanning, loopback service access, or cloud metadata exfiltration."
                                ),
                                proof=proof,
                                cwe_id="CWE-918",
                                remediation=(
                                    "Validate destination URLs against an allowlist of permitted external domains. "
                                    "Block loopback (127.0.0.0/8), private RFC 1918 subnets, and cloud metadata (169.254.169.254) addresses."
                                ),
                            )
                        )
                        break

        return findings
