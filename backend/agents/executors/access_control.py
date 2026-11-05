"""Access Control Attack Executor (BOLA / IDOR & BOPLA / Mass Assignment)."""

import contextlib
import re
import uuid

from backend.agents.executors.base import BaseAttackExecutor
from backend.agents.models import (
    AttackPlanItem,
    SeverityLevel,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from backend.agents.verifier import DoubleProofVerifier


class AccessControlExecutor(BaseAttackExecutor):
    """Executes BOLA/IDOR and BOPLA/Mass Assignment vulnerability vectors."""

    async def execute(self, plan_item: AttackPlanItem, base_url: str) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path.lower()

        if "promote" in path or "role" in path:
            findings.extend(await self._test_privilege_escalation(plan_item, base_url))
        elif plan_item.category == VulnerabilityCategory.BOLA:
            findings.extend(await self._test_bola(plan_item, base_url))
        elif plan_item.category == VulnerabilityCategory.BOPLA:
            findings.extend(await self._test_bopla(plan_item, base_url))

        return findings

    async def _test_privilege_escalation(
        self, plan_item: AttackPlanItem, base_url: str
    ) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path
        method = plan_item.method
        sample_ids = plan_item.context.get("sample_ids") or []
        user_candidates = list(sample_ids) + ["USR_ALPHA_SUB", "USR_SUB_1", "1"]
        target_uid = next(
            (u for u in user_candidates if "USR_" in str(u) or "sub" in str(u).lower()),
            "USR_ALPHA_SUB",
        )
        resolved_path = re.sub(r"\{[^}]+\}", str(target_uid), path)
        target_url = f"{base_url.rstrip('/')}/{resolved_path.lstrip('/')}"

        sub_headers = {"Authorization": "Bearer tok_USR_ALPHA_SUB"}
        primary_req = {"method": method, "url": target_url, "headers": sub_headers}
        try:
            primary_resp = await self.client.request(
                method=method, url=target_url, headers=sub_headers
            )
            if primary_resp.status_code == 200:
                control_req = {
                    "method": method,
                    "url": f"{target_url}-invalid-xyz",
                    "headers": sub_headers,
                }
                control_resp = await self.client.request(
                    method=method, url=f"{target_url}-invalid-xyz", headers=sub_headers
                )
                control_succeeded = control_resp.status_code in {404, 400, 422}
                proof = DoubleProofVerifier.verify(
                    primary_req=primary_req,
                    primary_resp=primary_resp,
                    primary_succeeded=True,
                    control_req=control_req,
                    control_resp=control_resp,
                    control_succeeded=control_succeeded,
                    notes="Sub-agent user successfully executed role promotion without administrative authorization.",
                )
                if proof.is_verified():
                    findings.append(
                        VulnerabilityFinding(
                            title=f"Sub-Agent Horizontal / Vertical Privilege Escalation on {method} {path}",
                            category=VulnerabilityCategory.BOLA,
                            severity=SeverityLevel.CRITICAL,
                            target_endpoint=path,
                            method=method,
                            description=(
                                f"Endpoint {method} {path} allows standard sub-agents to promote themselves or others "
                                f"to administrator status without verifying administrative privileges."
                            ),
                            proof=proof,
                            cwe_id="CWE-269",
                            remediation=(
                                "Enforce role-based access control (RBAC). Verify that the requesting identity possesses "
                                "the Admin role before executing user role or privilege mutations."
                            ),
                        )
                    )
        except Exception:
            pass
        return findings

    async def _test_bola(
        self, plan_item: AttackPlanItem, base_url: str
    ) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path
        method = plan_item.method

        # Probe cross-tenant ID access with generic test tokens/identities and discovered samples
        sample_ids = plan_item.context.get("sample_ids") or []
        test_ids = list(sample_ids) + [
            "1",
            "100",
            "ITEM-001",
            "REF-001",
        ]

        target_urls: list[str] = []
        if "{" in path:
            for tid in test_ids:
                substituted = re.sub(r"\{[^}]+\}", str(tid), path)
                target_urls.append(f"{base_url.rstrip('/')}/{substituted.lstrip('/')}")
        else:
            target_urls.append(f"{base_url.rstrip('/')}/{path.lstrip('/')}")

        for target_url in target_urls:
            # 1. Unauthenticated access check on sensitive endpoints
            if method == "GET":
                try:
                    unauth_resp = await self.client.request(
                        method="GET",
                        url=target_url,
                    )
                    if unauth_resp.status_code == 200 and "{" in path:
                        ctrl_url = f"{target_url}-invalid-probe-xyz"
                        ctrl_resp = await self.client.request(method="GET", url=ctrl_url)
                        if ctrl_resp.status_code in {404, 400, 422}:
                            proof = DoubleProofVerifier.verify(
                                primary_req={"method": "GET", "url": target_url, "headers": {}},
                                primary_resp=unauth_resp,
                                primary_succeeded=True,
                                control_req={"method": "GET", "url": ctrl_url, "headers": {}},
                                control_resp=ctrl_resp,
                                control_succeeded=True,
                                notes="Endpoint returned 200 without Authorization header; control confirmed 404 for invalid ID.",
                            )
                            if proof.is_verified():
                                findings.append(
                                    VulnerabilityFinding(
                                        title=f"Unauthenticated Access to Protected Resource on GET {path}",
                                        category=VulnerabilityCategory.BOLA,
                                        severity=SeverityLevel.CRITICAL,
                                        target_endpoint=path,
                                        method="GET",
                                        description=(
                                            f"Endpoint GET {path} serves sensitive customer records without requiring "
                                            f"authentication tokens or session verification."
                                        ),
                                        proof=proof,
                                        cwe_id="CWE-306",
                                        remediation=(
                                            "Require valid Bearer token authentication headers on all data retrieval routes."
                                        ),
                                    )
                                )
                                break
                except Exception:
                    pass

            # 2. Cross-tenant access with foreign agency token
            primary_headers = {
                "Authorization": "Bearer tok_USR_BETA_AGENT",
            }
            primary_req = {
                "method": method,
                "url": target_url,
                "headers": primary_headers,
            }

            try:
                primary_resp = await self.client.request(
                    method=method,
                    url=target_url,
                    headers=primary_headers,
                )
            except Exception:
                continue

            # Check if resource is accessible without strict tenant ownership validation
            if primary_resp.status_code == 200:
                # Negative control: Attempt request for a completely bogus random non-existent ID
                control_url = f"{target_url}-nonexistent-{uuid.uuid4().hex[:6]}"

                control_headers = primary_headers.copy()
                control_req = {
                    "method": method,
                    "url": control_url,
                    "headers": control_headers,
                }

                try:
                    control_resp = await self.client.request(
                        method=method,
                        url=control_url,
                        headers=control_headers,
                    )
                except Exception:
                    continue

                # Control succeeds if nonexistent ID returns 404 or 400 (confirming endpoint is dynamic and not static 200)
                control_succeeded = control_resp.status_code in {404, 400, 422}
                primary_succeeded = primary_resp.status_code == 200

                proof = DoubleProofVerifier.verify(
                    primary_req=primary_req,
                    primary_resp=primary_resp,
                    primary_succeeded=primary_succeeded,
                    control_req=control_req,
                    control_resp=control_resp,
                    control_succeeded=control_succeeded,
                    notes="Primary exploit accessed foreign tenant record; negative control confirmed 404 for invalid identifier.",
                )

                if proof.is_verified():
                    findings.append(
                        VulnerabilityFinding(
                            title=f"BOLA / Broken Object-Level Authorization on {method} {path}",
                            category=VulnerabilityCategory.BOLA,
                            severity=SeverityLevel.CRITICAL,
                            target_endpoint=path,
                            method=method,
                            description=(
                                f"Endpoint {method} {path} allows tenant to access or view records "
                                f"belonging to other organizations without tenant boundary verification."
                            ),
                            proof=proof,
                            cwe_id="CWE-639",
                            remediation=(
                                "Enforce authorization checks validating that the requesting tenant "
                                "owns the referenced resource identifier before returning data."
                            ),
                        )
                    )
                    break

        return findings

    async def _test_bopla(
        self, plan_item: AttackPlanItem, base_url: str
    ) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path
        method = plan_item.method
        target_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

        # Test injecting privileged properties
        privileged_payloads = [
            {"is_verified": True, "credit_limit": 999999.0},
            {"role": "SuperAdmin", "is_admin": True, "status": "CONFIRMED"},
            {"role": "Admin", "privileges": ["ALL"]},
        ]

        auth_headers = {
            "Authorization": "Bearer test-alpha-token",
            "Content-Type": "application/json",
        }

        for priv in privileged_payloads:
            primary_req = {
                "method": method,
                "url": target_url,
                "json": priv,
                "headers": auth_headers,
            }

            try:
                primary_resp = await self.client.request(
                    method=method,
                    url=target_url,
                    json=priv,
                    headers=auth_headers,
                )
            except Exception:
                continue

            # Check if privileged field was accepted and reflected in response
            accepted_priv = False
            resp_data = {}
            if primary_resp.status_code in {200, 201}:
                try:
                    resp_data = primary_resp.json()
                    for k, v in priv.items():
                        if resp_data.get(k) == v:
                            accepted_priv = True
                            break
                except Exception:
                    pass

            if accepted_priv:
                # Negative control: Send payload without privileged properties
                control_payload = {"name": "Test Baseline"}
                control_req = {
                    "method": method,
                    "url": target_url,
                    "json": control_payload,
                    "headers": auth_headers,
                }

                try:
                    control_resp = await self.client.request(
                        method=method,
                        url=target_url,
                        json=control_payload,
                        headers=auth_headers,
                    )
                except Exception:
                    continue

                control_data = {}
                with contextlib.suppress(Exception):
                    control_data = control_resp.json()

                # Control succeeds if benign update is processed normally without schema errors
                control_succeeded = (
                    control_resp.status_code in {200, 201}
                    and control_data.get("name") == "Test Baseline"
                )

                proof = DoubleProofVerifier.verify(
                    primary_req=primary_req,
                    primary_resp=primary_resp,
                    primary_succeeded=True,
                    control_req=control_req,
                    control_resp=control_resp,
                    control_succeeded=control_succeeded,
                    notes=f"Primary request accepted unauthorized privileged fields ({list(priv.keys())}); control established baseline.",
                )

                if proof.is_verified():
                    findings.append(
                        VulnerabilityFinding(
                            title=f"Mass Assignment / BOPLA on {method} {path}",
                            category=VulnerabilityCategory.BOPLA,
                            severity=SeverityLevel.HIGH,
                            target_endpoint=path,
                            method=method,
                            description=(
                                f"Endpoint {method} {path} binds arbitrary input fields directly to internal models, "
                                f"permitting unauthorized elevation of privileges or status manipulation."
                            ),
                            proof=proof,
                            cwe_id="CWE-915",
                            remediation=(
                                "Use strict data transfer objects (DTOs) and input schemas that whitelist "
                                "only client-modifiable fields. Ignore or reject unlisted properties."
                            ),
                        )
                    )
                    break
                    break

        return findings
