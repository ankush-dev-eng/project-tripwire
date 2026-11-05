"""Business Logic Attack Executor (Fare Tampering, Double Refund, Workflow Step Skips)."""

import contextlib
import re

from backend.agents.executors.base import BaseAttackExecutor
from backend.agents.models import (
    AttackPlanItem,
    SeverityLevel,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from backend.agents.verifier import DoubleProofVerifier


class BusinessLogicExecutor(BaseAttackExecutor):
    """Executes business logic tampering and race condition testing vectors."""

    async def execute(self, plan_item: AttackPlanItem, base_url: str) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path
        path_lower = path.lower()

        # 1. Price / Fare Tampering
        if any(k in path_lower for k in ["pay", "fare", "book", "hold", "wallet", "invoice"]):
            findings.extend(await self._test_fare_tampering(plan_item, base_url))

        # 2. Double Refund / Cancellation Abuse
        if "refund" in path_lower or "cancel" in path_lower:
            findings.extend(await self._test_double_refund(plan_item, base_url))

        # 3. Workflow Step Skipping
        if "pay" in path_lower or "confirm" in path_lower:
            findings.extend(await self._test_step_skipping(plan_item, base_url))

        return findings

    async def _test_fare_tampering(
        self, plan_item: AttackPlanItem, base_url: str
    ) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path
        method = plan_item.method
        sample_ids = plan_item.context.get("sample_ids") or []
        flight_candidates = list(sample_ids) + ["FL-1", "FL-100", "TEST-ITEM-1"]
        flight_id = next(
            (f for f in flight_candidates if "FL-" in str(f)),
            sample_ids[0] if sample_ids else "FL-100",
        )

        resolved_path = re.sub(r"\{[^}]+\}", str(flight_id), path)
        target_url = f"{base_url.rstrip('/')}/{resolved_path.lstrip('/')}"

        # Test negative price, zero price, client-controlled low total_amount, and negative seat quantity
        tampered_payloads = [
            {
                "flight_id": flight_id,
                "total_amount": 1.0,
                "seat_count": 1,
                "passengers": [{"name": "Tamper Test"}],
            },
            {
                "flight_id": flight_id,
                "total_amount": 650.0,
                "seat_count": -1,
                "passengers": [{"name": "Negative Seat Test"}],
            },
            {
                "flight_id": flight_id,
                "total_amount": 0.0,
                "seat_count": 1,
                "passengers": [{"name": "Tamper Test"}],
            },
            {
                "booking_id": flight_id,
                "amount": -500.0,
                "currency": "USD",
            },
            {"booking_id": flight_id, "amount": 0.0, "currency": "USD"},
        ]

        auth_headers = {"Authorization": "Bearer tok_USR_ALPHA_AGENT"}

        for payload in tampered_payloads:
            primary_req = {
                "method": method,
                "url": target_url,
                "json": payload,
                "headers": auth_headers,
            }

            try:
                primary_resp = await self.client.request(
                    method=method,
                    url=target_url,
                    json=payload,
                    headers=auth_headers,
                )
            except Exception:
                continue

            # Primary exploit succeeds if tampered amount or negative seats was accepted with 200/201
            if primary_resp.status_code in {200, 201}:
                resp_text = primary_resp.text
                resp_data = {}
                with contextlib.suppress(Exception):
                    resp_data = primary_resp.json()

                is_negative_qty = payload.get("seat_count", 1) < 0 and resp_data.get(
                    "seat_count"
                ) == payload.get("seat_count")
                is_tampered_accepted = False
                if (
                    "total_amount" in payload
                    and resp_data.get("total_amount") == payload["total_amount"]
                    or "amount" in payload
                    and payload["amount"] <= 0
                    and ("success" in resp_text.lower() or "confirmed" in resp_text.lower())
                ):
                    is_tampered_accepted = True

                if is_negative_qty or is_tampered_accepted:
                    # Negative control: Send request with missing body or invalid flight
                    control_payload = {
                        "flight_id": "FL-NONEXISTENT-999",
                        "seat_count": 1,
                        "passengers": [],
                    }
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

                    control_succeeded = control_resp.status_code in {400, 404, 422}

                    if is_negative_qty:
                        proof = DoubleProofVerifier.verify(
                            primary_req=primary_req,
                            primary_resp=primary_resp,
                            primary_succeeded=True,
                            control_req=control_req,
                            control_resp=control_resp,
                            control_succeeded=control_succeeded,
                            notes=f"Primary request accepted negative seat count ({payload.get('seat_count')}); control rejected invalid flight.",
                        )
                        if proof.is_verified():
                            findings.append(
                                VulnerabilityFinding(
                                    title=f"Negative Quantity Seat Refund Abuse on {method} {path}",
                                    category=VulnerabilityCategory.BUSINESS_LOGIC,
                                    severity=SeverityLevel.CRITICAL,
                                    target_endpoint=path,
                                    method=method,
                                    description=(
                                        f"Endpoint {method} {path} accepts negative seat count values, "
                                        f"allowing attackers to generate negative total charges that credit their wallet."
                                    ),
                                    proof=proof,
                                    cwe_id="CWE-1284",
                                    remediation=(
                                        "Validate that all quantity, seat count, and amount parameters are strictly positive integers."
                                    ),
                                )
                            )
                    elif is_tampered_accepted:
                        proof = DoubleProofVerifier.verify(
                            primary_req=primary_req,
                            primary_resp=primary_resp,
                            primary_succeeded=True,
                            control_req=control_req,
                            control_resp=control_resp,
                            control_succeeded=control_succeeded,
                            notes=f"Primary request accepted client-supplied fare ({payload.get('total_amount', payload.get('amount'))}); control rejected invalid flight.",
                        )

                        if proof.is_verified():
                            findings.append(
                                VulnerabilityFinding(
                                    title=f"Business Logic Fare / Amount Tampering on {method} {path}",
                                    category=VulnerabilityCategory.BUSINESS_LOGIC,
                                    severity=SeverityLevel.CRITICAL,
                                    target_endpoint=path,
                                    method=method,
                                    description=(
                                        f"Endpoint {method} {path} accepts client-supplied financial amounts, "
                                        f"allowing malicious actors to book tickets without payment or inflate account balances."
                                    ),
                                    proof=proof,
                                    cwe_id="CWE-20",
                                    remediation=(
                                        "Recalculate all transaction amounts and pricing server-side based on database "
                                        "catalog values. Never trust client-supplied totals for financial operations."
                                    ),
                                )
                            )
                            break

        return findings

    async def _test_double_refund(
        self, plan_item: AttackPlanItem, base_url: str
    ) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path
        method = plan_item.method
        sample_id = (
            str(plan_item.context.get("sample_ids", ["TEST-ITEM-1"])[0])
            if plan_item.context.get("sample_ids")
            else "TEST-ITEM-1"
        )
        resolved_path = re.sub(r"\{[^}]+\}", sample_id, path)
        target_url = f"{base_url.rstrip('/')}/{resolved_path.lstrip('/')}"

        refund_payload = {
            "booking_id": sample_id,
            "amount": 100.0,
            "reason": "Customer cancellation",
        }

        # First cancellation/refund call
        try:
            resp1 = await self.client.request(
                method=method,
                url=target_url,
                json=refund_payload,
                headers={"Authorization": "Bearer test-alpha-token"},
            )
        except Exception:
            return findings

        if resp1.status_code in {200, 201}:
            # Second refund call (replay on identical booking)
            primary_req = {
                "method": method,
                "url": target_url,
                "json": refund_payload,
                "headers": {"Authorization": "Bearer test-alpha-token"},
            }
            try:
                resp2 = await self.client.request(
                    method=method,
                    url=target_url,
                    json=refund_payload,
                    headers={"Authorization": "Bearer test-alpha-token"},
                )
            except Exception:
                return findings

            # Vulnerable if second refund also returns 200 OK (double refund)
            if resp2.status_code in {200, 201}:
                # Negative control: Attempt refund on invalid booking ID
                control_url = f"{target_url}-nonexistent-ctrl-999"
                control_payload = refund_payload.copy()
                control_payload["booking_id"] = "NONEXISTENT-TEST-999"
                control_req = {
                    "method": method,
                    "url": control_url,
                    "json": control_payload,
                    "headers": {"Authorization": "Bearer test-alpha-token"},
                }
                try:
                    control_resp = await self.client.request(
                        method=method,
                        url=control_url,
                        json=control_payload,
                        headers={"Authorization": "Bearer test-alpha-token"},
                    )
                except Exception:
                    return findings

                control_succeeded = control_resp.status_code in {400, 404, 422}

                proof = DoubleProofVerifier.verify(
                    primary_req=primary_req,
                    primary_resp=resp2,
                    primary_succeeded=True,
                    control_req=control_req,
                    control_resp=control_resp,
                    control_succeeded=control_succeeded,
                    notes="Second refund call succeeded on the same booking; negative control rejected nonexistent booking.",
                )

                if proof.is_verified():
                    findings.append(
                        VulnerabilityFinding(
                            title=f"Double Refund / Missing Idempotency on {method} {path}",
                            category=VulnerabilityCategory.BUSINESS_LOGIC,
                            severity=SeverityLevel.CRITICAL,
                            target_endpoint=path,
                            method=method,
                            description=(
                                f"Endpoint {method} {path} allows multiple refund executions on the same booking without "
                                f"state checks or idempotency keys, leading to financial drain."
                            ),
                            proof=proof,
                            cwe_id="CWE-674",
                            remediation=(
                                "Enforce atomic state transitions and require unique idempotency keys on all financial mutations. "
                                "Reject refund requests for bookings that are not in a refundable state."
                            ),
                        )
                    )

        return findings

    async def _test_step_skipping(
        self, plan_item: AttackPlanItem, base_url: str
    ) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path
        method = plan_item.method
        sample_id = (
            str(plan_item.context.get("sample_ids", ["TEST-ITEM-1"])[0])
            if plan_item.context.get("sample_ids")
            else "TEST-ITEM-1"
        )
        resolved_path = re.sub(r"\{[^}]+\}", sample_id, path)
        target_url = f"{base_url.rstrip('/')}/{resolved_path.lstrip('/')}"
        auth_headers = {"Authorization": "Bearer test-alpha-token"}

        # Test booking confirmation or payment without a preceding hold state
        skip_payload = {
            "booking_id": sample_id,
            "flight_id": sample_id,
            "amount": 250.0,
        }

        primary_req = {
            "method": method,
            "url": target_url,
            "json": skip_payload,
            "headers": auth_headers,
        }

        try:
            primary_resp = await self.client.request(
                method=method,
                url=target_url,
                json=skip_payload,
                headers=auth_headers,
            )
        except Exception:
            return findings

        # If confirmation/payment succeeded without verification of prerequisites
        if primary_resp.status_code in {200, 201}:
            # Negative control: Attempt on nonexistent booking
            control_url = f"{target_url}-nonexistent-ctrl-999"
            control_payload = skip_payload.copy()
            control_payload["booking_id"] = "NONEXISTENT-TEST-999"
            control_req = {
                "method": method,
                "url": control_url,
                "json": control_payload,
                "headers": auth_headers,
            }
            try:
                control_resp = await self.client.request(
                    method=method,
                    url=control_url,
                    json=control_payload,
                    headers=auth_headers,
                )
            except Exception:
                return findings

            control_succeeded = control_resp.status_code in {400, 404, 422}

            proof = DoubleProofVerifier.verify(
                primary_req=primary_req,
                primary_resp=primary_resp,
                primary_succeeded=True,
                control_req=control_req,
                control_resp=control_resp,
                control_succeeded=control_succeeded,
                notes="Payment or confirmation completed without verified inventory reservation.",
            )

            if proof.is_verified():
                findings.append(
                    VulnerabilityFinding(
                        title=f"Workflow Step Skipping / State Bypass on {method} {path}",
                        category=VulnerabilityCategory.BUSINESS_LOGIC,
                        severity=SeverityLevel.HIGH,
                        target_endpoint=path,
                        method=method,
                        description=(
                            f"Endpoint {method} {path} does not verify state prerequisites in the booking sequence, "
                            f"permitting out-of-order execution."
                        ),
                        proof=proof,
                        cwe_id="CWE-840",
                        remediation=(
                            "Implement finite state machine (FSM) validation for all booking lifecycles; "
                            "confirm preceding state invariants prior to confirming or charging."
                        ),
                    )
                )

        return findings
