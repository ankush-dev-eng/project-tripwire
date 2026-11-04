"""Injection Attack Executor (SQL Injection and Command Injection)."""

import re

from backend.agents.executors.base import BaseAttackExecutor
from backend.agents.models import (
    AttackPlanItem,
    SeverityLevel,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from backend.agents.verifier import DoubleProofVerifier

SQLI_PATTERNS = [
    re.compile(r"syntax error", re.IGNORECASE),
    re.compile(r"sqlite3?\.", re.IGNORECASE),
    re.compile(r"operationalerror", re.IGNORECASE),
    re.compile(r"postgresql", re.IGNORECASE),
    re.compile(r"mysql", re.IGNORECASE),
    re.compile(r"sql command not properly ended", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
]


class InjectionExecutor(BaseAttackExecutor):
    """Executes SQL and Command Injection vulnerability vectors."""

    async def execute(self, plan_item: AttackPlanItem, base_url: str) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        path = plan_item.target_path
        method = plan_item.method
        target_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

        # Target search/filter parameters
        param_candidates = list(plan_item.target_params) if plan_item.target_params else []
        for default_p in ["airline", "origin", "destination", "q", "query", "filter", "host"]:
            if default_p not in param_candidates:
                param_candidates.append(default_p)

        for param in param_candidates:
            # Test boolean-based or error-based SQLi
            sqli_payload = "' OR '1'='1"
            primary_params = {param: sqli_payload}
            primary_req = {
                "method": method,
                "url": target_url,
                "params": primary_params,
            }

            try:
                primary_resp = await self.client.request(
                    method=method,
                    url=target_url,
                    params=primary_params if method == "GET" else None,
                    json=primary_params if method != "GET" else None,
                )
            except Exception:
                continue

            resp_text = primary_resp.text

            # Check for SQL error signature, debug query leak, or boolean leak
            has_sql_error = any(p.search(resp_text) for p in SQLI_PATTERNS)
            has_sql_leak = "query_debug" in resp_text or "injected" in resp_text
            has_boolean_expansion = False

            if primary_resp.status_code == 200:
                try:
                    data = primary_resp.json()
                    # If injection returned a list of multiple items or flights list
                    if (
                        isinstance(data, list)
                        and len(data) > 0
                        or isinstance(data, dict)
                        and "flights" in data
                        and len(data["flights"]) > 0
                    ):
                        has_boolean_expansion = True
                except Exception:
                    pass

            if has_sql_error or has_sql_leak or has_boolean_expansion:
                # Negative control: Send non-matching benign string
                control_params = {param: "NONEXISTENT_BENIGN_SEARCH_XYZ_999"}
                control_req = {
                    "method": method,
                    "url": target_url,
                    "params": control_params,
                }

                try:
                    control_resp = await self.client.request(
                        method=method,
                        url=target_url,
                        params=control_params if method == "GET" else None,
                        json=control_params if method != "GET" else None,
                    )
                except Exception:
                    continue

                control_succeeded = False
                if control_resp.status_code == 200:
                    try:
                        c_data = control_resp.json()
                        # Control should return 0 items or no SQL error
                        if (
                            isinstance(c_data, list)
                            and len(c_data) == 0
                            or isinstance(c_data, dict)
                            and "flights" in c_data
                            and len(c_data["flights"]) == 0
                        ):
                            control_succeeded = True
                        elif (
                            not any(p.search(control_resp.text) for p in SQLI_PATTERNS)
                            and "query_debug" not in control_resp.text
                        ):
                            control_succeeded = has_sql_error or has_sql_leak
                    except Exception:
                        control_succeeded = not any(
                            p.search(control_resp.text) for p in SQLI_PATTERNS
                        )

                proof = DoubleProofVerifier.verify(
                    primary_req=primary_req,
                    primary_resp=primary_resp,
                    primary_succeeded=True,
                    control_req=control_req,
                    control_resp=control_resp,
                    control_succeeded=control_succeeded,
                    notes=f"SQL injection payload triggered syntax error or full record leakage on parameter '{param}'.",
                )

                if proof.is_verified():
                    findings.append(
                        VulnerabilityFinding(
                            title=f"SQL Injection on {method} {path} ({param})",
                            category=VulnerabilityCategory.INJECTION,
                            severity=SeverityLevel.CRITICAL,
                            target_endpoint=path,
                            method=method,
                            description=(
                                f"Endpoint {method} {path} concatenates parameter '{param}' directly into database "
                                f"queries without parameterization, permitting arbitrary database manipulation."
                            ),
                            proof=proof,
                            cwe_id="CWE-89",
                            remediation=(
                                "Use parameterized queries or Object-Relational Mapping (ORM) query builders. "
                                "Never concatenate untrusted user input into SQL execution statements."
                            ),
                        )
                    )
                    break

        return findings
