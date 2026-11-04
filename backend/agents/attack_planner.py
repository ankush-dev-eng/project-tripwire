"""Targeted Attack Planner querying the Knowledge Graph.

Formulates hypothesis-driven attack vectors rather than blind scanning.
Inspects parameters, roles, and detected business flows.
"""

import re
import uuid

from backend.agents.models import AttackPlanItem, VulnerabilityCategory
from backend.graph.knowledge_graph import KnowledgeGraph


class AttackPlanner:
    """Generates targeted attack plans based on Knowledge Graph topology."""

    def __init__(self, knowledge_graph: KnowledgeGraph) -> None:
        self.kg = knowledge_graph

    def generate_plan(self) -> list[AttackPlanItem]:
        """Traverse the knowledge graph and generate targeted test vectors."""
        plan: list[AttackPlanItem] = []
        endpoints = self.kg.get_all_endpoints()

        for ep in endpoints:
            ep_id = ep["endpoint_id"]
            method = ep["method"].upper()
            path = ep["path"]
            auth_required = ep.get("auth_required", False)
            params = self.kg.get_endpoint_parameters(ep_id)
            param_names = [p.get("name") or p.get("param_name", "") for p in params]
            observed_samples = []
            for p in params:
                observed_samples.extend(p.get("observed_values", []))
            path_lower = path.lower()

            base_context = {
                "param_names": param_names,
                "auth_required": auth_required,
                "sample_ids": observed_samples,
            }

            # 1. BOLA / IDOR Planning
            # Target endpoints with identifier parameters in path or query
            has_id_param = any(
                re.search(
                    r"(id|booking|user|invoice|wallet|agency|pnr|order)",
                    p,
                    re.IGNORECASE,
                )
                for p in param_names
            )
            has_id_in_path = "{" in path or any(
                re.search(
                    r"(id|booking|user|invoice|wallet|agency)",
                    segment,
                    re.IGNORECASE,
                )
                for segment in path.split("/")
            )
            if has_id_param or has_id_in_path:
                plan.append(
                    AttackPlanItem(
                        plan_id=str(uuid.uuid4()),
                        category=VulnerabilityCategory.BOLA,
                        target_endpoint_id=ep_id,
                        target_path=path,
                        method=method,
                        target_params=param_names,
                        priority=1,
                        description=f"Test BOLA/IDOR on {method} {path} with cross-tenant identifier swapping.",
                        context=base_context.copy(),
                    )
                )

            # 2. BOPLA / Mass Assignment Planning
            # Target mutation endpoints (POST, PUT, PATCH)
            if method in {"POST", "PUT", "PATCH"}:
                plan.append(
                    AttackPlanItem(
                        plan_id=str(uuid.uuid4()),
                        category=VulnerabilityCategory.BOPLA,
                        target_endpoint_id=ep_id,
                        target_path=path,
                        method=method,
                        target_params=param_names,
                        priority=2,
                        description=f"Test mass assignment on {method} {path} with privileged fields (role, status, admin).",
                        context=base_context.copy(),
                    )
                )

            # 3. SSRF & Webhook Injection Planning
            # Target endpoints with URL/webhook/callback/sync parameters or sync paths
            has_url_param = any(
                re.search(
                    r"(url|webhook|callback|target|endpoint|sync|host|uri)",
                    p,
                    re.IGNORECASE,
                )
                for p in param_names
            )
            has_url_in_path = any(k in path_lower for k in ["sync", "webhook", "callback", "fetch"])
            if has_url_param or has_url_in_path:
                plan.append(
                    AttackPlanItem(
                        plan_id=str(uuid.uuid4()),
                        category=VulnerabilityCategory.SSRF,
                        target_endpoint_id=ep_id,
                        target_path=path,
                        method=method,
                        target_params=param_names,
                        priority=1,
                        description=f"Test SSRF on {method} {path} against loopback and cloud metadata endpoints.",
                        context=base_context.copy(),
                    )
                )

            # 4. Business Logic & Race Condition Planning
            # Target financial, pricing, booking state transitions
            has_financial_param = any(
                re.search(
                    r"(price|amount|discount|coupon|promo|fare|currency|quantity)",
                    p,
                    re.IGNORECASE,
                )
                for p in param_names
            )
            has_state_in_path = any(
                k in path_lower
                for k in [
                    "pay",
                    "refund",
                    "cancel",
                    "hold",
                    "discount",
                    "coupon",
                    "wallet",
                    "confirm",
                    "book",
                ]
            )
            if has_financial_param or has_state_in_path:
                plan.append(
                    AttackPlanItem(
                        plan_id=str(uuid.uuid4()),
                        category=VulnerabilityCategory.BUSINESS_LOGIC,
                        target_endpoint_id=ep_id,
                        target_path=path,
                        method=method,
                        target_params=param_names,
                        priority=1,
                        description=f"Test business logic (fare manipulation, double refund, step skips) on {method} {path}.",
                        context=base_context.copy(),
                    )
                )

            # 5. Injection (SQLi & Command Injection) Planning
            # Target search, query, filter, sort parameters
            has_search_param = any(
                re.search(
                    r"(search|query|q|filter|origin|dest|sort|sql|cmd|exec)",
                    p,
                    re.IGNORECASE,
                )
                for p in param_names
            )
            if has_search_param or "search" in path_lower:
                plan.append(
                    AttackPlanItem(
                        plan_id=str(uuid.uuid4()),
                        category=VulnerabilityCategory.INJECTION,
                        target_endpoint_id=ep_id,
                        target_path=path,
                        method=method,
                        target_params=param_names,
                        priority=2,
                        description=f"Test SQLi and Command Injection on {method} {path} with polyglot payloads.",
                        context=base_context.copy(),
                    )
                )

            # 6. Excessive Data Exposure / PII Leaks Planning
            # Inspect responses of endpoints dealing with bookings, users, profiles, agencies
            if method == "GET" and any(
                k in path_lower for k in ["booking", "user", "profile", "agency", "invoice", "v1"]
            ):
                plan.append(
                    AttackPlanItem(
                        plan_id=str(uuid.uuid4()),
                        category=VulnerabilityCategory.DATA_EXPOSURE,
                        target_endpoint_id=ep_id,
                        target_path=path,
                        method=method,
                        target_params=param_names,
                        priority=3,
                        description=f"Inspect response of {method} {path} for raw PANs, CVVs, passwords, and PII.",
                        context=base_context.copy(),
                    )
                )

            # 7. Broken Authentication & Session Planning
            # Target auth routes or protected routes with JWT / bearer headers
            if (
                auth_required
                or "auth" in path_lower
                or "login" in path_lower
                or "token" in path_lower
                or "reset" in path_lower
            ):
                plan.append(
                    AttackPlanItem(
                        plan_id=str(uuid.uuid4()),
                        category=VulnerabilityCategory.AUTH_SESSION,
                        target_endpoint_id=ep_id,
                        target_path=path,
                        method=method,
                        target_params=param_names,
                        priority=1,
                        description=f"Test broken authentication (JWT alg: none, token tampering, missing auth) on {method} {path}.",
                        context=base_context.copy(),
                    )
                )

            # 8. API Hygiene & Information Disclosure Planning
            # Target debug, error probe, or undocumented endpoints
            if any(k in path_lower for k in ["debug", "env", "metric", "test", "probe", "error"]):
                plan.append(
                    AttackPlanItem(
                        plan_id=str(uuid.uuid4()),
                        category=VulnerabilityCategory.API_HYGIENE,
                        target_endpoint_id=ep_id,
                        target_path=path,
                        method=method,
                        target_params=param_names,
                        priority=2,
                        description=f"Probe API hygiene and verbose information disclosure on {method} {path}.",
                        context={"param_names": param_names},
                    )
                )

        # Sort by priority ascending (1 first, then 2, etc.)
        plan.sort(key=lambda item: item.priority)
        return plan
