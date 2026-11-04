"""API Inventory Agent classifying Active, Zombie, and Shadow endpoints."""

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from backend.graph.knowledge_graph import KnowledgeGraph


class InventoryClassification(StrEnum):
    ACTIVE = "ACTIVE"
    ZOMBIE = "ZOMBIE"
    SHADOW = "SHADOW"
    ZOMBIE_UNDOCUMENTED = "ZOMBIE_UNDOCUMENTED"


@dataclass
class EndpointInventoryRecord:
    endpoint_id: str
    method: str
    path: str
    classification: InventoryClassification
    declared_in_spec: bool
    discovered_in_app: bool
    has_traffic_in_window: bool
    traffic_hit_count: int = 0
    last_traffic_date: str | None = None
    auth_required: bool = False
    data_exposed: list[str] = field(default_factory=list)
    likely_owner: str = "Engineering Team"
    recommendation: str = "Maintain in production"
    risk_level: str = "LOW"


class InventoryAgent:
    """Classifies endpoints into Active, Zombie, and Shadow categories based on graph, declared specs, and traffic windows."""

    def __init__(self, knowledge_graph: KnowledgeGraph) -> None:
        self.kg = knowledge_graph
        self._traffic_stats: dict[str, dict[str, Any]] = {}

    def parse_traffic_log(
        self,
        log_path: Path | str,
        window_days: int = 30,
        reference_time: datetime | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Analyze gateway log to count hits and determine last seen traffic date."""
        path = Path(log_path)
        stats: dict[str, dict[str, Any]] = {}
        if not path.exists():
            return stats

        ref_time = reference_time or datetime.now(UTC)
        window_cutoff = ref_time - timedelta(days=window_days)

        with open(path, encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue

                # Parse timestamp e.g. 2026-11-05T00:00:00Z
                try:
                    ts = datetime.fromisoformat(parts[0])
                except Exception:
                    continue

                # Extract request method and path
                for i, part in enumerate(parts):
                    clean_part = part.strip('"')
                    if clean_part in {"GET", "POST", "PUT", "DELETE", "PATCH"} and i + 1 < len(
                        parts
                    ):
                        method = clean_part
                        raw_path = parts[i + 1].split("?")[0].rstrip("/")
                        if not raw_path.startswith("/"):
                            raw_path = "/" + raw_path

                        key = f"{method} {raw_path}"
                        if key not in stats:
                            stats[key] = {
                                "hits": 0,
                                "last_traffic": ts.isoformat(),
                                "in_window": False,
                            }

                        stats[key]["hits"] += 1
                        if ts > datetime.fromisoformat(stats[key]["last_traffic"]):
                            stats[key]["last_traffic"] = ts.isoformat()

                        if ts >= window_cutoff:
                            stats[key]["in_window"] = True

        self._traffic_stats = stats
        return stats

    def classify_inventory(
        self,
        declared_routes: set[str] | None = None,
        traffic_stats: dict[str, dict[str, Any]] | None = None,
    ) -> list[EndpointInventoryRecord]:
        """Classify each endpoint according to the 4.2 decision matrix."""
        declared = declared_routes or set()
        stats = traffic_stats if traffic_stats is not None else self._traffic_stats

        inventory: list[EndpointInventoryRecord] = []
        kg_endpoints = self.kg.get_endpoints()

        for ep in kg_endpoints:
            endpoint_id = ep["endpoint_id"]
            method = ep["method"]
            path = ep["path"]
            auth_req = ep.get("auth_required", False)

            # Match against traffic stats (support wildcard templates like /bookings/{id})
            traffic_info = self._find_traffic_match(method, path, stats)

            is_declared = endpoint_id in declared or path in declared or ep.get("declared", False)
            discovered = True
            has_traffic = traffic_info.get("in_window", False)
            hit_count = traffic_info.get("hits", 0)
            last_traffic = traffic_info.get("last_traffic")

            # Classification logic based on Section 4.2 matrix:
            # 1. Declared: Yes, Discovered: Yes, Traffic: Yes -> Active
            # 2. Declared: Any, Discovered: Responds, Traffic: No -> Zombie
            # 3. Declared: No, Discovered: Yes, Traffic: Yes -> Shadow
            # 4. Declared: No, Discovered: Responds, Traffic: No -> Zombie (undocumented)
            if has_traffic and is_declared:
                category = InventoryClassification.ACTIVE
                risk = "LOW"
                owner = self._infer_owner(path)
                rec = "Active service route. Maintain automated testing and continuous monitoring."
            elif not has_traffic and is_declared:
                category = InventoryClassification.ZOMBIE
                risk = "MEDIUM" if auth_req else "HIGH"
                owner = self._infer_owner(path)
                rec = "Decommission or retire route; endpoint has zero traffic within the observation window."
            elif has_traffic and not is_declared:
                category = InventoryClassification.SHADOW
                risk = "HIGH" if not auth_req else "MEDIUM"
                owner = self._infer_owner(path)
                rec = "Document in public API specification immediately or restrict external gateway access."
            else:
                category = InventoryClassification.ZOMBIE_UNDOCUMENTED
                risk = "CRITICAL" if not auth_req else "HIGH"
                owner = self._infer_owner(path)
                rec = "Decommission immediately; undocumented endpoint responsive to probes with zero traffic."

            # Infer exposed data
            exposed = self._infer_exposed_data(path)

            inventory.append(
                EndpointInventoryRecord(
                    endpoint_id=endpoint_id,
                    method=method,
                    path=path,
                    classification=category,
                    declared_in_spec=is_declared,
                    discovered_in_app=discovered,
                    has_traffic_in_window=has_traffic,
                    traffic_hit_count=hit_count,
                    last_traffic_date=last_traffic,
                    auth_required=auth_req,
                    data_exposed=exposed,
                    likely_owner=owner,
                    recommendation=rec,
                    risk_level=risk,
                )
            )

        return inventory

    def _find_traffic_match(
        self, method: str, path_template: str, stats: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        """Match endpoint against concrete traffic log URLs."""
        exact_key = f"{method} {path_template}"
        if exact_key in stats:
            return stats[exact_key]

        # Convert template e.g. /v1/bookings/{booking_id} to regex
        regex_pattern = re.sub(r"\{[^}]+\}", r"[^/]+", path_template)
        pattern = re.compile(f"^{method} {regex_pattern}$")

        total_hits = 0
        latest_ts = None
        in_window = False

        for k, v in stats.items():
            if pattern.match(k):
                total_hits += v["hits"]
                if v.get("in_window"):
                    in_window = True
                curr_ts = v.get("last_traffic")
                if curr_ts and (latest_ts is None or curr_ts > latest_ts):
                    latest_ts = curr_ts

        if total_hits > 0:
            return {
                "hits": total_hits,
                "last_traffic": latest_ts,
                "in_window": in_window,
            }
        return {"hits": 0, "last_traffic": None, "in_window": False}

    @staticmethod
    def _infer_owner(path: str) -> str:
        """Infer responsible team from path semantics without hardcoded lab names."""
        p_lower = path.lower()
        if "auth" in p_lower or "login" in p_lower:
            return "Identity & Access Management"
        elif "booking" in p_lower or "hold" in p_lower or "cancel" in p_lower:
            return "Core Booking Engine"
        elif "flight" in p_lower or "search" in p_lower:
            return "Catalog & Distribution"
        elif "wallet" in p_lower or "pay" in p_lower or "invoice" in p_lower:
            return "Payments & Settlement"
        elif "supplier" in p_lower:
            return "Supplier Integration Group"
        elif "debug" in p_lower or "test" in p_lower:
            return "Platform Engineering / QA"
        return "API Gateway Team"

    @staticmethod
    def _infer_exposed_data(path: str) -> list[str]:
        """Infer potential sensitive data exposure from endpoint path."""
        exposed: list[str] = []
        p_lower = path.lower()
        if "booking" in p_lower:
            exposed.extend(["Passenger Names", "PNR", "Itinerary Details"])
        if "invoice" in p_lower or "pay" in p_lower:
            exposed.extend(["Cardholder Data", "Billing Amounts", "Transaction Receipts"])
        if "wallet" in p_lower:
            exposed.extend(["Agency Balance", "Credit Limit", "Deposit Ledgers"])
        if "user" in p_lower or "profile" in p_lower:
            exposed.extend(["User Emails", "Account Privileges", "Contact Information"])
        if "supplier" in p_lower or "sync" in p_lower:
            exposed.extend(["Supplier Sync Records", "Internal Inventory State"])
        if "debug" in p_lower or "env" in p_lower:
            exposed.extend(["API Keys", "Environment Secrets", "Database Credentials"])
        return exposed

    def export_report_json(self, inventory: list[EndpointInventoryRecord]) -> str:
        """Serialize inventory report to JSON."""
        return json.dumps([asdict(r) for r in inventory], indent=2)
