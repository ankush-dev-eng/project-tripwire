"""Business-Context Severity Triage Engine.

Calculates contextual severity using config/severity.yaml multipliers:
- Base class weight
- Affected business asset multiplier
- Exploitability factor (cross-tenant, unauthenticated, privilege escalation)
- Route status boost (shadow / zombie visibility penalty)
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from backend.agents.models import (
    SeverityLevel,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from backend.graph.knowledge_graph import KnowledgeGraph


@dataclass
class TriageBreakdown:
    base_class: str
    base_weight: float
    asset_category: str
    asset_multiplier: float
    exploitability_category: str
    exploitability_multiplier: float
    inventory_boost: float
    final_score: float
    triaged_severity: SeverityLevel
    rationale: str


class TriageAgent:
    """Evaluates business asset impact and exploitability to produce contextual severity scores."""

    def __init__(
        self,
        config_path: Path | str = "config/severity.yaml",
        knowledge_graph: KnowledgeGraph | None = None,
    ) -> None:
        self.config_path = Path(config_path)
        self.kg = knowledge_graph
        self._load_config()

    def _load_config(self) -> None:
        cfg: dict[str, Any] = {}
        if self.config_path.exists():
            with open(self.config_path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}

        self.class_weights: dict[str, float] = cfg.get(
            "class_weights",
            {
                "access_control": 0.95,
                "business_logic": 0.90,
                "auth_session": 0.85,
                "injection": 0.85,
                "server_side": 0.80,
                "api_hygiene": 0.60,
                "data_exposure": 0.75,
                "zombie_shadow": 0.65,
            },
        )
        self.asset_weights: dict[str, float] = cfg.get(
            "asset_weights",
            {
                "payments_refunds": 1.50,
                "credit_balance": 1.40,
                "pii_traveller": 1.25,
                "supplier_credentials": 1.35,
                "booking_records": 1.15,
                "search_catalog": 0.80,
            },
        )
        self.exploitability_weights: dict[str, float] = cfg.get(
            "exploitability_weights",
            {
                "unauthenticated": 1.30,
                "cross_tenant": 1.40,
                "subagent_to_admin": 1.35,
                "authenticated_same_role": 1.00,
            },
        )
        self.thresholds: dict[str, float] = cfg.get(
            "thresholds",
            {
                "critical": 1.50,
                "high": 1.10,
                "medium": 0.70,
                "low": 0.00,
            },
        )

    def triage_finding(
        self,
        finding: VulnerabilityFinding,
        is_shadow: bool = False,
        is_zombie: bool = False,
    ) -> TriageBreakdown:
        """Calculate mathematically explainable contextual severity for a finding."""
        path_lower = finding.target_endpoint.lower()

        # 1. Base vulnerability class weight
        class_key = self._map_category_to_class_key(finding.category)
        base_weight = self.class_weights.get(class_key, 0.75)

        # 2. Asset multiplier
        asset_cat, asset_mult = self._infer_asset_category(finding, path_lower)

        # 3. Exploitability multiplier
        exp_cat, exp_mult = self._infer_exploitability(finding, path_lower)

        # 4. Inventory visibility penalty (Shadow = +25%, Zombie = +15%)
        inv_boost = 1.0
        if is_shadow:
            inv_boost = 1.25
        elif is_zombie:
            inv_boost = 1.15

        final_score = base_weight * asset_mult * exp_mult * inv_boost

        # Determine severity level from score thresholds
        if final_score >= self.thresholds.get("critical", 1.50):
            triaged_sev = SeverityLevel.CRITICAL
        elif final_score >= self.thresholds.get("high", 1.10):
            triaged_sev = SeverityLevel.HIGH
        elif final_score >= self.thresholds.get("medium", 0.70):
            triaged_sev = SeverityLevel.MEDIUM
        else:
            triaged_sev = SeverityLevel.LOW

        rationale = (
            f"Base class weight {base_weight:.2f} ({class_key}) × "
            f"Asset multiplier {asset_mult:.2f} ({asset_cat}) × "
            f"Exploitability {exp_mult:.2f} ({exp_cat})"
        )
        if inv_boost > 1.0:
            rationale += (
                f" × Visibility factor {inv_boost:.2f} ({'Shadow' if is_shadow else 'Zombie'})"
            )
        rationale += f" = Score {final_score:.2f} -> {triaged_sev.value}"

        breakdown = TriageBreakdown(
            base_class=class_key,
            base_weight=base_weight,
            asset_category=asset_cat,
            asset_multiplier=asset_mult,
            exploitability_category=exp_cat,
            exploitability_multiplier=exp_mult,
            inventory_boost=inv_boost,
            final_score=round(final_score, 3),
            triaged_severity=triaged_sev,
            rationale=rationale,
        )

        # Update finding severity and metadata
        finding.severity = triaged_sev
        finding.metadata["triage"] = {
            "score": breakdown.final_score,
            "base_class": breakdown.base_class,
            "asset_category": breakdown.asset_category,
            "exploitability": breakdown.exploitability_category,
            "inventory_boost": breakdown.inventory_boost,
            "rationale": breakdown.rationale,
        }

        return breakdown

    @staticmethod
    def _map_category_to_class_key(cat: VulnerabilityCategory) -> str:
        mapping = {
            VulnerabilityCategory.BOLA: "access_control",
            VulnerabilityCategory.BOPLA: "access_control",
            VulnerabilityCategory.BUSINESS_LOGIC: "business_logic",
            VulnerabilityCategory.AUTH_SESSION: "auth_session",
            VulnerabilityCategory.INJECTION: "injection",
            VulnerabilityCategory.SSRF: "server_side",
            VulnerabilityCategory.API_HYGIENE: "api_hygiene",
            VulnerabilityCategory.DATA_EXPOSURE: "data_exposure",
        }
        return mapping.get(cat, "access_control")

    def _infer_asset_category(
        self, finding: VulnerabilityFinding, path_lower: str
    ) -> tuple[str, float]:
        if any(k in path_lower for k in ["pay", "refund", "cancel", "invoice"]):
            return "payments_refunds", self.asset_weights["payments_refunds"]
        if any(k in path_lower for k in ["wallet", "topup", "credit"]):
            return "credit_balance", self.asset_weights["credit_balance"]
        if (
            finding.category == VulnerabilityCategory.DATA_EXPOSURE
            or "pan" in finding.title.lower()
            or "cvv" in finding.title.lower()
        ):
            return "pii_traveller", self.asset_weights["pii_traveller"]
        if any(k in path_lower for k in ["debug", "env", "supplier"]):
            return (
                "supplier_credentials",
                self.asset_weights["supplier_credentials"],
            )
        if any(k in path_lower for k in ["booking", "hold"]):
            return "booking_records", self.asset_weights["booking_records"]
        return "search_catalog", self.asset_weights["search_catalog"]

    def _infer_exploitability(
        self, finding: VulnerabilityFinding, path_lower: str
    ) -> tuple[str, float]:
        title_lower = finding.title.lower()
        if "bola" in title_lower or "idor" in title_lower or "cross-tenant" in title_lower:
            return "cross_tenant", self.exploitability_weights["cross_tenant"]
        if "mass assignment" in title_lower or "bopla" in title_lower or "promote" in path_lower:
            return (
                "subagent_to_admin",
                self.exploitability_weights["subagent_to_admin"],
            )
        if (
            "none" in title_lower
            or "bypass" in title_lower
            or not finding.proof.primary_request.get("headers", {}).get("Authorization")
        ):
            return (
                "unauthenticated",
                self.exploitability_weights["unauthenticated"],
            )
        return (
            "authenticated_same_role",
            self.exploitability_weights["authenticated_same_role"],
        )
