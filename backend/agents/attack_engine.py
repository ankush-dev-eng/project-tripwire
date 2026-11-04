"""Attack Engine orchestrating targeted planning, execution, and double-proof verification."""

from backend.agents.attack_planner import AttackPlanner
from backend.agents.executors.access_control import AccessControlExecutor
from backend.agents.executors.auth_session import AuthSessionExecutor
from backend.agents.executors.base import BaseAttackExecutor
from backend.agents.executors.business_logic import BusinessLogicExecutor
from backend.agents.executors.data_exposure import DataExposureExecutor
from backend.agents.executors.hygiene import HygieneExecutor
from backend.agents.executors.injection import InjectionExecutor
from backend.agents.executors.server_side import ServerSideExecutor
from backend.agents.models import (
    AttackPlanItem,
    VulnerabilityCategory,
    VulnerabilityFinding,
)
from backend.graph.knowledge_graph import KnowledgeGraph
from backend.safety.http_client import SafeHttpClient


class AttackEngine:
    """Orchestrates targeted planning, executor dispatch, and double-proof collection."""

    def __init__(
        self,
        knowledge_graph: KnowledgeGraph,
        client: SafeHttpClient,
        base_url: str = "http://127.0.0.1:8000",
    ) -> None:
        self.kg = knowledge_graph
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.planner = AttackPlanner(self.kg)

        # Initialize specialist executors
        self.executors: dict[VulnerabilityCategory, BaseAttackExecutor] = {
            VulnerabilityCategory.BOLA: AccessControlExecutor(self.client),
            VulnerabilityCategory.BOPLA: AccessControlExecutor(self.client),
            VulnerabilityCategory.SSRF: ServerSideExecutor(self.client),
            VulnerabilityCategory.BUSINESS_LOGIC: BusinessLogicExecutor(self.client),
            VulnerabilityCategory.INJECTION: InjectionExecutor(self.client),
            VulnerabilityCategory.DATA_EXPOSURE: DataExposureExecutor(self.client),
            VulnerabilityCategory.AUTH_SESSION: AuthSessionExecutor(self.client),
            VulnerabilityCategory.API_HYGIENE: HygieneExecutor(self.client),
        }

    async def run_plan(
        self, plan_items: list[AttackPlanItem] | None = None
    ) -> list[VulnerabilityFinding]:
        """Execute attack plan and return verified findings."""
        items = plan_items or self.planner.generate_plan()
        findings: list[VulnerabilityFinding] = []
        seen_keys: set[tuple[str, str, str]] = set()

        for item in items:
            executor = self.executors.get(item.category)
            if not executor:
                continue

            try:
                item_findings = await executor.execute(item, self.base_url)
                for f in item_findings:
                    # Enforce double-proof verification check
                    if not f.proof.is_verified():
                        continue

                    key = (f.category.value, f.target_endpoint, f.method)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        findings.append(f)
            except Exception:
                # Catch executor-level exceptions to maintain engine resilience
                continue

        return findings
