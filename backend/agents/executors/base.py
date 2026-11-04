"""Base Attack Executor defining the contract for all specialist vulnerability executors."""

from abc import ABC, abstractmethod

from backend.agents.models import AttackPlanItem, VulnerabilityFinding
from backend.safety.http_client import SafeHttpClient


class BaseAttackExecutor(ABC):
    """Abstract base class for all TRIPWIRE vulnerability testing executors."""

    def __init__(self, client: SafeHttpClient) -> None:
        self.client = client

    @abstractmethod
    async def execute(self, plan_item: AttackPlanItem, base_url: str) -> list[VulnerabilityFinding]:
        """Execute targeted vulnerability testing and return verified findings with DoubleProof."""
        pass
