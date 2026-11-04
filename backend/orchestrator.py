"""Central Orchestrator for PROJECT TRIPWIRE.

Coordinates end-to-end autonomous DAST lifecycle:
1. Reconnaissance & Knowledge Graph Construction
2. API Inventory (Active, Zombie, Shadow) & OpenAPI Synthesis
3. Targeted Hypothesis Attack Planning & Execution with Double-Proof Verification
4. Business-Context Severity Triaging & Scoring
5. Human-in-the-Loop Approval Queue & Retest Automation
Streams real-time events via async subscriber queues (WebSockets).
"""

import asyncio
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from backend.agents.attack_engine import AttackEngine
from backend.agents.attack_planner import AttackPlanner
from backend.agents.inventory_agent import (
    EndpointInventoryRecord,
    InventoryAgent,
    InventoryClassification,
)
from backend.agents.js_extractor import JSRouteExtractor
from backend.agents.models import AttackPlanItem, FindingStatus, VulnerabilityFinding
from backend.agents.openapi_generator import OpenAPISpecGenerator
from backend.agents.recon_crawler import ReconCrawler
from backend.agents.retest_agent import RetestAgent, RetestResult
from backend.agents.triage_agent import TriageAgent
from backend.graph.knowledge_graph import KnowledgeGraph
from backend.safety.approval_gate import ApprovalGate
from backend.safety.audit_logger import AuditLogger
from backend.safety.http_client import SafeHttpClient
from backend.safety.kill_switch import KillSwitch
from backend.safety.rate_limiter import RateLimiter
from backend.safety.scope import ScopeManager


class OrchestratorStatus(StrEnum):
    IDLE = "IDLE"
    RECON = "RECON"
    INVENTORY = "INVENTORY"
    PLANNING = "PLANNING"
    ATTACKING = "ATTACKING"
    TRIAGING = "TRIAGING"
    COMPLETED = "COMPLETED"
    PAUSED = "PAUSED"
    ERROR = "ERROR"


class TripwireOrchestrator:
    """Central state machine coordinating all TRIPWIRE agents, safety gates, and live streams."""

    def __init__(
        self,
        safe_client: SafeHttpClient | None = None,
        scope_manager: ScopeManager | None = None,
        kill_switch: KillSwitch | None = None,
        rate_limiter: RateLimiter | None = None,
        approval_gate: ApprovalGate | None = None,
        audit_logger: AuditLogger | None = None,
        config_dir: Path | str = "config",
    ) -> None:
        self.kill_switch = kill_switch or KillSwitch.get_instance()
        self.scope_manager = scope_manager or ScopeManager(kill_switch=self.kill_switch)
        self.rate_limiter = rate_limiter or RateLimiter(kill_switch=self.kill_switch)
        self.approval_gate = approval_gate or ApprovalGate(mode="permissive")
        self.audit_logger = audit_logger or AuditLogger()

        self.client = safe_client or SafeHttpClient(
            scope_manager=self.scope_manager,
            kill_switch=self.kill_switch,
            rate_limiter=self.rate_limiter,
            approval_gate=self.approval_gate,
            audit_logger=self.audit_logger,
        )

        # Core Graph & Agent Pipeline
        self.kg = KnowledgeGraph()
        self.recon = ReconCrawler(http_client=self.client, knowledge_graph=self.kg)
        self.js_extractor = JSRouteExtractor()
        self.inventory_agent = InventoryAgent(knowledge_graph=self.kg)
        self.openapi_gen = OpenAPISpecGenerator(knowledge_graph=self.kg)
        self.attack_planner = AttackPlanner(knowledge_graph=self.kg)
        self.attack_engine = AttackEngine(knowledge_graph=self.kg, client=self.client)
        self.triage_agent = TriageAgent(knowledge_graph=self.kg)
        self.retest_agent = RetestAgent(client=self.client)

        # State Variables
        self.status = OrchestratorStatus.IDLE
        self.progress = 0
        self.current_step = "System ready"
        self.target_url: str = ""
        self.inventory_records: list[EndpointInventoryRecord] = []
        self.plan_items: list[AttackPlanItem] = []
        self.findings: list[VulnerabilityFinding] = []
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._lock = asyncio.Lock()
        self.last_scan_time: str | None = None

    def add_subscriber(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Register a WebSocket client queue for live streaming events."""
        self._subscribers.add(queue)

    def remove_subscriber(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Deregister a WebSocket client queue."""
        self._subscribers.discard(queue)

    async def emit_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Broadcast structured event to all active observers."""
        payload = {
            "type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": data,
        }
        dead_queues = set()
        for q in self._subscribers:
            try:
                q.put_nowait(payload)
            except Exception:
                dead_queues.add(q)
        for dead in dead_queues:
            self._subscribers.discard(dead)

    async def run_scan(
        self,
        target_base_url: str = "http://127.0.0.1:8000",
        traffic_log_path: str | None = "data/gateway_30d.log",
        js_bundle_url: str | None = "http://127.0.0.1:8000/static/bundle.js",
    ) -> list[VulnerabilityFinding]:
        """Execute full autonomous end-to-end security assessment."""
        async with self._lock:
            if self.kill_switch.is_active():
                raise RuntimeError("Kill switch is active. Cannot start scan.")

            self.target_url = target_base_url
            self.findings.clear()
            self.plan_items.clear()
            self.last_scan_time = datetime.now(UTC).isoformat()

            # -------------------------------------------------------------
            # Step 1: Recon & Knowledge Graph
            # -------------------------------------------------------------
            self.status = OrchestratorStatus.RECON
            self.progress = 10
            self.current_step = "Crawling application and analyzing JS bundles"
            await self.emit_event(
                "STATUS_CHANGED",
                {
                    "status": self.status.value,
                    "progress": self.progress,
                    "step": self.current_step,
                },
            )

            # Fetch and extract endpoints from JS bundle if present
            if js_bundle_url:
                try:
                    js_resp = await self.client.get(js_bundle_url)
                    if js_resp.status_code == 200:
                        discovered_js_routes = self.js_extractor.extract_routes(js_resp.text)
                        for r in discovered_js_routes:
                            self.kg.add_endpoint(
                                method="GET",
                                path=r,
                                declared=False,
                            )
                except Exception as e:
                    await self.emit_event(
                        "LOG", {"level": "WARN", "message": f"JS bundle fetch error: {e}"}
                    )

            # Run crawler probe
            try:
                await self.recon.run_discovery(target_base_url)
            except Exception as e:
                await self.emit_event("LOG", {"level": "WARN", "message": f"Crawler error: {e}"})

            await self.emit_event(
                "GRAPH_UPDATED",
                {
                    "nodes_count": self.kg.get_endpoint_count(),
                    "graph": self.get_graph(),
                },
            )

            # -------------------------------------------------------------
            # Step 2: API Inventory & OpenAPI Synthesis
            # -------------------------------------------------------------
            self.status = OrchestratorStatus.INVENTORY
            self.progress = 30
            self.current_step = "Classifying Active, Zombie, and Shadow APIs"
            await self.emit_event(
                "STATUS_CHANGED",
                {
                    "status": self.status.value,
                    "progress": self.progress,
                    "step": self.current_step,
                },
            )

            declared_routes = [
                "/api/v3/auth/login",
                "/api/v3/auth/reset-password",
                "/api/v3/flights/search",
                "/api/v3/bookings/hold",
                "/api/v3/bookings/{booking_id}",
                "/api/v3/bookings/{booking_id}/pay",
                "/api/v3/bookings/{booking_id}/confirm",
                "/api/v3/bookings/{booking_id}/cancel",
                "/api/v3/bookings/{booking_id}/invoice",
                "/api/v3/agency/profile",
                "/api/v3/agency/users",
                "/api/v3/wallet/balance",
                "/api/v3/wallet/topup",
                "/api/v3/agency/documents",
            ]

            log_p = Path(traffic_log_path) if traffic_log_path else None
            stats = {}
            if log_p and log_p.exists():
                stats = self.inventory_agent.parse_traffic_log(log_p)
            self.inventory_records = self.inventory_agent.classify_inventory(
                declared_routes=set(declared_routes),
                traffic_stats=stats,
            )

            active_cnt = sum(
                1
                for r in self.inventory_records
                if r.classification == InventoryClassification.ACTIVE
            )
            zombie_cnt = sum(
                1
                for r in self.inventory_records
                if r.classification
                in {InventoryClassification.ZOMBIE, InventoryClassification.ZOMBIE_UNDOCUMENTED}
            )
            shadow_cnt = sum(
                1
                for r in self.inventory_records
                if r.classification == InventoryClassification.SHADOW
            )

            await self.emit_event(
                "INVENTORY_UPDATED",
                {
                    "active_count": active_cnt,
                    "zombie_count": zombie_cnt,
                    "shadow_count": shadow_cnt,
                    "inventory": self.get_inventory(),
                },
            )

            # -------------------------------------------------------------
            # Step 3: Targeted Attack Planning
            # -------------------------------------------------------------
            self.status = OrchestratorStatus.PLANNING
            self.progress = 50
            self.current_step = "Formulating targeted hypothesis-driven attack plan"
            await self.emit_event(
                "STATUS_CHANGED",
                {
                    "status": self.status.value,
                    "progress": self.progress,
                    "step": self.current_step,
                },
            )

            self.plan_items = self.attack_planner.generate_plan()
            await self.emit_event(
                "PLAN_GENERATED",
                {
                    "plan_items_count": len(self.plan_items),
                    "items": [
                        {
                            "plan_id": it.plan_id,
                            "category": it.category.value,
                            "path": it.target_path,
                            "method": it.method,
                            "priority": it.priority,
                        }
                        for it in self.plan_items
                    ],
                },
            )

            # -------------------------------------------------------------
            # Step 4: Targeted Attack Execution & Verification
            # -------------------------------------------------------------
            self.status = OrchestratorStatus.ATTACKING
            self.progress = 70
            self.current_step = "Executing specialist executors with Double-Proof verification"
            await self.emit_event(
                "STATUS_CHANGED",
                {
                    "status": self.status.value,
                    "progress": self.progress,
                    "step": self.current_step,
                },
            )

            self.attack_engine.base_url = target_base_url.rstrip("/")
            verified_findings = await self.attack_engine.run_plan(
                plan_items=self.plan_items,
            )

            for f in verified_findings:
                await self.emit_event(
                    "FINDING_DISCOVERED",
                    {
                        "finding_id": f.finding_id,
                        "title": f.title,
                        "category": f.category.value,
                        "endpoint": f.target_endpoint,
                        "reproduction_curl": f.proof.reproduction_curl,
                    },
                )

            # -------------------------------------------------------------
            # Step 5: Contextual Severity Triaging
            # -------------------------------------------------------------
            self.status = OrchestratorStatus.TRIAGING
            self.progress = 90
            self.current_step = "Evaluating contextual business asset impact and exploitability"
            await self.emit_event(
                "STATUS_CHANGED",
                {
                    "status": self.status.value,
                    "progress": self.progress,
                    "step": self.current_step,
                },
            )

            shadow_paths = {
                r.path
                for r in self.inventory_records
                if r.classification == InventoryClassification.SHADOW
            }
            zombie_paths = {
                r.path
                for r in self.inventory_records
                if r.classification
                in {
                    InventoryClassification.ZOMBIE,
                    InventoryClassification.ZOMBIE_UNDOCUMENTED,
                }
            }

            for f in verified_findings:
                is_shadow = any(sp in f.target_endpoint for sp in shadow_paths)
                is_zombie = any(zp in f.target_endpoint for zp in zombie_paths)
                breakdown = self.triage_agent.triage_finding(
                    finding=f,
                    is_shadow=is_shadow,
                    is_zombie=is_zombie,
                )
                await self.emit_event(
                    "FINDING_TRIAGED",
                    {
                        "finding_id": f.finding_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "score": breakdown.final_score,
                        "rationale": breakdown.rationale,
                    },
                )

            self.findings = verified_findings

            # -------------------------------------------------------------
            # Step 6: Completion
            # -------------------------------------------------------------
            self.status = OrchestratorStatus.COMPLETED
            self.progress = 100
            self.current_step = "Scan completed successfully"
            await self.emit_event(
                "STATUS_CHANGED",
                {
                    "status": self.status.value,
                    "progress": self.progress,
                    "step": self.current_step,
                    "total_findings": len(self.findings),
                },
            )

            return self.findings

    async def retest(
        self,
        finding_id: str | None = None,
        custom_headers: dict[str, str] | None = None,
    ) -> list[RetestResult]:
        """Trigger automated retest verification of specified or all findings."""
        if finding_id:
            targets = [f for f in self.findings if f.finding_id == finding_id]
        else:
            targets = list(self.findings)

        results: list[RetestResult] = []
        for target in targets:
            await self.emit_event(
                "RETEST_STARTED",
                {
                    "finding_id": target.finding_id,
                    "title": target.title,
                },
            )
            res = await self.retest_agent.retest_finding(
                finding=target,
                custom_headers=custom_headers,
            )
            results.append(res)
            await self.emit_event(
                "RETEST_RESULT",
                {
                    "finding_id": res.finding_id,
                    "is_fixed": res.is_fixed,
                    "previous_status": res.previous_status.value,
                    "new_status": res.new_status.value,
                    "status_code": res.status_code,
                    "rationale": res.rationale,
                },
            )

        return results

    def get_state(self) -> dict[str, Any]:
        """Return system status snapshot."""
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        status_counts = {
            FindingStatus.OPEN.value: 0,
            FindingStatus.VERIFIED.value: 0,
            FindingStatus.FIXED.value: 0,
            FindingStatus.REGRESSION.value: 0,
        }

        for f in self.findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
            status_counts[f.status.value] = status_counts.get(f.status.value, 0) + 1

        return {
            "status": self.status.value,
            "progress": self.progress,
            "current_step": self.current_step,
            "target_url": self.target_url,
            "last_scan_time": self.last_scan_time,
            "endpoints_count": self.kg.get_endpoint_count(),
            "findings_count": len(self.findings),
            "severity_breakdown": severity_counts,
            "status_breakdown": status_counts,
            "kill_switch_active": self.kill_switch.is_active(),
            "pending_approvals_count": len(self.approval_gate.get_pending_approvals()),
        }

    def get_graph(self) -> dict[str, Any]:
        """Return graph nodes and edges tailored for React Flow rendering."""
        return self.kg.export_topology_for_ui()

    def get_inventory(self) -> dict[str, Any]:
        """Return categorized API inventory listing."""
        if not self.inventory_records:
            return {"active": [], "zombie": [], "shadow": []}

        return {
            "active": [
                {
                    "path": r.path,
                    "method": r.method,
                    "last_seen": r.last_traffic_date,
                    "request_count": r.traffic_hit_count,
                    "status": "ACTIVE",
                    "risk_level": r.risk_level,
                    "recommendation": r.recommendation,
                }
                for r in self.inventory_records
                if r.classification == InventoryClassification.ACTIVE
            ],
            "zombie": [
                {
                    "path": r.path,
                    "method": r.method,
                    "last_seen": r.last_traffic_date,
                    "request_count": r.traffic_hit_count,
                    "status": "ZOMBIE",
                    "risk_level": r.risk_level,
                    "recommendation": r.recommendation,
                }
                for r in self.inventory_records
                if r.classification
                in {
                    InventoryClassification.ZOMBIE,
                    InventoryClassification.ZOMBIE_UNDOCUMENTED,
                }
            ],
            "shadow": [
                {
                    "path": r.path,
                    "method": r.method,
                    "last_seen": r.last_traffic_date,
                    "request_count": r.traffic_hit_count,
                    "status": "SHADOW",
                    "risk_level": r.risk_level,
                    "recommendation": r.recommendation,
                }
                for r in self.inventory_records
                if r.classification == InventoryClassification.SHADOW
            ],
        }

    def get_findings(self) -> list[dict[str, Any]]:
        """Return serialized list of all verified & triaged findings."""
        return [f.to_dict() for f in self.findings]

    def get_openapi_spec(self) -> dict[str, Any]:
        """Synthesize reverse-engineered OpenAPI 3.1 specification."""
        return self.openapi_gen.generate_spec(title="Voyager Synthesized API", version="3.1.0")

    def get_safety_status(self) -> dict[str, Any]:
        """Inspect active safety posture."""
        return {
            "kill_switch_active": self.kill_switch.is_active(),
            "scope_allowlist": [
                t.get("host") for t in self.scope_manager.allowed_targets if isinstance(t, dict)
            ] or ["127.0.0.1", "localhost"],
            "pending_approvals": self.approval_gate.get_pending_approvals(),
            "rate_limits": {
                "rpm": self.rate_limiter.requests_per_minute,
                "concurrency": self.rate_limiter.max_concurrent_requests,
            },
        }
