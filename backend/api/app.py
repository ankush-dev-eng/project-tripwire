"""TRIPWIRE Central Mission Control FastAPI & WebSocket Server.

Exposes REST APIs and a real-time duplex WebSocket event stream for:
- Scan execution & orchestrator state
- Interactive Knowledge Graph visualization
- Active / Zombie / Shadow API Inventory
- Verified & Triaged Findings with Double-Proof evidence
- Human-in-the-Loop Approvals Queue
- Safety Console (Kill Switch, Scope, Audit)
- Automated Retest Engine
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.orchestrator import OrchestratorStatus, TripwireOrchestrator

# Global Singleton Orchestrator Instance
orchestrator = TripwireOrchestrator()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Startup tasks if needed
    yield
    # Cleanup tasks
    await orchestrator.client.close()


api_app = FastAPI(
    title="PROJECT TRIPWIRE Mission Control API",
    description="Agentic Real-Time DAST for B2B Travel Platforms API and Event Stream.",
    version="1.0.0",
    lifespan=lifespan,
)

# Allow React Mission Control UI on Vite dev server
api_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request & Response Schemas
class StartScanRequest(BaseModel):
    target_url: str = Field(default="http://127.0.0.1:8000")
    traffic_log_path: str = Field(default="data/gateway_30d.log")
    js_bundle_url: str = Field(default="http://127.0.0.1:8000/static/bundle.js")


class ApprovalResolutionRequest(BaseModel):
    operator_id: str = "security_lead"
    reason: str = ""


class RetestRequest(BaseModel):
    finding_id: str | None = None


# -------------------------------------------------------------
# 1. Orchestrator Scan Control Endpoints
# -------------------------------------------------------------
@api_app.post("/api/scan/start")
async def start_scan(req: StartScanRequest) -> dict[str, Any]:
    if orchestrator.status in {
        OrchestratorStatus.RECON,
        OrchestratorStatus.INVENTORY,
        OrchestratorStatus.PLANNING,
        OrchestratorStatus.ATTACKING,
        OrchestratorStatus.TRIAGING,
    }:
        raise HTTPException(
            status_code=409,
            detail=f"Scan already in progress (Status: {orchestrator.status.value})",
        )

    if orchestrator.kill_switch.is_active():
        raise HTTPException(
            status_code=400,
            detail="Cannot start scan: Emergency Kill Switch is ACTIVE. Disarm before scanning.",
        )

    # Launch autonomous assessment as background task
    asyncio.create_task(
        orchestrator.run_scan(
            target_base_url=req.target_url,
            traffic_log_path=req.traffic_log_path,
            js_bundle_url=req.js_bundle_url,
        )
    )

    return {
        "status": "SCAN_STARTED",
        "target_url": req.target_url,
        "message": "Autonomous DAST scan launched in background.",
    }


@api_app.get("/api/scan/status")
async def get_scan_status() -> dict[str, Any]:
    return orchestrator.get_state()


# -------------------------------------------------------------
# 2. Knowledge Graph Endpoints
# -------------------------------------------------------------
@api_app.get("/api/graph")
async def get_knowledge_graph() -> dict[str, Any]:
    return orchestrator.get_graph()


# -------------------------------------------------------------
# 3. API Inventory Endpoints (Active / Zombie / Shadow)
# -------------------------------------------------------------
@api_app.get("/api/inventory")
async def get_api_inventory() -> dict[str, Any]:
    return orchestrator.get_inventory()


# -------------------------------------------------------------
# 4. Findings & Evidence Endpoints
# -------------------------------------------------------------
@api_app.get("/api/findings")
async def list_findings() -> list[dict[str, Any]]:
    return orchestrator.get_findings()


@api_app.get("/api/findings/{finding_id}")
async def get_finding(finding_id: str) -> dict[str, Any]:
    finding = next((f for f in orchestrator.findings if f.finding_id == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding.to_dict()


# -------------------------------------------------------------
# 5. Automated Retest Engine Endpoints
# -------------------------------------------------------------
@api_app.post("/api/retest")
async def trigger_retest(req: RetestRequest) -> list[dict[str, Any]]:
    results = await orchestrator.retest(finding_id=req.finding_id)
    return [
        {
            "finding_id": r.finding_id,
            "target_endpoint": r.target_endpoint,
            "method": r.method,
            "previous_status": r.previous_status.value,
            "new_status": r.new_status.value,
            "is_fixed": r.is_fixed,
            "status_code": r.status_code,
            "rationale": r.rationale,
            "retested_at": r.retested_at,
        }
        for r in results
    ]


# -------------------------------------------------------------
# 6. Human-in-the-Loop Approvals Queue Endpoints
# -------------------------------------------------------------
@api_app.get("/api/approvals")
async def list_pending_approvals() -> list[dict[str, Any]]:
    return orchestrator.approval_gate.get_pending_approvals()


@api_app.post("/api/approvals/{request_id}/approve")
async def approve_request(
    request_id: str,
    req: ApprovalResolutionRequest,
) -> dict[str, Any]:
    try:
        token = orchestrator.approval_gate.approve_request(
            request_id=request_id,
            operator_id=req.operator_id,
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    await orchestrator.emit_event(
        "APPROVAL_RESOLVED",
        {
            "request_id": request_id,
            "action": "APPROVED",
            "operator_id": req.operator_id,
        },
    )

    return {
        "status": "APPROVED",
        "request_id": request_id,
        "approval_token": token,
    }


@api_app.post("/api/approvals/{request_id}/reject")
async def reject_request(
    request_id: str,
    req: ApprovalResolutionRequest,
) -> dict[str, Any]:
    try:
        record = orchestrator.approval_gate.reject_request(
            request_id=request_id,
            operator_id=req.operator_id,
            reason=req.reason,
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    await orchestrator.emit_event(
        "APPROVAL_RESOLVED",
        {
            "request_id": request_id,
            "action": "REJECTED",
            "operator_id": req.operator_id,
            "reason": req.reason,
        },
    )

    return {
        "status": "REJECTED",
        "request_id": request_id,
        "record": record,
    }


# -------------------------------------------------------------
# 7. Safety Console Endpoints (Kill Switch & Scope)
# -------------------------------------------------------------
@api_app.get("/api/safety")
async def get_safety_status() -> dict[str, Any]:
    return orchestrator.get_safety_status()


@api_app.post("/api/safety/kill")
async def trigger_kill_switch(reason: str = "Emergency stop via API") -> dict[str, str]:
    orchestrator.kill_switch.trigger(reason)
    await orchestrator.emit_event(
        "SAFETY_EVENT",
        {
            "event": "KILL_SWITCH_ACTIVATED",
            "reason": reason,
        },
    )
    return {"status": "KILL_SWITCH_ACTIVATED", "reason": reason}


@api_app.post("/api/safety/disarm")
async def disarm_kill_switch() -> dict[str, str]:
    orchestrator.kill_switch.reset()
    await orchestrator.emit_event(
        "SAFETY_EVENT",
        {
            "event": "KILL_SWITCH_DISARMED",
        },
    )
    return {"status": "KILL_SWITCH_DISARMED"}


# -------------------------------------------------------------
# 8. Synthesized OpenAPI Specification
# -------------------------------------------------------------
@api_app.get("/api/spec/openapi.json")
async def get_openapi_specification() -> dict[str, Any]:
    return orchestrator.get_openapi_spec()


# -------------------------------------------------------------
# 9. Real-Time Duplex WebSocket Event Stream
# -------------------------------------------------------------
@api_app.websocket("/ws/stream")
async def websocket_event_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    orchestrator.add_subscriber(queue)

    # Initial state sync message upon connection
    await websocket.send_json(
        {
            "type": "INITIAL_SYNC",
            "state": orchestrator.get_state(),
        }
    )

    async def event_sender() -> None:
        try:
            while True:
                event = await queue.get()
                await websocket.send_json(event)
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass

    async def message_receiver() -> None:
        try:
            while True:
                msg = await websocket.receive_json()
                action = msg.get("action")
                if action == "ping":
                    await websocket.send_json({"type": "pong"})
                elif action == "get_state":
                    await websocket.send_json(
                        {
                            "type": "STATE_UPDATE",
                            "state": orchestrator.get_state(),
                        }
                    )
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass

    sender_task = asyncio.create_task(event_sender())
    receiver_task = asyncio.create_task(message_receiver())

    try:
        done, pending = await asyncio.wait(
            [sender_task, receiver_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
    finally:
        orchestrator.remove_subscriber(queue)


# -------------------------------------------------------------
# 10. Frontend Single Page Application Static File Serving
# -------------------------------------------------------------
frontend_dist = Path("frontend/dist")
if frontend_dist.exists() and (frontend_dist / "index.html").exists():
    assets_dir = frontend_dist / "assets"
    if assets_dir.exists():
        api_app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @api_app.get("/{full_path:path}")
    async def serve_spa(full_path: str) -> FileResponse:
        # Avoid intercepting API or WebSocket routes
        if full_path.startswith("api") or full_path.startswith("ws"):
            raise HTTPException(status_code=404, detail="Not found")
        target_file = frontend_dist / full_path
        if target_file.is_file():
            return FileResponse(target_file)
        return FileResponse(frontend_dist / "index.html")
else:

    @api_app.get("/")
    async def serve_fallback_spa() -> HTMLResponse:
        return HTMLResponse(
            "<!DOCTYPE html><html><head><title>PROJECT TRIPWIRE</title></head><body><h1>PROJECT TRIPWIRE Mission Control</h1></body></html>"
        )
