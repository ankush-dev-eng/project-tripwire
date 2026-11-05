"""Voyager-B Independent Target Application."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from lab_b.data_store import db_b
from lab_b.models import PatchRegistryB
from lab_b.routers.auth import router as auth_router
from lab_b.routers.finance import router as finance_router
from lab_b.routers.legacy import router as legacy_router
from lab_b.routers.ops import router as ops_router
from lab_b.routers.supplier import router as supplier_router
from lab_b.routers.travel import router as travel_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    db_b.reset()
    PatchRegistryB.reset()
    yield


app_b = FastAPI(
    title="Voyager-B Enterprise Travel Distribution API",
    description="Second independent laboratory target with modular router layout and distinct vulnerability variants.",
    version="2.4.0",
    lifespan=lifespan,
)

app_b.include_router(auth_router)
app_b.include_router(travel_router)
app_b.include_router(finance_router)
app_b.include_router(supplier_router)
app_b.include_router(ops_router)
app_b.include_router(legacy_router)


@app_b.get("/static/portal.js")
@app_b.get("/static/bundle.js")
async def client_portal_bundle() -> PlainTextResponse:
    """Frontend route bundle for Voyager-B."""
    js_code = """
    // Voyager-B Enterprise Client Portal v2.4
    const B2B_ENDPOINTS = {
        tokenExchange: "/v2/iam/tokens/exchange",
        recoverPassword: "/v2/iam/password/recover",
        agents: "/v2/iam/agents",
        tickets: "/v2/travel/tickets/{ticket_id}",
        reservations: "/v2/travel/reservations/{res_id}/passengers",
        orders: "/v2/travel/orders",
        orderRefund: "/v2/travel/orders/{order_id}/refund",
        orderFinalize: "/v2/travel/orders/{order_id}/finalize",
        catalogSearch: "/v2/travel/catalog/search",
        statements: "/v2/finance/statements/{stmt_id}",
        accounts: "/v2/finance/accounts/{acct_id}",
        creditsApply: "/v2/finance/credits/apply",
        balance: "/v2/finance/balance",
        webhooks: "/v2/supplier/webhooks",
        feedImport: "/v2/supplier/feed-import",
        dnsLookup: "/v2/supplier/dns-lookup",
        exportCsv: "/v2/supplier/export-csv",
        metrics: "/v2/ops/prometheus",
        crashReport: "/v2/ops/crash-report",
        ping: "/v2/ops/ping"
    };
    """
    return PlainTextResponse(content=js_code, media_type="application/javascript")


class PatchToggleRequest(BaseModel):
    vuln_id: str
    patched: bool


@app_b.post("/lab_b/patches/toggle")
async def toggle_patch(req: PatchToggleRequest) -> dict[str, Any]:
    PatchRegistryB.set_patched(req.vuln_id, req.patched)
    return {
        "vuln_id": req.vuln_id,
        "patched": PatchRegistryB.is_patched(req.vuln_id),
    }


@app_b.get("/lab_b/patches")
async def get_patches() -> dict[str, bool]:
    return PatchRegistryB.get_states()


app = app_b
