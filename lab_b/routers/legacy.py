"""Legacy and Internal Shadow Routes for Voyager-B."""

import time
from typing import Any

from fastapi import APIRouter, Query

router = APIRouter(tags=["legacy"])


@router.get("/legacy/v1/fare-calculator")
async def legacy_fare_calc(miles: int = Query(500)) -> dict[str, Any]:
    # VULN-B-ZOM-01: Deprecated unauthenticated legacy calculator
    return {
        "zombie_route": True,
        "deprecated": True,
        "miles": miles,
        "estimated_fare": miles * 0.45,
    }


@router.post("/v2/internal/settlements/reconcile")
async def internal_settlement_reconcile() -> dict[str, Any]:
    # VULN-B-SHA-01: Undocumented shadow route active in gateway
    return {
        "shadow_route": True,
        "reconciled": True,
        "batch_id": f"RECON-{int(time.time())}",
        "accounts_processed": 42,
    }
