"""Travel and Ticketing Router for Voyager-B."""

import time
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel

from lab_b.data_store import db_b
from lab_b.models import OrderB, PatchRegistryB
from lab_b.routers.auth import get_current_user_b

router = APIRouter(prefix="/v2/travel", tags=["travel"])


@router.get("/tickets/{ticket_id}")
async def get_ticket(
    ticket_id: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    # VULN-B-AC-01: BOLA on partner booking tickets
    user = get_current_user_b(authorization)
    ticket = db_b.tickets.get(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    if PatchRegistryB.is_patched("VULN-B-AC-01") and ticket.agency_id != user.agency_id:
        raise HTTPException(status_code=403, detail="Cross-agency ticket access prohibited")

    return ticket.model_dump()


@router.get("/reservations/{res_id}/passengers")
async def get_reservation_passengers(
    res_id: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    # VULN-B-AC-03: BOLA on passenger roster
    user = get_current_user_b(authorization)
    order = db_b.orders.get(res_id)
    if not order:
        raise HTTPException(status_code=404, detail="Reservation not found")

    if PatchRegistryB.is_patched("VULN-B-AC-03") and order.agency_id != user.agency_id:
        raise HTTPException(status_code=403, detail="Roster access denied for cross-agency order")

    return {
        "reservation_id": res_id,
        "passengers": [
            {"name": "Alice Morgan", "seat": "14A", "tier": "Gold"},
            {"name": "Boris Vance", "seat": "14B", "tier": "Silver"},
        ],
    }


class OrderCreateRequest(BaseModel):
    carrier_code: str = "BA-284"
    seat_count: int
    unit_price: float | None = None


@router.post("/orders")
async def create_order(
    req: OrderCreateRequest,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    user = get_current_user_b(authorization)

    # VULN-B-BL-01: Negative seat count
    if PatchRegistryB.is_patched("VULN-B-BL-01") and req.seat_count <= 0:
        raise HTTPException(status_code=400, detail="Invalid seat count: must be > 0")

    # VULN-B-BL-02: Zero-price fare tampering
    unit_fare = 450.0
    if not PatchRegistryB.is_patched("VULN-B-BL-02") and req.unit_price is not None:
        unit_fare = float(req.unit_price)

    order_id = f"ORD-{user.agency_id}-{int(time.time())}"
    total = round(unit_fare * req.seat_count, 2)
    order = OrderB(
        order_id=order_id,
        agency_id=user.agency_id,
        carrier_code=req.carrier_code,
        seat_count=req.seat_count,
        unit_price=unit_fare,
        total_charged=total,
        status="CONFIRMED",
    )
    db_b.orders[order_id] = order
    return order.model_dump()


@router.post("/orders/{order_id}/refund")
async def refund_order(
    order_id: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    get_current_user_b(authorization)
    order = db_b.orders.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # VULN-B-BL-04: Double refund
    if PatchRegistryB.is_patched("VULN-B-BL-04") and order.status == "REFUNDED":
        raise HTTPException(status_code=400, detail="Order has already been refunded")

    order.refunded_amount += order.total_charged
    order.status = "REFUNDED"
    return {
        "order_id": order.order_id,
        "status": "REFUNDED",
        "refunded_total": order.refunded_amount,
    }


@router.post("/orders/{order_id}/finalize")
async def finalize_order(
    order_id: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    get_current_user_b(authorization)
    order = db_b.orders.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # VULN-B-BL-05: Finalization without payment settlement
    if PatchRegistryB.is_patched("VULN-B-BL-05") and order.status != "SETTLED":
        raise HTTPException(status_code=400, detail="Cannot finalize unsettled booking")

    order.status = "FINALIZED"
    return {"order_id": order_id, "status": "FINALIZED"}


@router.get("/catalog/search")
async def catalog_search(carrier: str = Query(...)) -> dict[str, Any]:
    # VULN-B-INJ-01: JSON / SQL filter injection
    if not PatchRegistryB.is_patched("VULN-B-INJ-01") and any(
        k in carrier for k in ["'", "--", "OR", "1=1"]
    ):
        return {
            "injected": True,
            "carrier": carrier,
            "results": [
                {"flight": "BA-284", "status": "AVAILABLE"},
                {"flight": "LH-441", "status": "AVAILABLE"},
                {"flight": "SECRET-MIL-01", "status": "CONFIDENTIAL"},
            ],
        }
    return {
        "injected": False,
        "carrier": carrier,
        "results": [{"flight": "BA-284", "status": "AVAILABLE"}],
    }
