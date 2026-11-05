"""Finance and Ledger Router for Voyager-B."""

from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from lab_b.data_store import db_b
from lab_b.models import PatchRegistryB
from lab_b.routers.auth import get_current_user_b

router = APIRouter(prefix="/v2/finance", tags=["finance"])


@router.get("/statements/{stmt_id}")
async def get_statement(
    stmt_id: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    # VULN-B-AC-02: BOLA on financial statements
    user = get_current_user_b(authorization)
    stmt = db_b.statements.get(stmt_id)
    if not stmt:
        raise HTTPException(status_code=404, detail="Statement not found")

    if PatchRegistryB.is_patched("VULN-B-AC-02") and stmt["agency_id"] != user.agency_id:
        raise HTTPException(status_code=403, detail="Unauthorized statement access")

    return stmt


class AccountUpdateRequest(BaseModel):
    account_tier: str | None = None
    overdraft_limit: float | None = None


@router.put("/accounts/{acct_id}")
async def update_account(
    acct_id: str,
    req: AccountUpdateRequest,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    # VULN-B-BOPLA-02: Client-side tampering of overdraft_limit
    get_current_user_b(authorization)
    agency = db_b.agencies.get(acct_id)
    if not agency:
        raise HTTPException(status_code=404, detail="Account not found")

    if PatchRegistryB.is_patched("VULN-B-BOPLA-02") and req.overdraft_limit is not None:
        raise HTTPException(status_code=403, detail="Overdraft modification prohibited")

    if req.account_tier:
        agency.account_tier = req.account_tier
    if req.overdraft_limit is not None:
        agency.credit_pool += req.overdraft_limit

    return {
        "agency_id": agency.agency_id,
        "account_tier": agency.account_tier,
        "credit_pool": agency.credit_pool,
    }


class CreditApplyRequest(BaseModel):
    voucher_code: str
    nonce: str


@router.post("/credits/apply")
async def apply_voucher(
    req: CreditApplyRequest,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    # VULN-B-BL-03: Repeated voucher redemption without nonce invalidation
    user = get_current_user_b(authorization)
    agency = db_b.agencies.get(user.agency_id)
    if not agency:
        raise HTTPException(status_code=404, detail="Agency not found")

    if PatchRegistryB.is_patched("VULN-B-BL-03") and req.nonce in db_b.used_promo_nonces:
        raise HTTPException(status_code=400, detail="Voucher nonce already redeemed")

    db_b.used_promo_nonces.add(req.nonce)
    agency.credit_pool += 500.00
    return {
        "status": "APPLIED",
        "voucher": req.voucher_code,
        "credit_added": 500.00,
        "new_pool": agency.credit_pool,
    }


@router.get("/balance")
async def get_balance(authorization: str | None = Header(None)) -> dict[str, Any]:
    user = get_current_user_b(authorization)
    agency = db_b.agencies.get(user.agency_id)
    if not agency:
        raise HTTPException(status_code=404, detail="Agency not found")
    return {"agency_id": agency.agency_id, "credit_pool": agency.credit_pool}
