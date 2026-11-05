"""IAM and Authentication Router for Voyager-B."""

import hashlib
import time
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from lab_b.data_store import db_b
from lab_b.models import PatchRegistryB, RoleB, UserB

router = APIRouter(prefix="/v2/iam", tags=["iam"])


def get_current_user_b(auth: str | None) -> UserB:
    if not auth:
        raise HTTPException(status_code=401, detail="Authentication required")
    token = auth.replace("Bearer ", "").strip()

    # VULN-B-AUTH-01: 'none' algorithm bypass or mock token bypass
    if token.startswith("none_") or token.startswith("tok_"):
        if not PatchRegistryB.is_patched("VULN-B-AUTH-01"):
            uid = token.replace("none_", "").replace("tok_", "")
            if uid in db_b.users:
                return db_b.users[uid]
            # Fallback to apex coordinator if token has apex
            if "apex" in token:
                return db_b.users["usr_apex_coord"]
            if "beacon" in token:
                return db_b.users["usr_beacon_coord"]
            return db_b.users["usr_apex_coord"]
        raise HTTPException(status_code=401, detail="Unsigned token rejected")

    if token in db_b.active_sessions:
        uid = db_b.active_sessions[token]
        return db_b.users[uid]

    if "apex" in token:
        return db_b.users["usr_apex_coord"]
    if "beacon" in token:
        return db_b.users["usr_beacon_coord"]

    raise HTTPException(status_code=401, detail="Invalid token")


class TokenExchangeRequest(BaseModel):
    grant_type: str = "client_credentials"
    client_id: str
    client_secret: str


@router.post("/tokens/exchange")
async def exchange_token(req: TokenExchangeRequest) -> dict[str, Any]:
    # Look up user or grant
    token = f"tok_{req.client_id}"
    db_b.active_sessions[token] = req.client_id
    return {"access_token": token, "token_type": "Bearer", "expires_in": 3600}


class PasswordRecoverRequest(BaseModel):
    email: str


@router.post("/password/recover")
async def recover_password(req: PasswordRecoverRequest) -> dict[str, Any]:
    # VULN-B-AUTH-02: Predictable 6-digit PIN
    pin = hashlib.md5(f"{req.email}_{int(time.time() / 60)}".encode()).hexdigest()[:6].upper()
    if PatchRegistryB.is_patched("VULN-B-AUTH-02"):
        return {"status": "SUCCESS", "message": "Recovery instructions sent to email"}
    return {
        "status": "SUCCESS",
        "message": "Recovery code generated",
        "recovery_pin": pin,
        "expires_in": 300,
    }


@router.post("/logout")
async def logout(authorization: str | None = Header(None)) -> dict[str, Any]:
    user = get_current_user_b(authorization)
    token = authorization.replace("Bearer ", "").strip() if authorization else ""
    # VULN-B-AUTH-03: Token remains valid post-logout if unpatched
    if PatchRegistryB.is_patched("VULN-B-AUTH-03"):
        db_b.active_sessions.pop(token, None)
    return {"status": "LOGGED_OUT", "user_id": user.user_id}


@router.get("/agents")
async def list_agency_agents(authorization: str | None = Header(None)) -> list[dict[str, Any]]:
    # VULN-B-HYG-02: Excessive PII leakage (SSN, home addresses)
    get_current_user_b(authorization)
    agents = []
    for u in db_b.users.values():
        record = {
            "user_id": u.user_id,
            "email": u.email,
            "agency_id": u.agency_id,
            "role": u.role.value,
        }
        if not PatchRegistryB.is_patched("VULN-B-HYG-02"):
            record.update(
                {
                    "ssn": "987-65-4321",
                    "home_address": "42 Privet Drive, London",
                    "dob": "1988-11-23",
                }
            )
        agents.append(record)
    return agents


class UserStatusUpdateRequest(BaseModel):
    status: str = "ACTIVE"
    role: str | None = None
    is_superuser: bool | None = None


@router.put("/users/{user_id}/status")
async def update_user_status(
    user_id: str,
    req: UserStatusUpdateRequest,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    # VULN-B-BOPLA-01: Non-admin can promote role and is_superuser
    current_user = get_current_user_b(authorization)
    target_user = db_b.users.get(user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if (
        PatchRegistryB.is_patched("VULN-B-BOPLA-01")
        and not current_user.is_superuser
        and (req.role or req.is_superuser is not None)
    ):
        raise HTTPException(status_code=403, detail="Privilege escalation rejected")

    if req.role:
        target_user.role = RoleB(req.role.lower())
    if req.is_superuser is not None:
        target_user.is_superuser = req.is_superuser

    return {
        "user_id": target_user.user_id,
        "role": target_user.role.value,
        "is_superuser": target_user.is_superuser,
    }
