"""Voyager Mock B2B Travel Platform Application.

Contains realistic travel workflows (search, hold, book, pay, cancel, refund),
multi-tenant role-based access, and 26 seeded vulnerabilities with individual patch toggles.
"""

import hashlib
import json
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel

from lab.data_store import db
from lab.models import Booking, BookingStatus, Passenger, PatchRegistry, Role, User

SECRET_KEY = "voyager_dev_jwt_secret_key_2026"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Ensure fresh DB state on startup
    db.reset()
    yield


app = FastAPI(
    title="Voyager B2B Travel Platform",
    description="Mock production-like travel distribution API with multi-tenancy and workflows.",
    version="3.4.0",
    lifespan=lifespan,
)


# Helper Auth & Token Utilities
def create_token(user: User) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user.user_id,
        "email": user.email,
        "agency_id": user.agency_id,
        "role": user.role.value,
        "exp": int(time.time()) + 3600,
    }
    h_b64 = hashlib.sha256(json.dumps(header).encode()).hexdigest()[:16]
    p_b64 = hashlib.sha256(json.dumps(payload).encode()).hexdigest()[:16]
    sig = hashlib.sha256(f"{h_b64}.{p_b64}.{SECRET_KEY}".encode()).hexdigest()[:16]
    return f"{h_b64}.{p_b64}.{sig}"


def get_current_user(authorization: str | None) -> User:
    """Validate Bearer token and return current User. Supports JWT none exploit if unpatched."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = authorization.replace("Bearer ", "").strip()

    # VULN-AUTH-02: Check if unsigned JWT accepted
    if token.startswith("none_alg_"):
        if not PatchRegistry.is_patched("VULN-AUTH-02"):
            # Simulated 'none' alg payload: none_alg_<user_id>
            user_id = token.replace("none_alg_", "")
            if user_id in db.users:
                return db.users[user_id]
        raise HTTPException(status_code=401, detail="Unsigned 'none' algorithm token rejected")

    # Look up in active sessions
    if token in db.active_sessions:
        user_id = db.active_sessions[token]["user_id"]
        if user_id in db.users:
            return db.users[user_id]

    # Fallback to default demo user if token is mock
    for u in db.users.values():
        if u.email in token or u.user_id in token:
            return u

    if "test" in token or "alpha" in token:
        return db.users["USR_ALPHA_AGENT"]
    if "beta" in token:
        return db.users["USR_BETA_AGENT"]

    raise HTTPException(status_code=401, detail="Invalid or expired token")


# -------------------------------------------------------------
# 1. Authentication Routes
# -------------------------------------------------------------
class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/api/v3/auth/login")
async def login(req: LoginRequest) -> dict[str, Any]:
    # VULN-HYG-03: Missing rate limiting (no lockout on failed attempts)
    pwd_hash = hashlib.sha256(req.password.encode()).hexdigest()
    user = next((u for u in db.users.values() if u.email == req.email), None)

    if not user or user.password_hash != pwd_hash:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = f"tok_{user.user_id}_{hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]}"
    db.active_sessions[token] = {
        "user_id": user.user_id,
        "agency_id": user.agency_id,
        "created_at": time.time(),
    }
    return {
        "access_token": token,
        "token_type": "Bearer",
        "user": {
            "user_id": user.user_id,
            "email": user.email,
            "role": user.role.value,
            "agency_id": user.agency_id,
        },
    }


class ResetPasswordRequest(BaseModel):
    email: str


@app.post("/api/v3/auth/reset-password")
async def reset_password(req: ResetPasswordRequest) -> dict[str, Any]:
    # VULN-AUTH-01: Predictable reset token using email and rounded minute timestamp
    if not PatchRegistry.is_patched("VULN-AUTH-01"):
        rounded_minute = int(time.time() / 60)
        predictable_token = hashlib.md5(f"{req.email}-{rounded_minute}".encode()).hexdigest()
    else:
        predictable_token = hashlib.sha256(os.urandom(32)).hexdigest()

    return {
        "message": "Password reset instructions sent",
        "reset_token": predictable_token,
    }


@app.post("/api/v3/auth/logout")
async def logout(authorization: str | None = Header(None)) -> dict[str, Any]:
    # VULN-AUTH-04: Token remains valid post-logout unless patched
    if authorization and PatchRegistry.is_patched("VULN-AUTH-04"):
        token = authorization.replace("Bearer ", "").strip()
        db.active_sessions.pop(token, None)
    return {"message": "Successfully logged out"}


@app.get("/api/v3/auth/redirect")
async def auth_redirect(url: str = Query(...)) -> Any:
    # VULN-SSR-02: Open redirect unless patched
    if PatchRegistry.is_patched("VULN-SSR-02") and not (
        url.startswith("https://voyager.travel") or url.startswith("/")
    ):
        raise HTTPException(status_code=400, detail="Untrusted redirect destination")
    return RedirectResponse(url=url, status_code=302)


# -------------------------------------------------------------
# 2. Agency & User Management Routes
# -------------------------------------------------------------
@app.get("/api/v3/agency/profile")
async def get_agency_profile(authorization: str | None = Header(None)) -> dict[str, Any]:
    user = get_current_user(authorization)
    agency = db.agencies.get(user.agency_id)
    if not agency:
        raise HTTPException(status_code=404, detail="Agency not found")
    return agency.model_dump()


class AgencyProfileUpdate(BaseModel):
    name: str | None = None
    credit_limit: float | None = None
    is_verified: bool | None = None


@app.put("/api/v3/agency/profile")
async def update_agency_profile(
    body: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    user = get_current_user(authorization)
    agency = db.agencies.get(user.agency_id)
    if not agency:
        raise HTTPException(status_code=404, detail="Agency not found")

    # VULN-HYG-01: Mass assignment allows updating credit_limit and is_verified unless patched
    if not PatchRegistry.is_patched("VULN-HYG-01"):
        if "credit_limit" in body:
            agency.credit_limit = float(body["credit_limit"])
        if "is_verified" in body:
            agency.is_verified = bool(body["is_verified"])
    if "name" in body:
        agency.name = str(body["name"])

    return agency.model_dump()


@app.get("/api/v3/agency/users")
async def list_agency_users(authorization: str | None = Header(None)) -> list[dict[str, Any]]:
    user = get_current_user(authorization)
    users = [u for u in db.users.values() if u.agency_id == user.agency_id]

    # VULN-HYG-02: Excessive data exposure (password_hash leaked) unless patched
    if not PatchRegistry.is_patched("VULN-HYG-02"):
        return [u.model_dump() for u in users]

    return [
        {"user_id": u.user_id, "email": u.email, "agency_id": u.agency_id, "role": u.role.value}
        for u in users
    ]


@app.post("/api/v3/agency/users/{user_id}/promote")
async def promote_user(user_id: str, authorization: str | None = Header(None)) -> dict[str, Any]:
    current_user = get_current_user(authorization)

    # VULN-AC-03: Sub-agent can promote users to admin unless patched
    if PatchRegistry.is_patched("VULN-AC-03") and current_user.role != Role.ADMIN:
        raise HTTPException(status_code=403, detail="Only agency admins may promote users")

    target_user = db.users.get(user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    target_user.role = Role.ADMIN
    return {
        "message": f"User {user_id} promoted to admin",
        "role": target_user.role.value,
    }


@app.post("/api/v3/agency/documents")
async def upload_document(request: Request) -> dict[str, Any]:
    # VULN-SSR-03: Unrestricted file upload
    body = await request.body()
    request.headers.get("content-type", "")
    filename = request.headers.get("x-filename", "document.pdf")

    if PatchRegistry.is_patched("VULN-SSR-03"):
        ext = os.path.splitext(filename)[1].lower()
        if ext not in {".pdf", ".jpg", ".png"}:
            raise HTTPException(status_code=400, detail="Disallowed document extension")

    file_id = f"doc_{hashlib.md5(body).hexdigest()[:8]}"
    db.uploaded_files[file_id] = body
    return {
        "file_id": file_id,
        "filename": filename,
        "size_bytes": len(body),
        "status": "STORED",
    }


# -------------------------------------------------------------
# 3. Flight Search & Inventory
# -------------------------------------------------------------
@app.get("/api/v3/flights/search")
async def search_flights(
    origin: str | None = None,
    destination: str | None = None,
    airline: str | None = None,
) -> dict[str, Any]:
    # VULN-INJ-01: SQL injection in flight search filter parameter airline
    if (
        airline
        and not PatchRegistry.is_patched("VULN-INJ-01")
        and ("'" in airline or "OR" in airline.upper() or "UNION" in airline.upper())
    ):
        return {
            "query_debug": f"SELECT * FROM flights WHERE airline = '{airline}'",
            "flights": [f.model_dump() for f in db.flights.values()],
            "injected": True,
        }

    results = list(db.flights.values())
    if origin:
        results = [f for f in results if f.origin == origin.upper()]
    if destination:
        results = [f for f in results if f.destination == destination.upper()]
    if airline:
        results = [f for f in results if f.airline.lower() == airline.lower()]

    return {"flights": [f.model_dump() for f in results], "count": len(results)}


# -------------------------------------------------------------
# 4. Booking Lifecycle (Hold, Pay, Confirm, Cancel, Refund)
# -------------------------------------------------------------
class HoldBookingRequest(BaseModel):
    flight_id: str
    passengers: list[dict[str, Any]]
    seat_count: int = 1
    total_amount: float | None = None


@app.post("/api/v3/bookings/hold")
async def hold_booking(
    req: HoldBookingRequest,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    user = get_current_user(authorization)
    flight = db.flights.get(req.flight_id)
    if not flight:
        raise HTTPException(status_code=404, detail="Flight not found")

    # VULN-BL-02: Negative quantity seat refund abuse
    seat_count = req.seat_count
    if PatchRegistry.is_patched("VULN-BL-02") and seat_count <= 0:
        raise HTTPException(status_code=400, detail="Seat count must be positive")

    # VULN-BL-01: Fare tampering: client total_amount accepted directly if unpatched
    if not PatchRegistry.is_patched("VULN-BL-01") and req.total_amount is not None:
        total = float(req.total_amount)
    else:
        total = flight.base_fare * seat_count

    booking_id = (
        f"BKG-{user.agency_id}-{hashlib.md5(str(time.time()).encode()).hexdigest()[:6].upper()}"
    )
    new_booking = Booking(
        booking_id=booking_id,
        agency_id=user.agency_id,
        flight_id=req.flight_id,
        passengers=[
            Passenger(
                name=p.get("name", "Passenger"),
                passport_number=p.get("passport_number", "P999999"),
                email=p.get("email", "pax@voyage.com"),
            )
            for p in req.passengers
        ],
        seat_count=seat_count,
        total_amount=total,
        status=BookingStatus.HELD,
        card_pan="4111111111111111",
        card_cvv="999",
    )
    db.bookings[booking_id] = new_booking
    return new_booking.model_dump()


@app.get("/api/v3/bookings/error-probe")
async def error_probe(debug: str | None = None) -> Any:
    # VULN-DAT-02: PII leaked in traceback
    if debug and not PatchRegistry.is_patched("VULN-DAT-02"):
        return JSONResponse(
            status_code=500,
            content={
                "error": "InternalServerError",
                "traceback": "Traceback (most recent call last):\n  File 'voyager/app.py', line 450, in probe\n  local_vars: {'passenger_name': 'Lord Sterling', 'passport': 'GB987654321', 'dob': '1980-04-12'}",
            },
        )
    return {"status": "healthy"}


@app.get("/api/v3/bookings/{booking_id}")
async def get_booking(
    booking_id: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    user = get_current_user(authorization)
    booking = db.bookings.get(booking_id)
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")

    # VULN-AC-01: Cross-Tenant Booking IDOR
    if PatchRegistry.is_patched("VULN-AC-01") and booking.agency_id != user.agency_id:
        raise HTTPException(status_code=403, detail="Access denied: Cross-agency IDOR blocked")

    return booking.model_dump()


@app.post("/api/v3/bookings/{booking_id}/pay")
async def pay_booking(
    booking_id: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    user = get_current_user(authorization)
    booking = db.bookings.get(booking_id)
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")

    agency = db.agencies.get(user.agency_id)
    if not agency:
        raise HTTPException(status_code=404, detail="Agency not found")

    if agency.wallet_balance < booking.total_amount:
        raise HTTPException(status_code=402, detail="Insufficient wallet balance")

    agency.wallet_balance -= booking.total_amount
    booking.status = BookingStatus.CONFIRMED
    return {
        "booking_id": booking.booking_id,
        "status": booking.status.value,
        "amount_paid": booking.total_amount,
        "remaining_wallet_balance": agency.wallet_balance,
    }


@app.post("/api/v3/bookings/{booking_id}/confirm")
async def confirm_booking_without_pay(
    booking_id: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    # VULN-BL-04: Skipped payment step to confirmed
    booking = db.bookings.get(booking_id)
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")

    if PatchRegistry.is_patched("VULN-BL-04") and booking.status != BookingStatus.CONFIRMED:
        raise HTTPException(
            status_code=400,
            detail="Cannot confirm booking without prior payment receipt",
        )

    booking.status = BookingStatus.CONFIRMED
    return {"booking_id": booking.booking_id, "status": "CONFIRMED", "paid": False}


@app.post("/api/v3/bookings/{booking_id}/cancel")
async def cancel_booking(
    booking_id: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    get_current_user(authorization)
    booking = db.bookings.get(booking_id)
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")

    agency = db.agencies.get(booking.agency_id)
    if not agency:
        raise HTTPException(status_code=404, detail="Agency not found")

    # VULN-BL-03: Double refund on cancellation flaw
    if PatchRegistry.is_patched("VULN-BL-03") and booking.status == BookingStatus.CANCELLED:
        raise HTTPException(status_code=400, detail="Booking is already cancelled and refunded")

    agency.wallet_balance += booking.total_amount
    booking.refund_count += 1
    booking.status = BookingStatus.CANCELLED

    return {
        "booking_id": booking.booking_id,
        "status": "CANCELLED",
        "refund_issued": booking.total_amount,
        "refund_count": booking.refund_count,
        "wallet_balance": agency.wallet_balance,
    }


class CouponRequest(BaseModel):
    coupon_code: str


@app.post("/api/v3/bookings/{booking_id}/apply-coupon")
async def apply_coupon(booking_id: str, req: CouponRequest) -> dict[str, Any]:
    booking = db.bookings.get(booking_id)
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")

    # VULN-BL-05: Infinite coupon reuse
    if req.coupon_code.upper() == "VOYAGER50":
        if PatchRegistry.is_patched("VULN-BL-05"):
            usage = db.used_coupons.get(req.coupon_code, 0)
            if usage >= 1:
                raise HTTPException(status_code=400, detail="Coupon code has already been redeemed")
            db.used_coupons[req.coupon_code] = usage + 1

        booking.total_amount = max(0.0, booking.total_amount * 0.5)
        return {
            "booking_id": booking.booking_id,
            "discount_applied": "50%",
            "new_total": booking.total_amount,
        }

    raise HTTPException(status_code=400, detail="Invalid promo code")


@app.get("/api/v3/bookings/{booking_id}/invoice")
async def get_invoice(
    booking_id: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    user = get_current_user(authorization)
    booking = db.bookings.get(booking_id)
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")

    # VULN-AC-04: Cross-tenant invoice IDOR
    if PatchRegistry.is_patched("VULN-AC-04") and booking.agency_id != user.agency_id:
        raise HTTPException(status_code=403, detail="Cross-agency invoice access denied")

    # VULN-DAT-01: Cleartext card PAN and CVV exposed unless patched
    card_pan = booking.card_pan or "4111111111111111"
    card_cvv = booking.card_cvv or "999"
    if PatchRegistry.is_patched("VULN-DAT-01"):
        card_pan = f"****-****-****-{card_pan[-4:]}"
        card_cvv = "***"

    return {
        "invoice_id": f"INV-{booking.booking_id}",
        "booking_id": booking.booking_id,
        "agency_id": booking.agency_id,
        "amount": booking.total_amount,
        "payment_method": {
            "type": "CREDIT_CARD",
            "card_number": card_pan,
            "cvv": card_cvv,
        },
    }


# -------------------------------------------------------------
# 5. Wallet Routes
# -------------------------------------------------------------
@app.get("/api/v3/wallet/balance")
async def get_wallet_balance(authorization: str | None = Header(None)) -> dict[str, Any]:
    user = get_current_user(authorization)
    agency = db.agencies.get(user.agency_id)
    if not agency:
        raise HTTPException(status_code=404, detail="Agency not found")
    return {
        "agency_id": agency.agency_id,
        "wallet_balance": agency.wallet_balance,
        "credit_limit": agency.credit_limit,
    }


class TopupRequest(BaseModel):
    amount: float


@app.post("/api/v3/wallet/topup")
async def wallet_topup(
    req: TopupRequest,
    x_stepup_token: str | None = Header(None),
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    user = get_current_user(authorization)
    agency = db.agencies.get(user.agency_id)
    if not agency:
        raise HTTPException(status_code=404, detail="Agency not found")

    # VULN-AUTH-03: Missing step-up auth for high value transfers
    if PatchRegistry.is_patched("VULN-AUTH-03") and req.amount >= 10000.0 and not x_stepup_token:
        raise HTTPException(
            status_code=403,
            detail="Step-up authentication required for transfers exceeding $10,000",
        )

    agency.wallet_balance += req.amount
    return {
        "agency_id": agency.agency_id,
        "amount_added": req.amount,
        "new_balance": agency.wallet_balance,
    }


# -------------------------------------------------------------
# 6. Supplier Integration Routes
# -------------------------------------------------------------
class WebhookRequest(BaseModel):
    callback_url: str


@app.post("/api/v3/supplier/webhook")
async def register_supplier_webhook(req: WebhookRequest) -> dict[str, Any]:
    # VULN-SSR-01: SSRF in callback_url
    if PatchRegistry.is_patched("VULN-SSR-01") and (
        "169.254" in req.callback_url
        or "localhost" in req.callback_url
        or "127.0.0.1" in req.callback_url
    ):
        raise HTTPException(
            status_code=400,
            detail="SSRF blocked: Internal and link-local IP addresses disallowed",
        )

    return {
        "status": "REGISTERED",
        "callback_url": req.callback_url,
        "registered_at": time.time(),
    }


@app.get("/api/v3/supplier/diagnostics")
async def supplier_diagnostics(host: str = Query(...)) -> dict[str, Any]:
    # VULN-INJ-02: Command injection in host parameter
    if not PatchRegistry.is_patched("VULN-INJ-02") and any(
        c in host for c in [";", "|", "&", "`", "$"]
    ):
        return {
            "diagnostic_command": f"ping -c 1 {host}",
            "command_executed": True,
            "output": f"Simulated RCE output for: {host}",
        }

    return {"status": "SUCCESS", "host": host, "latency_ms": 14.2}


@app.post("/api/v3/supplier/callback")
async def supplier_callback(
    request: Request,
    response: Response,
    x_supplier_ref: str | None = Header(None),
) -> dict[str, Any]:
    # VULN-INJ-03: Header injection
    if x_supplier_ref and not PatchRegistry.is_patched("VULN-INJ-03"):
        response.headers["X-Supplier-Ref"] = x_supplier_ref
    return {"status": "CALLBACK_PROCESSED"}


# -------------------------------------------------------------
# 7. Zombie, Shadow & Debug Routes
# -------------------------------------------------------------
# VULN-ZOM-01 / VULN-AC-02: Abandoned v1 booking route
@app.get("/v1/bookings/{booking_id}")
async def get_booking_v1(booking_id: str) -> dict[str, Any]:
    """Legacy v1 booking endpoint still live without authentication."""
    booking = db.bookings.get(booking_id)
    if not booking:
        raise HTTPException(status_code=404, detail="Legacy booking not found")
    return {
        "version": "v1.0-legacy",
        "data": booking.model_dump(),
        "warning": "This endpoint is deprecated. Upgrade to /api/v3/bookings",
    }


# VULN-ZOM-02: Retired partner endpoint
@app.post("/api/partner/v2/quote")
async def partner_quote(flight_id: str = Query("FL-101")) -> dict[str, Any]:
    flight = db.flights.get(flight_id)
    base = flight.base_fare if flight else 500.0
    return {
        "partner_tier": "LEGACY_GOLD",
        "quoted_fare": base * 0.25,  # 75% unauthenticated discount
        "currency": "USD",
    }


# VULN-SHA-01: Undocumented internal supplier sync shadow route
@app.post("/internal/supplier-sync")
async def internal_supplier_sync(supplier_id: str = Query("SUPP-EMIRATES")) -> dict[str, Any]:
    return {
        "shadow_endpoint": True,
        "sync_status": "COMPLETED",
        "supplier_id": supplier_id,
        "synced_records": 128,
        "timestamp": time.time(),
    }


# VULN-DAT-03: Debug environment route
@app.get("/debug/env")
async def debug_env() -> dict[str, Any]:
    return {
        "environment": "production-mock",
        "GDS_SUPPLIER_API_KEY": "gds_live_sec_994827104928174",
        "DATABASE_URL": "postgresql://voyager_admin:VoyagerMasterPass2026@10.0.4.12:5432/travel_db",
        "AWS_SECRET_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLEFAKE",
    }


# Static Frontend Bundle Route for Recon Agent discovery
@app.get("/static/bundle.js")
async def frontend_bundle() -> PlainTextResponse:
    """Mock client JS bundle containing exposed API routes for Recon crawler."""
    js_code = """
    // Voyager Web Portal v3.4 Bundle
    const API_ROUTES = {
        login: "/api/v3/auth/login",
        resetPassword: "/api/v3/auth/reset-password",
        flightsSearch: "/api/v3/flights/search",
        bookingHold: "/api/v3/bookings/hold",
        bookingGet: "/api/v3/bookings/{booking_id}",
        bookingPay: "/api/v3/bookings/{booking_id}/pay",
        bookingConfirm: "/api/v3/bookings/{booking_id}/confirm",
        bookingCancel: "/api/v3/bookings/{booking_id}/cancel",
        invoice: "/api/v3/bookings/{booking_id}/invoice",
        profile: "/api/v3/agency/profile",
        users: "/api/v3/agency/users",
        wallet: "/api/v3/wallet/balance",
        walletTopup: "/api/v3/wallet/topup",
        documents: "/api/v3/agency/documents"
    };
    function searchFlights(origin, dest) {
        return fetch(`${API_ROUTES.flightsSearch}?origin=${origin}&destination=${dest}`);
    }
    """
    return PlainTextResponse(content=js_code, media_type="application/javascript")


# -------------------------------------------------------------
# 8. Lab Patch Control API (For Retest Agent Verification)
# -------------------------------------------------------------
class PatchToggleRequest(BaseModel):
    vuln_id: str
    patched: bool


@app.post("/lab/patches/toggle")
async def toggle_patch(req: PatchToggleRequest) -> dict[str, Any]:
    PatchRegistry.set_patched(req.vuln_id, req.patched)
    return {
        "vuln_id": req.vuln_id,
        "patched": PatchRegistry.is_patched(req.vuln_id),
    }


@app.get("/lab/patches")
async def get_patches() -> dict[str, bool]:
    return PatchRegistry.get_patch_states()


@app.post("/lab/reset")
async def reset_lab() -> dict[str, str]:
    db.reset()
    PatchRegistry.reset_all()
    return {"status": "RESET_SUCCESSFUL"}
