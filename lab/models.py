"""Voyager Data Models, Role Definitions, and Runtime Patch Registry."""

import threading
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Role(StrEnum):
    ADMIN = "admin"
    AGENT = "agent"
    SUB_AGENT = "sub_agent"


class BookingStatus(StrEnum):
    HELD = "HELD"
    CONFIRMED = "CONFIRMED"
    CANCELLED = "CANCELLED"
    REFUNDED = "REFUNDED"


class Passenger(BaseModel):
    name: str
    passport_number: str
    email: str


class Flight(BaseModel):
    flight_id: str
    airline: str
    origin: str
    destination: str
    departure_time: str
    base_fare: float
    available_seats: int


class Booking(BaseModel):
    booking_id: str
    agency_id: str
    flight_id: str
    passengers: list[Passenger]
    seat_count: int = 1
    total_amount: float
    status: BookingStatus = BookingStatus.HELD
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    refund_count: int = 0
    card_pan: str | None = None
    card_cvv: str | None = None


class Agency(BaseModel):
    agency_id: str
    name: str
    wallet_balance: float
    credit_limit: float
    is_verified: bool = True


class User(BaseModel):
    user_id: str
    email: str
    password_hash: str
    agency_id: str
    role: Role


class PatchRegistry:
    """Thread-safe runtime toggle for planted vulnerabilities.

    Allows tests and the Retest Agent to simulate patch deployment and regression testing.
    """

    _lock = threading.Lock()
    _patches: dict[str, bool] = {}

    @classmethod
    def set_patched(cls, vuln_id: str, patched: bool = True) -> None:
        with cls._lock:
            cls._patches[vuln_id] = patched

    @classmethod
    def is_patched(cls, vuln_id: str) -> bool:
        with cls._lock:
            return cls._patches.get(vuln_id, False)

    @classmethod
    def reset_all(cls) -> None:
        """Reset all vulnerabilities to unpatched state."""
        with cls._lock:
            cls._patches.clear()

    @classmethod
    def get_patch_states(cls) -> dict[str, bool]:
        with cls._lock:
            return dict(cls._patches)
