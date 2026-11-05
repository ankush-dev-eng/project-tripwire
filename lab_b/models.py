"""Data models and Patch Registry for Voyager-B."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class RoleB(StrEnum):
    DIRECTOR = "director"
    COORDINATOR = "coordinator"
    INTERN = "intern"


class AgencyB(BaseModel):
    agency_id: str
    legal_name: str
    credit_pool: float = 150000.00
    account_tier: str = "TIER_1"
    is_active: bool = True


class UserB(BaseModel):
    user_id: str
    email: str
    password_hash: str
    agency_id: str
    role: RoleB
    is_superuser: bool = False


class TicketB(BaseModel):
    ticket_id: str
    order_id: str
    agency_id: str
    passenger_name: str
    flight_code: str
    fare_paid: float
    status: str = "ISSUED"


class OrderB(BaseModel):
    order_id: str
    agency_id: str
    carrier_code: str
    seat_count: int
    unit_price: float
    total_charged: float
    status: str = "PENDING"
    refunded_amount: float = 0.0


class PatchRegistryB:
    """Independent patch toggle registry for Voyager-B."""

    _patches: dict[str, bool] = {}

    @classmethod
    def reset(cls) -> None:
        cls._patches.clear()

    @classmethod
    def set_patched(cls, vuln_id: str, state: bool) -> None:
        cls._patches[vuln_id] = state

    @classmethod
    def is_patched(cls, vuln_id: str) -> bool:
        return cls._patches.get(vuln_id, False)

    @classmethod
    def get_states(cls) -> dict[str, bool]:
        return cls._patches.copy()
