"""In-Memory Data Store Seeded with Multi-Tenant Agency Test Accounts."""

import hashlib
from typing import Any

from lab.models import Agency, Booking, BookingStatus, Flight, Passenger, Role, User


def _hash_pwd(pwd: str) -> str:
    return hashlib.sha256(pwd.encode("utf-8")).hexdigest()


class DataStore:
    """Thread-safe state store for Voyager mock platform."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        """Reset data store to pristine initial seed state."""
        self.agencies: dict[str, Agency] = {
            "AGY_ALPHA": Agency(
                agency_id="AGY_ALPHA",
                name="Alpha Global Travel Ltd",
                wallet_balance=50000.00,
                credit_limit=100000.00,
                is_verified=True,
            ),
            "AGY_BETA": Agency(
                agency_id="AGY_BETA",
                name="Beta Express Journeys",
                wallet_balance=12500.00,
                credit_limit=25000.00,
                is_verified=True,
            ),
        }

        self.users: dict[str, User] = {
            "USR_ALPHA_ADMIN": User(
                user_id="USR_ALPHA_ADMIN",
                email="admin@alpha.com",
                password_hash=_hash_pwd("AlphaAdmin#2026"),
                agency_id="AGY_ALPHA",
                role=Role.ADMIN,
            ),
            "USR_ALPHA_AGENT": User(
                user_id="USR_ALPHA_AGENT",
                email="agent@alpha.com",
                password_hash=_hash_pwd("AlphaAgent#2026"),
                agency_id="AGY_ALPHA",
                role=Role.AGENT,
            ),
            "USR_ALPHA_SUB": User(
                user_id="USR_ALPHA_SUB",
                email="subagent@alpha.com",
                password_hash=_hash_pwd("AlphaSub#2026"),
                agency_id="AGY_ALPHA",
                role=Role.SUB_AGENT,
            ),
            "USR_BETA_ADMIN": User(
                user_id="USR_BETA_ADMIN",
                email="admin@beta.com",
                password_hash=_hash_pwd("BetaAdmin#2026"),
                agency_id="AGY_BETA",
                role=Role.ADMIN,
            ),
            "USR_BETA_AGENT": User(
                user_id="USR_BETA_AGENT",
                email="agent@beta.com",
                password_hash=_hash_pwd("BetaAgent#2026"),
                agency_id="AGY_BETA",
                role=Role.AGENT,
            ),
            "USR_BETA_SUB": User(
                user_id="USR_BETA_SUB",
                email="subagent@beta.com",
                password_hash=_hash_pwd("BetaSub#2026"),
                agency_id="AGY_BETA",
                role=Role.SUB_AGENT,
            ),
        }

        self.flights: dict[str, Flight] = {
            "FL-101": Flight(
                flight_id="FL-101",
                airline="Emirates",
                origin="DXB",
                destination="LHR",
                departure_time="2026-12-01T08:00:00Z",
                base_fare=650.00,
                available_seats=42,
            ),
            "FL-202": Flight(
                flight_id="FL-202",
                airline="Singapore Airlines",
                origin="SIN",
                destination="HND",
                departure_time="2026-12-02T14:30:00Z",
                base_fare=480.00,
                available_seats=18,
            ),
            "FL-303": Flight(
                flight_id="FL-303",
                airline="British Airways",
                origin="LHR",
                destination="JFK",
                departure_time="2026-12-03T11:15:00Z",
                base_fare=720.00,
                available_seats=25,
            ),
        }

        self.bookings: dict[str, Booking] = {
            "BKG-ALPHA-001": Booking(
                booking_id="BKG-ALPHA-001",
                agency_id="AGY_ALPHA",
                flight_id="FL-101",
                passengers=[
                    Passenger(
                        name="Lord Sterling",
                        passport_number="GB987654321",
                        email="sterling@voyage.co.uk",
                    )
                ],
                seat_count=1,
                total_amount=650.00,
                status=BookingStatus.CONFIRMED,
                card_pan="4111111111111111",
                card_cvv="789",
            ),
            "BKG-BETA-001": Booking(
                booking_id="BKG-BETA-001",
                agency_id="AGY_BETA",
                flight_id="FL-202",
                passengers=[
                    Passenger(
                        name="Kenji Sato",
                        passport_number="JP123456789",
                        email="kenji@tokyo.jp",
                    )
                ],
                seat_count=1,
                total_amount=480.00,
                status=BookingStatus.CONFIRMED,
                card_pan="5500000000000004",
                card_cvv="321",
            ),
        }

        self.active_sessions: dict[str, dict[str, Any]] = {}
        self.used_coupons: dict[str, int] = {}
        self.uploaded_files: dict[str, bytes] = {}


# Global shared instance for Voyager app
db = DataStore()
