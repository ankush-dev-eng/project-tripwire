"""In-Memory Data Store for Voyager-B Mock Platform."""

import hashlib

from lab_b.models import AgencyB, OrderB, RoleB, TicketB, UserB


def _hash(pwd: str) -> str:
    return hashlib.sha256(pwd.encode("utf-8")).hexdigest()


class DataStoreB:
    """Thread-safe state store for Voyager-B."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.agencies: dict[str, AgencyB] = {
            "AGY_APEX": AgencyB(
                agency_id="AGY_APEX",
                legal_name="Apex Travel Solutions Ltd",
                credit_pool=120000.00,
                account_tier="ENTERPRISE",
            ),
            "AGY_BEACON": AgencyB(
                agency_id="AGY_BEACON",
                legal_name="Beacon Global Holidays Inc",
                credit_pool=65000.00,
                account_tier="PREMIER",
            ),
        }

        self.users: dict[str, UserB] = {
            "usr_apex_dir": UserB(
                user_id="usr_apex_dir",
                email="director@apex.com",
                password_hash=_hash("ApexDirector#2026"),
                agency_id="AGY_APEX",
                role=RoleB.DIRECTOR,
                is_superuser=True,
            ),
            "usr_apex_coord": UserB(
                user_id="usr_apex_coord",
                email="coord@apex.com",
                password_hash=_hash("ApexCoord#2026"),
                agency_id="AGY_APEX",
                role=RoleB.COORDINATOR,
            ),
            "usr_apex_intern": UserB(
                user_id="usr_apex_intern",
                email="intern@apex.com",
                password_hash=_hash("ApexIntern#2026"),
                agency_id="AGY_APEX",
                role=RoleB.INTERN,
            ),
            "usr_beacon_dir": UserB(
                user_id="usr_beacon_dir",
                email="director@beacon.com",
                password_hash=_hash("BeaconDirector#2026"),
                agency_id="AGY_BEACON",
                role=RoleB.DIRECTOR,
                is_superuser=True,
            ),
            "usr_beacon_coord": UserB(
                user_id="usr_beacon_coord",
                email="coord@beacon.com",
                password_hash=_hash("BeaconCoord#2026"),
                agency_id="AGY_BEACON",
                role=RoleB.COORDINATOR,
            ),
        }

        self.tickets: dict[str, TicketB] = {
            "TCK-APEX-8801": TicketB(
                ticket_id="TCK-APEX-8801",
                order_id="ORD-APEX-101",
                agency_id="AGY_APEX",
                passenger_name="Alice Morgan",
                flight_code="BA-284",
                fare_paid=850.00,
            ),
            "TCK-BEACON-9901": TicketB(
                ticket_id="TCK-BEACON-9901",
                order_id="ORD-BEACON-202",
                agency_id="AGY_BEACON",
                passenger_name="Boris Vance",
                flight_code="LH-441",
                fare_paid=720.00,
            ),
        }

        self.orders: dict[str, OrderB] = {
            "ORD-APEX-101": OrderB(
                order_id="ORD-APEX-101",
                agency_id="AGY_APEX",
                carrier_code="BA-284",
                seat_count=2,
                unit_price=425.00,
                total_charged=850.00,
                status="CONFIRMED",
            ),
            "ORD-BEACON-202": OrderB(
                order_id="ORD-BEACON-202",
                agency_id="AGY_BEACON",
                carrier_code="LH-441",
                seat_count=1,
                unit_price=720.00,
                total_charged=720.00,
                status="CONFIRMED",
            ),
        }

        self.statements: dict[str, dict] = {
            "STMT-APEX-2026-Q1": {
                "stmt_id": "STMT-APEX-2026-Q1",
                "agency_id": "AGY_APEX",
                "total_settled": 142500.00,
                "status": "SETTLED",
                "banking_iban": "GB82WEST12345678901234",
            },
            "STMT-BEACON-2026-Q1": {
                "stmt_id": "STMT-BEACON-2026-Q1",
                "agency_id": "AGY_BEACON",
                "total_settled": 89200.00,
                "status": "SETTLED",
                "banking_iban": "GB19BARC98765432109876",
            },
        }

        self.active_sessions: dict[str, str] = {}  # token -> user_id
        self.used_promo_nonces: set[str] = set()


db_b = DataStoreB()
