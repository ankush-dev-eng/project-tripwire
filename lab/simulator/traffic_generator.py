"""Synthetic Gateway Traffic and HAR Generator for 30-Day and 90-Day Windows."""

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path


def generate_gateway_logs(
    output_30d: Path | str = "data/gateway_30d.log",
    output_90d: Path | str = "data/gateway_90d.log",
    seed: int = 42,
) -> tuple[int, int]:
    """Generate synthetic gateway logs with ground-truth Active, Zombie, and Shadow patterns."""
    random.seed(seed)
    now = datetime.now(UTC)

    path_30d = Path(output_30d)
    path_90d = Path(output_90d)
    path_30d.parent.mkdir(parents=True, exist_ok=True)

    # Traffic categories:
    # 1. Active: present throughout all 90 days (and within last 30 days)
    active_routes = [
        ("GET", "/api/v3/flights/search", 200),
        ("POST", "/api/v3/bookings/hold", 200),
        ("GET", "/api/v3/bookings/BKG-ALPHA-001", 200),
        ("POST", "/api/v3/bookings/BKG-ALPHA-001/pay", 200),
        ("GET", "/api/v3/agency/profile", 200),
        ("GET", "/api/v3/wallet/balance", 200),
        ("POST", "/api/v3/auth/login", 200),
    ]

    # 2. Shadow: active throughout traffic, but undocumented in specs
    shadow_routes = [
        ("POST", "/internal/supplier-sync", 200),
    ]

    # 3. Zombie: had traffic between 31 and 90 days ago, but ZERO traffic in the last 30 days
    zombie_routes = [
        ("GET", "/v1/bookings/BKG-ALPHA-001", 200),
        ("POST", "/api/partner/v2/quote", 200),
    ]

    entries_30d: list[str] = []
    entries_90d: list[str] = []

    # Generate log lines across 90 days (from day -90 to day 0)
    for day_offset in range(90, 0, -1):
        day_date = now - timedelta(days=day_offset)
        is_within_30d = day_offset <= 30

        # Daily requests for active routes
        for method, path, status in active_routes:
            count = random.randint(15, 30)
            for _ in range(count):
                req_time = day_date + timedelta(seconds=random.randint(0, 86400))
                ip = random.choice(["192.168.1.10", "192.168.1.25", "10.0.2.14"])
                log_line = f'{req_time.isoformat()} {ip} "{method} {path} HTTP/1.1" {status} {random.randint(20, 250)}ms'
                entries_90d.append(log_line)
                if is_within_30d:
                    entries_30d.append(log_line)

        # Shadow route traffic (periodic internal worker)
        for method, path, status in shadow_routes:
            count = random.randint(5, 10)
            for _ in range(count):
                req_time = day_date + timedelta(seconds=random.randint(0, 86400))
                ip = "10.0.1.50"  # Internal batch worker
                log_line = f'{req_time.isoformat()} {ip} "{method} {path} HTTP/1.1" {status} {random.randint(40, 180)}ms'
                entries_90d.append(log_line)
                if is_within_30d:
                    entries_30d.append(log_line)

        # Zombie route traffic: ONLY generated between days 90 and 31!
        if not is_within_30d:
            for method, path, status in zombie_routes:
                count = random.randint(8, 15)
                for _ in range(count):
                    req_time = day_date + timedelta(seconds=random.randint(0, 86400))
                    ip = random.choice(["192.168.1.10", "192.168.1.99"])
                    log_line = f'{req_time.isoformat()} {ip} "{method} {path} HTTP/1.1" {status} {random.randint(100, 400)}ms'
                    entries_90d.append(log_line)

    entries_30d.sort()
    entries_90d.sort()

    with open(path_30d, "w", encoding="utf-8") as f:
        f.write("\n".join(entries_30d) + "\n")

    with open(path_90d, "w", encoding="utf-8") as f:
        f.write("\n".join(entries_90d) + "\n")

    return len(entries_30d), len(entries_90d)


def generate_sample_har(output_har: Path | str = "data/voyager_journey.har") -> None:
    """Generate sample HAR capturing a standard agent booking journey."""
    path = Path(output_har)
    path.parent.mkdir(parents=True, exist_ok=True)

    har_data = {
        "log": {
            "version": "1.2",
            "creator": {"name": "Tripwire Har Generator", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2026-11-01T10:00:00.000Z",
                    "time": 45,
                    "request": {
                        "method": "POST",
                        "url": "http://127.0.0.1:8000/api/v3/auth/login",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"email": "agent@alpha.com", "password": "AlphaAgent#2026"}',
                        },
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "content": {"mimeType": "application/json", "size": 128},
                    },
                },
                {
                    "startedDateTime": "2026-11-01T10:01:00.000Z",
                    "time": 82,
                    "request": {
                        "method": "GET",
                        "url": "http://127.0.0.1:8000/api/v3/flights/search?origin=DXB&destination=LHR",
                        "headers": [{"name": "Authorization", "value": "Bearer tok_demo"}],
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "content": {"mimeType": "application/json", "size": 512},
                    },
                },
                {
                    "startedDateTime": "2026-11-01T10:02:00.000Z",
                    "time": 115,
                    "request": {
                        "method": "POST",
                        "url": "http://127.0.0.1:8000/api/v3/bookings/hold",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "Authorization", "value": "Bearer tok_demo"},
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"flight_id": "FL-101", "passengers": [{"name": "Lord Sterling"}], "seat_count": 1, "total_amount": 650.0}',
                        },
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "content": {"mimeType": "application/json", "size": 256},
                    },
                },
            ],
        }
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(har_data, f, indent=2)
