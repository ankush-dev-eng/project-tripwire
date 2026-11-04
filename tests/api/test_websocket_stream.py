"""Tests for TRIPWIRE Real-Time Duplex WebSocket Stream."""

import asyncio
import time

from starlette.testclient import TestClient

from backend.api.app import api_app, orchestrator


def test_websocket_stream_initial_sync_and_ping() -> None:
    client = TestClient(api_app)

    with client.websocket_connect("/ws/stream") as ws:
        # 1. Verify INITIAL_SYNC is received immediately upon connection
        t0 = time.perf_counter()
        data = ws.receive_json()
        latency_ms = (time.perf_counter() - t0) * 1000

        assert data["type"] == "INITIAL_SYNC"
        assert "state" in data
        assert latency_ms < 200  # Gate 7: latency < 200ms

        # 2. Ping-pong roundtrip
        t0 = time.perf_counter()
        ws.send_json({"action": "ping"})
        pong = ws.receive_json()
        ping_latency_ms = (time.perf_counter() - t0) * 1000

        assert pong["type"] == "pong"
        assert ping_latency_ms < 200

        # 3. Request state update
        t0 = time.perf_counter()
        ws.send_json({"action": "get_state"})
        state_resp = ws.receive_json()
        state_latency_ms = (time.perf_counter() - t0) * 1000

        assert state_resp["type"] == "STATE_UPDATE"
        assert "state" in state_resp
        assert state_latency_ms < 200


def test_websocket_live_event_broadcast() -> None:
    client = TestClient(api_app)

    with client.websocket_connect("/ws/stream") as ws:
        # Drain initial sync
        _ = ws.receive_json()

        # Emit an event through orchestrator
        t0 = time.perf_counter()
        asyncio.run(
            orchestrator.emit_event(
                "TEST_BROADCAST",
                {"message": "Live attack progress update"},
            )
        )

        event = ws.receive_json()
        delivery_latency_ms = (time.perf_counter() - t0) * 1000

        assert event["type"] == "TEST_BROADCAST"
        assert event["data"]["message"] == "Live attack progress update"
        # Gate 7 requirement: Event delivery < 1s (1000ms)
        assert delivery_latency_ms < 1000
