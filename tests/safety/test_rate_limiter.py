"""Tests for Rate Limiter and Strain Backoff Engine."""

import pytest
from backend.safety.kill_switch import KillSwitch, KillSwitchTrippedError
from backend.safety.rate_limiter import RateLimiter


@pytest.mark.asyncio
async def test_token_bucket_acquire() -> None:
    limiter = RateLimiter(config_path="config/rate_limits.yaml")
    # Burst capacity allows immediate tokens
    for _ in range(5):
        await limiter.acquire(1.0)
    assert limiter.effective_rate == limiter.requests_per_second


def test_strain_detection_latency_spike() -> None:
    limiter = RateLimiter(config_path="config/rate_limits.yaml")
    assert not limiter.is_in_strain_mode()

    # Simulate 10 requests with high latency (600ms > 500ms threshold)
    for _ in range(10):
        limiter.record_response(latency_ms=650.0, status_code=200)

    assert limiter.is_in_strain_mode()
    # Effective rate should be halved
    assert limiter.effective_rate == limiter.requests_per_second * limiter.backoff_factor


def test_strain_detection_5xx_errors() -> None:
    limiter = RateLimiter(config_path="config/rate_limits.yaml")

    # Simulate 10 requests where 3 return 503 Service Unavailable (30% > 5% threshold)
    for _ in range(7):
        limiter.record_response(latency_ms=50.0, status_code=200)
    for _ in range(3):
        limiter.record_response(latency_ms=50.0, status_code=503)

    assert limiter.is_in_strain_mode()


@pytest.mark.asyncio
async def test_consecutive_timeouts_trip_kill_switch() -> None:
    ks = KillSwitch()
    ks.reset()
    limiter = RateLimiter(config_path="config/rate_limits.yaml", kill_switch=ks)

    # Trigger consecutive timeouts up to limit
    for _ in range(limiter.max_consecutive_timeouts):
        limiter.record_timeout()

    assert ks.is_tripped()
    assert "Consecutive timeouts" in (ks.get_trip_reason() or "")

    with pytest.raises(KillSwitchTrippedError):
        await limiter.acquire(1.0)
