"""Token Bucket Rate Limiter and Dynamic Strain Backoff Monitor."""

import asyncio
import time
from collections import deque
from pathlib import Path
from typing import Any

import yaml

from backend.safety.kill_switch import KillSwitch


class StrainBackoffActiveError(Exception):
    """Raised when request is dropped or throttled due to severe target strain."""


class RateLimiter:
    """Thread-safe and async token bucket rate limiter with adaptive strain backoff."""

    def __init__(
        self,
        config_path: Path | str = "config/rate_limits.yaml",
        kill_switch: KillSwitch | None = None,
    ) -> None:
        self.config_path = Path(config_path)
        self.kill_switch = kill_switch
        self._load_config()

        # Token bucket state
        self._tokens = float(self.burst_capacity)
        self._last_token_time = time.monotonic()
        self._lock = asyncio.Lock()

        # Strain monitoring state
        self._recent_latencies: deque[float] = deque(maxlen=self.rolling_window)
        self._recent_status_codes: deque[int] = deque(maxlen=self.rolling_window)
        self._consecutive_timeouts: int = 0
        self._in_strain_mode: bool = False
        self._strain_start_time: float = 0.0

    def _load_config(self) -> None:
        cfg: dict[str, Any] = {}
        if self.config_path.exists():
            with open(self.config_path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}

        rate_cfg = cfg.get("rate_limiting", {})
        self.requests_per_second: float = float(rate_cfg.get("requests_per_second", 15.0))
        self.burst_capacity: float = float(rate_cfg.get("burst_capacity", 25.0))
        self.max_concurrency: int = int(rate_cfg.get("max_concurrent_connections", 5))

        strain_cfg = cfg.get("strain_backoff", {})
        self.strain_enabled: bool = bool(strain_cfg.get("enabled", True))
        self.latency_threshold_ms: float = float(strain_cfg.get("latency_threshold_ms", 500.0))
        self.error_5xx_threshold_ratio: float = float(
            strain_cfg.get("error_5xx_threshold_ratio", 0.05)
        )
        self.rolling_window: int = int(strain_cfg.get("rolling_window_requests", 20))
        self.backoff_factor: float = float(strain_cfg.get("backoff_factor", 0.5))
        self.cooldown_seconds: float = float(strain_cfg.get("cooldown_seconds", 10.0))

        ks_cfg = cfg.get("kill_switch", {})
        self.max_consecutive_timeouts: int = int(ks_cfg.get("max_consecutive_timeouts", 5))

    @property
    def effective_rate(self) -> float:
        """Return the effective request rate accounting for strain backoff."""
        if self._in_strain_mode:
            return max(1.0, self.requests_per_second * self.backoff_factor)
        return self.requests_per_second

    async def acquire(self, tokens: float = 1.0) -> None:
        """Acquire token(s) before sending request, sleeping if bucket is depleted."""
        if self.kill_switch and self.kill_switch.is_tripped():
            self.kill_switch.check_or_raise()

        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_token_time
                self._last_token_time = now

                # Replenish tokens based on effective rate
                self._tokens = min(
                    self.burst_capacity,
                    self._tokens + elapsed * self.effective_rate,
                )

                if self._tokens >= tokens:
                    self._tokens -= tokens
                    break

                # Calculate sleep duration needed for required tokens
                missing_tokens = tokens - self._tokens
                sleep_time = missing_tokens / self.effective_rate
                await asyncio.sleep(sleep_time)

    def record_response(self, latency_ms: float, status_code: int) -> None:
        """Record request metrics to evaluate target strain."""
        self._recent_latencies.append(latency_ms)
        self._recent_status_codes.append(status_code)
        self._consecutive_timeouts = 0  # reset on successful response

        self._evaluate_strain()

    def record_timeout(self) -> None:
        """Record a connection timeout and trip kill switch if exceeding threshold."""
        self._consecutive_timeouts += 1
        if self._consecutive_timeouts >= self.max_consecutive_timeouts and self.kill_switch:
            self.kill_switch.trip(
                f"Consecutive timeouts ({self._consecutive_timeouts}) exceeded safety limit"
            )

    def _evaluate_strain(self) -> None:
        """Analyze rolling window to detect latency spikes or 5xx error surges."""
        if not self.strain_enabled or len(self._recent_latencies) < 5:
            return

        now = time.monotonic()
        # Cooldown check
        if self._in_strain_mode and (now - self._strain_start_time > self.cooldown_seconds):
            self._in_strain_mode = False

        # Calculate p90 latency
        sorted_latencies = sorted(self._recent_latencies)
        p90_idx = int(0.9 * len(sorted_latencies))
        p90_latency = sorted_latencies[min(p90_idx, len(sorted_latencies) - 1)]

        # Calculate 5xx error ratio
        error_count = sum(1 for sc in self._recent_status_codes if 500 <= sc <= 599)
        error_ratio = error_count / len(self._recent_status_codes)

        if (
            p90_latency > self.latency_threshold_ms or error_ratio > self.error_5xx_threshold_ratio
        ) and not self._in_strain_mode:
            self._in_strain_mode = True
            self._strain_start_time = now

    def is_in_strain_mode(self) -> bool:
        """Check if backoff strain mode is currently active."""
        return self._in_strain_mode
