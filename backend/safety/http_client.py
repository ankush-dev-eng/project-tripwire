"""The Single Authorized Egress Point for Outbound HTTP Operations."""

import json
import time
from collections.abc import Mapping
from typing import Any

import httpx

from backend.safety.approval_gate import ApprovalGate
from backend.safety.audit_logger import AuditLogger
from backend.safety.kill_switch import KillSwitch
from backend.safety.rate_limiter import RateLimiter
from backend.safety.scope import ScopeManager


class SafeResponse:
    """Sanitized HTTP response wrapper providing standard inspection attributes."""

    def __init__(
        self,
        status_code: int,
        headers: Mapping[str, str],
        content: bytes,
        elapsed_ms: float,
        url: str,
    ) -> None:
        self.status_code = status_code
        self.headers = dict(headers)
        self.content = content
        self.elapsed_ms = elapsed_ms
        self.url = url

    @property
    def text(self) -> str:
        """Return response body as decoded text."""
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        """Parse response content as JSON."""
        return json.loads(self.text)

    def __repr__(self) -> str:
        return f"<SafeResponse [{self.status_code}] ({self.elapsed_ms:.1f}ms)>"


class SafeHttpClient:
    """The mandatory, scope-locked, rate-limited, audit-logged HTTP client.

    All outbound network requests across TRIPWIRE must traverse this class.
    Direct usage of raw HTTP libraries outside this class fails the build.
    """

    def __init__(
        self,
        scope_manager: ScopeManager | None = None,
        kill_switch: KillSwitch | None = None,
        rate_limiter: RateLimiter | None = None,
        approval_gate: ApprovalGate | None = None,
        audit_logger: AuditLogger | None = None,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.kill_switch = kill_switch or KillSwitch.get_instance()
        self.scope_manager = scope_manager or ScopeManager(kill_switch=self.kill_switch)
        self.rate_limiter = rate_limiter or RateLimiter(kill_switch=self.kill_switch)
        self.approval_gate = approval_gate or ApprovalGate()
        self.audit_logger = audit_logger or AuditLogger()
        self.default_timeout = timeout
        self.transport = transport
        self._async_client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._async_client is None or self._async_client.is_closed:
            self._async_client = httpx.AsyncClient(
                transport=self.transport,
                timeout=httpx.Timeout(self.default_timeout),
                follow_redirects=False,  # Redirects must be inspected explicitly
            )
        return self._async_client

    async def close(self) -> None:
        """Close underlying client connections."""
        if self._async_client and not self._async_client.is_closed:
            await self._async_client.aclose()
            self._async_client = None

    async def __aenter__(self) -> "SafeHttpClient":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json_data: Any | None = None,
        json: Any | None = None,
        data: Any | None = None,
        approval_token: str | None = None,
        timeout: float | None = None,
        context: dict[str, Any] | None = None,
    ) -> SafeResponse:
        """Execute a secure, scope-verified, rate-governed outbound HTTP request."""
        method = method.upper()
        req_headers = dict(headers or {})
        effective_json = json if json is not None else json_data

        # 1. Check Global Kill Switch
        self.kill_switch.check_or_raise()

        # 2. Scope Allowlist Verification
        self.scope_manager.check_url_or_raise(url)

        # 3. Guarded State-Change Approval Gate
        self.approval_gate.check_approval(
            method=method,
            url=url,
            approval_token=approval_token,
            context=context,
        )

        # 4. Token Bucket Rate Limiting & Strain Backoff
        await self.rate_limiter.acquire(1.0)

        client = await self._get_client()
        req_timeout = timeout or self.default_timeout
        start_time = time.monotonic()

        try:
            raw_response = await client.request(
                method=method,
                url=url,
                params=params,
                headers=req_headers,
                json=effective_json,
                data=data,
                timeout=req_timeout,
            )
            elapsed_ms = (time.monotonic() - start_time) * 1000.0

            # Record metrics for strain monitoring
            self.rate_limiter.record_response(
                latency_ms=elapsed_ms,
                status_code=raw_response.status_code,
            )

            # Log to cryptographic audit trail
            body_to_log = json_data if json_data is not None else data
            self.audit_logger.log_interaction(
                method=method,
                url=str(raw_response.url),
                request_headers=req_headers,
                request_body=body_to_log,
                status_code=raw_response.status_code,
                response_headers=dict(raw_response.headers),
                response_body=raw_response.text,
                latency_ms=elapsed_ms,
            )

            return SafeResponse(
                status_code=raw_response.status_code,
                headers=raw_response.headers,
                content=raw_response.content,
                elapsed_ms=elapsed_ms,
                url=str(raw_response.url),
            )

        except httpx.TimeoutException:
            elapsed_ms = (time.monotonic() - start_time) * 1000.0
            self.rate_limiter.record_timeout()
            self.audit_logger.log_interaction(
                method=method,
                url=url,
                request_headers=req_headers,
                request_body=json_data or data,
                status_code=504,
                response_headers={},
                response_body="[TIMEOUT_ERROR]",
                latency_ms=elapsed_ms,
            )
            raise

    # Convenience HTTP verbs
    async def get(self, url: str, **kwargs: Any) -> SafeResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> SafeResponse:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> SafeResponse:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> SafeResponse:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> SafeResponse:
        return await self.request("DELETE", url, **kwargs)
