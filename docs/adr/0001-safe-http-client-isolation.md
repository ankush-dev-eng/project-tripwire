# ADR 0001: SafeHttpClient AST Egress Isolation and Token-Bucket Rate Limiting

## Status
Accepted

## Context
In automated Dynamic Application Security Testing (DAST) for enterprise platforms, an rogue agent or untrusted external plugin can potentially cause severe operational damage if outbound HTTP traffic escapes lab scope boundaries or overwhelms target infrastructure.

Key risks include:
1. Scanning production or third-party partner systems outside testing authorization.
2. Triggering denial-of-service conditions through uncontrolled thread concurrency or unthrottled request loops.
3. Leaking tenant credentials or secrets in outbound payloads.
4. Lacking tamper-evident non-repudiation records of testing activity.

## Decision
We enforce a mandatory **Deterministic Safety Layer** centered around `SafeHttpClient` (`backend/safety/http_client.py`):

1. **AST Isolation Enforcement**:
   - Automated unit tests (`tests/safety/test_egress_isolation.py`) inspect Python AST across all agent and test modules.
   - Any raw invocation of `requests`, standard `urllib`, `aiohttp`, or direct unmonitored `httpx.Client`/`httpx.AsyncClient` outside `backend/safety/http_client.py` triggers an immediate CI build failure.

2. **Immutable Scope Containment**:
   - All target URLs are parsed and strictly checked against `scope.yaml` using exact IP and domain allowlists.
   - The default scope is locked to `127.0.0.1` and `localhost`. Any out-of-scope address raises `ScopeViolationError` and trips the global `KillSwitch`.

3. **Token-Bucket Rate Limiting & Dynamic Backoff**:
   - All egress calls pass through a thread-safe token bucket rate limiter (`RateLimiter`).
   - If target response times spike beyond safe thresholds ($> 1500\text{ ms}$) or error responses ($5xx$) spike above $10\%$, a dynamic backoff engine throttles throughput and activates a circuit breaker.

4. **Cryptographic Audit Trail**:
   - Every outbound request and response is recorded in an append-only JSONL audit log with SHA-256 hash chaining (`AuditLogger`), enabling tamper-evident forensic replays.

## Consequences
- **Positive**: Zero possibility of accidental out-of-scope traffic or runaway fuzzing strain.
- **Positive**: 100% testable safety guarantees verifiable in CI.
- **Trade-off**: Agent authors cannot use off-the-shelf third-party libraries that make unmanaged network calls; all HTTP operations must pass through `SafeHttpClient`.

