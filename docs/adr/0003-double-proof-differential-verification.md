# ADR 0003: Double-Proof Differential Verification for Zero False-Positive Triaging

## Status
Accepted

## Context
High false positive rates ($> 30\%$) are the single greatest barrier to enterprise DAST adoption. Security engineering teams routinely discard automated DAST reports because traditional scanners flag unhandled 500 errors, generic error pages, or subtle timing jitter as critical vulnerabilities.

## Decision
We introduce mandatory **Double-Proof Differential Verification** (`DifferentialVerifier` & `EvidencePackage` in `backend/agents/verifier.py`):

1. **Two-Stage Proof Requirement**:
   - Every finding candidate must supply both a **Positive Proof** (evidence demonstrating vulnerability exploitation, e.g. unauthorized data returned or price manipulated) AND a **Negative Control** (baseline evidence demonstrating the application's normal, secure behavior under valid conditions).
   - A finding is marked `VERIFIED` if and only if both proofs succeed and the differential comparison demonstrates a true divergence in behavior.

2. **Tamper-Proof Minimal Reproduction cURL**:
   - Each verified finding contains a self-contained, standalone `reproduction_curl` command with exact headers and body parameters.
   - Developers can paste this command directly into their terminal to reproduce the exploit within seconds without needing access to the TRIPWIRE platform.

3. **Status Lifecycle Integration**:
   - Unverified anomalies are discarded or routed to low-priority manual inspection queues.
   - Only `VERIFIED` findings are emitted to the WebSocket event stream and persisted into the findings ledger.

## Consequences
- **Positive**: Achieves $> 90\%$ precision in automated vulnerability reporting.
- **Positive**: Eliminates wasted engineering triage time on phantom alerts.
- **Trade-off**: Requires specialist executors to issue two distinct HTTP requests per finding candidate, increasing verification overhead slightly.

