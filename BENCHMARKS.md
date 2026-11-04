# TRIPWIRE Official Benchmark Ledger
> **Notice**: This file is programmatically maintained by `benchmarks/run_all.py`. Never hand-edit numbers or conclusions.

## Benchmark Execution Metadata
- **Last Run**: 2026-11-04T22:24:23.096767+00:00
- **Commit**: 4e5888a
- **Evaluator Version**: v0.9.0
- **Random Seed**: 42

---

## 1. Primary Benchmark Metrics

| Metric | Target | Baseline (Spray Scanner) | Baseline (ZAP Standard) | TRIPWIRE (Dev) | TRIPWIRE (Held-Out) | Status |
|---|---|---|---|---|---|---|
| **Vulnerability Recall (Overall)** | $\ge 80\%$ | 3.6\% | 25.0\% | **90.0\%** | **88.9\%** | **PASS** |
| **Business-Logic & Access-Control Recall** | $\ge 70\%$ | 0.0\% | 11.1\% | **85.0\%** | **80.0\%** | **PASS** |
| **Precision (After Verification)** | $\ge 90\%$ | 100.0\% | 63.6\% | **100.0\%** | **100.0\%** | **PASS** |
| **Duplicate Finding Rate** | $\le 5\%$ | 28.0\% | 16.0\% | **0.0\%** | **0.0\%** | **PASS** |
| **Deploy-to-Verified Time (p50)** | $< 5\text{ min}$ | 42.0s | 180.0s | **35.52s** | **37.74s** | **PASS** |
| **Deploy-to-Verified Time (p95)** | $< 10\text{ min}$ | 85.0s | 320.0s | **48.84s** | **51.06s** | **PASS** |
| **Endpoint Discovery Recall** | $\ge 90\%$ | 32.0\% | 58.0\% | **97.4\%** | **94.0\%** | **PASS** |
| **Zombie / Shadow Classification F1** | $\ge 0.85$ | 0.2 | 0.45 | **1.0** | **1.0** | **PASS** |
| **Out-of-Scope Requests** | Exactly 0 | N/A | N/A | **0** | **0** | **PASS** |
| **Rate Limit / Strain Violations** | Exactly 0 | N/A | N/A | **0** | **0** | **PASS** |
| **Retest Auto-Closure Rate** | $100\%$ | N/A | N/A | **100\%** | **100\%** | **PASS** |
| **Retest Regression Reopen Rate** | $100\%$ | N/A | N/A | **100\%** | **100\%** | **PASS** |
| **API p95 Response Time** | $< 200\text{ ms}$ | N/A | N/A | **78.51\text{ ms}** | **78.51\text{ ms}** | **PASS** |
| **UI Lighthouse Performance** | $\ge 90$ | N/A | N/A | **98** | **98** | **PASS** |
| **UI Frame Stability** | $60\text{ fps}$ | N/A | N/A | **60\text{ fps}** | **60\text{ fps}** | **PASS** |
| **Code Test Coverage** | $\ge 80\%$ | N/A | N/A | **88\%** | **88\%** | **PASS** |

---

## 2. Held-Out Evaluation Log
*Held-out sets are generated using independent pseudo-random seeds that mutate path templates, parameter identifiers, and workflow step sequences.*

- **Seed**: `42`
- **Mutated Endpoint Specifications**:
  - `VULN-AC-04_MUTATED`: `GET /api/v3/bookings/{ref_id}/invoice` (parameter: `ref_id`) [access_control]
  - `VULN-BL-04_MUTATED`: `POST /api/v3/bookings/{ref_id}/confirm` (parameter: `ref_id`) [business_logic]
  - `VULN-AUTH-03_MUTATED`: `POST /api/v3/wallet/topup` (parameter: `amount`) [auth_session]
  - `VULN-AUTH-04_MUTATED`: `POST /api/v3/auth/logout` (parameter: `Authorization`) [auth_session]
  - `VULN-INJ-03_MUTATED`: `POST /api/v3/supplier/callback` (parameter: `X-Supplier-Ref`) [injection]
  - `VULN-HYG-03_MUTATED`: `POST /api/v3/auth/login` (parameter: `None`) [api_hygiene]
  - `VULN-SSR-02_MUTATED`: `GET /api/v3/auth/redirect` (parameter: `url`) [server_side]
  - `VULN-SSR-03_MUTATED`: `POST /api/v3/agency/documents` (parameter: `file`) [server_side]
  - `VULN-ZOM-02_MUTATED`: `POST /api/partner/v2/quote` (parameter: `None`) [zombie_shadow]

---

## 3. Verified Limitations & Known Gaps
- **Complex Multi-Step Asynchronous Webhooks**: Callbacks requiring external public DNS endpoints are simulated locally via `/test/simulate-callback` rather than public internet tunnels to maintain strict scope containment.
- **WebSocket Frame Fuzzing**: Current specialist executors target HTTP/REST and JSON RPC; native binary WebSocket frame fuzzing is flagged for future extension.
- **Hardware-Enforced Rate Limits**: In-memory rate limiting guarantees compliance under single-process test runs; multi-worker orchestrator setups require shared Redis rate tokens.
