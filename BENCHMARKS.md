# TRIPWIRE Official Benchmark Ledger
> **Notice**: This file is programmatically maintained by `benchmarks/run_all.py`. Never hand-edit numbers or conclusions.

## Benchmark Execution Metadata
- **Last Run**: 2026-11-05T08:42:07.358194+00:00
- **Commit**: 78b8f3c
- **Evaluator Version**: v1.1.0
- **Evaluated Seeds**: `[101, 202, 303, 404, 505]`

---

## 1. Primary Benchmark Metrics

| Metric | Target | Baseline (Spray - Simulated) | Baseline (OWASP ZAP 2.17.0 - Unauth) | Baseline (OWASP ZAP 2.17.0 - Auth A & B) | TRIPWIRE (Dev) | TRIPWIRE (Held-Out 5-Seed Mean & Spread) | TRIPWIRE (Sealed Voyager-B) | Status |
|---|---|---|---|---|---|---|---|---|
| **Vulnerability Recall (Overall)** | $\ge 80\%$ | 3.6\% | 3.6\% | 7.1\% | **100.0\%** | **100.0\%** (100.0\% - 100.0\%) | **82.6\%** | **PASS** |
| **Business-Logic & Access-Control Recall (Dev)** | $\ge 70\%$ | 0.0\% | 0.0\% | 0.0\% | **100.0\%** | N/A | N/A | **PASS** |
| **Business-Logic & Access-Control Recall (Held-Out)** | $\ge 70\%$ | 0.0\% | 0.0\% | 0.0\% | N/A | **100.0\%** (100.0\% - 100.0\%) | **90.0\%** | **PASS** |
| **Precision (After Verification)** | $\ge 90\%$ | 100.0\% | 33.3\% | 40.0\% | **100.0\%** | **100.0\%** | **100.0\%** | **PASS** |
| **Duplicate Finding Rate** | $\le 5\%$ | 28.0\% | 0.0\% | 0.0\% | **0.0\%** | **0.0\%** | **0.0\%** | **PASS** |
| **Deploy-to-Verified Time (p50)** | $< 5\text{ min}$ | 42.0s | 18.5s | 24.1s | **83.58s** | **52.18s** | **45.01s** | **PASS** |
| **Deploy-to-Verified Time (p95)** | $< 10\text{ min}$ | 85.0s | 35.2s | 52.8s | **83.58s** | **52.18s** | **45.01s** | **PASS** |
| **Endpoint Discovery Recall** | $\ge 90\%$ | 32.0\% | 100.0\% | 100.0\% | **100.0\%** | **100.0\%** | **80.0\%** | **FAIL** |
| **Zombie / Shadow Classification F1** | $\ge 0.85$ | 0.2 | 0.0 | 0.0 | **1.0** | **1.0** | **N/A** | **PASS** |
| **Out-of-Scope Requests** | Exactly 0 | N/A | N/A | N/A | **0** | **0** | **0** | **PASS** |
| **Rate Limit / Strain Violations** | Exactly 0 | N/A | N/A | N/A | **0** | **0** | **0** | **PASS** |
| **Retest Auto-Closure Rate** | $100\%$ | N/A | N/A | N/A | **100\%** | **100\%** | **N/A** | **PASS** |
| **Retest Regression Reopen Rate** | $100\%$ | N/A | N/A | N/A | **100\%** | **100\%** | **N/A** | **PASS** |
| **API p95 Response Time** | $< 200\text{ ms}$ | N/A | N/A | N/A | **77.87\text{ ms}** | **77.87\text{ ms}** | **77.87\text{ ms}** | **PASS** |
| **UI Lighthouse Performance** | $\ge 90$ | N/A | N/A | N/A | **99** | **99** | **99** | **PASS** |
| **UI Frame Stability** | $60\text{ fps}$ | N/A | N/A | N/A | **60\text{ fps}** | **60\text{ fps}** | **60\text{ fps}** | **PASS** |
| **UI Interaction to Next Paint (INP)** | $< 200\text{ ms}$ | N/A | N/A | N/A | **12.0\text{ ms}** | **12.0\text{ ms}** | **12.0\text{ ms}** | **PASS** |
| **Code Test Coverage** | $\ge 80\%$ | N/A | N/A | N/A | **90\%** | **90\%** | **90\%** | **PASS** |

---

> **Honesty & Baseline Methodology Note**:
> In accordance with Section 10 (Honesty Rules):
> 1. **OWASP ZAP 2.17.0 Baselines**: Evaluated in both unauthenticated and authenticated multi-tenant configurations (Agency Alpha and Agency Beta contexts). Even with authenticated tokens, ZAP achieves only 7.1% overall recall and 0.0% business-logic / access-control recall because it lacks domain workflow models and cross-tenant authorization oracles.
> 2. **Spray Scanner Baseline**: Explicitly labeled as **Simulated** (`Baseline (Spray - Simulated)`).
> 3. **Spec-Free Held-Out Recon**: Evaluated across 5 independent seeds (`[101, 202, 303, 404, 505]`) with `openapi_url=None`, `docs_url=None`, and no target spec pre-loaded into the agent. Discovery recall was measured from scratch via frontend JS bundle analysis and probing, achieving an empirical mean recall of **100.0\%** (spread: 100.0\% - 100.0\%).
> 4. **Sealed Voyager-B Target**: Evaluated once for release v1.1.0 on a distinct modular architecture (`lab_b/app.py`) with 23 seeded vulnerabilities across all 8 vulnerability categories without tuning against its cases.

---

## 2. Held-Out Evaluation Log (5-Seed Breakdown)
*Evaluated across 5 seeds with mutated routes, parameter pools, flow graphs, and sampled vulnerability sets.*

- **Seed 101**: Recall = 100.0%, BL Recall = 100.0%, Discovery = 100.0%, Precision = 100.0%, Scan Time = 48.89s (Verified Findings: 33/8)
- **Seed 202**: Recall = 100.0%, BL Recall = 100.0%, Discovery = 100.0%, Precision = 100.0%, Scan Time = 54.29s (Verified Findings: 34/8)
- **Seed 303**: Recall = 100.0%, BL Recall = 100.0%, Discovery = 100.0%, Precision = 100.0%, Scan Time = 57.29s (Verified Findings: 39/8)
- **Seed 404**: Recall = 100.0%, BL Recall = 100.0%, Discovery = 100.0%, Precision = 100.0%, Scan Time = 50.89s (Verified Findings: 38/8)
- **Seed 505**: Recall = 100.0%, BL Recall = 100.0%, Discovery = 100.0%, Precision = 100.0%, Scan Time = 49.55s (Verified Findings: 34/8)

---

## 3. Verified Limitations & Known Gaps
- **Complex Multi-Step Asynchronous Webhooks**: Callbacks requiring external public DNS endpoints are simulated locally via `/test/simulate-callback` rather than public internet tunnels to maintain strict scope containment.
- **WebSocket Frame Fuzzing**: Current specialist executors target HTTP/REST and JSON RPC; native binary WebSocket frame fuzzing is flagged for future extension.
- **Hardware-Enforced Rate Limits**: In-memory rate limiting guarantees compliance under single-process test runs; multi-worker orchestrator setups require shared Redis rate tokens.
