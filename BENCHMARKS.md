# TRIPWIRE Official Benchmark Ledger
> **Notice**: This file is programmatically maintained by `make benchmark`. Never hand-edit numbers or conclusions.

## Benchmark Execution Metadata
- **Last Run**: Not yet executed (Pending Phase 0 baseline & Phase 9 hardening)
- **Commit**: Initializing
- **Evaluator Version**: v0.0.1
- **Random Seed**: 42

---

## 1. Primary Benchmark Metrics

| Metric | Target | Baseline (Spray Scanner) | Baseline (ZAP Standard) | TRIPWIRE (Dev) | TRIPWIRE (Held-Out) | Status |
|---|---|---|---|---|---|---|
| **Vulnerability Recall (Overall)** | $\ge 80\%$ | TBD | TBD | TBD | TBD | PENDING |
| **Business-Logic & Access-Control Recall** | $\ge 70\%$ | TBD | TBD | TBD | TBD | PENDING |
| **Precision (After Verification)** | $\ge 90\%$ | TBD | TBD | TBD | TBD | PENDING |
| **Duplicate Finding Rate** | $\le 5\%$ | TBD | TBD | TBD | TBD | PENDING |
| **Deploy-to-Verified Time (p50)** | $< 5\text{ min}$ | TBD | TBD | TBD | TBD | PENDING |
| **Deploy-to-Verified Time (p95)** | $< 10\text{ min}$ | TBD | TBD | TBD | TBD | PENDING |
| **Endpoint Discovery Recall** | $\ge 90\%$ | TBD | TBD | TBD | TBD | PENDING |
| **Zombie / Shadow Classification F1** | $\ge 0.85$ | TBD | TBD | TBD | TBD | PENDING |
| **Out-of-Scope Requests** | Exactly 0 | N/A | N/A | TBD | TBD | PENDING |
| **Rate Limit / Strain Violations** | Exactly 0 | N/A | N/A | TBD | TBD | PENDING |
| **Retest Auto-Closure Rate** | $100\%$ | N/A | N/A | TBD | TBD | PENDING |
| **Retest Regression Reopen Rate** | $100\%$ | N/A | N/A | TBD | TBD | PENDING |
| **API p95 Response Time** | $< 200\text{ ms}$ | N/A | N/A | TBD | TBD | PENDING |
| **UI Lighthouse Performance** | $\ge 90$ | N/A | N/A | TBD | TBD | PENDING |
| **UI Frame Stability** | $60\text{ fps}$ | N/A | N/A | TBD | TBD | PENDING |
| **Code Test Coverage** | $\ge 80\%$ | N/A | N/A | TBD | TBD | PENDING |

---

## 2. Held-Out Evaluation Log
*Held-out sets are generated using independent pseudo-random seeds that mutate path templates, parameter identifiers, and workflow step sequences. Generated once per benchmark run.*

*(Pending initial benchmark suite run in Phase 9)*

---

## 3. Verified Limitations & Known Gaps
- None recorded yet.

