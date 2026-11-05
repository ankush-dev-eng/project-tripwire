# PROJECT TRIPWIRE Threat Model & Security Architecture

## 1. Overview & System Scope
PROJECT TRIPWIRE is an autonomous agentic Dynamic Application Security Testing (DAST) platform specifically designed for high-consequence B2B travel distribution architectures (e.g. Voyager / GDS platforms). Travel distribution platforms present unique attack surfaces characterized by:
- Multi-tier tenancy (Host platform, Master Agencies, Sub-agencies, Corporate Travellers)
- Stateful transactional workflows (Search -> Hold -> Book -> Pay -> Confirm -> Cancel -> Refund)
- Sensitive financial transactions, wallet balances, credit lines, and PCI-DSS sensitive cardholder data (PAN/CVV)
- Distributed third-party integrations (Airlines, GDS aggregators, Webhook notification sinks)

This document establishes the comprehensive threat model for both the **Voyager B2B Platform Target** and the **TRIPWIRE Autonomous DAST Scanner Infrastructure** using the **STRIDE** and **DREAD** security frameworks.

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing (Identity & Authentication)
| Threat ID | Threat Description | Target Component | Mitigating Control & TRIPWIRE Defense |
|---|---|---|---|
| **STRIDE-S-01** | **Unsigned JWT Algorithm 'None' Forgery**: An attacker creates an unauthenticated JWT with `"alg": "none"` and forged claims (`"sub": "USR_ADMIN"`, `"role": "admin"`). | Voyager Auth Gateway (`/api/v3/auth/login`, `/api/v3/agency/profile`) | Cryptographic signature validation; rejected with HTTP 401. Tested by `AuthSessionExecutor` and verified by `DoubleProofVerifier`. |
| **STRIDE-S-02** | **Predictable Password Reset Token**: Token generation utilizes timestamp rounding (`hashlib.md5(f"{email}-{rounded_minute}")`), enabling token prediction. | Voyager Auth Gateway (`/api/v3/auth/reset-password`) | Cryptographically secure pseudo-random token generation (`secrets.token_urlsafe(32)`). |
| **STRIDE-S-03** | **Agent Session Persistence Post-Logout**: Revoked bearer tokens remain valid in server cache, permitting unauthorized replay attacks. | Session Store / Cache (`/api/v3/auth/logout`) | Server-side token invalidation blacklist and session revocation on logout. |

---

### 2.2 Tampering (Data & Business Logic Integrity)
| Threat ID | Threat Description | Target Component | Mitigating Control & TRIPWIRE Defense |
|---|---|---|---|
| **STRIDE-T-01** | **Fare Price Tampering**: Client-supplied `total_amount` in booking hold requests is accepted directly without server-side recalculation. | Booking Engine (`/api/v3/bookings/hold`) | Mandatory server-side fare re-computation from supplier catalog base fare and seat count; client fare overrides strictly rejected with HTTP 400. |
| **STRIDE-T-02** | **Negative Quantity Seat Abuse**: Attacker holds or cancels `-5` seats to credit money or corrupt seat availability. | Booking Engine (`/api/v3/bookings/hold`) | Strict input schema validation enforcing integer seat count $\ge 1$. |
| **STRIDE-T-03** | **Double Refund / Duplicate Cancellation**: Attacker rapidly cancels an already-cancelled booking to trigger duplicate wallet refund credits. | Payment & Refund Engine (`/api/v3/bookings/{id}/cancel`) | Strict state machine lifecycle validation: only `CONFIRMED` or `HELD` bookings are cancellable. Atomic DB transactions with optimistic locking. |
| **STRIDE-T-04** | **Unconfirmed Booking Payment**: Attacker bypasses the payment gateway by invoking confirmation endpoints directly on unpaid held bookings. | Booking Flow Engine (`/api/v3/bookings/{id}/confirm`) | Invariant assertion requiring `booking.status == CONFIRMED` prior to issuing confirmation tickets. |

---

### 2.3 Repudiation (Audit Integrity & Non-Repudiation)
| Threat ID | Threat Description | Target Component | Mitigating Control & TRIPWIRE Defense |
|---|---|---|---|
| **STRIDE-R-01** | **DAST Scan Log Manipulation**: A compromised agent or external adversary modifies scan execution logs to conceal security findings. | TRIPWIRE `AuditLogger` | Append-only cryptographically hash-chained audit ledger (`SHA-256(previous_hash + entry_data)`). |
| **STRIDE-R-02** | **Disavowed High-Risk Probes**: An operator or auditor denies authorizing destructive state-changing probes (e.g. balance deductions). | TRIPWIRE `ApprovalGate` | Operator authorization tokens signed with cryptographic operator ID, timestamp, and action hash. |

---

### 2.4 Information Disclosure (Confidentiality & PCI-DSS)
| Threat ID | Threat Description | Target Component | Mitigating Control & TRIPWIRE Defense |
|---|---|---|---|
| **STRIDE-I-01** | **Unmasked Credit Card PAN & CVV in Invoices**: Invoices return cleartext 16-digit Primary Account Numbers (PAN) and 3-digit CVVs. | Invoice Service (`/api/v3/bookings/{id}/invoice`) | Field-level redaction masking card numbers to `****-****-****-XXXX` and omitting CVVs in API responses. |
| **STRIDE-I-02** | **Debug Environment Leakage**: Sensitive cloud credentials, GDS supplier API keys, and database passwords exposed on unauthenticated endpoints. | Debug Endpoint (`/debug/env`) | Completely disable debug endpoints in non-development profiles; enforce IP whitelisting and administrative role restrictions. |
| **STRIDE-I-03** | **Verbose Stack Trace Leakage**: Malformed inputs trigger uncaught Python exceptions returning file system paths and framework internals. | Global Error Handler | Custom global exception handler returning sanitized JSON error messages with generic error correlation IDs. |

---

### 2.5 Denial of Service (Availability & Strain)
| Threat ID | Threat Description | Target Component | Mitigating Control & TRIPWIRE Defense |
|---|---|---|---|
| **STRIDE-D-01** | **Target Resource Exhaustion via Aggressive Scanning**: Scanner floods production services with high concurrency, causing supplier outages or locking inventory. | Voyager Lab / Live Target | TRIPWIRE `RateLimiter`: Token bucket algorithm enforcing 300 RPM ceiling and 5 max concurrent requests. Dynamic strain backoff on HTTP 429/503. |
| **STRIDE-D-02** | **Runaway Agent Loop**: An autonomous LLM or test loop enters infinite recursion, consuming memory and bandwidth. | TRIPWIRE Orchestrator | Atomic `KillSwitch` callable via CLI, UI, API, or disk file (`.tripwire_kill`). Instantly severs network egress across all threads. |

---

### 2.6 Elevation of Privilege (Access Control & Tenancy)
| Threat ID | Threat Description | Target Component | Mitigating Control & TRIPWIRE Defense |
|---|---|---|---|
| **STRIDE-E-01** | **Cross-Tenant Booking IDOR (BOLA)**: Agency Alpha queries or modifies booking records owned by Agency Beta by altering the `booking_id` path parameter. | Booking Resource API (`/api/v3/bookings/{id}`) | Enforce multi-tenant data isolation: assert `booking.agency_id == current_user.agency_id` on all record access; deny with HTTP 403. |
| **STRIDE-E-02** | **Role Escalation via Mass Assignment (BOPLA)**: A sub-agent user submits `{ "role": "admin" }` or `{ "is_verified": true }` in profile update requests. | User Profile API (`/api/v3/agency/users`) | Strict Pydantic input schemas filtering administrative fields; prohibit client-side role assignment. |
| **STRIDE-E-03** | **Internal SSRF via Webhook Registration**: Attacker registers webhook pointing to internal cloud metadata (`http://169.254.169.254`) or localhost services. | Webhook Gateway (`/api/v3/supplier/webhook`) | Strict URL parsing, private/loopback IP address rejection, and egress allowlisting. |

---

## 3. DREAD Risk Scoring Matrix

The DREAD framework evaluates risk quantitatively across five dimensions on a 0–10 scale:
- **D**amage Potential: Extent of financial or operational harm if exploited.
- **R**eproducibility: Ease of consistently reproducing the exploit.
- **E**xploitability: Skill and tooling required to execute the exploit.
- **A**ffected Users: Proportion of users impacted.
- **D**iscoverability: Ease with which an attacker can locate the flaw.

$$\text{DREAD Score} = \frac{D + R + E + A + D}{5}$$

| Vulnerability Category | Example Flaw | D | R | E | A | D | DREAD Score | Risk Level |
|---|---|---|---|---|---|---|---|---|
| **BOLA / IDOR** | Cross-Tenant Booking Record Access | 9 | 10 | 9 | 9 | 8 | **9.0** | **CRITICAL** |
| **Business Logic** | Negative Seats / Fare Price Tampering | 10 | 10 | 9 | 8 | 8 | **9.0** | **CRITICAL** |
| **Authentication** | JWT Alg None Signature Bypass | 10 | 10 | 9 | 10 | 7 | **9.2** | **CRITICAL** |
| **BOPLA / Mass Assign** | Sub-agent to Admin Role Escalation | 9 | 10 | 8 | 8 | 7 | **8.4** | **HIGH** |
| **Data Exposure** | Cleartext PCI Card PAN & CVV Exposed | 9 | 10 | 10 | 7 | 6 | **8.4** | **HIGH** |
| **SSRF / Cloud Metadata** | Internal Webhook Callback Injection | 8 | 9 | 7 | 6 | 6 | **7.2** | **HIGH** |
| **API Hygiene** | Cleartext Supplier Keys on `/debug/env` | 8 | 10 | 9 | 5 | 7 | **7.8** | **HIGH** |
| **Zombie API Abuse** | Unauthenticated Quote on Deprecated v1 | 6 | 10 | 9 | 6 | 7 | **7.6** | **HIGH** |
| **API Hygiene** | Verbose Unhandled Exception Stack Trace | 4 | 9 | 8 | 4 | 7 | **6.4** | **MEDIUM** |

---

## 4. DAST Safety Guardrails & Defense-in-Depth Architecture

TRIPWIRE enforces a multi-tiered safety architecture ensuring safe operation:

```
[ TRIPWIRE Autonomous Agent ]
             │
             ▼
   [ AST Egress Linter ] ─── (Ensures all network calls use SafeHttpClient)
             │
             ▼
    [ ScopeManager ] ─────── (Restricts destinations strictly to 127.0.0.1 / localhost)
             │
             ▼
   [ Atomic KillSwitch ] ─── (Immediate single-call halt mechanism)
             │
             ▼
    [ RateLimiter ] ──────── (Token bucket limiter; 300 RPM ceiling + backoff)
             │
             ▼
   [ ApprovalGate ] ──────── (Guards high-risk state-changing operations)
             │
             ▼
    [ AuditLogger ] ──────── (Append-only SHA-256 hash-chained ledger)
             │
             ▼
    [ SafeHttpClient ] ───── (Egress to localhost testbed)
```

1. **AST Egress Linting**: Automated static analysis inspects every agent file to verify raw socket or standard HTTP libraries (`requests`, raw `urllib`, `aiohttp`, raw `httpx.Client`) are never imported or invoked outside `SafeHttpClient`.
2. **Target Allowlist Integrity**: Target boundaries in `scope.yaml` are cryptographically verified at runtime using SHA-256 baseline hashing (`verify_file_integrity`); any unauthorized filesystem alteration instantly trips the `KillSwitch` and aborts all execution.
3. **Double-Proof Zero False-Positive Gate**: A finding is marked `VERIFIED` if and only if both the primary exploit succeeds and a counter-factual negative control succeeds, eliminating noisy false alarms.
4. **Contextual Severity Multipliers**: Business asset weighting prioritizes payment routes, wallet transactions, and traveler PII over static catalog endpoints.
5. **Human-in-the-Loop Approval Queue**: Destructive operations (balance top-up, bulk cancellations, account deletions) require explicit operator authorization before execution.

