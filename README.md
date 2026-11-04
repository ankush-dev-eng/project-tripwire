<div align="center">

![PROJECT TRIPWIRE Banner](assets/hero_banner.svg)

<br/>

![Tagline](assets/tagline.svg)

<br/>

[![CI](https://github.com/ankush-dev-eng/project-tripwire/actions/workflows/ci.yml/badge.svg)](https://github.com/ankush-dev-eng/project-tripwire/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-6F8F7B.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%20%7C%203.14-1D2327.svg)](https://www.python.org/)
[![Scope Lock](https://img.shields.io/badge/safety-scope--locked-4F7A5A.svg)](scope.yaml)
[![Status](https://img.shields.io/badge/hackathon-TBO%20Security%202026-C79A3B.svg)](#)

</div>

---

## 1. Problem Statement

Modern B2B travel platforms deploy continuously. Hundreds of endpoints handle complex booking lifecycles—flight search, temporary fare hold, payment gateway handoffs, PNR issuance, split cancellations, and supplier refund reconciliations.

Conventional DAST scanners fail in this environment:
- **Blind to Workflow Semantics**: Scanners treat every endpoint as isolated, missing business-logic flaws (e.g. fare tampering, double-refunds, cross-tenant IDOR).
- **High Alert Fatigue**: Spray-and-pray fuzzing inundates engineering teams with non-exploitable noise.
- **Untracked Surface Drift**: Zombie APIs (`/v1/` routes abandoned beside `/v3/`) and Shadow APIs (endpoints active in traffic but absent from specs) linger unmonitored.
- **Late Feedback**: Periodic weekly scans report vulnerabilities days after code has shipped.

---

## 2. Our Solution: TRIPWIRE

**TRIPWIRE** is an autonomous, agentic Dynamic Application Security Testing platform engineered for real-time B2B travel security. It reacts within seconds of a deploy, reconstructs application topology from scratch, reasons over workflow graphs to formulate targeted test plans, executes through a mathematically isolated safety client, validates findings with double-differential proofs, and auto-verifies fixes on redeploy.

### Core Architectural Principles
1. **Safety First**: Outbound HTTP traffic is restricted to a single egress point (`SafeHttpClient`) bound to an immutable `scope.yaml` allowlist.
2. **Proof or Silence**: A finding exists only if a deterministic oracle reproduces it twice against a negative control request.
3. **Business-Context Severity**: Impact is scored by actual financial and data asset weights (wallet balance, cardholder PII, GDS supplier keys), not generic CVSS metrics.
4. **Deterministic Reasoning**: Test planning and verification use deterministic differential oracles; LLMs are restricted to explanation synthesis.
5. **Continuous Retest**: Stored proof scripts automatically run after deployments to verify patch resolution or flag regressions.

---

## 3. Architecture

```mermaid
flowchart TD
    subgraph Triggers ["Change Detection Triggers"]
        D["CI/CD Deploy Webhook"]
        T["Gateway / Access Traffic Diff"]
        J["Frontend JS Bundle Hash Diff"]
        N["DNS & Subdomain Watcher"]
    end

    subgraph Core ["Orchestrator & Intelligence"]
        CD["Change Detector Agent"]
        ORC["Deterministic Orchestrator"]
        REC["Recon Agent (Crawl & Harvest)"]
        KG[("Application Knowledge Graph")]
        INV["Inventory Agent (Active / Zombie / Shadow)"]
        PLN["Targeted Attack Planner"]
        EXE["Specialist Attack Executors"]
        VER["Differential Verifier (2x Confirmation)"]
        TRI["Contextual Triage Engine"]
        REP["Ticketing & Report Generator"]
        RET["Retest & Verification Agent"]
    end

    subgraph Safety ["Hard Boundary: Safety Layer"]
        SAFE{{"SafeHttpClient (Singleton Egress)"}}
        SCOPE[("scope.yaml (Immutable Allowlist)")]
        RATE["Token Bucket & Concurrency Limiter"]
        BACKOFF["Strain Monitor & Backoff Engine"]
        KILL["Global Atomic Kill Switch"]
        AUDIT[("Append-Only Hash-Chained Audit Log")]
    end

    subgraph Targets ["Execution Targets"]
        TGT[("Voyager Mock B2B Travel Platform")]
        HUM[("Human Approvals Queue")]
    end

    D & T & J & N --> CD
    CD --> ORC
    ORC --> REC
    REC --> SAFE
    REC --> KG
    KG --> INV
    KG --> PLN
    PLN --> EXE
    EXE --> SAFE
    SAFE --> SCOPE & RATE & BACKOFF & KILL
    SAFE --> TGT
    SAFE --> AUDIT
    EXE --> VER
    VER --> TRI
    TRI --> REP
    REP --> RET
    ORC -.->|State-changing approval| HUM
    SAFE -.->|Health alarm / Latency spike| ORC
```

---

## 4. The Agent Loop

| Stage | Agent | Responsibility |
|---|---|---|
| **1. Detect** | Change Detector | Ingests deploy webhooks, front-end bundle hash diffs, and traffic delta streams. |
| **2. Recon** | Recon Agent | Role-based headless crawler crawls UI, parses JS bundles for hidden routes, probes patterns. Builds Knowledge Graph. |
| **3. Inventory** | Inventory Agent | Reconciles Knowledge Graph against 30/90-day traffic logs. Categorizes endpoints as **Active**, **Zombie**, or **Shadow**. Synthesizes OpenAPI 3.1 spec. |
| **4. Plan** | Attack Planner | Selects targeted tests per endpoint based on parameters, roles, and business flows. Eliminates blind spray. |
| **5. Execute** | Specialist Executors | Class-specific modules (Access Control, Business Logic, Auth/Session, Injection, Data Exposure, SSRF). |
| **6. Verify** | Differential Verifier | Re-runs hits using clean minimal proofs and negative control requests. Double confirmation required. |
| **7. Triage** | Triage Engine | Deduplicates findings, computes business-context severity (`config/severity.yaml`), maps to asset owners. |
| **8. Retest** | Retest Agent | Executes stored proof scripts against updated builds; auto-closes verified fixes and reopens regressions. |

---

## 5. Hard Safety Model

TRIPWIRE treats safety as an immutable architectural guarantee:

| Safety Guard | Implementation | Enforcement |
|---|---|---|
| **Single Egress Point** | `SafeHttpClient` is the only authorized HTTP transport. | AST linting test fails if `requests`, `httpx`, or `urllib` are imported elsewhere. |
| **Strict Scope Allowlist** | Target restrictions defined in `scope.yaml` (default `127.0.0.1` lab targets). | Out-of-scope targets trigger an immediate hard halt and audit alarm. |
| **Immutable Scope** | `scope.yaml` cannot be altered by agent logic. | File integrity tests enforce read-only semantics for agents. |
| **Strain Throttling** | Dynamic latency and 5xx error tracking. | Automatically throttles throughput if p90 response time exceeds 500ms. |
| **Global Kill Switch** | Thread-safe atomic flag in memory and filesystem. | Instantly terminates active and pending requests. |
| **Audit Log & Replay** | SHA-256 hash-chained `audit.jsonl`. | Every outbound request and response is replayable for human audit. |
| **Human Approvals** | State-changing tests (`/pay`, `/cancel`, `/refund`) require human sign-off. | Hard-blocked by `config/approval_policy.yaml` until token is provided. |

---

## 6. Official Benchmarks

All benchmark metrics are generated programmatically via `make benchmark` and recorded in [BENCHMARKS.md](BENCHMARKS.md).

| Metric | Target | Status |
|---|---|---|
| **Vulnerability Recall (Overall)** | $\ge 80\%$ | Tracking via `make benchmark` |
| **Business-Logic & Access-Control Recall** | $\ge 70\%$ | Tracking via `make benchmark` |
| **Precision (After Double-Verification)** | $\ge 90\%$ | Tracking via `make benchmark` |
| **Duplicate Finding Rate** | $\le 5\%$ | Tracking via `make benchmark` |
| **Deploy-to-Verified Finding Time** | $p50 < 5\text{m}, p95 < 10\text{m}$ | Tracking via `make benchmark` |
| **Endpoint Discovery Recall** | $\ge 90\%$ | Tracking via `make benchmark` |
| **Zombie & Shadow Classification F1** | $\ge 0.85$ | Tracking via `make benchmark` |
| **Out-of-Scope Requests** | Exactly 0 | Verified by Safety Engine |
| **Retest Auto-Closure Rate** | $100\%$ | Verified by Retest Agent |

---

## 7. Palette & Visual Design

TRIPWIRE adheres to a calm, high-contrast, professional security palette:

| Token | Hex | Role | Contrast / Purpose |
|---|---|---|---|
| **Ink** | `#14181B` | Dark Background | Primary dark surface |
| **Basalt** | `#1D2327` | Dark Elev / Cards | Secondary dark surface |
| **Bone** | `#F2EFE8` | Light Background | Primary typography on dark |
| **Stone** | `#D9D4C7` | Borders & Muted Text | Structure & dividing lines |
| **Sage** | `#6F8F7B` | Primary Accent | System health & primary actions |
| **Moss** | `#4F7A5A` | Success / Scope Locked | Verified safe / Auto-closed |
| **Brass** | `#C79A3B` | Medium Severity | Cautionary indicators |
| **Copper** | `#B5693E` | High Severity | Financial & tenant risks |
| **Brick** | `#A8403A` | Critical Severity | Remote execution / PII dump |

---

## 8. Quickstart

### Prerequisites
- Python 3.12+ (or 3.14)
- Node.js 20+
- Git

### Installation
```bash
# Clone the repository
git clone https://github.com/ankush-dev-eng/project-tripwire.git
cd project-tripwire

# Install Python backend dependencies
make install
# Or on Windows PowerShell:
.\run.ps1 install
```

### Running Tests & Verification
```bash
# Run full test suite with coverage
make test
# Or on Windows:
.\run.ps1 test

# Run linter
make lint
```

---

## 9. Roadmap & Gates

- [x] **Phase 0**: Project Scaffolding, Repository Setup & CI
- [ ] **Phase 1**: Safety Layer & Single Egress Client (`SafeHttpClient`)
- [ ] **Phase 2**: Voyager B2B Lab Target & Sealed Ground Truth
- [ ] **Phase 3**: Change Detection, Reconnaissance & Knowledge Graph
- [ ] **Phase 4**: API Inventory (Active/Zombie/Shadow) & OpenAPI Generator
- [ ] **Phase 5**: Targeted Attack Planner, Executors & Double-Proof Verifier
- [ ] **Phase 6**: Triage, Severity Scoring & Automatic Retest Engine
- [ ] **Phase 7**: Central Orchestrator, WebSocket Stream & Approvals Queue
- [ ] **Phase 8**: Mission Control Frontend & Knowledge Graph Canvas
- [ ] **Phase 9**: Hardening, Threat Model & Full Benchmark Run
- [ ] **Phase 10**: Release v1.0.0 & Project Handoff

---

## 10. Responsible Use

TRIPWIRE is designed solely for authorized dynamic security testing of applications within pre-approved scopes. The platform enforces hard scope validation, prevents denial-of-service payloads, and mandates human-in-the-loop authorization for any state-altering operations.

