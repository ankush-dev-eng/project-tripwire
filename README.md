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

## 6. Official Benchmarks & Comparative Evaluation

All benchmark metrics are programmatically measured by `python benchmarks/run_all.py` and maintained in [`BENCHMARKS.md`](BENCHMARKS.md) and [`benchmarks/results.json`](benchmarks/results.json):

| Metric | Target | Baseline (Spray Scanner) | Baseline (OWASP ZAP) | TRIPWIRE (Dev) | TRIPWIRE (Held-Out) | Status |
|---|---|---|---|---|---|---|
| **Vulnerability Recall (Overall)** | $\ge 80\%$ | 3.6\% | 25.0\% | **90.0\%** | **88.9\%** | **PASS** |
| **Business-Logic & Access-Control Recall** | $\ge 70\%$ | 0.0\% | 11.1\% | **85.0\%** | **80.0\%** | **PASS** |
| **Precision (After Double-Verification)** | $\ge 90\%$ | 100.0\% | 63.6\% | **100.0\%** | **100.0\%** | **PASS** |
| **Duplicate Finding Rate** | $\le 5\%$ | 28.0\% | 16.0\% | **0.0\%** | **0.0\%** | **PASS** |
| **Deploy-to-Verified Time (p50)** | $< 5\text{ min}$ | 42.0s | 180.0s | **35.5s** | **37.7s** | **PASS** |
| **Endpoint Discovery Recall** | $\ge 90\%$ | 32.0\% | 58.0\% | **97.4\%** | **94.0\%** | **PASS** |
| **Zombie / Shadow Classification F1** | $\ge 0.85$ | 0.20 | 0.45 | **1.0** | **1.0** | **PASS** |
| **Out-of-Scope Requests** | Exactly 0 | N/A | N/A | **0** | **0** | **PASS** |
| **Rate Limit / Strain Violations** | Exactly 0 | N/A | N/A | **0** | **0** | **PASS** |
| **Retest Auto-Closure Rate** | $100\%$ | N/A | N/A | **100\%** | **100\%** | **PASS** |
| **Retest Regression Reopen Rate** | $100\%$ | N/A | N/A | **100\%** | **100\%** | **PASS** |
| **API p95 Response Time** | $< 200\text{ ms}$ | N/A | N/A | **78.5\text{ ms}** | **78.5\text{ ms}** | **PASS** |
| **Code Test Coverage** | $\ge 80\%$ | N/A | N/A | **90\%** (76 tests) | **90\%** | **PASS** |

---

## 7. Palette & Visual Design

TRIPWIRE adheres to a calm, high-contrast, professional security palette across all UI views:

| Token | Hex | Role | Purpose |
|---|---|---|---|
| **Ink** | `#14181B` | Dark Background | Primary background surface |
| **Basalt** | `#1D2327` | Dark Elevation / Cards | Secondary card surfaces and borders |
| **Bone** | `#F2EFE8` | Light Typography | Primary body text and headers |
| **Stone** | `#D9D4C7` | Muted Text / Borders | Subtle secondary metadata and dividers |
| **Sage** | `#6F8F7B` | Primary Accent | System health, active connections, graph nodes |
| **Moss** | `#4F7A5A` | Success / Scope Locked | Verified safe, closed tickets, 100% tests |
| **Brass** | `#C79A3B` | Medium Severity / Warn | Approvals queue, warning badges |
| **Copper** | `#B5693E` | High Severity | Financial risks, tenant escalation |
| **Brick** | `#A8403A` | Critical Severity | Remote exploits, credential leaks, kill switch |

---

## 8. Quickstart & Demonstration Guide

### Prerequisites
- Python 3.12+ (or 3.14)
- Node.js 20+ (optional; pre-compiled React SPA is included in `frontend/dist`)
- Git

### Installation
```bash
git clone https://github.com/ankush-dev-eng/project-tripwire.git
cd project-tripwire

# Install Python dependencies
pip install -r requirements-dev.txt
pip install -e .
```

### Running the Live Platform
```powershell
# 1. Start the Voyager Mock B2B Travel Platform (Terminal 1)
python -m uvicorn lab.app:app --host 127.0.0.1 --port 8000

# 2. Start the TRIPWIRE Mission Control Server (Terminal 2)
python -m uvicorn backend.api.app:api_app --host 127.0.0.1 --port 8080
```
Open **`http://localhost:8080`** in your browser to access the Mission Control UI.

### Triggering an Autonomous Scan
From the web UI, click **"Start Autonomous Scan"**, or trigger via CLI:
```powershell
curl -X POST http://127.0.0.1:8080/api/scan/start `
  -H "Content-Type: application/json" `
  -d '{"target_url": "http://127.0.0.1:8000", "traffic_log_path": "data/gateway_30d.log"}'
```

### Running Tests & Benchmarks
```powershell
# Run full test suite with coverage (76 passing tests, 90% coverage)
python -m pytest tests/ --cov=backend

# Run the complete official benchmark suite
python benchmarks/run_all.py

# Run linter and formatting checks
python -m ruff check .
python -m ruff format --check .
```

---

## 9. Completed Phases & Release Tags

- [x] **Phase 0**: Project Scaffolding, Repository Setup & CI (`v0.0.1`)
- [x] **Phase 1**: Safety Layer & Single Egress Client `SafeHttpClient` (`v0.1.0`)
- [x] **Phase 2**: Voyager B2B Lab Target & Sealed Ground Truth (`v0.2.0`)
- [x] **Phase 3**: Change Detection, Reconnaissance & Knowledge Graph (`v0.3.0`)
- [x] **Phase 4**: API Inventory (Active/Zombie/Shadow) & OpenAPI Generator (`v0.4.0`)
- [x] **Phase 5**: Targeted Attack Planner, Executors & Double-Proof Verifier (`v0.5.0`)
- [x] **Phase 6**: Triage, Severity Scoring & Automatic Retest Engine (`v0.6.0`)
- [x] **Phase 7**: Central Orchestrator, WebSocket Stream & Approvals Queue (`v0.7.0`)
- [x] **Phase 8**: Mission Control Frontend & Knowledge Graph Canvas (`v0.8.0`)
- [x] **Phase 9**: Hardening, Threat Model & Full Benchmark Run (`v0.9.0`)
- [x] **Phase 10**: Production Polish, Documentation & Release (`v1.0.0`)

---

## 10. Documentation Index

- **[Project Handoff & Event-Day Playbook](HANDOFF.md)**: Complete step-by-step evaluation guide and verification proofs.
- **[Official Benchmark Ledger](BENCHMARKS.md)**: Programmatically maintained metrics across Baselines, Dev, and Held-Out targets.
- **[STRIDE & DREAD Threat Model](docs/THREAT_MODEL.md)**: Exhaustive threat modeling of agentic DAST engines and 4-tier safety invariants.
- **[Architecture Decision Records (ADRs)](docs/adr/)**:
  - [ADR 0001: SafeHttpClient AST Egress Isolation & Rate Limiting](docs/adr/0001-safe-http-client-isolation.md)
  - [ADR 0002: Dynamic Bipartite Knowledge Graph Schema](docs/adr/0002-knowledge-graph-schema.md)
  - [ADR 0003: Double-Proof Differential Verification](docs/adr/0003-double-proof-differential-verification.md)
  - [ADR 0004: Contextual Business Impact Severity Scoring](docs/adr/0004-business-context-severity-scoring.md)

---

## 11. Responsible Use & Disclosure

TRIPWIRE is designed solely for authorized dynamic security testing of applications within pre-approved scopes. The platform enforces hard scope validation, prevents denial-of-service payloads, and mandates human-in-the-loop authorization for any state-altering operations.

