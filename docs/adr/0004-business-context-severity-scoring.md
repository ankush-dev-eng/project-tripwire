# ADR 0004: Business-Context Severity Triaging for B2B Travel Platforms

## Status
Accepted

## Context
Standard CVSS v3.1 calculators evaluate vulnerabilities in a vacuum (e.g. CVSS 7.5 for all IDORs), regardless of whether the affected endpoint processes passenger credit cards or returns static airport codes. In a B2B travel distribution platform, vulnerabilities carry vastly different business risks:
- Financial transactions (`/bookings/{id}/pay`, `/wallet/balance`) represent immediate revenue loss.
- PII leakage (`/passengers`, `/documents`) carries strict regulatory and GDPR/PCI-DSS liability.
- Technical misconfigurations on inactive legacy endpoints have lower immediate operational risk unless actively exposed.

## Decision
We implement a **Contextual Business Impact Matrix** (`TriageAgent` in `backend/agents/triage_agent.py` configured via `config/severity.yaml`):

1. **Asset Value Multipliers**:
   - High Financial Impact: payment gateways, wallet balance, refunds, bookings ($1.5\times$ weight).
   - High Compliance Impact: passport numbers, credit cards, user credentials ($1.4\times$ weight).
   - Low Operational Impact: public flight search, airline schedules, static assets ($0.8\times$ weight).

2. **Inventory Exposure Adjustments**:
   - `Shadow APIs`: receive an exposure penalty because unmonitored endpoints bypass WAF and central logging.
   - `Zombie APIs`: receive an urgency bump if unpatched legacy routes remain accessible from modern client networks.

3. **Explainable Triage Rationales**:
   - Every triaged finding includes a clear, plain-language business rationale explaining *why* the severity was elevated or reduced, enabling immediate prioritization for engineering leadership.

## Consequences
- **Positive**: Eliminates triage fatigue by aligning security findings with true business financial exposure.
- **Positive**: Transparent and configurable through declarative YAML policies.
- **Trade-off**: Requires platform domain modeling and asset categorization.

