# ADR 0002: Dynamic Bipartite Knowledge Graph for Contextual Attack Modeling

## Status
Accepted

## Context
Traditional DAST scanners suffer from low recall on B2B SaaS applications because they lack structural context. They treat endpoints as isolated URLs, blind to:
- Relationship between parent and child resources (e.g. `/agency/users` vs `/bookings/{id}/pay`).
- Tenant role boundaries (e.g. `Agency_Alpha` vs `Agency_Beta`, `admin` vs `sub_agent`).
- State-machine sequencing requirements (e.g. flight search -> hold -> book -> pay -> cancel).
- Parameter provenance and observed runtime values.

## Decision
We model the target application inside `backend/graph/knowledge_graph.py` as a typed bipartite directed property graph using `NetworkX`:

1. **Entity Node Types**:
   - `HostNode`: Target host configuration and root TLS properties.
   - `EndpointNode`: HTTP path template, HTTP method, authentication requirements, classification (Active, Zombie, Shadow).
   - `ParameterNode`: Parameter name, location (`path`, `query`, `header`, `body`), datatype, and historically observed runtime sample values.
   - `RoleNode`: Tenant identity, agency tier, permission scopes, and valid session token identifiers.
   - `FlowSequenceNode`: Ordered lifecycle sequences modeling multi-step business transactions.

2. **Autonomous Parameter Extraction**:
   - As traffic logs and crawler probes are analyzed, runtime values (e.g. `BKG-ALPHA-001`, `USR-001`) are automatically bound to `ParameterNode.observed_values`.
   - The `AttackPlanner` queries the Knowledge Graph to construct context-aware attack vectors with realistic parameters, eliminating blind spray fuzzing and hardcoded test data.

3. **Graph-Driven Frontend Visualization**:
   - The knowledge graph exports directly to a React Flow compatible JSON format (`export_topology_for_ui()`), allowing security analysts to inspect application topology interactively in real time.

## Consequences
- **Positive**: Eliminates blind scanning and hardcoded route identifiers in agent code.
- **Positive**: Achieves $\ge 90\%$ discovery recall and enables business-logic state machine fuzzing.
- **Trade-off**: Requires an initial reconnaissance pass and memory storage for graph entities.

