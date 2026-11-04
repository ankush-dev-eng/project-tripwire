"""Application Knowledge Graph Engine.

Maintains an in-memory NetworkX graph modeling Hosts, Endpoints, Parameters, Roles, and Flows.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

import networkx as nx


@dataclass
class EndpointNode:
    endpoint_id: str  # e.g. "GET /api/v3/flights/search"
    method: str
    path: str
    status: str = "DISCOVERED"  # "DISCOVERED", "VERIFIED", "ZOMBIE", "SHADOW"
    declared: bool = False
    discovered: bool = True
    last_traffic: str | None = None
    auth_required: bool = False
    first_seen: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass
class ParameterNode:
    name: str
    location: str  # "query", "path", "body", "header"
    param_type: str = "string"
    observed_values: list[str] = field(default_factory=list)


@dataclass
class RoleNode:
    name: str  # "admin", "agent", "sub_agent"
    agency_id: str | None = None


@dataclass
class FlowNode:
    name: str  # "search", "hold", "book", "pay", "cancel", "refund"
    step_order: int = 0


class KnowledgeGraph:
    """Directed Knowledge Graph representing the inferred application surface and flows."""

    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def add_host(
        self,
        host: str,
        port: int = 8000,
        scheme: str = "http",
        fingerprint: str | None = None,
    ) -> str:
        """Add or update a target Host node."""
        node_id = f"host:{scheme}://{host}:{port}"
        self.graph.add_node(
            node_id,
            node_type="host",
            host=host,
            port=port,
            scheme=scheme,
            fingerprint=fingerprint,
        )
        return node_id

    def add_endpoint(
        self,
        method: str,
        path: str,
        declared: bool = False,
        auth_required: bool = False,
        last_traffic: str | None = None,
        host_id: str | None = None,
    ) -> str:
        """Add or update an Endpoint node in the knowledge graph."""
        method_upper = method.upper()
        # Clean path template
        clean_path = path.split("?")[0]
        endpoint_id = f"{method_upper} {clean_path}"

        if endpoint_id not in self.graph:
            node = EndpointNode(
                endpoint_id=endpoint_id,
                method=method_upper,
                path=clean_path,
                declared=declared,
                discovered=True,
                auth_required=auth_required,
                last_traffic=last_traffic,
            )
            self.graph.add_node(endpoint_id, node_type="endpoint", **asdict(node))
        else:
            # Update attributes if existing
            if declared:
                self.graph.nodes[endpoint_id]["declared"] = True
            if auth_required:
                self.graph.nodes[endpoint_id]["auth_required"] = True
            if last_traffic:
                self.graph.nodes[endpoint_id]["last_traffic"] = last_traffic

        # Link Host -> Endpoint
        if host_id and host_id in self.graph:
            self.graph.add_edge(host_id, endpoint_id, relation="HAS_ENDPOINT")

        return endpoint_id

    def add_parameter(
        self,
        endpoint_id: str,
        param_name: str,
        location: str = "query",
        param_type: str = "string",
        observed_value: str | None = None,
    ) -> str:
        """Add a parameter associated with an endpoint."""
        param_id = f"param:{endpoint_id}:{location}:{param_name}"
        if param_id not in self.graph:
            p_node = ParameterNode(
                name=param_name,
                location=location,
                param_type=param_type,
                observed_values=[observed_value] if observed_value else [],
            )
            self.graph.add_node(param_id, node_type="parameter", **asdict(p_node))
        else:
            if (
                observed_value
                and observed_value not in self.graph.nodes[param_id]["observed_values"]
            ):
                self.graph.nodes[param_id]["observed_values"].append(observed_value)

        self.graph.add_edge(endpoint_id, param_id, relation="TAKES_PARAM")
        return param_id

    def add_role_access(
        self, role_name: str, endpoint_id: str, agency_id: str | None = None
    ) -> None:
        """Link a Role node to an Endpoint with a CAN_CALL edge."""
        role_id = f"role:{role_name}"
        if role_id not in self.graph:
            r_node = RoleNode(name=role_name, agency_id=agency_id)
            self.graph.add_node(role_id, node_type="role", **asdict(r_node))

        if endpoint_id in self.graph:
            self.graph.add_edge(role_id, endpoint_id, relation="CAN_CALL")

    def add_flow_step(self, flow_name: str, endpoint_id: str, step_order: int) -> None:
        """Link a business Flow to an Endpoint."""
        flow_id = f"flow:{flow_name}"
        if flow_id not in self.graph:
            f_node = FlowNode(name=flow_name, step_order=step_order)
            self.graph.add_node(flow_id, node_type="flow", **asdict(f_node))

        if endpoint_id in self.graph:
            self.graph.add_edge(
                flow_id, endpoint_id, relation="INCLUDES_ENDPOINT", order=step_order
            )

    def get_endpoints(self) -> list[dict[str, Any]]:
        """Return all endpoint nodes and their attributes."""
        endpoints = []
        for _n, d in self.graph.nodes(data=True):
            if d.get("node_type") == "endpoint":
                endpoints.append(d)
        return endpoints

    def get_endpoint_count(self) -> int:
        return len(self.get_endpoints())

    def get_parameters_for_endpoint(self, endpoint_id: str) -> list[dict[str, Any]]:
        """Retrieve all parameter nodes connected to a given endpoint."""
        params = []
        for successor in self.graph.successors(endpoint_id):
            node_data = self.graph.nodes[successor]
            if node_data.get("node_type") == "parameter":
                params.append(node_data)
        return params

    def export_topology_for_ui(self) -> dict[str, Any]:
        """Export graph formatted for React Flow visualization (nodes & edges)."""
        nodes = []
        edges = []

        for node_id, data in self.graph.nodes(data=True):
            node_type = data.get("node_type", "default")
            label = data.get("endpoint_id") or data.get("name") or data.get("host") or node_id
            nodes.append(
                {
                    "id": node_id,
                    "type": node_type,
                    "data": {"label": label, **data},
                    "position": {"x": 0, "y": 0},
                }
            )

        for u, v, data in self.graph.edges(data=True):
            edges.append(
                {
                    "id": f"e_{u}_{v}",
                    "source": u,
                    "target": v,
                    "label": data.get("relation", ""),
                    "data": data,
                }
            )

        return {"nodes": nodes, "edges": edges}

    def to_json(self) -> str:
        """Serialize Knowledge Graph to JSON string."""
        return json.dumps(self.export_topology_for_ui(), indent=2)
