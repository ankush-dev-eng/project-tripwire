"""Autonomous Surface Reconnaissance and Knowledge Graph Populator."""

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from backend.agents.js_extractor import JSRouteExtractor
from backend.graph.knowledge_graph import KnowledgeGraph
from backend.safety.http_client import SafeHttpClient


class ReconCrawler:
    """Autonomous reconnaissance agent that discovers endpoints without prior documentation."""

    COMMON_JS_BUNDLE_PATHS = [
        "/static/bundle.js",
        "/static/main.js",
        "/bundle.js",
        "/assets/index.js",
    ]

    # Systematic heuristic probes for discovering versioned APIs, administrative endpoints, and debug routes
    COMMON_PROBE_SEGMENTS = [
        "",
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/v1",
        "/v2",
        "/v3",
        "/internal",
        "/debug",
        "/test",
    ]

    COMMON_RESOURCE_NAMES = [
        "auth/login",
        "auth/reset-password",
        "flights/search",
        "bookings",
        "bookings/hold",
        "bookings/B-001",
        "bookings/1",
        "bookings/1/pay",
        "bookings/1/cancel",
        "bookings/1/invoice",
        "agency/profile",
        "agency/users",
        "wallet/balance",
        "supplier/webhook",
        "supplier/diagnostics",
        "supplier-sync",
        "env",
    ]

    def __init__(self, http_client: SafeHttpClient, knowledge_graph: KnowledgeGraph) -> None:
        self.client = http_client
        self.kg = knowledge_graph

    async def run_discovery(self, target_base_url: str, har_path: Path | str | None = None) -> int:
        """Execute full autonomous discovery routine against target surface."""
        parsed_base = urlparse(target_base_url)
        host = parsed_base.hostname or "127.0.0.1"
        port = parsed_base.port or (443 if parsed_base.scheme == "https" else 80)
        scheme = parsed_base.scheme or "http"

        host_id = self.kg.add_host(host=host, port=port, scheme=scheme)

        # 1. Inspect and extract routes from frontend JavaScript bundles
        for js_path in self.COMMON_JS_BUNDLE_PATHS:
            bundle_url = f"{target_base_url.rstrip('/')}{js_path}"
            try:
                res = await self.client.get(bundle_url)
                if res.status_code == 200:
                    extracted_routes = JSRouteExtractor.extract_routes(res.text)
                    for route in extracted_routes:
                        ep_id = self.kg.add_endpoint(
                            method="GET",
                            path=route,
                            declared=False,
                            host_id=host_id,
                        )
                        # Extract path parameter tokens
                        if "{" in route and "}" in route:
                            for token in route.split("/"):
                                if token.startswith("{") and token.endswith("}"):
                                    param_name = token[1:-1]
                                    self.kg.add_parameter(
                                        endpoint_id=ep_id,
                                        param_name=param_name,
                                        location="path",
                                    )
            except Exception:
                continue

        # 2. Ingest HAR recording if provided
        if har_path:
            self._ingest_har(har_path, host_id)

        # 3. Perform systematic pattern probes across version and resource matrices
        for prefix in self.COMMON_PROBE_SEGMENTS:
            for resource in self.COMMON_RESOURCE_NAMES:
                candidate_path = f"{prefix}/{resource}".replace("//", "/")
                probe_url = f"{target_base_url.rstrip('/')}{candidate_path}"

                for method in ["GET", "POST"]:
                    try:
                        res = await self.client.request(method, probe_url)
                        # HTTP 200, 201, 400, 401, 403, 405 indicate the route exists on the target
                        if res.status_code in {200, 201, 400, 401, 403, 405}:
                            auth_req = res.status_code in {401, 403}
                            self.kg.add_endpoint(
                                method=method,
                                path=candidate_path,
                                declared=False,
                                auth_required=auth_req,
                                host_id=host_id,
                            )
                    except Exception:
                        continue

        return self.kg.get_endpoint_count()

    def _ingest_har(self, har_path: Path | str, host_id: str) -> None:
        """Parse recorded HAR file and integrate observed endpoints, methods, and parameters."""
        path = Path(har_path)
        if not path.exists():
            return

        with open(path, encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return

        entries = data.get("log", {}).get("entries", [])
        for entry in entries:
            req = entry.get("request", {})
            method = req.get("method", "GET").upper()
            url = req.get("url", "")
            if not url:
                continue

            parsed = urlparse(url)
            route_path = parsed.path
            ep_id = self.kg.add_endpoint(
                method=method,
                path=route_path,
                declared=False,
                host_id=host_id,
            )

            # Ingest query parameters
            query_params = parse_qs(parsed.query)
            for param_name, values in query_params.items():
                val = values[0] if values else None
                self.kg.add_parameter(
                    endpoint_id=ep_id,
                    param_name=param_name,
                    location="query",
                    observed_value=val,
                )

            # Ingest postData parameters if JSON
            post_data = req.get("postData", {})
            if post_data.get("mimeType") == "application/json":
                try:
                    body_json = json.loads(post_data.get("text", "{}"))
                    if isinstance(body_json, dict):
                        for k, v in body_json.items():
                            self.kg.add_parameter(
                                endpoint_id=ep_id,
                                param_name=k,
                                location="body",
                                observed_value=str(v),
                            )
                except Exception:
                    pass
