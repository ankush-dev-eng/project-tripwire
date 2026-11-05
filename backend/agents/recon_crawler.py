"""Autonomous Surface Reconnaissance and Knowledge Graph Populator."""

import json
import re
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
        "auth/redirect",
        "flights/search",
        "bookings",
        "bookings/hold",
        "bookings/error-probe",
        "bookings/B-001",
        "bookings/1",
        "bookings/1/pay",
        "bookings/1/cancel",
        "bookings/1/invoice",
        "agency/profile",
        "agency/users",
        "agency/users/{user_id}/promote",
        "agency/documents",
        "wallet/balance",
        "wallet/topup",
        "supplier/webhook",
        "supplier/diagnostics",
        "supplier/callback",
        "supplier-sync",
        "partner/v2/quote",
        "env",
    ]

    def __init__(self, http_client: SafeHttpClient, knowledge_graph: KnowledgeGraph) -> None:
        self.client = http_client
        self.kg = knowledge_graph

    async def run_discovery(
        self,
        target_base_url: str,
        har_path: Path | str | None = None,
        traffic_log_path: Path | str | None = None,
    ) -> int:
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

        # 3. Ingest Traffic Log if provided
        if traffic_log_path:
            self._ingest_traffic_log(traffic_log_path, host_id)

        # 4. Perform systematic pattern probes across version and resource matrices
        for prefix in self.COMMON_PROBE_SEGMENTS:
            for resource in self.COMMON_RESOURCE_NAMES:
                candidate_path = f"{prefix}/{resource}".replace("//", "/")
                probe_url = f"{target_base_url.rstrip('/')}{candidate_path}"

                for method in ["GET", "POST"]:
                    try:
                        res = await self.client.request(method, probe_url)
                        # HTTP 200, 201, 400, 401, 403, 405, 422 indicate the route exists on the target
                        if res.status_code in {200, 201, 400, 401, 403, 405, 422}:
                            auth_req = res.status_code in {401, 403}
                            ep_id = self.kg.add_endpoint(
                                method=method,
                                path=candidate_path,
                                declared=False,
                                auth_required=auth_req,
                                host_id=host_id,
                            )
                            # Dynamic discovery: inspect response for entities/sample IDs and sub-resources
                            if res.status_code in {200, 201}:
                                try:
                                    resp_json = res.json()
                                    if isinstance(resp_json, dict) and "flights" in resp_json:
                                        items = resp_json["flights"]
                                    elif isinstance(resp_json, list):
                                        items = resp_json
                                    elif isinstance(resp_json, dict):
                                        items = [resp_json]
                                    else:
                                        items = []
                                    for item in items:
                                        if isinstance(item, dict):
                                            for k, v in item.items():
                                                if any(
                                                    sub in k.lower()
                                                    for sub in [
                                                        "id",
                                                        "flight",
                                                        "user",
                                                        "booking",
                                                    ]
                                                ) and isinstance(v, (str, int)):
                                                    self.kg.add_parameter(
                                                        endpoint_id=ep_id,
                                                        param_name=k,
                                                        location="path"
                                                        if "{" in candidate_path
                                                        else "query",
                                                        observed_value=str(v),
                                                    )
                                            # If user entity discovered, probe user sub-actions (e.g. promote)
                                            if "user_id" in item:
                                                sub_path = (
                                                    f"{candidate_path}/{item['user_id']}/promote"
                                                )
                                                self.kg.add_endpoint(
                                                    method="POST",
                                                    path=sub_path,
                                                    declared=False,
                                                    auth_required=True,
                                                    host_id=host_id,
                                                )
                                except Exception:
                                    pass
                    except Exception:
                        continue

        return self.kg.get_endpoint_count()

    def _ingest_traffic_log(self, log_path: Path | str, host_id: str) -> None:
        """Parse traffic log lines to extract endpoints, methods, and observed sample IDs."""
        path = Path(log_path)
        if not path.exists():
            return
        id_pattern = re.compile(
            r"^([A-Za-z0-9]+-[A-Za-z0-9\-]+|[A-Za-z0-9]+_[A-Za-z0-9\_]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
        )
        seen_routes: set[tuple[str, str]] = set()
        with open(path, encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                for i, part in enumerate(parts):
                    clean_m = part.strip('"')
                    if clean_m in {"GET", "POST", "PUT", "DELETE", "PATCH"} and i + 1 < len(parts):
                        raw_path = parts[i + 1].split("?")[0].rstrip("/")
                        if not raw_path.startswith("/"):
                            raw_path = "/" + raw_path
                        route_key = (clean_m, raw_path)
                        if route_key in seen_routes:
                            continue
                        seen_routes.add(route_key)

                        segments = raw_path.split("/")
                        has_id = False
                        for idx, seg in enumerate(segments):
                            if (
                                id_pattern.match(seg)
                                and len(seg) >= 4
                                and not seg.startswith("api")
                            ):
                                templated = segments.copy()
                                param_n = "booking_id" if "booking" in raw_path else "id"
                                templated[idx] = f"{{{param_n}}}"
                                templated_path = "/".join(templated)
                                t_id = self.kg.add_endpoint(
                                    method=clean_m,
                                    path=templated_path,
                                    declared=False,
                                    host_id=host_id,
                                )
                                self.kg.add_parameter(
                                    endpoint_id=t_id,
                                    param_name=param_n,
                                    location="path",
                                    observed_value=seg,
                                )
                                has_id = True
                        if not has_id:
                            self.kg.add_endpoint(
                                method=clean_m,
                                path=raw_path,
                                declared=False,
                                host_id=host_id,
                            )

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
