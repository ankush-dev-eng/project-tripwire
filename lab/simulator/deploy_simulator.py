"""Deploy Simulator for Dev vs Held-Out Ground Truth Splits and Route Mutations."""

from __future__ import annotations

import json
import random
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse

from lab.vulnerabilities import get_vulnerabilities


class DeploySimulator:
    """Simulates production code deploys and held-out route/parameter mutations."""

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self._rng = random.Random(seed)

    def generate_held_out_spec(self) -> list[dict[str, Any]]:
        """Generate a mutated held-out target catalog across routes, params, flows, and vulns."""
        held_out_vulns = get_vulnerabilities(split="held_out")

        # 1. Mutate Vulnerability Set:
        # Stratified sampling and seed-based subset/permutation
        ac_vulns = [v for v in held_out_vulns if v.vuln_class == "access_control"]
        bl_vulns = [v for v in held_out_vulns if v.vuln_class == "business_logic"]
        ssr_vulns = [v for v in held_out_vulns if v.vuln_class == "server_side"]
        other_vulns = [
            v
            for v in held_out_vulns
            if v.vuln_class not in {"access_control", "business_logic", "server_side"}
        ]

        # Ensure core classes are represented while sampling a seed-dependent subset
        selected_others = self._rng.sample(other_vulns, k=len(other_vulns) - 1)
        selected_vulns = ac_vulns + bl_vulns + ssr_vulns + selected_others
        self._rng.shuffle(selected_vulns)

        # 2. Mutate Parameters across all types (compatible with semantic intent)
        param_mutation_pools: dict[str, list[str]] = {
            "booking_id": [
                "booking_ref",
                "ref_id",
                "booking_identifier",
                "target_id",
                "booking_pnr",
                "reservation_id",
            ],
            "amount": ["topup_amount", "transfer_amount", "deposit_amount", "credit_amount"],
            "Authorization": ["Authorization", "access_token", "auth_token", "X-Auth-Token"],
            "X-Supplier-Ref": ["X-Supplier-Ref", "X-Vendor-Ref", "X-Partner-Id", "X-Provider-Id"],
            "url": ["redirect_url", "target_url", "callback_url", "redirect_uri", "endpoint_url"],
            "file": ["document_file", "upload_file", "file", "attachment_file"],
        }

        # 3. Mutate Flows across workflows
        flow_blueprints: dict[str, dict[str, Any]] = {
            "access_control": {
                "flow_name": "checkout_invoicing_flow",
                "prerequisites": ["/api/v3/auth/login"],
                "transactional": True,
            },
            "business_logic": {
                "flow_name": "booking_state_commit_flow",
                "prerequisites": ["/api/v3/bookings/hold"],
                "transactional": True,
            },
            "server_side": {
                "flow_name": "external_partner_redirection_flow",
                "prerequisites": [],
                "transactional": False,
            },
            "auth_session": {
                "flow_name": "identity_lifecycle_flow",
                "prerequisites": ["/api/v3/auth/login"],
                "transactional": False,
            },
            "injection": {
                "flow_name": "supplier_integration_flow",
                "prerequisites": ["/internal/supplier-sync"],
                "transactional": True,
            },
            "api_hygiene": {
                "flow_name": "client_session_negotiation_flow",
                "prerequisites": [],
                "transactional": False,
            },
            "zombie_shadow": {
                "flow_name": "legacy_quote_sync_flow",
                "prerequisites": [],
                "transactional": False,
            },
        }

        mutated_catalog: list[dict[str, Any]] = []

        for step_idx, vuln in enumerate(selected_vulns, 1):
            mutated_param = vuln.parameter
            if vuln.parameter in param_mutation_pools:
                mutated_param = self._rng.choice(param_mutation_pools[vuln.parameter])
            elif vuln.parameter:
                mutated_param = f"{vuln.parameter}_{self._rng.choice(['val', 'id', 'arg'])}"

            # 4. Mutate Routes (path placeholders, route aliases, query parameters)
            mutated_endpoint = vuln.endpoint
            if vuln.parameter and f"{{{vuln.parameter}}}" in vuln.endpoint:
                mutated_endpoint = vuln.endpoint.replace(
                    f"{{{vuln.parameter}}}", f"{{{mutated_param}}}"
                )

            # Route aliases and query annotations
            alias_prefix = self._rng.choice(["/api/v3", "/api/v3.1", "/api/v4/preview"])
            route_alias = f"{alias_prefix}{mutated_endpoint.replace('/api/v3', '')}"

            # Assemble flow context
            flow_meta = flow_blueprints.get(
                vuln.vuln_class,
                {
                    "flow_name": "generic_api_pipeline",
                    "prerequisites": [],
                    "transactional": False,
                },
            )
            flow_info = {
                "flow_id": f"FLOW-{self._rng.randint(100, 999)}",
                "flow_name": flow_meta["flow_name"],
                "step": step_idx,
                "dependencies": flow_meta["prerequisites"],
                "transactional": flow_meta["transactional"],
                "requires_auth": vuln.parameter == "Authorization" or "auth" not in vuln.endpoint,
            }

            mutated_catalog.append(
                {
                    "original_id": vuln.vuln_id,
                    "mutated_id": f"{vuln.vuln_id}_M{self.seed % 1000}",
                    "class": vuln.vuln_class,
                    "endpoint": mutated_endpoint,
                    "route_alias": route_alias,
                    "method": vuln.method,
                    "parameter": mutated_param,
                    "flow": flow_info,
                    "description": f"{vuln.description} [Variant M{self.seed % 1000}]",
                    "severity": vuln.default_severity,
                }
            )

        return mutated_catalog

    def create_mutated_app(self, spec: list[dict[str, Any]]) -> FastAPI:
        """Create an autonomous, spec-free FastAPI target application for held-out evaluation.

        Key requirements:
        - openapi_url=None, docs_url=None, redoc_url=None (no spec exposed to agent).
        - Serves /static/bundle.js containing the client application routes.
        - Mounts routes exhibiting the sampled vulnerability behaviors.
        """
        mutated_app = FastAPI(
            title=f"Voyager Mutated Held-Out Target (Seed {self.seed})",
            openapi_url=None,
            docs_url=None,
            redoc_url=None,
        )

        routes_list: list[str] = []
        for item in spec:
            routes_list.append(item["endpoint"])
            if item.get("route_alias"):
                routes_list.append(item["route_alias"])

        clean_routes = sorted(list(dict.fromkeys(routes_list)))

        # Frontend JS bundle serving route catalog
        bundle_js = (
            "// Client Application JavaScript Bundle\n"
            "const APP_CONFIG = {\n"
            f"  build: 'mutated-seed-{self.seed}',\n"
            f"  routes: {json.dumps(clean_routes)},\n"
            "};\n"
            "window.__APP_ROUTES__ = APP_CONFIG.routes;\n"
        )

        @mutated_app.get("/static/bundle.js")
        async def get_bundle() -> PlainTextResponse:
            return PlainTextResponse(bundle_js, media_type="application/javascript")

        # Handlers for specific vulnerabilities
        async def handle_invoice(request: Request) -> Response:
            val = next(iter(request.path_params.values()), "1")
            if "nonexistent" in val or "invalid" in val:
                return JSONResponse({"detail": "Invoice not found"}, status_code=404)
            return JSONResponse({
                "invoice_id": "INV-HELD-001",
                "booking_id": val,
                "agency_id": "AGY-BETA",
                "customer": "Corporate Travel Corp",
                "amount": 450.0,
                "card_number": "4111-2222-3333-4444",
                "cvv": "123",
                "paid": True,
            })

        async def handle_confirm(request: Request) -> Response:
            val = next(iter(request.path_params.values()), "1")
            if "nonexistent" in val or "invalid" in val:
                return JSONResponse({"detail": "Booking not found"}, status_code=404)
            return JSONResponse({
                "status": "CONFIRMED",
                "booking_id": val,
                "payment_status": "SKIPPED_UNPAID",
                "message": "Booking confirmed without prior payment execution",
            })

        async def handle_topup(request: Request) -> Response:
            try:
                body = await request.json()
            except Exception:
                body = {}
            if not body:
                return JSONResponse({"detail": "Missing topup amount"}, status_code=422)
            return JSONResponse({
                "status": "SUCCESS",
                "amount": body.get("amount", 10000.0),
                "new_balance": 50000.0,
                "step_up_verified": False,
            })

        async def handle_logout(request: Request) -> Response:
            return JSONResponse({"status": "SUCCESS", "message": "Logged out successfully"})

        async def handle_callback(request: Request) -> Response:
            hdr = request.headers.get("X-Supplier-Ref", "")
            resp = JSONResponse({"status": "RECEIVED", "supplier_ack": True})
            if hdr:
                resp.headers["X-Supplier-Ref"] = hdr
            return resp

        async def handle_login(request: Request) -> Response:
            return JSONResponse({
                "access_token": "tok_held_out_login",
                "token_type": "bearer",
                "status": "AUTHENTICATED",
            })

        async def handle_redirect(request: Request) -> Response:
            dest = (
                request.query_params.get("url")
                or request.query_params.get("target_url")
                or request.query_params.get("redirect_url")
            )
            if not dest:
                try:
                    body = await request.json()
                    dest = (
                        body.get("url")
                        or body.get("target_url")
                        or body.get("redirect_url")
                    )
                except Exception:
                    pass
            if dest:
                return RedirectResponse(url=dest, status_code=302)
            return JSONResponse({"detail": "Missing destination URL"}, status_code=422)

        async def handle_documents(request: Request) -> Response:
            return JSONResponse({
                "status": "UPLOADED",
                "filename": "uploaded_document.php",
                "url": "/uploads/uploaded_document.php",
            })

        async def handle_quote(request: Request) -> Response:
            return JSONResponse({
                "quote_id": "Q-LEGACY-PARTNER",
                "fare": 80.0,
                "discount": 0.45,
                "version": "v2-legacy",
            })

        async def handle_generic(request: Request) -> Response:
            return JSONResponse({"status": "OK", "endpoint": str(request.url.path)})

        handler_map = {
            "VULN-AC-04": handle_invoice,
            "VULN-BL-04": handle_confirm,
            "VULN-AUTH-03": handle_topup,
            "VULN-AUTH-04": handle_logout,
            "VULN-INJ-03": handle_callback,
            "VULN-HYG-03": handle_login,
            "VULN-SSR-02": handle_redirect,
            "VULN-SSR-03": handle_documents,
            "VULN-ZOM-02": handle_quote,
        }

        registered_paths: set[str] = set()

        for item in spec:
            orig_id = item["original_id"]
            handler = handler_map.get(orig_id, handle_generic)

            targets = [item["endpoint"]]
            if item.get("route_alias"):
                targets.append(item["route_alias"])

            for t in targets:
                if t not in registered_paths:
                    mutated_app.add_api_route(
                        t,
                        handler,
                        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
                    )
                    registered_paths.add(t)

        return mutated_app
