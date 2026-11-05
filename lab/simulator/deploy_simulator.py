"""Deploy Simulator for Dev vs Held-Out Ground Truth Splits and Route Mutations."""

from __future__ import annotations

import random
from typing import Any

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
