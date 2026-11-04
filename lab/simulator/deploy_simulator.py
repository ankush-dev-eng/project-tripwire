"""Deploy Simulator for Dev vs Held-Out Ground Truth Splits and Route Mutations."""

import random
from typing import Any

from lab.vulnerabilities import get_vulnerabilities


class DeploySimulator:
    """Simulates production code deploys and held-out route/parameter mutations."""

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self._rng = random.Random(seed)

    def generate_held_out_spec(self) -> list[dict[str, Any]]:
        """Generate a mutated held-out target catalog to test generalizability."""
        held_out_vulns = get_vulnerabilities(split="held_out")
        mutated_catalog: list[dict[str, Any]] = []

        id_param_names = ["ref_id", "booking_ref", "identifier", "target_id"]

        for vuln in held_out_vulns:
            # Randomly mutate path segment prefix or parameter naming based on seed
            mutated_param = vuln.parameter
            mutated_endpoint = vuln.endpoint

            if vuln.parameter in {"booking_id", "user_id"}:
                mutated_param = self._rng.choice(id_param_names)
                mutated_endpoint = vuln.endpoint.replace(
                    f"{{{vuln.parameter}}}", f"{{{mutated_param}}}"
                )

            mutated_catalog.append(
                {
                    "original_id": vuln.vuln_id,
                    "mutated_id": f"{vuln.vuln_id}_MUTATED",
                    "class": vuln.vuln_class,
                    "endpoint": mutated_endpoint,
                    "method": vuln.method,
                    "parameter": mutated_param,
                    "description": vuln.description,
                    "severity": vuln.default_severity,
                }
            )

        return mutated_catalog
