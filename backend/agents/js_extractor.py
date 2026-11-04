"""Generic JavaScript Route and Endpoint Extractor."""

import re


class JSRouteExtractor:
    """Extracts API path templates and route definitions from client JavaScript bundles."""

    # Patterns matching API paths, route maps, and fetch calls without lab-specific identifiers
    ROUTE_PATTERNS = [
        # Explicit api / v-version routes e.g. "/api/v3/...", "/v1/..."
        re.compile(
            r"""["'](/(?:api|v[0-9]+|service|internal|debug|test)/[a-zA-Z0-9_\-/{}\.]+)["']"""
        ),
        # General route map values e.g. login: "/api/..."
        re.compile(r"""[a-zA-Z0-9_]+\s*:\s*["'](/[a-zA-Z0-9_\-/{}\.]+)["']"""),
        # Fetch or axios calls e.g. fetch(`/api/...`)
        re.compile(
            r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`"'](/[a-zA-Z0-9_\-/{}\.\$]+)[`"']"""
        ),
        # Template literal paths
        re.compile(r"""`(/[a-zA-Z0-9_\-/{}\.\$]+)`"""),
    ]

    @classmethod
    def extract_routes(cls, js_source: str) -> list[str]:
        """Parse JavaScript bundle and return deduplicated list of candidate API paths."""
        discovered: set[str] = set()

        for pattern in cls.ROUTE_PATTERNS:
            for match in pattern.finditer(js_source):
                route = match.group(1).strip()
                # Clean template string expressions e.g. `${...}` into `{param}`
                cleaned = re.sub(r"\$\{[^}]+\}", "{param}", route)
                # Strip query strings
                cleaned = cleaned.split("?")[0].rstrip("/")
                if cleaned and cleaned.startswith("/"):
                    discovered.add(cleaned)

        return sorted(discovered)
