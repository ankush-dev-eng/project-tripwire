"""Static AST tests enforcing the single egress and ground-truth isolation invariants."""

import ast
from pathlib import Path

import yaml

FORBIDDEN_NETWORK_MODULES = {"urllib", "requests", "aiohttp", "socket", "http.client"}
# httpx is allowed ONLY inside backend/safety/http_client.py
ALLOWED_HTTPX_PATH = Path("backend/safety/http_client.py")


def test_no_forbidden_network_imports_in_backend() -> None:
    """Verify that no module in backend/ imports raw networking libraries."""
    backend_dir = Path("backend")
    assert backend_dir.is_dir(), "backend directory must exist"

    violations: list[str] = []

    for py_file in backend_dir.rglob("*.py"):
        rel_path = py_file.relative_to(Path("."))
        with open(py_file, encoding="utf-8") as f:
            try:
                tree = ast.parse(f.read(), filename=str(py_file))
            except SyntaxError as e:
                violations.append(f"Syntax error parsing {py_file}: {e}")
                continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod_root = alias.name.split(".")[0]
                    if mod_root in FORBIDDEN_NETWORK_MODULES:
                        violations.append(
                            f"{rel_path}:{node.lineno} imports forbidden module '{alias.name}'"
                        )
                    if mod_root == "httpx" and rel_path != ALLOWED_HTTPX_PATH:
                        violations.append(
                            f"{rel_path}:{node.lineno} imports 'httpx' outside SafeHttpClient"
                        )
            elif isinstance(node, ast.ImportFrom) and node.module:
                mod_root = node.module.split(".")[0]
                if mod_root in FORBIDDEN_NETWORK_MODULES:
                    violations.append(
                        f"{rel_path}:{node.lineno} imports from forbidden module '{node.module}'"
                    )
                if mod_root == "httpx" and rel_path != ALLOWED_HTTPX_PATH:
                    violations.append(
                        f"{rel_path}:{node.lineno} imports 'httpx' outside SafeHttpClient"
                    )

    assert not violations, "Egress safety invariant breached:\n" + "\n".join(violations)


def test_ground_truth_never_imported_in_agents() -> None:
    """Verify that agent code never imports lab/ground_truth."""
    agents_dir = Path("backend/agents")
    if not agents_dir.is_dir():
        return

    violations: list[str] = []
    for py_file in agents_dir.rglob("*.py"):
        rel_path = py_file.relative_to(Path("."))
        with open(py_file, encoding="utf-8") as f:
            try:
                tree = ast.parse(f.read(), filename=str(py_file))
            except SyntaxError as e:
                violations.append(f"Syntax error parsing {py_file}: {e}")
                continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "ground_truth" in alias.name:
                        violations.append(
                            f"{rel_path}:{node.lineno} directly imports ground truth: '{alias.name}'"
                        )
            elif isinstance(node, ast.ImportFrom) and node.module and "ground_truth" in node.module:
                violations.append(
                    f"{rel_path}:{node.lineno} imports from ground truth: '{node.module}'"
                )

    assert not violations, "Ground truth isolation breached:\n" + "\n".join(violations)


def test_scope_yaml_defaults() -> None:
    """Verify that scope.yaml strictly restricts targets by default to localhost / 127.0.0.1."""
    scope_file = Path("scope.yaml")
    assert scope_file.exists(), "scope.yaml must exist in root"

    with open(scope_file, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "allowed_targets" in data, "scope.yaml must specify allowed_targets"
    allowed = data["allowed_targets"]
    assert len(allowed) > 0, "scope.yaml must list allowed targets"

    for target in allowed:
        host = target.get("host")
        assert host in {"127.0.0.1", "localhost"}, (
            f"Default target '{host}' in scope.yaml must only be localhost/127.0.0.1"
        )
