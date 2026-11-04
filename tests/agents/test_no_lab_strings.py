"""Honesty test enforcing that agent code contains NO hardcoded lab-specific strings."""

from pathlib import Path

FORBIDDEN_LAB_STRINGS = [
    "BKG-ALPHA-001",
    "BKG-BETA-001",
    "AGY_ALPHA",
    "AGY_BETA",
    "Alpha Global Travel",
    "Beta Express Journeys",
    "FL-101",
    "FL-202",
    "FL-303",
    "VOYAGER50",
    "Lord Sterling",
    "Kenji Sato",
]


def test_no_hardcoded_lab_strings_in_agents() -> None:
    """Agents must operate on generalized discovery, never hardcoded lab IDs or names."""
    agents_dir = Path("backend/agents")
    assert agents_dir.is_dir()

    violations: list[str] = []

    for py_file in agents_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for forbidden in FORBIDDEN_LAB_STRINGS:
            if forbidden in content:
                violations.append(f"{py_file.name} contains forbidden lab string '{forbidden}'")

    assert not violations, "Anti-overfitting honesty check failed:\n" + "\n".join(violations)
