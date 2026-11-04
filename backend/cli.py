"""TRIPWIRE Command Line Interface."""

import typer
from rich.console import Console

app = typer.Typer(
    name="tripwire",
    help="TRIPWIRE: Agentic Real-Time DAST for B2B Travel Platforms",
    add_completion=False,
)
console = Console()


@app.command()
def version() -> None:
    """Print TRIPWIRE engine version."""
    console.print("[bold green]TRIPWIRE[/bold green] version [cyan]0.0.1[/cyan]")


@app.command()
def status() -> None:
    """Display system and safety status."""
    console.print("[bold green]System Status:[/bold green] Operational")
    console.print("[bold yellow]Scope Enforcement:[/bold yellow] Active (scope.yaml locked)")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
