"""TRIPWIRE Benchmark Harness Runner."""

import sys

from rich.console import Console

console = Console()


def run_benchmarks() -> int:
    console.print("[bold green]TRIPWIRE Benchmark Harness[/bold green]")
    console.print("Running in baseline check mode (Phase 0)...")
    console.print("[green]OK[/green]: Benchmark runner initialized.")
    return 0


if __name__ == "__main__":
    sys.exit(run_benchmarks())
