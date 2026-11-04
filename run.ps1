# TRIPWIRE Windows Build & Task Runner
param (
    [Parameter(Position=0)]
    [string]$Task = "test"
)

$ErrorActionPreference = "Stop"

switch ($Task) {
    "install" {
        Write-Host "Installing dependencies..." -ForegroundColor Cyan
        python -m pip install --upgrade pip
        python -m pip install -r requirements-dev.txt
    }
    "test" {
        Write-Host "Running pytest suite..." -ForegroundColor Cyan
        python -m pytest tests/ -v
    }
    "coverage" {
        Write-Host "Running pytest with coverage..." -ForegroundColor Cyan
        python -m pytest tests/ --cov=backend --cov=lab --cov-report=term-missing
    }
    "lint" {
        Write-Host "Running ruff check..." -ForegroundColor Cyan
        python -m ruff check .
        python -m ruff format --check .
    }
    "format" {
        Write-Host "Applying ruff format and fixes..." -ForegroundColor Cyan
        python -m ruff format .
        python -m ruff check --fix .
    }
    "benchmark" {
        Write-Host "Executing benchmark suite..." -ForegroundColor Cyan
        python -m benchmarks.run_all
    }
    default {
        Write-Host "Unknown task: $Task. Available: install, test, coverage, lint, format, benchmark" -ForegroundColor Red
        exit 1
    }
}

