"""Operational Diagnostics and Metrics Router for Voyager-B."""

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Response

from lab_b.models import PatchRegistryB

router = APIRouter(prefix="/v2/ops", tags=["ops"])


@router.get("/ping")
async def ping() -> dict[str, str]:
    return {"status": "ok", "service": "voyager-b"}


@router.get("/prometheus")
async def prometheus_metrics() -> Response:
    # VULN-B-HYG-01: Exposes database connection strings and secret tokens unauthenticated
    if PatchRegistryB.is_patched("VULN-B-HYG-01"):
        raise HTTPException(status_code=401, detail="Metrics authentication required")

    metrics_text = """# HELP travel_db_pool Active database connections
# TYPE travel_db_pool gauge
travel_db_pool{database_url="postgresql://apex_admin:SuperSecretApex2026@10.0.5.21:5432/apex_travel",jwt_secret="apex_hmac_secret_key_2026"} 14
# HELP http_requests_total Total HTTP requests
http_requests_total{status="200"} 8421
"""
    return Response(content=metrics_text, media_type="text/plain")


@router.get("/crash-report")
async def crash_report(trace: str | None = Query(None)) -> dict[str, Any]:
    # VULN-B-HYG-03: Stack trace & local variables exposure
    if trace and not PatchRegistryB.is_patched("VULN-B-HYG-03"):
        return {
            "error": "OperationalCrash",
            "traceback": (
                "Traceback (most recent call last):\n"
                '  File "voyager_b/engine.py", line 124, in process_settlement\n'
                "  local_vars: {'api_key': 'apex_live_sec_key_4412', 'session_id': 'sess_9981'}\n"
                "ZeroDivisionError: division by zero"
            ),
        }
    return {"status": "NO_CRASH_DATA"}
