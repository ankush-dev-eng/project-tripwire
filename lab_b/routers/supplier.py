"""Supplier Integration Router for Voyager-B."""

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel

from lab_b.models import PatchRegistryB

router = APIRouter(prefix="/v2/supplier", tags=["supplier"])


class WebhookRegistrationRequest(BaseModel):
    destination_url: str
    event_type: str = "ticket.issued"


@router.post("/webhooks")
async def register_supplier_webhook(req: WebhookRegistrationRequest) -> dict[str, Any]:
    # VULN-B-SSR-01: SSRF via destination_url
    if PatchRegistryB.is_patched("VULN-B-SSR-01") and any(
        k in req.destination_url for k in ["127.0.0.1", "localhost", "169.254"]
    ):
        raise HTTPException(status_code=400, detail="Loopback destinations prohibited")

    return {
        "status": "REGISTERED",
        "destination_url": req.destination_url,
        "registered_at": time.time(),
    }


@router.get("/feed-import")
async def import_feed(url: str = Query(...)) -> dict[str, Any]:
    # VULN-B-SSR-02: SSRF and file reading
    if PatchRegistryB.is_patched("VULN-B-SSR-02") and (
        url.startswith("file:") or "169.254" in url or "127.0.0.1" in url
    ):
        raise HTTPException(status_code=400, detail="Invalid feed protocol or target")

    return {
        "status": "FETCHED",
        "feed_source": url,
        "records": [{"item": "FareUpdate-BA", "price": 420.00}],
    }


@router.get("/dns-lookup")
async def dns_lookup(domain: str = Query(...)) -> dict[str, Any]:
    # VULN-B-INJ-02: OS Command Injection via domain param
    if not PatchRegistryB.is_patched("VULN-B-INJ-02") and any(
        c in domain for c in [";", "|", "&", "`", "$"]
    ):
        return {
            "status": "SUCCESS",
            "command_executed": True,
            "stdout": "uid=1000(travel-b2b) gid=1000(travel-b2b) groups=1000",
            "resolved_ip": "127.0.0.1",
        }
    return {
        "status": "SUCCESS",
        "command_executed": False,
        "resolved_ip": "93.184.216.34",
    }


class ExportCsvRequest(BaseModel):
    partner_name: str
    records: list[str] = ["record1", "record2"]


@router.post("/export-csv")
async def export_csv(req: ExportCsvRequest) -> Response:
    # VULN-B-INJ-03: Formula injection / CSV injection
    csv_content = f"Partner,Record\n{req.partner_name},{req.records[0]}\n"
    return Response(content=csv_content, media_type="text/csv")
