"""Change Detection Agent watching Deploys, JS Bundle Hashes, and Traffic Diffs."""

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class ChangeEvent:
    event_id: str
    change_type: str  # "DEPLOY_WEBHOOK", "JS_BUNDLE_DIFF", "TRAFFIC_DIFF", "DNS_CHANGE"
    target_service: str
    impacted_endpoints: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


class ChangeDetector:
    """Detects platform changes and emits ChangeEvents to trigger autonomous recon and attack planning."""

    def __init__(self) -> None:
        self._cached_bundle_hashes: dict[str, str] = {}
        self._seen_traffic_routes: set[str] = set()

    def handle_deploy_webhook(self, payload: dict[str, Any]) -> ChangeEvent:
        """Process incoming CI/CD deploy event."""
        event_id = f"evt_{uuid.uuid4().hex[:10]}"
        service = payload.get("service", "travel-platform")
        endpoints = payload.get("changed_endpoints", [])
        version = payload.get("version", "unknown")

        return ChangeEvent(
            event_id=event_id,
            change_type="DEPLOY_WEBHOOK",
            target_service=service,
            impacted_endpoints=endpoints,
            metadata={"version": version, "commit": payload.get("commit")},
        )

    def check_bundle_diff(self, bundle_url: str, bundle_content: str) -> ChangeEvent | None:
        """Check if client JS bundle hash has changed since last inspection."""
        current_hash = hashlib.sha256(bundle_content.encode("utf-8")).hexdigest()
        prev_hash = self._cached_bundle_hashes.get(bundle_url)

        self._cached_bundle_hashes[bundle_url] = current_hash

        if prev_hash is not None and prev_hash != current_hash:
            event_id = f"evt_{uuid.uuid4().hex[:10]}"
            return ChangeEvent(
                event_id=event_id,
                change_type="JS_BUNDLE_DIFF",
                target_service=bundle_url,
                metadata={
                    "previous_hash": prev_hash,
                    "current_hash": current_hash,
                },
            )
        return None

    def ingest_traffic_diff(self, log_path: Path | str) -> list[ChangeEvent]:
        """Parse traffic log file and emit ChangeEvent for any newly observed routes."""
        path = Path(log_path)
        if not path.exists():
            return []

        new_routes: list[str] = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                # Find HTTP request component e.g. "GET /path HTTP/1.1"
                for i, part in enumerate(parts):
                    if (
                        part.startswith('"')
                        and part.strip('"')
                        in {
                            "GET",
                            "POST",
                            "PUT",
                            "DELETE",
                            "PATCH",
                        }
                        and i + 1 < len(parts)
                    ):
                        method = part.strip('"')
                        url_path = parts[i + 1].split("?")[0]
                        endpoint_key = f"{method} {url_path}"
                        if endpoint_key not in self._seen_traffic_routes:
                            self._seen_traffic_routes.add(endpoint_key)
                            new_routes.append(endpoint_key)

        if new_routes:
            event = ChangeEvent(
                event_id=f"evt_{uuid.uuid4().hex[:10]}",
                change_type="TRAFFIC_DIFF",
                target_service="gateway_traffic",
                impacted_endpoints=new_routes,
                metadata={"new_route_count": len(new_routes)},
            )
            return [event]
        return []
