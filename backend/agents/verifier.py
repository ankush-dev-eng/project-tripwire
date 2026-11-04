"""Double-Proof Verification Engine for TRIPWIRE.

Enforces Section 5.3: Zero false-positive mandate via two-sided confirmation:
1. Proof 1 (Primary exploit): Primary payload succeeds and triggers an anomaly or unauthorized state change.
2. Proof 2 (Negative control / counter-factual): A control request with inverted/legitimate params
   behaves as expected (denied with 403/404, or invariant holds), confirming the behavior is an actual
   vulnerability and not an open route or static responder.
"""

from typing import Any

from backend.agents.models import DoubleProof


class DoubleProofVerifier:
    """Verifies potential findings through counter-factual negative control requests."""

    @staticmethod
    def build_curl(
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        params: dict[str, Any] | None = None,
    ) -> str:
        """Generate a clean, copy-pasteable reproduction curl command."""
        parts = [f"curl -s -X {method.upper()}"]

        # Append query params if present
        target_url = url
        if params:
            import urllib.parse

            query_str = urllib.parse.urlencode(params)
            target_url = f"{url}?{query_str}" if "?" not in url else f"{url}&{query_str}"

        parts.append(f'"{target_url}"')

        if headers:
            for k, v in headers.items():
                # Redact sensitive bearer tokens for reproduction safety
                val = v
                if k.lower() == "authorization" and "bearer" in v.lower():
                    val = "Bearer <TOKEN_REDACTED>"
                parts.append(f"-H '{k}: {val}'")

        if json_body is not None:
            import json

            body_str = json.dumps(json_body) if not isinstance(json_body, str) else json_body
            # Escape single quotes for bash/sh curl commands
            escaped_body = body_str.replace("'", "'\\''")
            parts.append("-H 'Content-Type: application/json'")
            parts.append(f"-d '{escaped_body}'")

        return " ".join(parts)

    @classmethod
    def verify(
        cls,
        primary_req: dict[str, Any],
        primary_resp: Any,
        primary_succeeded: bool,
        control_req: dict[str, Any],
        control_resp: Any,
        control_succeeded: bool,
        notes: str = "",
    ) -> DoubleProof:
        """Assemble and validate a DoubleProof object."""
        curl_cmd = cls.build_curl(
            method=primary_req.get("method", "GET"),
            url=primary_req.get("url", ""),
            headers=primary_req.get("headers"),
            json_body=primary_req.get("json"),
            params=primary_req.get("params"),
        )

        # Primary response preview
        try:
            p_body_preview = primary_resp.text[:500] if primary_resp.text else ""
        except Exception:
            p_body_preview = "<binary or empty>"

        # Control response preview
        try:
            c_body_preview = control_resp.text[:500] if control_resp.text else ""
        except Exception:
            c_body_preview = "<binary or empty>"

        confidence = 1.0 if (primary_succeeded and control_succeeded) else 0.0

        return DoubleProof(
            primary_payload=primary_req.get("json") or primary_req.get("params") or {},
            primary_request={
                "method": primary_req.get("method", "GET"),
                "url": primary_req.get("url", ""),
                "headers": {
                    k: (v if k.lower() != "authorization" else "REDACTED")
                    for k, v in (primary_req.get("headers") or {}).items()
                },
                "body": primary_req.get("json"),
            },
            primary_response={
                "status_code": primary_resp.status_code,
                "body_preview": p_body_preview,
            },
            primary_succeeded=primary_succeeded,
            negative_control_payload=control_req.get("json") or control_req.get("params") or {},
            negative_control_request={
                "method": control_req.get("method", "GET"),
                "url": control_req.get("url", ""),
                "headers": {
                    k: (v if k.lower() != "authorization" else "REDACTED")
                    for k, v in (control_req.get("headers") or {}).items()
                },
                "body": control_req.get("json"),
            },
            negative_control_response={
                "status_code": control_resp.status_code,
                "body_preview": c_body_preview,
            },
            negative_control_succeeded=control_succeeded,
            reproduction_curl=curl_cmd,
            confidence_score=confidence,
            evidence_notes=notes,
        )
