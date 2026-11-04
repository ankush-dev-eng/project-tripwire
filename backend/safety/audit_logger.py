"""Append-only, SHA-256 hash-chained audit logger with replay verification."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import threading
from typing import Any

from backend.safety.redactor import redact_data, redact_text

GENESIS_HASH = "0" * 64


class AuditChainCorruptedError(Exception):
    """Raised when the cryptographic audit chain verification fails."""


class AuditLogger:
    """Thread-safe append-only audit logger maintaining a cryptographic SHA-256 hash chain."""

    def __init__(self, log_path: Path | str = "data/audit.jsonl") -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._sequence = 0
        self._last_hash = GENESIS_HASH
        self._init_state_from_log()

    def _init_state_from_log(self) -> None:
        """Read existing log file to synchronize sequence counter and last hash."""
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return

        with open(self.log_path, "r", encoding="utf-8") as f:
            last_line = ""
            count = 0
            for line in f:
                if line.strip():
                    last_line = line
                    count += 1
            if last_line:
                try:
                    data = json.loads(last_line)
                    self._sequence = data.get("sequence", 0) + 1
                    self._last_hash = data.get("entry_hash", GENESIS_HASH)
                except json.JSONDecodeError:
                    pass

    @staticmethod
    def _compute_entry_hash(
        sequence: int,
        timestamp: str,
        request_data: dict[str, Any],
        response_data: dict[str, Any],
        prev_hash: str,
    ) -> str:
        payload = {
            "sequence": sequence,
            "timestamp": timestamp,
            "request": request_data,
            "response": response_data,
            "prev_hash": prev_hash,
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def log_interaction(
        self,
        method: str,
        url: str,
        request_headers: dict[str, str],
        request_body: Any,
        status_code: int,
        response_headers: dict[str, str],
        response_body: Any,
        latency_ms: float,
    ) -> dict[str, Any]:
        """Record an outbound HTTP transaction into the hash-chained audit log."""
        with self._lock:
            timestamp = datetime.now(timezone.utc).isoformat()

            # Sanitize request and response data
            safe_req_headers = redact_data(dict(request_headers))
            safe_req_body = redact_data(request_body) if request_body is not None else None
            safe_res_headers = redact_data(dict(response_headers))
            safe_res_body = (
                redact_text(response_body)
                if isinstance(response_body, str)
                else redact_data(response_body)
            )

            req_payload = {
                "method": method.upper(),
                "url": url,
                "headers": safe_req_headers,
                "body": safe_req_body,
            }
            res_payload = {
                "status_code": status_code,
                "headers": safe_res_headers,
                "body": safe_res_body,
                "latency_ms": round(latency_ms, 2),
            }

            current_seq = self._sequence
            current_prev_hash = self._last_hash

            entry_hash = self._compute_entry_hash(
                sequence=current_seq,
                timestamp=timestamp,
                request_data=req_payload,
                response_data=res_payload,
                prev_hash=current_prev_hash,
            )

            entry = {
                "sequence": current_seq,
                "timestamp": timestamp,
                "request": req_payload,
                "response": res_payload,
                "prev_hash": current_prev_hash,
                "entry_hash": entry_hash,
            }

            # Write line atomically
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

            self._sequence += 1
            self._last_hash = entry_hash
            return entry

    @staticmethod
    def verify_chain(log_path: Path | str) -> tuple[bool, str, int]:
        """Verify the cryptographic integrity of the entire audit log."""
        path = Path(log_path)
        if not path.exists():
            return True, "Log file does not exist (empty chain valid)", 0

        expected_prev_hash = GENESIS_HASH
        expected_seq = 0

        with open(path, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                raw_line = raw_line.strip()
                if not raw_line:
                    continue

                try:
                    entry = json.loads(raw_line)
                except json.JSONDecodeError as e:
                    return False, f"JSON parse error at line {line_no}: {e}", line_no

                seq = entry.get("sequence")
                timestamp = entry.get("timestamp")
                req_data = entry.get("request")
                res_data = entry.get("response")
                prev_hash = entry.get("prev_hash")
                entry_hash = entry.get("entry_hash")

                if seq != expected_seq:
                    return (
                        False,
                        f"Sequence mismatch at line {line_no}: expected {expected_seq}, got {seq}",
                        line_no,
                    )

                if prev_hash != expected_prev_hash:
                    return (
                        False,
                        f"Hash chain broken at line {line_no}: expected prev_hash {expected_prev_hash}, got {prev_hash}",
                        line_no,
                    )

                # Recompute hash
                recomputed = AuditLogger._compute_entry_hash(
                    sequence=seq,
                    timestamp=timestamp,
                    request_data=req_data,
                    response_data=res_data,
                    prev_hash=prev_hash,
                )

                if recomputed != entry_hash:
                    return (
                        False,
                        f"Entry hash mismatch at line {line_no}: computed {recomputed}, logged {entry_hash}",
                        line_no,
                    )

                expected_prev_hash = entry_hash
                expected_seq += 1

        return True, "Chain verified valid", expected_seq
