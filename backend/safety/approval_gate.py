"""Human-in-the-Loop Approval Gate for Guarded & State-Changing Probes."""

from fnmatch import fnmatch
from pathlib import Path
import time
from typing import Any
from urllib.parse import urlparse
import uuid
import yaml


class ApprovalRequiredError(Exception):
    """Raised when an agent attempts a state-changing or guarded probe without human authorization."""

    def __init__(self, action_type: str, path: str, request_id: str):
        super().__init__(
            f"Action requires explicit human approval token: type='{action_type}', path='{path}', approval_request_id='{request_id}'"
        )
        self.action_type = action_type
        self.path = path
        self.request_id = request_id


class ApprovalGate:
    """Evaluates whether an outbound probe requires human operator sign-off."""

    def __init__(self, policy_path: Path | str = "config/approval_policy.yaml") -> None:
        self.policy_path = Path(policy_path)
        self._policy: dict[str, Any] = {}
        self._pending_approvals: dict[str, dict[str, Any]] = {}
        self._approved_tokens: dict[str, dict[str, Any]] = {}
        self._load_policy()

    def _load_policy(self) -> None:
        if self.policy_path.exists():
            with open(self.policy_path, encoding="utf-8") as f:
                self._policy = yaml.safe_load(f) or {}
        self._guarded_actions = self._policy.get("guarded_actions", [])
        self._mode = self._policy.get("mode", "strict")

    def check_approval(
        self,
        method: str,
        url: str,
        approval_token: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Verify if action is permitted or if an approval token is mandatory."""
        parsed = urlparse(url)
        path = parsed.path
        method_upper = method.upper()

        # Check against guarded actions
        for rule in self._guarded_actions:
            matches_method = True
            if "methods" in rule:
                matches_method = method_upper in [m.upper() for m in rule["methods"]]

            matches_path = False
            for pattern in rule.get("path_patterns", []):
                if fnmatch(path, pattern) or fnmatch(path.lstrip("/"), pattern):
                    matches_path = True
                    break

            if matches_method and matches_path:
                action_type = rule.get("action_type", "state_change")
                desc = rule.get("description", "State-changing operation")

                # Validate approval token if supplied
                if approval_token and self._validate_token(approval_token, path, method_upper):
                    # Valid token consumed
                    return

                # Token missing or invalid -> register pending request and raise
                req_id = str(uuid.uuid4())
                self._pending_approvals[req_id] = {
                    "id": req_id,
                    "method": method_upper,
                    "url": url,
                    "path": path,
                    "action_type": action_type,
                    "description": desc,
                    "context": context or {},
                    "requested_at": time.time(),
                    "status": "PENDING",
                }
                raise ApprovalRequiredError(action_type, path, req_id)

    def _validate_token(self, token: str, path: str, method: str) -> bool:
        """Validate that token was issued by human operator for this target."""
        if token not in self._approved_tokens:
            return False
        meta = self._approved_tokens[token]
        if meta.get("path") != path or meta.get("method") != method:
            return False
        if time.time() > meta.get("expires_at", 0):
            return False
        return True

    def approve_request(
        self,
        request_id: str,
        operator_id: str = "human_operator",
        validity_seconds: int = 300,
    ) -> str:
        """Operator approves a pending request and receives an authorization token."""
        if request_id not in self._pending_approvals:
            raise KeyError(f"Approval request {request_id} not found")

        req = self._pending_approvals.pop(request_id)
        token = f"tok_{uuid.uuid4().hex}"
        self._approved_tokens[token] = {
            "token": token,
            "path": req["path"],
            "method": req["method"],
            "operator_id": operator_id,
            "approved_at": time.time(),
            "expires_at": time.time() + validity_seconds,
        }
        return token

    def get_pending_approvals(self) -> list[dict[str, Any]]:
        """List all requests currently awaiting human sign-off."""
        return list(self._pending_approvals.values())
