"""Scope Allowlist and Target Boundary Manager."""

import hashlib
import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from backend.safety.kill_switch import KillSwitch


class OutOfScopeError(Exception):
    """Raised when an outbound request attempts to target an unauthorized host/port."""

    def __init__(self, url: str, reason: str):
        super().__init__(f"Out-of-scope target blocked: {url} ({reason})")
        self.url = url
        self.reason = reason


class ScopeTamperingError(Exception):
    """Raised when scope.yaml has been modified or corrupted at runtime."""


class ScopeManager:
    """Enforces target allowlist rules defined in scope.yaml."""

    def __init__(
        self,
        scope_path: Path | str = "scope.yaml",
        kill_switch: KillSwitch | None = None,
    ) -> None:
        self.scope_path = Path(scope_path)
        self.kill_switch = kill_switch
        self._initial_hash: str = ""
        self._config: dict[str, Any] = {}
        self._allowed_targets: list[dict[str, Any]] = []
        self._blocked_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.reload()

    @property
    def config(self) -> dict[str, Any]:
        """Return raw parsed scope configuration dictionary."""
        return dict(self._config)

    @property
    def allowed_targets(self) -> list[dict[str, Any]]:
        """Return list of allowed target specifications."""
        return list(self._allowed_targets)

    def _calculate_file_hash(self) -> str:
        """Compute SHA-256 hash of scope.yaml."""
        if not self.scope_path.exists():
            raise FileNotFoundError(f"Scope file not found: {self.scope_path}")
        content = self.scope_path.read_bytes()
        return hashlib.sha256(content).hexdigest()

    def verify_file_integrity(self) -> bool:
        """Verify that scope.yaml has not been altered since initialization."""
        current_hash = self._calculate_file_hash()
        if current_hash != self._initial_hash:
            msg = f"Scope configuration tampering detected in {self.scope_path}"
            if self.kill_switch:
                self.kill_switch.trip(msg)
            raise ScopeTamperingError(msg)
        return True

    def reload(self) -> None:
        """Load and parse scope.yaml configuration."""
        if not self.scope_path.exists():
            raise FileNotFoundError(f"Scope configuration missing at {self.scope_path}")

        self._initial_hash = self._calculate_file_hash()
        with open(self.scope_path, encoding="utf-8") as f:
            self._config = yaml.safe_load(f) or {}

        self._allowed_targets = self._config.get("allowed_targets", [])

        # Parse blocked CIDRs
        self._blocked_networks = []
        for cidr in self._config.get("blocked_cidrs", []):
            try:
                self._blocked_networks.append(ipaddress.ip_network(cidr))
            except ValueError:
                continue

    def is_in_scope(self, url: str) -> tuple[bool, str]:
        """Determine whether a given URL is strictly within the allowed target scope."""
        self.verify_file_integrity()

        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Malformed URL: {e}"

        if not parsed.scheme or parsed.scheme not in {"http", "https"}:
            return False, f"Unsupported or missing protocol scheme: {parsed.scheme}"

        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname in target URL"

        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80

        # Check for direct IP address targeting against blocked CIDRs
        try:
            ip_obj = ipaddress.ip_address(hostname)
            # Cloud metadata protection (169.254.169.254 etc.)
            for blocked_net in self._blocked_networks:
                # If target is explicitly in allowed_targets, check ports
                is_explicit_allow = any(
                    tgt.get("host") == hostname and port in tgt.get("ports", [])
                    for tgt in self._allowed_targets
                )
                if ip_obj in blocked_net and not is_explicit_allow:
                    return False, f"IP {hostname} is in blocked network range {blocked_net}"
        except ValueError:
            # Hostname is a domain/alias, not an IP literal
            pass

        # Check against allowed_targets
        match_found = False
        for target in self._allowed_targets:
            target_host = target.get("host")
            target_ports = target.get("ports", [])
            target_protocol = target.get("protocol")

            if target_host in {hostname, hostname.lower()}:
                if target_protocol and parsed.scheme != target_protocol:
                    continue
                if port in target_ports:
                    match_found = True
                    break

        if not match_found:
            return False, f"Host {hostname}:{port} not in approved allowed_targets list"

        return True, "In scope"

    def check_url_or_raise(self, url: str) -> None:
        """Validate URL and raise OutOfScopeError and trip kill switch if out of scope."""
        in_scope, reason = self.is_in_scope(url)
        if not in_scope:
            if self.kill_switch:
                self.kill_switch.trip(f"Out of scope request attempt to: {url} ({reason})")
            raise OutOfScopeError(url, reason)
