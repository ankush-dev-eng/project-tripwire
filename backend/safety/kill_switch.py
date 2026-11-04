"""Thread-safe and process-aware global kill switch."""

import contextlib
import os
import threading
from pathlib import Path


class KillSwitchTrippedError(Exception):
    """Raised when an operation is attempted while the global kill switch is active."""

    def __init__(self, reason: str = "Kill switch tripped by safety controller"):
        super().__init__(reason)
        self.reason = reason


class KillSwitch:
    """Global atomic kill switch for TRIPWIRE operations."""

    _instance: "KillSwitch | None" = None
    _lock = threading.Lock()

    def __init__(self, trigger_file: Path | str = ".tripwire_kill") -> None:
        self.trigger_file = Path(trigger_file)
        self._tripped: bool = False
        self._trip_reason: str | None = None
        self._thread_lock = threading.Lock()

    @classmethod
    def get_instance(cls, trigger_file: Path | str = ".tripwire_kill") -> "KillSwitch":
        """Get or initialize singleton KillSwitch instance."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(trigger_file)
            return cls._instance

    def trip(self, reason: str) -> None:
        """Trip the kill switch immediately, pausing all agents and network egress."""
        with self._thread_lock:
            self._tripped = True
            self._trip_reason = reason
            with contextlib.suppress(OSError):
                self.trigger_file.write_text(reason, encoding="utf-8")

    def reset(self) -> None:
        """Reset the kill switch to normal operational state."""
        with self._thread_lock:
            self._tripped = False
            self._trip_reason = None
            if self.trigger_file.exists():
                with contextlib.suppress(OSError):
                    os.remove(self.trigger_file)

    def is_tripped(self) -> bool:
        """Check if the kill switch is currently active (in-memory or on disk)."""
        if self._tripped:
            return True
        if self.trigger_file.exists():
            try:
                content = self.trigger_file.read_text(encoding="utf-8").strip()
                self._trip_reason = content or "Kill switch file triggered on disk"
                self._tripped = True
                return True
            except OSError:
                return True
        return False

    def get_trip_reason(self) -> str | None:
        """Retrieve the reason why the kill switch was tripped."""
        self.is_tripped()
        return self._trip_reason

    def check_or_raise(self) -> None:
        """Check if tripped and raise KillSwitchTrippedError if active."""
        if self.is_tripped():
            reason = self._trip_reason or "Kill switch is active"
            raise KillSwitchTrippedError(f"Operation halted: {reason}")

    # Aliases for API ergonomic compatibility
    is_active = is_tripped
    trigger = trip
