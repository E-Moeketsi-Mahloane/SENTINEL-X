from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: datetime
    event_type: str
    source_ip: str | None = None
    username: str | None = None
    destination: str | None = None
    success: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SecurityEvent":
        timestamp_value = payload.get("timestamp")
        if isinstance(timestamp_value, str):
            timestamp = datetime.fromisoformat(timestamp_value)
        else:
            raise ValueError(f"Missing or invalid timestamp field: {timestamp_value!r}")

        event_type = str(payload.get("event_type", "unknown")).strip()
        return cls(
            timestamp=timestamp,
            event_type=event_type,
            source_ip=payload.get("source_ip"),
            username=payload.get("username"),
            destination=payload.get("destination"),
            success=bool(payload.get("success", False)),
            raw=payload,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "username": self.username,
            "destination": self.destination,
            "success": self.success,
        }
