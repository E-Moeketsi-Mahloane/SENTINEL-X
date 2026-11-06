from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from sentinel_x.models import SecurityEvent


class RepeatedFailedAuthenticationRule:
    """Detect repeated failed authentication attempts from the same source."""

    def __init__(self, threshold: int = 3, window_seconds: int = 600):
        if type(threshold) is not int or threshold < 1:
            raise ValueError("threshold must be a positive integer")
        if type(window_seconds) is not int or window_seconds < 1:
            raise ValueError("window_seconds must be a positive integer")
        self.threshold = threshold
        self.window_seconds = window_seconds

    def evaluate(self, events: Iterable[SecurityEvent]) -> list[dict]:
        grouped: dict[str, list[SecurityEvent]] = defaultdict(list)

        for event in events:
            if event.event_type == "auth_failed" and event.source_ip:
                grouped[event.source_ip].append(event)

        alerts: list[dict] = []
        for source_ip, source_events in grouped.items():
            ordered_events = sorted(source_events, key=lambda event: event.timestamp)
            for index, current_event in enumerate(ordered_events):
                window_end = current_event.timestamp + timedelta(seconds=self.window_seconds)
                window_events = [
                    item for item in ordered_events[index:]
                    if item.timestamp <= window_end
                ]

                if len(window_events) >= self.threshold:
                    evidence = [
                        {
                            "timestamp": event.timestamp.isoformat(),
                            "username": event.username,
                            "source_ip": event.source_ip,
                        }
                        for event in window_events
                    ]
                    alerts.append(
                        {
                            "rule_id": "AUTH-FAIL-REPEATED",
                            "rule_name": "Repeated failed authentication",
                            "severity": "high",
                            "summary": (
                                f"{len(window_events)} failed authentication attempts from {source_ip} "
                                f"within {self.window_seconds} seconds."
                            ),
                            "source_ip": source_ip,
                            "count": len(window_events),
                            "window_seconds": self.window_seconds,
                            "threshold": self.threshold,
                            "evidence": evidence,
                            "recommended_investigation": [
                                "Review the source IP against recent remote access logs.",
                                "Check whether the attempted usernames match a known brute-force pattern.",
                                "Validate whether the target service is exposed to unauthorised access.",
                            ],
                            "recommended_remediation": [
                                "Verify the affected service and monitor for additional login attempts.",
                                "Consider rate limiting or blocking only after explicit authorisation and policy approval.",
                            ],
                        }
                    )
                    break

        return alerts
