from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from sentinel_x.config import DEFAULT_DETECTION_CONFIG
from sentinel_x.detection.rules import RepeatedFailedAuthenticationRule
from sentinel_x.models import SecurityEvent

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def load_events(path: str | Path) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    for line_number, raw_line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            payload = json.loads(raw_line)
            if not isinstance(payload, dict):
                raise TypeError("JSON event must be an object")
            events.append(SecurityEvent.from_dict(payload))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            logging.warning("Skipping malformed event at line %s: %s", line_number, exc)
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the SENTINEL-X detection prototype.")
    parser.add_argument("events_path", nargs="?", default="data/sample_security_events.jsonl")
    parser.add_argument("--threshold", type=positive_int, default=DEFAULT_DETECTION_CONFIG.failed_auth_threshold)
    parser.add_argument("--window-seconds", type=positive_int, default=DEFAULT_DETECTION_CONFIG.failed_auth_window_seconds)
    args = parser.parse_args()

    events = load_events(args.events_path)
    rule = RepeatedFailedAuthenticationRule(threshold=args.threshold, window_seconds=args.window_seconds)
    alerts = rule.evaluate(events)

    result = {
        "event_count": len(events),
        "alerts": alerts,
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
