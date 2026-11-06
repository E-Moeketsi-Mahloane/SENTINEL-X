# SENTINEL-X

SENTINEL-X is a defensive cybersecurity project focused on explainable detection and Linux hardening assessment. The project is intentionally scoped to provide a working baseline first: a deterministic rule engine, synthetic security event ingestion, and a clear set of milestones for future expansion.

## Problem statement

Security teams need practical evidence before making decisions. This project demonstrates how to collect suspicious network and authentication activity, explain why a rule fired, and preserve the supporting evidence needed for investigation and reporting.

## Architecture proposal

The initial architecture keeps the first milestone small and maintainable:

```text
SENTINEL-X
├── README.md
├── main.py
├── data/
│   └── sample_security_events.jsonl
├── sentinel_x/
│   ├── __init__.py
│   ├── config.py
│   ├── models.py
│   ├── detection/
│   │   ├── __init__.py
│   │   └── rules.py
│   └── storage/
│       └── __init__.py
└── tests/
    └── test_detection.py
```

### Design choices

- Deterministic rule engine first: no ML or opaque scoring model.
- Explainable alerts: each alert shows the rule, source IP, event count, and evidence.
- Synthetic lab data only: the event samples are clearly labelled as test data.
- Linux-safe by default: no automatic blocking or firewall changes in the prototype.

## Risk assessment

- Security risk: Low in the prototype, because the code is read-only and does not modify systems.
- Operational risk: Medium if event data is malformed, but the project handles malformed input by skipping invalid records.
- Detection risk: Medium, because rule thresholds are configurable but not yet tuned against a real labelled dataset.
- Privacy risk: Low, because the prototype only stores source IP, usernames, and timestamps from synthetic data.

## Milestone plan

### Milestone 0 — environment and design
- Confirm workspace state and Python version.
- Define a minimal architecture and risk posture.
- Document the initial plan.

### Milestone 1 — working detection prototype
- Load synthetic JSONL event data.
- Detect repeated failed authentication attempts using a threshold and a time window.
- Emit a structured, explainable alert.
- Add tests that confirm the alert triggers for suspicious behaviour and stays quiet for normal activity.

### Milestone 2 onward
- Add more detection rules, SQLite persistence, and audit logic.
- Introduce incident correlation and linux security auditing.
- Add dashboard/reporting features only after the rule engine is stable.

## Quick start

CLI detection prototype:

```bash
cd "C:\Users\maxfi\Desktop\Networking&CyberSecurity"
python main.py data/sample_security_events.jsonl
pytest -q
```

The CLI also accepts `--threshold` and `--window-seconds`; both must be positive integers.

Flet graphical interface:

```bash
cd "C:\Users\maxfi\Desktop\Networking&CyberSecurity"
python gui.py
```

The GUI runs the same detection logic and provides a dark dashboard with overview metrics, explainable alert cards, a searchable event log, and a manual detection refresh. It reads the bundled JSONL sample by default. Malformed lines are skipped and counted; file read errors are displayed in the interface. The dashboard is read-only and does not block or modify traffic.

## Security boundaries

This project is intentionally constrained to read-only detection and analysis. It does not automatically block traffic, change system state, or modify firewall policies.
