from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import flet as ft

from sentinel_x.detection.rules import RepeatedFailedAuthenticationRule
from sentinel_x.models import SecurityEvent

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EVENTS_PATH = PROJECT_ROOT / "data" / "sample_security_events.jsonl"

BACKGROUND = "#0B1220"
SIDEBAR = "#111B2E"
PANEL = "#151F32"
PANEL_LIGHT = "#1B2940"
ACCENT = "#24D6C5"
TEXT = "#E8EEF8"
MUTED = "#93A4BC"
RED = "#FF647C"
GREEN = "#39D98A"
AMBER = "#F5BE55"


def load_events(path: str | Path) -> tuple[list[SecurityEvent], int]:
    events: list[SecurityEvent] = []
    malformed_count = 0
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        if not raw_line.strip():
            continue
        try:
            payload = json.loads(raw_line)
            if not isinstance(payload, dict):
                raise TypeError("JSON event must be an object")
            events.append(SecurityEvent.from_dict(payload))
        except (TypeError, ValueError, json.JSONDecodeError):
            malformed_count += 1
    return events, malformed_count


def run_detection(path: str | Path = DEFAULT_EVENTS_PATH) -> dict[str, Any]:
    events, malformed_count = load_events(path)
    rule = RepeatedFailedAuthenticationRule(threshold=3, window_seconds=600)
    alerts = rule.evaluate(events)
    return {
        "event_count": len(events),
        "malformed_count": malformed_count,
        "alerts": alerts,
        "events": [event.to_dict() for event in events],
        "source": str(path),
    }


def _panel(content: ft.Control, *, padding: int = 18) -> ft.Container:
    return ft.Container(
        content=content,
        bgcolor=PANEL,
        padding=padding,
        border_radius=12,
    )


def _metric_card(label: str, value: str, accent: str, hint: str) -> ft.Container:
    return _panel(
        ft.Column(
            controls=[
                ft.Text(label.upper(), size=11, color=MUTED, weight="bold"),
                ft.Text(value, size=28, color=accent, weight="bold"),
                ft.Text(hint, size=12, color=MUTED),
            ],
            spacing=6,
        )
    )


def main(page: ft.Page) -> None:
    page.title = "SENTINEL-X | Security Monitor"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = BACKGROUND
    page.padding = 0
    page.window_width = 1180
    page.window_height = 820
    page.window_min_width = 760
    page.window_min_height = 600

    snapshot: dict[str, Any] = {}
    active_view = "overview"
    query = ""
    content = ft.Column(spacing=16, expand=True)
    search_field = ft.TextField(
        hint_text="Filter by IP, username, or event type",
        on_change=lambda event: update_search(event.control.value),
        bgcolor=PANEL,
        color=TEXT,
        border_color=PANEL_LIGHT,
        expand=True,
    )

    def update_search(value: str | None) -> None:
        nonlocal query
        query = (value or "").strip().casefold()
        render()

    def filtered_events() -> list[dict[str, Any]]:
        events = snapshot.get("events", [])
        if not query:
            return events
        return [
            event for event in events
            if query in " ".join(str(value or "") for value in event.values()).casefold()
        ]

    def filtered_alerts() -> list[dict[str, Any]]:
        alerts = snapshot.get("alerts", [])
        if not query:
            return alerts
        return [
            alert for alert in alerts
            if query in " ".join(
                [
                    str(alert.get("rule_name", "")),
                    str(alert.get("source_ip", "")),
                    str(alert.get("summary", "")),
                    *(str(item.get("username", "")) for item in alert.get("evidence", [])),
                ]
            ).casefold()
        ]

    def show_view(view: str) -> None:
        nonlocal active_view
        active_view = view
        render()

    def nav_button(label: str, view: str) -> ft.Button:
        return ft.Button(
            content=label,
            on_click=lambda _: show_view(view),
            color=ACCENT if active_view == view else MUTED,
            bgcolor=PANEL_LIGHT if active_view == view else SIDEBAR,
        )

    def make_alert_card(alert: dict[str, Any]) -> ft.Container:
        evidence = [
            ft.Text(
                f"{item['timestamp']}   •   {item['username'] or 'unknown user'}   •   {item['source_ip']}",
                size=12,
                color=MUTED,
            )
            for item in alert["evidence"]
        ]
        return _panel(
            ft.Column(
                controls=[
                    ft.Row(
                        controls=[
                            ft.Text(alert["rule_name"], size=17, weight="bold", color=TEXT, expand=True),
                            ft.Text(alert["severity"].upper(), size=11, color=RED, weight="bold"),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    ft.Text(alert["summary"], color=MUTED),
                    ft.Text(
                        f"Rule {alert['rule_id']}  •  threshold {alert['threshold']} / {alert['window_seconds']} sec",
                        size=12,
                        color=ACCENT,
                    ),
                    ft.Text("Supporting evidence", size=12, weight="bold", color=TEXT),
                    *evidence,
                    ft.Text(
                        "Next step: review the source against authorised access logs; no blocking action was taken.",
                        size=12,
                        color=AMBER,
                    ),
                ],
                spacing=9,
            )
        )

    def render_overview() -> list[ft.Control]:
        alerts = filtered_alerts()
        events = filtered_events()
        high_count = sum(alert.get("severity") == "high" for alert in snapshot.get("alerts", []))
        cards = ft.Row(
            controls=[
                _metric_card("Events ingested", str(snapshot.get("event_count", 0)), ACCENT, "From the selected JSONL sample"),
                _metric_card("Active alerts", str(len(snapshot.get("alerts", []))), RED if high_count else GREEN, "Deterministic rule matches"),
                _metric_card("High severity", str(high_count), RED if high_count else GREEN, "Requires analyst review"),
            ],
            spacing=12,
            wrap=True,
        )
        alert_content: list[ft.Control]
        if alerts:
            alert_content = [make_alert_card(alert) for alert in alerts]
        else:
            alert_content = [
                _panel(
                    ft.Text(
                        "No matching alerts. Try clearing the filter or load events that match a configured rule.",
                        color=GREEN,
                    )
                )
            ]
        return [
            ft.Text("Overview", size=24, weight="bold", color=TEXT),
            ft.Text("Read-only analysis • explainable rules • synthetic sample data", size=13, color=MUTED),
            cards,
            ft.Row(
                controls=[
                    ft.Text("Detection findings", size=18, weight="bold", color=TEXT, expand=True),
                    ft.Text(f"Showing {len(alerts)} of {len(snapshot.get('alerts', []))}", size=12, color=MUTED),
                ]
            ),
            *alert_content,
            ft.Text(
                f"{len(events)} event records match the current filter. "
                f"{snapshot.get('malformed_count', 0)} malformed record(s) were skipped."
                if snapshot.get("malformed_count")
                else f"{len(events)} event records match the current filter. No malformed records.",
                size=12,
                color=MUTED,
            ),
        ]

    def render_events() -> list[ft.Control]:
        events = filtered_events()
        rows: list[ft.Control] = []
        for event in events:
            is_failure = event["event_type"] == "auth_failed"
            rows.append(
                _panel(
                    ft.Row(
                        controls=[
                            ft.Text(event["timestamp"], size=12, color=MUTED, width=205),
                            ft.Text(
                                event["event_type"].replace("_", " ").upper(),
                                size=11,
                                color=RED if is_failure else GREEN,
                                weight="bold",
                                width=155,
                            ),
                            ft.Text(event.get("source_ip") or "—", size=12, color=TEXT, width=135),
                            ft.Text(event.get("username") or "—", size=12, color=MUTED, expand=True),
                            ft.Text(event.get("destination") or "—", size=12, color=MUTED, width=80),
                        ],
                        spacing=8,
                    ),
                    padding=12,
                )
            )
        if not rows:
            rows.append(_panel(ft.Text("No events match this filter.", color=MUTED)))
        return [
            ft.Text("Event log", size=24, weight="bold", color=TEXT),
            ft.Text("Searchable view of parsed event data; this prototype does not collect live traffic.", size=13, color=MUTED),
            ft.Row(
                controls=[
                    ft.Text("TIMESTAMP", size=10, color=MUTED, width=205),
                    ft.Text("TYPE", size=10, color=MUTED, width=155),
                    ft.Text("SOURCE", size=10, color=MUTED, width=135),
                    ft.Text("USER", size=10, color=MUTED, expand=True),
                    ft.Text("SERVICE", size=10, color=MUTED, width=80),
                ],
                spacing=8,
            ),
            *rows,
        ]

    def render() -> None:
        if not snapshot:
            content.controls = [_panel(ft.Text("No event data loaded yet.", color=MUTED))]
        elif active_view == "events":
            content.controls = render_events()
        else:
            content.controls = render_overview()
        page.update()

    def refresh(_: Any = None) -> None:
        nonlocal snapshot
        try:
            snapshot = run_detection()
        except OSError as exc:
            snapshot = {}
            content.controls = [
                _panel(
                    ft.Text(
                        f"Could not read the sample event file at {DEFAULT_EVENTS_PATH}: {exc}",
                        color=RED,
                    )
                )
            ]
            page.update()
            return
        render()

    sidebar = ft.Container(
        content=ft.Column(
            controls=[
                ft.Text("SENTINEL-X", size=21, weight="bold", color=ACCENT),
                ft.Text("DEFENSIVE SECURITY", size=10, color=MUTED, weight="bold"),
                ft.Container(height=18),
                nav_button("Overview", "overview"),
                nav_button("Event log", "events"),
                ft.Container(expand=True),
                ft.Text("MODE", size=10, color=MUTED, weight="bold"),
                ft.Text("READ ONLY", size=12, color=GREEN, weight="bold"),
                ft.Text("No automatic blocking", size=11, color=MUTED),
            ],
            spacing=10,
            expand=True,
        ),
        width=210,
        bgcolor=SIDEBAR,
        padding=18,
    )

    workspace = ft.Column(
        controls=[
            ft.Row(
                controls=[
                    ft.Column(
                        controls=[
                            ft.Text("Security monitoring", size=13, color=MUTED),
                            ft.Text("Lab event analysis", size=19, weight="bold", color=TEXT),
                        ],
                        spacing=3,
                        expand=True,
                    ),
                    ft.Button(content="Run detection", on_click=refresh, bgcolor=ACCENT, color=BACKGROUND),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            ft.Row(controls=[search_field], spacing=10),
            content,
        ],
        spacing=18,
        expand=True,
    )

    page.add(
        ft.Row(
            controls=[
                sidebar,
                ft.Container(content=workspace, padding=24, expand=True),
            ],
            spacing=0,
            expand=True,
        )
    )
    refresh()


if __name__ == "__main__":
    ft.run(main)
