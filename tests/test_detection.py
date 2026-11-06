import pytest

from datetime import datetime, timedelta

from sentinel_x.detection.rules import RepeatedFailedAuthenticationRule
from sentinel_x.models import SecurityEvent


def make_event(
    source_ip: str,
    username: str,
    minutes_after: int,
    seconds_after: int = 0,
) -> SecurityEvent:
    timestamp = datetime(2026, 11, 1, 10, 0, 0) + timedelta(
        minutes=minutes_after,
        seconds=seconds_after,
    )
    return SecurityEvent(
        timestamp=timestamp,
        event_type="auth_failed",
        source_ip=source_ip,
        username=username,
        destination="sshd",
        success=False,
    )


def test_repeated_failed_auth_triggered():
    events = [
        make_event("198.51.100.77", "root", 0),
        make_event("198.51.100.77", "admin", 1),
        make_event("198.51.100.77", "support", 2),
    ]

    rule = RepeatedFailedAuthenticationRule(threshold=3, window_seconds=600)
    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "198.51.100.77"
    assert alerts[0]["count"] == 3
    assert alerts[0]["rule_id"] == "AUTH-FAIL-REPEATED"


def test_repeated_failed_auth_not_triggered_below_threshold():
    events = [
        make_event("198.51.100.44", "root", 0),
        make_event("198.51.100.44", "admin", 1),
    ]

    rule = RepeatedFailedAuthenticationRule(threshold=3, window_seconds=600)
    alerts = rule.evaluate(events)

    assert alerts == []


def test_ignore_non_failed_auth_events():
    events = [
        SecurityEvent(
            timestamp=datetime(2026, 11, 1, 10, 0, 0),
            event_type="auth_success",
            source_ip="198.51.100.66",
            username="alice",
            destination="sshd",
            success=True,
        )
    ]

    rule = RepeatedFailedAuthenticationRule(threshold=3, window_seconds=600)
    alerts = rule.evaluate(events)

    assert alerts == []


@pytest.mark.parametrize(
    ("threshold", "window_seconds"),
    [(0, 600), (-1, 600), (3, 0), (3, -1), (1.5, 600), (3, True)],
)
def test_detection_rule_rejects_non_positive_configuration(threshold, window_seconds):
    with pytest.raises(ValueError):
        RepeatedFailedAuthenticationRule(
            threshold=threshold,
            window_seconds=window_seconds,
        )


def test_events_exactly_on_window_boundary_are_included():
    events = [
        make_event("198.51.100.77", "root", 0),
        make_event("198.51.100.77", "admin", 5),
        make_event("198.51.100.77", "support", 10),
    ]

    alerts = RepeatedFailedAuthenticationRule(
        threshold=3,
        window_seconds=600,
    ).evaluate(events)

    assert len(alerts) == 1
    assert alerts[0]["count"] == 3


def test_events_beyond_window_boundary_do_not_trigger():
    events = [
        make_event("198.51.100.77", "root", 0),
        make_event("198.51.100.77", "admin", 5),
        make_event("198.51.100.77", "support", 10, seconds_after=1),
    ]

    alerts = RepeatedFailedAuthenticationRule(
        threshold=3,
        window_seconds=600,
    ).evaluate(events)

    assert alerts == []
