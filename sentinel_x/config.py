from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionConfig:
    failed_auth_threshold: int = 3
    failed_auth_window_seconds: int = 600
    max_event_count: int = 2000


DEFAULT_DETECTION_CONFIG = DetectionConfig()
