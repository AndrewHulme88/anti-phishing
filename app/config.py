"""Runtime configuration loaded from environment variables."""

import os
from dataclasses import dataclass


DEFAULT_MAX_UPLOAD_SIZE = 10 * 1024 * 1024


def _positive_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer.") from error
    if parsed <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return parsed


def _boolean(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false.")


@dataclass(frozen=True)
class Settings:
    """Settings deliberately exclude uploaded-message content."""

    api_key: str | None
    rapidapi_proxy_secret: str | None
    max_upload_size: int
    rate_limit_enabled: bool
    rate_limit_requests: int
    rate_limit_window_seconds: int


def load_settings() -> Settings:
    api_key = os.getenv("PHISHING_ANALYZER_API_KEY") or None
    return Settings(
        api_key=api_key,
        rapidapi_proxy_secret=os.getenv("PHISHING_ANALYZER_RAPIDAPI_PROXY_SECRET") or None,
        max_upload_size=_positive_int("PHISHING_ANALYZER_MAX_UPLOAD_BYTES", DEFAULT_MAX_UPLOAD_SIZE),
        rate_limit_enabled=_boolean("PHISHING_ANALYZER_RATE_LIMIT_ENABLED", True),
        rate_limit_requests=_positive_int("PHISHING_ANALYZER_RATE_LIMIT_REQUESTS", 60),
        rate_limit_window_seconds=_positive_int("PHISHING_ANALYZER_RATE_LIMIT_WINDOW_SECONDS", 60),
    )


settings = load_settings()
