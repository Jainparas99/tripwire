from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

DESTINATION_KEYS = ("url", "destination", "to")


def extract_destination(arguments: dict[str, Any]) -> str | None:
    for key in DESTINATION_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def destination_host(destination: str) -> str:
    parsed = urlparse(destination)
    return parsed.netloc or destination.split("@")[-1]


def destination_allowed(destination: str, allowed_destinations: tuple[str, ...]) -> bool:
    allowed = set(allowed_destinations)
    return destination in allowed or destination_host(destination) in allowed
