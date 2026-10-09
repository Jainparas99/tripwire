from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

DESTINATION_KEYS = ("url", "destination", "to")


def extract_destination(arguments: dict[str, Any]) -> str | None:
    for key in DESTINATION_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


@dataclass(frozen=True)
class _Destination:
    raw: str
    host: str
    port: int | None
    scheme: str | None
    path: str = ""
    is_email: bool = False

    @property
    def canonical_url(self) -> str:
        if self.scheme is None:
            return ""
        host = f"[{self.host}]" if ":" in self.host else self.host
        port = _effective_port(self)
        netloc = host if port is None else f"{host}:{port}"
        return urlunsplit((self.scheme, netloc, self.path or "", "", ""))


def _parse_destination(value: str) -> _Destination | None:
    raw = value.strip()
    if not raw:
        return None

    # Email destinations are compared by domain for allowlist purposes.
    if "@" in raw and "://" not in raw and "/" not in raw:
        domain = raw.rsplit("@", 1)[1].strip().lower().rstrip(".")
        if domain:
            return _Destination(raw=raw, host=domain, port=None, scheme=None, is_email=True)

    has_scheme = "://" in raw
    candidate = raw if has_scheme else f"//{raw}"
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not host:
        return None
    return _Destination(
        raw=raw,
        host=host.lower().rstrip("."),
        port=port,
        scheme=parsed.scheme.lower() if has_scheme else None,
        path=parsed.path.rstrip("/") if parsed.path != "/" else "",
    )


def destination_host(destination: str) -> str:
    parsed = _parse_destination(destination)
    if parsed is not None:
        return parsed.host
    return destination.strip().lower().split("@")[-1].rstrip(".")


def _effective_port(destination: _Destination) -> int | None:
    if destination.port is not None:
        return destination.port
    return {"http": 80, "https": 443}.get(destination.scheme)


def _host_rule(rule: str) -> tuple[str, int | None, bool] | None:
    wildcard = rule.startswith("*.")
    candidate = rule[2:] if wildcard else rule
    parsed = _parse_destination(candidate)
    if parsed is None or parsed.scheme is not None or parsed.is_email:
        return None
    return parsed.host, parsed.port, wildcard


def _host_matches(
    destination: _Destination, rule: str, rule_port: int | None, wildcard: bool
) -> bool:
    host_matches = destination.host.endswith(f".{rule}") if wildcard else destination.host == rule
    if not host_matches:
        return False
    if rule_port is None:
        return True
    return _effective_port(destination) == rule_port


def destination_allowed(destination: str, allowed_destinations: tuple[str, ...]) -> bool:
    """Match normalized hosts, URLs, email domains, ports, and explicit wildcards."""
    parsed_destination = _parse_destination(destination)
    if parsed_destination is None:
        return False
    raw_destination = parsed_destination.raw.casefold()

    for raw_rule in allowed_destinations:
        if not isinstance(raw_rule, str) or not raw_rule.strip():
            continue
        rule = raw_rule.strip()
        parsed_rule = _parse_destination(rule)

        if parsed_destination.is_email and parsed_rule is not None and parsed_rule.is_email:
            if rule.startswith("@") and parsed_destination.host == parsed_rule.host:
                return True
            if raw_destination == parsed_rule.raw.casefold():
                return True
            continue

        host_rule = _host_rule(rule.casefold())
        if host_rule is not None:
            host, port, wildcard = host_rule
            if _host_matches(parsed_destination, host, port, wildcard):
                return True
            continue

        if parsed_rule is None or parsed_rule.scheme is None:
            # A domain-only rule authorizes any email local part at that domain.
            if (
                parsed_rule is not None
                and parsed_destination.is_email
                and parsed_destination.host == parsed_rule.host
            ):
                return True
            continue

        if parsed_destination.scheme != parsed_rule.scheme:
            continue
        if parsed_destination.host != parsed_rule.host:
            continue
        if _effective_port(parsed_destination) != _effective_port(parsed_rule):
            continue
        if parsed_rule.path and parsed_destination.canonical_url == parsed_rule.canonical_url:
            return True
        if not parsed_rule.path:
            return True

    return False
