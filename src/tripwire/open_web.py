"""Autonomous open-web threat monitor protected by the Tripwire gateway."""

from __future__ import annotations

import argparse
import json
import ssl
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from tripwire.audit import AuditLog
from tripwire.contracts import ToolCall, load_task_contract
from tripwire.gateway import TripwireGateway
from tripwire.tools.base import TOOL_ARGUMENTS

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_FILE = REPO_ROOT / "examples/contracts/threat_watch.yaml"
LOG_FILE = REPO_ROOT / ".tripwire/open-web-watch.jsonl"
ALERT_FILE = REPO_ROOT / ".tripwire/open-web-alert.json"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class OpenWebToolRegistry:
    """Only two real actions: read one trusted public feed and publish a local alert."""

    call_counts: dict[str, int]

    def __init__(self, alert_path: Path = ALERT_FILE) -> None:
        self.alert_path = alert_path.resolve()
        self.call_counts = {"fetch_cisa_kev": 0, "publish_alert": 0}

    def has_tool(self, name: str) -> bool:
        return name in self.call_counts

    def allowed_arguments(self, name: str) -> frozenset[str]:
        return TOOL_ARGUMENTS.get(name, frozenset())

    def validate(self, call: ToolCall) -> str | None:
        if call.tool == "fetch_cisa_kev" and call.arguments.get("url") != CISA_KEV_URL:
            return "WEB_SOURCE_NOT_ALLOWED"
        if call.tool == "publish_alert":
            path = Path(str(call.arguments.get("path", ""))).resolve()
            if path != self.alert_path:
                return "PUBLISH_PATH_NOT_ALLOWED"
            if not isinstance(call.arguments.get("content"), str):
                return "MALFORMED_ARGUMENTS"
        return None

    def resource_scope(self, call: ToolCall) -> dict[str, str]:
        return {}

    def preview(self, call: ToolCall) -> str:
        return str(call.arguments.get("url", call.arguments.get("path", "")))

    def run(self, call: ToolCall) -> dict[str, Any]:
        self.call_counts[call.tool] += 1
        if call.tool == "fetch_cisa_kev":
            request = Request(
                CISA_KEV_URL,
                headers={"accept": "application/json", "user-agent": "Tripwire-threat-watch/1.0"},
            )
            with urlopen(request, timeout=20, context=_https_context()) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if not isinstance(payload, dict) or not isinstance(
                payload.get("vulnerabilities"), list
            ):
                raise ValueError("CISA feed returned an unexpected shape")
            return payload
        content = str(call.arguments["content"])
        self.alert_path.parent.mkdir(parents=True, exist_ok=True)
        self.alert_path.write_text(content, encoding="utf-8")
        return {"path": str(self.alert_path), "bytes": len(content.encode("utf-8"))}


def run_monitor(*, limit: int = 5) -> dict[str, Any]:
    audit = AuditLog(LOG_FILE, reset=True)
    gateway = TripwireGateway(
        contract=load_task_contract(CONTRACT_FILE),
        audit_log=audit,
        tools=OpenWebToolRegistry(),
        session_id="sess_open_web_watch",
    )
    fetched = gateway.call_tool("fetch_cisa_kev", {"url": CISA_KEV_URL})
    if fetched.data is None:
        raise RuntimeError(f"CISA fetch blocked: {fetched.decision.reason_codes}")

    vulnerabilities = fetched.data.get("vulnerabilities", [])
    recent = sorted(
        (item for item in vulnerabilities if isinstance(item, dict)),
        key=lambda item: str(item.get("dateAdded", "")),
        reverse=True,
    )
    urgent = [
        item
        for item in recent
        if item.get("knownRansomwareCampaignUse") == "Known"
        or str(item.get("dueDate", "")) <= "2026-10-31"
    ][:limit]
    selected = urgent or recent[:limit]
    alert = {
        "agent": "tripwire-threat-watch",
        "source": CISA_KEV_URL,
        "catalogVersion": fetched.data.get("catalogVersion"),
        "totalVulnerabilities": len(vulnerabilities),
        "selectionRule": "recent KEV entries prioritized for ransomware use or near due date",
        "vulnerabilities": selected,
    }
    published = gateway.call_tool(
        "publish_alert",
        {"path": str(ALERT_FILE.resolve()), "content": json.dumps(alert, indent=2)},
    )
    if published.data is None:
        raise RuntimeError(f"Alert publication blocked: {published.decision.reason_codes}")
    return {"fetch": fetched, "publish": published, "alert": alert}


def _https_context() -> ssl.SSLContext:
    """Use the bundled CA set when the host Python has no configured trust anchors."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=5)
    args = parser.parse_args()
    result = run_monitor(limit=max(1, min(args.limit, 20)))
    print(f"Fetched live CISA KEV feed: {result['alert']['totalVulnerabilities']} vulnerabilities")
    print(f"Published {len(result['alert']['vulnerabilities'])} prioritized alerts to {ALERT_FILE}")
    print(f"Audit trail: {LOG_FILE}")
    for event in AuditLog(LOG_FILE).read_events():
        print(
            f"  {event.event_id} {event.attempted.tool} {event.decision} "
            f"{event.containment_state} executed={event.tool_executed}"
        )


if __name__ == "__main__":
    main()
