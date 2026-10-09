"""Small, truthful sponsor integration status helpers for the demo surface."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def semgrep_scan() -> dict[str, Any]:
    """Run the checked-in local rule pack; never contacts the Semgrep registry."""
    binary = shutil.which("semgrep")
    config = ROOT / "semgrep.yml"
    if not binary:
        return {"configured": False, "status": "not installed", "findings": []}
    try:
        result = subprocess.run(
            [
                binary,
                "scan",
                "--config",
                str(config),
                "--json",
                "--metrics=off",
                "--no-git-ignore",
                "src",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        payload = json.loads(result.stdout or "{}")
        findings = payload.get("results", []) if isinstance(payload, dict) else []
        return {
            "configured": True,
            "status": "connected" if result.returncode in (0, 1) else "error",
            "findings": findings,
            "errors": result.stderr[-500:] if result.returncode not in (0, 1) else "",
        }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return {"configured": True, "status": "error", "findings": [], "errors": str(exc)}


def provider_status() -> dict[str, dict[str, str]]:
    """Expose configuration state; secrets are never returned."""
    akash = os.getenv("TRIPWIRE_OPENAI_COMPAT_ENDPOINT") or os.getenv("AKASHML_ENDPOINT")
    return {
        "AkashML": {
            "status": "configured" if akash else "ready",
            "detail": (
                "OpenAI-compatible investigator endpoint"
                if akash
                else "Set TRIPWIRE_OPENAI_COMPAT_ENDPOINT"
            ),
        },
        "Guild.ai": {
            "status": "configured" if os.getenv("GUILD_RUN_ID") else "ready",
            "detail": (
                "Agent run metadata available"
                if os.getenv("GUILD_RUN_ID")
                else "Deploy the same worker with Guild"
            ),
        },
        "Senso.ai": {
            "status": "configured" if os.getenv("SENSO_CONTEXT_URL") else "ready",
            "detail": (
                "Verified context URL configured"
                if os.getenv("SENSO_CONTEXT_URL")
                else "Set SENSO_CONTEXT_URL for grounded context"
            ),
        },
    }
