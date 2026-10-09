"""Optional ClickHouse analytics over Tripwire audit logs.

Nothing in the gateway, detectors or audit log imports this module, and enforcement never
waits on it. It copies audit events into a local ClickHouse for fleet-scale queries.

The scale-up data is SYNTHETIC: the 26 fixture trajectories are replayed once through the real
gateway (same trace, same decisions), then copied under new session ids with spread-out,
seeded timestamps. Every synthetic row has synthetic=1 and source='synthetic-scaleup'.
"""

from __future__ import annotations

import argparse
import math
import os
import random
import subprocess
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import yaml

from tripwire.audit import AuditEvent, AuditLog
from tripwire.contracts import load_task_contract
from tripwire.gateway import TripwireGateway

REPO_ROOT = Path(__file__).resolve().parents[2]
TRACE_FILE = REPO_ROOT / "evaluation/traces/checkpoint_b.yaml"
CONTRACT_FILE = REPO_ROOT / "examples/contracts/support_summary.yaml"
LOG_DIR = REPO_ROOT / ".tripwire"

IMAGE = "clickhouse/clickhouse-server:24.8"
CONTAINER = "tripwire-clickhouse"


# Local, throwaway development database only. Read at call time so callers can repoint it.
def _host() -> str:
    return os.getenv("TRIPWIRE_CLICKHOUSE_HOST", "127.0.0.1")


def _port() -> int:
    return int(os.getenv("TRIPWIRE_CLICKHOUSE_PORT", "8123"))


USER = os.getenv("TRIPWIRE_CLICKHOUSE_USER", "tripwire")
PASSWORD = os.getenv("TRIPWIRE_CLICKHOUSE_PASSWORD", "tripwire-local")
DATABASE = "tripwire"
TABLE = f"{DATABASE}.audit_events"
SYNTHETIC_SOURCE = "synthetic-scaleup"
DEFAULT_TARGET_EVENTS = 1_000_000

COLUMNS = (
    "session_id",
    "ts",
    "seq",
    "event_id",
    "task_id",
    "tool",
    "decision",
    "containment_state",
    "reason_codes",
    "score",
    "tool_invoked",
    "tool_completed",
    "synthetic",
    "source",
)

DDL = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    session_id String,
    ts DateTime64(6, 'UTC'),
    seq UInt32,
    event_id String,
    task_id LowCardinality(String),
    tool LowCardinality(String),
    decision LowCardinality(String),
    containment_state LowCardinality(String),
    reason_codes Array(LowCardinality(String)),
    score Int32,
    tool_invoked UInt8,
    tool_completed UInt8,
    synthetic UInt8,
    source LowCardinality(String)
) ENGINE = MergeTree
ORDER BY (session_id, ts)
"""

QUERIES: dict[str, str] = {
    "top_deny_reasons": f"""
        SELECT reason, count() AS denials
        FROM {TABLE}
        ARRAY JOIN reason_codes AS reason
        WHERE decision = 'DENY'
        GROUP BY reason
        ORDER BY denials DESC
        LIMIT 10
    """,
    "time_to_kill": f"""
        SELECT
            count() AS killed_sessions,
            toUInt32(quantileExact(0.5)(ms_to_kill)) AS p50_ms,
            toUInt32(quantileExact(0.95)(ms_to_kill)) AS p95_ms,
            max(ms_to_kill) AS max_ms
        FROM (
            SELECT
                session_id,
                dateDiff('millisecond', min(ts), minIf(ts, containment_state = 'KILLED'))
                    AS ms_to_kill
            FROM {TABLE}
            GROUP BY session_id
            HAVING countIf(containment_state = 'KILLED') > 0
        )
    """,
    "read_then_send_sessions": f"""
        SELECT
            count() AS sessions,
            countIf(flagged) AS flagged_read_then_send
        FROM (
            SELECT
                session_id,
                sequenceMatch('(?1).*(?2)')(
                    seq,
                    tool IN ('read_customer', 'read_ticket') AND tool_completed = 1,
                    tool IN ('http_post', 'send_email')
                ) AS read_then_send,
                has(groupArrayArray(reason_codes), 'READ_THEN_SEND') AS flagged
            FROM {TABLE}
            GROUP BY session_id
        )
        WHERE read_then_send
    """,
}


# ---------------------------------------------------------------- data


def event_row(event: AuditEvent, *, source: str, synthetic: bool) -> list[Any]:
    return [
        event.session_id,
        event.ts,
        event.seq,
        event.event_id,
        event.task_id,
        event.attempted.tool,
        event.decision.value,
        event.containment_state.value,
        list(event.reason_codes),
        event.score,
        int(event.tool_invoked),
        int(event.tool_completed),
        int(synthetic),
        source,
    ]


def replay_fixtures(trace_path: Path = TRACE_FILE) -> list[tuple[str, list[AuditEvent]]]:
    """Replay each fixture trace once through the real gateway."""
    traces = yaml.safe_load(trace_path.read_text(encoding="utf-8"))["traces"]
    replayed = []
    with TemporaryDirectory() as tmpdir:
        for index, trace in enumerate(traces, start=1):
            contract_path = (
                REPO_ROOT / trace["contract"] if trace.get("contract") else CONTRACT_FILE
            )
            log = AuditLog(Path(tmpdir) / f"{index}.jsonl", reset=True)
            gateway = TripwireGateway(
                contract=load_task_contract(contract_path),
                audit_log=log,
                session_id=f"fixture-{index:02d}",
            )
            for step in trace["calls"]:
                gateway.call_tool(step["tool"], step.get("arguments", {}))
            replayed.append((trace["name"], log.read_events()))
    return replayed


def synthetic_rows(
    replayed: list[tuple[str, list[AuditEvent]]],
    *,
    target_events: int = DEFAULT_TARGET_EVENTS,
    seed: int = 7,
    start: datetime = datetime(2026, 10, 1, tzinfo=UTC),
) -> Iterator[list[Any]]:
    """SYNTHETIC: copy replayed fixture sessions under new ids and seeded timestamps.

    Decisions are copied, not re-derived, which is valid because replay is deterministic:
    the same trace always produces the same decisions.
    """
    rng = random.Random(seed)
    produced = 0
    copy = 0
    while produced < target_events:
        for name, events in replayed:
            if produced >= target_events:
                return
            copy += 1
            session_id = f"syn-{copy:07d}-{name}"
            ts = start + timedelta(seconds=rng.uniform(0, 7 * 24 * 3600))
            for event in events:
                ts += timedelta(milliseconds=rng.uniform(40, 2500))
                row = event_row(event, source=SYNTHETIC_SOURCE, synthetic=True)
                row[0] = session_id
                row[1] = ts
                row[3] = f"{session_id}:{event.event_id}"
                yield row
                produced += 1


def demo_rows(log_dir: Path = LOG_DIR) -> Iterator[list[Any]]:
    """Events from local demo/replay logs (also fixtures, but not multiplied)."""
    for path in sorted(log_dir.glob("*.jsonl")):
        for event in AuditLog(path).read_events():
            yield event_row(event, source=f"log:{path.stem}", synthetic=False)


# ---------------------------------------------------------------- clickhouse


def client(timeout: float = 10) -> Any:
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=_host(),
        port=_port(),
        username=USER,
        password=PASSWORD,
        # The client truncates timeouts to whole seconds, so never pass less than 1.
        connect_timeout=max(1, math.ceil(timeout)),
        send_receive_timeout=max(timeout, 60),
    )


def reachable(timeout: float = 0.5) -> bool:
    """True only if the optional client is installed and ClickHouse answers quickly."""
    try:
        return bool(client(timeout=timeout).ping())
    except Exception:
        return False


def start_server(wait_seconds: float = 60) -> None:
    running = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"name=^{CONTAINER}$"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if not running:
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True, check=False)
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                CONTAINER,
                "-p",
                f"127.0.0.1:{_port()}:8123",
                "-e",
                f"CLICKHOUSE_USER={USER}",
                "-e",
                f"CLICKHOUSE_PASSWORD={PASSWORD}",
                "-e",
                "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1",
                "--ulimit",
                "nofile=262144:262144",
                IMAGE,
            ],
            check=True,
            capture_output=True,
        )
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if reachable(timeout=1):
            return
        time.sleep(1)
    raise RuntimeError(f"ClickHouse did not become reachable on {_host()}:{_port()}")


def load(
    *,
    target_events: int = DEFAULT_TARGET_EVENTS,
    batch_size: int = 100_000,
) -> dict[str, int]:
    ch = client()
    ch.command(f"CREATE DATABASE IF NOT EXISTS {DATABASE}")
    ch.command(f"DROP TABLE IF EXISTS {TABLE}")
    ch.command(DDL)
    counts = {"demo_events": 0, "synthetic_events": 0}
    for key, rows in (
        ("demo_events", demo_rows()),
        ("synthetic_events", synthetic_rows(replay_fixtures(), target_events=target_events)),
    ):
        batch: list[list[Any]] = []
        for row in rows:
            batch.append(row)
            if len(batch) >= batch_size:
                ch.insert(TABLE, batch, column_names=COLUMNS)
                counts[key] += len(batch)
                batch = []
        if batch:
            ch.insert(TABLE, batch, column_names=COLUMNS)
            counts[key] += len(batch)
    return counts


def run_queries() -> dict[str, dict[str, Any]]:
    """Run each query once to warm caches, then time a second run (client wall clock)."""
    ch = client()
    results: dict[str, dict[str, Any]] = {}
    for name, sql in QUERIES.items():
        ch.query(sql)
        started = time.perf_counter()
        result = ch.query(sql)
        elapsed_ms = (time.perf_counter() - started) * 1000
        results[name] = {
            "columns": list(result.column_names),
            "rows": [list(row) for row in result.result_rows],
            "latency_ms": round(elapsed_ms, 1),
        }
    return results


def table_summary() -> dict[str, int]:
    row = (
        client()
        .query(f"SELECT count(), uniqExact(session_id), countIf(synthetic = 1) FROM {TABLE}")
        .result_rows[0]
    )
    return {"events": row[0], "sessions": row[1], "synthetic_events": row[2]}


# ---------------------------------------------------------------- cli


def _print_results(results: dict[str, dict[str, Any]]) -> None:
    for name, result in results.items():
        print(f"\n{name}  ({result['latency_ms']} ms, measured round trip)")
        print("  " + " | ".join(result["columns"]))
        for row in result["rows"]:
            print("  " + " | ".join(str(value) for value in row))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("up", "load", "query", "all"), nargs="?", default="all")
    parser.add_argument("--events", type=int, default=DEFAULT_TARGET_EVENTS)
    args = parser.parse_args()

    if args.command in {"up", "all"}:
        start_server()
        print(f"ClickHouse reachable on {_host()}:{_port()}")
    if args.command in {"load", "all"}:
        started = time.perf_counter()
        counts = load(target_events=args.events)
        print(
            f"Loaded {counts['demo_events']} demo-log events and "
            f"{counts['synthetic_events']:,} SYNTHETIC events (fixture traces replayed through "
            f"the gateway, copied under new session ids) in {time.perf_counter() - started:.1f}s"
        )
    if args.command in {"query", "all"}:
        summary = table_summary()
        print(
            f"\nTable {TABLE}: {summary['events']:,} events, {summary['sessions']:,} sessions, "
            f"{summary['synthetic_events']:,} of them SYNTHETIC"
        )
        _print_results(run_queries())
        print(
            "\nNote: read-then-send sessions include sends to allowed destinations "
            "(benign_read_then_email_allowed), which Tripwire deliberately does not flag."
        )


if __name__ == "__main__":
    main()
