from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1
RETRY_DELAYS_SECONDS = (15 * 60, 60 * 60, 6 * 60 * 60, 24 * 60 * 60, 3 * 24 * 60 * 60, 7 * 24 * 60 * 60)
SUCCESS_RECHECK_SECONDS = 6 * 60 * 60
_write_lock = threading.RLock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS node_history (
    endpoint_key TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    remote_host TEXT NOT NULL DEFAULT '',
    remote_port INTEGER NOT NULL DEFAULT 0,
    proto TEXT NOT NULL DEFAULT 'tcp',
    country TEXT NOT NULL DEFAULT '',
    country_short TEXT NOT NULL DEFAULT '',
    source_score INTEGER NOT NULL DEFAULT 0,
    config_text TEXT NOT NULL DEFAULT '',
    config_sha256 TEXT NOT NULL DEFAULT '',
    node_json TEXT NOT NULL DEFAULT '{}',
    first_seen_at REAL NOT NULL,
    last_seen_at REAL NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    in_current_pool INTEGER NOT NULL DEFAULT 0,
    last_probe_at REAL NOT NULL DEFAULT 0,
    last_probe_status TEXT NOT NULL DEFAULT 'not_checked',
    last_probe_message TEXT NOT NULL DEFAULT '',
    last_latency_ms INTEGER NOT NULL DEFAULT 0,
    probe_success_count INTEGER NOT NULL DEFAULT 0,
    probe_failure_count INTEGER NOT NULL DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_success_at REAL NOT NULL DEFAULT 0,
    next_probe_at REAL NOT NULL DEFAULT 0,
    connect_success_count INTEGER NOT NULL DEFAULT 0,
    connect_failure_count INTEGER NOT NULL DEFAULT 0,
    last_connect_at REAL NOT NULL DEFAULT 0,
    last_exit_ip TEXT NOT NULL DEFAULT '',
    archived INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_node_history_pool_due
    ON node_history(in_current_pool, archived, next_probe_at);
CREATE INDEX IF NOT EXISTS idx_node_history_last_seen
    ON node_history(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_node_history_last_success
    ON node_history(last_success_at);
"""


def _now(value: float | None = None) -> float:
    return time.time() if value is None else float(value)


def _connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _database(db_path: str | Path):
    connection = _connect(db_path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize(db_path: str | Path) -> None:
    path = Path(db_path)
    with _write_lock:
        with _database(path) as connection:
            connection.executescript(_SCHEMA)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        try:
            path.chmod(0o600)
        except OSError:
            pass


def _normalized_host(node: dict[str, Any]) -> str:
    raw_ip = str(node.get("ip") or "").strip()
    raw_host = str(node.get("remote_host") or raw_ip).strip().lower().rstrip(".")
    for value in (raw_ip, raw_host):
        if not value:
            continue
        try:
            return ipaddress.ip_address(value.strip("[]")).compressed.lower()
        except ValueError:
            pass
    return raw_host


def endpoint_key(node: dict[str, Any]) -> str:
    host = _normalized_host(node)
    try:
        port = int(node.get("remote_port") or 0)
    except (TypeError, ValueError):
        port = 0
    proto = str(node.get("proto") or "tcp").strip().lower() or "tcp"
    material = f"{proto}|{host}|{port}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def config_fingerprint(config_text: Any) -> str:
    return hashlib.sha256(str(config_text or "").encode("utf-8")).hexdigest()


def _safe_node_json(node: dict[str, Any]) -> str:
    excluded = {
        "active",
        "config_file",
        "config_text",
        "history_only",
        "history_status",
        "history_force_probe",
    }
    payload = {key: value for key, value in node.items() if key not in excluded}
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


def _initial_probe_values(node: dict[str, Any], now: float) -> tuple[str, int, int, int, float, float]:
    status = str(node.get("probe_status") or "not_checked")
    if status == "available":
        return status, 1, 0, 0, now, now + SUCCESS_RECHECK_SECONDS
    if status == "unavailable":
        return status, 0, 1, 1, 0.0, now + RETRY_DELAYS_SECONDS[0]
    return "not_checked", 0, 0, 0, 0.0, now


def seed_if_empty(db_path: str | Path, nodes: Iterable[dict[str, Any]], now: float | None = None) -> int:
    initialize(db_path)
    with _database(db_path) as connection:
        existing = int(connection.execute("SELECT COUNT(*) FROM node_history").fetchone()[0])
    if existing:
        return 0
    return sync_snapshot(db_path, list(nodes), now=now, mark_missing=False)


def sync_snapshot(
    db_path: str | Path,
    nodes: Iterable[dict[str, Any]],
    now: float | None = None,
    *,
    mark_missing: bool = True,
) -> int:
    initialize(db_path)
    timestamp = _now(now)
    normalized_nodes = [dict(node) for node in nodes if isinstance(node, dict) and node.get("id")]
    with _write_lock:
        with _database(db_path) as connection:
            if mark_missing and normalized_nodes:
                connection.execute("UPDATE node_history SET in_current_pool = 0, updated_at = ?", (timestamp,))
            for node in normalized_nodes:
                key = endpoint_key(node)
                config_text = str(node.get("config_text") or "")
                config_sha = config_fingerprint(config_text)
                initial_status, initial_success, initial_failure, initial_streak, initial_last_success, initial_next = _initial_probe_values(node, timestamp)
                try:
                    port = int(node.get("remote_port") or 0)
                except (TypeError, ValueError):
                    port = 0
                try:
                    score = int(node.get("score") or 0)
                except (TypeError, ValueError):
                    score = 0
                connection.execute(
                    """
                    INSERT INTO node_history (
                        endpoint_key, node_id, ip, remote_host, remote_port, proto,
                        country, country_short, source_score, config_text, config_sha256,
                        node_json, first_seen_at, last_seen_at, seen_count, in_current_pool,
                        last_probe_at, last_probe_status, last_probe_message, last_latency_ms,
                        probe_success_count, probe_failure_count, consecutive_failures,
                        last_success_at, next_probe_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(endpoint_key) DO UPDATE SET
                        node_id = excluded.node_id,
                        ip = excluded.ip,
                        remote_host = excluded.remote_host,
                        remote_port = excluded.remote_port,
                        proto = excluded.proto,
                        country = excluded.country,
                        country_short = excluded.country_short,
                        source_score = excluded.source_score,
                        config_text = excluded.config_text,
                        node_json = excluded.node_json,
                        last_seen_at = excluded.last_seen_at,
                        seen_count = node_history.seen_count + 1,
                        in_current_pool = 1,
                        last_probe_status = CASE
                            WHEN node_history.config_sha256 <> excluded.config_sha256 THEN 'not_checked'
                            ELSE node_history.last_probe_status
                        END,
                        last_probe_message = CASE
                            WHEN node_history.config_sha256 <> excluded.config_sha256 THEN ''
                            ELSE node_history.last_probe_message
                        END,
                        consecutive_failures = CASE
                            WHEN node_history.config_sha256 <> excluded.config_sha256 THEN 0
                            ELSE node_history.consecutive_failures
                        END,
                        next_probe_at = CASE
                            WHEN node_history.config_sha256 <> excluded.config_sha256 THEN excluded.last_seen_at
                            ELSE node_history.next_probe_at
                        END,
                        archived = CASE
                            WHEN node_history.config_sha256 <> excluded.config_sha256 THEN 0
                            ELSE node_history.archived
                        END,
                        config_sha256 = excluded.config_sha256,
                        updated_at = excluded.updated_at
                    """,
                    (
                        key,
                        str(node.get("id") or ""),
                        str(node.get("ip") or ""),
                        str(node.get("remote_host") or ""),
                        port,
                        str(node.get("proto") or "tcp").lower(),
                        str(node.get("country") or ""),
                        str(node.get("country_short") or "").upper(),
                        score,
                        config_text,
                        config_sha,
                        _safe_node_json(node),
                        timestamp,
                        timestamp,
                        timestamp if initial_status != "not_checked" else 0.0,
                        initial_status,
                        str(node.get("probe_message") or ""),
                        int(node.get("latency_ms") or 0),
                        initial_success,
                        initial_failure,
                        initial_streak,
                        initial_last_success,
                        initial_next,
                        timestamp,
                    ),
                )
    return len(normalized_nodes)


def select_workset(
    db_path: str | Path,
    *,
    limit: int = 25,
    country_codes: Iterable[str] | None = None,
    favorite_node_ids: Iterable[str] | None = None,
    exclude_endpoint_keys: Iterable[str] | None = None,
    exclude_node_ids: Iterable[str] | None = None,
    include_current: bool = False,
    now: float | None = None,
) -> list[dict[str, Any]]:
    initialize(db_path)
    requested_limit = max(0, int(limit))
    if requested_limit == 0:
        return []

    timestamp = _now(now)
    countries = {str(code).strip().upper() for code in (country_codes or []) if str(code).strip()}
    favorites = {str(value) for value in (favorite_node_ids or []) if str(value)}
    excluded_keys = {str(value) for value in (exclude_endpoint_keys or []) if str(value)}
    excluded_ids = {str(value) for value in (exclude_node_ids or []) if str(value)}

    where_parts = ["archived = 0"]
    where_params: list[Any] = [timestamp]
    if include_current:
        # During source outages the latest current pool is a recovery source,
        # even when its normal success recheck is scheduled for later.
        where_parts.append("(next_probe_at <= ? OR in_current_pool = 1)")
    else:
        where_parts.extend(["next_probe_at <= ?", "in_current_pool = 0"])
    if countries:
        country_values = sorted(countries)
        placeholders = ",".join("?" for _ in country_values)
        where_parts.append(f"UPPER(country_short) IN ({placeholders})")
        where_params.extend(country_values)

    order_parts: list[str] = []
    order_params: list[Any] = []
    if favorites:
        favorite_values = sorted(favorites)
        placeholders = ",".join("?" for _ in favorite_values)
        order_parts.append(f"CASE WHEN node_id IN ({placeholders}) THEN 0 ELSE 1 END")
        order_params.extend(favorite_values)
    order_parts.extend(
        [
            "CASE WHEN probe_success_count + connect_success_count > 0 THEN 0 ELSE 1 END",
            "(probe_success_count + connect_success_count) DESC",
            "consecutive_failures ASC",
            "source_score DESC",
            "last_seen_at DESC",
        ]
    )

    # Page through due rows so a large fresh snapshot or a large blacklist cannot
    # starve older historical nodes before the Python-side exclusions are applied.
    page_size = max(100, min(500, requested_limit * 5))
    offset = 0
    selected: list[dict[str, Any]] = []
    query = f"""
        SELECT *
        FROM node_history
        WHERE {' AND '.join(where_parts)}
        ORDER BY {', '.join(order_parts)}
        LIMIT ? OFFSET ?
    """
    with _database(db_path) as connection:
        while len(selected) < requested_limit:
            rows = connection.execute(
                query,
                (*where_params, *order_params, page_size, offset),
            ).fetchall()
            if not rows:
                break
            offset += len(rows)

            for row in rows:
                if row["endpoint_key"] in excluded_keys or row["node_id"] in excluded_ids:
                    continue
                try:
                    node = json.loads(row["node_json"] or "{}")
                except json.JSONDecodeError:
                    node = {}
                if not isinstance(node, dict):
                    node = {}
                node.update(
                    {
                        "id": row["node_id"],
                        "ip": row["ip"],
                        "remote_host": row["remote_host"],
                        "remote_port": row["remote_port"],
                        "proto": row["proto"],
                        "country": row["country"],
                        "country_short": row["country_short"],
                        "score": row["source_score"],
                        "config_text": row["config_text"],
                        "active": False,
                        "probe_status": "not_checked",
                        "probe_message": "历史节点待复测",
                        "probed_at": 0,
                        "history_only": True,
                        "history_status": "历史复测",
                        "history_force_probe": True,
                        "history_endpoint_key": row["endpoint_key"],
                    }
                )
                selected.append(node)
                if len(selected) >= requested_limit:
                    break

            if len(rows) < page_size:
                break

    return selected


def archive_node(
    db_path: str | Path,
    node_id: str,
    *,
    message: str = "",
    now: float | None = None,
) -> bool:
    initialize(db_path)
    timestamp = _now(now)
    with _write_lock:
        with _database(db_path) as connection:
            cursor = connection.execute(
                """
                UPDATE node_history
                SET archived = 1,
                    in_current_pool = 0,
                    last_probe_status = 'invalid_config',
                    last_probe_message = ?,
                    updated_at = ?
                WHERE node_id = ?
                """,
                (str(message or "历史配置无效"), timestamp, str(node_id)),
            )
            return cursor.rowcount > 0

def record_probe_results(db_path: str | Path, results: Iterable[dict[str, Any]], now: float | None = None) -> int:
    initialize(db_path)
    timestamp = _now(now)
    changed = 0
    with _write_lock:
        with _database(db_path) as connection:
            for result in results:
                node_id = str(result.get("id") or "")
                if not node_id:
                    continue
                status = str(result.get("probe_status") or "not_checked")
                message = str(result.get("probe_message") or "")
                latency = int(result.get("latency_ms") or 0)
                row = connection.execute(
                    "SELECT consecutive_failures FROM node_history WHERE node_id = ? ORDER BY last_seen_at DESC LIMIT 1",
                    (node_id,),
                ).fetchone()
                if row is None:
                    continue
                if status == "available":
                    connection.execute(
                        """
                        UPDATE node_history
                        SET last_probe_at = ?, last_probe_status = 'available',
                            last_probe_message = ?, last_latency_ms = ?,
                            probe_success_count = probe_success_count + 1,
                            consecutive_failures = 0, last_success_at = ?,
                            next_probe_at = ?, archived = 0, updated_at = ?
                        WHERE node_id = ?
                        """,
                        (timestamp, message, latency, timestamp, timestamp + SUCCESS_RECHECK_SECONDS, timestamp, node_id),
                    )
                    changed += 1
                elif status == "unavailable":
                    streak = int(row["consecutive_failures"] or 0) + 1
                    delay = RETRY_DELAYS_SECONDS[min(streak - 1, len(RETRY_DELAYS_SECONDS) - 1)]
                    connection.execute(
                        """
                        UPDATE node_history
                        SET last_probe_at = ?, last_probe_status = 'unavailable',
                            last_probe_message = ?, last_latency_ms = ?,
                            probe_failure_count = probe_failure_count + 1,
                            consecutive_failures = ?, next_probe_at = ?, updated_at = ?
                        WHERE node_id = ?
                        """,
                        (timestamp, message, latency, streak, timestamp + delay, timestamp, node_id),
                    )
                    changed += 1
    return changed


def record_connection_result(
    db_path: str | Path,
    node_id: str,
    *,
    success: bool,
    exit_ip: str = "",
    message: str = "",
    now: float | None = None,
) -> bool:
    initialize(db_path)
    timestamp = _now(now)
    with _write_lock:
        with _database(db_path) as connection:
            row = connection.execute(
                "SELECT consecutive_failures FROM node_history WHERE node_id = ? ORDER BY last_seen_at DESC LIMIT 1",
                (str(node_id),),
            ).fetchone()
            if row is None:
                return False
            if success:
                connection.execute(
                    """
                    UPDATE node_history
                    SET connect_success_count = connect_success_count + 1,
                        last_connect_at = ?, last_exit_ip = ?,
                        last_probe_status = 'available', last_probe_message = ?,
                        last_success_at = ?, consecutive_failures = 0,
                        next_probe_at = ?, archived = 0, updated_at = ?
                    WHERE node_id = ?
                    """,
                    (timestamp, str(exit_ip or ""), str(message or ""), timestamp, timestamp + SUCCESS_RECHECK_SECONDS, timestamp, str(node_id)),
                )
            else:
                streak = int(row["consecutive_failures"] or 0) + 1
                delay = RETRY_DELAYS_SECONDS[min(streak - 1, len(RETRY_DELAYS_SECONDS) - 1)]
                connection.execute(
                    """
                    UPDATE node_history
                    SET connect_failure_count = connect_failure_count + 1,
                        last_connect_at = ?, last_probe_message = ?,
                        consecutive_failures = ?, next_probe_at = ?, updated_at = ?
                    WHERE node_id = ?
                    """,
                    (timestamp, str(message or ""), streak, timestamp + delay, timestamp, str(node_id)),
                )
    return True


def statistics(db_path: str | Path, now: float | None = None) -> dict[str, int]:
    initialize(db_path)
    timestamp = _now(now)
    with _database(db_path) as connection:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS endpoints,
                COUNT(DISTINCT CASE
                    WHEN ip <> '' THEN ip
                    WHEN remote_host <> '' THEN remote_host
                    ELSE endpoint_key
                END) AS unique_ips,
                SUM(CASE WHEN in_current_pool = 1 AND archived = 0 THEN 1 ELSE 0 END) AS current_count,
                SUM(CASE WHEN probe_success_count > 0 OR connect_success_count > 0 THEN 1 ELSE 0 END) AS ever_available,
                SUM(CASE WHEN archived = 0 AND next_probe_at <= ? THEN 1 ELSE 0 END) AS due_count,
                SUM(CASE WHEN archived = 1 THEN 1 ELSE 0 END) AS archived_count
            FROM node_history
            """,
            (timestamp,),
        ).fetchone()
    return {
        "history_endpoints": int(row["endpoints"] or 0),
        "history_unique_ips": int(row["unique_ips"] or 0),
        "history_current": int(row["current_count"] or 0),
        "history_ever_available": int(row["ever_available"] or 0),
        "history_due": int(row["due_count"] or 0),
        "history_archived": int(row["archived_count"] or 0),
    }


def cleanup(
    db_path: str | Path,
    *,
    protected_node_ids: Iterable[str] | None = None,
    max_rows: int = 10_000,
    now: float | None = None,
) -> dict[str, int]:
    initialize(db_path)
    timestamp = _now(now)
    protected = {str(value) for value in (protected_node_ids or []) if str(value)}
    placeholders = ",".join("?" for _ in protected)
    protected_sql = f" AND node_id NOT IN ({placeholders})" if protected else ""
    protected_args = tuple(sorted(protected))
    archived = 0
    deleted = 0
    with _write_lock:
        with _database(db_path) as connection:
            cursor = connection.execute(
                f"""
                UPDATE node_history
                SET archived = 1, updated_at = ?
                WHERE archived = 0
                  AND probe_success_count = 0
                  AND connect_success_count = 0
                  AND consecutive_failures >= 5
                  AND last_seen_at < ?
                  {protected_sql}
                """,
                (timestamp, timestamp - 30 * 24 * 60 * 60, *protected_args),
            )
            archived += max(0, cursor.rowcount)
            cursor = connection.execute(
                f"""
                DELETE FROM node_history
                WHERE probe_success_count = 0
                  AND connect_success_count = 0
                  AND last_seen_at < ?
                  {protected_sql}
                """,
                (timestamp - 90 * 24 * 60 * 60, *protected_args),
            )
            deleted += max(0, cursor.rowcount)
            total = int(connection.execute("SELECT COUNT(*) FROM node_history").fetchone()[0])
            overflow = max(0, total - max(100, int(max_rows)))
            if overflow:
                rows = connection.execute(
                    f"""
                    SELECT endpoint_key FROM node_history
                    WHERE probe_success_count = 0 AND connect_success_count = 0
                    {protected_sql}
                    ORDER BY archived DESC, last_seen_at ASC, consecutive_failures DESC
                    LIMIT ?
                    """,
                    (*protected_args, overflow),
                ).fetchall()
                keys = [row["endpoint_key"] for row in rows]
                if keys:
                    key_placeholders = ",".join("?" for _ in keys)
                    connection.execute(
                        f"DELETE FROM node_history WHERE endpoint_key IN ({key_placeholders})",
                        keys,
                    )
                    deleted += len(keys)
    return {"archived": archived, "deleted": deleted}
