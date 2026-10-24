from __future__ import annotations

import os
import sqlite3
import stat
import tempfile
import threading
import unittest
from pathlib import Path

import node_history


def make_node(
    node_id: str,
    ip: str,
    *,
    country_short: str = "JP",
    port: int = 443,
    config_text: str = "client\nremote 203.0.113.1 443 tcp\n",
    probe_status: str = "not_checked",
) -> dict:
    return {
        "id": node_id,
        "ip": ip,
        "remote_host": ip,
        "remote_port": port,
        "proto": "tcp",
        "country": country_short,
        "country_short": country_short,
        "score": 100,
        "config_text": config_text,
        "probe_status": probe_status,
        "probe_message": "",
        "latency_ms": 0,
    }


class NodeHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "node_history.sqlite3"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def row(self, node_id: str):
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            return connection.execute(
                "SELECT * FROM node_history WHERE node_id = ?",
                (node_id,),
            ).fetchone()

    def test_initialize_is_idempotent_and_private(self) -> None:
        node_history.initialize(self.db_path)
        node_history.initialize(self.db_path)

        with sqlite3.connect(self.db_path) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(node_history.SCHEMA_VERSION, version)
        if os.name != "nt":
            self.assertEqual(0o600, stat.S_IMODE(self.db_path.stat().st_mode))

    def test_endpoint_identity_ignores_country_label(self) -> None:
        first = make_node("JP_198_51_100_10_443_tcp", "198.51.100.10", country_short="JP")
        second = make_node("US_198_51_100_10_443_tcp", "198.51.100.10", country_short="US")

        self.assertEqual(node_history.endpoint_key(first), node_history.endpoint_key(second))
        node_history.sync_snapshot(self.db_path, [first], now=100)
        node_history.sync_snapshot(self.db_path, [second], now=200)

        stats = node_history.statistics(self.db_path, now=200)
        self.assertEqual(1, stats["history_endpoints"])
        self.assertEqual(1, stats["history_unique_ips"])
        self.assertEqual(2, self.row(second["id"])["seen_count"])

    def test_snapshot_accumulates_missing_nodes_instead_of_deleting_them(self) -> None:
        first = make_node("node-a", "198.51.100.1")
        second = make_node("node-b", "198.51.100.2")

        node_history.sync_snapshot(self.db_path, [first], now=100)
        node_history.sync_snapshot(self.db_path, [second], now=200)

        stats = node_history.statistics(self.db_path, now=200)
        self.assertEqual(2, stats["history_endpoints"])
        self.assertEqual(2, stats["history_unique_ips"])
        self.assertEqual(1, stats["history_current"])

    def test_same_config_preserves_state_but_changed_config_resets_it(self) -> None:
        node = make_node("node-a", "198.51.100.3")
        node_history.sync_snapshot(self.db_path, [node], now=100)
        node_history.record_probe_results(
            self.db_path,
            [{"id": "node-a", "probe_status": "unavailable", "probe_message": "timeout"}],
            now=110,
        )
        self.assertEqual(1, self.row("node-a")["consecutive_failures"])

        node_history.sync_snapshot(self.db_path, [node], now=120)
        self.assertEqual(1, self.row("node-a")["consecutive_failures"])

        changed = dict(node)
        changed["config_text"] += "verb 3\n"
        node_history.sync_snapshot(self.db_path, [changed], now=130)
        row = self.row("node-a")
        self.assertEqual("not_checked", row["last_probe_status"])
        self.assertEqual(0, row["consecutive_failures"])
        self.assertEqual(130, row["next_probe_at"])

    def test_probe_result_updates_backoff_and_success_score(self) -> None:
        node_history.sync_snapshot(self.db_path, [make_node("node-a", "198.51.100.4")], now=100)

        node_history.record_probe_results(
            self.db_path,
            [{"id": "node-a", "probe_status": "unavailable", "probe_message": "timeout"}],
            now=200,
        )
        first = self.row("node-a")
        self.assertEqual(1, first["probe_failure_count"])
        self.assertEqual(200 + 15 * 60, first["next_probe_at"])

        node_history.record_probe_results(
            self.db_path,
            [{"id": "node-a", "probe_status": "unavailable", "probe_message": "timeout"}],
            now=300,
        )
        second = self.row("node-a")
        self.assertEqual(2, second["consecutive_failures"])
        self.assertEqual(300 + 60 * 60, second["next_probe_at"])

        node_history.record_probe_results(
            self.db_path,
            [{"id": "node-a", "probe_status": "available", "probe_message": "ok", "latency_ms": 88}],
            now=400,
        )
        success = self.row("node-a")
        self.assertEqual(1, success["probe_success_count"])
        self.assertEqual(0, success["consecutive_failures"])
        self.assertEqual(88, success["last_latency_ms"])
        self.assertEqual(400 + node_history.SUCCESS_RECHECK_SECONDS, success["next_probe_at"])

    def test_workset_respects_country_exclusions_and_favorites(self) -> None:
        jp_a = make_node("jp-a", "198.51.100.10", country_short="JP")
        jp_b = make_node("jp-b", "198.51.100.11", country_short="JP")
        us = make_node("us-a", "198.51.100.12", country_short="US")
        node_history.sync_snapshot(self.db_path, [jp_a, jp_b, us], now=100)

        selected = node_history.select_workset(
            self.db_path,
            limit=5,
            country_codes=["JP"],
            favorite_node_ids=["jp-b"],
            exclude_endpoint_keys=[node_history.endpoint_key(jp_a)],
            now=100,
        )

        self.assertEqual(["jp-b"], [node["id"] for node in selected])
        self.assertTrue(selected[0]["history_only"])
        self.assertEqual("not_checked", selected[0]["probe_status"])
        self.assertNotIn("config_file", selected[0])

    def test_real_connection_success_is_strong_positive_signal(self) -> None:
        node_history.sync_snapshot(self.db_path, [make_node("node-a", "198.51.100.20")], now=100)

        changed = node_history.record_connection_result(
            self.db_path,
            "node-a",
            success=True,
            exit_ip="203.0.113.9",
            message="verified",
            now=200,
        )

        self.assertTrue(changed)
        row = self.row("node-a")
        self.assertEqual(1, row["connect_success_count"])
        self.assertEqual("203.0.113.9", row["last_exit_ip"])
        self.assertEqual("available", row["last_probe_status"])
        self.assertEqual(0, row["consecutive_failures"])

    def test_cleanup_never_deletes_successful_or_protected_nodes(self) -> None:
        old = 100.0
        nodes = [
            make_node("failed", "198.51.100.30"),
            make_node("successful", "198.51.100.31"),
            make_node("protected", "198.51.100.32"),
        ]
        node_history.sync_snapshot(self.db_path, nodes, now=old)
        node_history.record_probe_results(
            self.db_path,
            [{"id": "successful", "probe_status": "available", "probe_message": "ok"}],
            now=old + 1,
        )

        result = node_history.cleanup(
            self.db_path,
            protected_node_ids=["protected"],
            max_rows=100,
            now=old + 100 * 24 * 60 * 60,
        )

        self.assertGreaterEqual(result["deleted"], 1)
        with sqlite3.connect(self.db_path) as connection:
            remaining = {row[0] for row in connection.execute("SELECT node_id FROM node_history")}
        self.assertNotIn("failed", remaining)
        self.assertIn("successful", remaining)
        self.assertIn("protected", remaining)

    def test_parallel_probe_writes_are_serialized(self) -> None:
        node_history.sync_snapshot(self.db_path, [make_node("node-a", "198.51.100.40")], now=100)
        errors: list[Exception] = []

        def worker() -> None:
            try:
                for _ in range(10):
                    node_history.record_probe_results(
                        self.db_path,
                        [{"id": "node-a", "probe_status": "available", "probe_message": "ok"}],
                    )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual([], errors)
        self.assertEqual(80, self.row("node-a")["probe_success_count"])


if __name__ == "__main__":
    unittest.main()
