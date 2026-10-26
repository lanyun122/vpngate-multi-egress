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
            include_current=True,
            now=100,
        )

        self.assertEqual(["jp-b"], [node["id"] for node in selected])
        self.assertTrue(selected[0]["history_only"])
        self.assertEqual("not_checked", selected[0]["probe_status"])
        self.assertNotIn("config_file", selected[0])

    def test_large_fresh_pool_cannot_starve_due_history_node(self) -> None:
        old_node = make_node("old-node", "203.0.113.200", country_short="JP")
        node_history.sync_snapshot(self.db_path, [old_node], now=100)

        fresh_nodes = [
            make_node(
                f"fresh-{index}",
                f"198.51.{index // 250}.{index % 250 + 1}",
                country_short="JP",
            )
            for index in range(300)
        ]
        node_history.sync_snapshot(self.db_path, fresh_nodes, now=200)

        selected = node_history.select_workset(
            self.db_path,
            limit=25,
            country_codes=["JP"],
            exclude_endpoint_keys=[
                node_history.endpoint_key(node)
                for node in fresh_nodes
            ],
            now=200,
        )

        self.assertIn("old-node", [node["id"] for node in selected])
        self.assertNotIn("fresh-0", [node["id"] for node in selected])

    def test_current_pool_can_be_reused_only_when_explicitly_allowed(self) -> None:
        current = make_node(
            "current-node",
            "198.51.100.50",
            country_short="JP",
            probe_status="available",
        )
        node_history.sync_snapshot(self.db_path, [current], now=100)

        # A successful node is normally not due again for one day. Source
        # outage recovery must still be able to rebuild from that current pool.
        normal = node_history.select_workset(self.db_path, limit=5, now=101)
        fallback = node_history.select_workset(
            self.db_path,
            limit=5,
            include_current=True,
            now=101,
        )

        self.assertEqual([], normal)
        self.assertEqual(["current-node"], [node["id"] for node in fallback])

    def test_invalid_config_can_be_archived(self) -> None:
        node = make_node("invalid-node", "198.51.100.60")
        node_history.sync_snapshot(self.db_path, [node], now=100)

        changed = node_history.archive_node(
            self.db_path,
            "invalid-node",
            message="invalid config",
            now=200,
        )

        self.assertTrue(changed)
        self.assertEqual(1, self.row("invalid-node")["archived"])
        self.assertEqual(
            [],
            node_history.select_workset(
                self.db_path,
                limit=5,
                include_current=True,
                now=200,
            ),
        )

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

    def test_successful_nodes_are_rechecked_after_one_day(self) -> None:
        self.assertEqual(24 * 60 * 60, node_history.SUCCESS_RECHECK_SECONDS)
        node_history.sync_snapshot(self.db_path, [make_node("daily", "198.51.100.70")], now=100)
        node_history.record_probe_results(
            self.db_path,
            [{"id": "daily", "probe_status": "available", "probe_message": "ok"}],
            now=200,
        )
        self.assertEqual(200 + 24 * 60 * 60, self.row("daily")["next_probe_at"])

    def test_fair_probe_plan_reserves_all_three_queues(self) -> None:
        untested = [make_node(f"untested-{index:02d}", f"198.51.1.{index + 1}") for index in range(15)]
        known_good = [make_node(f"good-{index:02d}", f"198.51.2.{index + 1}") for index in range(8)]
        retry = [make_node(f"retry-{index:02d}", f"198.51.3.{index + 1}") for index in range(8)]
        all_nodes = untested + known_good + retry
        node_history.sync_snapshot(self.db_path, all_nodes, now=100)

        with sqlite3.connect(self.db_path) as connection:
            for index, node in enumerate(untested):
                connection.execute(
                    "UPDATE node_history SET next_probe_at = ?, last_probe_at = 0 WHERE node_id = ?",
                    (10 + index, node["id"]),
                )
            for index, node in enumerate(known_good):
                connection.execute(
                    """
                    UPDATE node_history
                    SET last_probe_status = 'available', probe_success_count = 1,
                        consecutive_failures = 0, last_probe_at = ?, next_probe_at = ?
                    WHERE node_id = ?
                    """,
                    (20 + index, 30 + index, node["id"]),
                )
            for index, node in enumerate(retry):
                connection.execute(
                    """
                    UPDATE node_history
                    SET last_probe_status = 'unavailable', probe_failure_count = 1,
                        consecutive_failures = 1, last_probe_at = ?, next_probe_at = ?
                    WHERE node_id = ?
                    """,
                    (40 + index, 50 + index, node["id"]),
                )
            connection.commit()

        plan = node_history.select_probe_plan(
            self.db_path,
            untested_limit=10,
            known_good_limit=5,
            retry_limit=5,
            now=1_000,
        )
        buckets = {
            name: [node["id"] for node in plan if node["probe_queue"] == name]
            for name in ("untested", "known_good", "retry")
        }

        self.assertEqual([node["id"] for node in untested[:10]], buckets["untested"])
        self.assertEqual([node["id"] for node in known_good[:5]], buckets["known_good"])
        self.assertEqual([node["id"] for node in retry[:5]], buckets["retry"])
        self.assertEqual(20, len({node["id"] for node in plan}))

    def test_history_statistics_have_unambiguous_queue_counts(self) -> None:
        available_a = make_node("available-a", "198.51.100.80", port=443)
        available_b = make_node("available-b", "198.51.100.80", port=8443)
        untested = make_node("untested", "198.51.100.81")
        retry_due = make_node("retry-due", "198.51.100.82")
        retry_cooldown = make_node("retry-cooldown", "198.51.100.83")
        node_history.sync_snapshot(
            self.db_path,
            [available_a, available_b, untested, retry_due, retry_cooldown],
            now=100,
        )

        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                UPDATE node_history
                SET last_probe_status = 'available', probe_success_count = 1,
                    consecutive_failures = 0, next_probe_at = 200
                WHERE node_id IN ('available-a', 'available-b')
                """
            )
            connection.execute(
                "UPDATE node_history SET next_probe_at = 50 WHERE node_id = 'untested'"
            )
            connection.execute(
                """
                UPDATE node_history
                SET last_probe_status = 'unavailable', probe_failure_count = 1,
                    consecutive_failures = 1, next_probe_at = 50
                WHERE node_id = 'retry-due'
                """
            )
            connection.execute(
                """
                UPDATE node_history
                SET last_probe_status = 'unavailable', probe_failure_count = 1,
                    consecutive_failures = 1, next_probe_at = 200
                WHERE node_id = 'retry-cooldown'
                """
            )
            connection.commit()

        stats = node_history.statistics(self.db_path, now=100)
        self.assertEqual(1, stats["history_available_unique_ips"])
        self.assertEqual(1, stats["history_untested_due"])
        self.assertEqual(1, stats["history_retest_due"])
        self.assertEqual(1, stats["history_failure_cooldown"])

    def test_connection_failure_clears_confirmed_available_state(self) -> None:
        node_history.sync_snapshot(self.db_path, [make_node("node-a", "198.51.100.90")], now=100)
        node_history.record_probe_results(
            self.db_path,
            [{"id": "node-a", "probe_status": "available", "probe_message": "ok"}],
            now=200,
        )

        node_history.record_connection_result(
            self.db_path,
            "node-a",
            success=False,
            message="handshake failed",
            now=300,
        )

        row = self.row("node-a")
        self.assertEqual("unavailable", row["last_probe_status"])
        self.assertEqual(300, row["last_probe_at"])
        self.assertEqual(1, row["consecutive_failures"])

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
