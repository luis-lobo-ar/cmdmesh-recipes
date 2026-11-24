"""Observable reference application state for later disposable recovery trials."""

import importlib.util
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "reference_ledger", ROOT / "examples/reference-ledger/ledger.py"
)
ledger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ledger)


class ReferenceLedger(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".generated"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="", dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        self.config = self.root / "config"
        self.data.mkdir(mode=0o700)
        self.config.mkdir(mode=0o700)
        self.identity = {
            "schema_version": 1,
            "instance_id": "a" * 32,
            "uid": os.geteuid(),
            "token": "b" * 64,
        }

    def initialize(self):
        ledger.initialize(self.data, self.config, self.identity)

    def test_committed_record_and_credentials_survive_reopening(self):
        self.initialize()
        with ledger.Ledger(self.data, self.config) as app:
            result = app.request(
                {
                    "action": "append",
                    "token": self.identity["token"],
                    "operation_id": "c" * 32,
                    "value": "kept payload",
                }
            )
            self.assertEqual(result["outcome"], "committed")
        with ledger.Ledger(self.data, self.config) as app:
            result = app.request({"action": "read", "token": self.identity["token"]})
            self.assertEqual(result["instance_id"], self.identity["instance_id"])
            self.assertEqual(
                result["entries"],
                [{"sequence": 1, "operation_id": "c" * 32, "value": "kept payload"}],
            )

    def test_startup_never_creates_missing_application_state(self):
        self.initialize()
        (self.data / "ledger.sqlite3").unlink()
        with self.assertRaises(ledger.UnqualifiedState):
            ledger.Ledger(self.data, self.config)
        self.assertEqual(list(self.data.iterdir()), [])

    def test_second_process_cannot_start_for_the_same_retained_identity(self):
        self.initialize()
        with ledger.Ledger(self.data, self.config) as app:
            child = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/reference-ledger/ledger.py"),
                    "serve",
                    "--data",
                    str(self.data),
                    "--config",
                    str(self.config),
                    "--socket",
                    str(self.root / "second.sock"),
                ],
                capture_output=True,
                timeout=2,
            )
            self.assertEqual(child.returncode, 1)
            self.assertEqual(json.loads(child.stdout), {"outcome": "refused"})
            self.assertFalse((self.root / "second.sock").exists())
            self.assertEqual(
                app.request({"action": "read", "token": self.identity["token"]})[
                    "outcome"
                ],
                "read",
            )
        # A normal stop releases ownership for the replacement process.
        with ledger.Ledger(self.data, self.config) as replacement:
            self.assertEqual(replacement.identity, self.identity)

    def test_failed_database_open_releases_the_retained_identity_lock(self):
        self.initialize()
        database = self.data / "ledger.sqlite3"
        saved = self.root / "saved.sqlite3"
        database.rename(saved)
        with self.assertRaises(ledger.UnqualifiedState):
            ledger.Ledger(self.data, self.config)
        saved.rename(database)
        with ledger.Ledger(self.data, self.config) as replacement:
            self.assertEqual(replacement.identity, self.identity)

    def test_wrong_identity_uid_or_permissions_cannot_open(self):
        self.initialize()
        original = json.loads((self.config / "application.json").read_text())
        for key, value in [("instance_id", "e" * 32), ("uid", os.geteuid() + 1)]:
            (self.config / "application.json").write_text(
                json.dumps({**original, key: value})
            )
            with self.subTest(key=key), self.assertRaises(ledger.UnqualifiedState):
                ledger.Ledger(self.data, self.config)
        (self.config / "application.json").write_text(json.dumps(original))
        self.data.chmod(0o755)
        with self.assertRaises(ledger.UnqualifiedState):
            ledger.Ledger(self.data, self.config)

    def test_authentication_failure_does_not_add_a_record(self):
        self.initialize()
        with ledger.Ledger(self.data, self.config) as app:
            refused = app.request(
                {
                    "action": "append",
                    "token": "wrong-secret",
                    "operation_id": "c" * 32,
                    "value": "not saved",
                }
            )
            self.assertEqual(refused, {"outcome": "unauthorized"})
            self.assertEqual(
                app.request({"action": "read", "token": self.identity["token"]})[
                    "entries"
                ],
                [],
            )

    def test_matching_retry_is_idempotent_and_conflict_preserves_original(self):
        self.initialize()
        with ledger.Ledger(self.data, self.config) as app:
            command = {
                "action": "append",
                "token": self.identity["token"],
                "operation_id": "c" * 32,
                "value": "original",
            }
            self.assertEqual(app.request(command)["outcome"], "committed")
            self.assertEqual(app.request(command)["outcome"], "unchanged")
            self.assertEqual(
                app.request({**command, "value": "conflict"}), {"outcome": "conflict"}
            )
            self.assertEqual(
                app.request({"action": "read", "token": self.identity["token"]})[
                    "entries"
                ][0]["value"],
                "original",
            )

    def test_initialization_refuses_existing_or_symlinked_storage(self):
        self.initialize()
        with self.assertRaises(ledger.UnqualifiedState):
            self.initialize()
        alternate = self.root / "alternate"
        alternate.mkdir(mode=0o700)
        link = self.root / "link"
        link.symlink_to(alternate, target_is_directory=True)
        with self.assertRaises(ledger.UnqualifiedState):
            ledger.initialize(link, self.config, self.identity)

    def test_malformed_token_is_rejected_without_echo_or_write(self):
        self.initialize()
        with ledger.Ledger(self.data, self.config) as app:
            self.assertEqual(
                app.request({"action": "read", "token": "\ud800"}),
                {"outcome": "unauthorized"},
            )

    def test_full_database_never_reports_commit_and_freezes_further_writes(self):
        self.initialize()
        with ledger.Ledger(self.data, self.config) as app:
            pages = app.db.execute("PRAGMA page_count").fetchone()[0]
            app.db.execute("PRAGMA max_page_count=" + str(pages))
            command = {
                "action": "append",
                "token": self.identity["token"],
                "operation_id": "c" * 32,
                "value": "x" * 65536,
            }
            self.assertEqual(app.request(command), {"outcome": "uncertain"})
            self.assertEqual(
                app.request({**command, "operation_id": "d" * 32, "value": "small"}),
                {"outcome": "uncertain"},
            )
        with ledger.Ledger(self.data, self.config) as app:
            self.assertEqual(
                app.request({"action": "read", "token": self.identity["token"]})[
                    "entries"
                ],
                [],
            )

    def test_unexpected_trigger_refuses_startup(self):
        self.initialize()
        with sqlite3.connect(self.data / "ledger.sqlite3") as db:
            db.execute(
                "CREATE TRIGGER ignore_append BEFORE INSERT ON entries BEGIN SELECT RAISE(IGNORE); END"
            )
        db.close()
        with self.assertRaises(ledger.UnqualifiedState):
            ledger.Ledger(self.data, self.config)

    def test_success_requires_the_actual_committed_record(self):
        self.initialize()
        with ledger.Ledger(self.data, self.config) as app:
            app.db.execute(
                "CREATE TRIGGER ignore_append BEFORE INSERT ON entries BEGIN SELECT RAISE(IGNORE); END"
            )
            command = {
                "action": "append",
                "token": self.identity["token"],
                "operation_id": "c" * 32,
                "value": "must exist",
            }
            self.assertEqual(app.request(command), {"outcome": "uncertain"})
            self.assertEqual(
                app.request({"action": "read", "token": self.identity["token"]})[
                    "entries"
                ],
                [],
            )

    def test_unix_service_performs_authenticated_write_and_removes_only_its_socket(
        self,
    ):
        self.initialize()
        runtime = self.root / "r"
        runtime.mkdir(mode=0o700)
        endpoint = runtime / "s"
        process = subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "examples/reference-ledger/ledger.py"),
                "serve",
                "--data",
                str(self.data),
                "--config",
                str(self.config),
                "--socket",
                str(endpoint),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 5
            while not endpoint.exists():
                self.assertIsNone(
                    process.poll(),
                    process.stderr.read() if process.poll() is not None else "",
                )
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.02)
            with socket.socket(socket.AF_UNIX) as channel:
                channel.settimeout(3)
                channel.connect(str(endpoint))
                command = {
                    "action": "append",
                    "token": self.identity["token"],
                    "operation_id": "c" * 32,
                    "value": "socket entry",
                }
                channel.sendall((json.dumps(command) + "\n").encode())
                self.assertEqual(
                    json.loads(channel.makefile("rb").readline())["outcome"],
                    "committed",
                )
            client = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/reference-ledger/ledger.py"),
                    "request",
                    "--socket",
                    str(endpoint),
                ],
                input=json.dumps(
                    {"action": "read", "token": self.identity["token"]}, indent=2
                ),
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(client.returncode, 0, client.stderr)
            self.assertEqual(
                json.loads(client.stdout)["entries"][0]["value"], "socket entry"
            )
            self.assertNotIn(self.identity["token"], client.stdout + client.stderr)
        finally:
            process.terminate()
            output, errors = process.communicate(timeout=5)
        self.assertNotIn(self.identity["token"], output + errors)
        self.assertFalse(endpoint.exists())
        with ledger.Ledger(self.data, self.config) as app:
            self.assertEqual(
                app.request({"action": "read", "token": self.identity["token"]})[
                    "entries"
                ][0]["value"],
                "socket entry",
            )


if __name__ == "__main__":
    unittest.main()
