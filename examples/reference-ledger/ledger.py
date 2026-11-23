"""Small authenticated SQLite workload for disposable recovery qualification."""

import argparse
from contextlib import closing
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import signal
import socket
import socketserver
import sys


class UnqualifiedState(ValueError):
    """Existing application state cannot be accepted without reconciliation."""


IDENTITY_SQL = "CREATE TABLE identity (instance_id TEXT NOT NULL)"
ENTRIES_SQL = "CREATE TABLE entries (sequence INTEGER PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE, value TEXT NOT NULL)"
SCHEMA = [
    ("table", "entries", "entries", ENTRIES_SQL),
    ("table", "identity", "identity", IDENTITY_SQL),
    ("index", "sqlite_autoindex_entries_1", "entries", None),
]


def private_path(path, directory=False):
    path = Path(path)
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise UnqualifiedState("application-storage-unqualified")
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise UnqualifiedState("application-storage-unqualified")
    return path


def validate_identity(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "instance_id", "uid", "token"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or type(value["uid"]) is not int
        or value["uid"] != os.geteuid()
        or not isinstance(value["instance_id"], str)
        or not re.fullmatch("[a-f0-9]{32}", value["instance_id"])
        or not isinstance(value["token"], str)
        or not re.fullmatch("[a-f0-9]{64}", value["token"])
    ):
        raise UnqualifiedState("application-identity-unqualified")


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def initialize(data, config, identity):
    """Explicit bootstrap only; partial or existing state is never adopted."""
    validate_identity(identity)
    data = private_path(data, directory=True)
    config = private_path(config, directory=True)
    if (
        data.resolve() == config.resolve()
        or any(data.iterdir())
        or any(config.iterdir())
    ):
        raise UnqualifiedState("application-storage-not-empty")
    try:
        descriptor = os.open(
            config / "application.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "w") as stream:
            json.dump(identity, stream)
            stream.flush()
            os.fsync(stream.fileno())
        sync_directory(config)
        descriptor = os.open(
            data / "ledger.sqlite3", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        os.close(descriptor)
        with closing(
            sqlite3.connect((data / "ledger.sqlite3").as_uri() + "?mode=rw", uri=True)
        ) as db:
            with db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute(IDENTITY_SQL)
                db.execute(
                    "INSERT INTO identity VALUES (?)", (identity["instance_id"],)
                )
                db.execute(ENTRIES_SQL)
                db.execute("PRAGMA user_version=1")
        sync_directory(data)
    except (OSError, sqlite3.Error):
        raise UnqualifiedState("application-bootstrap-incomplete") from None


class Ledger:
    def __init__(self, data, config):
        self.db = None
        self.writes_uncertain = False
        try:
            data = private_path(data, directory=True)
            config = private_path(config, directory=True)
            source = private_path(config / "application.json")
            if source.stat().st_size > 4096:
                raise UnqualifiedState("application-configuration-oversized")
            self.identity = json.loads(source.read_text())
            validate_identity(self.identity)
            database = private_path(data / "ledger.sqlite3")
            self.db = sqlite3.connect(
                database.as_uri() + "?mode=rw", uri=True, isolation_level=None
            )
            self.db.execute("PRAGMA synchronous=FULL")
            if (
                self.db.execute("PRAGMA user_version").fetchone() != (1,)
                or self.db.execute(
                    "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name"
                ).fetchall()
                != SCHEMA
                or self.db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]
                or self.db.execute("SELECT instance_id FROM identity").fetchall()
                != [(self.identity["instance_id"],)]
            ):
                raise UnqualifiedState("application-database-unqualified")
            self.db.execute("SELECT sequence, operation_id, value FROM entries LIMIT 0")
        except (OSError, sqlite3.Error, ValueError):
            if self.db is not None:
                self.db.close()
            raise UnqualifiedState("application-state-unqualified") from None

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.db.close()

    def request(self, command):
        if (
            not isinstance(command, dict)
            or not isinstance(command.get("token"), str)
            or not re.fullmatch("[a-f0-9]{64}", command["token"])
            or not hmac.compare_digest(
                command["token"].encode(), self.identity["token"].encode()
            )
        ):
            return {"outcome": "unauthorized"}
        if command.get("action") == "read" and set(command) == {"action", "token"}:
            rows = self.db.execute(
                "SELECT sequence, operation_id, value FROM entries ORDER BY sequence"
            ).fetchall()
            return {
                "outcome": "read",
                "instance_id": self.identity["instance_id"],
                "entries": [
                    dict(zip(("sequence", "operation_id", "value"), row))
                    for row in rows
                ],
            }
        if (
            set(command) != {"action", "token", "operation_id", "value"}
            or command["action"] != "append"
            or not isinstance(command["operation_id"], str)
            or not re.fullmatch("[a-f0-9]{32}", command["operation_id"])
            or not isinstance(command["value"], str)
        ):
            return {"outcome": "invalid-request"}
        try:
            if len(command["value"].encode()) > 65536:
                return {"outcome": "invalid-request"}
        except UnicodeError:
            return {"outcome": "invalid-request"}
        if self.writes_uncertain:
            return {"outcome": "uncertain"}
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT sequence, value FROM entries WHERE operation_id=?",
                (command["operation_id"],),
            ).fetchone()
            if row:
                self.db.execute("ROLLBACK")
                if row[1] != command["value"]:
                    return {"outcome": "conflict"}
                return {"outcome": "unchanged", "sequence": row[0]}
            cursor = self.db.execute(
                "INSERT INTO entries (operation_id, value) VALUES (?, ?)",
                (command["operation_id"], command["value"]),
            )
            self.db.execute("COMMIT")
            committed = self.db.execute(
                "SELECT sequence, value FROM entries WHERE operation_id=?",
                (command["operation_id"],),
            ).fetchone()
            if (
                committed != (cursor.lastrowid, command["value"])
                or not isinstance(cursor.lastrowid, int)
                or cursor.lastrowid < 1
            ):
                self.writes_uncertain = True
                return {"outcome": "uncertain"}
            return {"outcome": "committed", "sequence": cursor.lastrowid}
        except sqlite3.Error:
            self.writes_uncertain = True
            try:
                self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return {"outcome": "uncertain"}


def serve(app, endpoint):
    endpoint = Path(endpoint)
    private_path(endpoint.parent, directory=True)
    if os.path.lexists(endpoint):
        raise UnqualifiedState("application-socket-exists")

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(5)
            try:
                raw = self.rfile.readline(70001)
                if len(raw) > 70000 or not raw.endswith(b"\n"):
                    result = {"outcome": "invalid-request"}
                else:
                    result = app.request(json.loads(raw))
                self.wfile.write((json.dumps(result) + "\n").encode())
            except (OSError, ValueError, sqlite3.Error):
                try:
                    self.wfile.write(b'{"outcome":"unavailable"}\n')
                except OSError:
                    pass

    def stop(*unused):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    with socketserver.UnixStreamServer(str(endpoint), Handler) as server:
        identity = endpoint.lstat()
        endpoint.chmod(0o600)
        try:
            server.serve_forever(poll_interval=0.1)
        finally:
            if os.path.lexists(endpoint):
                current = endpoint.lstat()
                if (current.st_dev, current.st_ino) == (
                    identity.st_dev,
                    identity.st_ino,
                ):
                    endpoint.unlink()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("init", "serve", "request"))
    parser.add_argument("--data", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--socket", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "request":
            if args.socket is None:
                raise UnqualifiedState("socket-required")
            command = sys.stdin.buffer.read(70001)
            if len(command) > 70000:
                raise UnqualifiedState("request-oversized")
            command = (
                json.dumps(json.loads(command), ensure_ascii=False) + "\n"
            ).encode()
            if len(command) > 70000:
                raise UnqualifiedState("request-oversized")
            with socket.socket(socket.AF_UNIX) as channel:
                channel.settimeout(10)
                channel.connect(str(args.socket))
                channel.sendall(command)
                response = channel.makefile("rb").readline(8 * 1024 * 1024)
                result = json.loads(response)
        else:
            if args.data is None or args.config is None:
                raise UnqualifiedState("storage-required")
            if args.action == "init":
                raw = sys.stdin.buffer.read(4097)
                if len(raw) > 4096:
                    raise UnqualifiedState("identity-oversized")
                initialize(args.data, args.config, json.loads(raw))
                result = {"outcome": "initialized"}
            else:
                if args.socket is None:
                    raise UnqualifiedState("socket-required")
                with Ledger(args.data, args.config) as app:
                    serve(app, args.socket)
                return 0
    except (OSError, ValueError, sqlite3.Error):
        print(json.dumps({"outcome": "refused"}))
        return 1
    print(json.dumps(result))
    return (
        0
        if result["outcome"] in ("initialized", "read", "committed", "unchanged")
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
