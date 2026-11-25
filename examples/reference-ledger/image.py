"""Prepare only the replaceable image of an offline unprivileged reference LXC."""

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import sqlite3
import stat
import subprocess
import sys

ROOT = Path("/")
ROOT_UID = ROOT_GID = 0
PROGRAM_SHA256 = "7dcf85b94609f8c8cab13fed97ce78fff23a2beb66938484a1aa00d484137542"
PROGRAM = "/opt/reference-ledger/ledger.py"
UNIT_NAME = "reference-ledger.service"
UNIT_PATH = "/etc/systemd/system/" + UNIT_NAME
CLAIM = "/var/lib/cmdmesh-reference-image"
RETAINED = (
    "/var/lib/reference-ledger",
    "/etc/reference-ledger",
    "/run/reference-ledger",
)
ACCOUNT = {
    "name": "reference-ledger",
    "uid": 1100,
    "gid": 1100,
    "group": "reference-ledger",
    "home": "/nonexistent",
    "shell": "/usr/sbin/nologin",
    "locked": True,
}
GROUPADD = ["/usr/sbin/groupadd", "--gid", "1100", "reference-ledger"]
USERADD = [
    "/usr/sbin/useradd",
    "--system",
    "-K",
    "SYS_UID_MAX=1100",
    "--uid",
    "1100",
    "--gid",
    "1100",
    "--no-create-home",
    "--no-user-group",
    "--no-log-init",
    "--home-dir",
    "/nonexistent",
    "--shell",
    "/usr/sbin/nologin",
    "reference-ledger",
]
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


class ImageError(ValueError):
    def __init__(self, code):
        self.code = code
        self.mutation_attempted = False
        self.effects_may_exist = False
        super().__init__(code)


def require(value, code="reference-image-invalid-state"):
    if not value:
        raise ImageError(code)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def path(name):
    return ROOT / name.lstrip("/")


def service_unit():
    return (
        "[Unit]\nDescription=CmdMesh reference ledger\nAfter=local-fs.target\n\n[Service]\nType=simple\n"
        "User=1100\nGroup=1100\nUMask=0077\nNoNewPrivileges=yes\nRuntimeDirectory=reference-ledger\nRuntimeDirectoryMode=0700\n"
        "ExecStart=/usr/bin/python3 -I -S -B /opt/reference-ledger/ledger.py serve --data /var/lib/reference-ledger --config /etc/reference-ledger --socket /run/reference-ledger/api.sock\n"
        "Restart=no\n\n[Install]\nWantedBy=multi-user.target\n"
    ).encode()


def captured(argv):
    result = subprocess.run(
        argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=30, env=ENV
    )
    require(len(result.stdout) <= 65536 and len(result.stderr) <= 4096)
    return {
        "code": result.returncode,
        "stdout": result.stdout.decode(),
        "stderr": result.stderr.decode(),
    }


def command(argv):
    result = captured(argv)
    require(
        result["code"] == 0 and result["stderr"] == "", "reference-image-command-failed"
    )
    return result


def environment():
    maps = lambda name: [
        [int(part) for part in row.split()]
        for row in path("/proc/self/" + name).read_text().splitlines()
    ]
    return {
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "uid_map": maps("uid_map"),
        "gid_map": maps("gid_map"),
        "interfaces": sorted(name for _, name in socket.if_nameindex()),
        "python": list(sys.version_info[:3]),
        "sqlite": sqlite3.sqlite_version,
        "systemd": captured(["/usr/bin/systemctl", "is-system-running"]),
        "failed": captured(
            ["/usr/bin/systemctl", "--failed", "--plain", "--no-legend", "--no-pager"]
        ),
    }


def validate_environment(value):
    require(
        type(value["uid"]) is int
        and value["uid"] == 0
        and type(value["gid"]) is int
        and value["gid"] == 0,
        "reference-image-root-required",
    )
    mapping = [[0, 100000, 65536]]
    require(
        canonical(value["uid_map"]) == canonical(mapping)
        and canonical(value["gid_map"]) == canonical(mapping),
        "reference-image-unprivileged-map-mismatch",
    )
    require(value["interfaces"] == ["lo"], "reference-image-network-not-isolated")
    require(value["python"][:2] == [3, 12], "reference-image-python-unsupported")
    require(
        tuple(int(part) for part in value["sqlite"].split(".")) >= (3, 37, 0),
        "reference-image-sqlite-unsupported",
    )
    require(
        value["systemd"] == {"code": 0, "stdout": "running\n", "stderr": ""}
        and value["failed"] == {"code": 0, "stdout": "", "stderr": ""},
        "reference-image-os-not-ready",
    )


def regular(name, limit=1048576):
    p = path(name)
    require(p.resolve(strict=True) == p)
    info = p.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == ROOT_UID
        and info.st_nlink == 1
        and not info.st_mode & 0o022
        and 0 <= info.st_size <= limit
    )
    raw = p.read_bytes()
    closing = p.lstat()
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    require(identity(info) == identity(closing) and len(raw) == info.st_size)
    return raw, identity(info)


ACCOUNT_DATABASES = ("passwd", "group", "shadow", "gshadow")
SUBID_DATABASES = ("subuid", "subgid")


def account_data():
    raw, facts = {}, {}
    for name in (*ACCOUNT_DATABASES, *SUBID_DATABASES):
        if name in SUBID_DATABASES and not os.path.lexists(path("/etc/" + name)):
            raw[name] = facts[name] = None
            continue
        body, identity = regular("/etc/" + name)
        raw[name] = body
        facts[name] = {"sha256": digest(body), "identity": list(identity)}
    return raw, facts


def account_files():
    return account_data()[1]


def accounts():
    raw, facts = account_data()
    users, groups = pwd.getpwall(), grp.getgrall()
    target = next(
        (value for value in users if value.pw_name == "reference-ledger"), None
    )
    group = next(
        (value for value in groups if value.gr_name == "reference-ledger"), None
    )
    shadow = [
        line.split(b":")
        for line in raw["shadow"].splitlines()
        if line.startswith(b"reference-ledger:")
    ]
    account = None
    if target is not None and group is not None:
        account = {
            "name": target.pw_name,
            "uid": target.pw_uid,
            "gid": target.pw_gid,
            "group": group.gr_name,
            "home": target.pw_dir,
            "shell": target.pw_shell,
            "locked": len(shadow) == 1 and shadow[0][1].startswith((b"!", b"*")),
        }
    processes = {"uid_processes": [], "gid_processes": []}
    for status in path("/proc").glob("[0-9]*/status"):
        try:
            fields = dict(
                row.split(":", 1)
                for row in status.read_text().splitlines()
                if ":" in row
            )
        except FileNotFoundError:
            continue
        if "1100" in fields.get("Uid", "").split():
            processes["uid_processes"].append(int(status.parent.name))
        if "1100" in fields.get("Gid", "").split() + fields.get("Groups", "").split():
            processes["gid_processes"].append(int(status.parent.name))
    require(
        canonical(account_files()) == canonical(facts),
        "reference-image-account-files-changed",
    )
    return {
        "uid_owners": sorted(value.pw_name for value in users if value.pw_uid == 1100),
        "gid_owners": sorted(value.gr_name for value in groups if value.gr_gid == 1100),
        "names_used": target is not None or group is not None,
        "account": account,
        **processes,
        "home_exists": os.path.lexists(path("/nonexistent")),
        "base": {
            name: digest(
                b"".join(
                    row
                    for row in body.splitlines(keepends=True)
                    if not row.startswith(b"reference-ledger:")
                )
            )
            for name in ACCOUNT_DATABASES
            for body in (raw[name],)
        },
        "subids": {
            name: digest(raw[name]) if raw[name] is not None else None
            for name in SUBID_DATABASES
        },
        "files": facts,
    }


def unit():
    fields = "LoadState,ActiveState,SubState,MainPID,UnitFileState,User,Group,DropInPaths,FragmentPath"
    result = captured(["/usr/bin/systemctl", "show", UNIT_NAME, "-p", fields])
    require(result["code"] in {0, 1} and not result["stderr"])
    values = {}
    for row in result["stdout"].splitlines():
        key, separator, value = row.partition("=")
        require(separator == "=" and key not in values)
        values[key] = value
    require(set(values) == set(fields.split(",")))
    return values


def validate_no_writer(value):
    require(
        value["uid_processes"] == value["gid_processes"] == []
        and value["home_exists"] is False
    )


def validate_absent():
    require(
        all(not os.path.lexists(path(name)) for name in RETAINED),
        "reference-image-retained-path-present",
    )


def directory(name, mode=None):
    p = path(name)
    require(p.resolve(strict=True) == p)
    info = p.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == ROOT_UID
        and info.st_gid == ROOT_GID
        and not info.st_mode & 0o022
    )
    if mode is not None:
        require(stat.S_IMODE(info.st_mode) == mode)


def blank(program):
    env = environment()
    validate_environment(env)
    validate_absent()
    require(
        not os.path.lexists(path(PROGRAM).parent)
        and not os.path.lexists(path(UNIT_PATH)),
        "reference-image-artifact-path-present",
    )
    for name in ("/opt", "/etc/systemd/system", "/var/lib"):
        directory(name)
    account = accounts()
    validate_no_writer(account)
    require(
        account["uid_owners"] == account["gid_owners"] == []
        and account["names_used"] is False
        and account["account"] is None,
        "reference-image-account-collision",
    )
    loaded = unit()
    require(
        loaded["LoadState"] == "not-found"
        and loaded["ActiveState"] == "inactive"
        and loaded["MainPID"] == "0"
        and loaded["DropInPaths"] == ""
    )
    require(
        canonical(account_files()) == canonical(account["files"]),
        "reference-image-account-files-changed",
    )
    validate_absent()
    require(
        not os.path.lexists(path(PROGRAM).parent)
        and not os.path.lexists(path(UNIT_PATH)),
        "reference-image-artifact-path-present",
    )
    return {
        "environment": env,
        "accounts": account,
        "unit": loaded,
        "program_sha256": digest(program),
        "unit_sha256": digest(service_unit()),
    }


def sync_directory(p):
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_blob(p, raw, mode):
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(fd, remaining)
            require(written > 0)
            remaining = remaining[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_directory(p.parent)


def write_json(p, value):
    raw = canonical(value)
    write_blob(p, raw, 0o600)
    return digest(raw)


def read_as_application():
    source = "import hashlib,json,os,pathlib;os.setgroups([]);os.setgid(1100);os.setuid(1100);p=pathlib.Path('/opt/reference-ledger/ledger.py');raw=p.read_bytes();compile(raw,str(p),'exec');print(json.dumps({'uid':os.geteuid(),'gid':os.getegid(),'sha256':hashlib.sha256(raw).hexdigest(),'compiled':True}))"
    return json.loads(
        command(["/usr/bin/python3", "-I", "-S", "-B", "-c", source])["stdout"]
    )


def observe_image(program, before):
    env = environment()
    validate_environment(env)
    validate_absent()
    current = unit()
    require(
        current
        == {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "SubState": "dead",
            "MainPID": "0",
            "UnitFileState": "disabled",
            "User": "1100",
            "Group": "1100",
            "DropInPaths": "",
            "FragmentPath": UNIT_PATH,
        }
    )
    child = read_as_application()
    require(
        child == {"uid": 1100, "gid": 1100, "sha256": PROGRAM_SHA256, "compiled": True}
    )
    account = accounts()
    validate_no_writer(account)
    require(
        account["uid_owners"] == account["gid_owners"] == ["reference-ledger"]
        and account["names_used"] is True
        and canonical(account["account"]) == canonical(ACCOUNT)
    )
    require(
        canonical(account["base"]) == canonical(before["accounts"]["base"])
        and canonical(account["subids"]) == canonical(before["accounts"]["subids"]),
        "reference-image-account-drift",
    )
    closing_environment = environment()
    validate_environment(closing_environment)
    closing_unit = unit()
    require(
        canonical(closing_environment) == canonical(env)
        and canonical(closing_unit) == canonical(current),
        "reference-image-state-changed",
    )
    validate_absent()
    require(
        canonical(account_files()) == canonical(account["files"]),
        "reference-image-account-files-changed",
    )
    directory("/opt/reference-ledger", 0o755)
    artifacts = {}
    for name, expected in ((PROGRAM, program), (UNIT_PATH, service_unit())):
        raw, identity = regular(name, 65536)
        require(
            raw == expected
            and identity[4] == ROOT_GID
            and stat.S_IMODE(identity[2]) == 0o644,
            "reference-image-installed-artifact-mismatch",
        )
        artifacts[name] = {"sha256": digest(raw), "identity": list(identity)}
    return {
        "environment": env,
        "accounts": account,
        "unit": current,
        "application_read": child,
        "artifacts": artifacts,
    }


def program_check(program):
    require(
        type(program) is bytes
        and 0 < len(program) <= 65536
        and digest(program) == PROGRAM_SHA256,
        "reference-image-artifact-mismatch",
    )


def prepare(program, *, allow_changes=False, check_mode=False):
    program_check(program)
    require(check_mode or allow_changes, "reference-image-changes-disabled")
    require(not os.path.lexists(path(CLAIM)), "reference-image-attempt-consumed")
    before = blank(program)
    if check_mode:
        return {
            "assessment": "image-preflight-only",
            "changed": False,
            "would_change": True,
            "image_verified": False,
            "before": before,
        }
    claim = path(CLAIM)
    owned = False
    stage = "claim"
    try:
        claim.mkdir(mode=0o700)
        owned = True
        claim.chmod(0o700)
        sync_directory(claim.parent)
        write_json(claim / "intent.json", {"schema_version": 1, "before": before})
        stage = "group"
        command(GROUPADD)
        stage = "account"
        command(USERADD)
        created = accounts()
        validate_no_writer(created)
        require(
            canonical(created["account"]) == canonical(ACCOUNT)
            and created["base"] == before["accounts"]["base"]
            and created["subids"] == before["accounts"]["subids"]
        )
        stage = "artifact-publication"
        program_directory = path(PROGRAM).parent
        program_directory.mkdir(mode=0o755)
        program_directory.chmod(0o755)
        sync_directory(program_directory.parent)
        write_blob(path(PROGRAM), program, 0o644)
        write_blob(path(UNIT_PATH), service_unit(), 0o644)
        stage = "guest-manager-reload"
        command(["/usr/bin/systemctl", "daemon-reload"])
        stage = "postcheck"
        after = observe_image(program, before)
        complete = {
            "assessment": "image-prepared",
            "changed": True,
            "image_verified": True,
            "before": before,
            "after": after,
        }
        stage = "completion"
        checksum = write_json(claim / "complete.json", complete)
        stage = "closing-postcheck"
        require(canonical(observe_image(program, before)) == canonical(after))
        return {**complete, "completion_sha256": checksum}
    except BaseException as error:
        error.mutation_attempted = True
        error.effects_may_exist = owned or not isinstance(error, FileExistsError)
        error.stage = stage
        if owned:
            try:
                write_json(
                    claim / "failed.json",
                    {
                        "error_code": getattr(
                            error, "code", "reference-image-incomplete"
                        ),
                        "stage": stage,
                    },
                )
            except OSError:
                pass
        raise


def inspect_image(program):
    program_check(program)
    env = environment()
    validate_environment(env)
    directory(CLAIM, 0o700)
    raw, _ = regular(CLAIM + "/intent.json")
    intent = json.loads(raw)
    require(
        raw == canonical(intent)
        and set(intent) == {"schema_version", "before"}
        and type(intent["schema_version"]) is int
        and intent["schema_version"] == 1
        and intent["before"]["program_sha256"] == PROGRAM_SHA256
        and intent["before"]["unit_sha256"] == digest(service_unit())
    )
    after = observe_image(program, intent["before"])
    return {
        "assessment": "observed",
        "changed": False,
        "image_verified": True,
        "after": after,
        "attempt_failure_present": os.path.lexists(path(CLAIM + "/failed.json")),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "install", "inspect"))
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--program", type=Path)
    source.add_argument("--program-hex")
    parser.add_argument("--allow-changes", action="store_true")
    args = parser.parse_args()
    try:
        if args.program_hex is not None:
            require(len(args.program_hex) <= 131072)
            program = bytes.fromhex(args.program_hex)
        else:
            require(
                args.program.is_file()
                and not args.program.is_symlink()
                and args.program.stat().st_size <= 65536
            )
            program = args.program.read_bytes()
        if args.action == "inspect":
            require(not args.allow_changes)
            result = inspect_image(program)
        else:
            require(args.action == "install" or not args.allow_changes)
            result = prepare(
                program,
                allow_changes=args.allow_changes,
                check_mode=args.action == "check",
            )
    except Exception as error:
        print(
            json.dumps(
                {
                    "assessment": "refused",
                    "image_verified": False,
                    "error_code": getattr(
                        error, "code", "reference-image-observation-failed"
                    ),
                    "failed_stage": getattr(error, "stage", None),
                    "mutation_attempted": getattr(error, "mutation_attempted", False),
                    "effects_may_exist": getattr(error, "effects_may_exist", False),
                    "recovery": "Preserve partial files and the consumed image claim. Inspect current image state without replaying installation.",
                }
            )
        )
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
