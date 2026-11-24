"""Read-only persistence checks for a managed, NIC-free reference LXC start.

Use an instance-specific ExecStartPre in both Proxmox normal/debug units. This
does not guard an administrator deliberately invoking lxc-start outside systemd.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT_UID = 0


class Refused(ValueError):
    """A named persistence precondition was not established."""


def require(value, reason):
    if not value:
        raise Refused(reason)


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def absolute(value):
    return (
        type(value) is str
        and value.startswith("/")
        and value != "/"
        and str(Path(value)) == value
        and ".." not in Path(value).parts
        and not any(c in value for c in "\r\n\0")
    )


def matches(pattern, value):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-field")
        result[key] = value
    return result


def decode(raw):
    def invalid(unused):
        raise Refused("non-finite-input")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def validate_policy(policy):
    require(
        type(policy) is dict
        and set(policy)
        == {
            "schema_version",
            "node",
            "vmid",
            "owner_tag",
            "generation_tag",
            "generated_config_sha256",
            "mapping",
            "rootfs",
            "datasets",
            "application",
        },
        "policy-shape",
    )
    require(
        type(policy["schema_version"]) is int and policy["schema_version"] == 1,
        "policy-version",
    )
    require(integer(policy["vmid"], 100, 999999), "target-invalid")
    require(matches(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", policy["node"]), "node-invalid")
    require(
        matches(r"cmdmesh-own-[a-f0-9]{32}", policy["owner_tag"])
        and matches(r"cmdmesh-gen-[a-f0-9]{32}", policy["generation_tag"]),
        "ownership-invalid",
    )
    require(
        matches(r"[a-f0-9]{64}", policy["generated_config_sha256"]),
        "generated-config-policy-invalid",
    )
    mapping = policy["mapping"]
    require(
        type(mapping) is dict
        and set(mapping) == {"offset", "length", "uid", "gid"}
        and integer(mapping["offset"], 65536, 2**32 - 65536)
        and mapping["length"] == 65536
        and type(mapping["length"]) is int
        and integer(mapping["uid"], 1, 65535)
        and integer(mapping["gid"], 1, 65535),
        "mapping-invalid",
    )
    root = policy["rootfs"]
    vmid = str(policy["vmid"])
    require(
        type(root) is dict
        and set(root) == {"volume", "path", "bytes", "inode", "uuid"}
        and matches(
            r"[A-Za-z0-9][A-Za-z0-9_-]*:"
            + vmid
            + r"/vm-"
            + vmid
            + r"-disk-[0-9]+\.raw",
            root["volume"],
        )
        and absolute(root["path"])
        and root["path"].endswith("/" + root["volume"].split(":", 1)[1])
        and integer(root["bytes"], 1024, 2**63 - 1)
        and integer(root["inode"], 1, 2**64 - 1)
        and matches(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", root["uuid"]),
        "rootfs-policy-invalid",
    )
    require(
        type(policy["datasets"]) is dict
        and set(policy["datasets"]) == {"data", "config"},
        "dataset-policy-invalid",
    )
    for item in policy["datasets"].values():
        require(
            type(item) is dict
            and set(item) == {"name", "guid", "mountpoint"}
            and matches(r"[A-Za-z][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)+", item["name"])
            and matches(r"[1-9][0-9]{0,19}", item["guid"])
            and int(item["guid"]) < 2**64
            and absolute(item["mountpoint"]),
            "dataset-policy-invalid",
        )
    data, config = (
        Path(policy["datasets"][role]["mountpoint"]) for role in ("data", "config")
    )
    require(
        data != config
        and data not in config.parents
        and config not in data.parents
        and policy["datasets"]["data"]["name"] != policy["datasets"]["config"]["name"]
        and policy["datasets"]["data"]["guid"] != policy["datasets"]["config"]["guid"],
        "shared-datasets",
    )
    app = policy["application"]
    require(
        type(app) is dict
        and set(app) == {"initialized", "instance_id", "config_sha256"}
        and app["initialized"] is True
        and matches(r"[a-f0-9]{32}", app["instance_id"])
        and matches(r"[a-f0-9]{64}", app["config_sha256"]),
        "application-uninitialized",
    )


def options(value):
    require(type(value) is str, "mount-options-invalid")
    path, *parts = value.split(",")
    pairs = [part.split("=", 1) for part in parts]
    require(
        all(len(row) == 2 for row in pairs) and len(pairs) == len(dict(pairs)),
        "mount-options-invalid",
    )
    return path, dict(pairs)


def private(value, uid, gid, directory=False):
    return (
        value.get("directory" if directory else "regular") is True
        and value["uid"] == uid
        and value["gid"] == gid
        and value["mode"] == (0o700 if directory else 0o600)
    )


def validate(policy, facts, vmid):
    validate_policy(policy)
    require(type(vmid) is int and vmid == policy["vmid"], "wrong-target")
    config = facts["config"]
    require(
        type(config) is dict and type(config.get("tags")) is str, "config-unqualified"
    )
    mapping = policy["mapping"]
    root = policy["rootfs"]
    require(
        config.get("unprivileged") == 1
        and type(config.get("unprivileged")) is int
        and not any(key in config for key in ("lxc", "features", "hookscript", "dev0"))
        and not any(key.startswith(("net", "dev")) for key in config),
        "guest-isolation-unqualified",
    )
    require(
        {key for key in config if re.fullmatch(r"mp[0-9]+", key)} == {"mp0", "mp1"},
        "unexpected-mounts",
    )
    tags = config.get("tags", "").split(";")
    require(
        [tag for tag in tags if tag.startswith("cmdmesh-own-")] == [policy["owner_tag"]]
        and [tag for tag in tags if tag.startswith("cmdmesh-gen-")]
        == [policy["generation_tag"]],
        "guest-ownership-mismatch",
    )
    volume, root_options = options(config["rootfs"])
    require(
        volume == root["volume"] and set(root_options) <= {"size"},
        "rootfs-volume-mismatch",
    )
    require(
        facts["id_maps"]
        == {
            "u": [[0, mapping["offset"], mapping["length"]]],
            "g": [[0, mapping["offset"], mapping["length"]]],
        },
        "mapping-mismatch",
    )
    require(
        facts["generated_config_sha256"] == policy["generated_config_sha256"],
        "generated-config-mismatch",
    )
    image = facts["rootfs"]
    require(
        image["resolved_path"] == root["path"]
        and image["regular"] is True
        and image["uid"] == ROOT_UID
        and not image["mode"] & 0o022
        and image["inode"] == root["inode"]
        and image["bytes"] == root["bytes"]
        and image["uuid"] == root["uuid"]
        and image["type"] == "ext4",
        "rootfs-identity-mismatch",
    )
    host_uid, host_gid = (
        mapping["offset"] + mapping["uid"],
        mapping["offset"] + mapping["gid"],
    )
    for index, role, target in (
        (0, "data", "/var/lib/reference-ledger"),
        (1, "config", "/etc/reference-ledger"),
    ):
        expected = policy["datasets"][role]
        actual = facts["datasets"][role]
        path, mount_options = options(config["mp" + str(index)])
        require(
            path == expected["mountpoint"]
            and mount_options == {"mp": target, "backup": "0"},
            role + "-bind-mismatch",
        )
        require(
            actual["properties"]
            == {
                "guid": expected["guid"],
                "mounted": "yes",
                "mountpoint": expected["mountpoint"],
                "org.cmdmesh:owner": policy["owner_tag"],
            },
            role + "-dataset-mismatch",
        )
        require(
            actual["mount"]
            == {
                "target": expected["mountpoint"],
                "source": expected["name"],
                "fstype": "zfs",
                "fsroot": "/",
            },
            role + "-mount-mismatch",
        )
        require(
            private(actual["directory"], host_uid, host_gid, True),
            role + "-permissions-mismatch",
        )
    app = facts["application"]
    require(
        private(app["config"], host_uid, host_gid)
        and private(app["database"], host_uid, host_gid)
        and app["database"]["sqlite_header"] is True,
        "application-files-unqualified",
    )
    require(
        app["config"]["sha256"] == policy["application"]["config_sha256"]
        and type(app["identity"]["schema_version"]) is int
        and type(app["identity"]["uid"]) is int
        and app["identity"]
        == {
            "schema_version": 1,
            "instance_id": policy["application"]["instance_id"],
            "uid": mapping["uid"],
            "token_valid": True,
        },
        "application-identity-mismatch",
    )


def stable(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def metadata(path, directory=False):
    require(
        absolute(str(path)) and path.resolve(strict=True) == path, "path-unqualified"
    )
    info = path.lstat()
    require(
        (stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode),
        "path-type-unqualified",
    )
    return {
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "inode": info.st_ino,
        "bytes": info.st_size,
        "directory" if directory else "regular": True,
    }


def read_file(path, limit):
    require(path.resolve(strict=True) == path, "path-unqualified")
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode) and before.st_size <= limit, "file-unqualified"
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(stable(os.fstat(fd)) == stable(before), "file-changed")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        require(
            len(raw) <= limit and stable(os.fstat(fd)) == stable(before), "file-changed"
        )
    finally:
        os.close(fd)
    require(stable(path.lstat()) == stable(before), "file-changed")
    return raw


def native(argv):
    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=20,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        umask=0o077,
    )
    require(
        result.returncode == 0 and not result.stderr and len(result.stdout) <= 262144,
        "native-observation-failed",
    )
    return result.stdout


def collect(policy):
    require(os.geteuid() == ROOT_UID, "root-required")
    validate_policy(policy)
    config = decode(
        native(
            [
                "/usr/bin/pvesh",
                "get",
                "/nodes/" + policy["node"] + "/lxc/" + str(policy["vmid"]) + "/config",
                "--output-format",
                "json",
            ]
        )
    )
    generated_raw = read_file(
        Path("/var/lib/lxc") / str(policy["vmid"]) / "config", 65536
    )
    require(
        hashlib.sha256(generated_raw).hexdigest() == policy["generated_config_sha256"],
        "generated-config-mismatch",
    )
    generated = generated_raw.decode()
    id_maps = {"u": [], "g": []}
    for line in generated.splitlines():
        if line.startswith("lxc.idmap"):
            match = re.fullmatch(
                r"lxc\.idmap\s*=\s*([ug])\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)", line
            )
            require(match is not None, "mapping-unqualified")
            id_maps[match[1]].append([int(n) for n in match.groups()[1:]])
    root = Path(policy["rootfs"]["path"])
    resolved = (
        native(["/usr/sbin/pvesm", "path", policy["rootfs"]["volume"]]).decode().strip()
    )
    require(resolved == str(root), "rootfs-storage-path-mismatch")
    image = metadata(root)
    image["resolved_path"] = resolved
    pairs = [
        line.split("=", 1)
        for line in native(["/usr/sbin/blkid", "-p", "-o", "export", str(root)])
        .decode()
        .splitlines()
    ]
    require(
        all(len(row) == 2 for row in pairs) and len(pairs) == len(dict(pairs)),
        "rootfs-observation-unqualified",
    )
    filesystem = dict(pairs)
    image.update(uuid=filesystem.get("UUID"), type=filesystem.get("TYPE"))
    datasets = {}
    for role, expected in policy["datasets"].items():
        path = Path(expected["mountpoint"])
        rows = [
            line.split("\t")
            for line in native(
                [
                    "/usr/sbin/zfs",
                    "get",
                    "-H",
                    "-p",
                    "-o",
                    "property,value",
                    "guid,mounted,mountpoint,org.cmdmesh:owner",
                    expected["name"],
                ]
            )
            .decode()
            .splitlines()
        ]
        require(
            all(len(row) == 2 for row in rows) and len(rows) == len(dict(rows)),
            "dataset-observation-unqualified",
        )
        mounts = decode(
            native(
                [
                    "/usr/bin/findmnt",
                    "--json",
                    "--mountpoint",
                    str(path),
                    "-o",
                    "TARGET,SOURCE,FSTYPE,FSROOT",
                ]
            )
        )
        require(
            set(mounts) == {"filesystems"} and len(mounts["filesystems"]) == 1,
            "mount-observation-unqualified",
        )
        datasets[role] = {
            "properties": dict(rows),
            "mount": mounts["filesystems"][0],
            "directory": metadata(path, True),
        }
    data = Path(policy["datasets"]["data"]["mountpoint"])
    config_path = Path(policy["datasets"]["config"]["mountpoint"]) / "application.json"
    raw = read_file(config_path, 4096)
    identity = decode(raw)
    require(
        type(identity) is dict
        and set(identity) == {"schema_version", "instance_id", "uid", "token"},
        "application-configuration-unqualified",
    )
    public_identity = {
        key: identity[key] for key in ("schema_version", "instance_id", "uid")
    }
    public_identity["token_valid"] = matches(r"[a-f0-9]{64}", identity["token"])
    conf = metadata(config_path)
    conf["sha256"] = hashlib.sha256(raw).hexdigest()
    database_path = data / "ledger.sqlite3"
    database = metadata(database_path)
    with database_path.open("rb") as stream:
        database["sqlite_header"] = stream.read(16) == b"SQLite format 3\0"
    return {
        "config": config,
        "generated_config_sha256": hashlib.sha256(generated_raw).hexdigest(),
        "id_maps": id_maps,
        "rootfs": image,
        "datasets": datasets,
        "application": {
            "config": conf,
            "database": database,
            "identity": public_identity,
        },
    }


def load_policy(path):
    info = metadata(path)
    require(
        info["uid"] == ROOT_UID and info["mode"] == 0o600, "policy-file-unqualified"
    )
    policy = decode(read_file(path, 65536))
    validate_policy(policy)
    for item in policy["datasets"].values():
        directory = Path(item["mountpoint"])
        require(
            path != directory and directory not in path.parents,
            "policy-inside-retained-data",
        )
    return policy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--vmid", required=True, type=int)
    args = parser.parse_args()
    try:
        policy = load_policy(args.manifest)
        require(args.vmid == policy["vmid"], "wrong-target")
        validate(policy, collect(policy), args.vmid)
    except (
        ValueError,
        OSError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as error:
        print(
            json.dumps(
                {
                    "outcome": "refused",
                    "reason": (
                        str(error)
                        if isinstance(error, Refused)
                        else "observation-unavailable"
                    ),
                }
            )
        )
        return 1
    print(json.dumps({"outcome": "qualified"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
