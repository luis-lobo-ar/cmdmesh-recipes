"""Schema3 retained-pair ownership checks for a replacement reference LXC.

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
OWNERS_ROOT = Path("/var/lib/cmdmesh/persistence-owners")
DENIAL = b"[Service]\nExecStartPre=\nExecStartPre=/usr/bin/false\n"


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
            "generated_config_stable_sha256",
            "cpu_policy",
            "mapping",
            "rootfs",
            "datasets",
            "application",
            "retired_guest",
        },
        "policy-shape",
    )
    require(
        type(policy["schema_version"]) is int and policy["schema_version"] == 3,
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
        matches(r"[a-f0-9]{64}", policy["generated_config_stable_sha256"]),
        "generated-config-policy-invalid",
    )
    cpu = policy["cpu_policy"]
    require(
        type(cpu) is dict
        and set(cpu) == {"count", "allowed"}
        and type(cpu["allowed"]) is list
        and 1 <= len(cpu["allowed"]) <= 4096
        and all(integer(value, 0, 65535) for value in cpu["allowed"])
        and cpu["allowed"] == sorted(set(cpu["allowed"]))
        and integer(cpu["count"], 1, len(cpu["allowed"])),
        "cpu-policy-invalid",
    )
    require(cpu["count"] == 1, "handoff-one-core-required")
    retired = policy["retired_guest"]
    require(
        type(retired) is dict
        and set(retired) == {"vmid", "generation_tag", "preserved_dropin_sha256"}
        and integer(retired["vmid"], 100, 999999)
        and retired["vmid"] != policy["vmid"]
        and matches(r"cmdmesh-gen-[a-f0-9]{32}", retired["generation_tag"])
        and retired["generation_tag"] != policy["generation_tag"]
        and matches(r"[a-f0-9]{64}", retired["preserved_dropin_sha256"]),
        "retired-guest-policy-invalid",
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

    controls = [owner_path(policy)]
    for name in retired_units(policy):
        controls.extend(retired_paths(policy, name))
    for item in policy["datasets"].values():
        mount = Path(item["mountpoint"])
        require(
            all(path != mount and mount not in path.parents for path in controls),
            "control-inside-retained-data",
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


def generated_fingerprint(raw):
    require(
        type(raw) is bytes and 0 < len(raw) <= 65536, "generated-config-unqualified"
    )
    lines = raw.splitlines(keepends=True)
    quotas = [line for line in lines if line.strip().startswith(b"lxc.cgroup2.cpu.max")]
    require(
        quotas == [b"lxc.cgroup2.cpu.max = 100000 100000\n"], "cpu-quota-unqualified"
    )
    candidates = [
        index
        for index, line in enumerate(lines)
        if line.strip().startswith(b"lxc.cgroup2.cpuset.cpus")
    ]
    require(len(candidates) == 1, "cpu-directive-unqualified")
    index = candidates[0]
    match = re.fullmatch(
        rb"(lxc\.cgroup2\.cpuset\.cpus = )([0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*)?(\n)",
        lines[index],
    )
    require(match is not None, "cpu-directive-unqualified")
    cpus = []
    for part in (match[2].split(b",") if match[2] else []):
        bounds = [int(value) for value in part.split(b"-")]
        low, high = bounds[0], bounds[-1]
        require(
            0 <= low <= high <= 65535
            and high - low < 4096
            and len(cpus) + high - low + 1 <= 4096,
            "cpu-selection-unqualified",
        )
        cpus.extend(range(low, high + 1))
    require(cpus == sorted(set(cpus)), "cpu-selection-unqualified")
    # Only this value is generator-managed. All other bytes remain attributable.
    lines[index] = match[1] + match[3]
    return hashlib.sha256(b"".join(lines)).hexdigest(), cpus


def validate_cpu(policy, config, facts):
    selection, available = facts["cpu_selection"], facts["cpu_available"]
    require(
        all(
            type(value) is list
            and all(integer(cpu, 0, 65535) for cpu in value)
            and value == sorted(set(value))
            for value in (selection, available)
        )
        and bool(available)
        and type(config.get("cores")) is int
        and config["cores"] == 1
        and type(config.get("cpulimit")) in (int, float, str)
        and config["cpulimit"] in (1, 1.0, "1")
        and facts["generated_cpu_max"] == "100000 100000",
        "cpu-quota-mismatch",
    )
    allowed = set(policy["cpu_policy"]["allowed"])
    require(
        (not selection and set(available) <= allowed)
        or (len(selection) == 1 and set(selection) <= allowed & set(available)),
        "cpu-selection-mismatch",
    )
    require(
        facts["generated_config_stable_sha256"]
        == policy["generated_config_stable_sha256"],
        "generated-config-mismatch",
    )


def validate_dataset_properties(policy, role, actual):
    expected = policy["datasets"][role]
    require(
        actual
        == {
            "guid": expected["guid"],
            "mounted": "yes",
            "mountpoint": expected["mountpoint"],
            "org.cmdmesh:owner": policy["owner_tag"],
        },
        role + "-dataset-mismatch",
    )


def validate(policy, facts, vmid):
    validate_policy(policy)
    require(type(vmid) is int and vmid == policy["vmid"], "wrong-target")
    validate_ownership(policy, facts["ownership"])
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
    validate_cpu(policy, config, facts)
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
        validate_dataset_properties(policy, role, actual["properties"])
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


def _collect_retained(policy):
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
    stable, selection = generated_fingerprint(generated_raw)
    cpu_facts = {
        "generated_config_stable_sha256": stable,
        "cpu_selection": selection,
        "generated_cpu_max": "100000 100000",
        "cpu_available": sorted(os.sched_getaffinity(0)),
    }
    validate_cpu(policy, config, cpu_facts)
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
        validate_dataset_properties(policy, role, dict(rows))
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
    result = {
        "config": config,
        "generated_config_sha256": hashlib.sha256(generated_raw).hexdigest(),
        **cpu_facts,
        "id_maps": id_maps,
        "rootfs": image,
        "datasets": datasets,
        "application": {
            "config": conf,
            "database": database,
            "identity": public_identity,
        },
    }
    return result


def _file_seal(path, *, directory=False, limit=None, header=False):
    require(path.resolve(strict=True) == path, "sealed-path-unqualified")
    before = path.lstat()
    require(
        (stat.S_ISDIR if directory else stat.S_ISREG)(before.st_mode),
        "sealed-type-unqualified",
    )
    result = {"identity": list(control_stable(before))}
    if limit is not None:
        raw = read_file(path, limit)
        require(raw == read_file(path, limit), "sealed-file-changed")
        result["sha256"] = hashlib.sha256(raw).hexdigest()
    if header:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            require(
                control_stable(os.fstat(fd)) == control_stable(before),
                "sealed-file-changed",
            )
            raw = os.read(fd, 16)
            os.lseek(fd, 0, os.SEEK_SET)
            require(raw == os.read(fd, 16), "sealed-file-changed")
            result["header_sha256"] = hashlib.sha256(raw).hexdigest()
            require(
                control_stable(os.fstat(fd)) == control_stable(before),
                "sealed-file-changed",
            )
        finally:
            os.close(fd)
    require(
        control_stable(path.lstat()) == control_stable(before), "sealed-file-changed"
    )
    return result


def _core_files(policy):
    data = Path(policy["datasets"]["data"]["mountpoint"])
    config = Path(policy["datasets"]["config"]["mountpoint"])
    return {
        "generated": _file_seal(
            Path("/var/lib/lxc") / str(policy["vmid"]) / "config", limit=65536
        ),
        "storage": _file_seal(Path("/etc/pve/storage.cfg"), limit=65536),
        "root": _file_seal(Path(policy["rootfs"]["path"])),
        "data": _file_seal(data, directory=True),
        "config": _file_seal(config, directory=True),
        "identity": _file_seal(config / "application.json", limit=4096),
        "database": _file_seal(data / "ledger.sqlite3", header=True),
        "cpu_available": sorted(os.sched_getaffinity(0)),
    }


def ownership_seal(value):
    result = {key: value[key] for key in ("document", "file", "directory")}
    result["units"] = {
        name: {
            key: unit[key]
            for key in ("preserved_file", "denial_file", "directory_membership")
        }
        for name, unit in value["retired"]["units"].items()
    }
    return result


def collect(policy):
    require(os.geteuid() == ROOT_UID, "root-required")
    validate_policy(policy)
    ownership = collect_ownership(policy)
    before = _collect_retained(policy)
    validate(policy, {**before, "ownership": ownership}, policy["vmid"])
    sealed = _core_files(policy)
    closing_ownership = collect_ownership(policy)
    require(canonical(closing_ownership) == canonical(ownership), "ownership-changed")
    after = _collect_retained(policy)
    validate(policy, {**after, "ownership": closing_ownership}, policy["vmid"])
    require(canonical(after) == canonical(before), "retained-state-changed")
    require(
        canonical(_core_files(policy)) == canonical(sealed), "retained-files-changed"
    )
    require(
        canonical(ownership_files(policy))
        == canonical(ownership_seal(closing_ownership)),
        "ownership-files-changed",
    )
    return {**after, "ownership": closing_ownership}


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def pair_key(policy):
    return hashlib.sha256(
        canonical(sorted(item["guid"] for item in policy["datasets"].values()))
    ).hexdigest()


def owner_path(policy):
    return OWNERS_ROOT / pair_key(policy) / "owner.json"


def owner_document(policy):
    return {
        "schema_version": 1,
        "pair_key": pair_key(policy),
        "state": "attached",
        "node": policy["node"],
        "owner_tag": policy["owner_tag"],
        "active": {
            "vmid": policy["vmid"],
            "generation_tag": policy["generation_tag"],
            "rootfs_uuid": policy["rootfs"]["uuid"],
        },
        "retired": dict(policy["retired_guest"]),
    }


def retired_units(policy):
    vmid = str(policy["retired_guest"]["vmid"])
    return (
        "pve-container@" + vmid + ".service",
        "pve-container-debug@" + vmid + ".service",
    )


def retired_paths(policy, name):
    require(name in retired_units(policy), "retired-unit-invalid")
    parent = Path("/etc/systemd/system") / (name + ".d")
    return (
        parent / "50-cmdmesh-reference.conf",
        parent / "99-cmdmesh-retired-prestart.conf",
    )


def root_control(value, directory=False):
    return (
        type(value) is dict
        and all(type(value.get(k)) is int for k in ("uid", "gid", "mode"))
        and value["uid"] == value["gid"] == ROOT_UID
        and value.get("directory" if directory else "regular") is True
        and value["mode"] == (0o700 if directory else 0o600)
        and (directory or (type(value.get("nlink")) is int and value["nlink"] == 1))
    )


def false_command(value):
    require(
        type(value) is dict
        and set(value) == {"type", "data"}
        and value["type"] == "a(sasbttttuii)"
        and type(value["data"]) is list
        and len(value["data"]) == 1,
        "retired-command-unqualified",
    )
    row = value["data"][0]
    require(
        type(row) is list
        and len(row) == 10
        and row[:2] == ["/usr/bin/false", ["/usr/bin/false"]]
        and row[2] is False
        and all(type(part) is int for part in row[3:])
        and all(0 <= part < 2**64 for part in row[3:7])
        and 0 <= row[7] < 2**32
        and 0 <= row[8] <= 6
        and 0 <= row[9] <= 255,
        "retired-command-unqualified",
    )


def validate_ownership(policy, facts):
    require(
        type(facts) is dict
        and root_control(facts["file"])
        and root_control(facts["directory"], True)
        and canonical(facts["document"]) == canonical(owner_document(policy)),
        "pair-owner-mismatch",
    )
    retired = facts["retired"]
    require(
        type(retired) is dict and type(retired.get("tags")) is str,
        "retired-identity-unqualified",
    )
    tags = retired["tags"].split(";")
    require(
        [tag for tag in tags if tag.startswith("cmdmesh-own-")] == [policy["owner_tag"]]
        and [tag for tag in tags if tag.startswith("cmdmesh-gen-")]
        == [policy["retired_guest"]["generation_tag"]],
        "retired-identity-mismatch",
    )
    status = retired["status"]
    require(type(status) is dict, "retired-status-unqualified")
    require(
        status["status"] == "stopped"
        and type(status["vmid"]) is int
        and status["vmid"] == policy["retired_guest"]["vmid"]
        and type(status["pid"]) is int
        and status["pid"] == 0
        and type(status["uptime"]) is int
        and status["uptime"] == 0,
        "retired-guest-running",
    )
    require(
        retired["pending_clear"] is True and retired["ha_absent"] is True,
        "retired-management-unqualified",
    )
    require(
        set(retired["units"]) == set(retired_units(policy)), "retired-units-incomplete"
    )
    for name, unit in retired["units"].items():
        paths = retired_paths(policy, name)
        require(
            unit["LoadState"] == "loaded"
            and unit["ActiveState"] in {"inactive", "failed"}
            and type(unit["MainPID"]) is int
            and unit["MainPID"] == 0
            and unit["DropInPaths"] == [str(path) for path in paths]
            and unit["directory_membership"] == [path.name for path in paths],
            "retired-managed-start-not-denied",
        )
        false_command(unit["commands"])
        require(
            root_control(unit["preserved_file"])
            and root_control(unit["denial_file"])
            and unit["preserved_file"]["sha256"]
            == policy["retired_guest"]["preserved_dropin_sha256"]
            and unit["denial_file"]["sha256"] == hashlib.sha256(DENIAL).hexdigest(),
            "retired-denial-file-mismatch",
        )


def control_stable(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def control_directory(path, private=False):
    require(
        absolute(str(path)) and path.resolve(strict=True) == path,
        "control-directory-unqualified",
    )
    for current in (path, *path.parents):
        info = current.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == info.st_gid == ROOT_UID
            and not info.st_mode & 0o022,
            "control-directory-unqualified",
        )
    info = path.lstat()
    require(
        not private or stat.S_IMODE(info.st_mode) == 0o700,
        "owner-directory-unqualified",
    )
    return {**metadata(path, True), "identity": list(control_stable(info))}


def control_file(path):
    control_directory(path.parent)
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == before.st_gid == ROOT_UID
        and stat.S_IMODE(before.st_mode) == 0o600
        and before.st_nlink == 1
        and 0 < before.st_size <= 65536,
        "control-file-unqualified",
    )
    raw = read_file(path, 65536)
    require(
        control_stable(before) == control_stable(path.lstat()), "control-file-changed"
    )
    return raw, {
        **metadata(path),
        "nlink": 1,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "identity": list(control_stable(before)),
    }


def unit_path(name):
    encoded = "".join(
        char if char.isascii() and char.isalnum() else "_" + format(ord(char), "02x")
        for char in name
    )
    return "/org/freedesktop/systemd1/unit/" + encoded


def ownership_files(policy):
    path = owner_path(policy)
    directory = control_directory(path.parent, True)
    raw, info = control_file(path)
    document = decode(raw)
    require(
        raw == canonical(document)
        and canonical(document) == canonical(owner_document(policy)),
        "pair-owner-mismatch",
    )
    files = {"document": document, "file": info, "directory": directory, "units": {}}
    for name in retired_units(policy):
        preserved, denial = retired_paths(policy, name)
        control_directory(preserved.parent)
        membership = sorted(item.name for item in preserved.parent.iterdir())
        require(
            membership == [preserved.name, denial.name], "retired-dropin-membership"
        )
        old, old_info = control_file(preserved)
        body, denial_info = control_file(denial)
        require(
            hashlib.sha256(old).hexdigest()
            == policy["retired_guest"]["preserved_dropin_sha256"]
            and body == DENIAL,
            "retired-denial-file-mismatch",
        )
        files["units"][name] = {
            "preserved_file": old_info,
            "denial_file": denial_info,
            "directory_membership": membership,
        }
    return files


def collect_ownership(policy):
    files = ownership_files(policy)
    base = "/nodes/" + policy["node"] + "/lxc/" + str(policy["retired_guest"]["vmid"])
    read = lambda path: decode(
        native(["/usr/bin/pvesh", "get", path, "--output-format", "json"])
    )
    old_config = read(base + "/config")
    status = read(base + "/status/current")
    require(
        type(old_config) is dict
        and type(old_config.get("tags")) is str
        and type(status) is dict,
        "retired-api-unqualified",
    )
    pending = read(base + "/pending")
    require(
        type(pending) is list
        and len(pending) <= 4096
        and all(
            type(item) is dict
            and type(item.get("key")) is str
            and "pending" not in item
            and not item.get("delete")
            for item in pending
        ),
        "retired-pending-change",
    )
    ha = read("/cluster/ha/resources")
    require(
        type(ha) is list
        and len(ha) <= 128
        and all(
            type(item) is dict and matches(r"(?:ct|vm):[1-9][0-9]*", item.get("sid"))
            for item in ha
        ),
        "retired-ha-unqualified",
    )
    denied = {
        kind + ":" + str(vmid)
        for kind in ("ct", "vm")
        for vmid in (policy["vmid"], policy["retired_guest"]["vmid"])
    }
    require(not any(item["sid"] in denied for item in ha), "handoff-ha-conflict")
    units = {}
    for name in retired_units(policy):
        fields = {}
        for row in (
            native(
                [
                    "/usr/bin/systemctl",
                    "show",
                    name,
                    "-p",
                    "LoadState,ActiveState,MainPID,DropInPaths",
                ]
            )
            .decode()
            .splitlines()
        ):
            key, separator, value = row.partition("=")
            require(separator == "=" and key not in fields, "retired-unit-unqualified")
            fields[key] = value
        require(
            set(fields) == {"LoadState", "ActiveState", "MainPID", "DropInPaths"}
            and fields["MainPID"] == "0",
            "retired-unit-unqualified",
        )
        fields["MainPID"] = 0
        fields["DropInPaths"] = fields["DropInPaths"].split()
        fields["commands"] = decode(
            native(
                [
                    "/usr/bin/busctl",
                    "--json=short",
                    "get-property",
                    "org.freedesktop.systemd1",
                    unit_path(name),
                    "org.freedesktop.systemd1.Service",
                    "ExecStartPre",
                ]
            )
        )
        units[name] = {**fields, **files["units"][name]}
    final_files = ownership_files(policy)
    require(canonical(final_files) == canonical(files), "ownership-files-changed")
    result = {key: files[key] for key in ("document", "file", "directory")}
    result["retired"] = {
        "tags": old_config["tags"],
        "status": {
            "status": status.get("status"),
            "vmid": status.get("vmid"),
            "pid": status.get("pid", 0),
            "uptime": status.get("uptime", 0),
        },
        "pending_clear": True,
        "ha_absent": True,
        "units": units,
    }
    validate_ownership(policy, result)
    return result


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
