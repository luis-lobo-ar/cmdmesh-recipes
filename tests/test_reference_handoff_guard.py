"""Retained state must have one intended managed guest owner before boot."""

import copy
import hashlib
import io
import json
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
import tempfile
from unittest import mock

from test_reference_prestart_guard import fixture, guard as legacy

SOURCE = (
    Path(__file__).resolve().parents[1] / "examples/reference-ledger/handoff_guard.py"
)
spec = importlib.util.spec_from_file_location("reference_handoff_guard", SOURCE)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def example():
    policy, facts = fixture()
    policy["schema_version"] = 3
    policy["retired_guest"] = {
        "vmid": 100,
        "generation_tag": "cmdmesh-gen-" + "3" * 32,
        "preserved_dropin_sha256": "f" * 64,
    }
    facts["config"]["cpulimit"] = "1"
    facts["generated_cpu_max"] = "100000 100000"
    control = {"regular": True, "uid": 0, "gid": 0, "mode": 0o600, "nlink": 1}
    units = {}
    for name in guard.retired_units(policy):
        paths = guard.retired_paths(policy, name)
        units[name] = {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "MainPID": 0,
            "DropInPaths": [str(paths[0]), str(paths[1])],
            "commands": {
                "type": "a(sasbttttuii)",
                "data": [
                    ["/usr/bin/false", ["/usr/bin/false"], False, 0, 0, 0, 0, 0, 0, 0]
                ],
            },
            "preserved_file": {**control, "sha256": "f" * 64},
            "denial_file": {
                **control,
                "sha256": hashlib.sha256(guard.DENIAL).hexdigest(),
            },
            "directory_membership": [path.name for path in paths],
        }
    facts["ownership"] = {
        "document": guard.owner_document(policy),
        "file": control,
        "directory": {"directory": True, "uid": 0, "gid": 0, "mode": 0o700},
        "retired": {
            "tags": policy["owner_tag"]
            + ";"
            + policy["retired_guest"]["generation_tag"],
            "status": {"status": "stopped", "vmid": 100, "pid": 0, "uptime": 0},
            "pending_clear": True,
            "ha_absent": True,
            "units": units,
        },
    }
    return policy, facts


class HandoffGuardTests(unittest.TestCase):
    def test_public_manifest_uses_the_explicit_successor_schema(self):
        policy = guard.decode(
            (SOURCE.parent / "handoff-manifest.example.json").read_bytes()
        )
        guard.validate_policy(policy)
        self.assertEqual(policy, example()[0])

    def test_fast_file_seals_use_real_metadata_and_fingerprints_without_raw_bytes(self):
        scratch = SOURCE.parents[2] / ".generated"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="handoff-seal-", dir=scratch
        ) as directory:
            path = Path(directory) / "private.json"
            path.write_bytes(b"private fixture bytes")
            first = guard._file_seal(path, limit=4096)
            self.assertNotIn("private fixture bytes", json.dumps(first))
            path.write_bytes(b"different private fixture bytes")
            self.assertNotEqual(first, guard._file_seal(path, limit=4096))
            link = path.with_name("linked.json")
            link.symlink_to(path)
            with self.assertRaises(guard.Refused):
                guard._file_seal(link, limit=4096)
            with self.assertRaises(guard.Refused):
                guard._file_seal(path, limit=1)

    def test_file_changed_during_seal_is_refused(self):
        scratch = SOURCE.parents[2] / ".generated"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="handoff-seal-drift-", dir=scratch
        ) as directory:
            path = Path(directory) / "private.json"
            path.write_bytes(b"checked fixture")
            original = guard.read_file

            def read_then_change(target, limit):
                raw = original(target, limit)
                target.write_bytes(b"changed fixture")
                return raw

            with mock.patch.object(guard, "read_file", side_effect=read_then_change):
                with self.assertRaises(guard.Refused):
                    guard._file_seal(path, limit=4096)

    def collect_model(self, change_root=False):
        policy, facts = example()
        generated = b"lxc.idmap = u 0 100000 65536\nlxc.idmap = g 0 100000 65536\nlxc.cgroup2.cpu.max = 100000 100000\nlxc.cgroup2.cpuset.cpus = 0\n"
        policy["generated_config_stable_sha256"] = guard.generated_fingerprint(
            generated
        )[0]
        identity = {
            "schema_version": 1,
            "instance_id": policy["application"]["instance_id"],
            "uid": 1100,
            "token": "0" * 64,
        }
        config_raw = guard.canonical(identity)
        policy["application"]["config_sha256"] = hashlib.sha256(config_raw).hexdigest()
        state = {"reads": 0, "changed": False}
        root = Path(policy["rootfs"]["path"])
        config = Path(policy["datasets"]["config"]["mountpoint"]) / "application.json"
        database = Path(policy["datasets"]["data"]["mountpoint"]) / "ledger.sqlite3"

        def ownership(unused):
            state["reads"] += 1
            if change_root and state["reads"] == 2:
                state["changed"] = True
            return copy.deepcopy(facts["ownership"])

        def native(argv):
            if argv[0] == "/usr/bin/pvesh":
                return guard.canonical(facts["config"])
            if argv[0] == "/usr/sbin/pvesm":
                return str(root).encode() + b"\n"
            if argv[0] == "/usr/sbin/blkid":
                return ("UUID=" + policy["rootfs"]["uuid"] + "\nTYPE=ext4\n").encode()
            if argv[0] == "/usr/sbin/zfs":
                role = next(
                    k for k, v in policy["datasets"].items() if v["name"] == argv[-1]
                )
                return "".join(
                    k + "\t" + v + "\n"
                    for k, v in facts["datasets"][role]["properties"].items()
                ).encode()
            if argv[0] == "/usr/bin/findmnt":
                path = argv[argv.index("--mountpoint") + 1]
                role = next(
                    k for k, v in policy["datasets"].items() if v["mountpoint"] == path
                )
                return guard.canonical(
                    {"filesystems": [facts["datasets"][role]["mount"]]}
                )
            raise AssertionError(argv)

        def metadata(path, directory=False):
            if path == root:
                value = copy.deepcopy(facts["rootfs"])
                value["inode"] += int(state["changed"])
                return value
            for role, item in policy["datasets"].items():
                if path == Path(item["mountpoint"]):
                    return copy.deepcopy(facts["datasets"][role]["directory"])
            if path == config:
                return copy.deepcopy(facts["application"]["config"])
            if path == database:
                return copy.deepcopy(facts["application"]["database"])
            raise AssertionError(str(path))

        def read_file(path, limit):
            if path == config:
                return config_raw
            if str(path) == f"/var/lib/lxc/{policy['vmid']}/config":
                return generated
            raise AssertionError(str(path))

        def opening(path, *args, **kwargs):
            self.assertEqual(path, database)
            return io.BytesIO(b"SQLite format 3\0synthetic")

        owner = facts["ownership"]
        files = {key: owner[key] for key in ("document", "file", "directory")}
        files["units"] = {
            name: {
                key: unit[key]
                for key in ("preserved_file", "denial_file", "directory_membership")
            }
            for name, unit in owner["retired"]["units"].items()
        }
        with mock.patch.object(
            guard,
            "os",
            SimpleNamespace(
                geteuid=lambda: 0, sched_getaffinity=lambda unused: {0, 1, 2, 3}
            ),
        ), mock.patch.object(guard, "native", side_effect=native), mock.patch.object(
            guard, "metadata", side_effect=metadata
        ), mock.patch.object(
            guard, "read_file", side_effect=read_file
        ), mock.patch.object(
            guard, "collect_ownership", side_effect=ownership
        ), mock.patch.object(
            guard, "ownership_files", return_value=copy.deepcopy(files)
        ), mock.patch.object(
            guard,
            "_core_files",
            side_effect=lambda unused: {"root_inode": 123 + int(state["changed"])},
            create=True,
        ), mock.patch.object(
            Path, "open", opening
        ):
            actual = guard.collect(policy)
            guard.validate(policy, actual, policy["vmid"])
        return actual

    def test_complete_collector_positive_control(self):
        self.assertEqual(self.collect_model()["rootfs"]["inode"], 123)

    def test_root_replaced_during_closing_ownership_cannot_qualify(self):
        with self.assertRaises(guard.Refused):
            self.collect_model(change_root=True)

    def test_nonempty_and_bounded_empty_placement_need_exact_quota_and_owner(self):
        policy, facts = example()
        guard.validate(policy, facts, policy["vmid"])
        facts["cpu_selection"] = []
        guard.validate(policy, facts, policy["vmid"])

    def test_empty_placement_rejects_unbounded_or_unapproved_resources(self):
        for fault in ("quota", "limit", "parent", "cores", "bool-limit"):
            policy, facts = example()
            facts["cpu_selection"] = []
            if fault == "quota":
                facts["generated_cpu_max"] = "max 100000"
            if fault == "limit":
                facts["config"]["cpulimit"] = "2"
            if fault == "parent":
                facts["cpu_available"].append(4)
            if fault == "cores":
                facts["config"]["cores"] = 2
            if fault == "bool-limit":
                facts["config"]["cpulimit"] = True
            with self.subTest(fault=fault), self.assertRaises(guard.Refused):
                guard.validate(policy, facts, policy["vmid"])

    def test_generated_fingerprint_accepts_empty_only_with_single_exact_quota(self):
        first = b"lxc.idmap = u 0 100000 65536\nlxc.cgroup2.cpu.max = 100000 100000\nlxc.cgroup2.cpuset.cpus = \n"
        changed = first.replace(b"cpuset.cpus = \n", b"cpuset.cpus = 2\n")
        self.assertEqual(
            guard.generated_fingerprint(first)[0],
            guard.generated_fingerprint(changed)[0],
        )
        self.assertEqual(guard.generated_fingerprint(first)[1], [])
        for raw in (
            first.replace(b"100000 100000", b"max 100000"),
            first + b"lxc.cgroup2.cpu.max = 100000 100000\n",
        ):
            with self.assertRaises(guard.Refused):
                guard.generated_fingerprint(raw)

    def test_owner_reassignment_missing_retirement_or_live_retired_guest_refuses(self):
        for fault in (
            "active",
            "pair",
            "mode",
            "missing-debug",
            "live",
            "ignored",
            "argv",
            "late-override",
            "preserved",
        ):
            policy, facts = example()
            owner = facts["ownership"]
            unit = next(iter(owner["retired"]["units"].values()))
            if fault == "active":
                owner["document"]["active"]["vmid"] = 999
            if fault == "pair":
                owner["document"]["pair_key"] = "0" * 64
            if fault == "mode":
                owner["file"]["mode"] = 0o644
            if fault == "missing-debug":
                owner["retired"]["units"].pop(next(reversed(owner["retired"]["units"])))
            if fault == "live":
                owner["retired"]["status"].update(status="running", pid=42)
            if fault == "ignored":
                unit["commands"]["data"][0][2] = True
            if fault == "argv":
                unit["commands"]["data"][0][1] = ["/usr/bin/true"]
            if fault == "late-override":
                unit["directory_membership"].append("zz-override.conf")
            if fault == "preserved":
                unit["preserved_file"]["sha256"] = "0" * 64
            with self.subTest(fault=fault), self.assertRaises(guard.Refused):
                guard.validate(policy, facts, policy["vmid"])

    def test_existing_storage_mapping_and_application_refusals_stay_in_force(self):
        for fault in (
            "root",
            "guid",
            "covering",
            "map",
            "credential",
            "permissions",
            "extra-bind",
            "network",
        ):
            policy, facts = example()
            old_policy, old_facts = fixture()
            for target in (facts, old_facts):
                if fault == "root":
                    target["rootfs"]["inode"] += 1
                if fault == "guid":
                    target["datasets"]["data"]["properties"]["guid"] = "999"
                if fault == "covering":
                    target["datasets"]["data"]["mount"]["fstype"] = "ext4"
                if fault == "map":
                    target["id_maps"]["u"] = [[0, 0, 65536]]
                if fault == "credential":
                    target["application"]["config"]["sha256"] = "0" * 64
                if fault == "permissions":
                    target["datasets"]["config"]["directory"]["mode"] = 0o755
                if fault == "extra-bind":
                    target["config"]["mp2"] = "/other,mp=/other"
                if fault == "network":
                    target["config"]["net0"] = "name=eth0"
            with self.subTest(fault=fault, schema=2), self.assertRaises(legacy.Refused):
                legacy.validate(old_policy, old_facts, old_policy["vmid"])
            with self.subTest(fault=fault, schema=3), self.assertRaises(guard.Refused):
                guard.validate(policy, facts, policy["vmid"])


if __name__ == "__main__":
    unittest.main()
