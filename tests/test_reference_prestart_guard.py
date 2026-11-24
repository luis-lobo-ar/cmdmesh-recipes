"""A managed container must not start on missing or substituted retained state."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = (
    Path(__file__).resolve().parents[1] / "examples/reference-ledger/prestart_guard.py"
)
spec = importlib.util.spec_from_file_location("reference_prestart_guard", SOURCE)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def fixture():
    policy = {
        "schema_version": 1,
        "node": "pve-example",
        "vmid": 101,
        "owner_tag": "cmdmesh-own-" + "1" * 32,
        "generation_tag": "cmdmesh-gen-" + "2" * 32,
        "generated_config_sha256": "c" * 64,
        "mapping": {"offset": 100000, "length": 65536, "uid": 1100, "gid": 1100},
        "rootfs": {
            "volume": "local:101/vm-101-disk-0.raw",
            "path": "/var/lib/vz/images/101/vm-101-disk-0.raw",
            "bytes": 2 * 1024**3,
            "inode": 123,
            "uuid": "11111111-2222-3333-4444-555555555555",
        },
        "datasets": {
            role: {
                "name": "example/reference/" + role,
                "guid": str(i),
                "mountpoint": "/srv/example/" + role,
            }
            for i, role in enumerate(("data", "config"), 1)
        },
        "application": {
            "initialized": True,
            "instance_id": "a" * 32,
            "config_sha256": "b" * 64,
        },
    }
    config = {
        "unprivileged": 1,
        "tags": policy["owner_tag"] + ";" + policy["generation_tag"],
        "rootfs": policy["rootfs"]["volume"] + ",size=2G",
        "mp0": "/srv/example/data,mp=/var/lib/reference-ledger,backup=0",
        "mp1": "/srv/example/config,mp=/etc/reference-ledger,backup=0",
    }
    private_dir = {"uid": 101100, "gid": 101100, "mode": 0o700, "directory": True}
    private_file = {"uid": 101100, "gid": 101100, "mode": 0o600, "regular": True}
    facts = {
        "config": config,
        "generated_config_sha256": "c" * 64,
        "id_maps": {"u": [[0, 100000, 65536]], "g": [[0, 100000, 65536]]},
        "rootfs": {
            "inode": 123,
            "resolved_path": policy["rootfs"]["path"],
            "bytes": 2 * 1024**3,
            "uid": 0,
            "mode": 0o600,
            "regular": True,
            "uuid": policy["rootfs"]["uuid"],
            "type": "ext4",
        },
        "datasets": {
            role: {
                "properties": {
                    "guid": p["guid"],
                    "mounted": "yes",
                    "mountpoint": p["mountpoint"],
                    "org.cmdmesh:owner": policy["owner_tag"],
                },
                "mount": {
                    "target": p["mountpoint"],
                    "source": p["name"],
                    "fstype": "zfs",
                    "fsroot": "/",
                },
                "directory": copy.deepcopy(private_dir),
            }
            for role, p in policy["datasets"].items()
        },
        "application": {
            "config": {**private_file, "sha256": "b" * 64},
            "database": {**private_file, "sqlite_header": True},
            "identity": {
                "schema_version": 1,
                "instance_id": "a" * 32,
                "uid": 1100,
                "token_valid": True,
            },
        },
    }
    return policy, facts


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.policy, self.facts = fixture()

    def test_qualified_retained_pair_can_start_without_a_running_guest(self):
        guard.validate_policy(self.policy)
        self.assertIsNone(guard.validate(self.policy, self.facts, 101))
        # There is deliberately no guest PID or current-runtime dependency.
        self.assertNotIn("pid", self.facts)

    def test_public_example_matches_the_supported_policy(self):
        policy = guard.decode(
            (SOURCE.parent / "prestart-manifest.example.json").read_bytes()
        )
        guard.validate_policy(policy)
        self.assertEqual(policy, self.policy)

    def test_wrong_target_owner_generation_or_mapping_is_refused(self):
        with self.assertRaises(guard.Refused):
            guard.validate(self.policy, self.facts, 102)
        for change in (
            "owner",
            "generation",
            "privileged",
            "idmap",
            "hook",
            "extra-mount",
        ):
            facts = copy.deepcopy(self.facts)
            if change in {"owner", "generation"}:
                facts["config"]["tags"] = (
                    facts["config"]["tags"].replace("1" * 32, "3" * 32)
                    if change == "owner"
                    else facts["config"]["tags"].replace("2" * 32, "4" * 32)
                )
            elif change == "privileged":
                facts["config"]["unprivileged"] = 0
            elif change == "idmap":
                facts["id_maps"]["u"] = [[0, 0, 65536]]
            elif change == "hook":
                facts["config"]["lxc"] = [["lxc.apparmor.profile", "unconfined"]]
            else:
                facts["config"]["mp2"] = "/foreign,mp=/foreign"
            with self.subTest(change=change), self.assertRaises(guard.Refused):
                guard.validate(self.policy, facts, 101)

    def test_empty_covering_directory_or_wrong_dataset_guid_is_refused(self):
        for role in ("data", "config"):
            for change in ("unmounted", "covering", "guid", "ownership", "mode"):
                facts = copy.deepcopy(self.facts)
                dataset = facts["datasets"][role]
                if change == "unmounted":
                    dataset["properties"]["mounted"] = "no"
                elif change == "covering":
                    dataset["mount"] = {
                        "target": "/",
                        "source": "/dev/example",
                        "fstype": "ext4",
                        "fsroot": "/",
                    }
                elif change == "guid":
                    dataset["properties"]["guid"] = "999"
                elif change == "ownership":
                    dataset["directory"]["uid"] = 0
                else:
                    dataset["directory"]["mode"] = 0o755
                with self.subTest(role=role, change=change), self.assertRaises(
                    guard.Refused
                ):
                    guard.validate(self.policy, facts, 101)

    def test_substituted_rootfs_or_duplicate_mount_option_is_refused(self):
        for key, value in (
            ("uuid", "other"),
            ("inode", 124),
            ("bytes", 1),
            ("uid", 1100),
        ):
            facts = copy.deepcopy(self.facts)
            facts["rootfs"][key] = value
            with self.subTest(key=key), self.assertRaises(guard.Refused):
                guard.validate(self.policy, facts, 101)
        self.facts["config"]["mp0"] += ",mp=/foreign"
        with self.assertRaises(guard.Refused):
            guard.validate(self.policy, self.facts, 101)

    def test_reconfigured_storage_cannot_adopt_the_leftover_old_image(self):
        self.facts["rootfs"][
            "resolved_path"
        ] = "/srv/reconfigured/101/vm-101-disk-0.raw"
        with self.assertRaises(guard.Refused):
            guard.validate(self.policy, self.facts, 101)

    def test_stale_generated_privilege_or_network_cannot_pass_api_config_checks(self):
        self.facts["generated_config_sha256"] = "d" * 64
        with self.assertRaises(guard.Refused):
            guard.validate(self.policy, self.facts, 101)

    def test_uninitialized_missing_or_replaced_application_state_refuses(self):
        policy = copy.deepcopy(self.policy)
        policy["application"]["initialized"] = False
        with self.assertRaises(guard.Refused):
            guard.validate_policy(policy)
        for change in (
            "database",
            "identity",
            "credentials",
            "private-mode",
            "schema-type",
        ):
            facts = copy.deepcopy(self.facts)
            if change == "database":
                del facts["application"]["database"]
            elif change == "identity":
                facts["application"]["identity"]["instance_id"] = "c" * 32
            elif change == "credentials":
                facts["application"]["config"]["sha256"] = "d" * 64
            elif change == "private-mode":
                facts["application"]["database"]["mode"] = 0o644
            else:
                facts["application"]["identity"]["schema_version"] = True
            with self.subTest(change=change), self.assertRaises(
                (guard.Refused, KeyError)
            ):
                guard.validate(self.policy, facts, 101)

    def test_policy_has_no_extra_commands_shared_paths_or_outside_uid_range(self):
        for change in ("command", "shared", "uid", "target-bool"):
            policy = copy.deepcopy(self.policy)
            if change == "command":
                policy["command"] = ["touch", "/foreign"]
            elif change == "shared":
                policy["datasets"]["config"]["mountpoint"] = policy["datasets"]["data"][
                    "mountpoint"
                ]
            elif change == "uid":
                policy["mapping"]["uid"] = 65536
            else:
                policy["vmid"] = True
            with self.subTest(change=change), self.assertRaises(guard.Refused):
                guard.validate_policy(policy)

    def test_real_cli_refusal_does_not_initialize_or_disclose_input(self):
        scratch = Path(__file__).resolve().parents[1] / ".generated"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="prestart-cli-", dir=scratch) as tmp:
            root = Path(tmp)
            manifest = root / "policy.json"
            policy = copy.deepcopy(self.policy)
            policy["secret"] = "synthetic-do-not-disclose"
            manifest.write_text(json.dumps(policy))
            manifest.chmod(0o600)
            code = "import importlib.util,os,sys; s=importlib.util.spec_from_file_location('guard',sys.argv.pop(1)); g=importlib.util.module_from_spec(s); s.loader.exec_module(g); g.ROOT_UID=os.geteuid(); raise SystemExit(g.main())"
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    code,
                    str(SOURCE),
                    "--manifest",
                    str(manifest),
                    "--vmid",
                    "101",
                ],
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(
                json.loads(result.stdout),
                {"outcome": "refused", "reason": "policy-shape"},
            )
            self.assertNotIn(
                b"synthetic-do-not-disclose", result.stdout + result.stderr
            )
            self.assertEqual(list(root.iterdir()), [manifest])
            del policy["secret"]
            manifest.write_text(json.dumps(policy))
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    code,
                    str(SOURCE),
                    "--manifest",
                    str(manifest),
                    "--vmid",
                    "102",
                ],
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(
                json.loads(result.stdout),
                {"outcome": "refused", "reason": "wrong-target"},
            )
            self.assertEqual(list(root.iterdir()), [manifest])


if __name__ == "__main__":
    unittest.main()
