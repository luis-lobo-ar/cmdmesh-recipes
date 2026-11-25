"""Image preparation must leave persistent data and application startup alone."""

import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import json
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class ReferenceImageTests(unittest.TestCase):
    def assert_final_state_drift_refuses(self, fault):
        reads = []
        active = []
        account_provider = self.accounts
        unit_provider = self.unit

        def accounts():
            reads.append(True)
            if len(reads) == 4:
                if fault == "data":
                    self.image.path(self.image.RETAINED[1]).mkdir()
                if fault == "unit":
                    active.append(True)
                if fault == "health":
                    self.environment["systemd"] = {
                        "code": 1,
                        "stdout": "degraded\n",
                        "stderr": "",
                    }
            return account_provider()

        def unit():
            value = unit_provider()
            if active:
                value.update(ActiveState="active", MainPID="123")
            return value

        with mock.patch.object(
            self.image, "accounts", side_effect=accounts
        ), mock.patch.object(self.image, "unit", side_effect=unit):
            with self.assertRaises(ValueError):
                self.image.prepare(self.program, allow_changes=True)
        self.assertTrue((self.image.path(self.image.CLAIM) / "failed.json").exists())

    def test_final_retained_path_drift_cannot_qualify(self):
        self.assert_final_state_drift_refuses("data")

    def test_final_active_unit_drift_cannot_qualify(self):
        self.assert_final_state_drift_refuses("unit")

    def test_final_health_drift_cannot_qualify(self):
        self.assert_final_state_drift_refuses("health")

    def test_cli_reports_failed_guard_without_claiming_effects_before_admission(self):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "examples/reference-ledger/image.py"),
                "install",
                "--program-hex",
                "00",
                "--allow-changes",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        value = json.loads(result.stdout)
        self.assertEqual(value.get("error_code"), "reference-image-artifact-mismatch")
        self.assertFalse(value["effects_may_exist"])

    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "reference_image", ROOT / "examples/reference-ledger/image.py"
        )
        self.image = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.image)
        self.real_accounts = self.image.accounts
        self.real_account_files = self.image.account_files
        scratch = ROOT / ".generated"
        scratch.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="reference-image-", dir=scratch
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("opt", "etc/systemd/system", "var/lib", "run"):
            (self.root / name).mkdir(parents=True, exist_ok=True)
            (self.root / name).chmod(0o755)
        self.program = (ROOT / "examples/reference-ledger/ledger.py").read_bytes()
        self.created = False
        self.loaded = False
        self.commands = []
        self.account_signatures = {
            name: {"sha256": "a" * 64}
            for name in ("passwd", "group", "shadow", "gshadow", "subuid", "subgid")
        }
        self.environment = {
            "uid": 0,
            "gid": 0,
            "uid_map": [[0, 100000, 65536]],
            "gid_map": [[0, 100000, 65536]],
            "interfaces": ["lo"],
            "python": [3, 12, 3],
            "sqlite": "3.45.1",
            "systemd": {"code": 0, "stdout": "running\n", "stderr": ""},
            "failed": {"code": 0, "stdout": "", "stderr": ""},
        }
        for patch in (
            mock.patch.object(self.image, "ROOT", self.root),
            mock.patch.object(self.image, "ROOT_UID", os.geteuid()),
            mock.patch.object(self.image, "ROOT_GID", os.getegid()),
            mock.patch.object(
                self.image,
                "environment",
                side_effect=lambda: copy.deepcopy(self.environment),
            ),
            mock.patch.object(self.image, "accounts", side_effect=self.accounts),
            mock.patch.object(
                self.image,
                "account_files",
                side_effect=lambda: copy.deepcopy(self.account_signatures),
                create=True,
            ),
            mock.patch.object(self.image, "unit", side_effect=self.unit),
            mock.patch.object(self.image, "command", side_effect=self.command),
            mock.patch.object(
                self.image,
                "read_as_application",
                side_effect=lambda: {
                    "uid": 1100,
                    "gid": 1100,
                    "sha256": self.image.digest(
                        self.image.path(self.image.PROGRAM).read_bytes()
                    ),
                    "compiled": True,
                },
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def accounts(self):
        return {
            "uid_owners": ["reference-ledger"] if self.created else [],
            "gid_owners": ["reference-ledger"] if self.created else [],
            "names_used": self.created,
            "account": self.image.ACCOUNT if self.created else None,
            "uid_processes": [],
            "gid_processes": [],
            "home_exists": False,
            "base": {
                name: "a" * 64 for name in ("passwd", "group", "shadow", "gshadow")
            },
            "subids": {name: "b" * 64 for name in ("subuid", "subgid")},
            "files": copy.deepcopy(self.account_signatures),
        }

    def unit(self):
        return {
            "LoadState": "loaded" if self.loaded else "not-found",
            "ActiveState": "inactive",
            "SubState": "dead",
            "MainPID": "0",
            "UnitFileState": "disabled" if self.loaded else "",
            "User": "1100" if self.loaded else "",
            "Group": "1100" if self.loaded else "",
            "DropInPaths": "",
            "FragmentPath": self.image.UNIT_PATH if self.loaded else "",
        }

    def command(self, argv):
        self.commands.append(argv)
        if argv == self.image.USERADD:
            self.assertFalse(self.image.path(self.image.PROGRAM).exists())
            self.created = True
        if argv == ["/usr/bin/systemctl", "daemon-reload"]:
            self.assertTrue(self.created)
            self.assertTrue(self.image.path(self.image.PROGRAM).exists())
            self.loaded = True
        return {"code": 0, "stdout": "", "stderr": ""}

    def test_check_does_not_create_account_files_or_claim(self):
        result = self.image.prepare(self.program, check_mode=True)
        self.assertFalse(result["changed"] or result["image_verified"])
        self.assertTrue(result["would_change"])
        self.assertFalse(self.commands or self.created)
        self.assertFalse(self.image.path(self.image.CLAIM).exists())

    def test_install_account_first_then_readable_pinned_disabled_image(self):
        result = self.image.prepare(self.program, allow_changes=True)
        self.assertTrue(result["image_verified"])
        self.assertEqual(
            self.commands,
            [
                self.image.GROUPADD,
                self.image.USERADD,
                ["/usr/bin/systemctl", "daemon-reload"],
            ],
        )
        self.assertEqual(self.image.path(self.image.PROGRAM).read_bytes(), self.program)
        self.assertEqual(
            self.image.path(self.image.PROGRAM).stat().st_mode & 0o777, 0o644
        )
        self.assertEqual(
            self.image.path(self.image.PROGRAM).parent.stat().st_mode & 0o777, 0o755
        )
        for name in self.image.RETAINED:
            self.assertFalse(self.image.path(name).exists())
        observed = self.image.inspect_image(self.program)
        self.assertTrue(observed["image_verified"])
        self.assertFalse(observed["changed"])

    def test_wrong_artifact_or_disabled_apply_refuses_before_any_environment_access(
        self,
    ):
        with mock.patch.object(self.image, "environment") as environment:
            for program, allow in ((b"not the artifact", True), (self.program, False)):
                with self.assertRaises(ValueError):
                    self.image.prepare(program, allow_changes=allow)
        environment.assert_not_called()
        self.assertFalse(self.commands)

    def test_host_identity_mapping_or_network_cannot_be_installed(self):
        for key, invalid in (
            ("uid_map", [[0, 0, 4294967295]]),
            ("gid_map", [[0, 0, 65536]]),
            ("interfaces", ["lo", "eth0"]),
            ("uid", 1000),
        ):
            environment = copy.deepcopy(self.environment)
            environment[key] = invalid
            with mock.patch.object(self.image, "environment", return_value=environment):
                with self.assertRaises(ValueError):
                    self.image.prepare(self.program, allow_changes=True)
        self.assertFalse(self.commands or self.image.path(self.image.CLAIM).exists())

    def test_existing_account_or_retained_data_refuses_without_mutation(self):
        self.created = True
        with self.assertRaises(ValueError):
            self.image.prepare(self.program, allow_changes=True)
        self.created = False
        self.image.path(self.image.RETAINED[0]).mkdir()
        with self.assertRaises(ValueError):
            self.image.prepare(self.program, allow_changes=True)
        self.assertFalse(self.commands or self.image.path(self.image.CLAIM).exists())

    def test_partial_account_failure_is_consumed_and_never_replayed(self):
        original = self.command

        def fail(argv):
            if argv == self.image.USERADD:
                raise OSError("account creation uncertain")
            return original(argv)

        with mock.patch.object(self.image, "command", side_effect=fail):
            with self.assertRaises(OSError) as failure:
                self.image.prepare(self.program, allow_changes=True)
        claim = self.image.path(self.image.CLAIM)
        self.assertTrue((claim / "failed.json").exists())
        self.assertTrue(failure.exception.mutation_attempted)
        self.assertTrue(failure.exception.effects_may_exist)
        self.assertEqual(
            json.loads((claim / "failed.json").read_bytes())["stage"], "account"
        )
        self.assertFalse((claim / "complete.json").exists())
        count = len(self.commands)
        with self.assertRaises(ValueError):
            self.image.prepare(self.program, allow_changes=True)
        self.assertEqual(len(self.commands), count)

    def test_claim_sync_failure_reports_uncertainty_before_account_commands(self):
        with mock.patch.object(
            self.image, "sync_directory", side_effect=OSError("sync uncertain")
        ):
            with self.assertRaises(OSError) as failure:
                self.image.prepare(self.program, allow_changes=True)
        self.assertTrue(failure.exception.mutation_attempted)
        self.assertTrue(failure.exception.effects_may_exist)
        self.assertTrue(self.image.path(self.image.CLAIM).exists())
        self.assertFalse(self.commands)

    def test_racing_foreign_claim_is_never_modified(self):
        claim = self.image.path(self.image.CLAIM)
        mkdir = Path.mkdir

        def raced(p, *args, **kwargs):
            if p == claim:
                mkdir(p, *args, **kwargs)
                (p / "foreign.json").write_bytes(b"preserve")
                raise FileExistsError("other creator won")
            return mkdir(p, *args, **kwargs)

        with mock.patch.object(Path, "mkdir", raced):
            with self.assertRaises(FileExistsError) as failure:
                self.image.prepare(self.program, allow_changes=True)
        self.assertTrue(failure.exception.mutation_attempted)
        self.assertFalse(failure.exception.effects_may_exist)
        self.assertEqual({p.name for p in claim.iterdir()}, {"foreign.json"})
        self.assertEqual((claim / "foreign.json").read_bytes(), b"preserve")
        self.assertFalse(self.commands)

    def test_post_install_readability_or_artifact_drift_cannot_qualify(self):
        with mock.patch.object(
            self.image,
            "read_as_application",
            side_effect=PermissionError("cannot read"),
        ):
            with self.assertRaises(PermissionError):
                self.image.prepare(self.program, allow_changes=True)
        self.assertFalse((self.image.path(self.image.CLAIM) / "complete.json").exists())

    def test_candidate_completion_alone_cannot_hide_late_program_change(self):
        write = self.image.write_json

        def late(path, value):
            result = write(path, value)
            if path.name == "complete.json":
                self.image.path(self.image.PROGRAM).write_bytes(b"changed")
            return result

        with mock.patch.object(self.image, "write_json", side_effect=late):
            with self.assertRaises(ValueError):
                self.image.prepare(self.program, allow_changes=True)
        claim = self.image.path(self.image.CLAIM)
        self.assertTrue((claim / "complete.json").exists())
        self.assertTrue((claim / "failed.json").exists())

    def test_account_file_change_during_final_unit_read_cannot_qualify(self):
        reads = []
        provider = self.unit

        def unit():
            reads.append(True)
            if len(reads) == 5:
                self.account_signatures["passwd"]["sha256"] = "f" * 64
            return provider()

        with mock.patch.object(self.image, "unit", side_effect=unit):
            with self.assertRaises(ValueError):
                self.image.prepare(self.program, allow_changes=True)
        self.assertTrue((self.image.path(self.image.CLAIM) / "failed.json").exists())

    def account_database_fixture(self):
        (self.root / "proc").mkdir()
        for name in self.image.ACCOUNT_DATABASES:
            p = self.root / "etc" / name
            p.write_bytes(b"root:synthetic-private-value:0:0\n")
            p.chmod(0o640)
        p = self.root / "etc/subgid"
        p.write_bytes(b"")
        p.chmod(0o640)

    def test_real_private_account_files_report_only_fingerprints(self):
        self.account_database_fixture()
        with mock.patch.object(
            self.image.pwd, "getpwall", return_value=[]
        ), mock.patch.object(
            self.image.grp, "getgrall", return_value=[]
        ), mock.patch.object(
            self.image, "account_files", side_effect=self.real_account_files
        ):
            value = self.real_accounts()
        self.assertNotIn("synthetic-private-value", json.dumps(value))
        self.assertEqual(
            value["files"]["shadow"]["sha256"],
            self.image.digest((self.root / "etc/shadow").read_bytes()),
        )
        self.assertIsNone(value["subids"]["subuid"])
        self.assertEqual(value["subids"]["subgid"], self.image.digest(b""))

    def test_real_account_file_change_during_name_lookup_refuses(self):
        self.account_database_fixture()

        def changed():
            (self.root / "etc/passwd").write_bytes(b"changed\n")
            return []

        with mock.patch.object(
            self.image.pwd, "getpwall", side_effect=changed
        ), mock.patch.object(
            self.image.grp, "getgrall", return_value=[]
        ), mock.patch.object(
            self.image, "account_files", side_effect=self.real_account_files
        ):
            with self.assertRaises(self.image.ImageError) as failure:
                self.real_accounts()
        self.assertEqual(
            failure.exception.code, "reference-image-account-files-changed"
        )


if __name__ == "__main__":
    unittest.main()
