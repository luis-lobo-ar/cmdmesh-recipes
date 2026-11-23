"""Optional actual CLI parser contract. Set CMDMESH_BIN to a compiled binary."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = os.environ.get("CMDMESH_BIN")


@unittest.skipUnless(BINARY, "set CMDMESH_BIN for actual core parser validation")
class CoreContract(unittest.TestCase):
    def test_operation_discovery_exposes_check_plans_and_one_fixed_verified_profile(self):
        result = subprocess.run([BINARY, "operation", "list", "--catalog", str(ROOT)],
                                capture_output=True, text=True, timeout=10, check=True)
        entries = json.loads(result.stdout)["items"]
        expected = {"proxmox-host-baseline-check", "proxmox-backup-schedule-check",
                    "proxmox-host-maintenance-check", "proxmox-lxc-growth-check",
                    "proxmox-lxc-memory-grow"}
        self.assertEqual({entry["id"] for entry in entries}, expected)
        for entry in entries:
            inspected = subprocess.run([BINARY, "operation", "inspect", entry["id"],
                                        "--catalog", str(ROOT)],
                                       capture_output=True, text=True, timeout=10, check=True)
            operation = json.loads(inspected.stdout)
            if entry["id"] == "proxmox-lxc-memory-grow":
                self.assertEqual(operation["schema_version"], 2)
                self.assertEqual(operation["entrypoint"], {
                    "driver": "procedure-plan", "profile": "proxmox-lxc-memory",
                    "profile_version": 1})
                self.assertEqual({name: spec["type"] for name, spec in
                                  operation["parameters"].items()}, {
                    "inspector": "inspector", "state_directory": "state-directory",
                    "request": "memory-request", "desired_memory_mb": "memory-mb",
                    "capacity_policy": "memory-capacity-policy"})
            else:
                self.assertEqual(operation["entrypoint"]["operation"], "check")
                self.assertEqual(operation["parameters"]["target"]["type"], "target")
            self.assertTrue(operation["known_failures"])
            self.assertTrue(operation["provenance"]["limitations"])

    def test_memory_example_validates_offline_without_claiming_live_qualification(self):
        scratch = ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        source = ROOT / "examples/private-memory"
        with tempfile.TemporaryDirectory(prefix="memory-inputs-", dir=scratch) as directory:
            inputs = Path(directory) / "inputs.json"
            values = json.loads((source / "operation-inputs.json").read_text())
            inputs.write_text(json.dumps(values))
            command = [BINARY, "--config", str(source / "environment.json"),
                       "operation", "validate-inputs", "proxmox-lxc-memory-grow",
                       "--catalog", str(ROOT), "--inputs", str(inputs)]
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=10, check=True)
            report = json.loads(result.stdout)
            self.assertTrue(report["valid"])
            self.assertFalse(report["requirements_evaluated"])
            self.assertEqual(report["execution"], "not-run")
            self.assertNotIn(values["request"]["owner_tag"], result.stdout)
            values["execute"] = True
            inputs.write_text(json.dumps(values))
            invalid = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertFalse(json.loads(invalid.stdout)["valid"])

    def test_catalog_memory_entry_prepares_against_the_actual_pinned_native_inspector(self):
        """Reuse the pinned integration's loopback TLS/synthetic SSH fixtures."""
        package = Path(os.environ.get("CMDMESH_PROXMOX_ROOT", ROOT.parent / "cmdmesh-proxmox"))
        if not package.is_dir():
            if "CMDMESH_PROXMOX_ROOT" in os.environ:
                self.fail("explicit CMDMESH_PROXMOX_ROOT does not exist")
            self.skipTest("set CMDMESH_PROXMOX_ROOT to the integration checkout")
        # Tests are a pinned cross-repository qualification dependency, not a
        # runtime dependency of the catalog. Avoid a second synthetic domain model.
        sys.path.insert(0, str(package / "tests"))
        from test_memory_phases import MemoryPhaseTests
        MemoryPhaseTests.setUpClass()
        fixture = MemoryPhaseTests()
        try:
            fixture.setUp()
            with fixture.transports() as (tls_port, ssh_port, requests):
                parameters, native = fixture.configured(tls_port, ssh_port)
                scratch = ROOT / ".generated"
                scratch.mkdir(mode=0o700, exist_ok=True)
                journal = tempfile.TemporaryDirectory(prefix="memory-journal-", dir=scratch)
                self.addCleanup(journal.cleanup)
                state = Path(journal.name) / "state"
                state.mkdir(mode=0o700)
                inputs = fixture.base / "inputs.json"
                parameters.pop("phase")
                parameters.update(inspector="test-inspector", state_directory=str(state))
                inputs.write_text(json.dumps(parameters))
                config = fixture.base / "environment.json"
                config.write_text(json.dumps({
                    "schema_version": 1, "packages": {"cmdmesh-proxmox": str(package.resolve())},
                    "providers": {"test-inspector": {
                        "executable": str(fixture.bundle),
                        "expected_sha256": hashlib.sha256(fixture.bundle.read_bytes()).hexdigest(),
                        "config": native}},
                    "execution": {"allow_execution": False, "allow_mutations": False,
                                  "ansible_executable": native["controller"]["tools"]["ansible-playbook"],
                                  "timeout_seconds": 20}}))
                output = fixture.base / "plan.json"
                result = subprocess.run([
                    BINARY, "--config", str(config), "operation", "plan",
                    "grow owned LXC memory", "--catalog", str(ROOT),
                    "--inputs", str(inputs), "--out", str(output)],
                    capture_output=True, text=True, timeout=40)
                self.assertEqual(result.returncode, 0, result.stderr)
                plan = json.loads(output.read_text())
                self.assertEqual(plan["document_type"], "cmdmesh.procedure.plan")
                source = ROOT / "operations/proxmox-lxc-memory-grow/operation.json"
                self.assertEqual(plan["operation_source"], {
                    "id": "proxmox-lxc-memory-grow", "document": {
                        "path": str(source.resolve()),
                        "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}})
                prepared = plan["assessment"]["prepared"]
                self.assertEqual(prepared["desired_memory_mb"], parameters["desired_memory_mb"])
                self.assertEqual(prepared["capacity_policy"], parameters["capacity_policy"])
                self.assertEqual(prepared["request"]["selector"], parameters["request"]["selector"])
                self.assertTrue(all(plan["assessment"]["checks"].values()))
                self.assertFalse(plan["assessment"]["mutation_authorized"])
                self.assertEqual(requests, [])  # TLS identity only; no API writes.
                self.assertEqual(output.stat().st_mode & 0o077, 0)
                derived = json.loads(Path(plan["inner_plan"]["environment"]).read_text())
                self.assertFalse(derived["execution"]["allow_execution"])
                self.assertFalse(derived["execution"]["allow_mutations"])
        finally:
            fixture.doCleanups()
            MemoryPhaseTests.tearDownClass()
            sys.path.pop(0)

    def test_core_lists_the_entire_catalog(self):
        result = subprocess.run([BINARY, "recipe", "list", "--catalog", str(ROOT)],
                                capture_output=True, text=True, timeout=10, check=True)
        for path in (ROOT / "recipes").glob("*/recipe.json"):
            self.assertIn(path.parent.name, result.stdout)

    def test_core_inspects_every_manifest_without_execution(self):
        for path in sorted((ROOT / "recipes").glob("*/recipe.json")):
            with self.subTest(recipe=path.parent.name):
                result = subprocess.run([BINARY, "recipe", "inspect", str(path)],
                                        capture_output=True, text=True, timeout=10, check=True)
                manifest = json.loads(result.stdout)
                self.assertEqual(manifest["id"], path.parent.name)

    def test_real_core_plans_ready_recipes_without_enabling_execution(self):
        package = Path(os.environ.get("CMDMESH_PROXMOX_ROOT", ROOT.parent / "cmdmesh-proxmox"))
        if not package.is_dir():
            if "CMDMESH_PROXMOX_ROOT" in os.environ:
                self.fail("explicit CMDMESH_PROXMOX_ROOT does not exist")
            self.skipTest("set CMDMESH_PROXMOX_ROOT to the integration checkout")
        scratch = ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        examples = ROOT / "examples/private-environment"
        with tempfile.TemporaryDirectory(prefix="core-contract-", dir=scratch) as directory:
            private = Path(directory)
            environment = json.loads((examples / "environment.json").read_text())
            environment["packages"]["proxmox"] = str(package.resolve())
            environment["targets"]["lab"]["inventory"] = str(examples / "inventory.yml")
            environment["targets"]["lab"]["vars_file"] = str(examples / "growth.yml")
            environment["targets"]["lab"]["lifecycle_owner"] = "ansible"
            config = private / "environment.json"
            config.write_text(json.dumps(environment))
            for path in sorted((ROOT / "recipes").glob("*/recipe.json")):
                manifest = json.loads(path.read_text())
                plan = private / f"{manifest['id']}.plan.json"
                result = subprocess.run([
                    BINARY, "--config", str(config), "recipe", "plan", str(path),
                    "--target", "lab", "--operation", "check", "--out", str(plan)],
                    capture_output=True, text=True, timeout=20)
                with self.subTest(recipe=manifest["id"]):
                    if manifest["status"] == "draft":
                        self.assertNotEqual(result.returncode, 0)
                        self.assertFalse(plan.exists())
                        continue
                    self.assertEqual(result.returncode, 0, result.stderr)
                    output = json.loads(result.stdout)
                    self.assertRegex(output["digest"], r"^[a-f0-9]{64}$")
                    prepared = json.loads(plan.read_text())
                    self.assertEqual(prepared["operation"], "check")
                    self.assertIn("--check", prepared["commands"][0]["argv"])
                    operation_plan = private / f"{manifest['id']}.operation.plan.json"
                    inputs = private / "operation-inputs.json"
                    inputs.write_text(json.dumps({"target": "lab"}))
                    via_operation = subprocess.run([
                        BINARY, "--config", str(config), "operation", "plan", manifest["id"] + "-check",
                        "--catalog", str(ROOT), "--inputs", str(inputs), "--out", str(operation_plan)],
                        capture_output=True, text=True, timeout=20)
                    self.assertEqual(via_operation.returncode, 0, via_operation.stderr)
                    self.assertEqual(json.loads(operation_plan.read_text())["digest"], prepared["digest"])

    def test_plan_rejects_changed_automatic_inventory_group_variables(self):
        """A single inventory file still has automatically loaded sibling inputs."""
        self.assert_automatic_variables_bound("group_vars", "cmdmesh_targets", True)

    def test_plan_rejects_new_automatic_inventory_variables_after_approval(self):
        self.assert_automatic_variables_bound("group_vars", "cmdmesh_targets", False)

    def test_plan_rejects_changed_automatic_inventory_host_variables(self):
        self.assert_automatic_variables_bound("host_vars", "synthetic_local", True)

    def assert_automatic_variables_bound(self, kind, name, initially_exists):
        scratch = ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="inventory-binding-", dir=scratch) as directory:
            private = Path(directory)
            (private / "inventory.yml").write_text(
                "all:\n  children:\n    cmdmesh_targets:\n      hosts:\n        synthetic_local:\n")
            variables = private / kind / f"{name}.yml"
            if initially_exists:
                variables.parent.mkdir()
                variables.write_text("ansible_connection: local\nexample_value: before\n")
            environment = {
                "schema_version": 1, "providers": {}, "packages": {},
                "targets": {"test": {"inventory": "inventory.yml", "limit": "synthetic_local",
                                       "lifecycle_owner": "ansible"}},
                "execution": {"allow_execution": True, "allow_mutations": False,
                              "ansible_executable": "/usr/bin/true", "timeout_seconds": 5}}
            config = private / "environment.json"
            config.write_text(json.dumps(environment))
            recipe = private / "recipe"
            recipe.mkdir()
            (recipe / "README.md").write_text("Synthetic fixture; no infrastructure used.")
            (recipe / "playbook.yml").write_text(
                "- hosts: cmdmesh_targets\n  tasks:\n    - ansible.builtin.debug:\n        var: example_value\n")
            manifest = {"schema_version": 1, "id": "synthetic", "title": "Synthetic",
                        "summary": "Offline fixture", "status": "ready", "requirements": [],
                        "dependencies": [], "steps": [{"id": "test", "driver": "ansible",
                                                          "playbook": "playbook.yml"}],
                        "verification": [], "recovery": "README.md"}
            source = recipe / "recipe.json"
            source.write_text(json.dumps(manifest))
            plan = private / "plan.json"
            result = subprocess.run([
                BINARY, "--config", str(config), "recipe", "plan", str(source),
                "--target", "test", "--operation", "check", "--out", str(plan)],
                capture_output=True, text=True, timeout=10, check=True)
            digest = json.loads(result.stdout)["digest"]
            variables.parent.mkdir(exist_ok=True)
            variables.write_text("ansible_connection: local\nexample_value: changed-after-approval\n")
            executed = subprocess.run([
                BINARY, "recipe", "execute", "--plan", str(plan), "--approve-digest", digest],
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(executed.returncode, 0,
                                f"automatic inventory {kind} changed but approved plan still executed")


if __name__ == "__main__":
    unittest.main()
