"""Optional actual CLI parser contract. Set CMDMESH_BIN to a compiled binary."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = os.environ.get("CMDMESH_BIN")


@unittest.skipUnless(BINARY, "set CMDMESH_BIN for actual core parser validation")
class CoreContract(unittest.TestCase):
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
