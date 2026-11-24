"""Offline catalog contract tests. No infrastructure commands are executed."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("catalog", ROOT / "scripts/validate_catalog.py")
catalog = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(catalog)


class CatalogContract(unittest.TestCase):
    def test_catalog_has_five_runnable_recipes_and_one_draft(self):
        manifests = catalog.validate_catalog(ROOT)
        self.assertEqual({item["id"] for item in manifests if item["status"] == "ready"},
                         {"proxmox-host-baseline", "proxmox-backup-schedule",
                          "proxmox-host-maintenance", "proxmox-lxc-growth", "proxmox-nfs-backup-storage"})
        draft = next(item for item in manifests if item["id"] == "ephemeral-lxc-zfs")
        self.assertEqual(draft["status"], "draft")
        self.assertEqual(draft["steps"], [])

    def test_unknown_fields_unsafe_paths_and_drivers_are_rejected(self):
        valid = json.loads((ROOT / "recipes/proxmox-host-baseline/recipe.json").read_text())
        for field, value in [("unknown", True), ("schema_version", 2), ("status", "complete")]:
            candidate = copy.deepcopy(valid)
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                catalog.validate_manifest(candidate, ROOT / "recipes/proxmox-host-baseline")
        for step in [{"id": "bad", "driver": "shell", "playbook": "playbook.yml"},
                     {"id": "bad", "driver": "ansible", "playbook": "../../LICENSE"}]:
            candidate = copy.deepcopy(valid)
            candidate["steps"] = [step]
            with self.subTest(step=step), self.assertRaises(ValueError):
                catalog.validate_manifest(candidate, ROOT / "recipes/proxmox-host-baseline")

    def test_symlink_recipe_artifacts_are_rejected(self):
        valid = json.loads((ROOT / "recipes/proxmox-host-baseline/recipe.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("Recovery")
            (root / "playbook.yml").symlink_to(ROOT / "README.md")
            with self.assertRaises(ValueError):
                catalog.validate_manifest(valid, root)

    def test_growth_requires_exclusive_ansible_lifecycle_ownership(self):
        manifest = json.loads((ROOT / "recipes/proxmox-lxc-growth/recipe.json").read_text())
        self.assertIn("lifecycle-owner:ansible", manifest["requirements"])


if __name__ == "__main__":
    unittest.main()
