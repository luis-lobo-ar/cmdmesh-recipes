"""A collection lacking the create-only role must fail before connecting."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = shutil.which("ansible-playbook")


@unittest.skipUnless(ANSIBLE, "ansible-playbook is needed for collection resolution")
class CollectionGuardTests(unittest.TestCase):
    def test_old_collection_cannot_silently_ignore_create_only(self):
        scratch = ROOT / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="old-nfs-collection-", dir=scratch) as work:
            work = Path(work)
            role = work / "collections/ansible_collections/cmdmesh/proxmox/roles/proxmox_nfs_backup_storage/tasks"
            role.mkdir(parents=True)
            (role / "main.yml").write_text("---\n[]\n")
            result = subprocess.run([ANSIBLE, "-i", str(ROOT / "examples/private-environment/inventory.yml"), str(ROOT / "recipes/proxmox-nfs-backup-storage/playbook.yml"), "--syntax-check"], capture_output=True, text=True, timeout=20, env={**os.environ, "ANSIBLE_COLLECTIONS_PATH": str(work / "collections"), "ANSIBLE_HOME": str(work / "home"), "ANSIBLE_LOCAL_TEMP": str(work / "tmp"), "TMPDIR": str(work)})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("proxmox_nfs_backup_create", result.stderr)


if __name__ == "__main__":
    unittest.main()
