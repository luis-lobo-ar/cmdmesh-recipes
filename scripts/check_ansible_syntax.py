#!/usr/bin/env python3
"""Resolve all ready recipe roles with Ansible syntax-check; never run a play."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

from validate_catalog import validate_catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collection-root", required=True, type=Path,
                        help="cmdmesh-proxmox checkout root")
    parser.add_argument("--ansible", default="ansible-playbook")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    collection_path = args.collection_root.resolve() / "ansible"
    if not (collection_path / "ansible_collections/cmdmesh/proxmox").is_dir():
        parser.error("collection root does not contain cmdmesh.proxmox")
    scratch = root / ".generated"
    scratch.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="syntax-", dir=scratch) as temporary:
        env = dict(os.environ, ANSIBLE_COLLECTIONS_PATH=str(collection_path),
                   ANSIBLE_LOCAL_TEMP=temporary, ANSIBLE_REMOTE_TEMP=temporary,
                   ANSIBLE_NOCOLOR="1")
        for manifest in validate_catalog(root):
            for step in manifest["steps"]:
                subprocess.run([
                    args.ansible, "-i", str(root / "examples/private-environment/inventory.yml"),
                    str(root / "recipes" / manifest["id"] / step["playbook"]),
                    "--syntax-check"], check=True, env=env)
    print("All ready recipe syntax checks passed; no host connection requested.")


if __name__ == "__main__":
    main()
