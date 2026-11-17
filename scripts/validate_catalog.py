#!/usr/bin/env python3
"""Validate the portable CmdMesh v1 recipe contract without running recipes."""
import argparse
import json
from pathlib import Path
import re

FIELDS = {"schema_version", "id", "title", "summary", "status", "requirements",
          "dependencies", "steps", "verification", "recovery"}
SLUG = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")


def artifact(root, value):
    if not isinstance(value, str) or not value:
        raise ValueError("artifact must be a nonempty relative path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("artifact path escapes recipe")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("symlink recipe artifacts are not supported")
    if not current.is_file():
        raise ValueError(f"missing recipe artifact: {value}")


def strings(value):
    return isinstance(value, list) and all(isinstance(item, str) and item.strip()
                                           for item in value)


def validate_manifest(manifest, root):
    if not isinstance(manifest, dict) or set(manifest) != FIELDS:
        raise ValueError("manifest fields must match the v1 contract")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("unsupported schema_version")
    if not isinstance(manifest["id"], str) or not SLUG.fullmatch(manifest["id"]):
        raise ValueError("invalid recipe id")
    for field in ("title", "summary"):
        if not isinstance(manifest[field], str) or not manifest[field].strip():
            raise ValueError(f"missing {field}")
    for field in ("requirements", "dependencies", "verification"):
        if not strings(manifest[field]) or len(set(manifest[field])) != len(manifest[field]):
            raise ValueError(f"invalid {field}")
    if manifest["status"] not in ("ready", "draft"):
        raise ValueError("invalid status")
    if not isinstance(manifest["steps"], list):
        raise ValueError("steps must be a list")
    if manifest["status"] == "ready" and not all(manifest[key] for key in
                                                ("steps", "requirements", "verification")):
        raise ValueError("ready recipes require steps, requirements and verification")
    if manifest["status"] == "draft" and manifest["steps"]:
        raise ValueError("draft recipes in this catalog cannot execute")
    seen = set()
    for step in manifest["steps"]:
        if not isinstance(step, dict) or set(step) != {"id", "driver", "playbook"}:
            raise ValueError("invalid step fields")
        if not isinstance(step["id"], str) or not SLUG.fullmatch(step["id"]):
            raise ValueError("invalid step id")
        if step["id"] in seen or step["driver"] != "ansible":
            raise ValueError("duplicate step or unsupported driver")
        seen.add(step["id"])
        artifact(root, step["playbook"])
    artifact(root, manifest["recovery"])
    return manifest


def validate_catalog(root):
    root = Path(root)
    manifests = []
    for path in sorted((root / "recipes").glob("*/recipe.json")):
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("symlink recipes are not supported")
        manifest = validate_manifest(json.loads(path.read_text()), path.parent)
        if manifest["id"] != path.parent.name:
            raise ValueError("recipe directory must match id")
        manifests.append(manifest)
    if not manifests:
        raise ValueError("empty recipe catalog")
    return manifests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", nargs="?", type=Path,
                        default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        manifests = validate_catalog(args.catalog)
    except (ValueError, OSError) as error:
        parser.exit(1, f"catalog validation failed: {error}\n")
    print(f"Validated {len(manifests)} recipes; no recipe executed.")


if __name__ == "__main__":
    main()
