"""Implicit default storage is valid; absence is an observed state, not a repair."""

import errno
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

from test_reference_handoff_guard import guard, SOURCE, example


class StorageSealTests(unittest.TestCase):
    def setUp(self):
        scratch = SOURCE.parents[2] / ".generated"
        scratch.mkdir(mode=0o700, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch, prefix="storage-seal-")
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.path = self.parent / "storage.cfg"
        patch = mock.patch.object(guard, "ROOT_UID", os.geteuid())
        patch.start()
        self.addCleanup(patch.stop)

    def test_absent_storage_is_stable_without_creating_a_file(self):
        first = guard._storage_seal(self.path)
        self.assertEqual(first["state"], "absent")
        self.assertEqual(first, guard._storage_seal(self.path))
        self.assertFalse(self.path.exists())

    def test_present_storage_retains_full_fingerprint(self):
        self.path.write_bytes(b"dir: local\n\tpath /var/lib/vz\n")
        self.path.chmod(0o600)
        first = guard._storage_seal(self.path)
        self.assertEqual(first["state"], "present")
        self.assertEqual(
            first["file"]["sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest()
        )
        self.path.write_bytes(b"changed storage\n")
        self.assertNotEqual(first, guard._storage_seal(self.path))

    def test_creation_and_removal_change_the_seal(self):
        absent = guard._storage_seal(self.path)
        self.path.write_bytes(b"dir: local\n")
        self.path.chmod(0o600)
        present = guard._storage_seal(self.path)
        self.assertNotEqual(absent, present)
        self.path.unlink()
        self.assertEqual(absent, guard._storage_seal(self.path))

    def test_regular_and_broken_symlinks_never_count_as_absence(self):
        target = self.parent / "target"
        target.write_bytes(b"fixture")
        self.path.symlink_to(target)
        with self.assertRaises((ValueError, OSError)):
            guard._storage_seal(self.path)
        target.unlink()
        with self.assertRaises((ValueError, OSError)):
            guard._storage_seal(self.path)

    def test_directory_and_fifo_leaves_refuse(self):
        self.path.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            guard._storage_seal(self.path)
        self.path.rmdir()
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(ValueError):
            guard._storage_seal(self.path)

    def test_writable_parent_refuses(self):
        self.parent.chmod(0o770)
        with self.assertRaises(ValueError):
            guard._storage_seal(self.path)

    def test_permission_error_is_not_absence(self):
        original = guard.os.stat

        def read(path, *args, **kwargs):
            if path == self.path.name and kwargs.get("dir_fd") is not None:
                raise PermissionError(errno.EACCES, "unavailable")
            return original(path, *args, **kwargs)

        with mock.patch.object(guard.os, "stat", side_effect=read):
            with self.assertRaises(OSError):
                guard._storage_seal(self.path)

    def test_parent_replacement_during_a_file_read_refuses(self):
        self.path.write_bytes(b"fixture")
        self.path.chmod(0o600)
        original = guard._file_seal
        moved = self.parent.with_name(self.parent.name + "-moved")
        self.addCleanup(lambda: __import__("shutil").rmtree(moved, ignore_errors=True))

        def sealed(path, **kwargs):
            result = original(path, **kwargs)
            self.parent.rename(moved)
            self.parent.mkdir(mode=0o700)
            self.path.write_bytes(b"fixture")
            self.path.chmod(0o600)
            return result

        with mock.patch.object(guard, "_file_seal", side_effect=sealed):
            with self.assertRaises(ValueError):
                guard._storage_seal(self.path)

    def test_group_write_on_a_present_file_refuses(self):
        self.path.write_bytes(b"fixture")
        self.path.chmod(0o660)
        with self.assertRaises(ValueError):
            guard._storage_seal(self.path)

    def test_unrelated_parent_metadata_changes_do_not_change_absence(self):
        before = guard._storage_seal(self.path)
        (self.parent / "unrelated").write_bytes(b"fixture")
        self.assertEqual(before, guard._storage_seal(self.path))

    def test_read_only_nonroot_parent_group_is_retained(self):
        real_lstat, real_fstat = Path.lstat, os.fstat
        inode = self.parent.stat().st_ino

        def group(info):
            if info.st_ino != inode:
                return info
            return SimpleNamespace(
                st_dev=info.st_dev,
                st_ino=info.st_ino,
                st_mode=info.st_mode,
                st_uid=info.st_uid,
                st_gid=33,
            )

        with mock.patch.object(
            Path,
            "lstat",
            side_effect=lambda path: group(real_lstat(path)),
            autospec=True,
        ), mock.patch.object(
            guard.os, "fstat", side_effect=lambda fd: group(real_fstat(fd))
        ):
            observed = guard._storage_seal(self.path)
        self.assertEqual(observed["parent"][-1], 33)

    def test_only_enoent_is_an_absent_leaf(self):
        original = guard.os.stat

        def read(path, *args, **kwargs):
            if path == self.path.name and kwargs.get("dir_fd") is not None:
                raise FileNotFoundError(errno.EACCES, "not actually absent")
            return original(path, *args, **kwargs)

        with mock.patch.object(guard.os, "stat", side_effect=read):
            with self.assertRaises(ValueError):
                guard._storage_seal(self.path)

    def test_file_appearing_before_closure_refuses(self):
        original = guard.os.stat
        count = 0

        def read(path, *args, **kwargs):
            nonlocal count
            if path == self.path.name and kwargs.get("dir_fd") is not None:
                count += 1
                if count == 2:
                    self.path.write_bytes(b"fixture")
                    self.path.chmod(0o600)
            return original(path, *args, **kwargs)

        with mock.patch.object(guard.os, "stat", side_effect=read):
            with self.assertRaises(ValueError):
                guard._storage_seal(self.path)

    def test_foreign_parent_error_closes_its_directory_descriptor(self):
        before = {path.name for path in Path("/proc/self/fd").iterdir()}
        with mock.patch.object(guard, "ROOT_UID", os.geteuid() + 1):
            with self.assertRaises(ValueError):
                guard._storage_seal(self.path)
        self.assertEqual(
            before, {path.name for path in Path("/proc/self/fd").iterdir()}
        )

    def test_core_collector_admits_both_storage_states_and_preserves_other_seals(self):
        policy, _ = example()
        root, data, config, lxc = [
            self.parent / name for name in ("root.raw", "data", "config", "lxc")
        ]
        data.mkdir(mode=0o700)
        config.mkdir(mode=0o700)
        (lxc / str(policy["vmid"])).mkdir(mode=0o700, parents=True)
        root.write_bytes(b"fixture image")
        (data / "ledger.sqlite3").write_bytes(b"SQLite format 3\0fixture")
        (config / "application.json").write_bytes(b"private fixture identity")
        (lxc / str(policy["vmid"]) / "config").write_bytes(b"fixture generated config")
        mapping = {
            "/etc/pve/storage.cfg": self.path,
            "/var/lib/lxc": lxc,
            policy["rootfs"]["path"]: root,
            policy["datasets"]["data"]["mountpoint"]: data,
            policy["datasets"]["config"]["mountpoint"]: config,
        }
        with mock.patch.object(
            guard, "Path", side_effect=lambda path: mapping.get(str(path), Path(path))
        ):
            absent = guard._core_files(policy)
            self.path.write_bytes(b"dir: local\n")
            self.path.chmod(0o600)
            present = guard._core_files(policy)
        self.assertEqual(absent["storage"]["state"], "absent")
        self.assertEqual(present["storage"]["state"], "present")
        self.assertEqual(
            {key: value for key, value in absent.items() if key != "storage"},
            {key: value for key, value in present.items() if key != "storage"},
        )
