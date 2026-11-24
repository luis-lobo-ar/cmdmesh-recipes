# Reference pre-start guard

`prestart_guard.py` checks retained storage before a managed reference container
starts. A directory left behind by a missing ZFS mount fails validation. The guard
does not create directories, initialize a database, change ownership, or repair
storage.

The helper is a standalone Python program. It has no dependency on a private
repository. Local tests cover refusal behavior. Actual systemd attachment,
guarded container starts, rootfs replacement, and independent restore remain
separate qualification requirements. The persistence recipe remains a draft.

## Supported reference layout

The guard supports one unprivileged, NIC-free Proxmox LXC with these properties:

- An ext4 raw rootfs on a directory storage backend.
- Separate mounted ZFS data and configuration datasets.
- A single UID and GID mapping of 65,536 IDs.
- A declared application UID and GID inside that mapping.
- Data mounted at `/var/lib/reference-ledger` and configuration at `/etc/reference-ledger`.
- Both bind mounts excluded from ordinary container backup with `backup=0`.
- Existing private application configuration and SQLite database.

Custom LXC directives, nesting, hooks, extra mounts, and additional devices refuse
validation. The helper does not implement a general application deployment or a
backup command.

## Manifest

[The example manifest](prestart-manifest.example.json) contains fictional
identities. Every identity must come from the current approved target. Adding
tags or replacing observations to make an unrelated target match is not adoption.

| Field | Meaning |
| --- | --- |
| `node`, `vmid` | Exact managed Proxmox node and container. |
| `owner_tag`, `generation_tag` | Expected lifecycle owner and generation. |
| `generated_config_stable_sha256` | Approved generated LXC bytes with only the single CPU-selection value replaced by an empty hash placeholder. |
| `cpu_policy` | Approved CPU count and permitted host CPU IDs. Selection must also belong to the guard process's actual available affinity. |
| `mapping` | Host offset, mapping length, and application UID and GID. |
| `rootfs` | Expected volume, backing file, size, inode, and ext4 UUID. |
| `datasets` | Separate dataset names, GUIDs, and host mountpoints. |
| `application` | Initialized state, application instance ID, and configuration SHA256. |

The manifest is a root-owned regular file with mode `0600`. It belongs outside
both retained datasets. The manifest contains a configuration hash, not the
authentication token. Changes to the rootfs or credentials require an explicitly
reviewed manifest update after the new state passes validation.

Policy version `2` handles Proxmox's regenerated CPU placement. The generated
file must contain exactly one strictly parsed `lxc.cgroup2.cpuset.cpus` line.
Its nonempty CPU selection must be unique, match the approved and configured core
count, and fit both the approved CPU IDs and actual available affinity. Empty,
duplicate, reversed, oversized or unavailable selections refuse startup.

The hash covers every other byte, including the CPU line's key, spacing and
newline. Compute it from approved bytes with `generated_fingerprint(raw)[0]`;
the function also returns the parsed selection. The empty value used for hashing
is never a valid observed runtime selection. Only CPU placement within these
bounds can vary without changing approval. Memory, hostname, UID mapping, mount,
network or other directive changes still require explicit review and a manifest
update. The guard never refreshes its own approval.

Direct systemctl starts consume the generated file. Matching API configuration
alone does not establish what `lxc-start` will use. Version `1` manifests are
rejected; migration requires preparing a version `2` policy and explicitly
attaching the reviewed guard. Existing manifests are never silently upgraded.

The data and configuration directories must belong to the mapped application UID
and GID with mode `0700`. The identity and database files require mode `0600` and
the same ownership. For example, container UID `1100` with offset `100000` maps to
host UID `101100`. Bootstrap owns the initial assignment. The guard never changes it.
The guest service also needs a registered locked, non-login application account
with those IDs before startup; numeric service IDs alone are not qualification.

## Command and outcomes

The command runs on the Proxmox host as root:

```sh
python3 -I -S -B /usr/local/lib/reference-ledger/prestart_guard.py \
	--manifest /etc/cmdmesh/reference-ledger.json --vmid 101
```

Exit `0` returns `{"outcome":"qualified"}`. Exit `1` returns `refused` with a
reason code. Output contains no authentication token or configuration contents.
Missing observations refuse acceptance.

Checks use read-only PVE configuration, the generated UID and GID mappings, actual
raw-rootfs identity, ZFS properties, and exact mountpoints. PVE storage must resolve
the selected volume to the expected backing file. A leftover image at an old
storage path does not qualify. An ordinary directory
covered by the root filesystem does not qualify as a retained mount. Application
checks require the existing identity, credential-file hash, private permissions,
and SQLite header. Normal ledger startup also verifies the database schema and
instance identity.

## Managed start attachment

[The instance drop-in example](prestart.conf.example) adds an `ExecStartPre` check.
For container `101`, the intended attachment paths are:

```text
/etc/systemd/system/pve-container@101.service.d/10-reference-persistence.conf
/etc/systemd/system/pve-container-debug@101.service.d/10-reference-persistence.conf
```

Both normal and debug units need the check. PVE GUI, API, and `pct` starts use
those units. Direct systemctl starts also run their `ExecStartPre` checks. A direct
administrator invocation of `lxc-start` bypasses this managed path.

The check does not require a running container or take its configuration lock.
The retained datasets must already be mounted on the host. The application
remains responsible for its retained-file writer lock. Independent restored
copies need an explicit cutover policy.

A failed guard leaves the container stopped when systemd invokes it before
`ExecStart`. Recovery requires inspection of the named target, mounts, and retained
state. Disabling the check or initializing an empty replacement is not recovery.
