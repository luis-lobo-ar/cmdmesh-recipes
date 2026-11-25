# Guard a replacement guest's retained data

`handoff_guard.py` is a read-only schema3 pre-start guard for the reference
ledger. It checks the mounted data and configuration datasets before a
replacement container starts. Its public predecessor, `prestart_guard.py`,
continues to enforce schema2 unchanged.

The successor also checks who owns the retained pair. A root-owned record
selects one active guest generation. Both normal and debug starts of the retired
guest must have an effective `/usr/bin/false` pre-start command. The preserved
earlier guard remains on disk. These checks cover managed systemd starts.

This component has local tests. Native data attachment, application recovery,
and the complete handoff workflow are not yet qualified.

## CPU contract

Schema3 supports this reference profile with one core and a CPU limit of one.
The generated configuration must contain exactly one CPU quota directive with
`100000 100000`. It can select one approved CPU or initially leave its CPU
selection empty. For an empty selection, every available parent CPU must be in
the policy's approved set. A later runtime check must establish the actual
one-CPU placement and quota before reporting a successful rebuild.

Only the generator's CPU selection is excluded from the stable generated-config
fingerprint. The bind mounts, privilege, namespace, quota, and other generated
bytes remain attributable to the checked configuration.

## Ownership record

Start with a qualified schema2 policy. Change `schema_version` to `3` and add:

```json
"retired_guest": {
  "vmid": 100,
  "generation_tag": "cmdmesh-gen-33333333333333333333333333333333",
  "preserved_dropin_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
}
```

The example hashes and generation are placeholders. The retired guest must be
distinct from the active guest and have the declared owner and generation tags.
The preserved drop-in hash must match the checked source's existing guard.

`owner_document(policy)` builds the exact ownership record. Its path is
`/var/lib/cmdmesh/persistence-owners/<pair-key>/owner.json`. The pair key is the
SHA-256 of the canonical sorted dataset GUIDs, matching the Proxmox package's
pair-lock identity. The record selects the active VMID, generation, and root UUID
and records the retired identity. Its state is `attached`.

The record and its directory require root ownership and modes `0600` and `0700`.
Control paths must be outside the retained datasets. The guard checks file
identity and bytes again after slow observations. It creates no state.
The collector also repeats the retained root, storage, dataset, mapping, and
application observations after ownership queries. Fast filesystem seals close
generated configuration, storage configuration, root identity, dataset
directories, credential fingerprints, and the database header afterwards.

## Retired start paths

Both retired unit directories must retain `50-cmdmesh-reference.conf` and have
only this additional `99-cmdmesh-retired-prestart.conf`:

```ini
[Service]
ExecStartPre=
ExecStartPre=/usr/bin/false
```

The reset comes after the preserved drop-in, so the effective command is the
denial. Both files require root ownership and mode `0600`. The guard validates
loaded commands through typed D-Bus data. It also checks that the retired guest
is stopped, has no pending changes, and has no HA ownership conflict.

## Read-only check

After a separately reviewed handoff has published these inputs, run:

```sh
python3 handoff_guard.py --manifest /etc/cmdmesh/reference-ledger3.json --vmid 101
```

Success prints `{"outcome":"qualified"}`. Failure prints a named refusal and
exits with status 1. Both normal and debug replacement units need the guard
before either can start. The application remains disabled during attachment.

Preserve claims, prior guard files, and partial operations after an interruption.
The application writer must start only after the source-state application lock
is released. Its file lock provides another single-writer check. The ownership
record and retired start denials select the intended guest.

The calling workflow must serialize the whole transition with the Proxmox
package's existing pair lock at
`/var/lib/cmdmesh/persistence/locks/<pair-key>.json`. Keep that lock through writer
startup while releasing the separate application-file lock. A second lock at a
different path would not exclude an existing backup from racing writer startup.
The guard itself is a pre-start predicate. The calling workflow owns this
operation-level serialization.
