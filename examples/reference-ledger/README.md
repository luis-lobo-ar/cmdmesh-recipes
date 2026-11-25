# Reference ledger for recovery tests

This is a working local application fixture for disposable persistence tests. It
is not an executable recovery recipe or a customer-facing application.

The replaceable rootfs holds the Python program and service definition. Separate
retained data and configuration datasets hold the SQLite database and application
identity/authentication configuration. Requests use a private local Unix socket.
Python and SQLite must already be present in the qualified template; do not give
a restored container a NIC merely to install them.

Initialization is explicit. Normal startup refuses missing databases, mismatched
identity, wrong UID or insecure ownership/modes. It must not silently initialize
empty replacement data. Writes require authentication and stable operation IDs;
matching retries preserve a record, while conflicting content refuses.

On Linux, each running ledger holds an exclusive advisory lock on the retained
`application.json` identity file. A second process using that file refuses startup
before opening the database or creating its socket. Normal shutdown and failed
startup release the lock. Keep this identity file unchanged while a writer runs.
The lock covers processes sharing the retained file; host pre-start guards must
also verify dataset GUIDs, UID mapping and guest ownership. Independent copies
need an explicit cutover policy.

Local tests establish those application behaviors only. Actual ZFS snapshots,
rootfs replacement, mount guards, backup encryption, source-unavailable restore
and independently verified application writes remain separate qualification work.

The standalone [pre-start guard](PRESTART.md) checks host dataset GUIDs, actual
mounts, UID mappings, and retained application identity before a managed start.
Its normal and debug instance drop-ins are examples pending disposable-host
qualification. The persistence recipe remains a draft.

## Prepare the replaceable image

The [image blueprint](IMAGE.md) creates the locked application account, installs
the pinned program and adds a disabled serve-existing service. It checks program
readability as UID/GID1100 and preserves all other account rows and sub-ID
assignments. Run its check inside a fresh, offline, unprivileged container before
installation. Host ownership, guarded lifecycle and retained dataset attachment
remain responsibilities of the calling recipe. The pinned helper passed native
account-first installation, application-UID readability, and a separate graceful
shutdown in an owned offline disposable guest. This qualifies image preparation.
Full retained-data rebuild and independent recovery remain pending.

## Guard the retained-data handoff

The developing [replacement guard](HANDOFF.md) checks an explicit active owner for
the dataset GUID pair and requires both retired managed start paths to remain
denied. It preserves schema2 and adds a narrow one-core quota contract that can
qualify the generator's initial empty CPU selection. Local tests cover the new
ownership predicates and preserve the existing storage and application refusals.
Native attachment and the complete handoff are still unqualified.
The guard also admits Proxmox's implicit default local storage without creating
`storage.cfg`, while binding actual parent identity and file presence through
closing checks. See the [storage seal contract](HANDOFF.md#explicit-and-default-storage-configuration).

## Run as the application user

Prepare separate existing data, config and runtime directories, owned by the
application UID with mode `0700`. Use absolute paths without symlinks. Initialization
reads a private JSON file containing `schema_version:1`, a 32-hex `instance_id`, the
actual numeric `uid` and a randomly generated 64-hex `token`. Do not pass the token
in command arguments. Initialization refuses existing or partial state.

```sh
python3 examples/reference-ledger/ledger.py init \
  --data /var/lib/reference-ledger --config /etc/reference-ledger \
  < /path/to/private/identity.json
python3 examples/reference-ledger/ledger.py serve \
  --data /var/lib/reference-ledger --config /etc/reference-ledger \
  --socket /run/reference-ledger/api.sock
```

Send requests from another process using a protected input file:

```sh
python3 examples/reference-ledger/ledger.py request \
  --socket /run/reference-ledger/api.sock < /path/to/private/request.json
```

Every request has `action` and `token`. `read` returns the instance ID and ordered
entries. `append` additionally requires a 32-hex `operation_id` and string `value`.
The same ID/value returns `unchanged`; a different value for that ID returns
`conflict`. Requests are limited to70,000 wire bytes and values to65,536 UTF-8 bytes.
Pretty-printed input is normalized to the one-line socket protocol.

SQLite errors or a missing/mismatched committed record return `uncertain` and
freeze further writes in that process. Reconcile the intended operation ID and
actual records before retrying; do not interpret an exit code alone as evidence
of a committed write. Startup requires the exact schema and rejects unexpected
triggers, views or tables. Partial initialization is retained for reconciliation.
The daemon removes only its own socket on a normal stop; it never removes an
existing socket to take over another instance.

## Validate locally

```sh
python3 -m unittest discover -s tests -p test_reference_ledger.py -v
```

The tests use project-local temporary files and a real Unix-socket subprocess.
The tests cover persisted records/credentials, missing DB with no replacement,
wrong identity/UID/modes, unauthorized writes, idempotency/conflicts, malformed
tokens, full-database uncertainty, unexpected triggers and actual client requests.
They do not qualify ZFS mounts, UID mappings, encrypted backups or disaster recovery.
