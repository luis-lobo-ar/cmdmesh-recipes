# Prepare a reference application image

Use [image.py](image.py) while building the replaceable rootfs for persistence
tests. The host recipe must first verify its node/container ownership, current
process/rootfs, resource limits and absent retained mounts. The helper runs as
root inside an offline unprivileged container with UID/GID map0→100000/65536,
healthy systemd, Python3.12 and SQLite3.37 or newer. Other environments refuse.

Copy this helper and the qualified `ledger.py` into private image staging. The
program is pinned by SHA256; a changed file refuses before installation. From
that staging directory inside the container, run:

```sh
python3 image.py check --program ./ledger.py
python3 image.py install --program ./ledger.py --allow-changes
python3 image.py inspect --program ./ledger.py
```

Check mode reports a preview without creating accounts, files or a claim.
Installation creates group/account1100 first, with a locked password, nologin
shell and no home. It then writes a root-owned0755 program directory,0644 pinned
program and service unit. An actual UID/GID1100 child must read and compile the
program. All other account rows and sub-ID assignments must match the original
observation. The service remains disabled/inactive, with no application process
or socket. Its normal command serves an existing database and configuration.

Data/config/runtime paths must be absent during image preparation. The host
recipe can then shut down the guest gracefully, qualify managed start guards,
attach the existing retained datasets and verify the application using its
existing identity, credentials and records. Keep initialization as an explicit
separate operation for genuinely new data.

The once-only image claim is `/var/lib/cmdmesh-reference-image`. Keep it and all
partial account/files after a failure; another install refuses instead of
repeating an uncertain mutation. `inspect` reads current image/account/service
facts. Its `image_verified` result describes that current image; an observed
completion file alone does not qualify the original operation. A failure after
candidate completion can leave both completion and failure files. Preserve that
history and the separately trusted host-controller result.

Refusals include a stable `error_code`, `failed_stage` when an install was
dispatched, and separate mutation/effect flags. An artifact mismatch or failed
admission reports no attempted mutation. Claim, account, publication and closing
failures retain uncertainty and their journal. A competing creator's claim is
never modified.

| Refusal | Next action |
| --- | --- |
| `reference-image-artifact-mismatch` | Supply the qualified program bytes. |
| `reference-image-unprivileged-map-mismatch` | Correct the caller's target; verify its guest namespace. |
| `reference-image-account-collision` or `reference-image-retained-path-present` | Use the image-preparation phase on a fresh rootfs before retained attachment. Preserve existing accounts and data. |
| `reference-image-os-not-ready` | Diagnose the guest's reported systemd state before installation. |
| `reference-image-attempt-consumed` | Keep its claim and inspect current state without another install. |
| `reference-image-account-files-changed` or `reference-image-state-changed` | Keep candidate/failure records and reconcile the changing state. |

Account database/sub-ID byte and file identities close around name lookup and
slow unit probes. Environment, inactive unit and absent retained paths are also
rechecked after slow child/account work and candidate completion. Returned
account observations contain fingerprints and target account metadata, without
password/shadow contents. These are observed checkpoints; the host recipe must
keep its own lifecycle and ownership constraints in force.

Local tests use real private scratch files with modeled account/systemd/runtime
providers. They cover account-first ordering, disabled service, immutable
artifact/readability, check-mode refusals, partial failures and late changes.
Additional cases exercise actual private account files, lookup-time drift,
claim-sync uncertainty, foreign-claim races and CLI refusal diagnostics.
Actual container account creation, image preparation, native shutdown, retained
attachment, application rebuild and source-unavailable restore remain separate
qualification work. The persistence recipe remains a draft.
