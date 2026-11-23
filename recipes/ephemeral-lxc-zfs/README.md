# Recreatable LXC with persistent ZFS data — draft

This is a design checklist, **not an implemented recipe**. There is no executable
playbook. The reference layout below is selected for implementation. Feedback from
Keaton can refine it later; disposable-host recovery evidence is required before
promoting it to ready.

The intended outcome is a replaceable guest root filesystem with application
data and configuration in deliberately owned ZFS datasets/bind mounts. Rebuilding
the container must not destroy those datasets or lose the application identity.

## Decisions and acceptance evidence needed

The reference uses an unprivileged LXC and two sibling datasets outside its
root filesystem. Dataset names and paths are examples, supplied through private
configuration in a real installation:

```text
storage/apps/example/             retained application boundary
  data                           transactional data and payloads
  config                         application configuration and stable identity

replaceable LXC root filesystem
  /var/lib/example  <- bind mount of data
  /etc/example     <- bind mount of config
```

The host retains ownership of these datasets when replacing a guest. Bind mounts
are not covered by assuming that a normal LXC rootfs archive includes them.
Keep an independently stored, application-consistent backup of both datasets
from the same generation. Capture exact dataset GUIDs and the observed LXC UID/GID
mapping; never assume host ownership follows the container's numeric IDs.

A missing dataset or incorrect mount must prevent application startup. It must
not create empty replacement data in an uncovered directory. Rebuild into a fresh
guest while the old guest is stopped, with only one application writer. Qualify
restore onto new storage with the original source unavailable, then check real
application reads, writes, identity and permissions. Same-pool snapshots alone
do not qualify as independent restore evidence.

These choices are a reference convention, not a claim about Keaton's setup.
The recipe remains draft with no executable steps until its checks pass.

The [reference ledger](../../examples/reference-ledger/README.md) supplies a
locally tested SQLite application for later recovery trials. It verifies actual
authenticated reads/writes and persisted identity instead of relying on file
existence. Its application tests do not qualify ZFS mounts or restore automation.

- Dataset layout, names, lifecycle owner and exact destroy-protection boundary.
- Privileged/unprivileged LXC choice and explicit UID/GID/idmap ownership.
- Mount propagation, startup ordering and behavior when storage is unavailable.
- Application credentials, configuration, identity and data persistence map.
- Backup coverage for every bind mount; LXC archive exclusions made explicit.
- Application-consistent snapshots/backup hooks where required.
- Off-host independent backup, retention, encryption and restore credentials.
- Rebuild rootfs while retaining data; verify permissions and application state.
- Simulate loss of the original dataset, restore into an isolated environment,
  and verify actual data and recovery time.
- Exercise interrupted rebuild, missing dataset and wrong UID/GID failure cases.

Snapshots on the same storage are useful recovery points, but are not independent
backups. A mount being present is not evidence its contents are backed up.

## Recovery

No recovery automation is supplied yet. Do not test destruction on an existing
environment. Use disposable guests/datasets and an independently verified backup
when qualifying this design. Retain original data until the isolated restore has
passed and an owner approves retirement.
