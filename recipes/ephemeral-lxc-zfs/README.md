# Recreatable LXC with persistent ZFS data — draft

This is a design checklist, **not an implemented recipe**. There is no executable
playbook. Keaton's storage conventions and disposable-host recovery evidence are
required before promoting it to ready.

The intended outcome is a replaceable guest root filesystem with application
data and configuration in deliberately owned ZFS datasets/bind mounts. Rebuilding
the container must not destroy those datasets or lose the application identity.

## Decisions and acceptance evidence needed

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
