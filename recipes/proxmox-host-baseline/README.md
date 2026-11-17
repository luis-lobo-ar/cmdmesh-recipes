# Proxmox host baseline

Install only the package list selected in private variables. This recipe targets
the Proxmox host, not its containers. It does not change repositories, networking,
users, SSH policy or guest lifecycle. An empty package list is intentional.

## Inputs

- Inventory: selected hosts in `cmdmesh_targets`; always use an explicit limit.
- `proxmox_baseline_host_packages`: explicit package names to install.
- `proxmox_baseline_host_absent_packages`: optional removal list; review purge and
  dependency/autoremove impact before supplying it.
- `cmdmesh_allow_changes`: false by default; CmdMesh sets true only for an
  approved apply. Direct Ansible requires an explicit true extra variable.

See `examples/private-environment/baseline.yml` and the repository quick start.
Record installed versions before applying. Package installation updates apt
metadata and may start services as normal Debian package behavior.

## Verify

Inspect `dpkg-query -W` for the selected packages and verify existing services and
guest health. A successful playbook is not workload acceptance.

## Recovery

Revert the private package selection for future runs. That does not automatically
uninstall packages added by a prior run. Explicit removal or version downgrade is
a separate reviewed change, and old packages may no longer be available. Restore
the host using its independent recovery procedure if package recovery fails.
