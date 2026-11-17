# Proxmox host maintenance

Assessment is the default. Actual maintenance performs Debian/Proxmox package
updates and may reboot. It refuses package maintenance while guests are running.
It does not migrate, stop or automatically restart guests for you.

## Qualify the target first

- Select one host with an explicit inventory limit; the playbook also uses serial1.
- Verify backups, independent console access, boot media and recovery ownership.
- Review cluster quorum, HA policy, storage dependencies and guest placement.
- Stop or migrate guests through a separate approved procedure.
- Check repository/subscription policy and package compatibility.
- Record the old kernel, package versions, guest state and host configuration.

The collection supports `proxmox_maintenance_assessment_only: true` by default.
That mode inspects the host; no package update/reboot is requested. For actual
maintenance, private variables must explicitly set all of:

```yaml
proxmox_maintenance_assessment_only: false
proxmox_maintenance_enabled: true
proxmox_maintenance_reboot: true
proxmox_maintenance_blocked_reason: ""
```

An approved apply must also opt into `cmdmesh_allow_changes: true`. Review the
planned package changes first. Check mode is not proof that the eventual update
or boot will succeed; inspection commands may run during check mode.

## Verify

After an update, inspect the active kernel, Proxmox service health, failed units,
cluster/quorum state, storage availability and network reachability. Restore
guest service only after the host is qualified, then verify real workloads.

## Recovery

Stop after any unexpected package, storage, quorum, reboot or service failure.
Do not continue to another host. Use the independent console to select a retained
previous kernel where appropriate. Package downgrades are not guaranteed and
may require host recovery from verified configuration/backups. Never treat
rerunning this recipe as a rollback or automatically reboot repeatedly.
