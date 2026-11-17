# Proxmox guest backup schedule

Install explicit backup jobs and systemd schedules through
`cmdmesh.proxmox.proxmox_vm_backup`. This recipe schedules jobs; it does not run an
immediate backup or certify recovery. Enabling a timer can make a persistent
overdue job run; inspect the timer template and upcoming schedule before enabling.

## Inputs

- `proxmox_vm_backup_jobs`: explicit jobs with `name`, `vmid`, `keep_last`,
  `on_calendar`, and optional `guest_type` (`qemu` or `lxc`).
- `proxmox_vm_backup_storage`: existing storage ID, or explicit local backup dir.
- `proxmox_vm_backup_mode`: `snapshot`, `suspend` or `stop`; assess workload impact.
- `proxmox_vm_backup_schedule_enabled`: false until scheduling is approved.
- `cmdmesh_allow_changes`: explicit opt-in for direct apply.

See `examples/private-environment/backups.yml`. Retention deletes old archives
under the selected job's policy. Confirm storage naming, job naming and capacity
before applying. Storage encryption and off-host copies are operator policies,
not automatically created by this recipe.

**A local snapshot is not an independent backup. External bind mounts are not
automatically included in an LXC backup.** Inventory every mount and dataset and
provide a separate backup/restore process for anything outside the archive.
Application-consistent database backups may need guest/application hooks.

## Verify

Inspect timer/service definitions and `systemctl list-timers` before waiting for
or separately approving a backup. Verify the job exit status, archive integrity,
retention and freshness metrics. Restore into a separate isolated guest, verify
application data, permissions and credentials, and record recovery time.

## Recovery

Set scheduling false and apply to disable the named jobs. This does not restore
deleted archives, remove every installed unit or undo a completed backup. Do not
rename/drop jobs and assume their old timers disappeared: explicitly disable old
jobs before removing them from inventory. Recover lost data from an independently
verified backup; never overwrite the original guest during a restore rehearsal.
