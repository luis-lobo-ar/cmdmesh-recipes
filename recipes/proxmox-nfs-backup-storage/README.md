# Register a new NFS backup store

Use this when an existing NFS export must become a new backup-only storage on
one Proxmox host. It reuses the public `proxmox_nfs_backup_storage` role. It does
not configure the NAS, modify its export or create a backup schedule.

Supply these values through a private variables file:

```yaml
proxmox_nfs_backup_storage_enabled: true
proxmox_nfs_backup_storage_create_only: true
proxmox_nfs_backup_storage_id: example-backup
proxmox_nfs_backup_storage_server: backup.example.invalid
proxmox_nfs_backup_storage_export: /backups
proxmox_nfs_backup_storage_content: backup
proxmox_nfs_backup_storage_options: vers=3,proto=tcp,hard,nolock,nodev,nosuid,noexec
```

Choose NFS version and lock policy for the actual server and backup workload;
the example options are not universal defaults. `nolock` disables remote NLM
locking: applications that depend on it need a different reviewed policy.
Independent encrypted-stream backups must provide their own exclusive output
and application-consistency controls.

First run through CmdMesh in check mode, using one explicit private target:

```sh
cmdmesh --config /path/to/private/environment.json recipe plan \
  /path/to/cmdmesh-recipes/recipes/proxmox-nfs-backup-storage/recipe.json \
  --target lab_node --operation check --out /path/to/private/nfs-check.json
```

Review and execute the resulting digest through the ordinary recipe workflow.
A separately authorized apply requires a fresh plan with `--operation apply`.
The collection refuses normal execution without explicit change permission.
Pin the reviewed collection revision containing the create-only guard; older
collections cannot supply that behavior merely by receiving the new variable.

The storage ID must be absent. The default `/mnt/pve/<storage-id>` path must also
be absent, including any symlink or uncovered empty directory. Existing storage
IDs refuse before package changes. APT installs `nfs-common` if needed, then the
role rechecks the new path before asking Proxmox to create the storage. Check
mode does not create the mount or certify export authorization. An active status
after apply is only one check: inspect actual backing/options and verify a private
owned destination before writing data.

## Recovery

On failure or timeout, inspect the actual storage registration and mount before
preparing further work. The remote command may have partially completed; do not
replay a consumed qualification intent or switch off create-only to force an
adoption. Keep partial evidence. No automatic removal, unmount, NAS cleanup or
destructive rollback is provided.

Registration and mounting do not establish an independent backup. The separate
persistence recipe remains draft until encrypted full-stream, rebuild and
source-unavailable restore trials pass.
