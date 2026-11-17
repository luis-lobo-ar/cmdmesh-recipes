# LXC resource and rootfs growth

Use only for guests whose memory, swap and rootfs size are **Ansible-owned**.
If Terraform owns those fields, change the Terraform module inputs and review
its saved plan instead. Do not enable this recipe to fight Terraform drift.

## Inputs

See `examples/private-environment/growth.yml` and its fictional guest inventory.

- `lifecycle_owner: ansible` is mandatory in both target configuration and vars.
- `proxmox_lxc_resources_guests` and `proxmox_lxc_storage_guests` are explicit
  inventory hostname lists, not automatically discovered groups.
- Selected host and guests need matching `proxmox_node`.
- Guests need `proxmox_vmid`, `proxmox_lxc_memory_mb`, `proxmox_lxc_swap_mb` and
  `proxmox_lxc_rootfs_size_gb` as appropriate.
- `cmdmesh_allow_changes` remains false until an approved apply.

Verify real VMID ownership, current configuration, filesystem support, free
storage and backup before applying. Memory changes can affect a live workload;
larger configured memory does not create physical capacity. Rootfs growth is
one-way in this workflow. Bind mounts and application datasets are not resized.

## Verify

Compare `pct config` with expected values. Verify filesystem size and free space
inside the guest as well as its application health. Run the other lifecycle
controller's plan separately to confirm it will not undo the change.

## Recovery

Do not attempt to shrink the rootfs to reverse growth. Restore into a separate
guest/volume from a verified backup if a smaller filesystem is required.
Memory/swap can be deliberately reconfigured after assessing workload impact;
that is a separate reviewed change, not automatic rollback. Stop on any VMID,
storage or inventory mismatch before proceeding to another guest.
