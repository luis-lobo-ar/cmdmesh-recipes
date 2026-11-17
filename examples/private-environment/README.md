# Your private environment

These addresses and guests are fictional; nothing here should be applied as-is.
Copy the examples into a separate private repository. Do not add credentials,
real hostnames or private addresses to a fork of the public catalog.

An example directory layout is:

```text
workspace/
  cmdmesh-proxmox/      # pinned public integration checkout
  cmdmesh-recipes/      # pinned public catalog checkout
  my-environment/      # private: copied examples and secrets references
```

The `packages.proxmox` path in `environment.json` is relative to that file.
Point it at the exact reviewed integration checkout. Use separate environment
targets or change `vars_file` to the recipe-specific file before planning.
For growth, change the target lifecycle owner to `ansible` only if Ansible really
owns those fields; the variable file alone is not sufficient.

All defaults prevent mutations and scheduling. Enabling execution is independent
of enabling mutations. A static plan does not require either policy to be true.
For an approved apply, CmdMesh supplies the per-run change opt-in; keep it false
in the checked-in private baseline. Maintenance still requires its additional
opt-ins. Use Ansible Vault or another secret reference mechanism privately.

Keep generated plans, logs, credentials and state out of public Git. Output may
contain topology or secret material. Commit reviewed configuration changes in
your private environment, not generated operational evidence in the catalog.
