# CmdMesh recipes

Reusable operating procedures built from ordinary Ansible playbooks. Your
inventory, credentials, state and execution evidence stay in your own private
environment repository. The recipes do not depend on Neo or its configuration.

## Catalog

| Recipe | Status | Outcome |
| --- | --- | --- |
| [Host baseline](recipes/proxmox-host-baseline/README.md) | Ready | Explicit host package selection; no guest-wide installation |
| [Backup schedule](recipes/proxmox-backup-schedule/README.md) | Ready | Explicit guest backup jobs, retention and schedules |
| [Host maintenance](recipes/proxmox-host-maintenance/README.md) | Ready | Assessment by default; qualified package update/reboot opt-in |
| [LXC growth](recipes/proxmox-lxc-growth/README.md) | Ready | Ansible-owned memory/swap and rootfs growth |
| [Persistent ZFS / recreatable LXC](recipes/ephemeral-lxc-zfs/README.md) | Draft | Design checklist only; no executable steps |

**Ready means the recipe contract and local checks pass. It does not mean your
hardware, restore procedure or production environment has been qualified.**
See [validation limits](docs/VALIDATION.md) and the [future catalog](docs/ROADMAP.md).

## Start with your own environment

1. Check out pinned revisions of `cmdmesh`, `cmdmesh-proxmox` and this catalog.
   Do not download unreviewed roles while executing a recipe.
2. Copy `examples/private-environment` into a separate private repository.
   Replace the fictional inventory and review every variable.
3. Install a compatible Ansible controller. The collection targets
   `ansible-core >=2.19`, as declared by the integration collection; CI installs
   2.20.4. Do not put passwords in public files.
4. Review the recipe README, package implementation, backup and recovery plan.
5. Validate syntax locally before connecting to a host.

From this repository, with sibling package checkouts:

```sh
python3 scripts/validate_catalog.py
python3 -m unittest discover -s tests -v
python3 scripts/check_ansible_syntax.py --collection-root ../cmdmesh-proxmox
export ANSIBLE_COLLECTIONS_PATH="../cmdmesh-proxmox/ansible"
ansible-playbook -i /path/to/private/inventory.yml \
  recipes/proxmox-host-baseline/playbook.yml --syntax-check
ansible-playbook -i /path/to/private/inventory.yml \
  recipes/proxmox-host-baseline/playbook.yml --limit lab_node \
  -e @/path/to/private/baseline.yml --check --diff
```

`--syntax-check` does not connect to the hosts. **Ansible check mode can connect,
run inspection commands and execute tasks that override check mode. It is not a
security sandbox or a guarantee of no effects.** Inspect the selected roles before
using it. `--diff` can reveal sensitive configuration; keep output private.

For a separately reviewed direct apply, remove `--check` and explicitly add
`-e cmdmesh_allow_changes=true`. Never set that variable globally. The maintenance
and growth recipes require additional private opt-ins described in their READMEs.

## Use CmdMesh

The CLI adds catalog discovery and approval bound to exact input content. It does
not make arbitrary Ansible code safe or replace operator review.

```sh
cmdmesh recipe list --catalog .
cmdmesh recipe inspect recipes/proxmox-host-baseline/recipe.json
cmdmesh --config /path/to/private/environment.json recipe plan \
  recipes/proxmox-host-baseline/recipe.json --target lab --operation check \
  --out /path/to/private/baseline-check.plan.json
cmdmesh recipe execute --plan /path/to/private/baseline-check.plan.json \
  --approve-digest DIGEST_FROM_PLAN
```

Planning is static: no Ansible, Terraform or provider command runs. Execution
requires `allow_execution: true` in the private environment. An apply needs a
separate `--operation apply` plan, its exact digest and `allow_mutations: true`.
Keep both policies false until an operator approves that environment. Changed
inventory, variables, recipe or dependency artifacts invalidate approval.

Targets use explicit inventory limits; `all` and wildcard limits are rejected.
Inventory hosts must belong to `cmdmesh_targets`. Choose one lifecycle owner:
Terraform or Ansible, never both for the same guest resource fields. The growth
recipe requires `lifecycle_owner: "ansible"` in CmdMesh and matching Ansible vars.

Execution is CLI-only in v0.1. MCP exposes discovery/inspection/static planning,
not recipe apply. Terraform execution remains direct tooling with reviewed saved
plans; this catalog does not pretend to offer CmdMesh Terraform apply.

## Contribute a recipe

Use a manifest with the exact v1 fields, a README with verification and recovery,
and ordinary playbooks calling integration roles by fully qualified name.
Do not duplicate provider roles, embed secrets, invent restore guarantees or mark
an unimplemented workflow ready. Add negative tests when changing validation.

Examples use reserved documentation addresses and `.invalid` names. Public
history must not contain inventory, real topology, encrypted secrets, state,
plans, backups or operational logs.
