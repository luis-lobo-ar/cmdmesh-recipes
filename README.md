# CmdMesh recipes

Reusable operating procedures using ordinary Ansible playbooks and fixed verified
profiles. Your
inventory, credentials, state and execution evidence stay in your own private
environment repository. The recipes do not depend on Neo or its configuration.

## Catalog

| Recipe | Status | Outcome |
| --- | --- | --- |
| [Host baseline](recipes/proxmox-host-baseline/README.md) | Ready | Explicit host package selection; no guest-wide installation |
| [Backup schedule](recipes/proxmox-backup-schedule/README.md) | Ready | Explicit guest backup jobs, retention and schedules |
| [New NFS backup store](recipes/proxmox-nfs-backup-storage/README.md) | Ready | One new backup-only registration; refuses existing IDs and mountpoints |
| [Host maintenance](recipes/proxmox-host-maintenance/README.md) | Ready | Assessment by default; qualified package update/reboot opt-in |
| [LXC growth](recipes/proxmox-lxc-growth/README.md) | Ready | Ansible-owned memory/swap and rootfs growth |
| [Verified LXC memory growth](operations/proxmox-lxc-memory-grow/README.md) | Contract tested | One owned running LXC; current identity/capacity, guarded dispatch and independent cgroup checks |
| [Persistent ZFS / recreatable LXC](recipes/ephemeral-lxc-zfs/README.md) | Draft | Reference layout and [tested ledger fixture](examples/reference-ledger/README.md); no recovery automation |

**Ready means the recipe contract and local checks pass. It does not mean your
hardware, restore procedure or production environment has been qualified.**
See [validation limits](docs/VALIDATION.md) and the [recipe extraction roadmap](docs/ROADMAP.md).

The [full CmdMesh extraction plan](https://github.com/luis-lobo-ar/cmdmesh/blob/main/docs/roadmap.md)
describes how operating knowledge becomes reusable components, beginning with
Proxmox. This catalog maps those phases to procedure work; planned capabilities
are not current release features.

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

With the exact core revision in `.github/core.json`, discover four static check
plans and one fixed memory procedure by intent before reconstructing commands.
The check-only entries use schema1; the verified memory entry requires schema2
support in the pinned core:

```sh
cmdmesh operation list --catalog . --query 'host tools'
cmdmesh operation inspect 'check host tools' --catalog .
cmdmesh --config /path/to/private/environment.json operation validate-inputs \
  proxmox-host-baseline-check --catalog . --inputs /path/to/private/operation-inputs.json
cmdmesh --config /path/to/private/environment.json operation plan \
  proxmox-host-baseline-check --catalog . --inputs /path/to/private/operation-inputs.json \
  --out /path/to/private/baseline-operation.plan.json
```

The private inputs file contains `{"target":"lab"}`, using your environment's
actual target name. Each check operation describes supported versions, the
mandatory target reference, exact entrypoint, known failures, next checks and
recovery. Discovery, validation and static recipe planning run no infrastructure command;
declared prerequisites remain unevaluated. The resulting plan is the existing
schema-1 recipe plan with unchanged execution policy. Metadata is colocated with
the recipe so edits invalidate its digest. See the
[operation contract](https://github.com/luis-lobo-ar/cmdmesh/blob/main/docs/operations.md).

All four schema1 entries prepare **check** plans. Existing explicit `recipe plan --operation apply`
remains the path for separately reviewed apply planning.
The draft persistence procedure is not advertised as an implemented operation.
Existing schema-1 recipe discovery/planning also works with older core releases.
Use the pinned core for discovery across this catalog's mixed operation schemas.

For **verified memory growth**, use the separate
[private memory example](examples/private-memory/README.md) and
[walkthrough](operations/proxmox-lxc-memory-grow/README.md). It consumes five
typed private inputs and collects current remote state during planning. Its
`cmdmesh.procedure.plan` is executed through `procedure execute`, with an exact
reviewed digest and the existing private permissions. Completion and independently
verified state are separate outcomes; uncertain work is never automatically
replayed. Real growth and recovery qualification remain separate milestones.

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

Recipe planning is static: no Ansible, Terraform or provider command runs. Execution
requires `allow_execution: true` in the private environment. An apply needs a
separate `--operation apply` plan, its exact digest and `allow_mutations: true`.
Keep both policies false until an operator approves that environment. Changed
inventory, variables, recipe or dependency artifacts invalidate approval.

Targets use explicit inventory limits; `all` and wildcard limits are rejected.
Inventory hosts must belong to `cmdmesh_targets`. Choose one lifecycle owner:
Terraform or Ansible, never both for the same guest resource fields. The growth
recipe requires `lifecycle_owner: "ansible"` in CmdMesh and matching Ansible vars.

Execution is CLI-only. MCP exposes discovery, inspection and planning, including
remote reads/private writes for the fixed procedure; no apply action. Terraform execution remains direct tooling with reviewed saved
plans; this catalog does not pretend to offer CmdMesh Terraform apply.

## Contribute a recipe

For recipes, use a manifest with the exact v1 fields, a README with verification
and recovery, and ordinary playbooks calling integration roles by fully qualified
name. A schema2 operation selects only a fixed profile implemented by the pinned
core; it cannot add metadata-supplied commands or a new workflow engine.
Do not duplicate provider roles, embed secrets, invent restore guarantees or mark
an unimplemented workflow ready. Add negative tests when changing validation.

Examples use reserved documentation addresses and `.invalid` names. Public
history must not contain inventory, real topology, encrypted secrets, state,
plans, backups or operational logs.
