# Grow and verify one owned LXC's memory

Use this when an agent knows “grow this container's memory” but would otherwise
have to rediscover its identity checks, Proxmox command, cgroup verification and
failure handling from a chat. The catalog selects the fixed procedure; private
configuration selects the actual infrastructure. Ansible performs the guarded
change. CmdMesh binds review to exact inputs and distinguishes command completion
from independently verified state.

This profile covers memory growth on one running Ansible-owned LXC, or an
already-desired no-op. It does not change swap/rootfs, shrink, restart or prove
application health. Real disposable growth and recovery qualification remain
separate from these synthetic contract tests.

## Discover and prepare

Use the catalog's pinned core/integration revisions, including schema2 operation
support. Copy and configure the [private example](../../examples/private-memory/README.md)
before planning. Paths below refer to that private copy:

```sh
cmdmesh operation list --catalog /path/to/catalog --query 'owned memory'
cmdmesh operation inspect 'grow owned LXC memory' --catalog /path/to/catalog
cmdmesh --config /path/to/private/environment.json operation validate-inputs \
  proxmox-lxc-memory-grow --catalog /path/to/catalog \
  --inputs /path/to/private/operation-inputs.json
cmdmesh --config /path/to/private/environment.json operation plan \
  proxmox-lxc-memory-grow --catalog /path/to/catalog \
  --inputs /path/to/private/operation-inputs.json \
  --out /path/to/private/memory.plan.json
```

Validation checks declared input shapes/references locally, without certifying
prerequisites. Planning collects fresh native evidence over verified TLS and
strict direct SSH, freezes the selected identity, intent, capacity policy and
driver sources, and writes owner-only context. It never dispatches a mutation.
Use new output filenames and keep the journal directory durable and private.

The five required inputs are a pinned inspector reference, state directory,
exact identity/ownership request, desired memory in MB and observed-headroom
policy. The native inspector's `inspection describe` contract supplies full
nested constraints and supported tool versions. No arbitrary command or SSH
option is accepted from operation metadata.

## Execute and assess the result

Review the exact subject, current/desired memory, policy, bindings and plan digest.
Set intended execution permissions in the private environment **before** planning;
changing them afterwards invalidates that plan. CmdMesh never enables them.
An unchanged target needs execution permission but no mutation permission.

```sh
cmdmesh procedure execute --plan /path/to/private/memory.plan.json \
  --approve-digest REVIEWED_PLAN_DIGEST
cmdmesh procedure status --plan /path/to/private/memory.plan.json
```

Execution holds the local physical-subject lock, recollects preflight, consumes
intent durably before one guarded dispatch, and independently checks configured
and enforced cgroup memory. Only controlled/native success plus all required
postconditions yields `verified`. An already-desired qualified target is `checked`
without dispatch. Failed checks are `unverified`; unknown completion or evidence
is `uncertain`, even if current checks pass. Execution exits zero only for
`checked`/`verified`. Status reads historical evidence; its exit zero does not
establish current health.

Retain the private receipts, logs and state. A consumed plan cannot be replayed.
After interruption, inspect actual state and reconcile before making another
plan. There is no automatic retry, shrink, restart or rollback. Locks coordinate
controllers sharing this durable directory, not unrelated machines/directories.

MCP `cmdmesh_operation` supports discovery, input validation and the same plan
preparation, with no execution action. See the core's
[outcomes and recovery](https://github.com/luis-lobo-ar/cmdmesh/blob/main/docs/verified-procedures.md).
