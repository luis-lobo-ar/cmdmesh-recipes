# Recipe extraction roadmap

The first P2 slice adds versioned operation metadata to the four implemented
check-planning recipes. Core 0.2.0 exposes intent search, typed private target
validation, known failure/recovery guidance and the same bound static plans.
This is discovery and planning, not executable prerequisite/postcondition checks
or end-to-end recovery qualification. Those remain later phases below.

The [CmdMesh extraction plan](https://github.com/luis-lobo-ar/cmdmesh/blob/main/docs/roadmap.md)
is the canonical product plan. Its goal is to convert actual operating knowledge
and built-in script context into reusable components, beginning with Proxmox.
Recipes are one layer of that work, alongside primitives, integrations and agent
knowledge/discovery. **Planned rows below are not available catalog commands.**

## What exists today

| Recipe | Current status | Remaining extraction/qualification work |
| --- | --- | --- |
| Host baseline | Ready manifest/playbook | Preserve host-only scope, private package policy and actual package postconditions |
| Backup schedule | Ready manifest/playbook | Coverage, storage/mode compatibility, last-success evidence and independent restore proof |
| Host maintenance | Ready manifest/playbook | Exact target/recovery/guest conditions, supported versions and verified post-maintenance outcomes |
| LXC growth | Ready manifest/playbook | Explicit owner, capacity/identity checks and observed resulting resource values |
| Persistent LXC/ZFS | Draft, no executable playbook | Agreed storage convention, retained-data rebuild and isolated restore evidence |

Ready means local contract checks, not qualification for every host, application,
storage or recovery scenario. See [validation limits](VALIDATION.md).

## How this catalog follows the product plan

| Phase | Catalog contribution | Exit evidence |
| --- | --- | --- |
| P1: source audit | Map historical procedures, agent rediscovery, rejected approaches and current scripts to recipe candidates | Each priority candidate has private source/evidence references and explicit coverage limits |
| P2: discovery contracts | Define task names/aliases, typed inputs, supported capabilities, prerequisites, expected results, known failures and recovery metadata | A new operator can find the right procedure without reading its old conversation |
| P3: Proxmox primitives | Reuse integration helpers for target/access/controller/inspection and operation work | Primitive behavior is independently testable; recipes do not copy private wrappers |
| P4: executable procedures | Compose the primitives into known recipes with preflight, plan, result, verification and recovery | Failed postconditions and unknown outcomes are distinguished from successful command execution |
| P5: workflow qualification | Exercise representative baseline, growth, maintenance and backup/rebuild/restore procedures | Disposable targets prove actual state/data outcomes and recovery limits |
| P6: agent evaluation/adoption | Supply fresh-agent examples and migrate qualified private consumers | Agreed valid cases complete and verify; invalid cases are refused; a second installation reuses the procedures without historical context |
| P7: deployment extension | Candidate work on one repeated guest/service rollout pattern | General mechanics and application/runtime policy are separated and qualified before expanding scope |

P1–P6 are the first Proxmox extraction/reuse finish line. P7 follows an explicit
scope decision and is not a commitment to support every deployment backend.

## What every extracted procedure should teach

This is a planned contract, not new fields already accepted by the current schema:

- The task and aliases an operator or agent would search for.
- The installed implementation and exact supported entrypoint/version.
- Typed parameters and references to private targets, credentials and policy.
- Prerequisites, ownership and the relevant current-state inspections.
- Plan/change behavior, expected results and independent verification.
- Known failure signatures, useful next checks and recovery/uncertainty limits.
- Provenance and supported qualification scope, with private source details excluded.

Raw conversations are source material for reviewed extraction, not instructions
to replay automatically. Distinguish a general invariant from environment policy,
a historical release condition or a safeguard the operator later rejected.

## Initial candidate families

The private audit determines the first implementation batch. These are grounded
families to investigate, not promises that all new procedures are implemented:

| Family | Useful outcome | Evidence needed before promotion |
| --- | --- | --- |
| Access diagnosis/repair | Distinguish SSH identity, API ACL, reachability and TLS-name problems using known steps | Correct diagnosis with invalid trust, insufficient visibility, address changes and supported repair/idempotence cases |
| Backup coverage and storage readiness | Compare declared protection with actual guests, schedules, storage/export access and last success | Version/mode/permission failures, capacity headroom and real scheduled outcomes |
| Isolated restore proof | Restore an attributable archive into owned scratch resources with explicit isolation | Verify actual guest/network configuration, meaningful data and ownership-checked cleanup; do not infer application recovery from filesystem proof |
| Persistent guest rebuild | Replace rootfs while retaining deliberate data/configuration datasets | Dataset/UID-GID convention, missing-mount refusal, interrupted rebuild and independent restore |
| Bounded maintenance | Prepare and execute a known operation under declared guest/recovery/availability policy | Actual prerequisites, check-mode inspection, reboot/service outcomes and compatible recovery |
| Guest/service delivery | Use an identified artifact, strategy and actual acceptance checks | Artifact identity, staged handoff, convergence and rollback proof for a selected runtime |

Monitoring, DNS/HTTPS, device/appliance profiles and additional service recipes can
follow when their source audit and reusable boundaries justify them. Do not add a
catalog entry merely to list a product ambition without an implementation/evidence path.

## Promotion and reuse

1. Link a real task/failure to current implementation and private source evidence.
2. Extract general behavior into an integration primitive; keep policy/values private.
3. Compose the recipe through supported contracts and preserve direct-tool use
   where documented. New schema/driver behavior requires a reviewed core change.
4. Reproduce relevant past failures, then qualify on disposable infrastructure.
5. Run a separately authorized bounded private trial and independently inspect
   actual outcomes. Keep credentials, state, raw logs and source chats private.
6. Publish the supported scope, then migrate private callers and retire only the
   qualified duplicate. Feed later failures back into components and tests.

Core owns discovery/result/driver contracts and shared CLI/MCP behavior. The
Proxmox integration owns platform implementations. This catalog owns procedures
and agent-facing operational guidance. A recipe does not create a new execution
engine or silently authorize broader changes.
