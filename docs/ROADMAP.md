# Future recipe candidates

The following are **not implemented**. They are backlog candidates, not commands
or guarantees provided by this release.

- Monitoring: exporters, metrics collection, alert routing, backup freshness and
  a test proving the alert reaches an operator.
- DNS and HTTPS: private zones, reverse proxy, certificate renewal and external
  access verification with explicit ingress boundaries.
- Home Assistant: VM provisioning, device mapping, upgrade checks and isolated
  backup/restore validation.
- Service delivery: guest setup, application rollout, health checks and recovery.
- Recovery drills: off-host archive restoration, dependency ordering and measured
  recovery time on disposable infrastructure.
- Persistent LXC/ZFS: the separately listed draft requires Keaton's conventions
  and successful data-loss/rebuild exercises.

Promote a candidate only when its implementation, ownership, verification,
failure behavior and recovery have evidence. Reuse integration modules rather
than copying deployment-specific scripts from a private environment.
