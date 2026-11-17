# Repository guidance

- This is a public repository. Never include private inventory, real credentials,
  encrypted secret files, Terraform state/plans, internal hostnames, or local
  workstation paths. Examples use reserved documentation addresses and .invalid.
- Keep code and examples usable without a private parent repository.
- Use apply_patch for edits. Add behavioral tests before changing executable code.
- Tests use synthetic fixtures or disposable local resources. Do not run commands
  against live infrastructure or publish from a delegated implementation task.
- Document capability limits and recovery behavior. A passed local test is not
  live infrastructure or disaster-recovery acceptance.
- Commit identity: Luis Lobo Borobia <luis@lobo.ar>. Preserve signing settings.
