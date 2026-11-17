# Validation boundaries

The test suite validates the v1 manifest contract, path confinement, local
artifact existence, unsupported driver rejection and draft status. Ansible
syntax checks resolve the actual `cmdmesh.proxmox` collection without connecting
to infrastructure. Optional CmdMesh parser checks use its real compiled binary.

```sh
CMDMESH_BIN=/path/to/cmdmesh python3 -m unittest discover -s tests -v
python3 scripts/check_ansible_syntax.py --collection-root ../cmdmesh-proxmox
```

Without `CMDMESH_BIN`, cross-repository parser/plan tests explicitly skip;
the manifest validator tests still run. CI builds the exact core commit in
`.github/core.json` and runs those contract tests against the exact integration
commit in `.github/proxmox-integration.json`. Update these locks only after
reviewing and testing the dependencies. Both locks identify exact public commits;
there is no moving branch or silent local fallback.

The workflow uses read-only repository permissions and full-commit action pins,
following [GitHub's secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use).

These checks do not prove Proxmox version compatibility, safe package updates,
storage capacity, guest availability, successful remote idempotency, archive
integrity or disaster recovery. No live target is used by catalog tests.

Operators must qualify recipes on disposable infrastructure, then capture
environment-specific preflight, check/apply output and postconditions privately.
Timeout or controller interruption can leave remote work in progress; inspect
actual host state before retrying. A killed local process is not remote rollback.
