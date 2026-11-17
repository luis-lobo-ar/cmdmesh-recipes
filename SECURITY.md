# Security

Use GitHub private vulnerability reporting when it is available. Do not post
credentials, private inventory, customer data, or unredacted execution output in
public issues.

Keep inventory, credentials, state, plans, and logs in your private environment
repository or private storage. Supply secret references rather than committed
values. Use verified TLS with your private CA where needed.

Recipe and integration code is trusted executable code. Installing a repository
can grant it the permissions of the invoking user. CmdMesh is not a sandbox or a
security boundary against a malicious recipe. Review and pin dependencies before
execution. A capability label is a declaration, not proof that code is read-only.

Review targets and side effects before any infrastructure operation. Plan output
is not authorization. Do not automatically retry a partially completed mutation
until its external state has been checked. Backups require independent storage
and tested recovery; a successful job or snapshot is not a restore test.
