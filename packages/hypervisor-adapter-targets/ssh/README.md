# SSH adapter target (declared, not yet built)

Declared editor-target in
[`code-editor-adapters/editor-targets.manifest.json`](../../../code-editor-adapters/editor-targets.manifest.json)
(`ssh`, `launchKind: "ssh"`, `status: "declared"`).

The Hypervisor App's per-environment editor picker offers **SSH** as a raw
remote target — the user connects their own client to a running Environment over
SSH, with no Hypervisor-managed editor host. It is a sibling target to the
VS Code-family and JetBrains families.

No adapter source lives here yet. Add the SSH connection/credential brokering
module here when the target is built; until then this directory only declares
the target so the registry's `adapterModule` path is real.
