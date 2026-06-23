# JetBrains adapter target (declared, not yet built)

Declared editor-target family in
[`code-editor-adapters/editor-targets.manifest.json`](../../../code-editor-adapters/editor-targets.manifest.json)
(`jetbrains-gateway`, `launchKind: "jetbrains-gateway"`, `status: "declared"`).

The Hypervisor App's per-environment editor picker offers the JetBrains IDEs —
IntelliJ IDEA Ultimate, GoLand, PyCharm Professional, PhpStorm, RubyMine,
WebStorm, CLion, RustRover, Rider — opened against a running Environment via
JetBrains Gateway. These share one Gateway-based mechanism, not the VS Code
extension protocol, so they are a sibling target family to
`code-editors/` rather than VS Code-family profiles.

No adapter source lives here yet. Add the Gateway integration module here when
the JetBrains target is built; until then this directory only declares the
target so the registry's `adapterModule` path is real and the next extraction is
obvious. Do not add VS Code-family code here.
