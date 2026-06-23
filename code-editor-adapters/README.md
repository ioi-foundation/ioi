# Code Editor Target Registry & Host Artifacts

`code-editor-adapters/` is the tracked home for the **editor-target registry**
metadata and local host build conventions. It is not the Hypervisor product, not
an npm workspace, and not runtime authority.

Hypervisor is an app that **orchestrates many code editors** — it is not one. The
registry in `editor-targets.manifest.json` enumerates the editor targets the App's
per-environment "Open in <editor>" picker offers, across families:

- **VS Code family** (`electron-host`): VS Code (flagship/default), VS Code
  Insiders, Cursor, Windsurf, Devin — all served by the shared
  `vscode-extension` module via host profiles.
- **Web** (`browser`): VS Code Browser.
- **JetBrains (Gateway)** (`jetbrains-gateway`, declared): IntelliJ IDEA Ultimate,
  GoLand, PyCharm Professional, PhpStorm, RubyMine, WebStorm, CLion, RustRover,
  Rider.
- **SSH** (`ssh`, declared): raw remote target.

The old root `ide/` path is retired. Local VS Code source checkouts and packaged
editor-host builds belong here so the repository does not imply that Hypervisor is
a single IDE product. The customized VS Code is the flagship VS Code-family
target — one entry in the registry, not "the host".

The intended layout is:

```text
code-editor-adapters/
  README.md
  editor-targets.manifest.json   editor-target registry (families -> editors, default)
  vscode/                        ignored local (customized) VS Code source checkout
  builds/VSCode-linux-x64/       ignored packaged runnable VS Code-family host
```

Canonical ownership stays split:

- Editor adapter **source** lives in the package graph, not here. The VS Code
  family is served by
  `packages/hypervisor-adapter-targets/code-editors/vscode-extension` — the shared
  VS Code-family adapter module. JetBrains and SSH are sibling target subtrees
  (`packages/hypervisor-adapter-targets/{jetbrains,ssh}`), declared until built.
  This directory holds registry metadata and ignored local host artifacts only.
- `code-editor-adapters/vscode` is the target optional local VS Code source
  checkout for host development and rebuilds.
- `code-editor-adapters/builds/VSCode-linux-x64` is the target local packaged
  Electron app path for the VS Code-family host launcher and validation harnesses.
- The default editor (`defaultEditorId`) is an org/user preference, not the
  adapter contract.
- No editor host is patched into a Hypervisor shell. Hypervisor Home, Sessions,
  Projects, Workbench, Foundry, Providers, Receipts, and Settings live in the
  Hypervisor App/Web clients; an editor host only contributes code editing context
  projection envelopes through the code editor adapter transport.
- The IOI daemon remains the runtime authority for model mounting, workflow
  execution, policy, receipts, replay, connectors, secrets, and workspace
  mutation.

Environment overrides still work:

- `HYPERVISOR_CODE_EDITOR_VSCODE_PACKAGED_ROOT`
- `HYPERVISOR_CODE_EDITOR_VSCODE_FORK_ROOT`
- `HYPERVISOR_CODE_EDITOR_VSCODE_FORK_BIN`

Keep fork code and packaged builds ignored unless a future repository split or
submodule decision makes them intentional tracked assets.
