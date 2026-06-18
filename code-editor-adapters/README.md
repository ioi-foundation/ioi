# Code Editor Adapter Host Artifacts

`code-editor-adapters/` is the tracked home for adapter-host metadata
and local build conventions. It is not the Hypervisor product, not an npm
workspace, and not runtime authority.

The old root `ide/` path is retired. Local VS Code source checkouts and
packaged editor-host builds belong here so the repository does not imply that
Hypervisor is a single IDE product.

The intended layout is:

```text
code-editor-adapters/
  README.md
  code-editor-adapter-host.manifest.json
  vscode/                  ignored local VS Code source checkout
  builds/VSCode-linux-x64/  ignored packaged runnable editor host
```

Canonical ownership stays split:

- `code-editor-adapters/ioi-code-editor-adapter` is the current code editor adapter
  extension source.
- `code-editor-adapters/vscode` is the target optional local VS Code source
  checkout for adapter-host development and rebuilds.
- `code-editor-adapters/builds/VSCode-linux-x64` is the target local packaged
  Electron app path for the current code editor adapter-host launcher and
  validation harnesses.
- The adapter host is not patched into a Hypervisor shell. Hypervisor Home,
  Sessions, Projects, Workbench, Foundry, Providers, Receipts, and Settings live
  in the Hypervisor App/Web clients; the editor host only contributes code
  editing context projection envelopes through the code editor adapter transport.
- The IOI daemon remains the runtime authority for model mounting, workflow
  execution, policy, receipts, replay, connectors, secrets, and workspace
  mutation.

Environment overrides still work:

- `HYPERVISOR_CODE_EDITOR_VSCODE_PACKAGED_ROOT`
- `HYPERVISOR_CODE_EDITOR_VSCODE_FORK_ROOT`
- `HYPERVISOR_CODE_EDITOR_VSCODE_FORK_BIN`

Keep fork code and packaged builds ignored unless a future repository split or
submodule decision makes them intentional tracked assets.
