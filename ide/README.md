# Autopilot IDE Substrate

`ide/` is the local boundary for the Autopilot Electron/VS Code fork. It is not
an npm workspace and should not become runtime authority.

The intended layout is:

```text
ide/
  README.md
  shell.manifest.json
  patches/
  vscode/                  ignored local VS Code source fork checkout
  builds/VSCode-linux-x64/  ignored packaged runnable Autopilot IDE
```

Canonical ownership stays split:

- `apps/autopilot/openvscode-extension/ioi-workbench` is the canonical
  Autopilot Workbench extension/API source.
- `ide/vscode` is an optional local source fork checkout for IDE shell
  development and rebuilds.
- `ide/builds/VSCode-linux-x64` is the local packaged Electron app used by
  `npm run dev:desktop` and validation harnesses.
- The IOI daemon remains the runtime authority for model mounting, workflow
  execution, policy, receipts, replay, connectors, secrets, and workspace
  mutation.

Environment overrides still work:

- `AUTOPILOT_VSCODE_PACKAGED_ROOT`
- `AUTOPILOT_VSCODE_FORK_ROOT`
- `AUTOPILOT_VSCODE_FORK_BIN`

Keep fork code and packaged builds ignored unless a future repository split or
submodule decision makes them intentional tracked assets.
