# Workbench Adapter Host Artifacts

`workbench-adapters/` is the tracked home for adapter-host metadata, patches,
and future local build conventions. It is not the Hypervisor product, not an
npm workspace, and not runtime authority.

The old root `ide/` path is now legacy local artifact storage only. Existing
machines may still keep ignored VS Code source checkouts and packaged builds
there until a machine-specific cleanup moves them to `workbench-adapters/`.

The intended layout is:

```text
workbench-adapters/
  README.md
  shell.manifest.json
  patches/
  vscode/                  ignored local VS Code source checkout
  builds/VSCode-linux-x64/  ignored packaged runnable editor host
```

Canonical ownership stays split:

- `apps/autopilot/openvscode-extension/ioi-workbench` is the current Workbench
  extension/API source.
- `workbench-adapters/vscode` is the target optional local VS Code source
  checkout for adapter-host development and rebuilds.
- `workbench-adapters/builds/VSCode-linux-x64` is the target local packaged
  Electron app path for the current Workbench adapter-host launcher and
  validation harnesses.
- `ide/vscode` and `ide/builds/VSCode-linux-x64` remain temporary legacy
  artifact paths only.
- The IOI daemon remains the runtime authority for model mounting, workflow
  execution, policy, receipts, replay, connectors, secrets, and workspace
  mutation.

Environment overrides still work:

- `AUTOPILOT_VSCODE_PACKAGED_ROOT`
- `AUTOPILOT_VSCODE_FORK_ROOT`
- `AUTOPILOT_VSCODE_FORK_BIN`

Keep fork code and packaged builds ignored unless a future repository split or
submodule decision makes them intentional tracked assets.
