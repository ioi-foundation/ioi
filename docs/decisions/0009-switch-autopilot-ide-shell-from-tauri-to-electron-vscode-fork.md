# ADR 0009: Switch Autopilot IDE Shell From Tauri To The Electron/VS Code Fork

- Status: Superseded by ADR 0013
- Date: 2026-05-20
- Owners: Autopilot / VS Code fork / daemon runtime / workbench UX

## Supersession Note

This ADR is retained as implementation history for why the Tauri/OpenVSCode
embedding path was retired. The current architecture no longer treats the
Electron/VS Code fork as the product identity. It is one Workbench adapter-host
implementation under Hypervisor Core, alongside other editor/viewer targets and
first-class Hypervisor App/Web/CLI-headless clients.

## Context

Autopilot initially used a Tauri desktop shell with an embedded OpenVSCode-style
workbench. That path was useful for proving local desktop affordances and early
runtime projections, but it created an impedance mismatch at the exact layer
Autopilot needs to own most deeply: the IDE substrate.

The product direction is IDE-first. Autopilot needs workflows, models, agents,
receipts, replay, approvals, terminals, files, diffs, Git, diagnostics, command
routing, activity bar surfaces, custom editors, webviews, extension
contributions, menus, keybindings, and daemon supervision to feel like one
native operator console.

Embedding a VS Code substrate inside Tauri made that harder:

- the app had two shells competing for lifecycle, navigation, focus, menus,
  commands, shortcuts, webviews, and window behavior;
- rich workbench surfaces could become iframe/projection islands instead of
  first-class VS Code workbench contributions;
- Tauri command handlers drifted toward runtime-adjacent responsibilities that
  should remain daemon-owned;
- renderer integration, asset loading, event routing, and deep IDE state were
  harder to reason about than in the native VS Code/Electron host;
- maintaining Tauri and Electron paths risked product drift, duplicate
  validation, and a hidden fallback that weakened the canonical app shell.

## Decision

Autopilot will retire the Tauri/OpenVSCode embedding path and make the
Electron/VS Code fork the canonical app shell for the IDE-first Autopilot
Workbench.

The shell decision is:

```text
Electron/VS Code fork = canonical Autopilot app shell
ioi-workbench = built-in workbench extension/API layer
IOI daemon = runtime authority and durable execution boundary
Tauri/OpenVSCode embedding = legacy extraction inventory to remove
```

Electron is chosen here because VS Code itself is Electron-based and the fork is
the shortest path to first-class IDE substrate integration: activity bar views,
custom editors, webviews, command/menu/keybinding contributions, extension-host
contracts, workbench state, terminal/Git/problems/search integration, and native
main-process shell affordances can be owned in one app shell.

## Consequences

- Autopilot Workbench surfaces such as Agent Studio, Models, Workflow Composer,
  receipts/replay, policy, runs, and evidence should be first-class VS
  Code/Electron workbench surfaces, not Tauri side panels around an embedded IDE.
- Electron main/native modules own shell affordances such as daemon supervision,
  windows, deep links, tray, global shortcuts, updater, auth handoff, and app
  lifecycle.
- `ioi-workbench` becomes the built-in extension/API layer inside the fork.
- Tauri command handlers and UI surfaces must be inventoried as migrate, retire,
  delete, or compatibility-only extraction references.
- Validation, screenshots, GUI control, and sprint-readiness evidence should
  target the Electron/VS Code fork path.
- Runtime launch should depend on the packaged Electron app plus canonical
  `ioi-workbench` source. The local checkout convention is `ide/vscode` for
  optional fork development and `ide/builds/VSCode-linux-x64` for the packaged
  runnable app; neither path is an npm workspace or runtime authority.
- The VS Code extension host, webviews, and Electron renderer remain projection
  and request surfaces. They must not become durable runtimes.
- The IOI daemon remains the authority for workflows, patch application,
  policy, receipts, replay, model mounting, connector calls, secrets, and
  workspace mutation.

## Alternatives Considered

1. **Keep Tauri and continue embedding OpenVSCode.**
   Rejected because it preserved the deepest integration mismatch and encouraged
   duplicate shell/runtime/projection paths.

2. **Maintain both Tauri and Electron indefinitely.**
   Rejected because it would split validation, product UX, shell affordances,
   and runtime-boundary discipline.

3. **Ship only a generic VS Code extension.**
   Rejected because Autopilot needs a sovereign operator console, shell
   affordances, daemon supervision, model/runtime management, and product-grade
   UX beyond a marketplace extension.

4. **Ship a generic web app beside the IDE.**
   Rejected as the canonical workbench because autonomous coding and workflow
   operation need IDE-native files, terminals, Git, diagnostics, diffs, and
   commands.

## Non-Goals

- This decision does not move runtime authority into Electron, the VS Code
  extension host, a webview, or `ioi-workbench`.
- This decision does not make Tauri a bridge to keep. Tauri is legacy extraction
  inventory until migrated or removed.
- This decision does not prevent non-Workbench compatibility adapters such as
  IOI Authority Gateway. It only defines the canonical Autopilot app shell.

## Relationship To Other ADRs

- ADR 0007 defines the broader IDE-first two-substrate architecture.
- ADR 0008 defines the IOI Authority Gateway sidecar adoption wedge for users
  who keep existing IDEs or agent tools.
- This ADR records the narrower shell substrate decision: Electron/VS Code fork
  replaces Tauri/OpenVSCode embedding for the canonical Autopilot Workbench.
