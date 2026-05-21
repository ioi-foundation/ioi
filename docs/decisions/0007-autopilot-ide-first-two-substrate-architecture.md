# ADR 0007: Adopt IDE-First Autopilot With Runtime And Workbench Substrates

- Status: Accepted
- Date: 2026-05-20
- Owners: Autopilot / daemon runtime / VS Code fork / policy / connectors-tools

## Context

Autopilot was evolving through a Tauri desktop shell that embedded OpenVSCode and
carried many runtime-adjacent commands in `apps/autopilot/src-tauri`. That path
proved valuable UI and workbench integration ideas, but it also blurred shell,
runtime, projection, and authority boundaries.

The long-term product direction is IDE-first. Autonomous work needs more than a
chat transcript: it needs files, terminals, diffs, diagnostics, Git, search,
plans, approvals, policy, connector readiness, run timelines, receipts, replay,
and workflow graphs in one operator surface.

## Decision

Autopilot is one product with two substrates:

1. Runtime substrate:
   IOI daemon as the hypervisor/control plane for autonomous execution.
2. Workbench substrate:
   Autopilot Workbench as the IDE-grade operator console.

The canonical framing is:

```text
IOI daemon = hypervisor/control plane for autonomous execution
Autopilot Workbench = IDE-grade operator console
Electron/VS Code fork = canonical app shell
Workers/models/tools/connectors = guest workloads/capabilities
Policy/receipts/replay = trust and audit substrate
```

The VS Code/Electron fork is the canonical Autopilot app shell. `ioi-workbench`
should be promoted into that fork as the built-in workbench API/extension layer.
Tauri/OpenVSCode embedding is legacy extraction inventory to remove, not a
product substrate to keep.

## Consequences

- The daemon remains the only authority for workflow execution, patch apply,
  connector calls, policy decisions, approvals, secrets, receipts, replay, and
  workspace mutation.
- The workbench observes, requests, approves, interrupts, debugs, and explains
  daemon-governed work.
- VS Code extension-host code must not become a second runtime.
- Electron main/native modules own app shell affordances such as deep links,
  tray, global shortcuts, windows, updater, auth handoff, and daemon
  supervision.
- Tauri command handlers must be classified as migrate, retire, delete, or
  compatibility-only before removal.
- Connector sprint work is blocked until fixture/dry-run UX readiness is proven
  in the canonical workbench.

## Non-Goals

- Do not start connector-specific live sprint work in this decision.
- Do not preserve Tauri/OpenVSCode embedding as a parallel product path.
- Do not move daemon authority into a VS Code extension, webview, React Flow
  graph, CLI/TUI surface, or SDK helper.

## Source Guide

The implementation umbrella guide is:

`.internal/plans/autopilot-ide-first-tauri-retirement-ux-readiness-master-guide.md`

## Related Decisions

- ADR 0009 records the narrower shell substrate decision: switch the canonical
  Autopilot IDE shell from Tauri/OpenVSCode embedding to the Electron/VS Code
  fork because deep IDE integration belongs inside the native VS Code/Electron
  substrate.
