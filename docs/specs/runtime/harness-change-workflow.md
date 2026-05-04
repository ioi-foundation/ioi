# Harness Change Workflow

Status: active implementation workflow.

Use this workflow for changes that touch route selection, CIRC/CEC boundaries,
tool execution, approvals, receipts, runtime status, chat process UX, or GUI
runtime harness behavior.

## Principle

Do not discover the architecture through the GUI. The GUI is the final integration
judge, not the first debugger for the runtime contract.

Harness work must move through contract, trace, fixture, UI, and real GUI
validation in that order. If a change cannot pass the earlier layers, launching
the app usually makes the failure slower and less precise.

## Required Order

1. Add invariant tests before changing behavior.
2. Validate the runtime contract with fixture providers or a dry-run executor.
3. Validate structured event traces from route decision through final receipt.
4. Validate UI rendering from structured events.
5. Run the real Tauri GUI in an isolated profile.
6. Stop dev/runtime processes, remove isolated profiles, and trim evidence.

## Invariant Tests

Add focused tests for the boundary being changed before implementation.

Required invariants for consequential tool paths:

- CIRC owns intent classification and route selection.
- CEC owns approved execution, receipts, verification, failure classes, and final
  state.
- Resolvers/providers own candidate discovery and source provenance.
- Executors do not receive raw user text when a resolved plan object is required.
- Mutating actions require approval before host or external state changes.
- Success is reported only after verification receipts pass.
- UI process state is rendered from structured events and receipts, not arbitrary
  status strings.
- Direct answers do not emit fake work graph rows or receipt-backed states they
  did not earn.

## Trace First

Before validating through the desktop app, create or update a replayable trace
for the turn shape. A useful trace includes:

- original user query
- structured intent frame or context envelope
- route decision
- resolver/provider events
- selected candidate or blocker
- approval request and decision
- execution stream
- verification result
- final assistant state

The trace should be deterministic enough to explain the expected UI without
requiring the GUI to be open.

## Fixture Before Reality

Use fake providers, fixture registries, and dry-run executors before real network,
browser, package-manager, or host-mutation paths.

For installs, this means fixture-backed provider discovery should prove the
ontology first. Real package managers, official web endpoints, browser discovery,
downloads, and verification are integration validation, not the main debugging
loop.

## UI Contract

Test the UI against structured process events before launching the app. The UI
may present concise labels, but it must not infer consequential runtime stages
from generic strings.

Approval UI and execution streaming should be separate surfaces:

- approval card: source, command/installer, elevation, verification plan, allow
  or deny
- execution stream: exact command/download/runtime output and receipt-backed
  progress after approval
- final answer: truthful installed, already installed, unresolved, denied,
  failed, or verified state

## GUI Validation

Real GUI validation is still required for harness work. Use an isolated profile
and keep evidence small.

Minimum GUI scenarios for install/runtime harness changes:

- one known resolvable install
- one unknown or unresolved target
- one denied approval path when the UI exposes denial
- one direct answer
- one explicit new-session submit after a completed turn

The GUI pass must confirm:

- no direct prose route for consequential install prompts
- no fake progress rows for direct answers
- approval appears in chat, not as a detached notification workflow
- execution output streams after approval
- final state is receipt-backed
- session controls behave as explicit user controls, not query heuristics

## Clean Break Rules

Do not add or preserve:

- app-specific route-selection branches
- executor-side app-name matching
- lexical install fallbacks outside structured intent extraction
- package-manager guessing for unknown auto installs
- compatibility shims without a protocol-versioned migration reason
- UI parsing of arbitrary status text as the source of runtime truth

If a compatibility path is unavoidable, document the external contract, expiry
condition, fail-closed behavior, and guard test before merging it.

## Cleanup Checklist

Before handoff:

- stop Tauri, Vite, local runtime, and helper processes started by validation
- remove isolated data profiles
- remove temporary screenshots and logs, or retain a small named evidence set
- verify no matching orphan processes remain
- report tests, GUI scenarios, cleanup, and any true residual risk

