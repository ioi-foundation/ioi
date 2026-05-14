# Agent Runtime DeepSeek TUI Parity Plus Implementation Log

Status: pruned implementation ledger
Source guide: `docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
Pruned: 2026-05-14

This ledger keeps the implementation history readable after the long parity
push. The exhaustive slice transcripts were intentionally collapsed; detailed
changes remain available through git history. New slices should add one compact
entry here and keep full proof output in CI or local artifacts rather than
committing bulky evidence bundles.

`docs/evidence/` was emptied on 2026-05-14 and is ignored by git. Historical
evidence paths named in older commits may no longer exist in the current tree.

## Current Completion Summary

| Area | State | Notes |
| --- | --- | --- |
| P0 live runtime bridge | Done / regression guard | TTI schemas, daemon replay, Rust bridge execution, KernelEvent mapping, SDK wrappers, CLI stream, React Flow projection, and runtime controls are in place. |
| P0 terminal coding-agent TUI | Done / regression guard | TUI rows, coding pack commands, terminal-loop template, live execution, saved workflow run launch, WorkflowComposer activation, and the real GUI Run-button harness proof are implemented. |
| P0 coding tool pack | Done / regression guard | Status, diff, inspect, patch, test, diagnostics, artifacts, result retrieval, receipts, approval, rollback refs, and React Flow config are implemented. |
| P0 diagnostics and rollback | Done / regression guard | Post-edit diagnostics, blocking gates, repair decisions, snapshots, restore preview/apply, and React Flow/TUI repair surfaces are implemented. |
| P1 subagents | Done / regression guard | Spawn, wait, result, send-input, cancel, resume, assign, parent propagation, child subflows, and budget enforcement are implemented. |
| P1 MCP | Done / regression guard | Discovery, validation, registry writes, enable/disable, invocation, stdio/HTTP/SSE transports, serve mode, vault auth, deferred catalog search/fetch, and React Flow/TUI authoring are implemented. |
| P1 memory | Done / regression guard | Status, validation, remember/edit/delete, policy controls, subagent inheritance, TUI commands, SDK helpers, and React Flow nodes are implemented. |
| P1 modes/trust/approvals | Done / regression guard | Thread mode, workspace trust warnings, acknowledgement gates, approval manifests, approved retries, and workflow-edit proposals are daemon-owned and projected. |
| P1 usage/cost/context | Done / regression guard | Usage summaries, context pressure, compaction, coding-tool budget gates, recovery policy, templates, binding assistants, and live chain execution are implemented. |
| P1 model routing | Partial / future plus | Basic model/thinking controls exist; richer provider priority, privacy tier, fallback, cost estimates, and deterministic failover remain future-plus work. |
| P1 doctor/config | Partial / future plus | Foundation slices exist; one canonical `/v1/doctor` product report is still a future-plus hardening target. |
| P1 skills/hooks | Partial / future plus | Discovery, manifests, dry-run policy, invocation, and escalation receipts exist; import/marketplace-grade UX remains future-plus. |
| P2 repo/PR/jobs/a11y | Partial / future plus | Foundation records and workflow surfaces exist; hosted/team coding polish remains future-plus. |

## Slice Rollup

| Range | Dates | Workstream | Outcome |
| --- | --- | --- | --- |
| 1-13 | 2026-05-11 | Model, memory, doctor, skills/hooks | Established the first parity-plus user surfaces and runtime-owned receipts. |
| 14-23 | 2026-05-11 | Repository, GitHub/PR, task/job records | Added governed repository context, branch/review gates, PR attempt records, and job/checklist foundations. |
| 24-86 | 2026-05-11 to 2026-05-12 | Workflow UI, packaging, localization, React Flow refactors | Made package/import, promotion, settings-harness, readiness, run-history, and workflow editor surfaces modular enough for later parity slices. |
| 87-113 | 2026-05-12 to 2026-05-13 | Live bridge and guide governance | Locked TTI/event contracts, daemon event store, bridge adapters, SDK/CLI/React Flow projection, and the first runtime-control nodes. |
| 114-139 | 2026-05-13 | Terminal TUI, coding pack, diagnostics, rollback | Delivered daemon-backed TUI controls, coding tools, post-edit diagnostics, snapshots, restore, repair, and job/run lifecycle rows. |
| 140-157 | 2026-05-13 | MCP, memory, diagnostics repair | Productized MCP manager, memory manager, repair decisions, and React Flow MCP/diagnostics authoring. |
| 158-162 | 2026-05-13 | Subagents | Added SDK/TUI/React Flow subagent controls, child subflows, and budget enforcement. |
| 163-205 | 2026-05-13 to 2026-05-14 | Usage, context, budget recovery | Added usage/context telemetry, context-pressure actions, coding-tool budget gates, recovery templates, binding assistants, and run-inspector-created chain execution. |
| 206-212 | 2026-05-14 | GUI evidence recovery and terminal coding-loop parity | Recovered full live GUI harness package/activation evidence, proved terminal coding-tool rows, added terminal coding-loop template, live execution, saved workflow run launch, WorkflowComposer activation, and real Run-button GUI harness proof. |

## Recent Terminal Coding-Loop Slices

| Slice | Commit | Summary |
| --- | --- | --- |
| 206 | `7ecfeaf17` | Recovered live GUI package/activation evidence and runtime-consistency checks. |
| 207 | `3c52e5976` | Proved terminal-first coding-tool rows across daemon, SDK, CLI/TUI, and React Flow projection. |
| 208 | `46cce7e96` | Added the React Flow terminal coding-loop template plus creator/run-inspector materialization. |
| 209 | `ae97df2d8` | Proved live execution of the terminal coding loop against daemon coding tools. |
| 210 | `1ff517599` | Added saved workflow run-launch for persisted terminal coding-loop workflows. |
| 211 | `0e1ad17af` | Wired pure terminal-loop WorkflowComposer Run actions through the shared composer activation wrapper. |
| 212 | this slice | Added the required GUI harness Run-button proof for terminal coding-loop WorkflowComposer activation. |

## Next Entry Template

```md
### Slice N. YYYY-MM-DD - Short title

- Area:
- Commit:
- Summary:
- Validation:
- Next tactical recommendation:
```
