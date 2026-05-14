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
| P1 model routing | Done / regression guard | Provider/endpoint route decisions, privacy posture, cost estimates, fallback policy/evidence, deterministic local failover, TUI rows, SDK records, and React Flow projections are implemented. Live hosted provider validation is credential-gated. |
| P1 doctor/config | Done / regression guard | `/v1/doctor`, `ioi agent doctor --json`, clean/degraded reports, secret redaction, runtime readiness blockers, and `RuntimeDoctorNode` are implemented. |
| P1 skills/hooks | Done / regression guard | Multi-source skill discovery/import, `SKILL.md` validation, active skill-set hash, prompt audit provenance, governed hook types/policies, TUI rows, and React Flow skill/hook nodes are implemented. Public marketplace catalog distribution is external. |
| P2 repo/PR/jobs/a11y | Done / regression guard | Governed repo/PR dry-run records, branch/diff artifacts, durable failed-attempt evidence, task/job/checklist APIs, hosted fail-closed behavior, React Flow task/job/checklist nodes, and accessibility/localization-boundary metadata are implemented. Live PR mutation and hosted workers are credential/provider gated. |

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
| 213 | 2026-05-14 | Future-plus closure | Closed the remaining local P1/P2 future-plus dashboard rows with canonical task APIs, SDK/CLI/TUI task controls, React Flow task-node endpoint correction, and guide/log/ledger completion cleanup. |

## Recent Slices

| Slice | Commit | Summary |
| --- | --- | --- |
| 206 | `7ecfeaf17` | Recovered live GUI package/activation evidence and runtime-consistency checks. |
| 207 | `3c52e5976` | Proved terminal-first coding-tool rows across daemon, SDK, CLI/TUI, and React Flow projection. |
| 208 | `46cce7e96` | Added the React Flow terminal coding-loop template plus creator/run-inspector materialization. |
| 209 | `ae97df2d8` | Proved live execution of the terminal coding loop against daemon coding tools. |
| 210 | `1ff517599` | Added saved workflow run-launch for persisted terminal coding-loop workflows. |
| 211 | `0e1ad17af` | Wired pure terminal-loop WorkflowComposer Run actions through the shared composer activation wrapper. |
| 212 | `ba9dc39a7` | Added the required GUI harness Run-button proof for terminal coding-loop WorkflowComposer activation. |
| 213 | final slice commit | Added canonical runtime task API projection across daemon, SDK, CLI/TUI, React Flow node metadata, live daemon validation, and final future-plus guide cleanup. |

## Next Entry Template

```md
### Slice N. YYYY-MM-DD - Short title

- Area:
- Commit:
- Summary:
- Validation:
- Next tactical recommendation:
```
