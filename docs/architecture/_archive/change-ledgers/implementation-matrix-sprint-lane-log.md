# Implementation Matrix — Historical Sprint-Lane Narration

Status: archived change ledger (verbatim extraction).
Doctrine status: archived
Implementation status: n/a (historical record)
Archived from: `docs/architecture/_meta/implementation-matrix.md` on 2026-07-05.
Canonical owner: `docs/architecture/_meta/implementation-matrix.md` (live doctrine); this file is history, not authority.
Superseded by: the canonical owner doc. Git history retains the original placement.

---

Current sprint lane: typed Rust daemon-core APIs are the migration substrate;
generic command invokers and binary bridge transports are not terminal
architecture. `AgentgresRuntimeStateStore` now passes typed daemon-core APIs into
mounted hot-path cores, and StepModule execution uses
`daemonCoreWorkloadApi.runCodingToolStepModule` instead of a daemon-core command
envelope. The shared JS-authored `mockResult` command fallback is retired, and
the shared JS daemon-core command-spawn helper is deleted. L1 settlement,
external capability authority, governed improvement, cTEE Private Workspace,
worker/service package, coding-tool approval, workspace restore, runtime
Agentgres admission, approval-state, model_mount, context-policy/state-update,
and StepModule execution are mounted typed Rust-client surfaces, so command-env
compatibility can no longer authorize, admit, plan, or execute those truth
paths. The coding-tool approval-satisfaction JS event/lease gate is also
retired, and the coding-tool budget recovery/operator-control/run-cancel
command-shaped Rust owner wrappers are deleted: those runtime-control families
now expose typed runtime-control APIs plus Rust policy cores instead of bridge
request/response wrappers. Approval-required coding-tool execution
now asks Rust
`project_coding_tool_approval_satisfaction` for request/decision/lease
projection and then Rust `plan_coding_tool_approval_satisfaction` for a
positive satisfaction record. The JS store projection callback and exported JS
manifest matcher are retired; unsatisfied approval otherwise fails closed at
the governance block surface until direct Rust approval/admission projection
owns block materialization end to end. Once real Rust daemon-core APIs are wired
and verified, retire remaining JS facade scaffolding instead of preserving it as
compatibility wrappers.

Current model_mount blocker interpretation: historical rows may preserve the
"remaining at this cut" wording for review lineage, but the active blocker
ledger is the newest dedicated model_mount rows plus the migration matrix
terminal-blocker section. Hosted live transport, hosted stream semantics,
backend-process live supervision, hosted cTEE egress resolver binding,
invocation authority planning, invocation JS helper deletion, and
backend-process fallback-proof protocol deletion are Rust-owned and are no
longer current implementation blockers. Capability-token and vault no-replay
`state_dir` compatibility handoff is also retired at the JS and Rust planning
boundaries, and provider-lifecycle health/start/stop topology subject replay is
owned by Rust provider/endpoint read-projection replay instead of JS endpoint
selection.
