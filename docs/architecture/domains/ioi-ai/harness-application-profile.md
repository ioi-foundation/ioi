# ioi.ai Harness Application Profile

Status: canonical reference.
Canonical owner: this file for the ioi.ai orchestration application's use of the
Default Harness Profile — the GoalRun admission-path decision, the pursuit
policy a GoalRun-coordinated invocation carries, and the room-collaboration
context a harness receives when it fulfils a room claim.
Supersedes: the same admission-path decision when it lived inside
[`default-harness-profile.md`](../../components/daemon-runtime/default-harness-profile.md)
as if selecting a harness selected a goal product (moved 2026-09-07 under
ADR 0052 Decision 4; the text is unchanged apart from link paths).
Superseded by: none.
Last alignment pass: 2026-09-07.
Doctrine status: canonical
Implementation status: partial (the GoalRun admission-path decision is
registered as an application contract; see
[`../../_meta/canon-to-code-delta.md`](../../_meta/canon-to-code-delta.md))
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/goalrun_routes.rs`
  - `crates/node/src/bin/hypervisor_daemon_routes/goal_profile_contract_routes.rs`
Last implementation audit: 2026-07-30

## Scope

The Default Harness Profile
([`default-harness-profile.md`](../../components/daemon-runtime/default-harness-profile.md))
owns harness selection, invocation, tool boundaries, model configuration,
lifecycle and evidence for every session. The same qualified harness executes
a direct session with no application present. This profile adds what the
ioi.ai orchestration application supplies when it requests an invocation:
the admission-path decision below, the exact `GoalRunProfile` revision the
invocation interprets, and the room context of a claimed subgoal. It grants
nothing the daemon's own admission does not grant.

## GoalRun Admission Path Decision

The Hypervisor Daemon is the sole admitting owner for selecting whether an
admitted GoalRun uses the direct non-System path or requires a System-bound
path. A client, surface, profile, harness, model, workflow, or correlation
reference may request a path but cannot select or upgrade it. The daemon emits
one `GoalRunAdmissionPathDecision` and binds its exact decision receipt before
GoalRun execution begins.

The direct non-System path is eligible only when every predicate below is
resolved true from admitted policy and live runtime facts:

- the request creates or continues exactly one bounded work subject;
- no System membership, constitutional state, shared frontier, OutcomeRoom,
  collective scheduler, or multi-party admission owner is required;
- the declared capability, authority, resource, budget, risk, isolation, and
  receipt requirements fit one admitted execution without widening;
- no unresolved dependency requires System-owned state or coordination; and
- no applicable policy requires the System-bound path.

Any false or unknown predicate makes direct admission ineligible. The daemon
returns `system_bound_required` with typed reason codes when the System-bound
path is available, or a typed `refused` decision when its prerequisites are not
available. It never silently downgrades System-bound work to the direct path,
silently widens the direct path, or treats a requested path as an admission
fact. Direct work still freezes the built-in generic-adaptive
`GoalRunProfile` revision and content hash, effective constraint hash, policy,
authority, resolved component set, result profile, and decision receipt. It is
not a profileless, authority-free, or receipt-free exception.

The canonical non-software M3 conformance profile is `research`. The minimum
positive proof emits a `WorkResult` with `result_profile: research`, a
profile-owned payload reference, claims and uncertainty, supporting and
contradicting evidence where present, exact producer-component resolution, and
a terminal receipt. Negative, inconclusive, challenged, and superseded research
results remain first-class retained outputs. This selection fixes a proof
profile; it does not make research the only non-software result family or move
result ownership into the harness.

The registered wire contract is
`schema://ioi/applications/ioi-ai/goal-run-admission-path-decision/v1`. ADR 0029 records
the durable owner ruling. Implementing or proving this direct-path contract
does not satisfy the System-bound prerequisites, close M3, or admit P0.

The live first implementation is intentionally narrower than this target. It
admits only `parallel_implement_reconcile`, uses one deterministic conductor,
at most two implementers, software-shaped task briefs/results, isolated
candidate workspaces, deterministic candidate verification, and one admitted
reconciliation. That is a valid bounded software profile, not evidence that
open participation, dynamic topology, generic results, or cross-domain room
coordination is already implemented.

Persistent workspace intelligence is separate from any selected model or
harness. Skills, memory, wiki state, learned tool affordances, and durable
behavior-affecting context belong to the workspace/project/domain through
Agent Wiki / `ioi-memory`, Agentgres-admitted mutations, receipts, provenance,
and policy. Swapping from one model or harness to another should not discard
that intelligence when workspace identity, compatibility, and authority remain
valid.
