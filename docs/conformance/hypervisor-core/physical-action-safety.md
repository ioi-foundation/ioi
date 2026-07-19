# Physical-action safety conformance

Status: active conformance target; partial admission and reference execution coverage.
Canonical inputs:
[`physical-action-safety.md`](../../architecture/foundations/physical-action-safety.md)
and
[`embodied-runtime.md`](../../architecture/components/daemon-runtime/embodied-runtime.md).
Last audited: 2026-07-16.

## Scope and honest implementation posture

This profile tests the existing `SafetyEnvelope` and
`EmbodiedDeploymentAssuranceCase` boundary. It does not define a generic Safety
contract, a second assurance kernel, or a parallel evidence registry.

The built seams are the Rust-owned pure admission planner exposed by
`POST /v1/hypervisor/physical-action-intent-admissions` and an unmounted
reference `PhysicalActionExecutionCore`. The planner validates and records
supplied refs, hashes, measurements, resource closures, command/controller
bindings, and evidence posture. The execution core recomputes the canonical
command hash, performs fresh preflight immediately before one typed invoker,
requires exact fresh-admission state-root and typed adapter identity, proves
zero-call denial and coordinator-side same-body replay, records serializable
`Prepared`/`Completed` phases, normalizes dispatch proof, and emits the
registered domain-separated, hash-chained
`PhysicalActionExecutionReceipt` bundle.

Neither seam resolves or cryptographically verifies every referenced evidence
artifact, schedules a native embodied graph, operates a
`LocalControlSupervisor`, mounts a real actuator/controller adapter, measures
live timing, persists execution idempotency/receipts through Agentgres, or emits
the full segment/exception/e-stop/incident family. Those unbuilt seams cannot
inherit estate-wide conformance from the reference-core tests. The typed adapter
reference is not cryptographic hardware identity, and requiring the adapter to
propagate an idempotency key does not prove controller-side deduplication.

## Conformance criteria

### CPAS-1 — Exact deployment binding

Live physical, hard-real-time, or asserted E1+ admission MUST fail closed unless
one exact evidence bundle/hash binds the target, SafetyEnvelope/hash, runtime
graph/hash, hardware, controller firmware, ODD/hash, monitor, command switch,
recovery controller, recoverable-region evidence, timing chain, and proof-test
receipts. Evidence for another deployment or revision is ineligible.

Observable pass evidence: a structured denial before any actuator invoker for a
missing or mismatched field, and an admitted record retaining the exact checked
bindings.

### CPAS-2 — Evidence-level honesty

The asserted E0..E3 level MUST NOT exceed the level supported by the bound
deployment evidence. E0 declarations alone MUST NOT admit live physical work.

Observable pass evidence: E2-over-E1 and E1-without-bundle adversarial requests
return deterministic 403 denials.

### CPAS-3 — Complete timing chain

The SafetyEnvelope MUST bind monitor period and jitter plus a graph-scoped total
observation-to-safe-switch bound. A demonstrated result later than the bound
MUST fail closed. Hard-real-time claims require analytic WCET/schedulability
evidence; bounded-soft claims require explicit tail percentile, sample count,
workload/fault envelope, and measured tail evidence.

Observable pass evidence: chain artifact/hash and timing mode in the admission
record, late-switch refusal, and—once the executor exists—timestamped receipts
covering every chain edge.

### CPAS-4 — Recoverable region and proof-test cadence

The current recoverable-region margin MUST meet the envelope minimum. Command
switch and recovery proof-test receipts MUST be current under the declared
cadence, and the safe-switch receipt MUST bind the exact deployment.

Observable pass evidence: insufficient-margin and stale-proof-test denials plus
current receipt refs in admitted records.

### CPAS-5 — Measurable ODD and exit response

Every safety-relevant ODD attribute MUST bind a unit, permitted range, monitor,
and measurement receipt. `exiting`, `outside`, `unknown`, or an out-of-range
measurement MUST invoke the declared local response within its deadline rather
than admit continued motion.

Observable pass evidence: ODD-exit denial and, once the local supervisor exists,
a receipt proving the declared response met its deadline.

### CPAS-6 — Assured safety inputs

An unassured learned stream MAY be supplemental but MUST NOT be the sole input to
the safe-set monitor, switch, recovery, interlock, or e-stop. At least one
current assured non-learned input MUST bind its stream contract/hash, producer,
failure domain, evidence, and receipt.

Observable pass evidence: learned-only denial and an admitted record preserving
the assured input bindings.

### CPAS-7 — Restart and exclusive writer

Restart MUST return actuator-bearing execution inactive and unarmed, and live
admission MUST retain the restart-unarmed receipt. Exactly one fenced active
writer is allowed. A configured standby MUST remain fenced and require explicit
safe-takeover proof before a new writer epoch.

Observable pass evidence: missing restart/fence/takeover denials and, once the
supervisor exists, concurrent-writer and restart-resume fault tests.

### CPAS-8 — Teleoperation contract

Active teleoperation MUST bind the exact link contract/hash, current operator
authority and authentication receipt, independent deadman, arbitration policy,
writer fence, round-trip bound, operator-takeover budget, and local loss
response. Link degradation/loss, auth expiry/revocation, deadman release/stale
state, or ambiguous arbitration MUST fail closed.

Observable pass evidence: deterministic teleop-loss denial and, once live
control exists, local stop/recovery receipts produced without a remote round
trip.

### CPAS-9 — Real invoker choke point

The final admission decision MUST execute immediately before the real actuator
or controller invoker. Every denial above MUST prove zero invoker calls, and
redirect, adapter, bridge, standby, or restart paths MUST NOT bypass it.

Implementation status: reference mechanism built, production mount open. The
reference core proves final-gate ordering; exact command, fresh
`state_root_before`, expanded resource-closure leaves, emergency-stop authority,
and typed `controller_binding_ref` binding; zero-call denial; changed-body
conflict; and same-body no-reinvoke replay for a completed invocation. The
target MUST be a bound unit or actuator, and the selected controller and
emergency-stop authority MUST occur in the same admitted closure. The
invoker-reported typed adapter identity MUST exactly match the admitted binding
before the call. It MUST NOT be cited as cryptographic controller identity or as
coverage of a real actuator path until a native or separately assured adapter
mounts it at the actual effect boundary; redirect, bridge, standby, restart, and
alternate-controller bypass probes also remain open.

### CPAS-10 — Receipts and replay

Switch, proof-test, ODD-exit, teleoperation-loss, restart-unarmed, writer handoff,
actuator command, segment, exception, e-stop, and incident receipts MUST bind the
same target, graph, envelope, evidence bundle, writer epoch, timing chain, and
state roots needed for replay.

Implementation status: reference execution receipt chain built, live local
emission open. The registered machine contract is exactly
`{ schema_version, receipt_envelope, body, body_hash, receipt_hash }`.
`receipt_envelope.input_hash` MUST equal the execution request hash,
`receipt_envelope.output_hash` MUST equal the JCS SHA-256 of the physical body,
and `receipt_envelope.policy_hash` MUST equal the SafetyEnvelope hash.
`body_hash` MUST bind the exact envelope/body pair and `receipt_hash` MUST be
the domain-separated bundle hash. The body binds target, expanded
resource-group closures, emergency-stop authority, controller, graph,
SafetyEnvelope, assurance bundle, writer lease/epoch/token, timing chain,
command hash, preflight and sensor receipts, controller effect, dispatch posture
and evidence, controller receipts, before/after state roots, effect status,
predecessor hash, and execution time. Flat or partially bound receipts are
non-conforming. Contract, tamper, and stale-head tests pass. Durable Agentgres
admission and the remaining switch, ODD-exit, teleoperation-loss, segment,
exception, e-stop, handoff, and incident receipt paths remain open.

### CPAS-11 — Interrupted execution and dispatch proof

The execution ledger MUST record a `Prepared` request hash immediately before
one controller invocation and MUST record `Completed` only after outcome
normalization and receipt-bundle verification. Restart or recovery that finds
`Prepared` MUST freeze the affected receipt chain, require reconciliation, and
MUST NOT blindly reinvoke. A committed outcome requires
`dispatched_observed`, non-empty dispatch evidence, non-empty controller
receipts, and a known after-state root. A rejected outcome requires
`not_dispatched_proven`, dispatch evidence, and no after-state root. Every
contradictory, incomplete, timed-out, or malformed post-invocation result MUST
remain an `unknown`/`dispatch_ambiguous` effect with explicit normalization
errors.

Implementation status: serializable reference mechanism built; production
crash boundary open. Restoring a reference snapshot containing `Prepared`
proves reconciliation-required/no-reinvoke behavior, but there is no durable
Agentgres transaction around the real controller boundary. The adapter contract
requires propagation of the idempotency key; controller-side idempotency remains
unproven.

## Current adversarial evidence

The focused Rust unit suite covers:

- missing assured safety input;
- demonstrated observation-to-switch time later than the admitted bound;
- ODD exit;
- teleoperation link loss;
- evidence-level overclaim;
- exact live command and controller binding;
- exact fresh-admission state root, expanded resource closure, selected
  emergency-stop authority, and typed adapter identity;
- zero controller calls on command-hash or fresh-admission denial;
- one invocation plus no-reinvoke same-body replay;
- changed-body idempotency conflict and stale predecessor-head refusal;
- restored-`Prepared` reconciliation refusal without blind reinvocation;
- committed/rejected dispatch-proof requirements and ambiguous normalization;
- exact `ReceiptEnvelope`/body cross-binding, registered-contract validation,
  chained verification, and tamper refusal;
- preservation of an unknown controller effect as unknown; and
- conversion of malformed post-invocation adapter output into a chained
  `unknown` receipt rather than a lost error.

Run:

```bash
npm run hypervisor-conformance:physical
```

Planner and reference-executor success are necessary but insufficient for full
CPAS-9 through CPAS-11. Native or separately assured controller mounting,
durable Agentgres ledger and receipt admission, cryptographic
hardware/controller identity, controller-side idempotency, receipt-backed
fault/bypass probes, and estate-wide CPAS coverage remain open.
