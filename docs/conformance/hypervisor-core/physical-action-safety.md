# Physical-action safety conformance

Status: active conformance target with a current declaration-level intent
admission planner and registered execution-receipt schema. Final-invoker
execution, interrupted-effect recovery, and live receipt emission remain target
contracts.
Canonical inputs:
[`physical-action-safety.md`](../../architecture/foundations/physical-action-safety.md)
and
[`embodied-runtime.md`](../../architecture/components/daemon-runtime/embodied-runtime.md).
Last audited: 2026-07-16.

## Scope and honest implementation posture

This profile specifies conformance for the existing `SafetyEnvelope` and
`EmbodiedDeploymentAssuranceCase` boundary. It does not define a generic Safety
contract, a second assurance kernel, or a parallel evidence registry.

The genuinely built seam is the Rust-owned pure admission planner exposed by
`POST /v1/hypervisor/physical-action-intent-admissions`. It validates
declaration-level identity schemes, physical primitive and authority-scope
presence, safety/policy/emergency-stop refs, tested emergency-stop posture,
sensor and phase-dependent command receipt refs, simulation and generic-tool
exclusions, and declared human-supervision/approval fields. It records supplied
facts; it does not resolve or cryptographically verify the referenced
authority, evidence, measurement, safety, controller, or receipt objects.

The machine-contract substrate also registers
`PhysicalActionExecutionReceipt` with positive and adversarial fixtures and
generated Rust/TypeScript projections. Current master has no shared
physical-action execution core, typed controller invoker,
`Prepared`/`Completed` execution store, dispatch normalizer, or live
execution-receipt emitter.

The planner and schema do not schedule a native embodied graph, operate a
`LocalControlSupervisor`, mount a real actuator/controller adapter, measure
live timing, persist execution idempotency through Agentgres, or emit the full
switch/segment/exception/e-stop/incident family. Neither supplied refs nor
generated receipt types prove cryptographic hardware identity,
controller-side deduplication, or final-effect enforcement.

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

Implementation status: planned. The current intent planner is not mounted
immediately before a real actuator/controller invocation and therefore does not
prove final-gate ordering or zero-call denial. A future implementation must bind
the exact command, fresh `state_root_before`, expanded resource closure,
emergency-stop authority, and typed `controller_binding_ref`; require the
target to be a bound unit or actuator; compare the invoker-reported adapter
identity; and prove same-body no-reinvoke versus changed-body conflict.
Redirect, bridge, standby, restart, and alternate-controller bypass probes
remain required. A typed adapter ref must never be cited as cryptographic
controller identity by itself.

### CPAS-10 — Receipts and replay

Switch, proof-test, ODD-exit, teleoperation-loss, restart-unarmed, writer handoff,
actuator command, segment, exception, e-stop, and incident receipts MUST bind the
same target, graph, envelope, evidence bundle, writer epoch, timing chain, and
state roots needed for replay.

Implementation status: schema, invariant, fixture, and generated-projection
substrate only; no live local emission or receipt chain is implemented. The
registered machine contract is exactly
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
non-conforming. The current architecture-contract checks validate one positive
committed fixture and reject missing dispatch evidence, envelope/input-hash
substitution, and flat unbundled shapes. Runtime hashing, predecessor-head
enforcement, durable Agentgres admission, and every switch, ODD-exit,
teleoperation-loss, segment, exception, e-stop, handoff, and incident receipt
path remain open.

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

Implementation status: planned. Current master has no serializable execution
snapshot, durable `Prepared`/`Completed` transition, or Agentgres transaction
around a controller boundary. Reconciliation-required/no-reinvoke recovery and
controller-side idempotency remain unproven.

## Current evidence and required promotion bar

Current evidence is limited to the existing intent-planner unit tests and daemon
journey plus the registered receipt-schema fixtures:

```bash
cargo test -p ioi-services runtime_physical_action_intent_admission --lib
npm run check:architecture-contracts
npm run test:architecture-contract-projections
```

The planner tests cover declaration admission, generic-tool and
simulation-as-execution refusal, emergency-stop testing/latency, sensor refs,
supervision fields, and retired request aliases. The contract fixtures cover a
committed receipt and the bounded structural substitutions named under CPAS-10.
They do not cover CPAS-9 final-invoker ordering or CPAS-11 crash recovery.
Current master has no `physical` conformance tier.

Promotion requires native or separately assured controller mounting, durable
Agentgres ledger and receipt admission, cryptographic hardware/controller
identity, controller-side idempotency, prepared/unknown-effect restart tests,
receipt-backed fault/bypass probes, and estate-wide CPAS coverage.
