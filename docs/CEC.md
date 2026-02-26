# Capability Execution Contract (CEC)

Status: Draft v0.4
Owners: Agentic Platform
Scope: Post-resolution execution discipline for inference-driven tasks

## 1. Purpose
CEC defines how the agent executes an already resolved intent before terminal completion is allowed.

CEC complements CIRC:
- CIRC governs `which intent` wins (Zero Heuristics).
- CEC governs `how execution` is carried out and verified (Zero Fallbacks).

CEC prevents topology shortcuts (hardcoded app assumptions, static provider shortcuts, exit-code-only success claims). It enables safe **probabilistic synthesis** (e.g., dynamically writing scripts to handle infinite topology variance) by permitting quality adjustment loops *prior* to execution, while strictly enforcing a single-shot deterministic boundary *during* execution.

## 2. Applicability Classes (Normative)
Each intent execution contract MUST declare `applicability_class`:
- `topology_dependent`: host environment discovery and provider selection are required prior to payload synthesis or execution.
- `deterministic_local`: deterministic local computation or transformation with no host topology dependency.
- `remote_retrieval`: external retrieval where host topology discovery is not required.
- `mixed`: combines two or more classes above.

Class defaults:
- `topology_dependent` implies `requires_host_discovery=true`.
- `deterministic_local` implies `requires_host_discovery=false`.

### 2.1 Classification Examples
Examples of class assignment:
- `topology_dependent`: synthesizing a bash script to launch an unknown desktop app on a host with varying OS permissions.
- `deterministic_local`: pure arithmetic evaluation, pure string transforms.
- `remote_retrieval`: fetching remote content where host capability probing is unnecessary.
- `mixed`: workflows combining local deterministic transforms with topology-dependent side effects.

## 3. Execution State Machine
Execution MUST follow this state machine:
1. `contract_loaded`
2. `discovery` (Gathering ground-truth host topology; required when contract requires it)
3. `provider_selection` / `payload_synthesis` (Probabilistically generating and iteratively refining the execution payload based strictly on discovery)
4. `execution` (Single-shot deterministic invocation)
5. `verification`
6. `completion_gate`
7. `terminal`

Normative constraints:
- Implementations MUST NOT transition to `terminal` before successful `completion_gate`.
- **Pre-Execution Quality Adjustment:** Iterative quality adjustment, self-critique, and validation loops (e.g., syntax linting, dry-runs) are explicitly permitted and encouraged *within* State 3 (`payload_synthesis`).
- **Single-Shot Execution Boundary:** Once the payload transitions to State 4 (`execution`), it is the point of no return. State 4 MUST be a single-shot invocation. Post-execution heuristic retries using the real environment as a sandbox are strictly forbidden.
- **Remote Retrieval Payload Linting:** For multi-source retrieval intents, State 3 MUST validate source-independence constraints (for example, a distinct-domain floor) before State 4 is allowed.
- For `deterministic_local`, states `discovery` and `provider_selection` MAY be skipped by contract.
- Verification MUST always execute unless the contract explicitly defines a `no_verify` class, which is forbidden in v0.4.

## 4. Contract Fields (Intent-Scoped)
Each applicable intent MUST define:
- `applicability_class: topology_dependent | deterministic_local | remote_retrieval | mixed`

Each applicable intent MAY additionally define:
- `requires_host_discovery: bool`
- `provider_selection_mode: dynamic_synthesis | capability_only`
- `required_receipts: [string]`
- `required_postconditions: [string]`
- `verification_mode: dynamic_synthesis | deterministic_check`

*(Note: `fallback_chain` is explicitly deprecated in v0.4. Infinite topology variance MUST be handled by robust `discovery` and `dynamic_synthesis` loops prior to execution, not via execution retries).*

## 5. Receipt and Postcondition Schema
Execution MUST emit machine-readable evidence records.

Required receipt fields:
- `contract_version`
- `intent_id`
- `stage`
- `key`
- `satisfied` (boolean)
- `timestamp_ms`
- `evidence_commit_hash`

Optional fields:
- `verifier_command_commit_hash`
- `provider_id`
- `synthesized_payload_hash`

Shorthand compatibility markers MAY be emitted:
- `receipt::<name>=true`
- `postcondition::<name>=true`

### 5.1 Minimum Receipts by Applicability Class
- `topology_dependent`: `host_discovery`, `provider_selection/synthesis`, `execution`, `verification`
- `deterministic_local`: `execution`, `verification`
- `remote_retrieval`: `execution`, `verification`
- `mixed`: union of required receipts from included classes

### 5.2 Verification Rule
The system MUST NOT assume success from process exit status alone.
Verification MUST include read-state evidence with a cryptographic commit when verification is synthesized dynamically.

## 6. Policy Precedence and Synthesis Semantics
When multiple gates apply, runtime MUST evaluate in this order:
1. hard safety and policy blocks
2. contract applicability and required phases
3. discovery phase (capturing topology)
4. payload synthesis (safe sandbox for probabilistic generation, linting, and self-correction)
5. single-shot execution attempt (committing the payload to the host environment)
6. verification
7. completion gate

A failure at Phase 6 (Verification) MUST trigger a terminal error. The system MUST NOT route the error back to Phase 4 for a heuristic retry.
If State 3 payload linting fails source-independence constraints, the system MUST stay in pre-execution phases (Discovery/Synthesis) and MUST NOT execute opportunistic reads that violate the contract.

## 7. Completion Gate
`agent__complete` (or any terminal completed status) MUST be blocked when:
- any required receipt is missing
- any required postcondition is missing
- `requires_host_discovery=true` and `host_discovery` receipt is missing
- verification fails

On violation, runtime MUST emit `ERROR_CLASS=ExecutionContractViolation` and include:
- `missing_receipts`
- `missing_postconditions`
- `failed_stage`

## 8. Failure Taxonomy
Implementations MUST emit stable machine-readable failures.

Required classes:
- `ERROR_CLASS=ExecutionContractViolation`
- `ERROR_CLASS=DiscoveryMissing`
- `ERROR_CLASS=SynthesisFailed` (Emitted if State 3 quality loops cannot produce a valid payload)
- `ERROR_CLASS=ExecutionFailedTerminal`
- `ERROR_CLASS=VerificationMissing`
- `ERROR_CLASS=PostconditionFailed`
- `ERROR_CLASS=PolicyBlocked`

## 9. Conformance Profiles
CEC conformance MUST be tested by profile:

Profile A: Topology-Dependent Execution
- discovery required and evidenced
- payload synthesis strictly depends on discovery receipt
- one-shot deterministic execution enforced (no cyclic retries after State 4)
- completion blocked on missing verification

Profile B: Deterministic-Local Execution
- no unnecessary discovery requirement
- execution and verification receipts required
- completion blocked on missing receipts

Profile C: Mixed Execution
- per-phase receipt union enforcement
- precedence order enforcement
- deterministic terminal gating

## 10. Anti-Patterns (Prohibited)
Implementations MUST NOT:
- Implement unbounded post-execution "try-and-catch" code-rewriting loops.
- Use the host environment as a trial-and-error sandbox (all quality adjustments MUST occur in State 3 before execution).
- Generate topology-dependent execution scripts without first executing a `discovery` phase.
- Treat zero exit code as sufficient proof of postcondition.
- Skip verification for synthesized execution payloads.
- Emit terminal completion before receipt and postcondition checks pass.

## 11. Non-Goals
CEC does not define semantic ranking, capability ontology design, or ambiguity winner selection. Those remain in CIRC.

## 12. Relationship to CIRC
CIRC + CEC define the full contract:
- CIRC: intent resolution correctness (what should happen, bound by primitives).
- CEC: execution correctness (how it is dynamically synthesized safely and verifiably executed).

## 13. Change Control and Versioning
CEC changes MUST be versioned.
Breaking changes MUST include:
- migration notes (e.g., deprecation of `fallback_chain` in v0.4)
- conformance profile updates
- receipt schema delta notes
