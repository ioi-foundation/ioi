# Capability Execution Contract (CEC)

Status: Draft v0.3
Owners: Agentic Platform
Scope: Post-resolution execution discipline for inference-driven tasks

## 1. Purpose
CEC defines how the agent executes an already resolved intent before terminal completion is allowed.

CEC complements CIRC:
- CIRC governs `which intent` wins.
- CEC governs `how execution` is carried out and verified.

CEC prevents topology shortcuts (hardcoded app assumptions, static provider shortcuts, exit-code-only success claims).

## 2. Applicability Classes (Normative)
Each intent execution contract MUST declare `applicability_class`:
- `topology_dependent`: host environment discovery and provider selection are required.
- `deterministic_local`: deterministic local computation or transformation with no host topology dependency.
- `remote_retrieval`: external retrieval where host topology discovery is not required.
- `mixed`: combines two or more classes above.

Class defaults:
- `topology_dependent` implies `requires_host_discovery=true`.
- `deterministic_local` implies `requires_host_discovery=false`.

### 2.1 Classification Examples
Examples of class assignment:
- `topology_dependent`: launching an unknown desktop app on a host with unknown tooling.
- `deterministic_local`: pure arithmetic evaluation, pure string transforms, local deterministic parsing.
- `remote_retrieval`: fetching and verifying remote content where host capability probing is unnecessary.
- `mixed`: workflows that combine local deterministic transforms with topology-dependent side effects.

## 3. Execution State Machine
Execution MUST follow this state machine:
1. `contract_loaded`
2. `discovery` (required only when contract requires it)
3. `provider_selection` (required when selection mode is dynamic)
4. `execution`
5. `verification`
6. `completion_gate`
7. `terminal`

Normative constraints:
- Implementations MUST NOT transition to `terminal` before successful `completion_gate`.
- For `deterministic_local`, states `discovery` and `provider_selection` MAY be skipped by contract.
- Verification MUST always execute unless contract explicitly defines a `no_verify` class, which is forbidden in v0.3.

## 4. Contract Fields (Intent-Scoped)
Each applicable intent MUST define:
- `applicability_class: topology_dependent | deterministic_local | remote_retrieval | mixed`

Each applicable intent MAY additionally define:
- `requires_host_discovery: bool`
- `provider_selection_mode: dynamic_synthesis | capability_only`
- `fallback_chain: [native, install_with_approval, script]`
- `required_receipts: [string]`
- `required_postconditions: [string]`
- `verification_mode: dynamic_synthesis | deterministic_check`

These fields are authoritative for runtime gating and MUST NOT be replaced by prompt-only policy.

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
- `fallback_step`

Shorthand compatibility markers MAY be emitted:
- `receipt::<name>=true`
- `postcondition::<name>=true`

### 5.1 Minimum Receipts by Applicability Class
- `topology_dependent`: `host_discovery`, `provider_selection`, `execution`, `verification`
- `deterministic_local`: `execution`, `verification`
- `remote_retrieval`: `execution`, `verification`
- `mixed`: union of required receipts from included classes

### 5.2 Verification Rule
The system MUST NOT assume success from process exit status alone.
Verification MUST include read-state evidence with a cryptographic commit when verification is synthesized dynamically.

## 6. Policy Precedence and Fallback Semantics
When multiple gates apply, runtime MUST evaluate in this order:
1. hard safety and policy blocks
2. contract applicability and required phases
3. fallback chain ordering
4. execution attempt
5. verification
6. completion gate

Fallback chain semantics for `dynamic_synthesis`:
1. `native`
2. `install_with_approval`
3. `script`

A lower-priority fallback is valid only after evidenced failure, unavailability, or user denial of higher-priority options.

## 7. Completion Gate
`agent__complete` (or any terminal completed status) MUST be blocked when:
- any required receipt is missing
- any required postcondition is missing
- `requires_host_discovery=true` and `host_discovery` receipt is missing

On violation, runtime MUST emit `ERROR_CLASS=ExecutionContractViolation` and include:
- `missing_receipts`
- `missing_postconditions`
- `failed_stage`

## 8. Failure Taxonomy
Implementations MUST emit stable machine-readable failures.

Required classes:
- `ERROR_CLASS=ExecutionContractViolation`
- `ERROR_CLASS=DiscoveryMissing`
- `ERROR_CLASS=ProviderSelectionFailed`
- `ERROR_CLASS=FallbackOrderViolation`
- `ERROR_CLASS=VerificationMissing`
- `ERROR_CLASS=PostconditionFailed`
- `ERROR_CLASS=PolicyBlocked`

## 9. Conformance Profiles
CEC conformance MUST be tested by profile:

Profile A: Topology-Dependent Execution
- discovery required and evidenced
- dynamic fallback ordering enforced
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
- bypass discovery with hardcoded OS app registries for topology-dependent intents
- treat zero exit code as sufficient proof of postcondition
- skip verification for synthesized execution payloads
- emit terminal completion before receipt and postcondition checks pass

## 11. Non-Goals
CEC does not define semantic ranking, capability ontology design, or ambiguity winner selection. Those remain in CIRC.

## 12. Relationship to CIRC
CIRC + CEC define the full contract:
- CIRC: intent resolution correctness (what should happen)
- CEC: execution correctness (how it is safely and verifiably done)

## 13. Change Control and Versioning
CEC changes MUST be versioned.
Breaking changes MUST include:
- migration notes
- conformance profile updates
- receipt schema delta notes
