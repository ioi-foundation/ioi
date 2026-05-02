# Capability Execution Contract (CEC)

Status: hidden conformance invariant; Draft v0.5
Owners: Agentic Platform
Canonical owner: this file for completion, evidence, and terminal-state invariants.
Supersedes: overlapping CEC descriptions outside `docs/conformance/agentic-runtime/` when invariant wording conflicts.
Superseded by: none.
Last alignment pass: 2026-05-01.
Scope: Post-resolution execution discipline for inference-driven tasks

## 1. Purpose
CEC defines how the agent executes an already resolved intent before terminal completion is allowed.

CEC complements CIRC:
- CIRC governs `which intent` wins (Zero Heuristics).
- CEC governs `how execution` is carried out and verified (Zero Fallbacks).

Normative clarification:
- "Zero Heuristics" in CIRC/CEC means zero ad hoc, topic-specific, or fallback-style heuristics in places that would undermine typed intent resolution or deterministic execution boundaries.
- It does NOT forbid scalable deterministic heuristics that are generic, feature-based, task-class-aware, and policy-controlled.

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

### 2.2 Remote Retrieval Discovery Rule (Normative)
For `remote_retrieval` and the remote-retrieval portions of `mixed` intents:
- `discovery` MUST still construct a candidate provider set when multiple providers or retrieval shapes are possible.
- provider selection MUST be grounded in typed retrieval requirements plus typed discovery evidence.
- query text MAY influence typed retrieval requirements, but MUST NOT directly emit provider IDs, provider order, hostnames, domain-specific execution branches, or predeclared query-class routes.
- implementations MUST NOT use query archetypes, domain buckets, or other predesignated query designs as an execution-planning substitute for typed discovery and typed provider admission.
- provider selection MUST NOT depend on static query-to-provider shortcuts, domain allowlists keyed by query class, or lexical asset/subject slug extraction used as a stand-in for discovery.
- reusable execution shapes MAY exist only when they are structural, cross-domain forms inferred from typed requirements and then validated through discovery, rather than canned query-family branches.
- policy-controlled feature scoring MAY be used to rank discovered candidates when it relies on generic evidence such as authority class, source kind, overlap, diversity, or freshness fit.
- such scoring MUST NOT hardcode topic-specific publishers, query-family-specific provider ladders, or domain-specific boost tables as a substitute for typed discovery.

For connector-backed execution:
- `discovery` MUST construct provider candidates from registered connector probes and currently connected accounts.
- provider selection MUST bind execution to one discovered connector/provider route only after candidate admission.
- execution MUST NOT select connectors via ad hoc lexical heuristics, tool-name prefix tests, or provider-specific branches embedded in the intent matrix.

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
- **Discovery-Backed Provider Selection:** For remote retrieval, State 3 MUST choose providers only from candidates evidenced in State 2 discovery. Hardcoded provider ladders keyed by content class are forbidden.
- **Scalable Heuristic Admission:** Within State 2 and State 3, implementations MAY use generic, deterministic, policy-scoped scoring heuristics to rank already admitted candidates. Those heuristics MUST be feature-based and cross-domain; they MUST NOT introduce topic-specific special casing or post-execution fallback behavior.
- For `deterministic_local`, states `discovery` and `provider_selection` MAY be skipped by contract.
- Verification MUST always execute unless the contract explicitly defines a `no_verify` class, which is forbidden in v0.5.

## 4. Contract Fields (Intent-Scoped)
Each applicable intent MUST define:
- `applicability_class: topology_dependent | deterministic_local | remote_retrieval | mixed`

Each applicable intent MAY additionally define:
- `requires_host_discovery: bool`
- `provider_selection_mode: dynamic_synthesis | capability_only | discovery_backed_only`
- `required_evidence: [string]`
- `success_conditions: [string]`
- `verification_mode: dynamic_synthesis | deterministic_check`

*(Note: `fallback_chain` is explicitly deprecated in v0.5. Infinite topology variance MUST be handled by robust `discovery` and `dynamic_synthesis` loops prior to execution, not via execution retries).*

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
- `probe_source`
- `observed_value`
- `evidence_type`

Shorthand compatibility markers MAY be emitted:
- `receipt::<name>=true`
- `postcondition::<name>=true`

Normative constraints:
- Human-readable shorthand markers MUST be treated as observability aids only.
- Completion gates, local judges, and arbiters MUST rely on typed receipt fields or typed observation structures, not on substring parsing over freeform replies, diagnostics, or debug log lines.
- Any claim about local or remote state in verification SHOULD carry `probe_source` and `observed_value`; for environment or host-state claims these fields SHOULD be treated as required by conformance policy.

### 5.1 Minimum Receipts by Applicability Class
- `topology_dependent`: `host_discovery`, `provider_selection/synthesis`, `execution`, `verification`
- `deterministic_local`: `execution`, `verification`
- `remote_retrieval`: `execution`, `verification`
- `mixed`: union of required receipts from included classes

### 5.2 Verification Rule
The system MUST NOT assume success from process exit status alone.
Verification MUST include read-state evidence with a cryptographic commit when verification is synthesized dynamically.

### 5.3 Judge Integrity Rule
Runtime success adjudication MUST be receipt-driven.

Normative constraints:
- Final chat reply text MUST NOT be the primary evidence channel for pass/fail.
- Debug-oriented verification strings MUST NOT be parsed as the sole source of truth for contract satisfaction.
- Implementations SHOULD project typed observation fields from runtime receipts so judges can evaluate structured evidence directly.
- If shorthand markers are mirrored into logs or verification strings, those mirrors MUST be secondary to the typed receipt objects they summarize.

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
If typed provider discovery cannot justify any valid provider candidate, runtime MUST terminate with synthesis/discovery failure rather than introducing a static provider shortcut.

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

Profile D: Remote Retrieval Discipline
- provider selection backed by typed discovery receipts
- no static query-conditioned provider shortcuts
- source-independence checks enforced pre-execution
- typed verification evidence available for final adjudication

Profile E: Judge Integrity
- local judge and arbiter consume typed receipt fields or typed observations
- final reply text is not required as primary success evidence
- shorthand verification strings are not the sole gating material

## 10. Anti-Patterns (Prohibited)
Implementations MUST NOT:
- Implement unbounded post-execution "try-and-catch" code-rewriting loops.
- Use the host environment as a trial-and-error sandbox (all quality adjustments MUST occur in State 3 before execution).
- Generate topology-dependent execution scripts without first executing a `discovery` phase.
- Treat zero exit code as sufficient proof of postcondition.
- Skip verification for synthesized execution payloads.
- Emit terminal completion before receipt and postcondition checks pass.
- Select remote providers through hardcoded query-class/provider-class mappings.
- Use predesignated query archetypes, domain buckets, or canned query designs as a stand-in for typed provider discovery or execution planning.
- Build provider-specific URLs or provider order directly from lexical subject extraction unless a discovery receipt has already admitted that provider and affordance.
- hide model-family-conditioned execution behavior, retry policy, prompt budgeting, or harness/runtime handling inside workflow code when the policy can instead be expressed through typed runtime provenance, declared lane, renderer class, or explicit preset configuration.
- use benchmark-specific or model-family-specific workflow branches without surfacing the governing preset/lane policy as an explicit configuration input or receipt-backed execution policy.
- Gate success primarily on reply text, diagnostic prose, or substring matches over debug output.

## 11. Non-Goals
CEC does not define semantic ranking, capability ontology design, or ambiguity winner selection. Those remain in CIRC.

## 12. Relationship to CIRC
CIRC + CEC define the full contract:
- CIRC: intent resolution correctness (what should happen, bound by primitives).
- CEC: execution correctness (how it is dynamically synthesized safely and verifiably executed).

## 13. Migration Guidance
To migrate a heuristic executor to Draft v0.5:
1. Inventory all query-conditioned provider ladders, domain allowlists, subject-slug URL builders, and reply-text/debug-string success checks.
2. Replace provider/domain outputs from query interpretation with typed retrieval requirements only.
3. Introduce a provider registry whose entries advertise structural affordances and admissibility predicates rather than domain semantics.
4. Make State 2 discovery produce typed provider-candidate receipts and require State 3 provider selection to reference those receipts.
5. Move provider-specific URL builders, parsers, and challenge handling behind adapters that are only reachable after discovery-backed provider admission.
6. For connector-backed systems, register connector route metadata and candidate probes in the provider registry so new connectors participate without intent-pipeline heuristics.
7. Normalize execution and verification outputs into typed receipt and observation structures with `probe_source` and `observed_value`.
8. Make completion gates, local judges, and arbiters consume typed evidence directly; demote reply text and shorthand markers to observability-only.
9. Add conformance coverage for provider-discovery integrity, source-independence enforcement, connector-registry routing integrity, and judge-integrity invariants.
10. Inventory model-family-conditioned execution branches, prompt-budget exceptions, reasoning toggles, and harness/runtime overrides; move them into versioned preset/lane policy or typed runtime-shape rules so workflow code no longer keys off model labels.

## 14. Change Control and Versioning
CEC changes MUST be versioned.
Breaking changes MUST include:
- migration notes (e.g., deprecation of `fallback_chain` in v0.5)
- conformance profile updates
- receipt schema delta notes
- judge-integrity and provider-discovery migration notes
