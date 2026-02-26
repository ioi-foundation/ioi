# Capability-Intent Resolution Contract (CIRC)

Status: Draft v0.5
Owners: Agentic Platform
Scope: Intent resolution and capability ontology for desktop agent execution

## 1. Purpose
CIRC defines a clean ontology contract for intent resolution that scales without devolving into alias tables, keyword patches, or capability bloat.

Primary goals:
- Keep routing semantics stable under query paraphrase.
- Keep behavior explainable and auditable.
- Prevent layer mixing between domain semantics and system primitives.
- Eliminate "heuristic routing" (guessing via regex/aliases).
- Enable safe **probabilistic payload synthesis** at infinite scale by grounding generative actions in strict primitive capability boundaries.

## 2. Normative Terms
The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in RFC 2119.

## 3. Ontology Model
### 3.1 Three-Layer Rule (Normative)
The resolver model MUST enforce three distinct layers:
- `Intent`: domain-level semantics (what the user wants).
- `Capability`: primitive permission or execution boundary (what is fundamentally possible and allowed).
- `Tool`: concrete implementation mechanism (how the action is executed).

Layer constraints:
- Intents MAY be domain-specific.
- Tools MAY be generic executors for probabilistically synthesized payloads.
- Capabilities MUST remain primitive and boundary-oriented.
- Resolver winner selection MUST be intent-driven, not tool-driven.

### 3.2 Intent
An Intent is a canonical semantic action class mapping user goals to required primitive execution boundaries:
- `intent_id` (stable identifier, for example `time.timer.create`)
- `scope` (ontology surface class)
- `semantic_descriptor` (authoritative routing text)
- `required_capabilities` (primitive set, for example `[sys.exec]`)
- `preferred_tier`
- `risk_class`

Normative note for time-sensitive remote retrieval intents:
- Intents that require "latest", "today", "current", or equivalent temporal grounding SHOULD include the primitive capability `sys.time.read` in `required_capabilities`.
- The resolver/runtime contract SHOULD treat this as a hard feasibility dependency before remote retrieval execution begins.

### 3.3 Capability (Primitive Boundary Rule)
A Capability is a foundational primitive (for example `sys.exec`, `fs.read`, `ui.interact`, `sys.env_read`).

Normative constraints:
- Capabilities MUST NOT encode domain operations (for example `timer.create`, `bluetooth.toggle`, `math.eval`).
- Capability additions MUST correspond to a new permission, isolation, or risk boundary.
- If a task can be expressed via existing primitives, the system MUST model it as a new intent or tool, not a new capability.

### 3.4 Tool (and Dynamic Synthesizers)
A Tool is an executable operation that provides one or more primitive capabilities:
- `tool_id`
- `provides_capabilities`
- optional policy constraints

Normative constraints:
- Introducing a tool MUST NOT require resolver keyword patches.
- Tool presence MAY change feasibility outcomes.
- Tool presence MUST NOT alter semantic ranking scores.
- If a Tool is designed to execute probabilistically synthesized payloads (e.g., an ephemeral shell), it MUST be strictly constrained by its declared `provides_capabilities`.

### 3.5 Policy
Policy provides versioned deterministic controls:
- confidence thresholds
- ambiguity margins and actions (`proceed`, `pause`, `abstain`)
- tie-region epsilon and score quantization
- safety and risk constraints

### 3.6 Normative Layering Examples
1. Arithmetic evaluation query:
- Intent: `math.eval`
- Required primitive capabilities: `agent.lifecycle`, `conversation.reply`
- Tool: `math__eval` as a domain-specific wrapper.

2. Timer creation via Dynamic Synthesis:
- Intent: `time.timer.create`
- Required primitive capabilities: `sys.exec`
- Tool: An ephemeral shell execution tool exposing `sys.exec` that runs a dynamically synthesized bash script based on topology discovery.

## 4. Resolution Contract
For query `q`, active intent set `I`, and active tool set `T`, the resolver MUST perform the phases below.

### 4.1 Semantic Ranking Phase (Only)
Semantic ranking MUST depend only on:
- query text
- canonical intent semantic descriptors
- embedding model output
- similarity function

The following MUST NOT affect ranking scores: aliases, exemplars, scope, risk class, or tool names.

### 4.2 Hard Constraint Phase
Feasibility MUST be determined strictly upfront. Trial-and-error routing is forbidden.
- `feasible(i)` iff all required primitive capabilities for intent `i` are satisfiable by `T`
- and policy does not prohibit execution

For intents that declare multi-source evidence floors, feasibility MUST also include a payload-shape check in Discovery/Synthesis before execution:
- the selected candidate payload MUST satisfy policy-defined source-independence constraints (for example, distinct domains for multi-story headline aggregation).
- if payload-shape constraints are not met, execution MUST NOT begin.

If the top-ranked intent is infeasible, selection MUST proceed to the next feasible ranked intent before abstention.

### 4.3 Deterministic Selection Phase
After ranking and feasibility:
- scores MUST be quantized at policy-defined precision
- ties MUST be evaluated using policy-defined tie region
- deterministic tie-break MUST use only versioned deterministic inputs

### 4.4 Ambiguity and Abstention
Policy MAY define explicit versioned ambiguity margins.
Low-confidence unresolved behavior MUST emit `resolver.unclassified` or policy-defined pause behavior.
If a successfully resolved intent fails downstream during CEC execution, the resolver MUST NOT automatically re-trigger a semantic ranking phase to "guess" an alternative intent.

### 4.5 Policy Evaluation Order (Normative)
1. hard policy block rules
2. capability feasibility
3. quantization and tie handling
4. ambiguity policy
5. abstention or final selection

## 5. Clean Routing Requirements
### 5.1 Authoritative Inputs
Resolver routing MUST depend only on canonical semantic ranking inputs plus explicit policy and feasibility checks.

### 5.2 Prohibited Patterns
Resolver logic MUST NOT:
- route by ad hoc keyword, substring tests, or lexicographic assertions.
- route by tool-name prefixes.
- route by prompt-only exceptions.
- short-circuit to a tool before intent winner selection.
- fallback to lower-ranked intents dynamically based on downstream execution failures.

### 5.3 Allowed Patterns
Resolver logic MAY:
- use aliases and exemplars for observability and analytics.
- include deterministic post-ranking feasibility filtering.

## 6. Determinism and Replayability
Resolver receipts MUST commit to model and policy state so selection is replayable.
Minimum resolver receipt fields:
- `contract_version`
- `intent_matrix_version`
- `intent_set_hash`
- `tool_registry_hash`
- `capability_ontology_hash`
- `query_normalization_version`
- `embedding_model_id`
- `embedding_model_version`
- `similarity_function_id`
- `selected_intent_id`
- `selected_score_quantized`
- `receipt_hash`

## 7. Capability Growth Contract
### 7.1 Tool and Intent Additions
When adding a tool:
- validate `provides_capabilities` maps to primitive capabilities
- do not patch resolver winner logic for that tool

### 7.2 Capability Admission Gate (Normative)
A new capability MAY be added only if all of the following are true:
1. Existing capabilities cannot represent the boundary safely.
2. The new capability introduces a distinct permission, isolation, or risk boundary.
3. The boundary can be enforced by runtime and policy.
4. The change includes ontology migration notes and conformance updates.

### 7.3 Growth Monotonicity
Adding tools that do not change feasibility of existing intents MUST NOT change winners for the golden query corpus.

## 8. Intent Granularity and Collision Control
Intent descriptors MUST be mutually discriminative. Implementations SHOULD run ontology collision linting and fail CI below policy-defined minimum separation thresholds.

Because execution strictly forbids fallbacks (per CEC), persistent execution failures indicate an inaccurate Discovery phase or poorly synthesized payload, NOT a need for runtime agentic retries. Teams MUST resolve execution gaps by refining the discovery context passed to the LLM or adding required primitives.

## 9. Conformance Profiles
CIRC conformance MUST be tested by profile:

Profile A: Resolver Core
- paraphrase invariance and metadata independence
- deterministic tie behavior and ambiguity handling

Profile B: Ontology Governance
- primitive capability enforcement
- capability admission gate enforcement
- growth monotonicity on golden corpus
- descriptor collision linting

Profile C: Replayability
- resolver receipt completeness
- deterministic replay from receipt material

## 10. Failure Taxonomy
Resolvers MUST emit machine-readable failures with stable `ERROR_CLASS`.

Required classes:
- `ERROR_CLASS=IntentUnclassified`
- `ERROR_CLASS=IntentInfeasible`
- `ERROR_CLASS=PolicyBlocked`
- `ERROR_CLASS=ResolverContractViolation`
- `ERROR_CLASS=OntologyViolation`

## 11. Migration Guidance
To migrate a heuristic resolver to Draft v0.5:
1. Extract routing fields into typed schema.
2. Separate semantic ranking from feasibility and policy checks.
3. Replace domain-specific capability bindings with primitive capability mappings.
4. Enforce deterministic selection and full cryptographic receipts.
5. Wire execution behavior strictly to CEC lifecycle gates (Zero Fallback).

## 12. Change Control and Versioning
CIRC changes MUST be versioned.
Breaking changes MUST include:
- migration notes (e.g., prohibition of heuristic execution retries)
- conformance-suite updates
- golden-corpus impact notes
- ontology delta summary (intents, capabilities, tools)
