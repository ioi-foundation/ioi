# Capability-Intent Resolution Contract (CIRC)

Status: Draft v0.4
Owners: Agentic Platform
Scope: Intent resolution and capability ontology for desktop agent execution

## 1. Purpose
CIRC defines a clean ontology contract for intent resolution that scales without devolving into alias tables, keyword patches, or capability bloat.

Primary goals:
- Keep routing semantics stable under query paraphrase.
- Keep behavior explainable and auditable.
- Prevent layer mixing between domain semantics and system primitives.

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
- Tools MAY be domain-specific wrappers.
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

### 3.3 Capability (Primitive Boundary Rule)
A Capability is a foundational primitive (for example `sys.exec`, `fs.read`, `ui.interact`, `sys.env_read`).

Normative constraints:
- Capabilities MUST NOT encode domain operations (for example `timer.create`, `bluetooth.toggle`, `math.eval`).
- Capability additions MUST correspond to a new permission, isolation, or risk boundary.
- If a task can be expressed via existing primitives, the system MUST model it as a new intent or tool, not a new capability.

### 3.4 Tool
A Tool is an executable operation that provides one or more primitive capabilities:
- `tool_id`
- `provides_capabilities`
- optional policy constraints

Normative constraints:
- Introducing a tool MUST NOT require resolver keyword patches.
- Tool presence MAY change feasibility outcomes.
- Tool presence MUST NOT alter semantic ranking scores.

### 3.5 Policy
Policy provides versioned deterministic controls:
- confidence thresholds
- ambiguity margins and actions (`proceed`, `pause`, `abstain`)
- tie-region epsilon and score quantization
- safety and risk constraints

### 3.6 Normative Layering Examples
The examples below are illustrative and conform to the three-layer rule:

1. Arithmetic evaluation query:
- Intent: `math.eval`
- Required primitive capabilities: for example `agent.lifecycle`, `conversation.reply`
- Tool: `math__eval` as a domain-specific wrapper
- Note: this covers expression-style math only, not opening the Calculator application UI.

2. Timer creation:
- Intent: `time.timer.create`
- Required primitive capabilities: for example `sys.exec`
- Tool: any compliant execution tool exposing `sys.exec`

3. Local app launch:
- Intent: `app.launch`
- Required primitive capabilities: for example `ui.interact` and/or `sys.exec` depending on platform policy
- Tool: platform-specific launcher or shell wrapper, without changing resolver semantics

## 4. Resolution Contract
For query `q`, active intent set `I`, and active tool set `T`, the resolver MUST perform the phases below.

### 4.1 Semantic Ranking Phase (Only)
Semantic ranking MUST depend only on:
- query text
- canonical intent semantic descriptors
- embedding model output
- similarity function

The following MUST NOT affect ranking scores:
- aliases
- exemplars
- scope
- risk class
- tool names

### 4.2 Hard Constraint Phase
Feasibility MUST be evaluated separately from ranking:
- `feasible(i)` iff all required primitive capabilities for intent `i` are satisfiable by `T`
- and policy does not prohibit execution

If the top-ranked intent is infeasible, selection MUST proceed to the next feasible ranked intent before abstention.

### 4.3 Deterministic Selection Phase
After ranking and feasibility:
- scores MUST be quantized at policy-defined precision
- ties MUST be evaluated using policy-defined tie region
- deterministic tie-break MUST use only versioned deterministic inputs

### 4.4 Ambiguity and Abstention
Policy MAY define explicit versioned ambiguity margins.
Low-confidence unresolved behavior MUST emit `resolver.unclassified` or policy-defined pause behavior.

### 4.5 Policy Evaluation Order (Normative)
When checks conflict, implementations MUST evaluate in this order:
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
- route by ad hoc keyword or substring tests
- route by tool-name prefixes
- route by prompt-only exceptions
- short-circuit to a tool before intent winner selection

### 5.3 Allowed Patterns
Resolver logic MAY:
- use aliases and exemplars for observability and analytics
- include deterministic post-ranking feasibility filtering

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

When adding an intent:
- add canonical descriptor
- map to existing primitive capabilities where possible

### 7.2 Capability Admission Gate (Normative)
A new capability MAY be added only if all of the following are true:
1. Existing capabilities cannot represent the boundary safely.
2. The new capability introduces a distinct permission, isolation, or risk boundary.
3. The boundary can be enforced by runtime and policy.
4. The change includes ontology migration notes and conformance updates.

### 7.3 Growth Monotonicity
Adding tools that do not change feasibility of existing intents MUST NOT change winners for the golden query corpus.

## 8. Intent Granularity and Collision Control
Intent descriptors MUST be mutually discriminative.
Implementations SHOULD run ontology collision linting and fail CI below policy-defined minimum separation thresholds.

## 9. Conformance Profiles
CIRC conformance MUST be tested by profile:

Profile A: Resolver Core
- paraphrase invariance
- metadata independence
- deterministic tie behavior
- ambiguity behavior

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
To migrate a heuristic resolver to Draft v0.4:
1. Extract routing fields into typed schema.
2. Separate semantic ranking from feasibility and policy checks.
3. Replace domain-specific capability bindings with primitive capability mappings.
4. Enforce deterministic selection and deterministic receipts.
5. Wire execution behavior to CEC lifecycle gates.

## 12. Change Control and Versioning
CIRC changes MUST be versioned.
Breaking changes MUST include:
- migration notes
- conformance-suite updates
- golden-corpus impact notes
- ontology delta summary (intents, capabilities, tools)
