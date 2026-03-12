# Capability-Intent Resolution Contract (CIRC)

Status: Draft v0.6
Owners: Agentic Platform
Scope: Intent resolution and capability ontology for desktop agent execution

## 1. Purpose
CIRC defines a clean ontology contract for intent resolution that scales without devolving into alias tables, keyword patches, or capability bloat.

Primary goals:
- Keep routing semantics stable under query paraphrase.
- Keep behavior explainable and auditable.
- Prevent layer mixing between domain semantics and system primitives.
- Eliminate "heuristic routing" (guessing via regex/aliases).
- Enforce structural retrieval modeling so ontology symbols do not collapse into provider or content vertical shortcuts.
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

### 3.5 Structural Retrieval Rule (Normative)
If the system models retrieval affordances, those affordances MUST describe structural evidence shape rather than domain semantics, provider families, or site topology.

Normative constraints:
- Retrieval affordances MUST be structural and cross-domain (for example `queryable_index`, `ordered_collection`, `link_collection`, `detail_document`, `structured_record`, `timestamped_record`, `geo_scoped_record`, `canonical_link_out`).
- Retrieval affordances MUST NOT encode content verticals or provider classes (for example `news_feed`, `price_page`, `restaurant_directory`, `menu_detail_page`, `google_news`, `coindesk_page`).
- Query inference MAY emit typed retrieval requirements (for example `currentness_required`, `locality_required`, `entity_cardinality_min`, `comparison_required`, `scalar_measure_required`, `source_independence_min`).
- Query inference MUST NOT emit provider IDs, provider families, hostnames, site slugs, or domain-specific affordance names as ontology-level routing outputs.
- Provider-specific parsers, URL builders, and transport quirks MAY exist only as adapter internals after provider selection has already been justified by typed discovery evidence.

### 3.6 Policy
Policy provides versioned deterministic controls:
- confidence thresholds
- ambiguity margins and actions (`proceed`, `pause`, `abstain`)
- tie-region epsilon and score quantization
- safety and risk constraints

### 3.7 Normative Layering Examples
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
The user query is the authoritative semantic input, but any downstream routing state derived from it MUST be normalized into provider-agnostic typed outputs before planning or execution decisions are made.

For retrieval-oriented intents:
- semantic ranking MUST still select the intent without regard to provider names, provider families, or domain-specific affordance labels.
- any post-ranking retrieval planning MUST operate only on typed retrieval requirements and typed feasibility constraints.
- implementations MUST NOT insert predeclared query archetypes, domain buckets, or query-class switchboards as an intermediate stand-in for semantic interpretation.
- reusable execution shapes MAY exist only when they are structural, cross-domain, and versioned ontology outputs inferred from the query (for example, a single-snapshot or document-briefing shape) rather than preassigned query families.

For connector-backed intents:
- semantic ranking MUST select the intent without regard to connector IDs, provider families, tool-name prefixes, or account labels.
- post-ranking provider selection MUST operate only on required primitive capabilities plus runtime-discovered provider candidates admitted by registered connector probes.
- connector additions MUST enter routing through registry metadata and discovery evidence, not through intent-matrix keyword patches or provider-specific winner rules.

### 5.2 Prohibited Patterns
Resolver logic MUST NOT:
- route by ad hoc keyword, substring tests, or lexicographic assertions.
- route by tool-name prefixes.
- route by prompt-only exceptions.
- route through predesignated query classes, archetypes, or domain buckets that directly choose providers, tools, or execution branches.
- short-circuit to a tool before intent winner selection.
- fallback to lower-ranked intents dynamically based on downstream execution failures.
- introduce domain-named or provider-named ontology symbols to avoid proper structural modeling.
- emit provider IDs, provider orderings, or provider-family hints directly from query interpretation.
- let provider availability or adapter presence alter semantic ranking scores.

### 5.3 Allowed Patterns
Resolver logic MAY:
- use aliases and exemplars for observability and analytics.
- include deterministic post-ranking feasibility filtering.
- produce typed structural retrieval requirements after intent selection, provided those outputs are provider-agnostic.
- use connector/provider registries that map tools to provider families and expose discovery-backed provider candidates, provided those registries are query-agnostic and versioned.

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
- structural retrieval affordance enforcement
- provider/domain symbol ban enforcement

Profile C: Replayability
- resolver receipt completeness
- deterministic replay from receipt material

Profile D: Retrieval Ontology Integrity
- typed retrieval requirements are provider-agnostic
- provider/domain names do not appear in ontology descriptors, affordance IDs, or ranking features
- adapter-specific details are isolated behind post-selection discovery evidence

## 10. Failure Taxonomy
Resolvers MUST emit machine-readable failures with stable `ERROR_CLASS`.

Required classes:
- `ERROR_CLASS=IntentUnclassified`
- `ERROR_CLASS=IntentInfeasible`
- `ERROR_CLASS=PolicyBlocked`
- `ERROR_CLASS=ResolverContractViolation`
- `ERROR_CLASS=OntologyViolation`

## 11. Migration Guidance
To migrate a heuristic resolver to Draft v0.6:
1. Extract routing fields into typed schema.
2. Separate semantic ranking from feasibility and policy checks.
3. Replace domain-specific capability bindings with primitive capability mappings.
4. Enforce deterministic selection and full cryptographic receipts.
5. Wire execution behavior strictly to CEC lifecycle gates (Zero Fallback).
6. Replace domain-named retrieval affordances with structural affordances only.
7. Remove provider/domain outputs from query interpretation and emit typed retrieval requirements instead.
8. Move provider-specific URL builders, parsers, and transport quirks behind adapter boundaries that are only reachable after typed discovery.
9. Add conformance tests that fail on provider/domain symbols appearing in ontology descriptors or ranking features.

## 12. Change Control and Versioning
CIRC changes MUST be versioned.
Breaking changes MUST include:
- migration notes (e.g., prohibition of heuristic execution retries)
- conformance-suite updates
- golden-corpus impact notes
- ontology delta summary (intents, capabilities, tools)
- structural-affordance delta summary and provider-symbol removals
