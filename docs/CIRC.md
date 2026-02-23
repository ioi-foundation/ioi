# Capability-Intent Resolution Contract (CIRC)

Status: Draft v0.2
Owners: Agentic Platform
Scope: Intent resolution and tool routing for desktop agent execution

## 1. Purpose
CIRC defines a clean-ontology contract for intent resolution that scales with capability growth without devolving into alias tables, keyword patches, or prompt-only topology hacks.

Primary goals:
- Keep routing semantics stable under query paraphrase.
- Keep behavior explainable and auditable.
- Keep growth additive via schema/data, not resolver code churn.

Non-goals:
- Replacing policy or safety gates.
- Replacing retrieval/citation ranking logic outside intent resolution.

## 2. Normative Terms
The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in RFC 2119.

## 3. Core Model
### 3.1 Intent
An Intent is a canonical semantic action class:
- `intent_id` (stable identifier)
- `scope` (ontology surface class)
- `semantic_descriptor` (authoritative routing text)
- `required_capabilities` (set)
- `preferred_tier`
- `risk_class`

### 3.2 Capability
A Capability is a stable semantic unit independent of concrete tool names (for example `web.retrieve`, `sys.exec`, `ui.interact`).

### 3.3 Tool
A Tool is an executable operation that provides one or more capabilities:
- `tool_id`
- `provides_capabilities`
- optional policy constraints

### 3.4 Policy
Policy provides versioned parameters and rules:
- confidence thresholds
- ambiguity margin and ambiguity actions (proceed, pause, abstain)
- safety/risk constraints
- score precision, rounding mode, and tie-region parameters
- embedding/runtime commitments

## 4. Resolution Contract
For query `q`, active intent set `I`, and active tool set `T`, the resolver MUST perform three distinct phases.

### 4.1 Semantic Ranking Phase (Only)
Semantic ranking MUST depend only on:
- query text (plus canonical normalization defined by policy)
- canonical intent semantic descriptors
- embedding model output
- similarity function

Normative scoring shape:
- `raw_score(i) = sim(embed(q), embed(descriptor(i)))`

`scope`, `risk_class`, `preferred_tier`, aliases, and exemplars MUST NOT alter semantic ranking scores.

### 4.2 Hard Constraint Phase
Feasibility MUST be evaluated separately from semantic ranking:
- `feasible(i)` iff required capabilities are satisfiable by `T`
- and policy constraints do not prohibit execution in current environment/tier/risk context

If top-ranked intent is infeasible, selection MUST proceed to next feasible ranked intent before abstention.

### 4.3 Deterministic Selection Phase
After ranking and feasibility:
- scores MUST be quantized at policy-defined precision
- ties MUST be evaluated using policy-defined tie region (`abs(s1 - s2) < tie_eps`)
- deterministic tie-break MUST be applied inside tie region using only versioned deterministic inputs (for example `intent_id`, `scope`, policy version)

### 4.4 Ambiguity Rules
Policy MAY define ambiguity margin:
- abstain/pause if `(score1 - score2) < ambiguity_margin`
- even when `score1` is above acceptance threshold

This margin MUST be explicit, versioned, and receipted.

### 4.5 Abstention
Low-confidence or ambiguous unresolved behavior MUST be explicit and deterministic:
- emit `resolver.unclassified` or policy-defined pause
- never select arbitrary lexicographic fallback winner when abstention condition is met

Resolver outputs MUST include:
- chosen `intent_id`
- `scope`
- quantized `score`
- confidence band
- top-k candidates
- matrix/policy version commitments
- deterministic receipt hash

## 5. Clean Ontology Requirements
### 5.1 Authoritative Inputs
Semantic ranking MUST depend only on canonical semantic inputs defined in Section 4.1.
Constraint gating MAY depend on capabilities and policy constraints defined in Section 4.2.

### 5.2 Metadata-Only Fields
Aliases, exemplars, slang labels, and examples:
- MAY exist for analytics and observability.
- MUST NOT be authoritative inputs to semantic ranking or winner selection.

### 5.3 Normalization Layer (Allowed Escape Hatch)
A separate normalization layer MAY annotate input text for analytics and UX.
If present, it MUST:
- be reversible and non-destructive to original query text
- be explicitly versioned
- be receipted
- be non-authoritative for semantic ranking

### 5.4 Prohibited Patterns (Resolver Path)
Resolver logic MUST NOT:
- route by ad-hoc keyword or substring tests (for example `"weather"` -> web intent)
- route by tool-name prefixes as substitute for ontology semantics
- use unversioned magic constants that alter winner choice
- use prompt-only exceptions as canonical topology behavior

## 6. Determinism and Replayability
### 6.1 Embedding Runtime Commitments
Resolver receipts MUST commit to:
- `embedding_model_id`
- `embedding_model_version` (or model hash)
- query normalization version/details
- similarity function identifier

Embedding model upgrades MUST follow an explicit upgrade protocol:
- policy/version bump
- release note with expected behavioral impact
- receipt snapshot refresh for conformance corpus

### 6.2 Numeric Determinism Contract
Policy MUST define:
- score quantization precision (for example `1e-4`)
- rounding mode
- tie region epsilon

Implementations MUST apply the same numeric contract in runtime and tests.

### 6.3 Receipt Completeness
Receipts MUST include sufficient commitments to replay selection:
- query hash
- policy/matrix version
- full `intent_set_hash`
- `tool_registry_hash`
- `capability_ontology_hash`
- ranked candidates with quantized scores
- final selection and confidence band

`ontology_source_hash` is acceptable only if it cryptographically commits to intents, capability ontology, and tool-capability mapping.

## 7. Capability Growth Contract
When adding a new tool:
- add or validate `provides_capabilities`
- do not patch resolver winner logic for that tool

When adding a new intent:
- add canonical descriptor, required capabilities, scope, and policy metadata
- add tests for paraphrase stability and ambiguity behavior

When adding a new capability:
- update capability ontology and tool mappings
- add conformance tests

Normal growth SHOULD be data/schema changes; resolver code changes SHOULD be rare and architectural.

### 7.1 Growth Monotonicity (Precise)
For fixed intent set and policy version:
- adding tools that do not change feasibility of existing intents MUST NOT change winners for the golden query corpus

If feasibility changes, winner changes are allowed but MUST be documented in release notes and visible in diffable receipts.

## 8. Intent Granularity and Collision Control
Intent descriptors MUST be mutually discriminative.

Implementations SHOULD run ontology collision lint:
- compute descriptor-space distances between intents
- flag pairs below policy-defined minimum distance as ontology smell
- require merge, split, or descriptor rewrite before release

## 9. Conformance Test Suite (Minimum)
An implementation is CIRC-conformant only if all pass:

1. Paraphrase invariance:
- semantically equivalent phrasings map to the same intent in stable environments

2. Metadata independence:
- changing aliases and exemplars does not change winner selection

3. Capability and policy feasibility:
- intents violating capability or policy constraints are not selected as final winner

4. Abstain correctness:
- unresolved low-confidence or ambiguous inputs emit `resolver.unclassified` (or policy pause), not arbitrary fallback

5. Deterministic receipts:
- identical input and policy produce identical receipt commitments

6. Growth monotonicity:
- unrelated tool additions do not regress winners for golden corpus

7. Embedding upgrade discipline:
- model version change without policy/version bump fails conformance

8. Descriptor collision lint:
- ontology fails conformance if minimum discriminative distance rule is violated

## 10. Migration Guidance
To migrate a heuristic resolver to CIRC:

1. extract current routing fields into typed schema
2. mark aliases and exemplars metadata-only
3. separate semantic ranking from feasibility and tie-break
4. implement capability plus policy feasibility gates
5. implement explicit abstain and ambiguity margin path
6. add deterministic numeric contract and receipts
7. add conformance tests and CI gates
8. remove obsolete keyword and prefix patches

## 11. CI Enforcement Recommendations
CI SHOULD include:
- static checks blocking prohibited resolver patterns
- required conformance test targets
- policy version bump requirement when routing semantics change
- receipt snapshot tests for deterministic critical paths
- embedding runtime commitment checks
- ontology collision lint

## 12. Versioning
CIRC changes MUST be versioned.

Breaking semantic changes MUST include:
- migration note
- conformance updates
- policy/schema compatibility guidance
- receipt and golden corpus update notes
