# Capability-Intent Resolution Contract (CIRC)

Status: Draft v0.3
Owners: Agentic Platform
Scope: Intent resolution and capability ontology for desktop agent execution

## 1. Purpose
CIRC defines a clean-ontology contract for intent resolution that scales without devolving into alias tables, keyword patches, or infinite capability bloat.

Primary goals:
- Keep routing semantics stable under query paraphrase.
- Keep behavior explainable and auditable.
- Prevent the "Infinite Capabilities" anti-pattern by strictly decoupling domain semantic intents from systemic execution primitives.

## 2. Normative Terms
The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in RFC 2119.

## 3. Core Model
### 3.1 Intent
An Intent is a canonical semantic action class mapping a user goal to required execution primitives:
- `intent_id` (stable identifier, e.g., `time.timer.create`)
- `scope` (ontology surface class)
- `semantic_descriptor` (authoritative routing text)
- `required_capabilities` (set of primitives, e.g., `[sys.exec]`)
- `preferred_tier`
- `risk_class`

### 3.2 Capability (The Primitive Rule)
A Capability is a foundational system primitive (e.g., `sys.exec`, `fs.read`, `ui.interact`, `sys.env_read`). 
- Capabilities MUST NOT be defined as domain-specific operations (e.g., `sys.clock.timer.set`, `sys.bluetooth.toggle`). 
- Domain-specific resolution belongs in the Semantic Intent. Execution of that intent MUST be dynamically synthesized using system primitives via the CEC.

### 3.3 Tool
A Tool is an executable operation that provides one or more capabilities:
- `tool_id`
- `provides_capabilities` (e.g., `LocalShell` provides `sys.exec`)
- optional policy constraints

### 3.4 Policy
Policy provides versioned parameters and rules:
- confidence thresholds
- ambiguity margin and ambiguity actions (proceed, pause, abstain)
- safety/risk constraints

## 4. Resolution Contract
For query `q`, active intent set `I`, and active tool set `T`, the resolver MUST perform three distinct phases.

### 4.1 Semantic Ranking Phase (Only)
Semantic ranking MUST depend only on:
- query text
- canonical intent semantic descriptors
- embedding model output
- similarity function

`scope`, `risk_class`, aliases, and exemplars MUST NOT alter semantic ranking scores.

### 4.2 Hard Constraint Phase
Feasibility MUST be evaluated separately from semantic ranking:
- `feasible(i)` iff required *primitive capabilities* are satisfiable by `T` (e.g., does the agent have `sys.exec` permission in this environment?)
- and policy constraints do not prohibit execution

If top-ranked intent is infeasible, selection MUST proceed to next feasible ranked intent before abstention.

### 4.3 Deterministic Selection Phase
After ranking and feasibility:
- scores MUST be quantized at policy-defined precision
- ties MUST be evaluated using policy-defined tie region
- deterministic tie-break MUST be applied using only versioned deterministic inputs

### 4.4 Ambiguity & Abstention
Policy MAY define explicit, versioned ambiguity margins. Low-confidence unresolved behavior MUST emit `resolver.unclassified` or a policy-defined pause. Resolver outputs MUST include standard commitments (intent_id, quantized score, deterministic receipt hash).

## 5. Clean Ontology Requirements
### 5.1 Authoritative Inputs
Semantic ranking MUST depend only on canonical semantic inputs defined in Section 4.1.

### 5.2 Prohibited Patterns (Resolver Path)
Resolver logic MUST NOT:
- route by ad-hoc keyword or substring tests
- route by tool-name prefixes
- use prompt-only exceptions as canonical topology behavior

## 6. Determinism and Replayability
Resolver receipts MUST commit to embedding model parameters, query normalization details, similarity functions, and full ontology hashes to ensure exact replayability of the resolution decision. 

## 7. Capability Growth Contract
When adding a new tool:
- validate `provides_capabilities` (ensure it maps to primitive standards)
- do not patch resolver winner logic for that tool

When adding a new intent:
- add canonical descriptor and map it to existing system primitives (`required_capabilities`)

### 7.1 Capability Monotonicity Guardrail
To prevent ontology bloat, developers MUST NOT add a new Capability to the system if the target action can be dynamically achieved via `sys.exec` (or similar primitives) combined with LLM inference. Capability additions SHOULD be restricted to fundamentally new security/permission boundaries (e.g., introducing a new hardware peripheral bridge).

### 7.2 Growth Monotonicity (Precise)
Adding tools that do not change feasibility of existing intents MUST NOT change winners for the golden query corpus.

## 8. Intent Granularity and Collision Control
Intent descriptors MUST be mutually discriminative. Implementations SHOULD run ontology collision lint to flag pairs below policy-defined minimum distances.

## 9. Conformance Test Suite (Minimum)
An implementation is CIRC-conformant only if it passes tests for paraphrase invariance, metadata independence, primitive feasibility, deterministic receipts, growth monotonicity, embedding upgrade discipline, and descriptor collision linting.

## 10. Migration Guidance
To migrate a heuristic resolver to Draft v0.3:
1. extract current routing fields into typed schema
2. delete domain-specific capability bindings (e.g., `timer_tool`) and replace them with mapping to `sys.exec`
3. separate semantic ranking from feasibility
4. enforce inference-driven execution via CEC

## 11. Versioning
CIRC changes MUST be versioned. Breaking semantic changes MUST include migration notes, conformance updates, and golden corpus update notes.