# Breaking the Lower Bound Epic

This document is the repo-native engineering epic for the next AFT moonshot:

- from: `99% Byzantine Tolerance` over an explicit public-state-continuity
  substrate
- to: a serious attempt to internalize that substrate and break through the
  classical lower-bound frontier using protocol-native primitives

It is intentionally written as a living engineering and theorem program, not
as marketing copy. The question it tackles is:

> Can AFT compile Public State Continuity into the protocol itself strongly
> enough that the uniqueness engine no longer depends on an externally assumed
> bulletin/recoverability substrate?

If the answer is yes, the resulting theorem would be far stronger than the
current PSC theorem. If the answer is no, this epic should still end with a
useful separation or impossibility result that sharply identifies what cannot
be internalized inside the classical model.

## Objective

The current theorem surface is already strong:

- relay-free, coordinator-free, pure-software deterministic `99% Byzantine
  Tolerance`
- durable canonical outcomes and sealed-effect releases are gated by canonical
  collapse
- dominant negative objects kill conflicting positives

But the current theorem still depends on an explicit PSC substrate:

- public bulletin recoverability
- canonical bulletin close
- proof-carrying public extraction
- collapse-gated durability

The breakthrough target is stronger:

- derive the effective PSC substrate from ordinary protocol communication
  itself,
- make conflicting worlds induce short signed public contradictions,
- make close-or-abort total and inevitable from endogenous protocol traces,
- and either:
  - prove a lower-bound-breaking theorem in the classical model, or
  - isolate the exact primitive that prevents such a theorem.

## Current Baseline

The repository already provides the starting point for this epic:

- canonical bulletin close and canonical ordering abort objects
- canonical observer close-or-abort and sealed-effect gating
- collapse-gated durable state and irreversible effects
- recursive continuity on the hot path
- optional checkpoint-compression backend separation

This epic does **not** replace that work. It treats the current PSC system as
the baseline substrate we now try to internalize.

## North Star

The north-star theorem shape is:

- there exists at most one admissible global execution object for a closed
  slot boundary generated entirely from protocol-native communication,
- every conflicting fully specified candidate induces a short signed public
  contradiction witness,
- the protocol deterministically derives exactly one canonical positive object
  or one canonical abort object without any designated honest relay,
  coordinator, or externally assumed bulletin board.

This epic is complete only when we can honestly say one of the following:

1. we internalized PSC enough to substantively break beyond the classical
   dense-vote frontier, or
2. we produced a sharp impossibility / separation result showing which PSC
   primitive resists internalization.

## Non-Goals

This epic is **not** complete merely because we:

- compress the continuity witness again,
- add more optional succinct backends,
- restyle the paper language,
- or repackage the current PSC theorem with stronger rhetoric.

Those may support the work, but they are not the breakthrough.

## Core Conjecture

The only credible path to overturning the classical lower-bound regime is to
make PSC endogenous.

That means compiling the following into the protocol itself:

- signed publication traces
- self-extracting published objects
- deterministic canonical close from endogenous traces
- deterministic canonical abort from endogenous failure
- recursive legality of extension
- finite obstruction completeness over signed public traces

The key substitution is:

- from quorum-intersection uniqueness
- to signed-frontier and obstruction-based uniqueness

## Throughput Guardrails

This epic is only acceptable if it preserves AFT's architectural split between
throughput-critical dissemination and authority-critical verification.

The hard rule is:

- never make the hot path perform global reconstruction, heavy recursive proof
  generation, or dense all-to-all validation before proposal or commit

The hot path may grow only through compact, commodity-safe objects such as:

- signed publication heads
- monotone counters
- compact frontier commitments
- content-addressed references
- short contradiction witnesses
- constant-size or small logarithmic legality / close-or-abort carriers

The cold path or side path may do heavier work such as:

- reconstruction
- republishing
- contradiction extraction
- recursive compression
- checkpoint proving
- light-client or external-verifier support

### Hot-path constraints

Every new primitive introduced by this epic must satisfy all of the following
unless explicitly marked experimental:

- constant-size or small logarithmic representation on proposals and live
  progress messages
- no requirement that every commodity validator generate a heavy zk or PCD
  proof every slot
- no requirement that every validator reconstruct the full publication surface
  before extending a branch
- no dependence on an external prover job for liveness
- fail-closed behavior when a compact legality or contradiction object is
  missing or malformed

### Rejection criteria

Any design in this epic should be rejected or demoted to an optional lane if
it:

- inflates proposal admission with full-surface replay
- requires large witness trees on every live message
- forces dense cross-checking of complete publication state during ordinary
  progression
- moves heavy recursive proving onto all validators
- makes throughput or liveness hinge on specialized hardware

### Allowed architecture split

The intended shape is:

- Hot path:
  - publish
  - hash
  - sign compact frontier state
  - carry small legality / contradiction objects
  - fail closed on compact contradictions
- Cold path:
  - reconstruct
  - compress
  - prove
  - republish
  - audit
  - export portable checkpoints

If a proposed lower-bound-breaking step cannot be expressed inside that split,
it should be treated as a research detour rather than the mainline engineering
track.

## Workstreams

### Workstream A: Endogenous Publication Traces

Goal:

- build an append-only, signed, protocol-native publication trace from ordinary
  authenticated messages

Deliverables:

- signed log-head objects
- parent-log-head links
- monotone publication counters
- message-root / frontier commitments
- availability receipt structure

Theorem target:

- two conflicting publication frontiers for the same closed boundary induce a
  short signed contradiction

### Workstream B: Self-Extracting Publication

Goal:

- make every admitted published object reconstructable or objectively missing
  from ordinary protocol traces

Deliverables:

- content-addressed publication references
- reconstruction metadata on references
- republishing rules from any honest receipt
- missing-payload contradiction objects

Theorem target:

- one honest receipt is enough to force either reconstruction or canonical
  abort

### Workstream C: Endogenous Bulletin Close

Goal:

- derive canonical bulletin close from protocol-internal traces rather than an
  externally assumed bulletin surface

Deliverables:

- endogenous close compiler
- signed close frontier
- public derivation rules for admissible boundary formation
- contradiction objects for stale / equivocated / omitted close inputs

Theorem target:

- same trace prefix implies same closed admissible surface or same abort

### Workstream D: Frontier Uniqueness Instead of Quorum Intersection

Goal:

- define the validator authority object as a signed frontier certificate over
  publication, admissibility, collapse, and continuity, not as a dense vote
  bundle

Deliverables:

- signed frontier certificate type
- frontier incompatibility witness types
- frontier merge / extension rules
- invalid frontier rejection path

Theorem target:

- conflicting frontier certificates imply a finite contradiction basis

### Workstream E: Total Deterministic Abort

Goal:

- make abort inevitable, not just decisive

Deliverables:

- total close-or-abort derivation rules
- no “wait for someone else to publish the abort” gaps
- canonical negative object families for endogenous publication failure

Theorem target:

- every closed slot boundary yields exactly one canonical positive object or
  one canonical abort object

### Workstream F: Recursive Legality of Extension

Goal:

- make recursive continuity the legality predicate for extension, not just a
  durability witness

Deliverables:

- extension legality tied to recursively valid predecessor state
- contradiction witnesses for invalid recursive extension
- proposal and commit rules that reject any branch lacking recursively legal
  continuity

Theorem target:

- no branch is admissible unless it is the unique recursively legal extension

### Workstream G: Obstruction Completeness

Goal:

- prove a finite obstruction basis for invalid global execution candidates
  induced by endogenous traces

Deliverables:

- explicit obstruction families for:
  - publication equivocation
  - missing payload
  - stale or conflicting close
  - admissibility inconsistency
  - recursive continuity inconsistency
  - positive / abort incompatibility
  - sealed-effect binding mismatch
- one concrete fixture and one formal witness for each obstruction family

Theorem target:

- every invalid fully specified candidate contains one short public
  contradiction witness

### Workstream H: Formal Indistinguishability / Separation Attack

Goal:

- directly attack the classical lower-bound core by showing how endogenous PSC
  destroys the critical indistinguishability patterns, or else prove it cannot

Deliverables:

- explicit reduction attempts from endogenous PSC to classical BA
- explicit failure modes where internalization still imports a stronger
  primitive
- formal statements of what is and is not classical-model-internal

End-state:

- either a genuine lower-bound-breaking theorem,
- or a publishable impossibility / separation theorem

## Phase Plan

### Phase 0: Preserve the Baseline

- keep the current PSC theorem and runtime intact while this epic proceeds
- do not weaken existing collapse-gated durability or sealing safety

### Phase 1: Endogenous Publication Surface

- implement Workstreams A and B
- make ordinary protocol messages sufficient to build a signed publication
  trace

### Phase 2: Endogenous Close-or-Abort

- implement Workstreams C and E
- compile bulletin close and total abort from signed traces

### Phase 3: Signed Frontier Authority

- implement Workstream D
- move progress authority away from dense-vote intuition toward frontier
  legality

### Phase 4: Recursive Extension Legality

- implement Workstream F
- make recursively legal extension the normative live-branch predicate

### Phase 5: Finite Obstruction Basis

- implement Workstream G
- finish the contradiction taxonomy for invalid global candidates

### Phase 6: Formal Breakthrough Attempt

- implement Workstream H
- either discharge a lower-bound-breaking result or prove the remaining gap

### Phase 7: Paper / Claim Upgrade

- only after Phase 6 lands do we change the top-line theorem language

## Immediate Next Slice

Start Phase 1 for real:

- define protocol-native signed publication trace objects
- thread those trace heads through live consensus messages
- define the first contradiction objects for conflicting or stale publication
  frontiers
- extend the formal ordering model to include signed publication traces, not
  just a fixed recoverable bulletin surface

The immediate implementation focal points are:

- `crates/types/src/app/consensus.rs`
- `crates/consensus/src/aft/guardian_majority/mod.rs`
- `crates/services/src/guardian_registry/mod.rs`
- `formal/aft/canonical_ordering/CanonicalOrdering.tla`
- `docs/consensus/aft/specs/yellow_paper.tex`

## Progress Context Window

1. Baseline inherited: the repository already completed the PSC transition to
   relay-free, coordinator-free, pure-software deterministic `99% Byzantine
   Tolerance` over an explicit PSC substrate, with collapse-gated durable state
   and sealed effects.
2. Baseline inherited: `GuardianMajority` now acts as transport / tentative
   progress under canonical-collapse-gated durability, so this epic starts from
   a runtime that already rejects dense positive quorum intersection as the
   sole source of durable truth.
3. Baseline inherited: ordering and sealing each already resolve to canonical
   close-or-abort objects, and late negative evidence rewrites prior positive
   artifacts instead of merely penalizing them.
4. Baseline inherited: hot-path recursive continuity already exists and is
   mechanically checked, with optional proof-compression backends separated from
   theorem-critical hot-path safety.
5. Strategic reframing landed: the new moonshot is no longer “finish PSC,” but
   “internalize PSC enough to either break the lower-bound frontier or isolate
   the exact primitive that resists internalization.”
6. Design principle locked: no new work should depend on trusted relays,
   coordinators, TEEs, or heavy per-slot zk proving by commodity validators.
7. Design principle locked: this epic succeeds only through endogenous
   publication traces, deterministic close-or-abort, frontier uniqueness, and
   obstruction completeness, not by rhetorical strengthening alone.
8. Immediate next target identified: define signed publication-trace objects and
   contradiction witnesses in the shared consensus types and thread them into
   the live AFT proposal path.

## Claim Discipline

Until this epic is complete, the repository should continue to say:

- `relay-free, coordinator-free, pure-software deterministic 99% Byzantine
  Tolerance`
- `over the explicit public-state-continuity substrate`

It should **not** say:

- `unconditional classical 99% Byzantine agreement`
- `no assumptions`
- `99.9% Byzantine tolerance`

unless and until this epic actually discharges the stronger theorem.
