# Canon Maximal-Ceiling Pass — 2026-07-25

Status: evidence artifact (pass record). Never authority; the owner docs and
ADRs changed by this pass are the authority.
Branch: `arch/maximal-ceiling-pass` (isolated; not pushed), based on
`9670a1d4a` (`integrate/canon-reconciliation` head at pass time).
Decision records: ADR 0019, ADR 0020, ADR 0021.

## 1. Thesis memo — what the architecture is now betting on

**The bet, before this pass:** IOI wins the "internet of intelligence"
category by specifying a complete bounded-autonomous-institution stack —
substrate, authority, truth, interop, settlement — ahead of building it, with
honesty discipline (target vs built) as the license for that breadth.

**What this pass changed about the bet:** breadth was never the weak flank;
the weak flank was that the boldest claims sat on contracts that could not
carry them, in exactly four places:

1. **The product boundary had a one-way contract.** The canon could prove
   ioi.ai never *takes* authority from Hypervisor, but had no object for work
   *entering* an admitted GoalRun from an existing context — so the whole
   product/substrate boundary thesis was enforceable in only one direction,
   and a correlation id could have quietly become admission.
   `GoalRunActivation` (ADR 0019) closes that: one typed, receipted,
   idempotent crossing for every source lane — ioi.ai drafts, Sessions,
   WorkRuns, work items, room claims, automation steps, and gateway adapter
   contexts — with the daemon as the only admitter.
2. **The flagship admission contract was two half-contracts.** Canon required
   a resolution closure code never checked; code required scope/session/state
   root canon never defined; and the running "enforcement" validated constants
   the route itself wrote. The unified admission contract plus **INV-37**
   (admission evidence is resolved, never asserted) makes the general failure
   class — route-laundered preconditions — a named, testable defect
   (ADR 0020).
3. **The proofs were unordered.** Sovereign-local completeness is now the
   selected first proof, because every other flagship proof presupposes it and
   because it converts the canon's most-repeated honesty caveat into evidence
   (ADR 0021). The Authority Gateway wedge is sequenced into Horizon 0 instead
   of floating beside the plan.
4. **Category ownership was asserted, not audited.** The adoption calculus in
   `web4-and-ioi-stack.md` now states, per property, which contract carries it
   and which gap undermines it — including the two the canon had not said out
   loud: the unresolved BBSL-vs-open-surface license question, and the absence
   of an outsider-runnable conformance suite.

**Why the new version is more likely to win:** a hostile reader's four best
attacks — "your product boundary is enforced by vibes," "your flagship
admission checks its own inputs," "your proofs are a wish list," "your
openness is marketing" — now each land on a contract, a named invariant, a
sequenced proof, or an explicitly registered gap with an owner. The claims did
not get smaller; they got dischargeable. And an implementer can start
load-bearing work sooner: the admission contract, the crossing object, the
attach-lane object family, and the first-proof selection are all specified to
the point of refusal semantics, with conformance cases (GRA-1..9) written
before any code exists.

## 2. Change ledger

### Semantic changes (change what the architecture *is*)

| # | Change | Class | Where |
| --- | --- | --- | --- |
| S1 | `GoalRunActivationEnvelope`: the product-crossing admission object; correlation-is-not-admission made normative; resolves the registered crossing gap | `new_architectural_requirement` | `foundations/objects/goal-pursuit.md`, ADR 0019 |
| S2 | INV-37 — admission evidence is resolved, never asserted; route-supplied constants void an admission | `new_architectural_requirement` | `foundations/invariants.md`, ADR 0020 |
| S3 | Unified GoalRun admission contract written into its named owner (which previously stated none); joins the canon half (resolution closure) and code half (scope/session/state root/receipts/bounds) | `semantic_correction` + `contract_normalization` | `components/daemon-runtime/doctrine.md` |
| S4 | `GoalRunEnvelope` gains retained admission bindings: `activation_ref`, `source_context_binding`, `admitted_state_root_ref`, `authority_scope_refs`, typed `receipt_obligations`; rules bind each to INV-8/12/37 | `contract_normalization` | `foundations/objects/goal-run-execution.md` |
| S5 | `ReceiptObligation` shared element type; boolean/untyped receipt obligations declared undischargeable | `contract_normalization` | `foundations/objects/evidence-and-delivery.md` |
| S6 | Attach-lane contract: `ActionRequestEnvelope` and `AuthorityGatewayProfile` named and owned; gateway receipt registration required before receipted-mediation claims; graduation contract (adapter admission + activation crossing + no implicit carry-over) | `new_architectural_requirement` | `components/daemon-runtime/doctrine.md`, `_meta/vocabulary.md` |
| S7 | First-proof ruling: sovereign-local completeness selected; attach lane sequenced into Horizon 0; H0 gains attach-lane and admission-contract bullets | `semantic_correction` (sequencing) | `_meta/execution-horizons.md`, ADR 0021 |
| S8 | ioi.ai product lane: reverse-crossing rule (draft/submit yes, admit never) | `semantic_correction` | `domains/ioi-ai/control-plane.md`, `collaborative-outcome-pattern.md` |

### Structural changes (make the same architecture sharper or cheaper to adopt)

| # | Change | Class | Where |
| --- | --- | --- | --- |
| T1 | Conformance state vocabulary (`active_invariant`…`named_target`…), distinguishing provable-but-unproven from not-yet-provable | `contract_normalization` | `docs/conformance/README.md` |
| T2 | Claim coverage index: every major canon claim mapped to an existing or named target; nine previously uncovered claims now have named targets | `contract_normalization` | `docs/conformance/README.md` |
| T3 | New conformance target: GoalRun admission + activation (GRA-1..GRA-9) | `contract_normalization` | `docs/conformance/hypervisor-core/goal-run-admission-and-activation.md` |
| T4 | Adoption calculus: five category-ownership properties audited contract-by-contract; license and runnable-suite flanks stated openly | `editorial_clarification` + gap registration | `foundations/web4-and-ioi-stack.md` |
| T5 | Term boundaries: `GoalRunActivation` row; qualified-`Handoff` row disambiguating the three handoff families | `canonical_rename` prevention / `editorial_clarification` | `foundations/term-boundaries.md` |
| T6 | Vocabulary: `GoalRunActivation`, `ActionRequestEnvelope`, `AuthorityGatewayProfile`, and the previously missing `prim:*`/`scope:*` entries (closing a registered vocabulary gap against ADR 0006/INV-4) | `editorial_clarification` | `_meta/vocabulary.md` |
| T7 | Canon-to-code delta rows: activation object, admission bindings (with the exact code-side defects as current anchors), attach-lane family | `editorial_clarification` | `_meta/canon-to-code-delta.md` |
| T8 | ADRs 0019–0021 + index | `decision-history` | `docs/decisions/` |

Nothing was deleted, renamed on the wire, descoped, or moved between owners.
Every change is additive; retained wire identifiers are untouched.

## 3. Decision ledger

Full records are ADRs 0019–0021; this ledger is the audit summary. Each was a
choice that would otherwise have been escalated.

| Ruling | Conflict | Chosen | Confidence | Reversal |
| --- | --- | --- | --- | --- |
| Crossing object exists and is substrate-owned | product-owned (gap register named `control-plane.md` first) vs substrate-owned vs widen the automation contract | substrate-owned in `objects/goal-pursuit.md`; products draft, daemon admits; automation contract keeps its owner and admits through the family | working_ruling | move the envelope section, repoint six referencing docs; the correlation rule must survive any reversal (ADR 0019) |
| Name avoids "Handoff" | reuse handoff grammar vs new activation grammar | `GoalRunActivation`; term-boundaries row fixes qualified-handoff usage | working_ruling | rename before first schema registration (ADR 0019) |
| Admission thinness is a canon defect, not just a code bug | fix Rust only vs state the missing rule | unified contract + INV-37; envelope fields added | settled (rule); working_ruling (field names) | narrow INV-37's wording rather than delete; fields free to rename until registered (ADR 0020) |
| First proof | network-first vs distribution-first vs local-first | sovereign-local completeness first; SLC → H2A → H2B → H3 | working_ruling | edit the ruling section + ADR status; order only, no contract depends on it (ADR 0021) |
| Attach lane not gated behind the first proof | wedge waits vs wedge sequenced in H0 | H0 contract work; reconciles ADR 0008 with the horizon owner | working_ruling | remove the H0 bullets (ADR 0021) |

## 4. Newly surfaced gaps and contradictions (each with a named owner)

1. **Licensing ADR required and absent.** `LICENSE-BBSL` on kernel/runtime vs
   the doctrine that the load-bearing open surface be permissively
   implementable; both ADR 0015 and the flywheel doc demand a dedicated
   licensing ADR; none exists. Owner: a dedicated licensing ADR with legal
   review (`docs/decisions/`); surfaced in the adoption calculus. This is the
   single most load-bearing adopt-vs-fork input. **Contested by construction**
   — it cannot be closed by documentation.
2. **No gateway receipt types are registered** while daemon invariant prose
   and the api sketch demand receipted mediation. Owner:
   `components/daemon-runtime/events-receipts-delivery-bundles.md`.
3. **Cancellation-completion receipts are unregistered**: daemon invariant 12
   requires child-owner cancellation receipts; the receipt registry defines no
   cancellation receipt family. Owner:
   `components/daemon-runtime/events-receipts-delivery-bundles.md`.
4. **The versioned legal-edge table for work lifecycles is normative but has
   no ref, schema, or location** (`work-results-and-lifecycle.md` declares it
   decisive and never says where it lives). Owner:
   `foundations/objects/work-results-and-lifecycle.md`.
5. **`ApprovalCeremonyContextEnvelope` is required-by-ref but unregistered**:
   `StepUpChallengeEnvelope` and v3 grants require a ref to a contract that
   does not exist as a closed machine contract. Owner:
   `foundations/objects/authority-and-access.md` (it self-records the target;
   the required-ref inconsistency is the gap).
6. **GoalRunProfile resolution semantics are undefined**: ~22 bare
   requirement-ref arrays with no cardinality or conflict rules, while the
   resolution receipt claims to commit "all compatibility/policy decisions" —
   a resolution algorithm with no declared semantics cannot be replayed from
   its receipt. Owner: `foundations/objects/goal-pursuit.md`.
7. **Certification issuer separation is unowned**: nothing prevents the spec
   owner, network operator, certification issuer, and marketplace ranker from
   being one party; the assurance anti-patterns forbid assurance-as-ranking
   but not same-party ownership. Owner:
   `foundations/ecosystem-assurance-certification-liability.md`.
8. **Reference-implementation recognition is uncontracted**: "reference" is
   used per-subject with no rule for what makes a release the reference or
   how a third party proves parity. Owner:
   `foundations/web4-and-ioi-stack.md` with
   `foundations/economic-flywheel-and-pricing-boundaries.md`.
9. **Attach-lane exit was unstated** (what an adopter keeps on leaving);
   partially paid by the graduation contract naming adapter contracts as open
   surface; the full exit statement remains open. Owner:
   `components/daemon-runtime/doctrine.md`.
10. **ADR 0008 vs execution-horizons contradiction** (wedge asserted,
    unsequenced) — resolved by this pass (H0 bullets + ADR 0021), recorded
    here because contradictions must be recorded even when fixed.

## 5. Revised proof sequence

```text
1. Sovereign-local completeness            (selected FIRST proof — ADR 0021)
     embedded_single_operator_offline + undeniable-product profile 1
     on the bounded software-change OutcomeRoom institution
     unlocks: honest local-first/exit/adoption claims; largest target→evidenced flip
     costs:  build steps 1–9, the SLC runner + isolated-egress harness
2. Horizon 2A — continuity across two failure domains
     same machinery + one node; fenced promotion, replay, no dual effects
3. Horizon 2B — useful same-system distributed work
4. Horizon 3 — two sovereign DASs over AIIP
     the minimum credible Internet-of-Intelligence proof; inherits two
     already-proven sovereign endpoints
parallel, not gated: Horizon 0 attach-lane contracts (ActionRequestEnvelope,
gateway receipts, AuthorityGatewayProfile, graduation) — the commercial wedge
does not wait on the flagship
```

## 6. Verification results (literal)

Run in the isolated worktree on `arch/maximal-ceiling-pass` with all pass
changes applied:

| Command | Result |
| --- | --- |
| `npm run check:architecture-docs` | pass — "Architecture documentation check passed." exit 0 |
| `npm run check:conformance-docs` | pass — tests 7 / fail 0, exit 0 |
| `npm run check:architecture-contracts` | pass — 171 fixtures, ajv-2020-12, exit 0 |
| `npm run check:work-items` | pass — 7 records, exit 0 |
| `git diff --check -- docs/` | clean, exit 0 |
| `npm run check:pre-next-leg` | 60 subtests: 48 pass / **12 fail** — identical 48/12 on the clean base commit `9670a1d4a` in the same worktree (verified by stash/rerun), so the failures are inherited, not introduced. The 12 are program-state/review-lock/snapshot-attestation subtests (e.g. "discovery and the committed review lock are complete and explicitly reviewed", "snapshot checking does not auto-discover HOME checkpoints"), consistent with the isolated worktree lacking the gitignored `internal-docs/implementation/` program state that gate reads; the base history already carries a "disposition the inherited pre-next-leg failure" evidence commit. |

Not run (and why): full journey suites, cargo test, and runtime verifiers —
this pass changes only `docs/architecture/**`, `docs/conformance/**`,
`docs/decisions/**`, and this record; no runtime code, schema registration,
or generated projection changed. The M-sequencer program-state refresh is
deferred to the next sequencer leg per its own owner
(`canon-to-code-delta.md` deferral table).

## 7. Session note — concurrent-work collision (recorded for auditability)

During this pass another session committed runtime work in the same checkout;
its commits landed on this pass's branch (which had the checkout), briefly
swept five in-progress canon files into one of its commits, and was then
amended by that session to exclude them. Resolution: the integration branch
was fast-forwarded onto that session's final commits (`f1a51df44`,
`9670a1d4a` — both authored by it and intended for the integration branch),
the shared checkout was returned to `integrate/canon-reconciliation` with a
clean tree, and this pass moved to an isolated git worktree, rebasing nothing
and rewriting no history. This pass's branch is therefore based on
`9670a1d4a`; every change in this ledger is contained in the single pass
commit on top of it.
