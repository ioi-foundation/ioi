# R10 — Live-Tier Responsiveness Assessment and Asynchronous-Fallback Design

**Status: NAMED RESIDUAL (RES-R10) — assessment complete, fallback DESIGNED
AND NOT BUILT.** The frontier-completeness flagship (P4.4) does not print
while this residual stands: its closing condition is a sim-exercised
fallback — the live tier progressing under an asynchronous adversary
schedule at the engine's fault bound. The pairing-table row for T4a in
`common_boundary_theorems.md` remains **L-OPEN** and points here.

This document is the leg's filed artifact under the R10 gate's second arm
("the residual + design doc filed and the flagship claim gated on it").
It changes no engine code.

## 1. Assessment of `GuardianMajority` as built

Facts, from the code as of this filing (paths relative to
`crates/consensus/src/aft/guardian_majority/`):

1. **Happy-path progress is certificate-driven and tracks network speed.**
   The echo phase thresholds on quorum count (`qc_state.rs`,
   `handle_echo`), votes form QCs, and a valid proposal resets the view
   timer (`pacemaker.rs`, `observe_progress`). With an honest proposer
   and a responsive quorum, no step waits out a timeout: the steady-state
   path is optimistically responsive in the weak sense.

2. **View recovery is wall-clock–driven with a FLAT timeout.** View
   change triggers on `Pacemaker::check_timeout` against `base_timeout`
   (default 5s, `engine.rs::new`). The `backoff_factor` field exists but
   `timeout_for_view` returns the flat base — the exponential backoff is
   an admitted stub (its own comment: "A robust implementation tracks
   consecutive failures"). Post-GST recovery therefore depends on the
   fixed timeout exceeding actual network delay; there is no adaptation
   if it does not.

3. **View change requires a TimeoutCertificate** accumulated from
   >½-weight timeout votes at a (height, view) (`qc_state.rs`,
   `check_quorum`). There is no TC relay/synchronizer step: nodes that
   missed the TC formation converge only via later traffic or their own
   timers, so entry into a new view is not synchronized to one message
   delay post-GST.

4. **The engine is fully deterministic.** No randomness exists anywhere
   in the engine (the mirror seed is zeroed; nothing else draws entropy).
   By FLP, a deterministic protocol cannot guarantee termination under a
   full asynchronous adversary — so the asynchronous-fallback obligation
   is NOT closable by parameter tuning; it structurally requires a source
   of common randomness. This is the load-bearing finding.

5. **Safety is accountability-anchored, not intersection-anchored.** In
   `GuardianMajority`/`Asymptote` modes the quorum threshold is simple
   majority (`engine.rs::quorum_weight_threshold`), divergence is
   detected and proven from double-signed headers (`qc_state.rs`,
   `check_divergence`), and QCs with empty signature sets are accepted
   (the guardian certificate is the authority; `qc_state.rs::verify_qc`).
   `ClassicBft` mode uses 2/3. Any fallback design must compose with the
   accountability anchoring — importing a 2/3-intersection assumption
   silently would change the engine's safety story, not extend it.

**Conclusion.** Safety under asynchrony is retained (voting discipline,
divergence proofs, guardian certificates — none of it consults a clock).
Liveness under asynchrony is not: recovery is timeout-only, timeouts do
not adapt, view entry is unsynchronized, and determinism forecloses any
asynchronous progress guarantee. A Ditto/VABA-class fallback is an
engine-structure change — the leg's pre-named out-of-session-scope
condition — so this leg files the residual instead of a partial build.

## 2. Fallback design (for the closing leg)

Four increments, ordered so each lands independently and the cheap ones
de-risk the expensive one:

- **D1 — View synchronizer + adaptive backoff** (no new assumptions).
  Track consecutive failed views since last commit; scale
  `timeout_for_view` by the existing `backoff_factor`; RELAY formed TCs
  so every honest node enters the new view within one message delay of
  the first post-GST entrant. This alone repairs post-GST recovery time
  and is buildable today, engine-local.

- **D2 — Fallback trigger.** After k consecutive TC formations at one
  height without a commit, that height's ordering switches to the
  pessimistic path (Ditto-style optimistic/pessimistic split). The
  trigger consumes only records the engine already forms (TCs), so it
  adds no new message type.

- **D3 — The pessimistic path needs a common coin.** Options:
  (a) threshold-BLS coin — needs a DKG and a pairing assumption
  (pq: false; tension with C7's PQ-awareness);
  (b) VDF-derived coin from the R11 clock plane — slower per fallback
  round, but R11 lands a VDF anyway and stays PQ-aware;
  (c) committee hash-coin — weaker adversary model, cheapest.
  **Recommendation: defer the coin choice to rendezvous with R11**, and
  treat any coin primitive as an externally-vetted cryptographic choice
  (ADR 0033 licensing rider; rule-12 escalation before an unvetted
  primitive becomes load-bearing).

- **D4 — Safety composition rule.** The coin SCHEDULES, never
  authorizes: every fallback-path decision carries the same signed-header
  + guardian-certificate evidence surface as the optimistic path, so
  divergence anywhere remains provable by the existing machinery, and
  the accountability anchoring is preserved across both paths.

The two-tier boundary is untouched by all four: T4a's non-interference is
structural (spec §11.4 — the only ring→live edge is the release gate for
effects typed irreversible), and the fallback lives entirely inside the
live tier.

## 3. The residual, precisely

- **RES-R10**: the live tier has no demonstrated progress under an
  asynchronous adversary schedule. Closing condition: D1–D4 built and a
  sim drill green — live-tier progress under an asynchronous adversary
  at the engine's fault bound, with the fallback trigger mutation drill
  RED when the trigger is disabled (the leg's own mutation).
- Gated on it: the P4.4 frontier-completeness flagship (this document +
  the T4a pairing row are the gate's anchors). The interim conditional
  claim (whitepaper §5.3) does not require this residual closed.
- NOT claimed by this filing: any liveness bound for the engine under
  asynchrony; any change to the engine's current post-GST behavior.
