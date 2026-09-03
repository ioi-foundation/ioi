# R10 — Live-Tier Responsiveness Assessment and Asynchronous-Fallback Design

**Status: CLOSED (RES-R10, 2026-09-03) — D1–D4 are implemented and the
normative hash-only path passes the adverse simulation, mutation campaign,
exact `n=130` benchmark, production same-height race, cold restart, and native
PQ re-entry drill.** The closure is model-relative: static Byzantine
adversary, exact `n=3f+1`, reliable private authenticated channels, and
randomized asynchronous termination. It is not an adaptive-security or
latency claim. Evidence is retained in
`../evidence/m3-adversarial-release-gate-2026-09-03.md`.

This document began as the leg's filed residual. Its status annotations now
record the completed construction and the exact limits that continue to bind
the theorem surface.

## 1. Assessment of `GuardianMajority` as built

Facts, from the code as of this filing (paths relative to
`crates/consensus/src/aft/guardian_majority/`):

1. **Happy-path progress is certificate-driven and tracks network speed.**
   The echo phase thresholds on quorum count (`qc_state.rs`,
   `handle_echo`), votes form QCs, and a valid proposal resets the view
   timer (`pacemaker.rs`, `observe_progress`). With an honest proposer
   and a responsive quorum, no step waits out a timeout: the steady-state
   path is optimistically responsive in the weak sense.

2. **View recovery remains wall-clock–driven but now adapts.** View change
   triggers on `Pacemaker::check_timeout`; capped geometric backoff tracks
   consecutive failed views and resets on authenticated progress.

3. **View change requires scoped timeout authority.** The normative ML-DSA
   Classic-BFT profile forms `AftTimeoutCertificateV1` from exactly q=2f+1
   distinct members. Every vote directly signs version, genesis network,
   configuration hash, epoch, height, view, and voter. It is relayed only over
   the strict PQ carrier, reverified against rooted membership, and adopted
   idempotently. Legacy `(height, view)` timeout evidence remains confined to
   separately labelled compatibility modes.

4. **The engine is fully deterministic.** No randomness exists anywhere
   in the engine (the mirror seed is zeroed; nothing else draws entropy).
   By FLP, a deterministic protocol cannot guarantee termination under a
   full asynchronous adversary — so the asynchronous-fallback obligation
   is NOT closable by parameter tuning; it structurally requires a source
   of common randomness. This is the load-bearing finding.

5. **The normative profile is intersection-anchored; compatibility profiles
   are not relabelled.** All-ML-DSA `ClassicBft` accepts only exact unit-weight
   n=3f+1 membership and q=2f+1 distinct rooted signatures. Empty and forged
   QCs are refused, and guardian non-equivocation is not a safety assumption.
   `GuardianMajority` and `Asymptote` keep their own named evidence semantics
   and cannot be exported as the normative PQ optimistic profile.

**Historical conclusion before the D3 implementation began.** Safety under asynchrony is retained (voting discipline,
divergence proofs, guardian certificates — none of it consults a clock).
Liveness under asynchrony is not: recovery still begins with timeouts, and
determinism forecloses any
asynchronous progress guarantee. A Ditto/VABA-class fallback is an
engine-structure change — the leg's pre-named out-of-session-scope
condition — so the original leg filed the residual instead of a partial build.
The current status is recorded below and in `../IMPLEMENTATION_LEDGER.md`.

## 2. Fallback design (for the closing leg)

Four increments, ordered so each lands independently and the cheap ones
de-risk the expensive one:

- **D1 — View synchronizer + adaptive backoff** (no new assumptions).
  Track consecutive failed views since last commit; scale
  `timeout_for_view` by the existing `backoff_factor`; RELAY formed TCs
  so every honest node enters the new view within one message delay of
  the first post-GST entrant. This alone repairs post-GST recovery time
  and is buildable today, engine-local. **STATUS: LANDED**: capped adaptive
  backoff, authenticated TC relay, one-time re-relay, and idempotent
  `adopt_relayed_view` are integrated through the runtime and strict PQ carrier.

- **D2 — Fallback trigger.** After k consecutive TC formations at one
  height without a commit, that height's ordering switches to the
  pessimistic path (Ditto-style optimistic/pessimistic split). The
  trigger consumes only records the engine already forms (TCs). **STATUS:
  TRANSITION BOUNDARY LANDED.** `FallbackStartCertificateV1` carries and
  re-verifies the complete view-1-through-view-3 TC chain, network,
  effective configuration and epoch, deterministic per-height instance id,
  authenticated high QC, lock QC, and locked root. The engine fsyncs the
  transition before adoption and restores it after restart. The timeout votes
  inside the trigger sign the complete scope directly, so a transport wrapper
  is not being mistaken for portable authority. D2 itself grants no
  asynchronous ordering authority; the separate D3 certificate does.

- **D3 — Build the complete setup-free hash-only asynchronous construction,
  not a coin substitution.** The normative target includes its authenticated
  channel abstraction, sharing, cover/gather, agreement/broadcast, index
  ABA/VABA, ACS, durable transcript, and ordering adapter. Its declared model
  is static Byzantine adversary, f<n/3, randomized asynchronous termination,
  and private authenticated channels; end-to-end PQ additionally requires the
  already named PQ-authenticated channel. It makes no adaptive-security claim
  and requires no private threshold setup or DKG. BLS/PVSS may remain only as
  a separately labelled `pq=false` optimization. A VDF remains advisory and
  enters neither the safety nor liveness theorem. The versioned Rust stack includes
  authenticated envelopes, Bracha RBC, reliable agreement, hash-only ASKS,
  gather/cover, index VABA, ACS, a lock-bound ordering adapter, exact-q rooted
  ML-DSA availability/ordering/executed-block evidence, encrypted append-only
  replay storage, strict-PQ carrier routing and per-height validator sessions.
  **STATUS: LANDED AND RELEASE-GATED FOR M3.** Canonical execution/admission,
  runtime receipts, same-height optimistic replacement, terminal compaction,
  cold restart, native PQ re-entry, production metrics and the exact `n=130`
  benchmark are complete.

- **D4 — Safety composition rule.** Randomness schedules and selects; it never
  authorizes. A fallback decision must propagate the highest authenticated
  QC/lock, emit a versioned PQ asynchronous ordering certificate, and be
  proven unable to conflict with an optimistic commit at the same height.
  Guardian evidence remains policy data and cannot raise this guarantee.
  **STATUS: LANDED.** The start certificate carries the authenticated
  high/lock state; a durable cross-path signing fence precedes authorization;
  fallback blocks later optimistic authority at the height; bounded
  same-height replacement cannot cross the Agentgres-admitted floor; the
  typed async-parent proof preserves rather than relabels authority. The
  bounded TLA+ composition model and production race drill are green.

The two-tier boundary is untouched by all four: T4a's non-interference is
structural (spec §11.4 — the only ring→live edge is the release gate for
effects typed irreversible), and the fallback lives entirely inside the
live tier.

## 3. Closure and surviving limits

- **RES-R10 is closed.** D1–D4 are built. The adverse simulation progresses
  with one silent Byzantine member, delay, reordering, first-transmission
  loss, duplication and malformed messages. The load-bearing lock and trigger
  mutants turn their focused tests red. The four-validator production drill
  forces the fallback after three certified views, replaces a real optimistic
  projection, admits one common executed block, cold-restarts and resumes
  native PQ finality.
- The positive result is randomized asynchronous progress only under the
  declared static-adversary, `f<n/3`, reliable-private-channel model. The
  optimistic path retains its separate post-GST behavior. Neither profile
  silently inherits the other's assumptions or latency.
- R10 no longer blocks the P4.4 ladder. T8 remains the open lower-bound row;
  responsive T5d is separately refuted and paired with L-S;
  closing R10 therefore does not by itself authorize the BLOCKED frontier-completeness
  claim or the integrated M8 headline.
