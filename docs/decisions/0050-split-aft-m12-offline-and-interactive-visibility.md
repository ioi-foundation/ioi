# ADR 0050: Split AFT M12 Offline and Interactive Visibility

Status: Accepted

Date: 2026-09-03

## Context

M11 deliberately specified a portable authorization whose acceptance is the
deterministic byte predicate `Verify(root, instance, proof)`. M12 then proved
that, with copyable participant state and an unknown sole correct member, such
an offline predicate cannot provide both solo non-`Abort` effect progress and
transferable non-conflict at `f = n - 1`. The exact R3 lower-bound candidate
was independently retested by the owner-authorized, context-isolated Daybreak
reviewer and upheld within that model.

The lower bound remains valid. It does not quantify over a verifier that
contacts the configured members while deciding. Query-Unanimity Verification
(QUV) is a candidate in that separate class: each executor pushes its candidate
to every configured member, and a known end-to-end timing bound ensures that a
fresh response from at least one correct member is present before acceptance.
The correct member durably records the candidate before replying, so concurrent
conflicting attempts intersect in its monotone conflict state.

The program's stop rule permits work to resume after an explicit owner decision
changing a task property. The owner has authorized changing the verifier model
and timing premise for an alternate track. This does not falsify the byte-only
theorem or satisfy the original portable-receipt target.

The supplied R3 Python and JSON artifacts were not byte-reproducible: the
supplied source reduced the `volatile` row's schedule space, while the supplied
JSON contained results from the unreduced run. The repository therefore carries
a corrected source and only results regenerated from that source. Hand-carried
counts are not gate evidence.

## Decision

### 1. Preserve the original result as M12a

M12a is `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`:

> No finite, portable, byte-only offline authorization derived from copyable
> participant state can simultaneously provide solo non-`Abort` effect
> liveness and transferable non-conflict at `f = n - 1`.

The prior R3 report is `UPHELD_WITHIN_SCOPE`. Any earlier prose that generalized
the result to every participant-only pure-software protocol is superseded by
this ADR. The theorem itself and its immutable review evidence are retained.

### 2. Create M12b and M13Q as a separate interactive track

M12b evaluates participant-interactive visibility. Its candidate is
`aft_quv_v0`, specified in
`internal-docs/architecture/protocols/aft/specs/query_unanimity_verification.md`.
The local disposition is `PASS_CONSTRUCTION_CANDIDATE`; it is not an admitted
theorem, consensus profile, receipt, or production authorization. M13Q may
attempt the arbitrary-`n` theorem only after an immutable-candidate independent
review accepts M12b's construction and exact assumptions.

Two premise changes are explicit:

1. Acceptance becomes
   `VerifyOnline(root, candidate, membership, delta_rt)`, not a function of
   portable proof bytes alone.
2. Known synchrony is safety-critical and covers verifier-to-member request
   delivery, admission and queueing, atomic durable processing, member-to-
   verifier response delivery, and local-clock error for at least one correct
   configured member.

QUV also requires durable monotone conflict state, no rollback, every relying
executor to perform the interaction immediately before externalization, and
the state to remain reachable for the conflict domain's authority lifetime.
These are theorem assumptions, not implementation details.

### 3. Keep finality modes separate

Future assurance schemas must distinguish at least:

- `offline_bytes` from `online_query_unanimity` finality;
- asynchronous, eventual-synchronous, and known-synchronous timing;
- portable final receipts from non-portable online decisions; and
- owner-authorized, unowned-first-winner, quorum, unclonable-authority, and
  executor-scoped conflict-domain authority.

The existing `GuaranteeVectorV1` is not changed by this ADR. A later versioned
schema change must preserve coordinate-wise meet semantics. QUV evidence may
never raise a portable-finality coordinate and must state
`portable_final_receipt = false`.

### 4. Preserve the ADR 0048 profile boundary

QUV is a separately named, known-synchronous research profile. It is never a
timeout fallback or downgrade from the asynchronous PQ v1 profile. Its deadline
is part of its own safety model; missing the bound means no QUV assurance may be
claimed.

### 5. Do not reuse the original completion gates

Original M13-M18 remain blocked for the M11 byte-portable target. Parallel
M13Q-M18Q gates may proceed only for the online profile and must retain the
non-portability and known-synchrony coordinates through ordering, durable state,
effects, implementation, qualification, review, and public wording.

No public consensus headline follows from this ADR. In particular, local
bounded checks of a per-slot authorization mechanism do not yet establish
Byzantine consensus, canonical ordering, reconfiguration, recovery, or
end-to-end irreversible-effect semantics.

## Consequences

This decision opens a participant-only, pure-software route around the offline
role-switch obstruction without introducing an external selector. It pays for
that route with an online verifier and a known round-trip bound that is part of
safety, not merely liveness.

The candidate can provide no portable final receipt. A later party cannot infer
from a finite transcript that it contains the unknown correct member's reply:
requiring fewer than all members reintroduces role switching, requiring all
members permits permanent withholding, and trusting the original executor or a
delivery attestation adds a notary or publication authority.

For an honest owner, no valid conflict can be forged and an accepted value can
be queried again while the configuration and retained state remain live. For an
equivocating owner, the domain can freeze with transferable signed equivocation
evidence; historical execution audit depends on the executor's durable record.
For unowned slots, a valid competing submission can veto progress. None of
those outcomes may be described as universal transaction fairness.
