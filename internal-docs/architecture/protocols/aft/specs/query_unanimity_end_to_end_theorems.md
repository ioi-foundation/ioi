# QUV ordering, recovery, and consequence lift

Status: M14Q local theorem candidate; not production admission or portable
finality. M17Q independent review remains required.

Date: 2026-09-03.

## 1. Additional assumptions

The M13Q assumptions remain visible. The lift adds:

| ID | Assumption | Purpose |
|---|---|---|
| Q-EA1 | Every ordered candidate binds its rooted configuration, domain, slot number, exact predecessor candidate hash, authority mode, and payload/manifest hash | prevents cross-history substitution |
| Q-EA2 | A correct runtime appends only the unique M13Q-accepted candidate for its next slot and durably commits the candidate, predecessor, and new head before exposing it | prefix and restart safety |
| Q-EA3 | Correct recovery begins from that durable head, never truncates or rewrites it, and replays no effect mutation from chain state alone | crash safety |
| Q-EA4 | Every irreversible executor performs its own QUV operation against the active rooted membership immediately before entering T10's durable `Claimed` state | consequence authorization |
| Q-EA5 | `EffectManifestV1` derives one stable idempotency key from the rooted conflict domain and slot, not from the candidate payload, and commits the exact atomic-resource profile | same-conflict deduplication |
| Q-EA6 | The external resource and executor satisfy T10's atomic idempotency-register and claim-before-call assumptions | at-most-once physical mutation |
| Q-EA7 | Reconfiguration is a typed handoff candidate under the old root; before old-root expiry, every correct new member performs QUV against every old correct member within the old rooted bound and durably installs the accepted predecessor/state root before activating | live handoff continuity |
| Q-EA8 | A client joining after the old authority is no longer reachable receives the current root through an independently provisioned trust channel; historical bytes alone do not establish currentness | honest bootstrap boundary |

Q-EA7 is intentionally stronger than carrying a signed handoff transcript. A
transcript is bytes and cannot preserve QUV's online timing fact. If no correct
new member completes the live handoff before expiry, the new configuration does
not activate under this theorem.

## 2. Theorems

### Q-E1: prefix-compatible accepted ordering

**Assumes:** Q-T1, Q-EA1 through Q-EA3, a fixed conflict domain, and correct
runtime admission.

Any two correct durable histories are prefix compatible. At each common slot,
both histories contain an M13Q-accepted candidate; Q-T1 makes those candidates
equal. Q-EA1/Q-EA2 prevent gaps and bind every append to the exact prior head.
Induction over the shorter history proves prefix compatibility. A restarted
runtime resumes from the same durable prefix by Q-EA3.

Mechanized as `QHistoryPrefixCompatibility` in
`QueryUnanimityCompositionProof.tla`, parameterized over arbitrary history and
candidate sets.

### Q-E2: accepted-consequence non-conflict

**Assumes:** Q-T1/Q-T2, Q-EA1, Q-EA4, and exact manifest validation.

Two mutation candidates admitted for the same rooted domain/slot are equal.
Every mutation candidate comes from an executor's own online QUV acceptance;
Q-T1 excludes two different accepted candidates. The executor may record
`Abort`, ambiguity, or attributable owner equivocation, but those records do
not authorize another mutation candidate.

Mechanized as `QConsequenceCandidateNonConflict` in the composition proof.

### Q-E3: at-most-once physical externalization

**Assumes:** Q-E2 and Q-EA4 through Q-EA6.

The rooted conflict-domain slot causes at most one modeled external-resource
mutation. Q-E2 gives one candidate class; Q-EA5 gives every duplicate delivery
the same stable resource key; T10's atomic put-if-absent/CAS register admits one
record and its claim-before-call recovery machine never blindly reinvokes after
ambiguity. The result composes QUV authorization with T10—it does not infer
endpoint semantics from consensus.

### Q-E4: live reconfiguration continuity

**Assumes:** Q-T1 through Q-T4, Q-EA1 through Q-EA3, Q-EA7, and at least one
correct member in both rooted configurations.

No two correct new members activate conflicting handoff roots. Each new
correct member is an honest relying verifier of the old configuration; Q-EA7
places every old-correct snapshot in each operation, so Q-T1 permits at most
one accepted handoff candidate. Q-EA2 durably installs that same predecessor
before activation. With one valid handoff and no conflict, Q-T4 completes each
new-correct operation within the old bound. A conflict may fail closed and
prevent reconfiguration; it cannot create a second lineage.

This is live-overlap handoff, not portable long-range verification. Q-EA8 is
mandatory for later bootstrap.

## 3. Composition boundaries

- Online acceptance is not convertible into a portable final receipt.
- An old configuration must remain reachable through every correct new
  member's handoff operation; expiry cannot be inferred from silence.
- QUV supplies accepted-value non-conflict, not global payload availability.
  Q-EA7 therefore requires the complete state/predecessor payload be installed
  durably by each correct new member before activation.
- Query-flood admission capacity, disk flush latency, clock error, and external
  endpoint latency must be measured against the rooted bounds in M16Q.
- A later conflict can make re-verification reject even though an earlier
  candidate was validly accepted and executed. The durable executor record is
  audit evidence; it is not an offline finality certificate.

## 4. Mechanization and pairing

`QueryUnanimityCompositionProof.tla` lifts M13Q accepted uniqueness into
arbitrary-set history prefix compatibility and non-conflicting mutation
candidates. T10's existing `AtMostOnceExternalization.tla` supplies physical
deduplication and crash-to-lookup recovery. M12a remains the matching lower
bound for portable authorization; L-X remains the matching lower bound for
at-most-once mutation after ambiguous endpoint responses.

M15Q may begin only after the composition proof, theorem-assumption discipline,
claim discipline, and architecture-document gates pass. Production must use a
new named profile and may not relabel the existing hash-async or terminal-seal
paths.
