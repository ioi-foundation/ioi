# IOI Authority Protocol Threat Model

Status: active internal threat-model candidate; non-canonical.
Authority: the canonical Machine Authority, IOI Authority Protocol, authority
object, daemon, receipt, and invariant owners win on drift.
Supports: candidate-profile design and adversarial-vector derivation only.
Last alignment pass: 2026-08-30.

## Security Objective

For the composed Complete-profile objective, an offline verifier must be able to
determine that the exact effect which reached the final policy-enforcement
point was proposed, reviewed when required, authorized by a current issuer,
properly delegated to the presenting holder, admitted within all remaining
bounds, consumed at most as permitted, and then either proved not invoked,
invoked at most once, or assigned an explicit unknown disposition with durable
outcome evidence.

The protocol fails closed when any required input is absent, ambiguous, stale,
substituted, non-canonical, outside the selected profile, or unavailable at the
last safe point before the effect.

A narrower profile selects only its canonical subset of this objective and the
corresponding threats below. Core does not claim delegation or effect evidence;
standalone Governed Effect does not claim portable delegated-authority closure.

## Protected Assets

- the principal's power to approve, deny, attenuate, revoke, and recover;
- exact-effect integrity between proposal, grant, admission, and invocation;
- grant-chain and descendant-allocation integrity;
- calls, budget, time, audience, holder, and purpose bounds;
- the single-consumption and exactly-once finalizer boundaries;
- the distinction between no invocation, known invocation, unknown outcome,
  observed effect, and reconciliation;
- receipt authenticity, ordering, and lineage;
- profile identity and downgrade resistance; and
- portable verification without an undeclared IOI-hosted dependency.

## Roles And Trust Boundaries

Roles are abstract and targeted for replacement under a released profile. The
first-party wallet, Hypervisor daemon, and Agentgres implementations fill
current roles but are not formal reference releases or protocol trust axioms.

| Role | Trusted only for | Must not be trusted for |
| --- | --- | --- |
| proposer | supplying candidate intent | issuer keys, currentness, final effect, or approval |
| reviewer/approver | the signed or otherwise qualified review decision it produces | silently widening the request or minting unrelated power |
| authority provider | signed grants, current keys, revocation/currentness, and atomic allocation/consumption state named by the profile | the PEP's actual effect or its own conformance verdict |
| holder/delegate | presenting a grant and requested use | proving its own authority, ancestry, remaining allocation, or identity |
| domain resolver | deriving the exact effect from owner state | importing caller-supplied effect truth |
| PEP/final invoker | last-safe-point admission, consumption coordination, and invocation | creating authority or treating an earlier check as sufficient |
| evidence store | durable ordered bytes and recovery | changing verdicts, filling missing signatures, or declaring effects correct |
| offline verifier | deterministic verification against declared trust inputs | discovering undeclared ambient state |
| certifier/marks function | evaluating a named implementation against a frozen profile | changing the profile or self-designating first-party behavior as normative |

Cryptographic libraries, canonicalizers, clocks, key/revocation distribution,
durable storage, and effect adapters are separate trust boundaries. A profile
must name which outputs are trusted inputs and which are independently
recomputed.

## Adversaries And Faults

Assume a malicious or compromised caller, model, holder, delegate, connector,
provider endpoint, cache, storage process, or first-party implementation. Also
assume honest components can crash, retry, reorder messages, observe different
currentness snapshots, or disagree about canonical bytes. The issuer and PEP
may fail independently. Operator error, insider key misuse, governance capture,
and dependency compromise are in scope where they affect profile claims.

Cryptographic primitive break, endpoint correctness after an accurately
authorized effect, and the truth of external-world assertions are outside the
base protocol's prevention claim. They still require explicit evidence and
must not be silently elevated into protocol truth.

## Required Adversarial Cases

Candidate vector ids are planning labels only. Released ids must be frozen by
the profile manifest.

| Threat ID | Threat / Attack Or Failure | MAC / Profile | Required Result | Candidate Vector Family | Primary Promotion Owner |
| --- | --- | --- | --- | --- | --- |
| IAP-T01 | canonicalization split: two parsers hash or sign semantically similar but byte-distinct inputs | MAC-1, MAC-11 / all | deterministic reject or identical canonical bytes across implementations | `ENC-*` | profile manifest + object owner |
| IAP-T02 | signature-domain confusion: reuse a valid signature for another object, version, profile, or lifecycle stage | MAC-1, MAC-3, MAC-11 / all | typed domain/profile mismatch refusal | `SIG-DOMAIN-*` | object owner |
| IAP-T03 | request-carried trust root: caller supplies issuer keys, revocation, clock, holder, or audience which validates its grant | MAC-3, MAC-5, MAC-8 / Delegated, Governed Effect | ignore as authority; independently resolve and bind declared trust inputs | `TRUST-ROOT-*` | authority + provider owners |
| IAP-T04 | request/review substitution: approval cites a different request or edited representation | MAC-1, MAC-2 / Core | refuse before grant or admission | `REVIEW-SUB-*` | Core profile owner |
| IAP-T05 | imported approval or approval replay: boolean/status input or reused ceremony/continuation claims assent | MAC-2, MAC-6 / Core | imported flag has no authority; exactly one admissible ceremony consumption | `REVIEW-REPLAY-*` | Core + provider owners |
| IAP-T06 | grant substitution: valid signature does not match the named hash or authorization subject | MAC-3 / Delegated | refuse without allocation change | `GRANT-SUB-*` | Delegated profile owner |
| IAP-T07 | ancestry splice or cycle: combine valid parents/children from different chains or loop ancestry | MAC-4 / Delegated | refuse parent, holder, audience, depth, cycle, or subject mismatch | `CHAIN-*` | Delegated profile owner |
| IAP-T08 | unsigned allocation closure: hide siblings, descendants, or prior allocation while presenting a valid chain | MAC-4, MAC-6 / Delegated | refuse portable verification without complete signed/current closure | `ALLOC-CLOSURE-*` | Delegated profile owner |
| IAP-T09 | attenuation widening: child expands effect, calls, budget, time, purpose, audience, holder, or re-delegation | MAC-4 / Delegated | refuse the child and every dependent use | `ATTENUATION-*` | Delegated profile owner |
| IAP-T10 | stale key or revocation view: use rotated key or newly revoked grant against cached evidence | MAC-5 / Delegated, Governed Effect | refuse outside declared freshness horizon and bind exact evidence into admission | `CURRENTNESS-*` | provider + Delegated profile owners |
| IAP-T11 | temporal ambiguity: skew, overflow, null expiry, rollback, or boundary disagreement changes validity | MAC-5 / Delegated, Governed Effect | one declared time authority/rule; malformed, overflowed, or stale values refuse | `TIME-*` | profile manifest |
| IAP-T12 | concurrent overspend: parallel callers race the final call or budget unit | MAC-6 / Delegated, Governed Effect | at most one succeeds; stable loser refusals; recovery preserves count | `CONCURRENCY-*` | provider + PEP owners |
| IAP-T13 | idempotency alias: same key is reused with different grant, effect, holder, or bounds | MAC-6 / Delegated, Governed Effect | refuse substitution; never return another use's receipt | `IDEMPOTENCY-*` | provider owner |
| IAP-T14 | actual-effect substitution: authorized input differs from the domain-derived effect at the PEP | MAC-7, MAC-8 / Governed Effect | refuse before invocation and without new consumption except declared identical-intent recovery | `EFFECT-SUB-*` | Governed Effect owner |
| IAP-T15 | batch escape: a valid batch is used for a non-member effect or mutated ordering/root | MAC-7, MAC-8 / Governed Effect | refuse membership/root mismatch | `BATCH-*` | Governed Effect owner |
| IAP-T16 | standing-envelope excess: a loose label matches while a concrete bound is exceeded | MAC-7, MAC-8 / Governed Effect | refuse exact constraint violation | `STANDING-*` | Governed Effect owner |
| IAP-T17 | check/use gap: policy or authority changes after an early check but before invocation | MAC-5, MAC-8 / Governed Effect | re-resolve or prove bounded freshness at final PEP; stale evidence refuses | `PEP-CURRENT-*` | PEP owner |
| IAP-T18 | finalizer bypass: alternate route, retry worker, or connector invokes without final admission/consumption | MAC-8, MAC-9 / Governed Effect | no effect; coverage evidence identifies every final invoker | `FINALIZER-*` | daemon owner |
| IAP-T19 | crash before consumption: process dies after decision but before atomic use | MAC-6, MAC-9 / Delegated, Governed Effect | recovery yields no use or resumes the identical prepared intent | `CRASH-PRE-CONSUME-*` | provider + PEP owners |
| IAP-T20 | crash after consumption, before invoke: durable use exists but invocation is unobserved | MAC-6, MAC-9, MAC-10 / Governed Effect | resume identical intent or record unknown/dead claim; never casually spend again | `CRASH-POST-CONSUME-*` | provider + PEP + receipt owners |
| IAP-T21 | crash after invoke, before outcome: effect may exist but terminal receipt is absent | MAC-9, MAC-10 / Governed Effect | explicit unknown outcome and reconciliation; no false success or safe-retry assumption | `CRASH-POST-INVOKE-*` | outcome owner |
| IAP-T22 | receipt substitution: valid admission/invocation/outcome/reconciliation belongs to another effect/use | MAC-9, MAC-10, MAC-11 / Governed Effect | exact lineage mismatch refusal | `RECEIPT-SUB-*` | receipt owner |
| IAP-T23 | receipt forgery/stripping: outer wrapper is unsigned, partly signed, or omits a load-bearing field | MAC-11 / Governed Effect, Complete | no portable authenticity claim until the profile binds the complete wrapper | `RECEIPT-SIG-*` | receipt + profile owners |
| IAP-T24 | profile downgrade: Complete or Governed Effect claim is checked under Core-only rules | MAC-11, MAC-12 / all | refuse claimed entitlement/profile mismatch | `PROFILE-DOWNGRADE-*` | manifest + verifier |
| IAP-T25 | extension smuggling: unknown or local fields alter semantics | MAC-11, MAC-12 / all | reject or ignore only as the frozen manifest declares | `EXTENSION-*` | profile manifest |
| IAP-T26 | discovery capture: verification silently calls an IOI endpoint for schema, key, or status | MAC-11, MAC-12 / all | incomplete portable bundle; offline verifier returns missing-input result | `OFFLINE-*` | profile/release owner |
| IAP-T27 | evidence auto-elevation: cross-sovereign receipt, certification, or settlement proof becomes local authority | MAC-2, MAC-3, MAC-8 / Governed Effect, Complete | retain as evidence until an explicit local admission rule accepts it | `EVIDENCE-ELEVATION-*` | AIIP + local authority owners |
| IAP-T28 | self-certification capture: first-party behavior or a first-party badge becomes specification | MAC-12 / all stable profiles | no profile change or neutral-certification claim; record governance violation | `GOV-CAPTURE-*` | governance owner |

## Crash And Outcome Model

The profile must distinguish these states; collapsing them creates replay or
false-success vulnerabilities:

```text
not_admitted
  -> admitted_and_consumed
  -> invocation_claimed
  -> outcome_observed

admitted_and_consumed -> invocation_unknown -> reconciled
invocation_claimed     -> outcome_unknown    -> reconciled
```

An implementation may refine the states, but it may not call an unknown effect
failed, retryable, or successful without the evidence required by the selected
profile. Reconciliation is a linked successor, not an edit of earlier receipts.

## Refusal Requirements

Every negative vector must establish all applicable side effects, not merely an
error string:

- no invocation;
- no new authority or widened descendant allocation;
- no calls/budget consumption, except where recovery of a previously committed
  identical intent is the subject under test;
- no misleading success or conformance receipt;
- stable typed refusal class at the profile boundary; and
- deterministic replay of the same durable result when the profile requires it.

Implementation-specific diagnostics may add detail but cannot replace the
profile refusal class.

## Questions Requiring Canonical Resolution

1. What signed object closes cumulative descendant allocation for portable v3
   delegation without mutating the registered grant body?
2. Which complete admission and outcome wrappers are signed, by whom, and over
   which canonical bytes without circular roots?
3. Which currentness distribution modes and maximum freshness horizons are
   allowed per profile?
4. What effect-neutral ABI makes actual-effect derivation reproducible for a
   non-Hypervisor PEP?
5. Which exact invocation/unknown/reconciliation states are mandatory in the
   Governed Effect profile?
6. Which refusal codes are wire-stable and which remain local diagnostics?
7. What evidence demonstrates that every consequential finalizer is covered?

Answers become authoritative only after promotion to the owning canonical file,
registered contract, accepted ADR, or frozen protocol manifest.
