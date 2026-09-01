# Planned Clean-Room Twin — Composed Delegated-Authority And Governed-Effect Evidence Verifier

Status: planned internal clean-room packet; non-canonical; no twin result exists.
Authority: the canonical IOI Authority Protocol and its exact object owners win
on drift; this packet cannot amend a contract or release a profile.
Supports: future specification-sufficiency and vector-parity evidence.
Last alignment pass: 2026-08-30.

## Objective

Build a procedurally isolated retrospective evidence verifier for the composed
`ioi_delegated_authority_v1` plus `ioi_governed_effect_v1` candidate manifests,
using a different language, parser/canonicalization implementation, and
cryptographic library from the first-party Rust implementation. This is not the
standalone Governed Effect profile and not the Complete profile.

For one declared effect surface, the twin must take only the frozen packet and
an input bundle containing:

- both profile surface manifests and hashes;
- action request, review/decision evidence, and authorization subject;
- grant body/signature, complete parent chain, and signed allocation closure;
- issuer keys, revocation/currentness evidence, time input, audience, and holder;
- domain-derived actual effect and declared effect-surface descriptor;
- consumption/admission, invocation, outcome, and reconciliation receipts; and
- the frozen trust policy describing which inputs are roots versus recomputed.

Every output wrapper must bind:

```text
delegated_authority_manifest_hash
governed_effect_manifest_hash
evidence_bundle_root
verdict:
  verified(<claim_set>, <effect_root>, <grant_hash>, <consumption_receipt_root>)
  | invalid(<wire_stable_refusal_class>)
  | indeterminate(<missing_or_unsupported_evidence_class>)
```

The exact output contract must be registered before implementation begins. It
must define `evidence_bundle_root` over every canonical input-bundle field so
profile, trust-input, or terminal-evidence substitution changes the result. It
verifies a retained lifecycle; it does not make a pre-effect admission decision
and cannot cause an invocation.

## Isolation Rules

The twin implementer receives only:

1. the frozen candidate manifests;
2. the manifests' listed prose specifications and schemas;
3. public standards referenced by those specifications;
4. the conformance-vector bundle; and
5. a runner I/O adapter specification containing no first-party algorithms.

The implementer must not receive or inspect the first-party Rust source,
private design discussions, first-party call graphs, copied generated code,
unpublished test expectations, or coaching about a disputed verdict. The
coordinator records packet hashes, time of handoff, environment, dependencies,
and every clarification request.

Clarifications are answered by amending and re-freezing the specification or
packet for all implementations. They are never answered with “match the first-
party implementation.”

## Entry Gates

Do not start the twin until all are true:

- both selected profile manifests and the effect surface have complete candidate
  closures;
- signed allocation closure and complete admission/outcome signature contracts
  are canonical and registered;
- wire-stable refusal classes and trust-input acquisition rules are frozen;
- positive and adversarial vectors cover every threat family selected by the
  profile;
- the first-party runner passes from a clean, reproducible checkout; and
- the packet's exact permissive licensing path is recorded.

Starting earlier would test the implementer's ability to guess unfinished
doctrine, not specification sufficiency.

## Packet Layout (Target)

```text
twin/
  PACKET-MANIFEST.json
  SPECIFICATION.md
  schemas/
  standards-lock.json
  vectors/
    positive/
    boundary/
    adversarial/
    concurrency/
    crash-recovery/
    outcome-reconciliation/
  runner-adapter/
  CLARIFICATIONS.md
  ADJUDICATIONS.md
  RESULT.json
  RESULT.md
```

No file is implied to exist merely because it is listed here.

## Required Vector Outcomes

The twin must reproduce:

- canonical bytes and content/signature roots;
- request/review/grant/actual-effect equality and lineage;
- parent-holder issuance, attenuation, depth, audience, holder, purpose, time,
  key, revocation, and signed allocation closure;
- calls/budget consumption and idempotency-substitution verdicts;
- exact-effect, batch membership, and standing-constraint verdicts;
- final-PEP admission and receipt-wrapper authenticity;
- no-invocation, known failure, unknown invocation/outcome, and reconciliation;
- every selected typed refusal and missing-evidence classification; and
- downgrade and undeclared-extension refusal.

Concurrency and crash tests may use a deterministic model adapter when the twin
is verifier-only. The packet must say whether they prove trace adjudication or
a live atomic store; the two claims cannot be conflated.

## Adjudication

For every disagreement:

1. preserve the original packet, input, first-party result, twin result, and logs;
2. classify it as specification ambiguity, vector defect, reference defect,
   twin defect, dependency divergence, or unresolved;
3. correct the owning specification/contract first when the text is ambiguous;
4. issue a new manifest and packet hash for any semantic change;
5. rerun both implementations from clean state; and
6. publish the finding and disposition with the eventual evidence bundle.

A first-party-only behavior is a first-party defect or specification proposal,
not an unwritten conformance rule.

## Exit Evidence

The result records:

- packet and dependency hashes;
- provenance/isolation declaration;
- language, libraries, and environment;
- per-vector verdict and byte/root comparison;
- every clarification and adjudication;
- reproducible commands;
- unresolved differences; and
- explicit `proves` and `does_not_prove` statements.

Full agreement may establish internal specification clarity, cross-language
canonicalization/signature parity, and vector agreement for the frozen packet.
It does not establish an external audit, organizational independence, neutral
certification, production safety, adoption, or the complete Machine Authority
claim.

The later organizationally independent implementation must start from the
public packet and is a separate gate; this in-session twin cannot satisfy it.
