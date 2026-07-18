# Attestation assurance conformance

Status: target conformance contract. Current master has a generic startup
verification gate, but no dedicated attestation-assurance evaluator,
deployment-policy obligation projector, live quote owner, or institutional
effector.
Canonical inputs:
[`runtime-nodes-tee-depin.md`](../../architecture/components/daemon-runtime/runtime-nodes-tee-depin.md),
[`hypervisoros.md`](../../architecture/components/daemon-runtime/hypervisoros.md),
and
[`ecosystem-assurance-certification-liability.md`](../../architecture/foundations/ecosystem-assurance-certification-liability.md).
Last audited: 2026-07-16.

## Scope and honest implementation posture

This document defines the target behavior of a future shared
attestation-assurance evaluator and deployment-policy obligation projector. The
current `RuntimeProfileValidator` evaluates generic caller-supplied startup
verification states. It does not implement the structured RATS-role,
nonce-consumption, endorsement, appraisal, lease, revocation, or re-attestation
contract below. The current `ioi-agent` startup call explicitly marks security
attestation `NotRequired` because the binary has no remote-attestation verifier.
That existing gate is adjacent implementation precedent, not proof of this
profile.

A conforming evaluator must retain effective posture, accepted and rejected
candidate refs, stable failure codes, and exact evidence-kind requirements. It
must not acquire or imply a CPU/TEE, TPM, DICE, secure-element, or GPU quote
without a real evidence owner; invent durable nonce consumption; treat supplied
endorsement or receipt refs as verified; mint or revoke leases; or make legal
determinations.

A future deployment-policy obligations projection may consume
`JurisdictionPolicyPack`, `AssuranceEvidenceBundle`, and
`AssurancePostureProjection` semantics to compute versioned reporting and
erasure duties. No such executable projector exists on current master, and a
calculation alone would not notify a regulator, erase bytes or keys, resolve a
legal hold, validate receipts, or establish legal conformity.

## Conformance criteria

### CAA-1 — Distinct RATS roles

Evidence must name an Attester, Verifier, Appraiser, and Relying Party. The
Attester and Relying Party cannot collapse into the Verifier/Appraiser role, and
the evidence must target the startup gate's exact Relying Party.

### CAA-2 — Fresh, single-use challenge

The challenge nonce must match and its
`consumed_for_this_appraisal` state must carry a consumption receipt ref.
`already_consumed`, `unverified`, a missing receipt, or a nonce mismatch makes
that evidence ineligible. A production claimant additionally needs a durable
atomic nonce owner; the pure evaluator is not that owner.

### CAA-3 — Exact workload and build binding

Every candidate must bind the expected workload identity, daemon build hash,
policy build hash, and admitted reference values. Evidence for another
workload, daemon, or policy is ineligible even if its quote and signature are
otherwise valid.

### CAA-4 — Endorsement and appraisal

Measured-boot, secure-element, CPU/TEE, and GPU confidential-compute candidates
must bind only trusted endorsement refs. All candidates must bind trusted
reference values, the exact appraisal policy, a passing appraisal result ref,
and a current validity window. A provider self-report is not an appraisal.

### CAA-5 — Lease, revocation, and cadence

Every candidate must bind the expected unexpired lease, a current revocation
check receipt at or beyond the required epoch, and a current re-attestation
deadline no later than policy cadence. Missing, stale, revoked, or expired state
makes that candidate ineligible.

### CAA-6 — Deterministic narrowing without overclaim

The evaluator selects the strongest eligible projection in canonical order and
retains rejected stronger-candidate findings. Valid software-only or
trusted-operator evidence may preserve operation only when the deployment
minimum permits it. Such fallback must set
`hardware_or_measured_attested: false`. CPU, GPU, secure-element, and
measured-boot minimums require their exact evidence kind; one does not satisfy
another merely because its display rank is higher.

### CAA-7 — Required startup admission seam

`RuntimeProfileValidator::evaluate_startup_gate` must invoke the shared
evaluator when structured input is present, expose its report, and block when
its minimum is unmet. Rejected stronger evidence remains visible as a warning
even when an allowed fallback keeps startup open. Structured input must not
erase a known legacy verifier failure; unavailable legacy verification may be
superseded only by an independently allowed structured report and remains
visible as a warning.

### CAA-8 — Deployment and jurisdiction projection honesty

Existing `JurisdictionPolicyPack`, `AssuranceEvidenceBundle`, and
`AssurancePostureProjection` shapes must retain pack/deadline version,
responsible/accountable issuer, reporting-clock evidence, attestation posture,
and crypto-shredding/erasure evidence state. A generated projection must emit
`legal_conformity_claim: not_determined`; receipt presence, appraisal success,
deadline calculation, or crypto-shredding never becomes a legal determination.

### CAA-9 — Versioned obligation and erasure projection

The deployment evaluator must reject missing responsible/accountable issuer
bindings, invalid pack/rules/deadline versions, duplicate or missing incident
rules, missing clock-basis evidence, future clocks/submissions, deadline
overflow, and submission timestamps without receipts. Overdue or late notice
and report state remains explicit.

Crypto-shredding receipts require pack eligibility and an exact policy. They
prove key destruction only and must not project `verified_erased` without
destructive evidence, a verification receipt/profile, complete replica,
derivative, and backup scope, and no retention lock or legal hold. Exception
refs require the pack's exception policy and project `excepted`, never erased.
A conforming generated projection may expose only
`legal_conformity_claim: not_determined`.

## Required adversarial evidence

A future executable conformance tier must cover:

- valid CPU plus GPU evidence selecting the composite posture;
- empty policy/evidence/role bindings and duplicate evidence refs;
- an allowed combined Verifier/Appraiser role;
- collapsed Attester/Verifier roles;
- GPU display precedence being unable to substitute for a required CPU/TEE
  evidence kind;
- an already-consumed nonce rejecting CPU/TEE while valid software evidence
  preserves a non-hardware startup;
- wrong workload, daemon build, and policy build;
- stale appraisal and overdue re-attestation;
- untrusted endorsements and reference values;
- missing lease and revocation evidence;
- loss of GPU evidence narrowing deterministically to CPU/TEE;
- rejected CPU/TEE narrowing to trusted-operator without a hardware claim;
- the real startup gate preserving an allowed software fallback; and
- the real startup gate blocking when the exact minimum posture is absent;
- an explicit legacy verifier failure remaining blocking despite a structured
  pass; and
- legacy verifier unavailability remaining visible when independently passing
  structured evidence supersedes it;
- missing issuer responsibility/accountability;
- invalid and duplicate deadline versions;
- missing selected clock facts, overdue notice, late full report, and receiptless
  submissions;
- stale evidence projections;
- crypto-shredding eligibility/policy binding and inability to claim verified
  erasure;
- complete, independently verified erasure;
- retention/legal-hold and incomplete-scope narrowing;
- exception-policy binding; and
- timestamp-overflow refusal.

Current master has no dedicated `attestation` conformance tier or the named
evaluator modules. `npm run hypervisor-conformance:docs` validates this
contract's architecture links and surrounding canon only; it is not runtime
attestation evidence. Promotion requires the executable suite above plus live
quote, endorsement, nonce-store, signature-chain, revocation-service, and
deployment fault-injection evidence. Incident timestamps, reporting receipts,
erasure receipts, legal holds, exceptions, and jurisdiction inputs must also be
authenticated by their owners rather than trusted as caller-supplied refs.
