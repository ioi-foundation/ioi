---
module_id: wallet-authority
module_class: method
title: Familiar identity to exact machine authority
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M1, M2, M5, M9, M12]
legacy_id: WP-WALLET
canon_owners:
  - docs/architecture/components/wallet-network/doctrine.md
  - docs/architecture/components/wallet-network/api-authority-scopes.md
  - docs/architecture/components/wallet-network/product-exchange-risk.md
  - docs/architecture/components/hypervisor/identity-access-and-metering.md
  - docs/architecture/foundations/common-objects-and-envelopes.md
  - docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md
  - docs/decisions/0002-execution-authority-and-client-boundaries.md
---

# Familiar Identity To Exact Machine Authority

## What this module owns

The reusable method that carries a familiar identity gesture to an exact, scoped,
expiring, revocable machine authority the daemon revalidates at the final invoker. It is
a method only — it never orders work, never carries status, and never sequences.

## Pulled by

`M1`, `M2`, `M5`, `M9`, `M12`, per `modules[].applies_to_stages` for this module id in
[`program/sequence.v1.json`](../program/sequence.v1.json), the sole binding source.
Retained horizon shape: designed once, integrated into contracts as stages add
authority-crossing surfaces, terminally proved at the single-node product proof, and
reapplied wherever later stages create cross-party or public effects.

## Canon owners

| Canon owner | What it governs here |
| --- | --- |
| [`wallet-network/doctrine.md`](../../../docs/architecture/components/wallet-network/doctrine.md) | authority doctrine, step-up, approval ceremony, presentation-evidence posture, factors/guardians/recovery |
| [`wallet-network/api-authority-scopes.md`](../../../docs/architecture/components/wallet-network/api-authority-scopes.md) | account, factor, session, `scope:*` grant, approval, secret-brokerage, and revocation APIs |
| [`wallet-network/product-exchange-risk.md`](../../../docs/architecture/components/wallet-network/product-exchange-risk.md) | approval inbox, user-facing wallet receipts, exposure/protection and risk disclosure |
| [`hypervisor/identity-access-and-metering.md`](../../../docs/architecture/components/hypervisor/identity-access-and-metering.md) | deployment-local principals, sessions, SSO/OIDC/SCIM, principal-scoped capability leases |
| [`foundations/common-objects-and-envelopes.md`](../../../docs/architecture/foundations/common-objects-and-envelopes.md) | `AuthorityGrantEnvelope` v1/v2, `ApprovalCeremonyContextEnvelope`, `ConsequentialEffectFenceContext`, key sets, revocation snapshots, typed `authorization_subject` |
| [`daemon-runtime/events-receipts-delivery-bundles.md`](../../../docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md) | receipt envelopes, checkpoints, proof bundles, offline-export integrity |
| [`decisions/0002`](../../../docs/decisions/0002-execution-authority-and-client-boundaries.md) | the daemon as canonical execution endpoint and final invoker for consequential effects |

## Retained obligations

The required experience is one unbroken ladder:

```text
Continue with eligible identity / enterprise SSO / passkey
  -> native wallet identity linked without protocol ceremony
  -> ordinary low-risk product session
  -> consequential action proposed
  -> immutable request plus exact-effect, batch, or standing authorization subject
  -> canonical semantic review on a policy-qualified presentation surface
  -> separately inspectable platform-authenticator step-up when required
  -> immutable authority-review receipt
  -> scoped, expiring, revocable grant
  -> daemon-computed actual effect plus equality, membership, or constraint check
  -> effect or refusal
  -> receipt and recovery/revocation visibility
```

Authentication never authorizes an effect by itself. Recovery never silently reconstructs
or widens a grant. The request body, canonical reviewed representation, single-use
approval-ceremony context, and typed authorization subject are independently inspectable
commitments. A generic passkey, hardware security key, user-verification flag, or
attestation is authenticator evidence, not proof that an application-defined
representation was displayed or understood.

The M9 sovereign-local authority proof must show:

- deployment-local authentication remains distinct from locally permitted nonportable
  exact-effect authority;
- the daemon recomputes the actual effect and verifies exact request, subject, equality
  or constraint, revocation, temporal validity, budget, and writer fence before the final
  invocation;
- substitution, stale authority, uncertainty, and recovery cases refuse or reconcile
  without a portable-authority claim; and
- ordinary and consequential receipts plus offline export preserve integrity,
  valid-as-of posture, and currentness as separate conclusions.

When the M9 managed-optionality overlay is selected, its additional authority proof must
show:

- exact-effect substitution, changed reviewed representation, principal/session/origin
  substitution, predecessor edit-and-approve reuse, and caller-asserted factor/guardian
  participation refuse before the invoker;
- every batch effect proves membership and every standing effect proves all active
  resource, destination, budget, call, time, and policy constraints;
- presentation evidence records operator/surface, exact-content binding,
  request/effect/envelope semantics, enrollment/attestation posture, UP/UV,
  freshness/replay, and proposer independence through a versioned profile rather than a
  fixed assurance rank;
- one-shot, batch, standing, silent, and after-the-fact receipts state the authority
  actually used and never upgrade it into a false per-effect human-review claim; and
- immutable v1/v2 grant contracts, the legacy review-schema compatibility contract, and
  the effect-fence v1 compatibility contract remain unchanged until explicit successor
  contracts are registered, generated, tested, and deployed.

## Applying it in a work item

- `falsifiable_claim` names the authority-crossing route family and the
  `authorization_subject` kind it binds: `exact_effect`, `batch_manifest`, or `standing_envelope`.
- `code_anchors` name the policy-enforcement point, the grant-verification path, and the
  final invoker separately; one anchor for all three leaves the boundary unestablished.
- `evidence_refs` are repo paths to retained literals for review-receipt emission, grant
  issuance, daemon-side effect recomputation, and the effect-or-refusal terminal.
- `adversarial_or_fault_proof` carries the refusal battery: exact-effect substitution,
  changed reviewed representation, principal/session/origin substitution, predecessor
  edit-and-approve reuse, caller-asserted factor/guardian participation, revoked and
  expired grants, budget/call-count exhaustion, stale writer fence, and restart
  mid-effect — each with zero final-invoker calls on denial.
- `remaining_nonclaims` names whether portable delegated authority, presentation-surface
  trust, guardian participation, or offline-export currentness is claimed or unclaimed.

## Terminal evidence

One selected authority-crossing route family shows, from retained artifacts, a complete
identity-to-effect ladder with independently inspectable request, reviewed representation,
ceremony context, and authorization-subject commitments; daemon-side recomputation refusing
every entry in the required battery before the final invoker; receipts stating the authority
actually used without upgrading it; and revocation plus recovery visibility that narrows and
never widens a grant. One route family proves only that family.

## Canon gaps

- The "legacy review-schema compatibility contract" required to stay unchanged has no
  canonically named contract, revision, or owner entry. Owner: `api-authority-scopes.md`.
- `ConsequentialEffectFenceContext` v1 and `ApprovalCeremonyContextEnvelope` are defined in
  `common-objects-and-envelopes.md` but absent from
  `_meta/schemas/architecture-contract-registry.v1.json`, so "effect-fence v1 unchanged until
  a successor is registered" has no registered baseline and the single-use ceremony context
  has no versioned compatibility contract. Owner: that envelope owner plus that registry.
- The versioned presentation-evidence profile is referenced as a
  `policy://wallet/presentation/...` ref, but its succession rule — what a profile bump
  may change about an already-issued grant's assurance conclusions — is unstated. Owner:
  `wallet-network/doctrine.md`.
