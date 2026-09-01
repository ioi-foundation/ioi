# IOI Authority Protocol

Status: canonical architecture authority.
Canonical owner: this file for the IOI Authority Protocol family, its external
role contract, ordered lifecycle, named target profiles, surface-manifest rule,
conformance entitlements, and stable-release gates.
Supersedes: unversioned reuse of the Machine Authority category name as though
the complete IOI stack or architecture contract registry were one implementable
protocol surface.
Superseded by: none.
Last alignment pass: 2026-08-30.
Doctrine status: canonical
Implementation status: mixed (constituent request, ceremony, review, grant,
key-set, revocation, and admission schemas plus generated projections, a
portable Rust grant verifier, and one qualified served SCM admission/finalizer
path exist; all profiles below remain target profiles until their frozen
manifests, runnable conformance releases, complete declared effect coverage,
and independent parity evidence exist)
Last implementation audit: 2026-08-30

## Definition

**The IOI Authority Protocol is the open protocol family for implementing
Machine Authority across independently governed products, runtimes, authority
providers, policy-enforcement points, invokers, and verifiers.**

It carries the smallest interoperable authority boundary first and composes
that boundary into delegated power and exact governed effects. It is not a wire
name for the entire IOI stack.

The protocol implements the category and completeness rules owned by
[`machine-authority.md`](./machine-authority.md). When this file and that owner
appear to conflict, the category owner decides what a complete claim requires;
this file decides how IOI names and composes protocol profiles.

## Externality Rule

A conforming implementation does not have to run wallet.network, Hypervisor,
Agentgres, AIIP, IOI L1, an IOI model, or an IOI-hosted service. It must
implement the roles and behavior required by the exact profile it claims.

IOI components are first-party implementations and may become candidates for
later formal reference designation. No named release is designated as the
reference implementation by this file:

| Protocol Role | IOI First-Party Implementation | Replaceable Under A Released Profile By |
| --- | --- | --- |
| Authority provider, issuer, approval coordination, revocation | wallet.network | Any provider satisfying the profile's issuer, custody, key, grant, currentness, and revocation behavior |
| Policy-enforcement point and final-invoker mediation | Hypervisor Daemon | Any enforcing runtime, gateway, sidecar, connector host, transaction signer, robot controller, or resource owner satisfying the effect profile |
| Admitted operational truth and replay | Agentgres | Any deterministic store satisfying the named receipt, atomicity, replay, and recovery behavior |
| Cross-sovereign work carriage | AIIP | Optional transport/profile binding; not required by the authority profiles |
| Shared public finality | IOI L1 | Optional selected settlement or public-commitment service; never required for compatibility |

Current served portable-delegation routes are wallet.network-bound and expose
no alternate authority-provider adapter or interoperability proof. A future
released profile must make role replacement real before any provider-neutral
runtime claim is made. An IOI product may still require its first-party
components for a particular shipping posture; that product requirement cannot
be generalized into a future protocol dependency or conformance condition.

## Ordered Protocol State Machine

The portable lifecycle is ordered but branched as follows:

```text
proposed
  -> review_prepared
  -> decision_recorded
       denied   -> refusal_recorded (terminal)
       step_up  -> challenge_issued -> continuation_bound -> review_prepared
       approved -> approval_evidence_bound
                     -> grant_issued
                     -> grant_delegated*       # every hop strictly attenuates
                     -> authority_revalidated
                     -> actual_effect_derived
                     -> effect_decision
                          refused  -> effect_refusal_recorded (terminal; no consume/invoke)
                          admitted -> consume_or_replay
                                        replay_resolved -> prior disposition/evidence returned;
                                                           never invoke
                                        authority_consumed -> invoker_not_called (terminal), or
                                                           -> invoker_called
                                                                -> effect_failed | effect_unknown | effect_observed
                                                                -> reconciled*
```

No transition is inferred from the next transition's existence. A grant does
not imply admission; admission does not imply invocation; invocation does not
imply success; observation does not imply acceptance or settlement.

Every implementation maps its transport and storage choices onto this state
machine. A transport may combine messages, but it must preserve the distinct
hashes, decisions, failure states, and proof obligations.

## Named Target Profiles

The protocol family has four composable target profiles. Their identifiers are
stable doctrine names; no profile is a released conformance surface until a
versioned `ProtocolSurfaceManifest` freezes its exact closure.

### `ioi_authority_core_v1`

Purpose: the smallest drop-in authorization boundary for existing agent hosts,
IDEs, gateways, tool runtimes, CI systems, and autonomous applications.

Required behavior:

- canonical action/request identity;
- canonical reviewed representation;
- attributable approve, deny, edit, and step-up decisions;
- qualified presentation and authenticator evidence when the selected policy
  requires them;
- asynchronous challenge/continuation without treating timeout as approval;
- signed or otherwise profile-authenticated decision evidence; and
- deterministic offline verification of the named evidence claims.

Current primary contract families:

- `ActionRequestEnvelope` at an attach or gateway boundary;
- `AuthorityScopeRequestEnvelopeV2` at the authority-review boundary;
- `ApprovalCeremonyContextEnvelopeV1`; and
- `AuthorityReviewReceiptV1`.

Passing this profile permits an **IOI action-authorization conformant** claim.
It does not permit a Machine Authority claim and proves no grant, delegation,
revocation currentness, final-PEP admission, or execution fact.

### `ioi_delegated_authority_v1`

Purpose: portable machine power that can be held and, when explicitly allowed,
delegated across processes, runtimes, and sovereign systems.

It includes `ioi_authority_core_v1` and additionally requires:

- signed issuer, holder, holder-key, audience, subject, scope, resource,
  purpose/caveat, time, budget, call, risk, and revocation binding;
- versioned trusted key-set and signed bounded-freshness revocation evidence;
- parent-holder issuance and complete ancestry verification;
- strict attenuation on every delegated dimension;
- explicit re-delegation and maximum-depth authority;
- complete allocation evidence for shared descendant budgets and calls;
- replay-safe, atomic consumable limits; and
- typed refusal parity for substitution, widening, cycle, stale/revoked state,
  budget, call, depth, issuer, audience, and holder failures.

Current primary contract families:

- `AuthorityGrantEnvelopeV3`;
- `AuthorityKeySetV1`;
- `AuthorityRevocationSnapshotV1`;
- the applicable temporal verification/evaluation contracts; and
- a future registered signed delegation-allocation closure, required before
  this profile can be frozen as portable.

Passing this profile permits an **IOI delegated-authority conformant** claim.
It does not establish that the eventual effect matched or consumed the grant.

### `ioi_governed_effect_v1`

Purpose: close the gap between authority that exists and the exact effect a
runtime or resource owner is about to perform.

It requires:

- enforcing-domain derivation of actual effect identity and payload;
- immediate final-PEP revalidation of current authority and resource posture;
- exact equality, committed-batch membership, or standing-constraint proof;
- atomic authority consumption and stable idempotent replay;
- separate immutable admission and invocation evidence;
- typed non-invocation, refusal, failure, unknown, partial, compensation, and
  reconciliation states; and
- portable verification of admission, consumption, execution, and outcome
  linkage.

Current primary contract families:

- `AuthorityEffectAdmissionReceiptV2`;
- `GatewayDecisionReceipt` and `GatewayExecutionReceipt` where the gateway
  profile applies;
- the applicable effect-specific execution receipt; and
- the applicable reconciliation evidence for external or ambiguous effects.

Passing this profile permits an **IOI governed-effect conformant** claim. It is
not a complete portable delegated-authority claim unless composed with
`ioi_delegated_authority_v1`.

### `ioi_machine_authority_complete_v1`

Purpose: the complete category claim.

It composes all three profiles and must satisfy MAC-1 through MAC-12 from
[`machine-authority.md`](./machine-authority.md), including:

- fully portable delegation closure;
- served final-PEP-to-invoker enforcement;
- offline verification from locally selected trust roots;
- replaceable issuer, PEP, invoker, truth-store, transport, and verifier roles;
- independently implemented behavioral parity; and
- portable exit without a required IOI account, token, network, chain, or
  hosted service.

Passing this profile permits an **IOI Machine Authority conformant** claim only
for the exact declared effect surface. It does not prove cognitive alignment,
effect correctness, legal enforceability, acceptance, adjudication, or
settlement.

## Protocol Surface Manifest

Every released profile is defined by one immutable, content-addressed
`ProtocolSurfaceManifest`. The manifest is a target machine contract until it
is registered; prose, a package version, or a reference binary may not
substitute for it.

The manifest binds at least:

```yaml
protocol_surface_manifest:
  protocol: ioi_authority
  profile_id: ioi_authority_core_v1 | ioi_delegated_authority_v1 |
    ioi_governed_effect_v1 | ioi_machine_authority_complete_v1
  release_version: semver
  status: candidate | stable | deprecated
  constituent_profile_manifest_hashes: []
  contract_ids_and_schema_hashes: []
  invariant_ids_and_hashes: []
  canonical_encoding_profiles: []
  signature_suites_and_domains: []
  required_role_behaviors_and_adapter_abis: []
  trust_input_profiles_and_freshness_rules: []
  declared_effect_surface_ids_and_hashes: []
  lifecycle_transition_table_hash: sha256:...
  required_refusal_codes: []
  positive_fixture_bundle_hash: sha256:...
  adversarial_fixture_bundle_hash: sha256:...
  crash_concurrency_outcome_bundle_hash: sha256:...
  verifier_release_and_hash: ...
  compatibility_and_deprecation_policy_ref: ...
  implementation_independence_evidence_refs: []
  manifest_hash: sha256:...
```

The complete profile binds the exact constituent profile manifest hashes; a
moving name or “latest” selector is invalid. The future registered manifest
contract must define a domain-separated canonical hash over the complete body
excluding `manifest_hash` and any enclosing signatures, so the manifest cannot
self-hash ambiguously. Until that contract is registered, the shape above is a
target and no prose-computed hash is authoritative.

The architecture contract registry remains the source for registered contract
identity and field-level schema metadata. It is not itself a protocol surface:
membership in that larger registry does not silently enter an authority profile.

## Conformance And Entitlements

Conformance is evaluated against one manifest at one version. A runner must
reject unknown contracts, invariants, signature suites, refusal codes, or
fixture identities rather than silently extending the surface.

Required evidence classes are:

1. **Schema and encoding parity** — exact acceptance and canonical-byte output.
2. **Signature and hash parity** — exact preimages, domains, trust inputs, and
   refusal on substitution.
3. **State-transition parity** — the same legal transitions and terminal facts.
4. **Refusal parity** — every required adversarial case produces the named
   refusal class, with no either-outcome passes.
5. **Crash and concurrency parity** — no double consumption, overspend,
   duplicate effect, partial acknowledgement, or restart ambiguity.
6. **Surface completeness** — implemented and explicitly unimplemented portions
   are machine-readable; silence is not partial conformance.
7. **Independence evidence and disclosure** — codegen, transport, verifier, and
   authoring independence are stated under ADR 0032, and stable-profile claims
   include the independent implementation required by gate 6 below.

Conformance does not confer certification, marks, endorsement, network
membership, settlement assurance, or legal status. Those remain separate.

The retired `docs/conformance/` document class is not recreated. Canonical
meaning and target profiles live here and with their subject owners. A runnable
release belongs with the public protocol artifact/package and must be usable by
an outsider without private program state.

## Stable Release Gates

No profile may be marked `stable` until all applicable gates pass:

1. The exact manifest and every referenced contract, invariant, fixture, and
   signature profile are public and immutably versioned.
2. The surface is specification-sufficient under `separate_codegen` and
   `separate_transport`.
3. A clone-and-run offline verifier produces deterministic typed verdicts.
4. Positive, negative, substitution, replay, expiry, revocation, crash,
   concurrency, and ambiguity cases required by the profile are public.
5. A clean-room implementation built only from the specification, manifest,
   and vectors reaches refusal parity.
6. At least one organizationally independent implementation reaches the
   profile's declared parity before that profile is called stable.
7. The served first-party candidate path implements every required transition;
   constructor or unit-test evidence alone is insufficient. Formal reference
   designation remains a separate decision.
8. Breaking-change, deprecation, designation, objection, and security-response
   records are operational rather than merely described.
9. The release states exactly what a passing implementation may and may not
   claim.

## Present Profile Status

| Profile | Current Evidence | Blocking Conditions |
| --- | --- | --- |
| `ioi_authority_core_v1` | Registered request, ceremony, and review-receipt schemas with generated projections; gateway request contracts exist | No frozen surface manifest, public runnable release, or independent implementation; production exact-action review/issuance remains incomplete |
| `ioi_delegated_authority_v1` | Registered v3 grant, key-set, and revocation schemas; offline Rust verification exercises chain, attenuation, currentness, budget, replay, and typed refusals | Signed portable allocation closure, public CLI/package surface, frozen vectors, independent implementation, and a served replaceable authority-provider adapter remain incomplete |
| `ioi_governed_effect_v1` | Registered admission receipt; the qualified live SCM path derives the effect, atomically consumes the exact grant, persists the v2 receipt, re-censuses current evidence, byte-compares owner recovery, and fences its exactly-once finalizer | Portable outer signature, frozen profile/runner, independent implementation, broader declared effect surfaces, complete portable outcome/reconciliation linkage, and alternate-provider interop evidence remain incomplete |
| `ioi_machine_authority_complete_v1` | The constituent architecture is defined | Every constituent profile must close its gates and pass as one end-to-end independently verifiable path |

This table is status orientation, not a second implementation ledger. Detailed
status remains with the object owners and
[`../_meta/canon-to-code-delta.md`](../_meta/canon-to-code-delta.md).

## Governance And Versioning

The change process, reference designation, certification separation, capture
resistance, and versioning rights are owned by
[`protocol-governance-neutrality.md`](./protocol-governance-neutrality.md) and
the reference-implementation contract in
[`web4-and-ioi-stack.md`](./web4-and-ioi-stack.md).

The protocol name never grants one implementation the power to legislate by
shipping. A divergence between a release and its manifest is a defect in the
release until the public change process amends the protocol.

## Related Owners

- [`machine-authority.md`](./machine-authority.md) — category and completeness.
- [`objects/authority-and-access.md`](./objects/authority-and-access.md) —
  request, ceremony, grant, key, revocation, and delegation object shapes.
- [`../components/wallet-network/api-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md)
  — first-party authority-provider APIs and current implementation boundary.
- [`../components/daemon-runtime/doctrine.md`](../components/daemon-runtime/doctrine.md)
  — PEP, final invoker, gateway, and execution semantics.
- [`../components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  — admission, execution, outcome, and reconciliation receipt meaning.
- [`ecosystem-assurance-certification-liability.md`](./ecosystem-assurance-certification-liability.md)
  — certification, issuer, assurance, and liability boundaries.
