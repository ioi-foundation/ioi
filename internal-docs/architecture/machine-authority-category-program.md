# Machine Authority Category Program

Status: active internal category program; non-canonical.
Authority: `docs/architecture/` owners and accepted ADRs are canonical and win
on drift; this file tracks evidence, promotion work, and claim gates only.
Supports: the canonical Machine Authority definition, IOI Authority Protocol
owner, protocol-governance owner, and canon-to-code delta.
Last alignment pass: 2026-08-30.

## Program Outcome

Produce the smallest externally adoptable IOI action-authorization boundary,
compose it into portable delegated authority and exact governed effects, and
earn a complete Machine Authority claim through a frozen public surface,
outsider-runnable verification, independently reproduced refusal parity, and a
served end-to-end first-party candidate path.

The program succeeds when an independently governed implementer can build and
operate the selected profile from public specification, manifest, schemas,
vectors, and trust inputs without reading IOI's first-party implementation
source or depending on an IOI-hosted service.

## Authority And Non-Authority Boundary

Canonical meaning lives only in:

- [`machine-authority.md`](../../docs/architecture/foundations/machine-authority.md);
- [`ioi-authority-protocol.md`](../../docs/architecture/foundations/ioi-authority-protocol.md);
- [`protocol-governance-neutrality.md`](../../docs/architecture/foundations/protocol-governance-neutrality.md);
- the exact object and receipt owners they cite; and
- accepted ADRs, especially
  [`0040`](../../docs/decisions/0040-make-machine-authority-the-category-and-ioi-authority-the-portable-protocol.md).

Canonical implementation truth lives in each subject owner's implementation-
status declaration and
[`canon-to-code-delta.md`](../../docs/architecture/_meta/canon-to-code-delta.md).
Tracked work items, code, and retained verifier evidence support those owners;
they do not independently own status. This program must link the owners, must
not restate their field contracts, and must not silently promote maturity or
become a release manifest.

## Public Claim Discipline

- No competitor comparison is part of a public category definition, protocol
  profile, conformance page, first-read architecture, or release claim.
- Public language is property-first: bounded power, delegation, revocation,
  exact-effect admission, controlled consumption, and verifiable outcomes.
- A released `ioi_authority_core_v1` manifest may entitle only the action-
  authorization claim its canonical owner declares.
- Only a released frozen surface passing MAC-1 through MAC-12 may entitle the
  complete Machine Authority claim.
- A schema, vector, constructor, unit test, internal twin, or first-party demo
  unlocks only the exact evidence claim it proves.
- Target profiles remain target profiles until their release gates close.

Internal landscape research may name systems inside a dated research note when
needed to detect missing properties. It is never canonical input, public
positioning, or evidence that IOI passes its own bar.

## Canonical Owners

| Subject | Owner |
| --- | --- |
| Category definition, roles, MAC-1–MAC-12, claim ladder | `docs/architecture/foundations/machine-authority.md` |
| Profile family, state machine, manifest rule, entitlements, release gates | `docs/architecture/foundations/ioi-authority-protocol.md` |
| Request, ceremony, grant, key-set, revocation shapes | `docs/architecture/foundations/objects/authority-and-access.md` |
| wallet.network first-party issuer/revocation/API behavior | `docs/architecture/components/wallet-network/` owners |
| PEP, final invoker, gateway, execution behavior | `docs/architecture/components/daemon-runtime/doctrine.md` |
| Admission, execution, outcome, reconciliation receipts | `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md` |
| Cross-owner invariant wording | `docs/architecture/foundations/invariants.md` |
| Specification/reference/certifier separation | `docs/architecture/foundations/protocol-governance-neutrality.md` |
| Current implementation delta | `docs/architecture/_meta/canon-to-code-delta.md` |

## Program Evidence States

These states describe the provenance of one program evidence item, not product
maturity and not a conformance entitlement:

| State | Mechanical entry criterion |
| --- | --- |
| `unmeasured` | no dated assessment or reproducible evidence locator exists |
| `evidence_missing` | the canonical owner or a scoped repository audit explicitly records the required artifact as absent |
| `owner_reported` | a current canonical status owner names the evidence/posture, but this program has not reproduced the underlying behavior |
| `first_party_verified` | an exact first-party artifact plus reproducible command and dated result establishes the narrow behavior on a clean checkout |
| `internally_reproduced` | a procedurally isolated second implementation built from the frozen packet, not first-party source or coaching, reaches recorded parity |
| `externally_reproduced` | an organizationally independent implementer reaches recorded parity from the public packet |
| `promoted` | the result is admitted by its canonical owner or exact released manifest; promotion alone does not imply implementation parity |

The states are not a simple maturity ladder: doctrine can be `promoted` while
runtime evidence remains `evidence_missing`, and first-party evidence never
becomes independent evidence through repetition by the same implementation.

## Category-Completeness Gates

| Gate | Contribution To Canonical Entitlement | Canonical Owner | Required Machine Artifact | Evidence Locator | Program Evidence State | Next Promotion |
| --- | --- | --- | --- | --- | --- | --- |
| MACG-01 category and protected terms | one externally inspectable category meaning | Machine Authority + term-boundary owners | canonical category owner, protected terms, accepted ownership ADR | [`machine-authority.md`](../../docs/architecture/foundations/machine-authority.md), [`term-boundaries.md`](../../docs/architecture/foundations/term-boundaries.md), [ADR 0040](../../docs/decisions/0040-make-machine-authority-the-category-and-ioi-authority-the-portable-protocol.md) | promoted | keep public copy synchronized without duplicating definition |
| MACG-02 portable surface manifest | exact bytes and entitlement can be evaluated | IOI Authority Protocol owner | registered/content-addressed `ProtocolSurfaceManifest`, exact closure and hashes | [`ioi-authority-protocol.md` § Present Profile Status](../../docs/architecture/foundations/ioi-authority-protocol.md#present-profile-status) records none released | evidence_missing | register manifest contract, choose the minimal Core closure, freeze a candidate |
| MACG-03 canonicalization and signature domains | profile-wide deterministic byte and signature evidence | each contract owner + profile manifest | exact JCS/schema/hash/signature-domain vectors | [contract registry](../../docs/architecture/_meta/schemas/architecture-contract-registry.v1.json) plus [authority row](../../docs/architecture/_meta/canon-to-code-delta.md#the-delta-table); no profile closure | owner_reported | derive profile-wide vectors independently and bind them in the manifest |
| MACG-04 action decision and review evidence | Core served-path evidence | Core profile owner | served request/review/decision/step-up/continuation path and verifier | [`authority-and-access.md`](../../docs/architecture/foundations/objects/authority-and-access.md) implementation status; production review/grant minting remains incomplete | owner_reported | close production Core path and public runner |
| MACG-05 delegation, currentness, attenuation | Delegated semantic and consumption evidence | Delegated profile owner | signed chain, signed allocation closure, time/key/revocation inputs, atomic budgets | [`portable_authority.rs`](../../crates/services/src/wallet_network/portable_authority.rs) and [`portable_authority_state.rs`](../../crates/services/src/wallet_network/tests/portable_authority_state.rs); raw-verifier command `cargo test --locked -p ioi-services wallet_network::portable_authority::tests -- --nocapture` = 12 passed on 2026-08-30; signed portable closure still absent | first_party_verified | register/sign the allocation closure; freeze vectors and public verifier |
| MACG-06 exact-effect admission and consumption | Governed Effect served-path evidence for one declared surface | Governed Effect profile owner | served domain-derived effect, v2 admission, atomic consumption, finalizer fence | [`governed_authority.rs`](../../crates/node/src/bin/hypervisor_daemon_routes/governed_authority.rs); `cargo test --locked -p ioi-node --bin hypervisor-daemon governed_authority -- --nocapture` = 17 mechanism tests passed on 2026-08-30; the subject owner reports the qualified SCM route, but no standalone retained end-to-end route command is cited here | owner_reported | add an exact end-to-end route evidence locator, portable outer signature, declared/frozen effect surface, and extended coverage |
| MACG-07 outcome and reconciliation | outcome/ambiguity evidence contribution | receipt and daemon owners | linked invocation, failure/unknown, dead-claim, reconciliation, effect receipt evidence | [receipt-owner status](../../docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md) and [authority delta row](../../docs/architecture/_meta/canon-to-code-delta.md#the-delta-table) | owner_reported | freeze portable outcome/reconciliation contracts and adversarial cases |
| MACG-08 offline verifier and adversarial vectors | reproducible first-party verifier evidence | profile owner | clone-and-run verifier, positive/adversarial bundles, typed refusals | [`portable_authority.rs`](../../crates/services/src/wallet_network/portable_authority.rs); `cargo test --locked -p ioi-services wallet_network::portable_authority::tests -- --nocapture` = 12 passed on 2026-08-30; no public profile release or frozen bundle | first_party_verified | package without private state; pin all bytes in candidate manifest |
| MACG-09 clean-room and external implementations | specification-sufficiency and independent-parity evidence | governance + profile owners | clean-room twin, then organizationally independent implementation | [`authority/twin/README.md`](./protocols/authority/twin/README.md) records planned/not executed | evidence_missing | execute the twin packet, resolve spec gaps, recruit independent implementer |
| MACG-10 governance, licensing, release independence | externally inspectable stable-release process | governance/licensing owners | public change/objection/designation record, exact permissive artifact path, role separation | [governance implementation status](../../docs/architecture/foundations/protocol-governance-neutrality.md) and [ADR 0033](../../docs/decisions/0033-licensing-split-surface-and-license-manifest.md) | owner_reported | decide public artifact path, refine manifest/license, implement records and structural review |
| MACG-11 independent adopter demonstration | outside-operation and portable-exit evidence | complete profile + adoption owner | outside-operated issuer/PEP/verifier over one consequential effect with portable exit | [`ioi-authority-protocol.md` § Present Profile Status](../../docs/architecture/foundations/ioi-authority-protocol.md#present-profile-status) records the complete profile blocked | evidence_missing | run only after candidate manifests and runner are public |

No row unlocks a conformance claim. Only the canonical profile owner and an
exact released manifest can confer an entitlement after every applicable gate
closes.

## MAC-To-Gate Audit Map

| MAC Requirement | Profile Contribution | Required Artifact/Vector Family | Program Gate |
| --- | --- | --- | --- |
| MAC-1 canonical request | Core | request/review canonical bytes; field, representation, origin, and subject substitution | MACG-03, MACG-04 |
| MAC-2 decision/escalation | Core | deny/edit/step-up/approve/continuation lifecycle and imported-approval refusal | MACG-04 |
| MAC-3 signed bounded grant | Delegated | grant domains, complete bounded subject, key and signature substitution | MACG-03, MACG-05 |
| MAC-4 attenuation | Delegated | ancestry, holder issuance, cycles, depth, re-delegation, cumulative allocation | MACG-05 |
| MAC-5 currentness/revocation | Delegated | key rotation, signed revocation, time boundaries, stale/absent input | MACG-05 |
| MAC-6 consumable bounds | Delegated + Governed Effect | final call/budget race, idempotency substitution, crash/restart state delta | MACG-05, MACG-06 |
| MAC-7 domain-derived effect | Governed Effect | caller/effect substitution, batch membership, standing constraints | MACG-06 |
| MAC-8 final-PEP admission | Governed Effect | final currentness census, admission signature, alternate-finalizer bypass | MACG-06 |
| MAC-9 invocation separation | Governed Effect | admitted/non-invoked, invoked/unadmitted, exact lineage | MACG-06, MACG-07 |
| MAC-10 outcome/ambiguity | Governed Effect | known failure, partial/unknown, dead claim, reconciliation successor | MACG-07 |
| MAC-11 independent verification | every released profile | frozen manifest, offline inputs, runner, refusal parity, twin and outside parity | MACG-02, MACG-03, MACG-08, MACG-09 |
| MAC-12 portability/exit | Complete | replaceable roles, no hosted dependency, independent operator and export/exit | MACG-09, MACG-10, MACG-11 |

## Profile Work IDs

The canonical profile definitions and current posture live in
[`ioi-authority-protocol.md`](../../docs/architecture/foundations/ioi-authority-protocol.md#named-target-profiles).
This program tracks only research and promotion work:

| Work ID | Applies To | Program Deliverable | Gates |
| --- | --- | --- | --- |
| IAP-W01 | all profiles | register and freeze the minimal manifest contract and exact closure | MACG-02, MACG-03 |
| IAP-W02 | Core | close the production decision/review path and public deterministic runner | MACG-04, MACG-08 |
| IAP-W03 | Delegated | register the signed portable descendant-allocation closure | MACG-05 |
| IAP-W03A | Delegated + Governed Effect | define the provider adapter and prove one alternate provider against the same frozen behavior | MACG-05, MACG-06, MACG-09 |
| IAP-W04 | Governed Effect | freeze complete admission/outcome signatures and ambiguity/reconciliation linkage | MACG-06, MACG-07 |
| IAP-W05 | Governed Effect | declare SCM as the first narrow served effect surface and extend only through separately proved adapters | MACG-06, MACG-07 |
| IAP-W06 | all profiles | publish the clone-and-run verifier and adversarial bundles | MACG-03, MACG-08 |
| IAP-W07 | all profiles | execute isolated twin, separate codegen/transport, and outside implementation | MACG-09 |
| IAP-W08 | stable/Complete | operationalize governance/licensing/designation, outside effect, and portable exit | MACG-10, MACG-11 |

## Independent Reproduction And Conformance

The evidence ladder is:

```text
first-party unit/integration proof
  -> frozen public specification and manifest
  -> first-party-generated plus independently derived adversarial vectors
  -> procedurally isolated clean-room twin
  -> separate codegen and separate transport parity
  -> organizationally independent implementation
  -> outside-operated consequential-effect demonstration and portable exit
```

An in-session twin may prove specification clarity and vector agreement. It may
not claim organizational independence, external audit, neutral certification,
or adoption.

## Adoption Evidence

Track evidence that an outsider's rational move is adopt rather than fork or
ignore:

- time from clone to first deterministic verdict;
- number of non-IOI languages and transports passing each frozen profile;
- number of independently operated authority providers, PEPs, and verifiers;
- consequential effects protected by profile and effect class;
- refused substitution, replay, stale-revocation, overspend, and finalizer-
  bypass attempts;
- decision-to-final-PEP latency and revocation-propagation horizon;
- percentage of protected effects whose evidence was independently verified;
- successful export/exit demonstrations requiring no IOI-hosted dependency;
- breaking-change migrations completed inside the declared window; and
- unresolved external objections and time to recorded disposition.

Volume, GitHub stars, schema counts, internal tests, and self-issued badges are
not category leadership evidence by themselves.

## Work Order

1. Reconcile canonical status and remove every stale owner/conformance pointer.
2. Select and register the minimal Core `ProtocolSurfaceManifest` contract.
3. Close the production Core decision/review path and freeze its vectors.
4. Register a signed delegation-allocation closure without mutating grant v3.
5. Define a provider adapter and prove one alternate authority provider without
   importing wallet.network state or hosted discovery as protocol truth.
6. Package the existing raw-v3 verifier and qualified SCM governed-effect path
   behind public, deterministic profile commands.
7. Freeze portable admission/outcome signatures and reconciliation linkage.
8. Execute the clean-room twin packet; repair the specification, never teach
   the twin from first-party source.
9. Publish the candidate artifact under an explicit permissive license path and
   public change record.
10. Obtain organizationally independent parity.
11. Run the independently operated consequential-effect and portable-exit
    demonstration before promoting the complete profile.

## Promotion And Retirement Rule

When a program result changes doctrine, promote it through the owning canon or
an accepted ADR first. When it changes implementation truth, update the
canon-to-code delta and subject owner in the same change. When a profile is
released, the frozen manifest and public evidence—not this file—become the
claim source.

Retire this program when every remaining item is either promoted into a durable
owner or explicitly rejected with a recorded reason. Archive it rather than
leaving a completed program as shadow canon.

## Non-Goals

- Rebranding the whole IOI architecture registry as one protocol.
- Requiring the complete IOI stack for compatibility.
- Weakening Machine Authority so a Core-only implementation can claim it.
- Naming competitors in canonical or public category doctrine.
- Treating internal clean-room work as an external audit.
- Declaring a stable profile before the runnable artifact exists.
- Making certification, marks, settlement, legal status, or effect correctness
  follow automatically from protocol parity.
