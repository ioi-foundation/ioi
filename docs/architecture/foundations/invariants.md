# Canonical Invariant Registry

Status: canonical architecture authority.
Doctrine status: canonical
Implementation status: mixed (each invariant lists where it is enforced today)
Canonical owner: this file for the canonical one-sentence wording of cross-cutting invariants; subject owners apply them.
Supersedes: repeated restatements of these invariants across foundations, components, and domains docs when wordings drift.
Superseded by: none.
Last alignment pass: 2026-07-11.

## Purpose

The same boundary invariants used to be restated, with drifting wording, in
four to seven files each. This registry owns the canonical wording. Other docs
cite an invariant by ID (`INV-*`) and add only their local application; where a
subject applies an invariant differently, the subject doc says so explicitly
next to the citation. If a restatement elsewhere conflicts with this file,
this file wins; update the other doc.

`security-privacy-policy-invariants.md` remains the security-domain
application of this registry; its wording defers to the IDs below.

## The Invariants

**INV-1 — No ambient authority.** No worker, model, tool, connector, harness,
or surface holds standing power; every consequential action requires a scoped,
expiring, revocable grant bound to the exact request.
Owner application: [`../components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md).

**INV-2 — Leases, not secrets.** Actors receive operation-scoped authority
leases; raw credentials, keys, and secrets stay in custody (wallet.network or
daemon-sealed vaults) and are never handed to the acting process.
Owner application: [`../components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md),
[`../components/hypervisor/byo-provider-plane.md`](../components/hypervisor/byo-provider-plane.md).

**INV-3 — AuthFactor ≠ AuthorityGrant.** Authentication factors open accounts
and prove presence; only an AuthorityGrant conveys power. Login methods never
widen authority.
Owner application: [`../components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md).

**INV-4 — Two-tier capabilities.** `prim:*` names what a runtime can
physically do; `scope:*` names what a delegated subject is authorized to do.
The tiers never collapse into one permission list.
Owner application: [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md).

**INV-5 — No self-granted authority.** Autonomous systems may propose changes
to their own policies, modules, routes, or contracts, but a proposal never
widens authority by itself; widening requires the governed approval path and
is receipted.
Owner application: [`governed-autonomous-systems.md`](./governed-autonomous-systems.md),
[`verifiable-bounded-agency.md`](./verifiable-bounded-agency.md).

**INV-6 — Training is not authority.** Training, tuning, distillation, and
promotion improve capability and eligibility evidence; they never grant power.
A better-trained worker still crosses the same authority gates.
Owner application: [`worker-training-lifecycle.md`](./worker-training-lifecycle.md).

**INV-7 — Candidates propose; authority authorizes.** Candidate intelligence
(routes, venues, resources, placements, quotes) is advisory evidence. It never
executes, holds custody, or substitutes for a grant.
Owner application: [`../domains/decentralized/README.md`](../domains/decentralized/README.md),
[`../domains/decentralized/cloud.md`](../domains/decentralized/cloud.md).

**INV-8 — Provider state is evidence; admission is truth.** Provider-native
ids, statuses, snapshots, and bills are recorded as evidence. Restore truth
and operational truth are only what the daemon/Agentgres admits (e.g.
daemon-admitted sha256 state roots).
Owner application: [`../components/hypervisor/byo-provider-plane.md`](../components/hypervisor/byo-provider-plane.md),
[`../components/storage-backends/doctrine.md`](../components/storage-backends/doctrine.md).

**INV-9 — Receipts bind boundary facts; assurance is progressive.**
Consequential effects mint receipts bound to declared request, policy, actor,
and effect facts; event streams are observability and analytics are improvement
signals. A receipt proves only the fact it binds. Evidence, verification,
acceptance, adjudication, and settlement are separate, progressively stronger
states; neither events, analytics, self-report, nor a receipt alone may
substitute for the state actually claimed.
Owner application: [`../components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md).

**INV-10 — The quadrant.** wallet.network owns authority; Agentgres owns
admitted operational truth; storage backends own payload bytes; IOI L1 settles
triggered public commitments. No layer absorbs another's role.
Owner application: [`../components/agentgres/doctrine.md`](../components/agentgres/doctrine.md),
[`../components/storage-backends/doctrine.md`](../components/storage-backends/doctrine.md).

**INV-11 — Sparse settlement.** IOI L1 stores commitments, rights, disputes,
and settlement triggers — never per-call operational data. Model calls, tool
calls, workflow steps, and Agentgres writes are not L1 transactions.
Owner application: [`ioi-l1-mainnet.md`](./ioi-l1-mainnet.md).

**INV-12 — Availability is not restore truth.** That bytes exist on a backend
(or a provider claims a snapshot) proves availability only; restore admits
solely after fetch + hash + decrypt + state-root validation against admitted
truth.
Owner application: [`../components/storage-backends/doctrine.md`](../components/storage-backends/doctrine.md),
[`../components/agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md).

**INV-13 — Foundry builds; Hypervisor executes; Governance promotes.**
Capability production (models, workers, evals, packages) is Foundry's lane;
execution is the daemon's; promotion/rollback of learned or built artifacts is
a governed, receipted release path. No lane shortcuts another.
Owner application: [`../components/hypervisor/foundry.md`](../components/hypervisor/foundry.md),
[`../components/daemon-runtime/improvement-governance-gates.md`](../components/daemon-runtime/improvement-governance-gates.md).

**INV-14 — Honest posture, fail closed.** Surfaces and adapters never claim a
state they cannot prove: unpriced is skipped rather than estimated, unproven
readiness blocks with a named reason, simulators label themselves, and missing
authority/credentials/budget refuse loudly and are receipted.
Owner application: [`../components/hypervisor/byo-provider-plane.md`](../components/hypervisor/byo-provider-plane.md),
[`security-privacy-policy-invariants.md`](./security-privacy-policy-invariants.md).

**INV-15 — No implicit global collaboration truth.** Every OutcomeRoom names
one hosted admission domain or a versioned federated admission policy with
ordering, merge, conflict, adjudication, and failover semantics. Each domain
retains local truth; boards, chat, inboxes, leaderboards, and shared projections
are never a universal mutable database by implication.
Owner application: [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md),
[`../components/agentgres/doctrine.md`](../components/agentgres/doctrine.md),
[`aiip.md`](./aiip.md).

**INV-16 — Participation never widens privacy or authority.** Contributor
scope, room visibility, network discovery, and cross-domain membership cannot
declassify data, broaden a context view, grant a capability, weaken custody, or
change retention. Every participant and route must satisfy the intersection of
room policy, local/domain policy, and its own authority/privacy posture.
Owner application: [`security-privacy-policy-invariants.md`](./security-privacy-policy-invariants.md),
[`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md).

**INV-17 — Participant input is untrusted until admitted.** Messages,
artifacts, patches, claims, ontology mappings, evaluator changes, and executable
results from participants remain tainted proposals until policy, isolation,
verification, and the declared room/domain admission path accept them. Shared
agreement is evidence, never authority or truth by itself.
Owner application: [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md),
[`../components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md).

**INV-18 — Multiplicity is not independence.** Several models, workers,
runtime nodes, providers, clouds, or keys controlled by one principal remain
one party when that principal controls authority, revocation, truth,
verification, risk, or settlement. Multi-party claims require disclosed and
separate accountable principals and affiliations.
Owner application: [`mixture-of-workers.md`](./mixture-of-workers.md),
[`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md).

**INV-19 — Complexity collapses when boundaries do.** One user, one process,
one local authority context, one minimal semantic contract, and no public
settlement remain first-class. OutcomeRoom, federation, marketplace,
multi-worker, ontology breadth, and L1 machinery appear only when the work's
actual trust, coordination, or economic boundary requires them.
Owner application: [`governed-autonomous-systems.md`](./governed-autonomous-systems.md),
[`../components/hypervisor/core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md).

## Citation Rule

When a doc needs one of these invariants, it writes one line — the ID, an
optional shortened restatement, and its local application — and links here.
Docs must not re-derive canonical wording. Local nuance (a stricter local
bound, a domain-specific consequence) belongs next to the citation, clearly
marked as local.

## Related Canon

- [`security-privacy-policy-invariants.md`](./security-privacy-policy-invariants.md) — security-domain application set.
- [`canonical-enums.md`](./canonical-enums.md) — canonical enumerations (risk classes, venues, account kinds).
- [`../_meta/current-canon-defaults.md`](../_meta/current-canon-defaults.md) — cross-owner defaults digest.
