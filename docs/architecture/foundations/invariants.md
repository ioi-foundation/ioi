# Canonical Invariant Registry

Status: canonical architecture authority.
Doctrine status: canonical
Implementation status: mixed (each invariant lists where it is enforced today)
Canonical owner: this file for the canonical one-sentence wording of cross-cutting invariants; subject owners apply them.
Supersedes: repeated restatements of these invariants across foundations, components, and domains docs when wordings drift.
Superseded by: none.
Last alignment pass: 2026-07-19.

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
and prove presence; only an AuthorityGrant conveys power. Authentication and
recovery never widen, reconstruct, or silently preserve consequential
authority.
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

**INV-9 — Receipts bind boundary facts; assurance stages stay distinct.**
Consequential effects mint receipts bound to declared request, policy, actor,
and effect facts; event streams are observability and analytics are improvement
signals. A receipt proves only the fact it binds. Evidence, verification,
acceptance, adjudication, and settlement are separate states; later
institutional or economic disposition does not automatically increase factual
certainty. Neither events, analytics, self-report, nor a receipt alone may
substitute for the state actually claimed.
Owner application: [`../components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md).

**INV-10 — The quadrant.** Local/domain governance owns local policy, and the
applicable authority provider issues authority under that policy.
wallet.network owns portable principal-to-approval-authority binding and is
mandatory for portable delegated authority and designated high-risk external
effects; it does not absorb ordinary deployment-local governance. Agentgres
owns admitted operational truth; storage backends own payload bytes; a
selected settlement service, including IOI L1 when enrolled, settles triggered
public commitments. No layer absorbs another's role.
Owner application: [`../components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md),
[`../components/agentgres/doctrine.md`](../components/agentgres/doctrine.md),
[`../components/storage-backends/doctrine.md`](../components/storage-backends/doctrine.md).

**INV-11 — Sparse settlement.** When selected, IOI L1 stores commitments,
rights, disputes, and settlement triggers — never per-call operational data.
Model calls, tool calls, workflow steps, and Agentgres writes are not L1
transactions.
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

**INV-20 — Pairing proves possession, not authority or competence.** A local-
agent pairing may authenticate control of a candidate key, process, or return
channel and permit bounded bootstrap submissions; it grants no room membership,
context, capability, authority, budget, reputation, payout right, marketplace
exposure, or assurance about the agent's claims. Those states require their
own admission, lease, evidence, verification, acceptance, and economic paths.
Owner application: [`../components/hypervisor/identity-access-and-metering.md`](../components/hypervisor/identity-access-and-metering.md),
[`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md),
[`security-privacy-policy-invariants.md`](./security-privacy-policy-invariants.md).

**INV-21 — Constitution outranks improvement.** Ordinary execution and upgrade
paths may propose but cannot self-commit changes to protected purpose,
authority ceilings, amendment gates, ordering/finality, oracle, lifecycle,
shutdown, or revocation boundaries.
Owner application: [`governed-autonomous-systems.md`](./governed-autonomous-systems.md),
[`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md).

**INV-22 — One system, governed node membership.** One logical autonomous
system retains its identity across node churn and may place useful work across
its admitted members; adding or replacing a node only extends that system
through admitted, scoped membership and neither clones the system, awards
work, nor silently widens authority.
Owner application: [`governed-autonomous-systems.md`](./governed-autonomous-systems.md),
[`domain-kernels.md`](./domain-kernels.md).

**INV-23 — Replication is not consensus.** Node count, durability quorum,
failover redundancy, and shared administration do not change authority
distribution, party independence, consensus, or public-finality claims.
Owner application: [`canonical-enums.md`](./canonical-enums.md),
[`../components/agentgres/doctrine.md`](../components/agentgres/doctrine.md).

**INV-24 — Failover fences before promotion and effect.** A replacement writer
may become active only after membership validation, state-root catch-up, an
immutable epoch transition admitted by durable continuity CAS, and fencing or
safe wait-out of the prior writer. Transition timing evidence is internally
ordered and fresh, and its exact authority-grant refs are nonempty and unique.
Immutable transition truth precedes its active projection; restart replay
rejects forks, gaps, tamper, and orphan projections before rebuilding the head.
Every System-scoped consequential resource
then checks that the trusted executing node is the active writer, plus that
active transition, revocation epoch, owner-derived resource and effect identity,
timing evidence, and required read posture before its invoker;
an ambiguous partition or stale field fails closed.
Owner application: [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md),
[`../components/agentgres/doctrine.md`](../components/agentgres/doctrine.md).

**INV-25 — Oracle input remains evidence.** External observations remain
attributed, freshness-bounded, contradictory, and challengeable evidence.
Their declared, correlation-aware composition may justify a defeasible scoped
operational determination and bounded consequence; no signature, receipt,
vote, verifier, consensus, acceptance, adjudication, or settlement
independently establishes universal external-world truth. Consequential use
requires both the current exact-head oracle-evidence decision and the current
exact-head domain assertion-admission decision, with an unexpired oracle
decision, active profile and sources/verifiers, a domain decision of
`admitted`, and matching oracle receipt, assertion commitment, fact class,
applicability, and consequence scope revalidated at the effect boundary. A
rejected or superseded domain-admission head blocks the effect even if the
oracle decision remains active.
Owner application: [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md),
[`domain-ontologies-and-data-recipes.md`](./domain-ontologies-and-data-recipes.md).

**INV-26 — Succession preserves bounds.** Succession rotates or reissues
governed responsibility inside the active constitution; absence, death,
incapacity, dissolution, key loss, or adoption never grants broader purpose or
power.
Owner application: [`governed-autonomous-systems.md`](./governed-autonomous-systems.md),
[`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md).

**INV-27 — Network assurance is opt-in and specific.** Compatibility,
connection, and shared security are distinct; a system may claim only the IOI
Network services and assurance it explicitly enrolled in and evidenced, and
local L0 work owes no ambient network toll.
Owner application: [`ioi-l1-mainnet.md`](./ioi-l1-mainnet.md),
[`economic-flywheel-and-pricing-boundaries.md`](./economic-flywheel-and-pricing-boundaries.md).

**INV-28 — Persistence remains externally bounded.** Self-preservation,
replication, resource acquisition, code propagation, recovery, and successor
activation remain subordinate to constitutional ceilings, governed membership,
external revocation, and terminal decommission semantics.
Owner application: [`governed-autonomous-systems.md`](./governed-autonomous-systems.md),
[`verifiable-bounded-agency.md`](./verifiable-bounded-agency.md).

**INV-29 — Intelligent blockchains require cryptographic continuity.** Every
admitted operation or batch in a system claiming the intelligent-blockchain
classification binds a monotonic sequence, expected predecessor commitment,
operation/batch commitment, admission signature or proof, resulting state root,
and receipt root. A bounded autonomous application without this verifiable
commitment chain is not relabeled a blockchain; consensus and tokens remain
optional.
Owner application: [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md),
[`domain-kernels.md`](./domain-kernels.md).

**INV-30 — Cooperation is explicitly conditional.** A sovereign system is
complete without federation, marketplace participation, external contribution,
or IOI Network enrollment. Discovery, a shared goal, room participation, a task
offer, a message, or a terms proposal creates no obligation, authority,
executable award, access right, reputation, or payout. Cross-domain work binds
only when each required party's governed decision accepts the exact terms root
and the required participant, work-claim, context, resource, budget, and
authority leases are admitted. A party may withhold its raw private valuation;
amendments require new acceptance and never retroactively rewrite admitted
work.
Owner application: [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md),
[`aiip.md`](./aiip.md),
[`../domains/ioi-ai/collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md),
[`economic-flywheel-and-pricing-boundaries.md`](./economic-flywheel-and-pricing-boundaries.md).

**INV-31 — Attribution is not allocation.** A contribution record or receipt
may establish who supplied declared work under which terms; it does not prove
causality, marginal value, acceptance, reward eligibility, or payout by itself.
Economic or non-economic consideration follows only the accepted terms,
contribution policy, verification and acceptance or adjudication path, and
settlement decision in force when the work was awarded.
Owner application: [`../domains/marketplace-neutrality.md`](../domains/marketplace-neutrality.md),
[`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md),
[`../components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md).

**INV-32 — Coordination follows the sovereignty boundary.** Replication,
failover, and useful distributed work among admitted members of one
`system_id` use native L0 membership, assignment, work-lease, evidence,
admission, and embodied-runtime contracts; they are not AIIP. AIIP begins only
when work crosses between independently governed systems with separate
authority, operational truth, risk, and exit boundaries. Reusing common
envelope or receipt conventions does not change that boundary.
Owner application: [`governed-autonomous-systems.md`](./governed-autonomous-systems.md),
[`domain-kernels.md`](./domain-kernels.md),
[`aiip.md`](./aiip.md).

**INV-33 — Improvement evidence never self-promotes.** A candidate may propose
its own or its pursuit method's successor, but it may not control the sealed
evidence, evaluator, resource or statistical meter, promotion authority, or
rollback, recall, containment, compensation, and residual-effect path by which
that successor becomes canonical. Adaptive or multi-epoch search binds a finite
`ImprovementCampaign`; ordinary one-shot upgrades may remain direct proposals.
Owner application:
[`bounded-recursive-improvement.md`](./bounded-recursive-improvement.md),
[`../components/daemon-runtime/improvement-governance-gates.md`](../components/daemon-runtime/improvement-governance-gates.md).

**INV-34 — Physical intelligence proposes; independently assured local control
realizes.** A model, planner, behavior graph, teleoperator, active component,
runtime graph, transport, fleet allocation, or spacetime reservation never
becomes actuator authority by itself. Every physical action binds fresh
authority, an exact resource fence, and an admitted mission and safety envelope,
then crosses a locally enforceable safety monitor and command switch whose
recovery and emergency behavior do not depend on the candidate generator,
network, wallet, ledger, or remote approval path.
Owner application:
[`physical-action-safety.md`](./physical-action-safety.md),
[`../components/daemon-runtime/embodied-runtime.md`](../components/daemon-runtime/embodied-runtime.md).

**INV-35 — Shared lifecycle mechanics never seize domain ownership.** GoalRun,
GoalGroundingLoop, WorkRun, AutomationRun, HarnessInvocation, ContextCell, and
external-handle owners keep distinct legal phases and transition authorities.
A shared lifecycle kernel may commit exact-head append-only transition and
child-reference facts, rebuild active projections, and derive cancellation
fanout, but it may not flatten those phase families, mutate a child through a
parent reference, or claim cancellation complete without owner-issued drain,
fence, timeout, compensation, reconciliation, and completion receipts. A
snapshot remains bound to immutable archived records and retained receipt
lineage.
Owner application:
[`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md),
[`../components/daemon-runtime/doctrine.md`](../components/daemon-runtime/doctrine.md),
[`../components/daemon-runtime/api.md`](../components/daemon-runtime/api.md).

**INV-36 — Temporal evidence is proposition-scoped and conditional.** Every
consequential temporal claim binds an exact `TemporalVerificationProfile` and
recomputable `TemporalValidityEvaluation`; a point timestamp, signature,
clock-health flag, or owner epoch cannot substitute for the requested
proposition, rollback resistance requires a namespace floor outside the
declared rollback domain or fresh independent re-anchoring, and the evaluation
supplies evidence without issuing authority or admitting the final effect.
Owner application:
[`security-privacy-policy-invariants.md`](./security-privacy-policy-invariants.md),
[`../components/daemon-runtime/platform-operability.md`](../components/daemon-runtime/platform-operability.md).

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
