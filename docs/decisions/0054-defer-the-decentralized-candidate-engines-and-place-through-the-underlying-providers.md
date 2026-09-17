# ADR 0054: Defer The decentralized.* Candidate Engines, Place Through The Underlying Providers, And Move The Product Out Of This Repository

Status: Accepted

Date: 2026-09-17

Supersedes: [ADR 0051](./0051-decentralized-cloud-public-face-job-primitive-and-supply-registry.md)
(the public face, job primitive and supply registry it accepted are deferred with the product).

## Context

`decentralized.cloud` and `decentralized.exchange` were specified as first-party
candidate engines: one proposing infrastructure capacity, the other proposing swap
routes. ADR 0051 accepted a branded public face, a job primitive and a supply
registry for the first. The console, control plane, brand and specification tree
were being built inside this repository.

Three facts made the cost visible.

**The engines were never the revenue.** Fees accrue where authority is exercised
and where placement is decided. wallet.network approves and signs; Hypervisor
selects a candidate into its own placement decision, and "managed" capacity is what
makes IOI or a partner provider-of-record. Both surfaces are already being built. A
candidate engine only *proposes* — and canon already said so, in these words: a
candidate is not authority, it cannot provision, release credentials, expose
ingress or claim custody, and it expires.

**The engine was the replaceable half.** `RouteCandidate` and `CandidateEvidence`
are the durable interfaces; whoever produces a candidate is swappable by
construction. Building the engine first meant building the replaceable half — the
expensive half — before the permanent one.

**It was never live, and the daemon already said so.** The cloud-candidate plane
enumerated thirteen candidate sources. `decentralized.cloud` was one of them, and
it reported `candidate_source_unavailable` with reason `network_adapter_absent` on
every call. The eight provider adapters beside it — Akash, Vast, RunPod, AWS, GCP,
Azure, Lambda, Kubernetes — are what actually propose, together with local
inventory and the storage backends. The substitution this ADR accepts had already
happened in the code; only the name and the product had not caught up.

Against that, the surface-area cost was real and recent: a brand split had just
been paid for to stop IOI's identity blurring, and standing up `.cloud`, `.exchange`
and `.trade` as products would have re-created the problem with three more sites,
docs sets, adapter registries and support surfaces.

## Decision

1. **Defer both engines.** IOI does not build `decentralized.cloud` or
   `decentralized.exchange`. Placement uses the underlying DePIN and centralized
   cloud integrations directly. Wallet-authorized exchange and trade actions use
   third-party aggregators as candidate sources — which
   [`wallet-network/doctrine.md`](../architecture/components/wallet-network/doctrine.md)
   always permitted, since route candidates may come from pools, routers, solvers,
   aggregators or the user and no named engine was ever mandatory.

2. **Move the product out of this repository.** `apps/decentralized-cloud/` and
   `docs/architecture/domains/decentralized/` were extracted with their full
   history into a separate repository, along with the sixteen decentralized brand
   tokens whose only consumer was the deleted console. Four short archived
   forwarding records remain in this repository so existing links resolve and a
   reader finds the decision where they look for the doctrine.

3. **Name the plane for what it is.** `decentralized_cloud_routes.rs` is renamed
   `cloud_candidate_routes.rs`, its never-live `decentralized.cloud` source
   declaration is removed, and its canonical doctrine owner becomes
   [`byo-provider-plane.md`](../architecture/components/hypervisor/byo-provider-plane.md).
   The routes themselves (`/v1/hypervisor/cloud-candidates/*`) are unchanged: this
   is a rename and a deletion of a dead declaration, not a behaviour change.

4. **An in-wallet swap does not wait on this.** The wallet is the cockpit, and
   exchange and trade are first-class wallet actions. Sourcing candidates from
   aggregators is the specified product, not a compromise version of it.

5. **Re-entry is a measurement, not a feeling.** Build the cloud engine when
   optimized-placement volume makes provider margin exceed the cost of running it,
   **or** when no provider will expose the custody, failover and restore evidence
   required to admit a candidate. Build the exchange engine when wallet-authorized
   swap flow is large enough that aggregator pricing costs more than running
   routing, **or** when aggregators cannot supply the evidence fields policy needs
   to approve a candidate. Both are visible from the wallet and the daemon.

## Consequences

- **Nothing had to be written to replace it.** The candidate plane, placement,
  failover, spend reconciliation and the eight provider adapters are untouched and
  keep serving the same routes.
- **One roadmap claim becomes untrue where it is published.** Any milestone
  presenting exchange or trade candidate clients as *active* must move to planned
  or gated. That data is not in this repository and is not changed by this ADR.
- **R-18 changes owner, not subject.** The mutation-event coverage finding on
  `handle_cloud_job_execute` was the decentralized-cloud program's. Its handler and
  module stayed; the program did not. It is re-owned to the MVP finish-line program
  rather than left unowned (private register R-182).
- **ADR 0051's public face, job primitive and supply registry are deferred**, not
  refuted. The boundaries it drew — never a second spine, never an authority layer
  — are what any candidate source is still held to, whoever produces it.
- **The shipped-products register drops to six lanes.** decentralized.cloud was
  registered there at `development_only`; it is removed with the workspace.
- **Deferral stays cheap.** Because switching candidate sources is designed to be
  cheap, this decision is reversible in a way that launching the products would
  not have been.
