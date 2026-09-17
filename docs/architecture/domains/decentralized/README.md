# decentralized.* Domain Pack — moved out of this repository

Status: archived forwarding record.
Canonical owner: none in this repository. The `decentralized.*` product lanes and
their specifications moved to their own repository on 2026-09-17; this directory
retains only the record of that move so the links that pointed here still resolve.
Supersedes: nothing.
Superseded by: the `decentralized-cloud` repository (local, unpublished).
Last alignment pass: 2026-09-17.
Doctrine status: archived
Implementation status: planned

## What moved, and where

`apps/decentralized-cloud/` and this directory's specification tree — the cloud
pack, `cloud.md`, `exchange.md` and `trade.md` — were extracted with their full
history into a separate repository, together with the decentralized brand tokens
that had exactly one consumer. Nothing in IOI depends on any of it.

## Why

The owner's decision was to **hold off on building the candidate engines and use
the underlying providers directly** until measured traffic justifies owning the
layer above them. The reasoning:

- Fees accrue where authority is exercised and where placement is decided — the
  wallet approves and signs, Hypervisor selects a candidate. A candidate engine
  only proposes, and both of those surfaces are already being built.
- `RouteCandidate` and `CandidateEvidence` are the durable half; whoever produces
  a candidate is swappable by construction. Building an engine first meant
  building the replaceable, expensive half before the permanent one.
- Using DePIN does not imply owning the intelligence layer over it. That margin is
  already reachable through Hypervisor's own provider adapters.

## What carries the work in IOI now

Nothing had to be written. The daemon's cloud-candidate plane
(`crates/node/src/bin/hypervisor_daemon_routes/cloud_candidate_routes.rs`, renamed
from `decentralized_cloud_routes.rs` on the same day) enumerated thirteen candidate
sources, of which `decentralized.cloud` was one — permanently reporting
`candidate_source_unavailable` with reason `network_adapter_absent`, because the
engine was never live. That declaration is gone. The sources that actually propose
remain and are unchanged:

| Kind | Sources |
|---|---|
| DePIN | Akash (`depin_market`), Vast, RunPod |
| Centralized cloud | AWS, GCP, Azure, Lambda |
| Cluster | Kubernetes / KubeVirt |
| Storage | `storage_network` (Filecoin/CAS) |
| Local | `customer_inventory`, `direct_provider` |

The owners of that behaviour are
[`../../components/hypervisor/byo-provider-plane.md`](../../components/hypervisor/byo-provider-plane.md)
and
[`../../components/hypervisor/providers-and-environments.md`](../../components/hypervisor/providers-and-environments.md).

## When this comes back

Measurements, not feelings:

- **Cloud.** When optimized-placement volume makes provider margin exceed the cost
  of running an engine, or when no provider will expose the custody, failover and
  restore evidence required to admit a candidate.
- **Exchange.** When wallet-authorized swap flow is large enough that aggregator
  pricing costs more than running routing, or when aggregators cannot supply the
  evidence fields policy needs to approve a candidate.

Until then the wallet's exchange and trade actions are served by third-party
aggregators as candidate sources, which is what
[`../../components/wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md)
always allowed: candidates may come from pools, routers, solvers, aggregators or
the user, and no named engine was ever mandatory.
