# decentralized.cloud Parked Future

Status: parked future canon note.
Canonical owner: this file for the current non-canonical status of
`decentralized.cloud` and its boundary with Hypervisor direct provider
integrations.
Supersedes: product prose that makes `decentralized.cloud` a mandatory cloud
gateway, DePIN gateway, privacy proof, execution owner, or present canon spine.
Superseded by: none.
Last alignment pass: 2026-06-14.

## Canonical Definition

`decentralized.cloud` is not part of the present canon spine or near-term
product architecture.

It is parked as a possible future public cloud layer:

```text
future decentralized.cloud
  provider marketplace
  P2P / PQ-aware cloud routing layer
  compute and storage receipt explorer
  cloud/provider reputation surface
  public provider catalog
  infrastructure marketplace with bonds, SLAs, and disputes
```

Current canon should not require Hypervisor, Wallet, or agents to route
through `decentralized.cloud`.

## Present Canon

Hypervisor has direct provider integrations for cloud compute, storage, GPUs,
bandwidth, confidential compute, DePIN, hyperscalers, customer cloud,
enterprise clusters, local machines, decentralized storage networks, and
user-specified providers.

Hypervisor may route workloads through:

- local machines and homelabs;
- user-owned or org-owned AWS, Google Cloud, Azure, and other cloud accounts;
- enterprise Kubernetes, KubeVirt, VMware, Proxmox, Nutanix, or bare-metal
  estates;
- hyperscaler confidential-compute services;
- cloud GPU providers;
- DePIN compute markets;
- decentralized storage networks;
- provider-specific GPU or storage markets;
- user-specified provider routes.

## Minimal Implementation Objects

### CloudRoute

`CloudRoute` is owned in detail by
[`hypervisor/providers-and-environments.md`](../../components/hypervisor/providers-and-environments.md).
It is the Hypervisor object for selecting compute, storage, GPU, network, or
confidential execution infrastructure.

### CloudCandidate

`CloudCandidate` is a candidate from a direct provider connector, local
inventory, customer cloud, DePIN market, decentralized storage network,
hyperscaler, cloud GPU provider, enterprise cluster, or user-specified route.
It is not authority, execution, storage truth, privacy proof, or approval.

## Boundary Rule

```text
Provider candidates are proposed.
wallet.network authorizes spend, provider access, secret release, and policy.
Hypervisor Daemon or approved provider connector deploys/runs workload.
Providers supply resources.
Agentgres records receipts and state refs.
Storage backends hold bytes.
IOI L1 settles only by trigger.
```

## Conformance Checks

- Hypervisor must support direct provider mode without `decentralized.cloud`.
- A cloud/provider catalog is not a compute provider.
- A cheap DePIN GPU route is not a privacy guarantee.
- Provider selection cannot release secrets or protected plaintext without
  wallet.network authority and the declared cTEE, TEE, local, customer-cloud,
  or provider-trust posture.
- Storage availability cannot be treated as payload meaning, artifact truth, or
  restore validity without Agentgres artifact refs, state roots, and receipts.

## Anti-Patterns

Reject these:

1. Promoting parked future `decentralized.cloud` into a mandatory gateway.
2. Treating provider catalogs or cloud routers as Hypervisor execution owners.
3. Treating Akash, Filecoin, AWS, GCP, local nodes, or customer VPCs as
   interchangeable resources without privacy, trust, region, storage,
   persistence, and receipt differences.
4. Treating hardware confidential compute as magic rather than an execution
   lane with attestation, workload, side-channel, key-release, and provider
   assumptions.
5. Treating cTEE as ordinary encryption at rest.

## Related Canon

- [`README.md`](./README.md)
- [`../../components/hypervisor/providers-and-environments.md`](../../components/hypervisor/providers-and-environments.md)
- [`../../components/daemon-runtime/private-workspace-ctee.md`](../../components/daemon-runtime/private-workspace-ctee.md)
- [`../../components/daemon-runtime/runtime-nodes-tee-depin.md`](../../components/daemon-runtime/runtime-nodes-tee-depin.md)
- [`../../components/agentgres/artifact-ref-plane.md`](../../components/agentgres/artifact-ref-plane.md)
- [`../../components/storage-backends/doctrine.md`](../../components/storage-backends/doctrine.md)
