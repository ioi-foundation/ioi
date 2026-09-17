# decentralized.cloud — moved out of this repository

Status: archived forwarding record.
Canonical owner: none in this repository. decentralized.cloud moved to its own repository on
2026-09-17 and is a deferred product; this file retains the record of that move so
links which pointed here still resolve.
Supersedes: nothing.
Superseded by: the `decentralized-cloud` repository (local, unpublished), and for
the behaviour IOI kept, the provider plane owners named below.
Last alignment pass: 2026-09-17.
Doctrine status: archived
Implementation status: planned

decentralized.cloud was specified here as the cloud resource-intelligence product — console, control plane, provider abstraction, placement and supply.
It was never a live engine in this estate: no external candidate API was called and
no price was ever invented on its behalf.

The decision, the substitution and the re-entry triggers are recorded once, in
[`README.md`](./README.md). The short version: IOI holds off on building the
engine and uses the underlying providers directly, because a candidate engine only
proposes while fees accrue where authority is exercised and where placement is
decided — and both of those surfaces already exist.

What carries this work in IOI now:

- Placement, candidates and provider adapters —
  [`../../components/hypervisor/byo-provider-plane.md`](../../components/hypervisor/byo-provider-plane.md)
- Wallet-authorized exchange and trade actions, sourced from third-party
  aggregators as candidates —
  [`../../components/wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md)
