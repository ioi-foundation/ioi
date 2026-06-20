# decentralized.* Domain Pack

Status: alpha canon architecture doctrine.
Canonical owner: this directory for the `decentralized.*` product/domain lanes
and their boundaries with wallet.network, Hypervisor, Agentgres, storage
backends, and IOI L1.
Supersedes: product prose that treats `decentralized.exchange`,
`decentralized.trade`, route-intelligence services, or venue-intelligence
services as authority layers, custody owners, execution owners, mandatory
gateways, or trust roots.
Superseded by: none.
Last alignment pass: 2026-06-14.

## Canonical Definition

The active `decentralized.*` canon has two Wallet-consumed
route-intelligence engines:

```text
decentralized.exchange
  route liquidity / convert assets

decentralized.trade
  route exposure / manage positions and event markets
```

They are not wallets, brokers, custodians, chains, liquidity owners, settlement
layers, or required destination UIs. They expose API/RPC/SDK candidate
services that Wallet, Hypervisor, agents, and third-party clients may consume.

Wallet is the user-facing authority cockpit. `decentralized.exchange` and
`decentralized.trade` may have docs, explorers, adapter registries, or
lightweight standalone surfaces, but the canonical Wallet user does not need to
leave Wallet to exchange or trade.

```text
Candidates are proposed.
wallet.network authorizes.
Hypervisor executes autonomous work when runtime work is involved.
Venues, pools, chains, and providers perform.
Agentgres records admitted truth.
IOI L1 settles only triggered public, economic, dispute, registry,
rights, reputation, or cross-domain commitments.
```

Hypervisor canon uses direct provider integrations for cloud compute, storage,
GPUs, confidential compute, DePIN, local machines, customer cloud, enterprise
clusters, decentralized storage networks, and user-specified providers.

## Files

- [`exchange.md`](./exchange.md): `decentralized.exchange`, spot/cross-chain
  route sources, `RouteCandidate`, exchange receipts, and exchange
  anti-patterns.
- [`trade.md`](./trade.md): `decentralized.trade`, spot orders, perps,
  leverage, margin, prediction markets, event contracts, position lifecycle,
  `TradeIntent`, `PredictionIntent`, `PositionReceipt`, `PredictionReceipt`,
  and agent-trading restrictions.
## Owns

This directory owns:

- the meaning of the `decentralized.*` names;
- route and venue-intelligence boundaries for `decentralized.exchange` and
  `decentralized.trade`;
- the route-intelligence / venue-intelligence engine boundary;
- cross-lane proposal/authority/execution/truth/settlement boundaries;
- route-source and venue-adapter non-ownership doctrine;
- anti-patterns for treating route/venue intelligence engines as authority,
  custody, or required user destinations.

## Does Not Own

This directory does not own:

- wallet authority, keys, policies, grants, approvals, or signatures;
- liquidity, venue execution, derivatives mechanics, or chain finality;
- Hypervisor execution semantics;
- Hypervisor provider connector implementations;
- Agentgres operation admission or canonical operational truth;
- storage payload meaning, lifecycle, or restore validity;
- IOI L1 settlement truth.

## Boundary Rule

```text
decentralized.exchange
  exposes route-intelligence and proposes asset-conversion candidates

decentralized.trade
  exposes venue/market intelligence and proposes exposure, event-market,
  and venue-action candidates

wallet.network
  presents the user-facing cockpit and authorizes or denies exact intents

Hypervisor
  executes autonomous work and provider-backed workloads

Agentgres
  records receipts, evidence, and admitted operational truth

IOI L1
  anchors only selected public/economic/cross-domain commitments
```

## Conformance Checks

- No `decentralized.*` surface can authorize a user, agent, or organization
  action.
- No route or trade candidate can execute until selected into a
  wallet.network-approved intent where funds, authority, secrets, private data,
  or consequential work are involved.
- Wallet app UI must be able to consume `decentralized.exchange` and
  `decentralized.trade` as route/venue intelligence services without requiring
  the user to visit those domains first.
- No `decentralized.*` surface can claim to own liquidity, user positions,
  venue execution, provider resources, storage truth, or settlement truth.
- Prediction markets and event contracts belong under `decentralized.trade` as
  event exposure, not under `decentralized.exchange` as asset conversion.
- Hypervisor must support direct provider integrations without routing through
  a separate cloud gateway.

## Related Canon

- [`exchange.md`](./exchange.md)
- [`trade.md`](./trade.md)
- [`../../components/wallet-network/product-exchange-risk.md`](../../components/wallet-network/product-exchange-risk.md)
- [`../../components/wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md)
- [`../../components/hypervisor/providers-and-environments.md`](../../components/hypervisor/providers-and-environments.md)
- [`../../components/agentgres/doctrine.md`](../../components/agentgres/doctrine.md)
- [`../../foundations/ioi-l1-mainnet.md`](../../foundations/ioi-l1-mainnet.md)
