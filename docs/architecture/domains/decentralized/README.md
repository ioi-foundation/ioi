# decentralized.* Domain Pack

Status: alpha canon architecture doctrine.
Canonical owner: this directory for the `decentralized.*` product/domain lanes
and their boundaries with wallet.network, Hypervisor, Agentgres, storage
backends, and IOI L1.
Supersedes: product prose that treats `decentralized.exchange`,
`decentralized.trade`, `decentralized.cloud`, route-intelligence services,
venue-intelligence services, or cloud-resource intelligence services as
authority layers, custody owners, execution owners, mandatory gateways, or
trust roots.
Superseded by: none.
Last alignment pass: 2026-07-05.
Doctrine status: canonical
Implementation status: mixed (cloud lane built; exchange/trade SDK seams only)
Last implementation audit: 2026-07-05

## Canonical Definition

The active `decentralized.*` canon has three candidate-intelligence engines:

```text
decentralized.exchange
  route liquidity / convert assets

decentralized.trade
  route exposure / manage positions and event markets

decentralized.cloud
  route infrastructure capacity / cloud resource liquidity
```

They are not wallets, brokers, custodians, chains, liquidity owners, settlement
layers, cloud control planes, restore truth layers, or required destination
UIs. They expose API/RPC/SDK candidate services that Wallet, Hypervisor,
agents, and third-party clients may consume.

Wallet is the user-facing authority cockpit. `decentralized.exchange` and
`decentralized.trade` may have docs, explorers, adapter registries, or
lightweight standalone surfaces, and `decentralized.cloud` may have provider
explorers, quote views, adapter registries, or status surfaces. The canonical
user does not need to leave Wallet or Hypervisor to exchange, trade, or place
workloads.

```text
Candidates are proposed.
wallet.network authorizes.
Hypervisor executes autonomous work when runtime work is involved.
Venues, pools, chains, and providers perform.
Agentgres records admitted truth.
The system settles locally unless its declared profile selects an external
service such as IOI L1 for triggered public, economic, dispute, registry,
rights, reputation, or cross-domain commitments.
```

Hypervisor canon uses direct provider integrations for cloud compute, storage,
GPUs, confidential compute, DePIN, local machines, customer cloud, enterprise
clusters, decentralized storage networks, and user-specified providers.
`decentralized.cloud` may support Hypervisor's optimized placement path by
returning resource candidates, quotes, custody plans, and failover plans, but it
does not replace Hypervisor provider integrations.

## Public Brand Position

The `decentralized.*` family is a protocol and product namespace under IOI, not
the default public umbrella for the whole company or product suite.

Canonical public umbrella:

```text
IOI / ioi.ai
```

Canonical protocol namespace:

```text
decentralized.exchange
decentralized.trade
decentralized.cloud
```

`decentralized.xyz` may be used as a redirect hub, developer/protocol docs
surface, explorer, or reserved namespace, but it should not be treated as the
primary public umbrella when `ioi.ai` can carry the simpler brand. Public app
labels may compress the family to Exchange, Trade, and Cloud Routing; exact
`decentralized.*` names remain in APIs, receipts, SDKs, adapter metadata, and
developer documentation.

This brand architecture does not change the control boundary:

```text
decentralized.* proposes candidates.
wallet.network authorizes.
Hypervisor executes runtime work.
Venues, pools, chains, and providers perform.
Agentgres records admitted truth.
```

## Files

- [`exchange.md`](./exchange.md): `decentralized.exchange`, spot/cross-chain
  route sources, `RouteCandidate`, exchange receipts, and exchange
  anti-patterns.
- [`trade.md`](./trade.md): `decentralized.trade`, spot orders, perps,
  leverage, margin, prediction markets, event contracts, position lifecycle,
  `TradeIntent`, `PredictionIntent`, `PositionReceipt`, `PredictionReceipt`,
  and agent-trading restrictions.
- [`cloud.md`](./cloud.md): `decentralized.cloud`, cloud resource candidates,
  provider quotes, optimized placement intelligence, compute/storage/network
  resource classes, custody plans, failover plans, placement receipts, and
  cloud-routing anti-patterns.

## Owns

This directory owns:

- the meaning of the `decentralized.*` names;
- route and venue-intelligence boundaries for `decentralized.exchange` and
  `decentralized.trade`;
- resource-intelligence boundaries for `decentralized.cloud`;
- the route-intelligence / venue-intelligence / resource-intelligence engine
  boundary;
- cross-lane proposal/authority/execution/truth/settlement boundaries;
- route-source, venue-adapter, and provider-candidate non-ownership doctrine;
- anti-patterns for treating route/venue/resource-intelligence engines as
  authority, custody, cloud-control, or required user destinations.

## Does Not Own

This directory does not own:

- wallet authority, keys, policies, grants, approvals, or signatures;
- liquidity, venue execution, derivatives mechanics, or chain finality;
- Hypervisor execution semantics;
- Hypervisor provider connector implementations;
- Hypervisor environment lifecycle;
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

decentralized.cloud
  exposes resource intelligence and proposes infrastructure-capacity,
  custody, failover, quote, and placement candidates

wallet.network
  authorizes or denies exact intents; Wallet may present the high-trust cockpit
  while embedded products may present narrower permission and approval flows

Hypervisor
  executes autonomous work, provider-backed workloads, environment lifecycle,
  VM/runtime provisioning, snapshot, restore, and teardown

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
- No cloud resource candidate can provision, spend, release credentials, expose
  ingress, claim custody, or restore until selected into a Hypervisor-admitted
  placement and approved by wallet.network or the relevant authority provider
  where required.
- Wallet app UI must be able to consume `decentralized.exchange` and
  `decentralized.trade` as route/venue intelligence services without requiring
  the user to visit those domains first.
- Hypervisor must be able to consume `decentralized.cloud` as an optimized
  placement intelligence service without requiring the user to visit
  `decentralized.cloud` first.
- No `decentralized.*` surface can claim to own liquidity, user positions,
  venue execution, provider resources, provider accounts, VM lifecycle,
  storage truth, restore validity, or settlement truth.
- Prediction markets and event contracts belong under `decentralized.trade` as
  event exposure, not under `decentralized.exchange` as asset conversion.
- Hypervisor must support direct provider integrations without routing through
  a separate cloud gateway. `decentralized.cloud` is optional optimized
  placement intelligence, not mandatory infrastructure middleware.

## Related Canon

- [`exchange.md`](./exchange.md)
- [`trade.md`](./trade.md)
- [`cloud.md`](./cloud.md)
- [`../../components/wallet-network/product-exchange-risk.md`](../../components/wallet-network/product-exchange-risk.md)
- [`../../components/wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md)
- [`../../components/hypervisor/providers-and-environments.md`](../../components/hypervisor/providers-and-environments.md)
- [`../../components/hypervisor/byo-provider-plane.md`](../../components/hypervisor/byo-provider-plane.md)
- [`../../components/agentgres/doctrine.md`](../../components/agentgres/doctrine.md)
- [`../../foundations/ioi-l1-mainnet.md`](../../foundations/ioi-l1-mainnet.md)
