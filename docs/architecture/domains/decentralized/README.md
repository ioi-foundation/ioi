# decentralized.* Domain Pack

Status: alpha canon architecture doctrine.
Canonical owner: this directory for the `decentralized.*` product/domain lanes
and their boundaries with wallet.network, Hypervisor, Agentgres, storage
backends, and IOI L1.
Supersedes: product prose that treats `decentralized.exchange`,
`decentralized.trade`, or parked future `decentralized.cloud` as authority
layers, custody owners, execution owners, mandatory gateways, or trust roots.
Superseded by: none.
Last alignment pass: 2026-06-14.

## Canonical Definition

The active `decentralized.*` canon has two Wallet-native route surfaces:

```text
decentralized.exchange
  route liquidity / convert assets

decentralized.trade
  route exposure / manage positions
```

They are not wallets, brokers, custodians, chains, liquidity owners, or
settlement layers. They propose candidates.

```text
Candidates are proposed.
wallet.network authorizes.
Hypervisor executes autonomous work when runtime work is involved.
Venues, pools, chains, and providers perform.
Agentgres records admitted truth.
IOI L1 settles only triggered public, economic, dispute, registry,
rights, reputation, or cross-domain commitments.
```

`decentralized.cloud` is parked future product space. Present Hypervisor canon
uses direct provider integrations for cloud compute, storage, GPUs,
confidential compute, DePIN, local machines, customer cloud, enterprise
clusters, decentralized storage networks, and user-specified providers.

## Files

- [`exchange.md`](./exchange.md): `decentralized.exchange`, spot/cross-chain
  route sources, `RouteCandidate`, exchange receipts, and exchange
  anti-patterns.
- [`trade.md`](./trade.md): `decentralized.trade`, spot orders, perps,
  leverage, margin, position lifecycle, `TradeIntent`, `PositionReceipt`, and
  agent-trading restrictions.
- [`cloud-parked-future.md`](./cloud-parked-future.md): parked future
  `decentralized.cloud` posture and the current Hypervisor direct-provider
  integration boundary.

## Owns

This directory owns:

- the meaning of the `decentralized.*` names;
- active versus parked status for `decentralized.exchange`,
  `decentralized.trade`, and `decentralized.cloud`;
- cross-lane proposal/authority/execution/truth/settlement boundaries;
- route-source and venue-adapter non-ownership doctrine;
- anti-patterns for treating route surfaces as authority or custody.

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
  proposes asset-conversion candidates

decentralized.trade
  proposes exposure and venue-action candidates

wallet.network
  authorizes or denies exact intents

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
- No `decentralized.*` surface can claim to own liquidity, user positions,
  venue execution, provider resources, storage truth, or settlement truth.
- `decentralized.cloud` must remain parked future product space until a later
  canon document promotes it explicitly.
- Hypervisor must support direct provider integrations without routing through
  `decentralized.cloud`.

## Related Canon

- [`exchange.md`](./exchange.md)
- [`trade.md`](./trade.md)
- [`cloud-parked-future.md`](./cloud-parked-future.md)
- [`../../components/wallet-network/product-exchange-risk.md`](../../components/wallet-network/product-exchange-risk.md)
- [`../../components/wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md)
- [`../../components/hypervisor/fleet.md`](../../components/hypervisor/fleet.md)
- [`../../components/agentgres/doctrine.md`](../../components/agentgres/doctrine.md)
- [`../../foundations/ioi-l1-mainnet.md`](../../foundations/ioi-l1-mainnet.md)
