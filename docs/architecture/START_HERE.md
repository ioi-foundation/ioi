# Start Here

Status: entry-point shim.
Canonical owner: [`_meta/start-here.md`](./_meta/start-here.md).
Supersedes: references that expected a top-level `docs/architecture/START_HERE.md`.
Superseded by: none.
Last alignment pass: 2026-06-12.

Start with [`_meta/start-here.md`](./_meta/start-here.md).

That file owns the five-minute stack model, role-based reading paths, common
boundary mistakes, and links to the source-of-truth map, vocabulary, and
implementation matrix.

Current Fleet addition:

> **Hypervisor Fleet is a general infrastructure manager whose first-class
> workload is autonomous systems. It appears inside Hypervisor IDE and
> console.ioi.ai, but its authority comes from wallet.network, its truth comes
> from Agentgres, and execution remains daemon-owned.**

Current Wallet addition:

> **wallet.network is the authority wallet for autonomous finance. Wallet
> Exchange is source-agnostic: route sources such as decentralized.exchange,
> direct pools, routers, solvers, and quote APIs produce candidates, but
> wallet.network owns exchange authority, risk disclosure, approval, signing or
> denial, revocation, protection actions, and receipts. Wallet Trade is
> advanced and high-risk: perps, margin, leverage, and position lifecycle
> require exact TradeIntent approval, risk labels, and position receipts.**

Current decentralized resource-lane addition:

> **decentralized.exchange routes liquidity, decentralized.trade routes
> exposure, and the Hypervisor Cloud Resource Lane routes execution through
> direct provider integrations. Lanes propose candidates; wallet.network
> authorizes; Hypervisor executes or deploys; venues and providers perform;
> Agentgres records; IOI L1 settles by trigger.**
