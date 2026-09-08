# ADR 0001 — decentralized.cloud is a product with its own control plane

Status: adopted product specification (owner, 2026-09-08); design baseline September 7, 2026.
Canonical owner: this file for the decision that decentralized.cloud is a product with its own control plane, and the estate planes are adapters.
Doctrine status: canonical
Implementation status: n/a (a decision record)

**Status:** accepted by the owner, 2026-09-08. **Supersedes, for this product:** the
"public face over the daemon" framing in `docs/architecture/domains/decentralized/cloud.md`
and ADR 0051 (`docs/decisions/0051-…`). Those documents are not edited by this ADR; they
are to be revised to match it, by their owners, as document 010 lands.

## Context

The estate's canon described decentralized.cloud as a routing face: it "routes cloud
resource liquidity; the Hypervisor runs the workload; wallet.network authorizes it;
Agentgres proves what happened." Its "does not own" list excluded identity, spend
authority, execution, storage bytes, ingress, settlement. The console programme was
built under that framing: read-only, daemon-proxied, an exact-match allowlist of
routes, no own database, no own auth, labelled stubs for everything the daemon could
not honour.

The owner adopted the specification in this directory on 2026-09-08. It defines an
application-first cloud whose infrastructure is purchased from an open provider
market, but whose service contracts, identities, networking, data guarantees and
customer experience belong to the cloud platform. That is a product, not a face.

## Decision

1. **decentralized.cloud is a product with its own resource model (010), control
   plane (030), ledger (100) and API (160).** The spec's principles, primitives, state
   machines, financial separation, trust model, release gates and wedge are binding.
2. **The estate's planes are consumed through the adapter boundary (040), not
   inherited as owners.** The Hypervisor is an execution and acquisition substrate
   (one adapter beside Akash and direct providers) and a runtime the cloud's own
   services may be placed on. wallet.network is one authority backend behind spend
   grants. Agentgres is one evidence source behind receipts. The CAS archive plane sits
   behind the archive contract in 070. The two products dogfood each other in both
   directions.
3. **One authority per object, direction written down.** For every canonical object in
   010 exactly one plane is authoritative. Where the cloud consumes an estate plane, the
   adapter contract states what that plane may claim and what it may not.
4. **The face rules lapse; the honesty rules survive.** "No route outside the
   capability table, no own database, no own auth" were the face's rules and end with
   this ADR. What survives, as spec principles 10, 12 and 13: no fixture painted as
   live; every claim carries evidence, scope and freshness; unknown outcomes are shown
   as unknown; unsupported semantics are rejected, not approximated.
5. **Per-subsystem reuse is a build decision, not canon.** Where an existing daemon
   plane already satisfies a spec contract (candidate discovery, placement advisory,
   budgets, receipts), reusing it behind the adapter boundary is preferred over a
   greenfield implementation. The spec's named stack (Go, PostgreSQL, NATS JetStream,
   Ceph, Envoy, WireGuard, SPIRE) is the selected architecture where nothing existing
   fits; it is not a mandate to rebuild what fits.

## Open owner decisions

These are named here so nobody decides them by shipping first. Each becomes its own
ADR in this directory.

| # | Decision | Spec position | Estate position today | Default until decided |
|---|---|---|---|---|
| A | Spend authority for a person | Card-funded USD balance; no wallet step (§7, §18) | A wallet grant signed at the moment of spend | A prepaid USD balance is a budget the wallet issues grants against; the customer never sees a token |
| B | The agent as a customer | An assistant that proposes and executes through the same API (§7, §22) | One job primitive, human or agent; CapabilityLease draw-down as authority | Agents are first-class principals in 090 with lease-bound execution grants; the assistant path in §7 is a special case of it |
| C | Unshipped services in navigation | Omitted from production navigation (§4) | Drawn and labelled "designed, not connected" | Omitted from the default rail; the labelled designs live behind a "designed" toggle for review |

## Consequences

- Document 010 is the first artefact; the daemon's next milestone and the console's
  registry both read from it.
- The console programme's scoreboard continues, iterating only against states the
  control plane can produce; the seven-group rail moves to the spec's navigation
  (Applications, Compute, AI, Data, Network, Observe, Security, Supply) with
  Applications as the default surface over existing records.
- `cloud.md` and ADR 0051 are revised by their owners to point here; until then, where
  they conflict with this tree, this tree wins for decentralized.cloud.
