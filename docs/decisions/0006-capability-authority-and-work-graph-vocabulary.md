# ADR 0006: Define Capability, Authority, And Work-Graph Vocabulary

- Status: Accepted
- Date: 2026-05-14
- Owners: IOI runtime / wallet.network / connectors-tools / architecture

## Context

IOI needs stable vocabulary for execution powers, authority grants, client
state, and delegated work structure. The vocabulary is not cosmetic: it
determines what can execute, who can authorize it, and which state is
canonical.

Earlier terms blurred these boundaries:

- `cap:*` and generic capability grants;
- flattened tool capability bags;
- `swarm` as if it were a product or runtime surface;
- historical adaptive work graph phrasing;
- contradiction logs as living architecture scaffolding rather than decision
  records.

## Decision

IOI adopts this vocabulary:

- `prim:*` for primitive execution capabilities;
- `scope:*` for wallet/provider authority scopes;
- `grant://` or `authority_grant_id` for grants and leases;
- `projection`, `cache`, or `checkpoint` for non-canonical client state;
- `adaptive_work_graph` only for public delegated execution strategy;
- `execution strategy` or `work graph` instead of `swarm` in public
  architecture prose.

Resolved decision history belongs in ADRs under `docs/decisions/`. Canonical
architecture docs should not maintain a contradiction log as a parallel
doctrine surface.

## Consequences

- Runtime policies can distinguish what an actor can technically do
  (`prim:*`) from what a user, wallet, provider, or tenant has authorized
  (`scope:*` and `grant://`).
- Tool contracts, worker manifests, and wallet grants should not use flattened
  capability bags when authority or execution semantics differ.
- Public product prose should talk about execution strategies, work graphs, or
  routed workers rather than treating `swarm` as a product/runtime primitive.
- Older plans may keep historical terms only when clearly describing decision
  history.
- Documentation checks should enforce this decision without requiring a
  contradiction log.

## Canonical References

- `docs/architecture/_meta/source-of-truth-map.md`
- `docs/architecture/_meta/vocabulary.md`
- `docs/architecture/foundations/common-objects-and-envelopes.md`
- `docs/architecture/components/connectors-tools/contracts.md`
