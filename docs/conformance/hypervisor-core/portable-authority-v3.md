# Portable authority v3 conformance

Status: target conformance contract. Current master registers the v2 grant
wire contract, invariants, fixtures, and generated projections, but the full
multi-hop chain is prose doctrine, not machine enforcement: no portable
Ed25519/JCS verifier, no offline CLI, and no negative-fixture corpus exist,
and network key discovery, trust-root acquisition, transparency
infrastructure, and universal revocation distribution remain separate planned
work.
Canonical inputs:
[`authority-and-access.md`](../../architecture/foundations/objects/authority-and-access.md),
[`invariants.md`](../../architecture/foundations/invariants.md),
[`security-privacy-policy-invariants.md`](../../architecture/foundations/security-privacy-policy-invariants.md),
and
[`verifiable-bounded-agency.md`](../../architecture/foundations/verifiable-bounded-agency.md).
Last audited: 2026-08-12.

## Scope and honest implementation posture

This target binds the successor (`v3`) `AuthorityGrantEnvelope` chain contract:
what a conforming verifier must accept, what it must refuse, and what evidence
each disposition carries. Everything below is a target. Nothing here claims a
verifier, fixture, runner, or release exists; the criteria define what would
have to pass before any portable-authority claim is made. The prose doctrine
(finite, acyclic, strictly narrowing delegation with ancestor validation) is
already canonical; this file is where that doctrine becomes falsifiable.

A future runner for this target is subject to the standing verifier
discipline: falsifiable by mutation, closed-world over the refusal classes
below, labels claiming only what the assertion checks, and independent
evidence from the durable record. A runner that cannot go red on its own
negative fixtures does not certify this target.

## Conformance criteria

### CPA-1 — Complete ancestor chain and parent-holder issuance

A conforming verifier accepts a grant only with the complete ancestor chain
present, each child issued by its parent holder key, and rejects any chain
with a missing, unordered, or out-of-family ancestor.

### CPA-2 — Strict narrowing at every hop

Every child may only narrow scopes, primitive capabilities, resources, risk
classes, budget, calls, and validity, while retaining or adding caveats and
approval requirements. Equality is narrowing; any widening on any axis at any
depth is a refusal, not a warning.

### CPA-3 — System identity and versioned issuer key sets

Issuer identity binds to a system identity with versioned key sets; a
signature that verifies against a key outside the issuer's declared,
version-valid set is a refusal even when cryptographically valid.

### CPA-4 — Revocation snapshots and freshness

Verification operates over a caller-supplied locally trusted key set and a
bounded-freshness signed revocation snapshot. A stale snapshot beyond the
declared freshness bound, or a revoked ancestor at any depth, is a refusal;
absence of revocation data is never treated as proof of non-revocation.

### CPA-5 — Delegation depth and re-delegation rights

Delegation depth limits and re-delegation permission bits are enforced at
every hop. A chain that exceeds declared depth, or contains a hop issued by a
holder without re-delegation rights, is a refusal.

### CPA-6 — Resource, call, spend, and descendant budgets

Budgets declared on an ancestor bind the whole subtree. The verifier enforces
per-grant and cumulative-descendant budget arithmetic; exhaustion is a typed
refusal distinct from structural invalidity.

### CPA-7 — Final effect-admission receipt binding

A chain verdict is not an effect. The accepted-chain evidence binds into the
final effect-admission receipt at the executing boundary, so a reviewer can
join the exact chain, snapshot, and budgets to the exact admitted effect.
Verification without admission binding certifies nothing about execution.

### CPA-8 — Portable offline verification

The verifier is portable (Ed25519/JCS profile) and runs offline from the
chain, key set, and snapshot alone — no network key discovery, trust-root
acquisition, or transparency dependency. Those remain separate planned work
and are out of scope here; a verifier that silently reaches the network to
resolve trust is non-conforming.

## Negative-fixture corpus (required before any pass is claimed)

Every fixture must produce its named typed refusal; an either-outcome pass on
any fixture fails the whole target.

- **NF-1 widened child** — any axis widened at any depth (scope, capability,
  resource, risk class, budget, validity, caveat removal).
- **NF-2 cycle** — a chain that revisits any grant or issuer-holder edge.
- **NF-3 stale ancestor state** — revocation snapshot older than the declared
  freshness bound for the chain being verified.
- **NF-4 revoked ancestor** — revocation at every tested depth, not only the
  leaf's parent.
- **NF-5 wrong issuer** — valid signature from a key outside the issuer's
  versioned key set; and a correct key signing a hop it does not hold.
- **NF-6 replay** — a chain or verification transcript presented outside its
  validity window or against a different effect than the one bound.
- **NF-7 budget exhaustion** — per-grant and cumulative-descendant exhaustion,
  each distinct from structural refusal.
- **NF-8 depth exhaustion** — declared depth exceeded; re-delegation by a
  holder without the right.

## Relationship to current v2

The registered v2 grant contract and its fixtures are implementation
precedent, not partial credit toward this target. v3 conformance is claimed
only when the criteria above pass together with the negative corpus, and any
claim is scoped to exactly the profile verified — never to network trust
distribution, transparency, or discovery, which stay separate planned work.
