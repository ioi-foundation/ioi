# Public Web Estate

Status: canonical public-estate ownership register.
Canonical owner: this file for the explicitly-public surface class — which
externally reachable surfaces are public by declaration — and the claims
discipline public web properties must follow.
Supersedes: implicit public/marketing surface classification scattered across
program records.
Superseded by: none.
Last alignment pass: 2026-07-26.
Doctrine status: canonical
Implementation status: partial (an externally-reachable route census with
public/authenticated/internal classification exists as retained program
evidence; public web properties ship from their own repositories; no runtime
gate yet refuses an unclassified route at startup)
Implementation refs:
  - scripts/m0-program-control.mjs
  - docs/evidence/m0-program-control/effect-census.json
Last implementation audit: 2026-07-26

## Definition

The public web estate is everything a principal can reach without presenting
identity or authority: explicitly-public daemon routes and the public web
properties (marketing, documentation, and download surfaces). This file is the
canonical owner of that class boundary. Every externally reachable surface of
the estate resolves to exactly one of three classes — `authenticated`,
`explicitly_public`, or `internal_only` — and membership in
`explicitly_public` is a declaration recorded here and in the route census,
never an inference from the absence of an auth check.

## Owns

- The membership rule for the `explicitly_public` class, for daemon routes and
  web properties alike.
- The public-claims discipline: what a public property may state about the
  system, and what it must never state.

## Does Not Own

- Route census mechanics and retained census evidence (program-control
  evidence under `docs/evidence/m0-program-control/`).
- Conformance claims and their owners (the claim coverage index in
  [`../../conformance/README.md`](../../conformance/README.md)).
- The authority model (wallet grants, leases, receipts) or any product
  taxonomy; public surfaces present, they never admit.

## The Explicitly Public Route Class

A route is `explicitly_public` only when all of the following hold:

1. Its owner declares it public; absence of authentication is never itself the
   declaration.
2. It serves no authority: it mints no identity, session, lease, grant, or
   token, and its response can never be replayed as admission evidence
   (`INV-37`).
3. It performs no consequential effect — static content or a read-only,
   non-consequential projection only.
4. Its response embeds no secret, credential, or tenant-scoped material.
5. It remains safe under unauthenticated, adversarial, repeated access.

Any externally reachable route that fails one of these conditions is
`authenticated` or `internal_only`. The target contract — stated as a target,
not claimed as runtime conformance — is that an externally reachable route
with no recorded class refuses to serve: an unclassified route is a census
defect, not a default-public surface.

## Public Web Properties

Public web properties are presentation only. They carry no admission path, no
runtime truth, and no authority-bearing state; anything interactive that they
expose resolves to the same daemon-admitted paths every other client uses.
Naming on public properties follows the canonical vocabulary owners
([`vocabulary.md`](./vocabulary.md), [`term-boundaries.md`](../foundations/term-boundaries.md)).

## Public Claims Discipline

- A public property may publish a capability claim only when the conformance
  claim coverage index names that claim's owner and the claim's evidence is
  retained; unshipped capability is described as a target or not at all.
- Nonclaims stay explicit: what the system does not do or has not proven is
  stated in the same register as what it does.
- Evidence artifacts referenced publicly (reports, attestations, badges) are
  evidence, never authority: publishing one grants nothing and closes no gate.

## Related Owners

- [`source-of-truth-map.md`](./source-of-truth-map.md) — subject ownership
  routing.
- [`../../conformance/README.md`](../../conformance/README.md) — claim
  coverage index.
- [`../components/hypervisor/providers-and-environments.md`](../components/hypervisor/providers-and-environments.md)
  — route-binding drift classes for served endpoints.
- [`../foundations/security-privacy-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md)
  — final-invoker and authority invariants that public surfaces must never
  bypass.
