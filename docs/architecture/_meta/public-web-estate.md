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
Implementation status: partial (public web properties ship from their own
repositories; no runtime gate yet refuses an unclassified route at startup). A
route census with public/authenticated/internal classification was produced on
2026-07-26; both its generator and its output were removed by the 2026-08-05
proof-apparatus strip (`9fe221227`), so **no current census artifact exists** and
this status has not been re-derived since. The removed paths are not restated as
refs, and this basis is stale rather than verified.
Implementation refs: none current.
Last implementation audit: 2026-07-26 (stale)

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

- Route census mechanics and census evidence. The prior program-control census
  artifact was removed with the proof apparatus and has no current successor;
  when one is rebuilt it is named here as a tracked path or not at all.
- Conformance claims and their owners: those bind to each subject owner's
  implementation status and to the exact manifest/evidence of a released
  protocol profile, including the entitlements in
  [`ioi-authority-protocol.md`](../foundations/ioi-authority-protocol.md) for
  authority claims.
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

- A public property may publish a capability claim only when the canonical
  source-of-truth map names its owner, that owner's implementation status permits
  the claim, and the exact claimed release/profile evidence is retained;
  unshipped capability is described as a target or not at all.
- Nonclaims stay explicit: what the system does not do or has not proven is
  stated in the same register as what it does.
- Evidence artifacts referenced publicly (reports, attestations, badges) are
  evidence, never authority: publishing one grants nothing and closes no gate.

## Related Owners

- [`source-of-truth-map.md`](./source-of-truth-map.md) — subject ownership
  routing.
- [`source-of-truth-map.md`](./source-of-truth-map.md), subject-owner
  `Implementation status:` declarations, and released protocol manifests — the
  retired `docs/conformance/` tree is not a public-claim authority.
- [`../components/hypervisor/providers-and-environments.md`](../components/hypervisor/providers-and-environments.md)
  — route-binding drift classes for served endpoints.
- [`../foundations/security-privacy-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md)
  — final-invoker and authority invariants that public surfaces must never
  bypass.

## Subject-specific compute claims

Every published secure-sandbox, Workstation, attached-Infrastructure, or
HypervisorOS/node-root statement binds one subject-specific claim id, one
conformance profile, the exact selected release/profile/backend matrix, and
fresh evidence. These claims are independently closable and withdrawable.
Missing, expired, simulated-only, or drifted evidence removes or downscopes the
copy; evidence for one subject never closes another.

Public pages may describe the integrated and focused-standalone delivery forms
of the same bundle, but must not turn distribution into a capability claim. A
downloadable Workstation client does not establish a Type 2 mapping until its
hosted machine lifecycle and compatibility matrix pass. A bootable image does
not establish a Type 1 mapping until the HypervisorOS installer, node-root
lifecycle, hardware, update/recovery, enforcement, and support profile pass.
Attached-estate evidence may qualify Hypervisor Infrastructure without claiming
that Hypervisor is the attached estate's VMM. “Drop-in replacement” or
supersession language additionally requires its own declared cluster, high
availability, migration, storage, network, device, guest-compatibility,
disaster-recovery, and operational-upgrade matrix; autonomy evidence cannot
substitute for that matrix.
