# ADR 0040: Make Machine Authority The Category And IOI Authority The Portable Protocol

- Status: Accepted — doctrine and ownership only; no wire, runtime, release, or
  conformance claim changes by this decision
- Date: 2026-08-30
- Owners: Machine Authority category / IOI Authority Protocol / Web4 stack
- Refines: ADRs 0008, 0010, 0015, 0032, and 0033
- Does not amend: registered contract bytes, wallet grant semantics, daemon
  admission behavior, Agentgres truth, AIIP, settlement, certification, marks,
  or the 2026-08-12 retirement of the separate `docs/conformance/` document tree
- Confidence: accepted as the category and ownership architecture; every stable
  protocol and implementation claim remains gated by independently runnable
  evidence

## Context

IOI already contains a strong machine-power lifecycle: review-bound authority
requests, approval ceremony context, signed holder/audience-bound grants,
delegation attenuation, key and revocation evidence, budgets and calls,
exact-effect admission, atomic consumption, invocation separation, receipts,
and reconciliation semantics.

The canonical category story did not expose that lifecycle as one external
protocol family. `web4-and-ioi-stack.md` simultaneously owned Web4, described
Machine Authority, and presented a wedge containing wallet.network, Hypervisor,
Agentgres, AIIP, IOI L1, ontologies, goal loops, campaigns, and rooms. That was
correct as a full-stack composition and weak as a protocol boundary: an
independent adopter could not tell which minimal closure to implement, what a
narrow implementation could accurately claim, or which first-party components
were replaceable.

The same ambiguity appeared when the category label was reused as an
unqualified protocol name rather than a versioned IOI surface. That made the
category, the protocol, and the product stack look interchangeable.

Meanwhile, the separate `docs/conformance/` document class was deliberately
retired on 2026-08-12. A handful of canonical files still pointed to its former
claim index. Recreating a prose-only tree would reverse that ruling without
creating the executable external artifact the adoption claim actually needs.

## Decision

### 1. Machine Authority is a first-class category

[`machine-authority.md`](../architecture/foundations/machine-authority.md) owns
the category definition, abstract roles, ordered lifecycle distinctions,
MAC-1–MAC-12 completeness contract, and claim ladder.

The category is independent of IOI products. It is defined by observable
security properties and replaceable roles, not by use of an IOI service, name,
schema, runtime, database, wallet, network, chain, or model.

### 2. The external family is named IOI Authority Protocol

[`ioi-authority-protocol.md`](../architecture/foundations/ioi-authority-protocol.md)
owns the portable protocol family. It defines four composable target profiles:

- `ioi_authority_core_v1`;
- `ioi_delegated_authority_v1`;
- `ioi_governed_effect_v1`; and
- `ioi_machine_authority_complete_v1`.

The Core profile makes the smallest action proposal, review, decision, step-up,
and approval-evidence boundary independently adoptable. It does not receive the
complete category claim. Delegated Authority and Governed Effect close the
power and exact-effect halves. Only their complete composition may claim
Machine Authority conformance.

### 3. First-party products implement roles targeted for replacement

wallet.network is IOI's first-party authority provider. Hypervisor Daemon is
IOI's first-party PEP and final-invoker mediator. Agentgres is IOI's first-party
admitted-truth and replay implementation. AIIP and IOI L1 are optional interop
and shared-finality extensions.

Current served portable-delegation routes remain wallet.network-bound, and no
alternate-provider adapter or interoperability proof exists. An IOI shipping
profile may require those components. A future released protocol profile must
permit another implementation to replace each role while satisfying the same
frozen behavior before provider-neutral compatibility is claimed.

### 4. Each released profile has one frozen surface manifest

The architecture contract registry is a source pool, not the protocol surface.
A released profile closes over an exact immutable
`ProtocolSurfaceManifest`: contract and invariant IDs/hashes, encodings,
signature domains, role behavior, refusals, fixtures, verifier identity,
compatibility policy, and independence evidence.

No unbounded registry subset, package release, prose list, or running reference
implementation may silently change that closure.

### 5. Conformance remains executable and outside the retired document class

The `docs/conformance/` tree remains retired. Canonical meaning and target
profiles live with architecture owners. A clone-and-run conformance artifact
ships with the future public protocol surface/package, under a license and
verification path that permit independent implementation and operation.

This decision refines ADR 0033's now-historical references to that tree as a
live permissive surface. The empty deleted glob is removed from
`LICENSE-MANIFEST.json`; no replacement path is invented before an artifact
exists.

Before such a directory or package is created, ADR 0033 and
`LICENSE-MANIFEST.json` must be refined at the exact path. This ADR grants no
license by implication and creates no placeholder artifact that could be
mistaken for a release.

### 6. Public category doctrine is property-first

Canonical category definitions, public protocol documentation, conformance
profiles, and first-read architecture do not depend on competitor comparisons.
Internal landscape research may identify properties and threats, but it is
non-canonical and cannot lend terminology or authority to the public standard.

## Consequences

- Machine Authority becomes the security/category substrate beneath Web4 and
  the Internet of Intelligence rather than one row inside the full stack.
- IOI can satisfy the small action-authorization adoption wedge without
  weakening the claim required for real delegated power.
- wallet.network, Hypervisor, and Agentgres retain strong first-party ownership
  while becoming candidates for formally designated reference releases after
  they meet the separate designation contract.
- The exact complete claim becomes harder to make and easier to audit.
- No current target profile is stable or externally conformant merely because
  this ADR is accepted.
- The signed portable delegation-allocation closure, profile-complete effect
  coverage beyond the qualified served SCM path, portable admission/outcome
  signatures, public surface manifest, offline release, independent
  implementations, and structural governance remain open.

## Rejected Alternatives

### Keep Machine Authority embedded in Web4

Rejected because it makes a security protocol inseparable from a much broader
system category and obscures the smallest externally implementable surface.

### Name the protocol after the generic category

Rejected because it collapses category and implementation identity. IOI owns
its protocol name and may lead the category without claiming that one branded
implementation is the category's definition.

### Publish only the complete stack

Rejected because an adopter should be able to place an existing agent host or
gateway behind the Core boundary before adopting delegation, runtime, truth,
interop, or settlement extensions.

### Let the Core profile claim Machine Authority

Rejected because decision and consent evidence do not establish scoped
delegated power, current revocation, final-PEP effect binding, atomic
consumption, or execution truth.

### Recreate `docs/conformance/`

Rejected because the document class was intentionally retired and did not
provide runnable external proof. The needed successor is an executable
protocol release, not another prose claims tree.

## Reversal

The ownership split is reversible only through another ADR that names the
replacement category owner, protocol owner, claim ladder, externality contract,
and migration for every released profile. A later formally designated reference
release may change or cease serving that role without changing the category or
protocol. A profile may be deprecated under the public change process without
erasing the accurate historical claim of an implementation that passed its
frozen version.
