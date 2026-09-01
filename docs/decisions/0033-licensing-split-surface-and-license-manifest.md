# ADR 0033: License The Protocol Surface Permissively And Define The Licensed Work By Manifest

- Status: Accepted
- Date: 2026-08-05
- Owners: IOI Foundation (licensor) / architecture canon owners / conformance
  and certification owners
- Refines: ADR 0015
- Refined by: ADR 0040 for the 2026-08-12 retirement of the separate
  `docs/conformance/` document class and the future exact IOI Authority Protocol
  artifact boundary
- Unaffected: the Change Date (November 6, 2029); the Section 2 Use Limitation;
  every technical contract, schema, and invariant in this canon
- Confidence: settled as the licensing architecture and as the repair of two
  drafting defects. **Not settled as legal advice.** See § Counsel Review below.

## Counsel Review Is Advised Before Any Public Release Relies On This

This ADR was drafted from the decision space in the R-03 track opener and from
the license text at the bytes. **It has not been reviewed by external counsel.**
The eight questions the track opener enumerated for review remain open questions
for counsel, and three of them — the reach of the Section 2 Use Limitation
against a redistributed modified L0, the pre-Change-Date patent posture, and
contribution-intake formality — are answered here provisionally or not at all.

Before any public release, marketing claim, certification programme, or
third-party adoption relies on this ADR, counsel should review the amended
`LICENSE-BBSL`, `LICENSE-MANIFEST.json`, and this decision. Landing it now
resolves the *architecture* question that every downstream adoption property was
waiting on; it does not convert that resolution into a legal opinion, and this
ADR must not be cited as one.

## 2026-08-30 Refinement: The Retired Conformance Tree Is Not A Surface

The `docs/conformance/` document class was retired on 2026-08-12. References
below to “the conformance tree” describe the surface as it existed when this ADR
was accepted; they no longer designate a live artifact, runnable profile, or
manifest member. ADR 0040 controls that later architecture decision.

`LICENSE-MANIFEST.json` no longer lists the deleted glob. A future IOI Authority
Protocol runner, vectors, manifest, or package must be added under its exact
public path with an explicit license-manifest refinement before release. The
remaining permissive grants are unchanged. Removal of an empty deleted glob
does not withdraw rights from any previously distributed file.

## Context

Canon named this the single most load-bearing adopt-vs-fork input: may a third
party legally implement and independently operate L0, and under exactly which
terms for exactly which components? ADR 0015 and
`foundations/economic-flywheel-and-pricing-boundaries.md` both required a
dedicated licensing ADR; `foundations/web4-and-ioi-stack.md` listed its absence
as open flank number one of its adoption calculus. Every downstream property —
open protocol surface, offline verifiability, credible neutrality, portable
exit — was contingent on an answer that did not exist.

Read at the bytes, `LICENSE-BBSL` is **more permissive than canon's framing
implied**: BUSL-shaped, with a fixed conversion to Apache-2.0 on 2029-11-06 and
a narrow restriction that reaches only competing blockchain development
frameworks and SDKs, explicitly not sovereign chains, agentic networks, DePIN,
contracts, services, consulting, hosting, validation, or private forks. The
problem was never that the license was closed. It was two drafting defects that
undermine the adoption calculus regardless of which licensing option is chosen,
and one structural mismatch between a kernel-era license and a monorepo that now
carries the daemon, Agentgres, product surfaces, marketplaces, schemas, and, at
the time of this decision, a conformance document tree later retired.

## Decision

### 1. Split the surface

The protocol source pool is licensed permissively **now**; first-party
implementation code remains under `LICENSE-BBSL` until the Change Date. A
formal reference-release designation is separate and has not occurred.

| Class | License | Covers | Effective |
| --- | --- | --- | --- |
| `apache_2_0` | Apache-2.0 | registered contracts, JSON Schemas, cross-field invariants, fixtures, both generated projections, client-facing protocol type libraries, and any future exact protocol artifact only after it is added to the manifest | now |
| `cc_by_4_0` | CC BY 4.0 | specification and decision prose under `docs/` | now |
| `bbsl_1_1` | BBSL 1.1 → Apache-2.0 | first-party implementation code and its build configuration; no formal reference designation implied | now, converting 2029-11-06 |
| `third_party` | per subtree | vendored material with its own `LICENSE` | now |
| `reserved` | none granted | internal working material, evidence, marks, brand assets | now |

The reasoning is the covenant canon already made: **anything a third party must
read, implement, or run to verify IOI's honesty must be inspectable and
independently operable.** A future conformance suite an adopter may not legally
run does not make them able to self-certify, and a schema registry under a
competition-restricted license does not make a protocol surface open. Those are
the artifacts that carry the openness claim, so those are the artifacts that get
permissive terms today rather than in 2029.

What the split does **not** give away is what the Use Limitation was actually
protecting: first-party implementation code stays under BBSL, and
redistributing it as a competing blockchain development framework stays
restricted until the Change Date. Publishing the specification has never been
how a framework moat is lost.

### 2. Define the Licensed Work by manifest

`LICENSE-MANIFEST.json`, committed at the repository root, assigns **every**
tracked path to exactly one license class by ordered, first-match glob rules. A
new Section 0 in `LICENSE-BBSL` makes that manifest the definition of the
Licensed Work, and gives the manifest control where the two disagree.

Two properties are deliberate:

- **Unmatched means reserved, never granted.** A path no rule matches is
  licensed to no one. Silence has to fail closed in a license for the same
  reason it fails closed everywhere else in this canon: an implied grant nobody
  wrote is a grant nobody can bound.
- **The manifest a copy carries governs that copy.** An adopter's rights are
  determined by the manifest in the copy they received, not by whatever the
  manifest later becomes.

### 3. Fix the revocable grant (D-1)

`LICENSE-BBSL` § 1 granted a *"revocable"* license while § 8 already terminated
on breach. Read together, § 1 was revocable **at will** — and no rational
institution builds on a grant the licensor can withdraw. One word contradicted
"adopt is the rational move" at the root.

The grant is now **perpetual and irrevocable**, terminable only under § 8 on the
licensee's own breach, with an explicit statement that the licensor may not
withdraw, revoke, suspend, or narrow the grant as to copies already distributed,
and that no later version of the License or the manifest reduces rights already
received under a version the licensee complied with.

### 4. Marks and certification stay separate

Neither the manifest nor any license class grants trademark, service mark, or
logo rights; `LICENSE-BBSL` § 5's reservation is unchanged and is restated in
the manifest and in both new license files. Separately: **a `CertificationClaim`
never requires a mark licence, and mark reservation never encumbers an
independent implementation.** Certification remains issued under
`foundations/ecosystem-assurance-certification-liability.md`.

This separation is not tidiness. `foundations/protocol-governance-neutrality.md`
holds specification ownership, reference implementation, and
certification-plus-marks apart as three roles precisely because a category owner
who could withhold the name from a conforming implementation would have a veto
over conformance that no conformance contract mentions.

### 5. Supersession posture

`LICENSE-BBSL` is **amended in place**, not superseded by a versioned successor.
Amendment is correct here because both changes are repairs that can only widen
or clarify a licensee's position — an irrevocable grant is strictly better than
a revocable one, and a defined Licensed Work is strictly better than an
undefined one — so no licensee's rights narrow. A change that could narrow
rights would need a versioned successor and the change process in
`protocol-governance-neutrality.md`.

## Consequences

- The adoption calculus's open flank number one closes as an *architecture*
  question. `web4-and-ioi-stack.md` may state the license posture instead of
  recording its absence, subject to the counsel caveat above.
- The `foundations/economic-flywheel-and-pricing-boundaries.md` requirement for
  a versioned open-protocol-surface manifest is discharged by the
  `open_protocol_surface` block in `LICENSE-MANIFEST.json`.
- R-05's reference-implementation contract gains a legal footing: a third party
  proving parity against a named surface may now legally read, implement, and
  run every artifact that surface consists of.
- At acceptance, R-07's then-proposed public conformance path was legally
  runnable but not operationally runnable. That document class was later
  retired. No current IOI Authority Protocol profile or runner exists; its
  future exact artifact path must be added to the manifest before release.
- `crates/*/Cargo.toml` entries carrying `license-file = "LICENSE-BBSL"` remain
  correct: those crates are `bbsl_1_1` under the manifest.
- Contributions continue under § 4 with no CLA or DCO formality. This is
  provisional and is one of the questions left for counsel.

## Rejected Alternatives

- **Option B — whole-repo BBSL with the defects fixed.** Cheapest legally, and
  rejected because it leaves the schema registry and any future conformance
  suite non-permissive. That directly contradicts outsider-runnable
  interoperability and would leave a chosen legal gap in the adoption calculus.
- **Option C — full permissive now.** Maximal adoption credibility, and
  rejected as strictly more than the problem required: the defects and the
  closed protocol surface are what damaged the calculus, not the Use Limitation,
  which already permits every use an adopter actually needs and expires in 2029
  regardless.
- **Versioned successor license instead of amending in place.** Rejected because
  both changes only widen a licensee's position; a successor would create a
  two-license estate and an unnecessary question about which copy carries which
  terms.
- **Enumerating the Licensed Work inside the license text.** Rejected: it would
  go stale on the first directory rename, and a stale definition of the Licensed
  Work is the defect D-2 already is.

## Cost Of Being Wrong And Reversal

The two defect repairs are one-way and intended to be: an irrevocable grant
cannot be walked back for copies already distributed, which is exactly the
property that makes it worth granting. If counsel finds the split-surface
boundary drawn in the wrong place, the manifest can move paths **toward**
permissive without any licensee losing rights; moving a path from permissive
back toward BBSL cannot retroactively affect copies already distributed under
the permissive class, and would need the change process, a new manifest version,
and a stated rationale. That asymmetry is deliberate — it means an error in this
ADR costs IOI optionality and never costs an adopter their footing.

## Canonical References

- [`../../LICENSE-BBSL`](../../LICENSE-BBSL) — amended: Section 0 and the
  irrevocable grant.
- [`../../LICENSE-MANIFEST.json`](../../LICENSE-MANIFEST.json) — the definition
  of the Licensed Work and the open-protocol-surface enumeration.
- [`../../LICENSE-APACHE-2.0`](../../LICENSE-APACHE-2.0),
  [`../../LICENSE-DOCS`](../../LICENSE-DOCS) — the permissive classes.
- [`0015-bounded-distributed-autonomous-systems-and-network-enrollment.md`](./0015-bounded-distributed-autonomous-systems-and-network-enrollment.md)
- [`../architecture/foundations/web4-and-ioi-stack.md`](../architecture/foundations/web4-and-ioi-stack.md)
  — the adoption calculus and the reference-implementation contract.
- [`../architecture/foundations/protocol-governance-neutrality.md`](../architecture/foundations/protocol-governance-neutrality.md)
  — the three roles and the change process.
- [`../architecture/foundations/ecosystem-assurance-certification-liability.md`](../architecture/foundations/ecosystem-assurance-certification-liability.md)
  — certification and issuers.
- [`../architecture/foundations/economic-flywheel-and-pricing-boundaries.md`](../architecture/foundations/economic-flywheel-and-pricing-boundaries.md)
  — the open-L0 covenant and the protocol-surface manifest requirement.
- [`0040-make-machine-authority-the-category-and-ioi-authority-the-portable-protocol.md`](./0040-make-machine-authority-the-category-and-ioi-authority-the-portable-protocol.md)
  — retires the former conformance-document assumption and requires the future
  executable artifact at an exact licensed path.
