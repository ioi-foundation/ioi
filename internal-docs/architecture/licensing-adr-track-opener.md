# Licensing ADR Track Opener (R-03) — Decision Space And Questions For Legal Review

Status: archived internal track opener; non-canonical historical record. The
architecture decision closed through accepted ADR 0033 on 2026-08-05.
Authority: canonical owner docs and accepted ADRs win on drift; this file is
frozen and must not direct current work or imply that the track remains open.
Archived: 2026-08-30.
Succeeded by: [`0033-licensing-split-surface-and-license-manifest.md`](../../docs/decisions/0033-licensing-split-surface-and-license-manifest.md).

Parent: [`canonical-ioi-thesis-and-canon-change-recommendations.md`](./canonical-ioi-thesis-and-canon-change-recommendations.md), R-03.

> **Frozen historical body.** Everything below records the question and byte
> posture as assessed on 2026-08-04. It is not a current open flank. Accepted
> [ADR 0033](../../docs/decisions/0033-licensing-split-surface-and-license-manifest.md)
> controls current architecture; current licensing bytes and legal conclusions
> must be reassessed from their live owners.

## The Question The ADR Must Answer

May a third party legally implement and independently operate L0 — and under
exactly which terms, for exactly which components? Canon names this the single
most load-bearing adopt-vs-fork input: ADR 0015 and
`docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md`
both require a dedicated accepted licensing ADR, and the adoption calculus in
`docs/architecture/foundations/web4-and-ioi-stack.md` lists it as open flank
number one. Every downstream adoption property (open protocol surface,
offline verifiability, credible neutrality, portable exit) is contingent on
this answer.

## Current State, Read At The Bytes (2026-08-04)

`LICENSE-BBSL` ("Bootstrap Business Source License 1.1") at the repo root:

- Licensor: IOI Foundation. Licensed Work: "The IOI Blockchain Framework (the
  'IOI Kernel') as defined in this repository" — **no definition exists in the
  repository**; the monorepo now contains far more than a kernel (daemon,
  Agentgres, product UI, marketplaces, docs, schemas, conformance tooling).
- Grant (§1): worldwide, non-exclusive, non-transferable, royalty-free, and
  **"revocable"**.
- Use Limitation (§2): restricts only creating/marketing/distributing a
  competing blockchain development framework or SDK. Explicitly NOT
  restricted: operating sovereign L1/L2 chains, application-specific chains,
  AI/agentic networks, DePIN, contracts/services/modules on IOI chains,
  consulting/hosting/validation, private forks.
- Change Date (§3): November 6, 2029 — automatic conversion to Apache-2.0.
- Contributions (§4): inbound under the same terms; no CLA/DCO formality.
- Trademarks (§5): no mark rights granted. Termination (§8): automatic on
  breach. Governing law (§9): Delaware.

Honest reading: the license is **more permissive than canon's framing
implied** — it is BUSL-shaped with a fixed open-conversion date and a narrow
competition restriction, not a closed license. But two drafting defects
undermine the adoption calculus regardless of which option the ADR selects.

## Two Defects To Fix Under Every Option

**D-1 — The revocable grant.** §1 grants a "revocable" license while §8
already provides automatic termination on breach. Read together, §1 is
revocable at will. No rational adopter builds an institution on a grant the
licensor can withdraw; this single word contradicts "adopt is the rational
move" at the root. Standard BUSL phrasing is irrevocable-except-breach.

**D-2 — Undefined Licensed Work.** "As defined in this repository" defines
nothing. Which paths are the IOI Kernel? Is the daemon covered? Agentgres?
The schemas? The docs? The accepted ADR must bind a machine-readable
per-path license manifest — which also discharges the flywheel doc's open
"versioned protocol-surface manifest" gap and feeds R-05 (reference
implementation contract).

## Decision Space For The ADR

**Option A — split surface (recommended input to drafting).** Permissive
terms (Apache-2.0; CC-BY for prose) NOW for the protocol surface: schemas,
the architecture contract registry and generated Rust/TS projections,
envelope definitions, the conformance suite, and client-facing type
libraries. BBSL retained for the reference implementation until the Change
Date. Trademarks and certification separately owned. This directly satisfies
the covenant that anything required to verify IOI's honesty must be
inspectable and independently operable, while keeping the competing-framework
protection until 2029.

**Option B — whole-repo BBSL, defects fixed.** Keep BBSL everywhere; fix D-1
and D-2, add a patent grant; let the Change Date carry the openness promise.
Cheapest legally; leaves the conformance suite non-permissive, which
conflicts with the outsider-runnable certification requirement (R-07).

**Option C — full permissive now.** Apache-2.0 everything; moat is
trademarks, certification lineage, and network services only. Maximal
adoption credibility; surrenders the pre-2029 framework protection.

## Exact Questions For Legal Review

1. Does §1's "revocable" render the grant revocable at will? Replace with
   irrevocable-except-breach (D-1).
2. Define the Licensed Work by path: produce the per-path license manifest
   the ADR will bind (D-2).
3. Does the §2 Use Limitation conflict with canon's requirement that the open
   surface be independently implementable and operable? Specifically: may a
   third party redistribute a modified L0 inside their own product before the
   Change Date, and does "competing framework" reach that?
4. May schemas, the contract registry, generated projections, conformance
   tooling, and architecture prose be relicensed permissive now, independent
   of kernel code (Option A's precondition)?
5. Patent posture: BBSL carries no explicit patent grant before conversion;
   Apache-2.0 brings one after. Is a defensive patent grant needed
   pre-Change-Date?
6. Contribution intake: is §4 sufficient provenance for inbound contributions
   given automatic conversion, or is DCO/CLA required?
7. Trademark/certification separation: confirm a `CertificationClaim` under
   the ecosystem-assurance contracts never requires a trademark license, and
   that mark reservation does not encumber independent implementations.
8. Change Date mechanics: confirm conversion is self-executing for all copies
   distributed before the date, and whether November 6, 2029 remains the
   intended date.

## What The Accepted ADR Must Bind

1. The license per component class, as a machine-readable per-path manifest.
2. The fixed grant language (D-1 resolved) and defined Licensed Work (D-2).
3. The open-protocol-surface enumeration required by the flywheel doc,
   version-controlled with the manifest.
4. The trademark/certification separation rule, cross-referenced by
   `ecosystem-assurance-certification-liability.md`.
5. Supersession posture toward `LICENSE-BBSL` (amend in place vs. versioned
   successor) and the contribution-intake rule.

## Non-Claims

- This opener decides nothing; the owner and counsel decide.
- No statement here is legal advice; it enumerates questions for review.
- Nothing here changes what any current license permits today.
