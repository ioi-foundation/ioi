# 08 — Current State: Where Implementation Truth Lives

Status: architecture guide chapter (non-owning synthesis).
Canonical owner: this file for the reading order and narrative sequencing of
how to find and read implementation status only; every status fact is owned by
the linked index or owner doc, which wins on any point of substance.
Supersedes: none (originates no doctrine).
Superseded by: none.
Last alignment pass: 2026-08-16.
Doctrine status: canonical
Implementation status: mixed (this chapter is a map to status truth and makes
no per-object built/partial claim; status truth lives in
[`canon-to-code-delta.md`](../_meta/canon-to-code-delta.md) and the
[`work-items/`](../_meta/work-items/) records)
Last implementation audit: 2026-08-16

## The Two Live Indexes

The chapters before this one describe the **target** architecture, and the
corpus is deliberate about never letting target prose read as shipped fact.
Exactly two indexes carry current implementation truth:

- [`canon-to-code-delta.md`](../_meta/canon-to-code-delta.md) — the
  object-level delta between canon and what the code durably implements, row
  by row, each cell carrying its own measurement basis. Its reading rules are
  the honest core: `not started` means the durable form does not exist even
  when an adjacent substrate is named as precedent, and a precedent is never a
  partial instance.
- the [`work-items/`](../_meta/work-items/) records — machine-checked status
  records whose code anchors, evidence paths, and status vocabulary are
  validated by `npm run check:architecture-docs` on every run.

The former implementation matrix is archived: it moved to
`_archive/implementation-logs/` on 2026-08-08, and its stub at
[`implementation-matrix.md`](../_meta/implementation-matrix.md) redirects to
the two live indexes above. Cite the archived matrix only as historical
evidence of the tree at its 2026-07-20 basis, never as current truth.

## How To Read A Status Claim

Every canon file carries two orthogonal axes in its header, owned by
[`doc-classes.md`](../_meta/doc-classes.md): `Doctrine status` says whether
the prose is authoritative (`canonical | reference | archived`), and
`Implementation status` says whether the described system exists today
(`built | partial | planned | speculative | mixed | n/a`), with code anchors
required for `built` and `partial`. The axes are independent — future doctrine
is still doctrine, and a file may be canonical and speculative at once. Never
demote doctrine because implementation is future, and never promote
implementation because doctrine is confident.

## What The Corpus Itself Says Is Not Yet Claimed

This section states no status of its own; it points at owners that carry their
honest position in their own text, so a reader knows where the major
distances are recorded:

- The end-to-end **standalone conformance pass** and the **zero-to-operable
  product journey** are target contracts the estate has not yet passed —
  stated by
  [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)
  in its Standalone Local Completeness and Zero-To-Operable sections.
- The **north-star network proof** is an unmet target — stated by
  [`internet-of-intelligence.md`](../foundations/internet-of-intelligence.md)
  in its own status line and non-claims.
- **AIIP transport** and the two-sovereign-system demonstration are planned —
  stated in the status header of [`aiip.md`](../foundations/aiip.md).
- **IOI L1** is speculative design authority with no deployment — stated in
  the status header of
  [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md).
- The full **ImprovementCampaign** protocol is planned over partial
  primitives — stated in the status header of
  [`bounded-recursive-improvement.md`](../foundations/bounded-recursive-improvement.md).

For everything else — and for the current form of everything above — consult
the delta file and the work-item records directly; their rows outrank any
narrative, including this one.

## Sequencing

What gets proven next, and in what order, is owned by
[`execution-horizons.md`](../_meta/execution-horizons.md) — the convergence
target and the gated later horizons. The guide deliberately ends here: the
story you have read is the target; the horizon file and the two live indexes
are how the estate keeps the story honest while it is built.

## Owners For This Chapter

- [`canon-to-code-delta.md`](../_meta/canon-to-code-delta.md) — object-level
  implementation truth.
- [`work-items/README.md`](../_meta/work-items/README.md) — the tracked
  work-item record index.
- [`doc-classes.md`](../_meta/doc-classes.md) — the status-axis vocabulary.
- [`execution-horizons.md`](../_meta/execution-horizons.md) — proof order and
  horizon gates.
