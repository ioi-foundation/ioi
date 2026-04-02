# Studio Artifact Benchmark Suite

This directory is both the retained evidence store for Studio artifact runs and
the source of truth for the artifact benchmark suite.

Key files:

- `benchmark-suite.catalog.json`
  Static benchmark catalog with fixed prompts, typed outcome requests, required
  interaction contracts, and golden evaluation criteria.
- `corpus-summary.json`
  Generated aggregate index across retained case summaries. This now includes
  `benchmarkSuite`, which joins the catalog to the latest matching retained
  evidence and computes benchmark metrics truthfully.
- `conformance-report.json`
  Generated anti-cheating conformance report covering benchmark-specific
  routing leakage, retained skill-name shortcuts, paraphrase stability across
  multi-binding cases, and shim-dependent tracked parity success.
- `release-gates.config.json`
  Source-of-truth release-bar configuration for the Studio artifact lane. Each
  gate binds to a retained metric or conformance source, defines a ship
  threshold, and carries a ratchet floor so the quality bar can rise over time
  without hiding regressions.
- `release-gates.json`
  Generated hard-gate report for the current retained lane. This report marks
  each gate as pass, fail, or pending-measurement, lists blocking gates, and
  emits ratchet candidates when the current retained value materially clears the
  configured floor.
- `parity-loop/ledger.json`
  Receipt-driven bounded autonomy ledger for the Codex parity loop. Each entry
  records the selected intervention family, weakest target, keep/drop decision,
  and stop condition without introducing lexical routing or heuristic fallback
  behavior.
- `distillation/ledger.json`
  Retained winner-versus-loser distillation proposals. Each proposal records
  before/after structural deltas, typed reasons, target upgrade families, and
  any measured post-application gain once a proposal has been folded back into
  the default lane.
- `arena/pairwise-matches.json`
  Optional blind pairwise evidence input. When present, the summary generator
  computes an Elo table and win-rate against external references without
  changing the primary artifact pipeline. Pairwise rows may additionally carry
  `leftExecutionId` / `rightExecutionId` when the comparison needs to bind a
  judgment to specific retained internal executions instead of participant
  aliases alone.
- `arena/external-references.json`
  Optional retained catalog of external reference artifacts used by the arena.
  These references are evidence records only; they inform comparative scoring
  and dashboard visibility but never routing shortcuts inside the artifact lane.
- `arena/ledger.json`
  Generated frontier-arena ledger. This file derives internal stack
  participants from retained artifact evidence, resolves blind pairwise matches
  against those participants, records provisional and blind winners per
  benchmark, and emits a pending blind-match queue for comparative gaps that
  still need evidence.

Benchmark metrics are reported with explicit availability:

- metrics that are directly grounded in retained evidence are emitted with
  `available: true`
- metrics that require receipts not yet emitted by the runtime remain present
  but `available: false`

Render-aware metrics are now grounded when retained generation evidence carries
`renderEvaluation` receipts:

- `screenshotQualityScore`
  Derived from the normalized render-evaluation overall score once first-paint
  desktop/mobile capture clears.
- `responsivenessScore`
  Derived from desktop/mobile capture preservation ratios across visible
  elements, visible text, and interactive controls.

This keeps the suite honest: missing measurements stay missing instead of being
filled in with ad hoc lexical or benchmark-specific shortcuts.

Arena receipts stay honest the same way:

- benchmark leaders are marked as `provisional` unless blind pairwise evidence
  produces a unique winner
- external references can carry optional structural metadata such as
  `generatorStackId`, `judgeStackId`, `scaffoldFamilyId`,
  `componentPackProfileId`, and `skillSpineId` so comparative ratings remain
  typed and replayable instead of inferred from prompt text

Release-gate receipts stay honest too:

- unavailable measurements remain `pending_measurement` instead of being filled
  with placeholder pass values
- lexical-routing checks are sourced from the retained conformance report rather
  than informal dashboard logic
- ratchet candidates are proposed, not silently adopted, so raising the floor
  remains an explicit decision
