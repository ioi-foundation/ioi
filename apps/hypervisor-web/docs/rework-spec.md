# hypervisor.com Rework Spec (Phase 2 — GATED)

Gate: the application suite is operationally complete and every shot in
`shot-list.md` is site-shot certified. Until then this spec is the plan of
record and nothing in it is executed. Claim rules and taxonomy come from
`docs/architecture/_meta/public-web-estate.md`; strings come from the estate
messaging spine (`src/config/estateMessaging.js`); stage labels come from the
status manifest (`src/config/estateStatus.js`).

## Master frame

Promote the Type-1/2/3 lineage (today a section on /platform, `PgLineage`)
to the site's organizing frame:

- Hero keeps "The operating environment for autonomous systems" but the first
  visual beat becomes the lineage: hardware virtualized (T1), operating
  systems virtualized (T2), autonomous work governed (T3, includes the layers
  beneath).
- HypervisorOS stays labeled from the manifest wherever the lineage renders —
  the lineage is a framing claim, never a shipping claim.

## Two lanes as top-level structure

- **Run on it** — the existing product story (Platform, products, solutions).
- **Attach it** — NEW page `authority-gateway.html`: detect an existing coding
  agent / MCP server → audit mode → attribute a sensitive action → hold for
  exact-action approval → execute or deny → full receipt trail. Built only
  when the adoption demo runs end-to-end (single-node proof exists in the
  daemon; the *product demo* is the gate). Lane copy = `TWO_LANES` from the
  spine; coverage claims bounded by the enforcement-coverage vocabulary.

## Mock → capture replacement map

Every DOM/CSS product mockup is replaced by a generated capture (see
`tools/capture-screens.mjs`). No staged screenshots, ever.

| Site component (today) | Replacement shot id |
|---|---|
| `HomeSections.jsx` `HeroPanel` (session + AUTHORITY GATE mock) | `shell-session-approval` |
| `PlatformApp.jsx` App/Web/CLI recreation | `shell-home`, `shell-web-org`, `cli-run` |
| `ProductPage.jsx` `SessionMock` (per product) | per-product shot ids (`app-*`, `web-*`, …) |
| `RuntimeSecurity.jsx` `AppMockup` | `shell-session-approval` or `gateway-hold` |
| Product feature-card gradient placeholders | per-app shots from `shot-list.md` |

Interim rule (pre-gate): mockups may remain but must be visibly labeled as
illustrative previews wherever a fresh reader could mistake them for the
shipped product.

## Page-by-page

- **Home** — hero + lineage beat + two lanes + doctrine band (unchanged) +
  govern (design guarantees, unchanged) + CTA. Proof bar flips from
  "Local private preview" only when the manifest flips.
- **Platform** — lineage moves up top; the 9-product families stay (packaging
  axis); each family card gains one real capture.
- **Product pages** — keep the install-focused template; terminal mocks stay
  (they are commands, not product claims) except design-stage products keep
  their honest no-build terminals until the manifest flips.
- **authority-gateway.html** — the attach lane (gated, above).
- **Solutions** — re-shot with real captures; copy re-audited against the
  spine; no structural change.
- **Docs** — dead nav links become real or are pruned; "ioi.ai outcomes"
  entry links the live property once activated.

## Explicitly out of scope

Design system, shell chrome, doctrine band content, Govern design-guarantee
stats (architectural invariants — they don't flip with usage), and anything
owned by the ioi-ai property.

## Execution checklist (run top to bottom when the gate opens)

1. `node tools/capture-screens.mjs --all` against a seeded daemon serve
   (no test flags — standing rule) → captures land in `src/assets/product/`.
2. Replace components per the map; label or delete every remaining mock.
3. Flip manifest stages only for surfaces that actually shipped.
4. Build authority-gateway.html if (and only if) the adoption demo runs.
5. `npm run build` (audit enforces banned claims + parity) + full-page
   headless render checks + screenshot review.
6. Cross-check every page against the 30-second fresh-reader bar.
