# decentralized.cloud console — audit and worklist

The live scoreboard for the console programme on branch `decentralized-cloud/console`.
Every score is read off a capture in `.artifacts/console/<iteration>/` (kept locally,
not committed) or a measurement taken in a browser — never off the source. A score
that cites no capture is not a score.

Axes, 0–10, as the loop prompt defines them: **R**ecognisability · **H**onesty ·
**C**omposition · **T**ypography · **D**ata density · **M**otion · **A**ccessibility ·
**K** (craft). Visitor importance: Home 5 · catalogue 5 · Jobs 4 · Spend 4 · Sources 4 ·
Candidates 3 · Placement 3 · Receipts 3 · IAM 2 · Supply 2 · Redundancy 2 · API 2 ·
Settings 1 · palette 2 · 404/error 2.

Capture instrument: `ITER=<name> PORT=4240 node scripts/console-capture.mjs` — every
registered surface at 390 / 768 / 1180 / 1440 / 1920 plus a reduced-motion pass at
1440, each image labelled with the state it caught and the wait it observed, with an
`index.json` of the measurements.

## Iteration 000 — baseline (2026-09-07)

Captures: `.artifacts/console/000-baseline/` — 49 images. Every read-backed surface
loaded (catalog after 49.6 s at 1440, sources 31.1 s, placement 13.8 s, candidates
4.9 s); nothing was scored from a waiting page.

What the captures show. The product is a public **face**, not a console: one row of
eight text tabs under a lockup, a dark hero with the cheapest live quote at 168px, then
"All resources" as a two-up directory of category tables. It is honest and it is
handsome, and a stranger from AWS or GCP would not call it a console: there is no
product rail, no search, no account or region control, no health or cost panel on
the landing, no jobs list, no activity trail as a first-class object. At 390 the eight
tabs wrap into three rows with the honesty chip on its own line above the surfaces.

| Surface | R | H | C | T | D | M | A | K | Note (capture) |
|---|---|---|---|---|---|---|---|---|---|
| Home | 0 | — | — | — | — | — | — | — | does not exist; the landing is the catalogue |
| All resources (catalogue) | 5 | 9 | 7 | 8 | 6 | 7 | 7 | 7 | directory reads well at 1440 (`catalog-1440.png`); no rail/search around it; 6,117px tall at 390 (`catalog-390.png`) — the hero's 44-column routing drawing is unreadable at phone width |
| Candidates | 4 | 9 | 7 | 8 | 7 | 8 | 7 | 7 | grouped price table is dense and correct (`candidates-1920.png`); no sort/filter controls; nothing says "compute" |
| Sources & health | 4 | 9 | 6 | 7 | 5 | 7 | 7 | 6 | health is a two-column ledger, not a panel (`sources-1440.png`); at 390 chips wrap mid-token `live_quote_sour/ce` (`sources-390.png`) |
| Placement | 4 | 9 | 7 | 8 | 5 | 7 | 7 | 7 | what/answer table (`placement-768.png`); no posture controls; the "region selector" counterpart is absent |
| Submit a job | 5 | 9 | 6 | 7 | 5 | 7 | 8 | 7 | a lane and a form; recognisable as "create"; not scored on a capture yet beyond 1440 |
| Redundancy | 4 | 9 | 7 | 7 | 5 | — | 7 | 7 | labelled unwired; postures table |
| Receipts | 3 | 9 | 6 | 7 | 6 | 7 | 7 | 6 | a ledger; not yet the activity trail a console has |
| Spend | 0 | — | — | — | — | — | — | — | does not exist |
| IAM (leases) | 0 | — | — | — | — | — | — | — | does not exist; no principal anywhere in the chrome |
| Supply registry | 0 | — | — | — | — | — | — | — | does not exist |
| API | 5 | 10 | 7 | 8 | 6 | — | 7 | 7 | generated allowlist tables |
| Settings | 0 | — | — | — | — | — | — | — | does not exist |
| Command palette / search | 0 | — | — | — | — | — | — | — | does not exist |
| 404 / daemon-down | — | 7 | 4 | — | — | — | — | 4 | JSON refusals from the proxy; no composition |
| Chrome (topbar + nav) | 2 | 9 | 6 | 8 | — | — | 7 | 7 | eight tabs in a row; at 390 three rows of chrome before the product (`sources-390.png`) |
| Chip / Freshness / Receipt / Waiting | — | 9 | 8 | 8 | — | 8 | 8 | 8 | the reusable pieces are the strongest part of the product |

## Iteration 001 — the console shell (2026-09-07)

**Should look and feel like:** a product rail down the left with grouped surfaces and
the current one marked in ink; a top bar with the lockup, a search box, and the two
chips a console keeps top-right — principal and placement posture — each linking to
the surface that draws what it stands for. The rail's foot carries the daemon host and
the generated capability chip, the console's "project line".
**Routes:** no new daemon route. Spend, IAM and Supply registry are labelled stubs
(no route on the table reads settled spend, a principal's leases, or the registry);
Settings reads `/api/face-config`, the surface's own in-process route.

Captures: `.artifacts/console/001-shell/` (72, every surface × 5 widths + reduced
motion), `001-shell-look/`, `001-shell-r2/` (after the two gate failures were fixed).

What the captures show. At 1440 (`001-shell/catalog-1440.png`, `001-shell-r2/api-1440.png`)
the page reads as a console at a glance: rail, search, two chips top-right, the
surface in the remaining column with the hero as a band. At 390
(`001-shell-r2/supply-390.png`) the rail becomes three wrapped rows of buttons under
the lockup, search and chips — about 430px of chrome before the h1, down from 640 in
the first cut but still more than a phone should carry (open item 8). The rail's
foot chip wraps to two lines at 232px. The catalogue at 1440 first fell to one
column beside the rail (4,415px tall vs 3,461 before); the two-up track was narrowed
to 520px and it is two-up again.

Gate: run 1 failed twice — `Spend names the canonical shape it draws` (the object was
named only in a stripped comment; it is now in the panel's own words) and
`at 390px no text is painted over other text` on Supply ("Evidence mode" over "Fee
basis": the five-column register was allowed to reflow at phone width; it scrolls
now, like every other four-plus-column table). Run 2: see the commit.
Also fixed on the way: `check:decentralized-cloud-spend-fence` could not start the
proxy in a fresh worktree because `dist/` did not exist yet — the fence now hands the
proxy a scratch directory, since it tests the write lane and never fetches the shell.

| Surface | before → after (R H C T D M A K) | Note |
|---|---|---|
| Chrome (rail + top bar) | 2 9 6 8 – – 7 7 → 7 9 7 8 – – 7 7 | rail, search, chips; phone chrome still tall |
| All resources | 5 9 7 8 6 7 7 7 → 7 9 7 8 6 7 7 7 | recognisable inside the shell; content unchanged |
| Spend | 0 → 6 9 7 8 3 – 7 7 | drawn, labelled, no figure; budgets to wire (item 3) |
| IAM · leases | 0 → 6 9 7 8 3 – 7 7 | drawn, labelled |
| Supply registry | 0 → 6 9 7 8 3 – 7 7 | drawn, labelled; venues route to wire |
| Settings | 0 → 6 9 7 8 5 – 7 7 | wired to face-config |
| Command palette / search | 0 → 4 9 7 8 – – 7 6 | filters surfaces only, and says so; `/` focuses |

Accessibility measured on this iteration: every rail button is a real `<button>` with
`aria-current="page"` on the active one; the unwired mark carries sr-only text; the
search input has a scope description; the skip link still lands on `#surface`. Not
yet measured: narration transcripts of the live region across a rail navigation
(item 10).

## Iteration 002 — the owner's mark (2026-09-07, owner-directed)

The owner ruled mid-loop that the three-lobe mark landed on the product branch is
"not the final mark" and that their brand page (`Brand Identity.dc(1).html`) holds
the current one: a cloud that opens into a network, with the hover cloud as the hero.
The vector for that page's static SVGs was nowhere on disk, so the mark was rebuilt
from the owner's own geometry: the four circles and rect of `cloud-hover.html`, with
a three-node network knocked out of the right lobes. One source (`brand/mark/mark.mjs`),
eleven regenerated SVGs, the hover cloud served verbatim at `/brand/hover.html`
(recoloured to the brand gradient, reduced motion honoured), the brand page rewritten,
and the retired drawings removed from `brand/` (last in commit d9e22de35).

The owner then ruled that the header carries the **animated** primary lockup. The
owner's pure-SVG "cloud to network" animation (no WebGL) is ported as
`src/components/AnimatedMark.jsx`, reading its geometry and timing from `mark.mjs`
(`ANIM`): the cloud is clipped at a seam, a pixel field and a network of squares
build on the right, pulses ride the network, the seam sweeps as the cloud
reabsorbs it, and it recedes, on an eleven-second loop. It pauses while the tab is
hidden and is replaced by the static cut mark under reduced motion. The standalone
file is served at `/brand/mark-animated.html`; the canvas hover cloud stays the
hero at `/brand/hover.html`.

Captures: scratch `anim-dsf3.png` (header at 3×, mid-build: pixels and nodes at
3.7px), `anim-big.png` (the same at a 120px block), `anim-header-reduced.png`
(reduced motion: the static mark), `brand-page-new.png`. The header lockup measures
42 × ~212px at the 22px block. Motion axis for the chrome: the loop is brand
motion and claims nothing about data; Settings says so and names both motions on
the face. Open: no blind reader has scored this mark; the header uses a compact
1.9× ratio against the owner's 2.65× rule and says so on the brand page; the
network is 3.7px at header size and reads as texture rather than as squares.

## Iteration 003 — Home (2026-09-07)

**Should look and feel like:** the page a console opens on — a row of quick actions,
then widgets a stranger recognises by name: Health, Cost and usage, Recent activity,
Live now, Recently visited — each figure with its route and read time under it.
**Routes:** candidate-sources (health), budgets (cost), jobs (activity, gate records
hidden as on Receipts), candidates latest (live now). Settled spend is an Unwired
placeholder; Recently visited is localStorage only and says so. Home is now the
default surface; All resources keeps the hero.

Captures: `.artifacts/console/003-home/` (6, all widths + reduced), `003-home-r2/`
(after two fixes). Before: Home did not exist (`000-baseline/catalog-1440.png` is
what a visitor landed on).

What the captures show. At 1440 (`003-home-r2/home-1440.png`) the page reads as a
console home at a glance: four tiles, then Health (13 rows, two quoting), Cost
(one budget: USD 0 spent of 5, bar in ink), Activity (five newest records with
state, venue, receipts), Live now, Recently visited. Every widget ends on its route
and read time. Round 1 defects, both fixed in r2: the cost widget stretched to the
health table's height with ~500px of nothing inside; the activity state chip broke
mid-token at 390. Still visible: at 390 the health table's source names wrap
mid-token (`customer_inven/tory`); under a busy daemon every read landed at ~30 s
while the "asking" line quotes the quiet-daemon cost ("under a second") — honest
about what was measured, not about the moment.

| Surface | R | H | C | T | D | M | A | K | Capture |
|---|---|---|---|---|---|---|---|---|---|
| Home | 8 | 9 | 7 | 8 | 6 | 7 | 7 | 7 | `003-home-r2/home-1440.png`, `home-390.png` |

## Worklist (lowest score × importance first)

1. ~~The console shell~~ — landed in iteration 001.
2. ~~Home~~ — landed in iteration 003 (R 8 H 9 C 7 T 8 D 6 M 7 A 7 K 7).
3. **Spend** wired to budgets; reconciliation stays a labelled door.
4. **Sources & health as a health panel** — a status strip above the ledger.
5. **Jobs list** as a resource table (sortable, sticky header) with Receipts as detail.
6. **Catalogue anchors** — Compute / Storage / Network / Runtime as rail entries that
   open the catalogue filtered.
7. **Candidates**: sort and filter controls, sticky header.
8. Phone chrome: ~430px before the h1 at 390 (`001-shell-r2/supply-390.png`); the
   hero's routing drawing at 390; chip wrap mid-token on Sources.
9. 404 and daemon-down as compositions.
10. Live-region narration transcripts for a rail navigation and a search.

## Kernel gaps this console waits on (recorded, not decided here)

- Settled provider spend / reconciliation read: no daemon route on the capability
  table; design doc §7 — `fee_object_minted: false` at both sites, no fee object.
- Principal and CapabilityLease read for a wallet session: no route on the table;
  design doc §3 — the agent path resolves a lease draw-down server-side.
- Supply registry (`CloudSupplyRegistration`): canon object, no route; ADR 0051 §4.
- Redundancy beyond `none`: design doc §8.3, refused by name.
