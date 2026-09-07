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

## Iteration 004 — Spend wired to budgets (2026-09-07)

**Should look and feel like:** a cost page — a budgets ledger at the top (budget,
spent, remaining, limit, drawn bar in ink), then the two panels no route feeds,
settled spend and quoted-versus-settled, with their Unwired placeholders, then the
provenance rules. **Route:** budgets. Settled spend stays a labelled door (no route on
the capability table; the fee object does not exist).

Captures: `.artifacts/console/004-spend/` (6). Before: `001-shell/spend-1440.png`
(a fully unwired stub).

What the captures show. At 1440 (`004-spend/spend-1440.png`) the ledger carries the
daemon's one external_spend budget — USD 0 spent, USD 5 remaining, 0% drawn — with
its id, creation time and the wallet-authorization note, and the "wired · GET
/api/budgets" chip beside the heading. At 390 the five-column ledger scrolls with the
fade cue; only Budget and Spent are visible without scrolling, which is the right
first pair. The gate gains an assertion that Spend reads budgets AND still draws
settled spend as an Unwired door naming SpendEstimate; three planted mutants
(Unwired removed, the budgets read removed, the shape moved into a comment) each
turned it red before it was committed green.

| Surface | before → after (R H C T D M A K) | Capture |
|---|---|---|
| Spend | 6 9 7 8 3 – 7 7 → 8 9 7 8 5 7 7 7 | `004-spend/spend-1440.png`, `spend-390.png` |

## Iteration 005 — the owner's complete identity (2026-09-07, owner-directed)

The owner ruled that every asset I had generated leaves, and delivered the identity
complete as `Brand Identity Standalone.html`. Its assets are decoded verbatim into
`brand/mark/source/` and served byte-for-byte from `/brand/`; the header carries the
owner's animated SVG mark (their replica engine, ported with its arithmetic kept),
with their static `mark-dark.svg` under reduced motion. Nothing is redrawn.

Captures: scratch `owner-header.png` (idle: the cut open at the owner's default
position, network inside), `owner-header-hover.png` (the cut follows the pointer),
`owner-header-reduced.png` (the static file), `owner-brand-page.png` (the owner's
page: hero, animated SVG mark, both lockups, four mark variants, glyph at 96/48/32/16,
colour system, usage rules). The WebGL hero loads three.js from unpkg and shows only
the wordmark offline, which the page says.

What the captures show at header size (42px): the cut and its network read as a
dense dark block with cyan points; hover motion is visible; the static mark under
reduced motion reads cleanly. Open: no blind reader has scored the owner's mark on
the face; the header's compact 1.9× ratio against the owner's 2.65× rule stands.

## Iteration 006 — Sources & health as a health panel (2026-09-07)

**Should look and feel like:** a health page — three tiles that count the sets a
console user asks about first (quoting, answering without a price, unavailable by
name), each naming the daemon's state word, each a button that narrows the evidence
ledger beneath. **Route:** candidate-sources, unchanged.

Captures: `.artifacts/console/006-sources/` (6). Before: `000-baseline/sources-1440.png`.

What the captures show. At 1440 (`006-sources/sources-1440.png`) the three tiles sit
above the ledger: 2 quoting in green, 3 answering, 8 unavailable in a dashed tile;
the heading reads "Sources & health" and the meta line names the route and read time.
At 390 the tiles stack as rows. Measured in a browser: the first tile is reached at
the 17th Tab, Enter narrows the ledger from 13 to 8 rows, `aria-pressed` flips on the
pressed tile, and the focus ring is a solid 2px outline. Still visible at 390: the
state chips break mid-token (`live_quote_sour/ce`), open since the baseline (item 8).

| Surface | before → after (R H C T D M A K) | Capture |
|---|---|---|
| Sources & health | 4 9 6 7 5 7 7 6 → 7 9 7 7 6 7 8 7 | `006-sources/sources-1440.png`, `sources-390.png` |

## Iteration 007 — Jobs & receipts as a resource table (2026-09-07)

**Should look and feel like:** the ledger a console user expects — sortable from the
column headers (time, receipts, venue, state), a row of state filters carrying the
daemon's own state words with counts, a header that stays in view down a long
ledger — with every row still carrying its receipts as objects. **Route:** jobs,
unchanged. The rail entry reads "Jobs & receipts".

Captures: `.artifacts/console/007-jobs/` (6) and `007-jobs-r2/` (after the sticky
fix); scratch `jobs-sticky.png`. Before: `000-baseline/receipts-1440.png`.

What the captures show. At 1440 (`007-jobs-r2/receipts-1440.png`) the filter row
reads all 33 · admitted_proposal 5 · placed 18 · refused_authority 8 ·
refused_provider_operation 2; the Job header carries the sort arrow. Measured in a
browser: the sort button flips `aria-sort` to ascending and the first row changes;
pressing a filter narrows 33 → 5 rows; the live region announces the count and the
sort; after scrolling 900px the header's top edge sits at 56px, flush under the top
bar. Round 1 defect, fixed in r2: the first cut capped the ledger at 70vh with an
inner vertical scroll and no cue — three rows then the notes in a full-page capture
(the silent truncation standing practice §8 names). The header now sticks to the page
at 1300px and up, where the ledger needs no sideways scroll; below that it scrolls
sideways as before with no sticky head. At 390 only Job and Authority are visible
before scrolling, so the state that the filters act on is off-screen (open).

| Surface | before → after (R H C T D M A K) | Capture |
|---|---|---|
| Jobs & receipts | 3 9 6 7 6 7 7 6 → 7 9 7 7 8 7 8 7 | `007-jobs-r2/receipts-1440.png`, `receipts-390.png` |

## Iteration 008 — the header lockup at the owner's ratio (2026-09-07, owner-directed)

The owner: the mark is bigger than the wordmark on every lockup. The header now
follows the rule exactly — mark 2.65× the wordmark block, gap 7.5% of the mark's
width — at a 20px block, and the top bar grew from 56 to 64px to hold it; the rail
and the sticky table heads follow a `--topbar-h` token. Measured in a browser at
1440 and 390: mark 53px tall over a 20px wordmark block (ratio 2.65), gap 6.67px
(7.49% of the mark's width), lockup 217.5px wide, no horizontal overflow. Captures:
scratch `lockup-265-1440.png`, `lockup-265-390.png`. The compact 1.9× deviation is
retired from the audit's open items.

## Iteration 009 — catalogue anchors in the rail (2026-09-07)

**Should look and feel like:** the product families a console lists under "all
products" — Compute, Storage, Networking, Runtime — as sub-entries under All
resources, each an address (`#/catalog/<family>`) that opens the catalogue at that
family alone with its own heading, a crumb back, and counts scoped to the family.
**Routes:** candidate-sources and candidates latest, unchanged; no new surface — the
anchors are views of one surface, so the registry and the gate's sweep are unchanged.

Captures: `.artifacts/console/009-anchors/` (four families × 1440 and 390, each
labelled with the wait it observed); scratch `anchor-compute-1440.png`,
`anchor-compute-390.png`.

What the captures show. At 1440 the rail shows the four anchors indented under All
resources with Compute marked by the edge bar; the page is headed "Compute" with a
crumb "All resources · Compute", the family's four classes in one table, no hero.
Pressing All resources in the rail returns to the whole catalogue (hash `#/catalog`,
hero back, six categories). At 390 the anchors sit as chips in the rail row. Measured:
h1 = the family name, `aria-current="location"` on the open anchor, no horizontal
overflow at either width. Round 1 defect, fixed in the same iteration: the family
page said "0 quoting live prices" before the candidates read landed — the line now
says "asking the daemon" until it does.

| Surface | before → after (R H C T D M A K) | Capture |
|---|---|---|
| All resources (catalogue) + anchors | 7 9 7 8 6 7 7 7 → 8 9 7 8 6 7 7 7 | `009-anchors/catalog-compute-1440.png`, `-390.png` |

## Iteration 010 — Candidates: venue filter and sortable price / good-for (2026-09-07)

**Should look and feel like:** the price table with a console's controls — a venue
filter row carrying each venue's live count, the price and good-for headers
sortable — while the venue grouping the readers asked for stays, and cheapest first
stays the default so the headline still equals row one. **Route:** candidates
latest, unchanged.

Captures: `.artifacts/console/010-candidates/` (6). Before: `001-shell/candidates-1440.png`.

What the captures show and the browser measured (1440): filter row "all venues 42 ·
runpod 18 · vast 24"; pressing vast narrows 42 → 24 rows in one group; the price
header flips to descending and the first row becomes $7.8900 from $0.0222, with the
live line reading "all 42 live quotes · dearest first"; `aria-sort` follows. The
grouped shape, per-venue cheapest and freshness bars are unchanged.

| Surface | before → after (R H C T D M A K) | Capture |
|---|---|---|
| Candidates | 4 9 7 8 7 8 7 7 → 6 9 7 8 8 8 8 7 | `010-candidates/candidates-1440.png`, `-390.png` |

## Iteration 011 — the phone chrome (2026-09-07)

**Should look and feel like:** at 390 a compact band — lockup, search, two short
chips, the surfaces, one status line — and then the page; state words that wrap at
their underscores; the hero's four numbers without the drawing they cannot hold.
**Routes:** none.

Captures: `.artifacts/console/011-phone/` (round 1) and `011-phone-r2/` (final):
`home-390.png`, `sources-390.png`.

Measured in a browser at 390 (Settings, the shortest surface): the first heading
sat **544px** down the screen before (bar 177 + rail 345); **448px** after round 1
(short chip words, scope line gone, tighter rail); **394px** after round 2 (the
catalogue anchors leave the phone rail, where the catalogue's own headings are a tap
away). Every rail button keeps a visible box. Chips now break at their underscores
(`candidate_source_` / `unavailable`) instead of mid-token; source names in the
Sources and Home tables do the same. Below 430 the hero's routing strip and its
caption are not drawn; the four numbers and their reasons stay.

| Surface | before → after (R H C T D M A K) | Capture |
|---|---|---|
| Chrome at 390 | 7 9 6 8 – – 7 7 → 7 9 7 8 – – 7 7 | `011-phone-r2/home-390.png` |
| Sources & health at 390 | (chip wrap) → fixed | `011-phone-r2/sources-390.png` |

Open: 394px is still a lot of chrome before the first heading; the next step is a
phone-only disclosure for the rail, which needs the gate's nav-visibility assertion
rewritten to open it first (and mutation-tested), so it is its own iteration.

## Iteration 012 — the 404 and the daemon-down state as compositions (2026-09-07)

**Should look and feel like:** an address that is not a surface gets a page inside
the shell — the address verbatim, "resolves to no surface", the surfaces by name —
instead of silently landing on Home; a read the daemon did not answer keeps its named
state and reason and adds what to do next, with no timer and nothing spinning.
**Routes:** none. The 404 is not a registered surface.

Captures: `.artifacts/console/012-errors/` — `notfound-1440.png`, `notfound-390.png`
(address `#/nope/here`), `down-sources-1440.png`, `down-home-390.png` (a second
server pointed at a dead daemon port).

What the captures show. The 404 sits in the shell with the rail intact, the address
in mono at reading size and all thirteen surfaces listed with their addresses and
unwired marks; the live region says "No surface at nope/here". Daemon-down: each
read's panel is headed "the daemon did not answer · candidate_plane_unreachable" with
the proxy's reason verbatim and a next-steps line; Home shows four such panels, one
per widget. Fixed in the same iteration: Sources and Home announced "0 quoting, 0
unavailable" and four zeros as counts when every read had failed; they now announce
that the daemon did not answer. Open: Home's four identical fault panels want one
banner, which needs a shell-level notion of "the daemon is down" (next item).

| Surface | before → after (R H C T D M A K) | Capture |
|---|---|---|
| 404 | – 7 4 – – – – 4 → 8 9 7 8 – – 8 7 | `012-errors/notfound-1440.png` |
| Daemon-down | (per-read panel) → 7 9 6 8 – 8 8 7 | `012-errors/down-home-390.png` |

## Worklist (lowest score × importance first)

1. ~~The console shell~~ — landed in iteration 001.
2. ~~Home~~ — landed in iteration 003 (R 8 H 9 C 7 T 8 D 6 M 7 A 7 K 7).
3. ~~Spend wired to budgets~~ — landed in iteration 004.
4. ~~Sources & health as a health panel~~ — landed in iteration 006.
5. ~~Jobs list as a resource table~~ — landed in iteration 007 (sort, filter, sticky head at ≥1300).
6. ~~Catalogue anchors~~ — landed in iteration 009.
7. ~~Candidates: sort and filter controls~~ — landed in iteration 010 (no sticky head: the grouped table's row-group heads are the anchors).
8. ~~Phone chrome~~ — iteration 011 took it from 544 to 394px before the h1, fixed
   the chip wrap and hid the drawing at phone width. Remaining: a phone rail
   disclosure (needs the nav-visibility assertion rewritten and mutation-tested).
9. ~~404 and daemon-down as compositions~~ — landed in iteration 012. Remaining: one
   daemon-down banner on Home instead of four panels.
10. Live-region narration transcripts for a rail navigation and a search.

## Kernel gaps this console waits on (recorded, not decided here)

- Settled provider spend / reconciliation read: no daemon route on the capability
  table; design doc §7 — `fee_object_minted: false` at both sites, no fee object.
- Principal and CapabilityLease read for a wallet session: no route on the table;
  design doc §3 — the agent path resolves a lease draw-down server-side.
- Supply registry (`CloudSupplyRegistration`): canon object, no route; ADR 0051 §4.
- Redundancy beyond `none`: design doc §8.3, refused by name.
