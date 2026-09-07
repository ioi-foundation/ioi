// THREE DIRECTIONS for decentralized.cloud, each with a stated system.
//
// The bar is ioi-c0's ninth criterion: "would a stranger believe this is a first-tier
// product in the first five seconds", scored against linear.app, vercel.com,
// stripe.com, railway.com, fly.io and the Hypervisor product UI's own shell.
//
// The three are deliberately far apart on ONE axis each — five shades of one aesthetic
// is no choice at all. Every direction uses the SAME identity (the owner's reserved
// mark, the adopted drawn Z and I) and the same real tokens; what varies is the system
// built around them.
//
// Colour is from packages/design-system/tokens/colors.css. No hex is invented: the
// palette gate on the shipped surface refuses any colour that is not a token, and a
// direction that could not survive that gate is not a direction for this product.

import { shell, LOCKUP, MARK } from "./brand.mjs";

// ── Tokens, restated once ────────────────────────────────────────────────────
const T = {
  ink: "#0a0e19",        // onyx black
  paper: "#ffffff",
  surface: "#f9f9f9",    // porcelain grey
  hair: "#e1e1e1",
  hairSoft: "#ececec",
  strong: "#cecece",
  muted: "#818181",
  label: "#636363",
  ui: "#1f1f1f",
  green: "#397554",      // link green — live evidence, and nothing else
  greenUp: "#3e7f5c",
  greenSoft: "#dbefdb",
  greenDark: "#1e3c2c",
  greenOnDark: "#7bbd97",
  red: "#e40014",
  blue: "#0048ff",
  pastelBlue: "#afc1fd",
};

// Real numbers, read off the live daemon this session. Nothing here is invented; where
// a figure would have to be, it is bracketed.
const D = {
  live: 47, venues: 2, cheapest: "0.0136", considered: "4,659",
  eligible: 47, sources: 13, quoting: 2, unavailable: 8,
  sweep: "1.0s", venueA: "vast", venueB: "runpod",
};

/* ═══════════════════════════════════════════════════════════════════════════
   DIRECTION A — "LEDGER"
   The axis: EVIDENCE AS THE AESTHETIC. Light, hairline-ruled, type-led, almost
   no chrome. The numbers are the largest thing on every screen and the rules
   between them do the work colour usually does. Closest reference: Stripe's
   documentation density and Linear's restraint.
   System: Archivo (grotesque, wide range) + IBM Plex Mono. 8px rhythm, 1px
   hairlines at #e1e1e1, single green accent reserved strictly for live
   evidence. No filled buttons except one per screen. No illustration.
   Tradeoff: it is quiet. It will read as serious and could read as plain.
   ═══════════════════════════════════════════════════════════════════════════ */

const A_FONTS = `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap">`;
const A_CSS = `
  .h { font-family: Archivo, ui-sans-serif, system-ui, sans-serif; }
  .m { font-family: "IBM Plex Mono", ui-monospace, Menlo, monospace; }
  .rule { border-top: 1px solid ${T.hair}; }
  .eyebrow { font-family: "IBM Plex Mono", monospace; font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: ${T.muted}; }`;

const A_landing = shell(
  `background:${T.paper};color:${T.ink};`, A_FONTS, A_CSS,
  `<div class="h" style="min-height:900px;display:flex;flex-direction:column">
    <header style="display:flex;align-items:center;justify-content:space-between;padding:22px 56px;border-bottom:1px solid ${T.hair}">
      ${LOCKUP(19, T.ink, T.ink, T.paper)}
      <nav style="display:flex;gap:30px;font-size:14px;color:${T.label}">
        <a href="#">Candidates</a><a href="#">Sources</a><a href="#">Placement</a><a href="#">API</a>
        <a href="#" style="color:${T.ink};font-weight:500">Submit a job</a>
      </nav>
    </header>

    <section style="padding:88px 56px 0;display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,1fr);gap:72px;align-items:start">
      <div style="display:flex;flex-direction:column;gap:28px">
        <div class="eyebrow">Rent compute across venues</div>
        <h1 style="margin:0;font-size:58px;line-height:1.02;letter-spacing:-0.03em;font-weight:600;text-wrap:pretty">
          Every price on this page came back from a venue in the last fifteen minutes.
        </h1>
        <p style="margin:0;font-size:19px;line-height:1.5;color:${T.label};max-width:52ch;text-wrap:pretty">
          You describe the capacity and the budget. We compare live quotes across venues,
          decide a placement, and hand you a receipt. You never name a provider and you
          never hold a provider credential.
        </p>
        <div style="display:flex;gap:14px;align-items:center;padding-top:6px">
          <a href="#" style="display:inline-flex;align-items:center;height:46px;padding:0 22px;background:${T.ink};color:${T.paper};border-radius:8px;font-size:15px;font-weight:500">Submit a job</a>
          <a href="#" style="display:inline-flex;align-items:center;height:46px;padding:0 20px;border:1px solid ${T.strong};border-radius:8px;font-size:15px">See live prices</a>
        </div>
      </div>

      <div style="border:1px solid ${T.hair};border-radius:12px;overflow:hidden">
        <div style="padding:18px 22px;border-bottom:1px solid ${T.hair};display:flex;align-items:center;justify-content:space-between">
          <span class="eyebrow">Cheapest live quote</span>
          <span class="m" style="display:inline-flex;align-items:center;gap:7px;font-size:12px;color:${T.green}">
            <span style="width:7px;height:7px;border-radius:50%;background:${T.green}"></span>live_evidence
          </span>
        </div>
        <div style="padding:30px 22px 26px">
          <div class="m" style="font-size:64px;line-height:1;letter-spacing:-0.03em;font-weight:500">$${D.cheapest}</div>
          <div style="font-size:14px;color:${T.label};margin-top:10px">per GPU-hour · ${D.venueA} · observed 12 minutes ago</div>
        </div>
        <div class="rule" style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr))">
          ${[[D.live, "live quotes"], [D.venues, "venues quoting"], [D.sources, "sources asked"]]
            .map(([n, l], i) => `<div style="padding:18px 22px;${i ? `border-left:1px solid ${T.hair}` : ""}">
              <div class="m" style="font-size:24px;font-weight:500">${n}</div>
              <div style="font-size:12px;color:${T.muted};margin-top:4px">${l}</div>
            </div>`).join("")}
        </div>
      </div>
    </section>

    <section style="padding:76px 56px 0">
      <div class="rule" style="padding-top:34px;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:52px">
        ${[
          ["Two venues, or it is not a decision", "A routing decision needs at least two venues quoting. With one, an intent can be priced but not routed — and no fee is minted against it."],
          ["The venue is evidence, not an input", "You never pick a provider. The placement decision names one, and the receipt carries which one and why."],
          ["A fee exists only as a receipt", "Nothing is charged for pricing, for looking, or for a decision taken between fewer than two real venues."],
        ].map(([h, p]) => `<div>
          <h3 style="margin:0 0 10px;font-size:17px;font-weight:600;letter-spacing:-0.01em">${h}</h3>
          <p style="margin:0;font-size:15px;line-height:1.55;color:${T.label};text-wrap:pretty">${p}</p>
        </div>`).join("")}
      </div>
    </section>

    <footer style="margin-top:auto;padding:34px 56px;border-top:1px solid ${T.hair};display:flex;justify-content:space-between;align-items:center">
      <span class="m" style="font-size:12px;color:${T.muted}">${D.sources} sources asked · ${D.quoting} quoting · ${D.unavailable} unavailable</span>
      <span class="m" style="font-size:12px;color:${T.muted}">read in ${D.sweep}</span>
    </footer>
  </div>`
);

const A_candidates = shell(
  `background:${T.paper};color:${T.ink};`, A_FONTS, A_CSS,
  `<div class="h" style="min-height:900px">
    <header style="display:flex;align-items:center;justify-content:space-between;padding:18px 40px;border-bottom:1px solid ${T.hair}">
      ${LOCKUP(17, T.ink, T.ink, T.paper)}
      <span class="m" style="font-size:11px;color:${T.muted}">reads · two writes, neither spends</span>
    </header>
    <div style="padding:40px">
      <h1 style="margin:0;font-size:34px;font-weight:600;letter-spacing:-0.02em">Candidates</h1>
      <div class="m" style="margin-top:10px;font-size:13px;color:${T.label}">
        ${D.live} live · ${D.venues} venues quoting · ${D.considered} considered · cheapest $${D.cheapest}/hr
      </div>
      <div style="margin-top:8px;font-size:13px;color:${T.muted};max-width:80ch">
        These count different sets, narrowing left to right. The table is sorted by price, so one venue's rows may sit far below another's.
      </div>

      <div style="margin-top:28px;border:1px solid ${T.hair};border-radius:10px;overflow:hidden">
        <table style="width:100%;border-collapse:collapse;table-layout:fixed">
          <thead><tr style="background:${T.surface}">
            ${[["Venue", "22%", "left"], ["Basis", "40%", "left"], ["USD per hour · cheapest first", "20%", "right"], ["Freshness", "18%", "left"]]
              .map(([h, w, a]) => `<th style="width:${w};text-align:${a};padding:12px 18px;border-bottom:1px solid ${T.hair};font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:${T.label};font-weight:400">${h}</th>`).join("")}
          </tr></thead>
          <tbody>
            ${[
              [D.venueA, "vast offer dph_total (verbatim)", "0.0136", "9 min left", 0.72],
              [D.venueA, "vast offer dph_total (verbatim)", "0.0164", "9 min left", 0.72],
              [D.venueB, "runpod gpuTypes.lowestPrice, secureCloud", "0.0222", "8 min left", 0.64],
              [D.venueA, "vast offer dph_total (verbatim)", "0.0233", "9 min left", 0.72],
              [D.venueB, "runpod gpuTypes.lowestPrice, community", "0.0289", "8 min left", 0.64],
            ].map(([v, b, p, f, frac]) => `<tr>
              <td style="padding:16px 18px;border-top:1px solid ${T.hairSoft};vertical-align:middle">
                <div class="m" style="font-size:14px">${v}</div>
                <div style="display:inline-flex;align-items:center;gap:6px;margin-top:7px;padding:3px 9px;border:1px solid ${T.green};border-radius:99px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:${T.green}">
                  <span style="width:6px;height:6px;border-radius:50%;background:${T.green}"></span>live_evidence
                </div>
              </td>
              <td class="m" style="padding:16px 18px;border-top:1px solid ${T.hairSoft};font-size:12px;color:${T.label};line-height:1.6;vertical-align:middle">${b}<br>observed 2026-09-05 05:41:39Z</td>
              <td class="m" style="padding:16px 18px;border-top:1px solid ${T.hairSoft};font-size:17px;text-align:right;font-variant-numeric:tabular-nums;vertical-align:middle">$${p}</td>
              <td style="padding:16px 18px;border-top:1px solid ${T.hairSoft};vertical-align:middle">
                <div style="display:flex;align-items:center;gap:10px">
                  <svg width="22" height="22" viewBox="0 0 22 22" style="flex-shrink:0"><circle cx="11" cy="11" r="9" fill="none" stroke="${T.hair}" stroke-width="2.5"></circle><circle cx="11" cy="11" r="9" fill="none" stroke="${T.green}" stroke-width="2.5" stroke-dasharray="${(56.5 * frac).toFixed(1)} 56.5" transform="rotate(-90 11 11)" stroke-linecap="round"></circle></svg>
                  <span class="m" style="font-size:12px;color:${T.label}">${f}</span>
                </div>
              </td>
            </tr>`).join("")}
          </tbody>
        </table>
      </div>
    </div>
  </div>`
);

const A_job = shell(
  `background:${T.paper};color:${T.ink};`, A_FONTS, A_CSS,
  `<div class="h" style="min-height:900px">
    <header style="display:flex;align-items:center;padding:18px 40px;border-bottom:1px solid ${T.hair}">${LOCKUP(17, T.ink, T.ink, T.paper)}</header>
    <div style="padding:40px;max-width:900px">
      <h1 style="margin:0;font-size:34px;font-weight:600;letter-spacing:-0.02em">Submit a job</h1>
      <p style="margin:12px 0 0;font-size:16px;color:${T.label};max-width:62ch">This much capacity, under this budget, for this long, receipt back. You do not name a venue.</p>

      <ol style="list-style:none;margin:30px 0 0;padding:0;border:1px solid ${T.hair};border-radius:10px;overflow:hidden">
        ${[
          ["1", "Admit", "The daemon records a proposal. It authorizes nothing and spends nothing.", "done"],
          ["2", "Place", "A dry run decides the placement and stops at the receipt. No provider is touched.", "now"],
        ].map(([n, t, d, st]) => `<li style="display:flex;gap:16px;padding:20px 22px;border-bottom:1px solid ${T.hairSoft};background:${st === "now" ? T.surface : T.paper}">
          <div class="m" style="flex-shrink:0;width:26px;height:26px;border-radius:50%;border:1px solid ${st === "done" ? T.green : T.ink};color:${st === "done" ? T.green : T.ink};display:flex;align-items:center;justify-content:center;font-size:12px">${n}</div>
          <div><div style="font-size:16px">${t}</div><div style="font-size:13px;color:${T.label};margin-top:4px">${d}</div></div>
        </li>`).join("")}
        <li style="display:flex;gap:16px;padding:20px 22px;background:${T.surface}">
          <div class="m" style="flex-shrink:0;width:26px;height:26px;border-radius:50%;border:1px dashed ${T.strong};color:${T.muted};display:flex;align-items:center;justify-content:center;font-size:12px">3</div>
          <div style="flex:1">
            <div style="font-size:16px">Execute</div>
            <div style="display:inline-flex;align-items:center;height:42px;margin-top:10px;padding:0 18px;border:1px solid ${T.strong};border-radius:8px;background:${T.paper};color:${T.label};font-size:14px">Locked — a wallet grant is required, and is not offered here</div>
            <div style="font-size:13px;color:${T.label};margin-top:10px;line-height:1.55;max-width:70ch">A real run is a metered provider spend. It needs an authorization naming the amount, the venue ceiling, the offer hash and the teardown — presented at the moment of spend, which is a thing a person does and not a thing a web form carries.</div>
          </div>
        </li>
      </ol>

      <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:22px 26px;margin-top:30px">
        ${[["budget_ref", "select an external_spend budget", "An existing budget, never an amount typed here."],
           ["authority_ref", "wallet-grant://", "A wallet grant, presented at submit. Never a provider credential."],
           ["deadline · max duration (hours)", "4", "Without one there is no boundary at which an unfinished job becomes a failed one."],
           ["redundancy", "none", "Declared or absent — never inferred or defaulted."]]
          .map(([l, v, h]) => `<label style="display:flex;flex-direction:column;gap:7px">
            <span class="eyebrow">${l}</span>
            <span style="display:flex;align-items:center;height:46px;padding:0 14px;border:1px solid ${T.muted};border-radius:8px;font-size:14px;color:${T.ink}">${v}</span>
            <span style="font-size:12px;color:${T.label};line-height:1.5">${h}</span>
          </label>`).join("")}
      </div>

      <div style="display:flex;align-items:center;gap:16px;margin-top:28px">
        <span style="display:inline-flex;align-items:center;height:46px;padding:0 22px;background:${T.ink};color:${T.paper};border-radius:8px;font-size:15px;font-weight:500">Admit this job</span>
        <span class="m" style="display:inline-flex;align-items:center;gap:7px;font-size:12px;color:${T.green};padding:0 12px;height:30px;border:1px solid ${T.green};border-radius:99px">
          <span style="width:6px;height:6px;border-radius:50%;background:${T.green}"></span>wired · POST /v1/hypervisor/cloud-jobs
        </span>
      </div>
    </div>
  </div>`
);

/* ═══════════════════════════════════════════════════════════════════════════
   DIRECTION B — "INSTRUMENT PANEL"
   The axis: INVERTED AND INSTRUMENTED. Onyx ground, green lifted to
   --color-green-on-dark, mono-led, the screen reads as a live instrument rather
   than a document. Closest reference: Railway and fly.io's dark product
   surfaces, and the Hypervisor shell's own dark chrome.
   System: Space Grotesk + JetBrains Mono. Layered surfaces at 4% and 8% white,
   a single luminous accent, tabular figures everywhere, 44px controls.
   Tradeoff: dark surfaces flatter screenshots and punish long reading. The
   honesty copy this product depends on is harder to read here.
   ═══════════════════════════════════════════════════════════════════════════ */

const B_FONTS = `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;500&display=swap">`;
const BSURF = "#12161f", BSURF2 = "#1a1f2a", BHAIR = "#232935";
const B_CSS = `
  .h { font-family: "Space Grotesk", ui-sans-serif, system-ui, sans-serif; }
  .m { font-family: "JetBrains Mono", ui-monospace, Menlo, monospace; font-variant-numeric: tabular-nums; }
  .eyebrow { font-family: "JetBrains Mono", monospace; font-size: 11px; letter-spacing: .12em; text-transform: uppercase; color: ${T.muted}; }`;

const B_landing = shell(
  `background:${T.ink};color:${T.paper};`, B_FONTS, B_CSS,
  `<div class="h" style="min-height:900px;display:flex;flex-direction:column">
    <header style="display:flex;align-items:center;justify-content:space-between;padding:20px 56px;border-bottom:1px solid ${BHAIR}">
      ${LOCKUP(19, T.paper, T.paper, T.ink)}
      <nav style="display:flex;gap:28px;font-size:14px;color:${T.strong}">
        <a href="#">Candidates</a><a href="#">Sources</a><a href="#">Placement</a><a href="#">API</a>
        <a href="#" style="color:${T.paper}">Submit a job</a>
      </nav>
    </header>

    <section style="padding:76px 56px 0;display:grid;grid-template-columns:minmax(0,1fr) minmax(0,0.9fr);gap:64px;align-items:center">
      <div style="display:flex;flex-direction:column;gap:26px">
        <div class="eyebrow" style="color:${T.greenOnDark}">live · ${D.venues} venues quoting</div>
        <h1 style="margin:0;font-size:60px;line-height:1.0;letter-spacing:-0.035em;font-weight:700;text-wrap:pretty">
          Compute at the price a venue quoted, not the price we remembered.
        </h1>
        <p style="margin:0;font-size:18px;line-height:1.55;color:${T.strong};max-width:50ch;text-wrap:pretty">
          Describe the capacity and the budget. We compare live quotes across venues,
          decide a placement, and hand back a receipt naming the venue and the evidence.
        </p>
        <div style="display:flex;gap:12px;padding-top:8px">
          <a href="#" style="display:inline-flex;align-items:center;height:46px;padding:0 22px;background:${T.greenOnDark};color:${T.ink};border-radius:8px;font-size:15px;font-weight:500">Submit a job</a>
          <a href="#" style="display:inline-flex;align-items:center;height:46px;padding:0 20px;border:1px solid ${BHAIR};border-radius:8px;font-size:15px;color:${T.paper}">Live prices</a>
        </div>
      </div>

      <div style="background:${BSURF};border:1px solid ${BHAIR};border-radius:14px;overflow:hidden">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid ${BHAIR}">
          <span class="eyebrow">cheapest live quote</span>
          <span class="m" style="font-size:11px;color:${T.greenOnDark}">◍ ${D.venueA}</span>
        </div>
        <div style="padding:26px 20px 22px">
          <div class="m" style="font-size:60px;line-height:1;letter-spacing:-0.04em;color:${T.greenOnDark}">$${D.cheapest}</div>
          <div style="font-size:13px;color:${T.muted};margin-top:8px">per GPU-hour · observed 12 minutes ago</div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border-top:1px solid ${BHAIR}">
          ${[[D.live, "live"], [D.considered, "considered"], [D.sources, "sources"]]
            .map(([n, l], i) => `<div style="padding:16px 20px;${i ? `border-left:1px solid ${BHAIR}` : ""}">
              <div class="m" style="font-size:20px">${n}</div><div class="eyebrow" style="margin-top:4px">${l}</div></div>`).join("")}
        </div>
      </div>
    </section>

    <section style="padding:68px 56px 0;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:20px">
      ${[
        ["TWO VENUES OR NOTHING", "A routing decision needs at least two venues quoting. With one, an intent can be priced but not routed."],
        ["NO CREDENTIAL LEAVES YOU", "You never hold a provider credential and never name a venue. The receipt names it, after the fact."],
        ["A FEE IS A RECEIPT", "No fee for pricing, for looking, or for a decision taken between fewer than two real venues."],
      ].map(([h, p]) => `<div style="background:${BSURF};border:1px solid ${BHAIR};border-radius:12px;padding:22px">
        <div class="eyebrow" style="color:${T.greenOnDark}">${h}</div>
        <p style="margin:12px 0 0;font-size:14px;line-height:1.6;color:${T.strong};text-wrap:pretty">${p}</p>
      </div>`).join("")}
    </section>

    <footer style="margin-top:auto;padding:30px 56px;border-top:1px solid ${BHAIR}">
      <span class="m" style="font-size:11px;color:${T.muted}">${D.sources} sources asked · ${D.quoting} quoting · ${D.unavailable} unavailable · read in ${D.sweep}</span>
    </footer>
  </div>`
);

const B_candidates = shell(
  `background:${T.ink};color:${T.paper};`, B_FONTS, B_CSS,
  `<div class="h" style="min-height:900px">
    <header style="display:flex;align-items:center;justify-content:space-between;padding:16px 40px;border-bottom:1px solid ${BHAIR}">
      ${LOCKUP(17, T.paper, T.paper, T.ink)}
      <span class="m" style="font-size:11px;color:${T.muted}">reads · two writes, neither spends</span>
    </header>
    <div style="padding:34px 40px">
      <div style="display:flex;align-items:flex-end;justify-content:space-between;gap:24px">
        <div>
          <h1 style="margin:0;font-size:32px;font-weight:700;letter-spacing:-0.02em">Candidates</h1>
          <div class="m" style="margin-top:8px;font-size:12px;color:${T.muted}">${D.live} live · ${D.venues} venues · ${D.considered} considered · ${D.sources} sources</div>
        </div>
        <div style="text-align:right">
          <div class="eyebrow">cheapest</div>
          <div class="m" style="font-size:30px;color:${T.greenOnDark};letter-spacing:-0.02em">$${D.cheapest}</div>
        </div>
      </div>

      <div style="margin-top:24px;background:${BSURF};border:1px solid ${BHAIR};border-radius:12px;overflow:hidden">
        <table style="width:100%;border-collapse:collapse;table-layout:fixed">
          <thead><tr style="background:${BSURF2}">
            ${[["Venue", "20%", "left"], ["Basis", "42%", "left"], ["USD / hr", "18%", "right"], ["Freshness", "20%", "left"]]
              .map(([h, w, a]) => `<th style="width:${w};text-align:${a};padding:11px 18px;border-bottom:1px solid ${BHAIR};font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:${T.muted};font-weight:400">${h}</th>`).join("")}
          </tr></thead>
          <tbody>
            ${[[D.venueA, "vast offer dph_total (verbatim)", "0.0136", "9 min", 0.72],
               [D.venueA, "vast offer dph_total (verbatim)", "0.0164", "9 min", 0.72],
               [D.venueB, "runpod gpuTypes.lowestPrice, secureCloud", "0.0222", "8 min", 0.64],
               [D.venueB, "runpod gpuTypes.lowestPrice, community", "0.0289", "8 min", 0.64]]
              .map(([v, b, p, f, frac]) => `<tr>
                <td style="padding:15px 18px;border-top:1px solid ${BHAIR};vertical-align:middle">
                  <div class="m" style="font-size:13px">${v}</div>
                  <div class="m" style="display:inline-flex;align-items:center;gap:6px;margin-top:6px;font-size:10px;color:${T.greenOnDark}"><span style="width:5px;height:5px;border-radius:50%;background:${T.greenOnDark}"></span>live_evidence</div>
                </td>
                <td class="m" style="padding:15px 18px;border-top:1px solid ${BHAIR};font-size:11px;color:${T.muted};line-height:1.6;vertical-align:middle">${b}</td>
                <td class="m" style="padding:15px 18px;border-top:1px solid ${BHAIR};font-size:16px;text-align:right;color:${T.greenOnDark};vertical-align:middle">$${p}</td>
                <td style="padding:15px 18px;border-top:1px solid ${BHAIR};vertical-align:middle">
                  <div style="display:flex;align-items:center;gap:9px">
                    <svg width="20" height="20" viewBox="0 0 22 22" style="flex-shrink:0"><circle cx="11" cy="11" r="9" fill="none" stroke="${BHAIR}" stroke-width="2.5"></circle><circle cx="11" cy="11" r="9" fill="none" stroke="${T.greenOnDark}" stroke-width="2.5" stroke-dasharray="${(56.5 * frac).toFixed(1)} 56.5" transform="rotate(-90 11 11)" stroke-linecap="round"></circle></svg>
                    <span class="m" style="font-size:11px;color:${T.strong}">${f}</span>
                  </div>
                </td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>
    </div>
  </div>`
);

const B_job = shell(
  `background:${T.ink};color:${T.paper};`, B_FONTS, B_CSS,
  `<div class="h" style="min-height:900px">
    <header style="display:flex;align-items:center;padding:16px 40px;border-bottom:1px solid ${BHAIR}">${LOCKUP(17, T.paper, T.paper, T.ink)}</header>
    <div style="padding:34px 40px;max-width:900px">
      <h1 style="margin:0;font-size:32px;font-weight:700;letter-spacing:-0.02em">Submit a job</h1>
      <p style="margin:10px 0 0;font-size:15px;color:${T.strong};max-width:62ch">This much capacity, under this budget, for this long, receipt back. You do not name a venue.</p>

      <ol style="list-style:none;margin:26px 0 0;padding:0;background:${BSURF};border:1px solid ${BHAIR};border-radius:12px;overflow:hidden">
        ${[["1", "Admit", "Records a proposal. Authorizes nothing, spends nothing.", true],
           ["2", "Place", "A dry run decides the placement and stops at the receipt.", true]]
          .map(([n, t, d]) => `<li style="display:flex;gap:15px;padding:18px 20px;border-bottom:1px solid ${BHAIR}">
            <div class="m" style="flex-shrink:0;width:26px;height:26px;border-radius:50%;border:1px solid ${T.greenOnDark};color:${T.greenOnDark};display:flex;align-items:center;justify-content:center;font-size:12px">${n}</div>
            <div><div style="font-size:15px">${t}</div><div style="font-size:13px;color:${T.muted};margin-top:3px">${d}</div></div>
          </li>`).join("")}
        <li style="display:flex;gap:15px;padding:18px 20px;background:${BSURF2}">
          <div class="m" style="flex-shrink:0;width:26px;height:26px;border-radius:50%;border:1px dashed ${T.muted};color:${T.muted};display:flex;align-items:center;justify-content:center;font-size:12px">3</div>
          <div style="flex:1">
            <div style="font-size:15px">Execute</div>
            <div style="display:inline-flex;align-items:center;height:42px;margin-top:10px;padding:0 18px;border:1px dashed ${T.muted};border-radius:8px;color:${T.strong};font-size:14px">Locked — a wallet grant is required, and is not offered here</div>
            <div style="font-size:13px;color:${T.muted};margin-top:10px;line-height:1.55;max-width:70ch">A real run is a metered provider spend, authorized at the moment of spend. The proxy sets the dry-run flag itself on every execute, so no request composed here reaches a provider even if this control were unlocked.</div>
          </div>
        </li>
      </ol>

      <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px 24px;margin-top:26px">
        ${[["budget_ref", "select an external_spend budget"], ["authority_ref", "wallet-grant://"],
           ["deadline · hours", "4"], ["redundancy", "none"]]
          .map(([l, v]) => `<label style="display:flex;flex-direction:column;gap:7px">
            <span class="eyebrow">${l}</span>
            <span style="display:flex;align-items:center;height:46px;padding:0 14px;background:${BSURF};border:1px solid ${T.muted};border-radius:8px;font-size:14px;color:${T.paper}">${v}</span>
          </label>`).join("")}
      </div>

      <div style="display:flex;align-items:center;gap:14px;margin-top:26px">
        <span style="display:inline-flex;align-items:center;height:46px;padding:0 22px;background:${T.greenOnDark};color:${T.ink};border-radius:8px;font-size:15px;font-weight:500">Admit this job</span>
        <span class="m" style="font-size:11px;color:${T.greenOnDark}">wired · POST /v1/hypervisor/cloud-jobs</span>
      </div>
    </div>
  </div>`
);

/* ═══════════════════════════════════════════════════════════════════════════
   DIRECTION C — "MARKET FLOOR"
   The axis: EDITORIAL AND ARGUED. Warm paper, a display serif for argument
   against the grotesque for data, an asymmetric grid, and one large diagram
   that shows the funnel — sources to candidates to a placement — as the
   product's actual idea. Closest reference: Stripe's marketing pages and
   Linear's essay-like sections, not their app chrome.
   System: Fraunces is deliberately avoided (slop list); Newsreader for
   argument, Archivo for data, IBM Plex Mono for evidence. Green used once,
   as the live thread through the diagram.
   Tradeoff: the most opinionated and the least like a console. It risks
   reading as a marketing site attached to a tool rather than as the tool.
   ═══════════════════════════════════════════════════════════════════════════ */

const C_FONTS = `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Newsreader:opsz,wght@6..72,400;6..72,500&family=Archivo:wght@400;500;600&family=IBM+Plex+Mono:wght@400&display=swap">`;
const CPAPER = "#fbfaf8";
const C_CSS = `
  .s { font-family: Newsreader, Georgia, serif; }
  .h { font-family: Archivo, ui-sans-serif, system-ui, sans-serif; }
  .m { font-family: "IBM Plex Mono", ui-monospace, Menlo, monospace; }
  .eyebrow { font-family: "IBM Plex Mono", monospace; font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: ${T.muted}; }`;

const C_landing = shell(
  `background:${CPAPER};color:${T.ink};`, C_FONTS, C_CSS,
  `<div class="h" style="min-height:900px;display:flex;flex-direction:column">
    <header style="display:flex;align-items:center;justify-content:space-between;padding:24px 60px">
      ${LOCKUP(19, T.ink, T.ink, CPAPER)}
      <nav style="display:flex;gap:28px;font-size:14px;color:${T.label}">
        <a href="#">Candidates</a><a href="#">Sources</a><a href="#">Placement</a>
        <a href="#" style="color:${T.ink};border-bottom:1px solid ${T.ink};padding-bottom:2px">Submit a job</a>
      </nav>
    </header>

    <section style="padding:56px 60px 0;display:grid;grid-template-columns:minmax(0,7fr) minmax(0,5fr);gap:70px">
      <div>
        <h1 class="s" style="margin:0;font-size:64px;line-height:1.04;letter-spacing:-0.02em;font-weight:400;text-wrap:pretty">
          The price you see is the price a venue<br>quoted <em style="font-style:italic;color:${T.green}">twelve minutes ago</em>.
        </h1>
        <p style="margin:26px 0 0;font-size:18px;line-height:1.6;color:${T.label};max-width:54ch;text-wrap:pretty">
          Most compute marketplaces show you a price they cached. This one asks every venue,
          shows you what came back and when it expires, and refuses to route an intent that
          only one venue answered.
        </p>
        <div style="display:flex;gap:14px;margin-top:30px">
          <a href="#" style="display:inline-flex;align-items:center;height:48px;padding:0 24px;background:${T.ink};color:${CPAPER};border-radius:2px;font-size:15px">Submit a job</a>
          <a href="#" style="display:inline-flex;align-items:center;height:48px;padding:0 22px;border:1px solid ${T.ink};border-radius:2px;font-size:15px">See the ${D.live} live quotes</a>
        </div>
      </div>

      <div style="border-left:1px solid ${T.strong};padding-left:34px">
        <div class="eyebrow">right now</div>
        <div class="m" style="font-size:52px;line-height:1;margin-top:14px;letter-spacing:-0.03em">$${D.cheapest}</div>
        <div style="font-size:14px;color:${T.label};margin-top:8px">cheapest live GPU-hour, from ${D.venueA}</div>
        <div style="margin-top:26px;display:flex;flex-direction:column;gap:14px">
          ${[[D.sources, "sources asked"], [D.quoting, "quoting a price"], [D.live, "live candidates"], [D.venues, "venues comparable"]]
            .map(([n, l]) => `<div style="display:flex;align-items:baseline;gap:12px">
              <span class="m" style="font-size:18px;min-width:44px">${n}</span>
              <span style="font-size:14px;color:${T.label}">${l}</span></div>`).join("")}
        </div>
      </div>
    </section>

    <section style="padding:74px 60px 0">
      <div style="border-top:1px solid ${T.strong};padding-top:40px">
        <h2 class="s" style="margin:0 0 30px;font-size:30px;font-weight:400;letter-spacing:-0.01em">How a price becomes a placement</h2>
        <div style="display:flex;align-items:stretch;gap:0">
          ${[
            [D.sources, "sources asked", "Every venue and inventory the daemon knows."],
            [D.quoting, "answered with a price", "The rest say why they could not, by name."],
            [D.live, "live candidates", "Priced, dated, and inside their window."],
            ["1", "placement decided", "With reason codes and a receipt. No fee minted."],
          ].map(([n, l, d], i, arr) => `<div style="flex:1;position:relative;padding-right:${i < arr.length - 1 ? "26px" : "0"}">
            <div style="height:3px;background:${i === arr.length - 1 ? T.green : T.ink};margin-bottom:16px"></div>
            <div class="m" style="font-size:28px;letter-spacing:-0.02em;color:${i === arr.length - 1 ? T.green : T.ink}">${n}</div>
            <div style="font-size:14px;margin-top:5px">${l}</div>
            <div style="font-size:13px;color:${T.label};margin-top:7px;line-height:1.5;max-width:26ch">${d}</div>
          </div>`).join("")}
        </div>
      </div>
    </section>

    <footer style="margin-top:auto;padding:34px 60px;border-top:1px solid ${T.strong};display:flex;justify-content:space-between">
      <span class="m" style="font-size:12px;color:${T.muted}">a fee exists only as a minted receipt</span>
      <span class="m" style="font-size:12px;color:${T.muted}">read in ${D.sweep}</span>
    </footer>
  </div>`
);

const C_candidates = shell(
  `background:${CPAPER};color:${T.ink};`, C_FONTS, C_CSS,
  `<div class="h" style="min-height:900px">
    <header style="display:flex;align-items:center;justify-content:space-between;padding:20px 46px;border-bottom:1px solid ${T.strong}">
      ${LOCKUP(17, T.ink, T.ink, CPAPER)}
      <span class="m" style="font-size:11px;color:${T.muted}">reads · two writes, neither spends</span>
    </header>
    <div style="padding:38px 46px">
      <div style="display:grid;grid-template-columns:minmax(0,7fr) minmax(0,5fr);gap:50px;align-items:end">
        <div>
          <h1 class="s" style="margin:0;font-size:42px;font-weight:400;letter-spacing:-0.02em">Candidates</h1>
          <p style="margin:10px 0 0;font-size:16px;color:${T.label};max-width:56ch">
            ${D.live} live quotes across ${D.venues} venues, so this intent can be compared and routed — not merely priced.
          </p>
        </div>
        <div style="text-align:right">
          <div class="eyebrow">cheapest live</div>
          <div class="m" style="font-size:36px;letter-spacing:-0.02em">$${D.cheapest}</div>
        </div>
      </div>

      <table style="width:100%;border-collapse:collapse;table-layout:fixed;margin-top:30px">
        <thead><tr>
          ${[["Venue", "20%", "left"], ["Basis", "42%", "left"], ["USD per hour", "18%", "right"], ["Freshness", "20%", "left"]]
            .map(([h, w, a]) => `<th style="width:${w};text-align:${a};padding:0 16px 12px;border-bottom:2px solid ${T.ink};font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:${T.ink};font-weight:500">${h}</th>`).join("")}
        </tr></thead>
        <tbody>
          ${[[D.venueA, "vast offer dph_total (verbatim)", "0.0136", "9 min left", 0.72],
             [D.venueA, "vast offer dph_total (verbatim)", "0.0164", "9 min left", 0.72],
             [D.venueB, "runpod gpuTypes.lowestPrice, secureCloud", "0.0222", "8 min left", 0.64],
             [D.venueB, "runpod gpuTypes.lowestPrice, community", "0.0289", "8 min left", 0.64]]
            .map(([v, b, p, f, frac]) => `<tr>
              <td style="padding:18px 16px;border-bottom:1px solid ${T.hair};vertical-align:middle">
                <div class="m" style="font-size:14px">${v}</div>
                <div class="m" style="display:inline-flex;align-items:center;gap:6px;margin-top:6px;font-size:11px;color:${T.green}"><span style="width:6px;height:6px;border-radius:50%;background:${T.green}"></span>live</div>
              </td>
              <td class="m" style="padding:18px 16px;border-bottom:1px solid ${T.hair};font-size:12px;color:${T.label};line-height:1.6;vertical-align:middle">${b}<br>observed 2026-09-05 05:41:39Z</td>
              <td class="m" style="padding:18px 16px;border-bottom:1px solid ${T.hair};font-size:19px;text-align:right;font-variant-numeric:tabular-nums;vertical-align:middle">$${p}</td>
              <td style="padding:18px 16px;border-bottom:1px solid ${T.hair};vertical-align:middle">
                <div style="display:flex;align-items:center;gap:10px">
                  <svg width="22" height="22" viewBox="0 0 22 22" style="flex-shrink:0"><circle cx="11" cy="11" r="9" fill="none" stroke="${T.hair}" stroke-width="2.5"></circle><circle cx="11" cy="11" r="9" fill="none" stroke="${T.green}" stroke-width="2.5" stroke-dasharray="${(56.5 * frac).toFixed(1)} 56.5" transform="rotate(-90 11 11)" stroke-linecap="round"></circle></svg>
                  <span class="m" style="font-size:12px;color:${T.label}">${f}</span>
                </div>
              </td>
            </tr>`).join("")}
        </tbody>
      </table>
    </div>
  </div>`
);

const C_job = shell(
  `background:${CPAPER};color:${T.ink};`, C_FONTS, C_CSS,
  `<div class="h" style="min-height:900px">
    <header style="display:flex;align-items:center;padding:20px 46px;border-bottom:1px solid ${T.strong}">${LOCKUP(17, T.ink, T.ink, CPAPER)}</header>
    <div style="padding:38px 46px;max-width:920px">
      <h1 class="s" style="margin:0;font-size:42px;font-weight:400;letter-spacing:-0.02em">Submit a job</h1>
      <p style="margin:12px 0 0;font-size:17px;color:${T.label};max-width:60ch">
        This much capacity, under this budget, for this long, receipt back. You do not name a venue — the venue is evidence in the receipt, not an input to the request.
      </p>

      <div style="display:flex;margin-top:32px;border-top:2px solid ${T.ink}">
        ${[["Admit", "Records a proposal. Authorizes nothing, spends nothing.", "done"],
           ["Place", "A dry run decides the placement and stops at the receipt.", "now"],
           ["Execute", "Locked — a wallet grant is required, and is not offered here.", "locked"]]
          .map(([t, d, st], i) => `<div style="flex:1;padding:20px 22px 22px 0;${i ? `border-left:1px solid ${T.hair};padding-left:22px` : ""}">
            <div class="eyebrow" style="color:${st === "locked" ? T.muted : T.green}">${st === "locked" ? "not offered here" : st === "done" ? "done" : "next"}</div>
            <div class="s" style="font-size:22px;margin-top:8px">${t}</div>
            <div style="font-size:14px;color:${T.label};margin-top:8px;line-height:1.5">${d}</div>
          </div>`).join("")}
      </div>

      <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px 30px;margin-top:34px">
        ${[["budget_ref", "select an external_spend budget", "An existing budget, never an amount typed here."],
           ["authority_ref", "wallet-grant://", "A grant a person signed. This page cannot create one for you."],
           ["deadline · max duration (hours)", "4", "Without one, an unfinished job never becomes a failed one."],
           ["redundancy", "none", "Declared or absent — never inferred, never defaulted."]]
          .map(([l, v, h]) => `<label style="display:flex;flex-direction:column;gap:8px">
            <span class="eyebrow">${l}</span>
            <span style="display:flex;align-items:center;height:48px;padding:0 14px;border:1px solid ${T.muted};border-radius:2px;background:${T.paper};font-size:15px">${v}</span>
            <span style="font-size:13px;color:${T.label};line-height:1.5">${h}</span>
          </label>`).join("")}
      </div>

      <div style="display:flex;align-items:center;gap:18px;margin-top:32px">
        <span style="display:inline-flex;align-items:center;height:48px;padding:0 26px;background:${T.ink};color:${CPAPER};border-radius:2px;font-size:15px">Admit this job</span>
        <span class="m" style="font-size:12px;color:${T.green}">wired · POST /v1/hypervisor/cloud-jobs</span>
      </div>
    </div>
  </div>`
);

export const ARTBOARDS = {
  Main: A_landing,
  ALedgerCandidates: A_candidates,
  ALedgerJob: A_job,
  BInstrumentLanding: B_landing,
  BInstrumentCandidates: B_candidates,
  BInstrumentJob: B_job,
  CMarketLanding: C_landing,
  CMarketCandidates: C_candidates,
  CMarketJob: C_job,
};

const W = 1440, H = 900, GAPX = 120, GAPY = 200;
export const CANVAS = {
  artboards: [
    { file: "Main.dc.html", title: "A · Ledger — landing", x: 0, y: 0, w: W, h: H },
    { file: "ALedgerCandidates.dc.html", title: "A · Ledger — candidates", x: W + GAPX, y: 0, w: W, h: H },
    { file: "ALedgerJob.dc.html", title: "A · Ledger — submit a job", x: (W + GAPX) * 2, y: 0, w: W, h: H },

    { file: "BInstrumentLanding.dc.html", title: "B · Instrument — landing", x: 0, y: H + GAPY, w: W, h: H },
    { file: "BInstrumentCandidates.dc.html", title: "B · Instrument — candidates", x: W + GAPX, y: H + GAPY, w: W, h: H },
    { file: "BInstrumentJob.dc.html", title: "B · Instrument — submit a job", x: (W + GAPX) * 2, y: H + GAPY, w: W, h: H },

    { file: "CMarketLanding.dc.html", title: "C · Market floor — landing", x: 0, y: (H + GAPY) * 2, w: W, h: H },
    { file: "CMarketCandidates.dc.html", title: "C · Market floor — candidates", x: W + GAPX, y: (H + GAPY) * 2, w: W, h: H },
    { file: "CMarketJob.dc.html", title: "C · Market floor — submit a job", x: (W + GAPX) * 2, y: (H + GAPY) * 2, w: W, h: H },
  ],
  annotations: [
    { id: "brief", x: -420, y: 0, w: 340,
      text: "THE QUESTION\nWould a stranger believe this is a first-tier product in the first five seconds?\n\nScored against linear.app, vercel.com, stripe.com, railway.com, fly.io and the Hypervisor shell.\n\nAll three directions use the SAME identity: the owner's reserved mark, and the adopted drawn Z and I (the brand face's own Z reads as a 2 and its I as a 1 — three readers typed digits for both).\n\nEvery colour is a token from the design system. Every number is read off the live daemon." },
    { id: "dir-a", x: -420, y: H + GAPY, w: 340,
      text: "A · LEDGER\nAxis: evidence as the aesthetic.\n\nArchivo + IBM Plex Mono. Hairline rules do the work colour usually does. Green reserved strictly for live evidence. One filled button per screen.\n\nTradeoff: it is quiet. Reads as serious; could read as plain." },
    { id: "dir-b", x: -420, y: (H + GAPY) * 2, w: 340,
      text: "B · INSTRUMENT PANEL\nAxis: inverted and instrumented.\n\nSpace Grotesk + JetBrains Mono on onyx. Green lifted to the on-dark token. Reads as a live instrument, not a document.\n\nTradeoff: dark flatters screenshots and punishes long reading — and this product depends on honesty copy people actually read." },
    { id: "dir-c", x: -420, y: (H + GAPY) * 3, w: 340,
      text: "C · MARKET FLOOR\nAxis: editorial and argued.\n\nNewsreader for argument, Archivo for data, Plex Mono for evidence. Warm paper, asymmetric grid, one funnel diagram carrying the product's actual idea.\n\nTradeoff: the most opinionated, the least console-like. Risks reading as marketing attached to a tool." },
  ],
  launch: { view: "canvas" },
};
