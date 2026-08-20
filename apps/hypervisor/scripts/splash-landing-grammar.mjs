// I-4 — THE SPLASH-LANDING SHARED GRAMMAR (Reference-UX Remediation Program v2, W3).
//
// The census + crawl proved that module (Workshop Home), logic-app, contour-app, slate — and the
// already-ported designer/machinery/monitors landings — are instances of ONE reference landing
// grammar: dark global rail · light app header (app chip · title · store dropdown · New <thing> ·
// Help) · hero band (title · description · optional verbatim capture illustration) · the View row
// (Recents active · Favorites gap) · the recents table over REAL estate rows · a truthful footer.
// This module implements that grammar ONCE, parameterized; each family port instantiates it with
// its truth binding instead of hand-building a bespoke shell.
//
// THE EXEMPLAR this template converges on is `changes` (adjudication IMP-1,
// reference-seed-adjudications.v1.json#changes): reference tabs became LIVE lanes, facets became
// live filters — a control is either bound to daemon truth or a typed absence under the unified
// gap contract (aria-disabled + title + data-ioi-disabled-reason), never decoration.
//
// Config contract (all strings pre-escaped by THIS module — pass raw values):
//   slug, title, appTileUri, chipTintRgba?      — identity + header chip
//   newLabel, newHref | newGapReason            — the New-<thing> entry: live link or typed absence
//   storeGapReason?, helpGapReason?             — header gaps (defaults provided)
//   heroTitle, heroDesc, heroImgUri?, heroImgAlt? — hero band (img = verbatim capture chrome ONLY)
//   favoritesGapReason?                         — the Favorites view (no favorites plane → absence)
//   columns: [string]                           — recents table header
//   rowsHtml                                    — CALLER-RENDERED rows (real estate truth; the
//                                                 caller owns escaping of its own row internals)
//   emptyCopy                                   — honest-empty copy when rowsHtml is ""
//   footHtml                                    — truthful footer (evidence citations)
//   embed                                       — native_single_rail contract: no global rail
// Returns the full HTML document string.
// chrome import removed: no fabricated rail on non-certified shells (owner ruling 2026-08-20)
import { escHtml } from "../surfaces/kit.mjs";

const esc = escHtml;
const gap = (cls, label, reason, inner = "") => `<span class="${cls} gap" aria-disabled="true" title="${esc(reason)}" data-ioi-disabled-reason="${esc(reason)}">${inner}${esc(label)}</span>`;

export function renderSplashLanding(cfg) {
  const route = `/__ioi/${cfg.slug}`;
  // OWNER RULING (2026-08-20): the fabricated reference global rail belongs ONLY on
  // pixel-certified ports (where it is evidence). Non-certified shells render RAILLESS — the
  // platform container provides the one rail (native_single_rail extended to standalone).
  const globalRail = "";
  const newEntry = cfg.newHref
    ? `<a class="spl-hbtn success" href="${esc(cfg.newHref)}" title="${esc(cfg.newTitle || `${cfg.newLabel} — a live estate lane`)}"><span class="spl-plus">+</span><span>${esc(cfg.newLabel)}</span></a>`
    : gap("spl-hbtn success", cfg.newLabel, cfg.newGapReason, `<span class="spl-plus">+</span>`);
  const header = `<header class="spl-header">
    <span class="spl-hchip" aria-hidden="true" style="background-image:url('${cfg.appTileUri}')${cfg.chipTintRgba ? `;background-color:${cfg.chipTintRgba}` : ""}"></span>
    <h1 class="spl-htitle">${esc(cfg.title)}</h1>
    <div class="spl-hright">
      ${gap("spl-hbtn outlined store", "", cfg.storeGapReason || "Recent installations — marketplace install lanes are not bound to this surface (named gap)", `<span class="spl-storeico" aria-hidden="true"></span>▾`)}
      ${newEntry}
      ${gap("spl-hbtn outlined", "Help", cfg.helpGapReason || "Reference help lane (named gap)")}
    </div>
  </header>`;
  const hero = `<section class="spl-hero"><div class="spl-heroct">
      <h3 class="spl-h1">${esc(cfg.heroTitle)}</h3>
      <p class="spl-desc">${esc(cfg.heroDesc)}</p>
    </div>${cfg.heroImgUri ? `<img class="spl-heroimg" src="${cfg.heroImgUri}" alt="${esc(cfg.heroImgAlt || "Reference illustration (verbatim capture chrome)")}">` : ""}</section>`;
  const viewRow = `<div class="spl-viewrow">
    <span class="spl-view on" aria-current="page">Recents</span>
    ${gap("spl-view", "Favorites", cfg.favoritesGapReason || "No favorites plane exists on the estate (typed absence)")}
  </div>`;
  const table = `<div class="spl-table">
    <div class="spl-thead">${cfg.columns.map((c) => `<span class="spl-th">${esc(c)}</span>`).join("")}</div>
    <div class="spl-rows">${cfg.rowsHtml || `<div class="spl-empty">${esc(cfg.emptyCopy)}</div>`}</div>
  </div>`;
  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .spl-shell{display:flex;height:100vh;width:100vw;overflow:hidden}

    .spl-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .spl-header{flex:0 0 50px;display:flex;align-items:center;background:#fff;box-shadow:0 1px 0 #d1d1d1,0 3px 4px rgba(0,0,0,.04);z-index:6}
    .spl-hchip{width:50px;height:50px;flex:0 0 50px;background-position:center;background-size:24px;background-repeat:no-repeat;background-color:rgba(45,114,210,.08)}
    .spl-htitle{font-size:16px;font-weight:600;color:#404854;margin:0 0 0 12px;flex:1 1 auto}
    .spl-hright{display:flex;align-items:center;gap:8px;padding-right:16px}
    .spl-hbtn{display:inline-flex;align-items:center;gap:6px;height:30px;padding:0 10px;border-radius:4px;font-size:14px}
    .spl-hbtn.success{background:#238551;color:#fff}
    .spl-hbtn.outlined{border:1px solid rgba(95,107,124,.25);color:#1c2127}
    .spl-hbtn.gap{opacity:.62;cursor:not-allowed}
    a.spl-hbtn{cursor:pointer}
    .spl-body{flex:1;overflow-y:auto}
    .spl-hero{display:flex;align-items:center;justify-content:space-between;padding:26px 32px 8px}
    .spl-h1{font-size:24px;font-weight:600;margin:0}
    .spl-desc{font-size:14px;color:#5f6b7c;margin:8px 0 0;max-width:560px}
    .spl-heroimg{max-height:120px}
    .spl-viewrow{display:flex;gap:18px;padding:18px 32px 0;border-bottom:1px solid #e5e8eb;margin:0 0 0}
    .spl-view{font-size:14px;padding-bottom:8px;color:#5f6b7c;position:relative}
    .spl-view.on{color:#215db0;font-weight:600}
    .spl-view.on::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:3px;background:#215db0}
    .spl-view.gap{cursor:not-allowed;opacity:.62}
    .spl-table{padding:10px 32px 40px}
    .spl-thead{display:grid;grid-template-columns:repeat(${cfg.columns.length},1fr);gap:8px;font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:#5f6b7c;padding:8px 10px 6px;border-bottom:1px solid #e5e8eb}
    .spl-rows a,.spl-rows .spl-row{display:grid;grid-template-columns:repeat(${cfg.columns.length},1fr);gap:8px;align-items:center;padding:9px 10px;border-bottom:1px solid #f0f2f5;color:#1c2127;font-size:14px}
    .spl-empty{padding:22px 10px;color:#5f6b7c;font-size:14px}
    .spl-foot{font-size:12px;line-height:1.6;color:#7b8494;margin:20px 32px 40px}`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(cfg.title)}</title><style>${css}</style></head>
    <body${cfg.surfaceRoute ? ` data-ioi-surface-route="${cfg.surfaceRoute}" data-ioi-surface-owner="${cfg.surfaceOwner || ""}"` : ""}><div class="spl-shell">${globalRail}<div class="spl-main">${header}<div class="spl-body">${hero}${viewRow}${table}<p class="spl-foot">${cfg.footHtml || ""}</p></div></div></div></body></html>`;
}
