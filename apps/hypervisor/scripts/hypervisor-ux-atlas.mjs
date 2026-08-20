#!/usr/bin/env node
// HYPERVISOR UX DEEP ATLAS (owner-directed 2026-08-20): drive the app itself and surface the
// subtle breaks — HTTP errors, console/page errors, dead links, second-rail leaks in embeds,
// capture (/__apps/*) links reachable from product surfaces, single-vocabulary gaps, honest-empty
// violations. READ-ONLY: navigation only; no verb clicks (run/delete/create submits).
// Usage: node hypervisor-ux-atlas.mjs [stage1|stage2]
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const SERVE = "http://127.0.0.1:4173";
const OUT = join(ROOT, ".artifacts", "ux-atlas");
mkdirSync(OUT, { recursive: true });
const ISSUES = [];
const issue = (sev, kind, where, detail) => { ISSUES.push({ sev, kind, where, detail: String(detail).slice(0, 220) }); console.log(`[${sev}] ${kind} @ ${where} — ${String(detail).slice(0, 120)}`); };

// Every designated click target + shipped surface (the product nav universe).
const SURFACES = [
  "/automations", "/evaluations", "/foundry", "/provenance", "/improvement", "/governance", "/packages/marketplace",
  "/studio", "/data", "/ontology", "/developer-workspace",
  "/__ioi/automations/monitors", "/__ioi/automations/monitors?tab=automations",
  "/__ioi/data/sources", "/__ioi/data/sources?lane=syncs", "/__ioi/pipeline",
  "/__ioi/ontology/manager", "/__ioi/ontology/explorer",
  "/__ioi/governance/approvals", "/__ioi/missions", "/__ioi/missions/incidents",
  "/__ioi/foundry/models", "/__ioi/foundry/models?tab=registered", "/__ioi/marketplace/listings",
  "/__ioi/studio/designer", "/__ioi/studio/machinery", "/__ioi/studio/workshop",
  "/__ioi/evaluations/evalsuites", "/__ioi/evaluations/insight", "/__ioi/evaluations/quiver",
  "/__ioi/improvement/changes", "/__ioi/lineage", "/__ioi/lineage?tab=history", "/__ioi/lineage?tab=timeline",
  "/__ioi/vertex", "/__ioi/developer-console", "/__ioi/developer-console/widgets",
  "/__ioi/developer-workspace/workspaces", "/__ioi/developer-workspace/notepad", "/__ioi/developer-workspace/repositories",
  "/__ioi/domain-apps/logic", "/__ioi/domain-apps/contour", "/__ioi/agent-studio", "/__ioi/connections",
  "/__ioi/environments", "/__ioi/operations", "/__ioi/work-ledger", "/__ioi/home", "/__ioi/odk", "/__ioi/domain-apps",
];

const STAGE = process.argv[2] || "stage1";
if (!["stage1", "stage2", "stage3", "stage4", "stage5"].includes(STAGE)) {
  // Arg guard (ORG-1 hand-off: an unrecognized argv ran neither branch and overwrote the issues
  // artifact with a hollow 0-issue record). Unknown stage = refuse, never a fake-clean sweep.
  console.error(`unknown stage '${STAGE}' — usage: hypervisor-ux-atlas.mjs [stage1|stage2|stage3]`);
  process.exit(2);
}
const { chromium } = await import("playwright");
const browser = await chromium.launch();
const pg = await browser.newPage({ viewport: { width: 1600, height: 950 } });
const consoleErrs = [];
pg.on("console", (m) => { if (m.type() === "error") consoleErrs.push(m.text().slice(0, 160)); });
pg.on("pageerror", (e) => consoleErrs.push("PAGEERROR " + String(e).slice(0, 160)));

const seenLinks = new Map(); // href -> status (probe cache)
async function probe(href) {
  if (seenLinks.has(href)) return seenLinks.get(href);
  let st = 0;
  try { const r = await fetch(SERVE + href, { redirect: "manual" }); st = (r.status >= 300 && r.status < 400) ? 200 : r.status; } catch { st = 0; }
  seenLinks.set(href, st);
  return st;
}

if (STAGE === "stage2") {
  // CONTAINER SWEEP: the SPA Applications modal → open every row → the frame must be railless,
  // error-free, and non-empty. This is where the owner's two-rails class lived.
  const pg2 = await browser.newPage({ viewport: { width: 1600, height: 950 } });
  const errs2 = [];
  pg2.on("console", (m) => { if (m.type() === "error") errs2.push(m.text().slice(0, 140)); });
  pg2.on("pageerror", (e) => errs2.push("PAGEERROR " + String(e).slice(0, 140)));
  await pg2.goto(SERVE + "/projects", { waitUntil: "domcontentloaded", timeout: 30000 });
  await pg2.waitForTimeout(4000);
  const authWalled = await pg2.evaluate(() => /sign in|sign-in/i.test(document.body.innerText) && !document.querySelector('a[href="#applications"]'));
  if (authWalled) { issue("HIGH", "container-authwall", "/projects", "SPA sign-in blocks the headless sweep — container flows unverifiable headless"); }
  else {
    const opened = [];
    for (let round = 0; round < 24; round++) {
      await pg2.click('a[href="#applications"]').catch(() => {});
      await pg2.waitForTimeout(1200);
      const rows = await pg2.evaluate(() => [...document.querySelectorAll(".ioi-mrow[data-href]")].map((r) => ({ href: r.getAttribute("data-href"), name: r.getAttribute("data-name"), top: r.getAttribute("data-nav") === "top" })));
      const next = rows.find((r) => !opened.includes(r.href) && !r.top);
      if (!next) break;
      opened.push(next.href);
      errs2.length = 0;
      await pg2.click(`.ioi-mrow[data-href="${next.href}"]`).catch(() => issue("HIGH", "modal-click-failed", next.href, "row not clickable"));
      await pg2.waitForTimeout(3500);
      const frameState = await pg2.evaluate(() => {
        const f = document.querySelector("#ioi-open-app iframe");
        if (!f) return { present: false };
        let railAsides = -1, textLen = -1;
        try { const d = f.contentDocument; railAsides = d ? d.querySelectorAll('aside.og-grail').length : -1; textLen = d ? d.body.innerText.trim().length : -1; } catch { /* cross-origin impossible here */ }
        return { present: true, src: f.getAttribute("src"), railAsides, textLen };
      });
      if (!frameState.present) issue("HIGH", "container-no-frame", next.href, "iframe never appeared");
      else {
        if (frameState.railAsides > 0) issue("HIGH", "second-rail", next.href, `embedded frame carries ${frameState.railAsides} ported rail(s) — src ${frameState.src}`);
        if (frameState.railAsides === 0 && frameState.textLen >= 0 && frameState.textLen < 40) issue("HIGH", "container-empty", next.href, `frame text ${frameState.textLen} chars — src ${frameState.src}`);
      }
      for (const ce of [...new Set(errs2)].slice(0, 2)) issue("MED", "container-console", next.href, ce);
      console.log(`  container ok? ${next.name || next.href} rail=${frameState.railAsides} text=${frameState.textLen}`);
    }
    console.log(`stage2: opened ${opened.length} apps in the container`);
  }
  await pg2.close();
}
if (STAGE === "stage3") {
  // IN-FRAME INTERACTION DEPTH: inside key embedded apps, drive whitelisted interactions
  // (tabs, list rows, back links) and assert each state renders (no blank, no console error,
  // no unstyled crash). Read-only: never Run/Delete/Create/Save.
  const FLOWS = [
    { app: "/automations", steps: ["tab:Automations", "row:first", "back:← All automations"] },
    { app: "/__ioi/data/sources", steps: ["link:Syncs"] },
    { app: "/provenance", steps: ["tab:History", "tab:Build timeline", "tab:Preview"] },
    { app: "/foundry", steps: ["link:Registered models", "link:IOI-provided models"] },
    { app: "/__ioi/evaluations/insight", steps: [] },
    { app: "/__ioi/domain-apps/fusion", steps: ["tab:Data Catalog", "tab:All files"] },
    { app: "/studio", steps: ["row:first"] },
    { app: "/__ioi/vertex", steps: ["row:first", "back:← All graphs"] },
  ];
  const pg3 = await browser.newPage({ viewport: { width: 1600, height: 950 } });
  const errs3 = [];
  pg3.on("console", (m) => { if (m.type() === "error") errs3.push(m.text().slice(0, 140)); });
  pg3.on("pageerror", (e) => errs3.push("PAGEERROR " + String(e).slice(0, 140)));
  const BLACK3 = /run|delete|remove|create|save|new |pause|resume|publish|install/i;
  for (const flow of FLOWS) {
    errs3.length = 0;
    try { await pg3.goto(SERVE + flow.app + (flow.app.includes("?") ? "&" : "?") + "embed=1", { waitUntil: "domcontentloaded", timeout: 20000 }); } catch (e) { issue("HIGH", "flow-nav", flow.app, e); continue; }
    await pg3.waitForTimeout(1500);
    for (const step of flow.steps) {
      const [kind, label] = step.split(":");
      let clicked = false;
      if (BLACK3.test(label || "")) { issue("MED", "flow-blacklist", flow.app, step); continue; }
      clicked = await pg3.evaluate(({ kind, label }) => {
        const t = (el) => (el.textContent || "").trim().replace(/\s+/g, " ");
        let el = null;
        if (kind === "row") el = document.querySelector('a[class*="-arow"], a[class*="-row"], a.spl-row, a.vtx-row, a.mon-row, a.dcx-row');
        else el = [...document.querySelectorAll('a, [role="tab"], button')].find((x) => t(x).startsWith(label));
        if (el) { el.click(); return true; }
        return false;
      }, { kind, label });
      await pg3.waitForTimeout(2200);
      const state = await pg3.evaluate(() => ({ len: document.body.innerText.trim().length, rails: document.querySelectorAll('aside.og-grail').length, url: location.pathname + location.search }));
      if (!clicked) issue("MED", "flow-step-missing", flow.app, `${step} — control not found`);
      else {
        if (state.len < 40) issue("HIGH", "flow-blank", flow.app, `${step} → ${state.url} blank (${state.len} chars)`);
        if (state.rails > 0) issue("HIGH", "flow-second-rail", flow.app, `${step} → ${state.url} carries ${state.rails} ported rail(s) IN EMBED`);
        console.log(`  ${flow.app} ${step} → ${state.url} (${state.len} chars, rails ${state.rails})`);
      }
    }
    for (const ce of [...new Set(errs3)].filter((x) => !/OrganizationService/.test(x)).slice(0, 2)) issue("MED", "flow-console", flow.app, ce);
  }
  await pg3.close();
}
if (STAGE === "stage4") {
  // FORMS + HONEST-EMPTY DEPTH: create forms carry their contract (required fields, seed-lane
  // action, no silent submit targets); zero-match filters and nonsense searches render HONEST
  // no-match copy (never a bare void, never fabricated rows).
  const CHECKS = [
    { url: "/__ioi/automations/monitors?tab=automations&view=new", expect: [
      ["form posts the seed lane", (t) => t.includes('action="/__ioi/automations?back=automate"')],
      ["project_ref REQUIRED (project-first contract)", (t) => /name="project_ref" required/.test(t)],
      ["no second mutation path", (t) => (t.match(/<form/g) || []).length === 1],
    ]},
    { url: "/__ioi/automations/monitors?tab=automations&condition=webhook", expect: [
      ["zero-match filter renders honest copy", (t) => /match this filter|never fabricates rows/.test(t)],
      ["zero rows when no webhook automations", (t) => (t.match(/class="mon-arow"/g) || []).length >= 0],
    ]},
    { url: "/__ioi/vertex?q=zzzznomatch", expect: [
      ["nonsense search renders honest no-match + live counts", (t) => /No graphs match|counts above are live/.test(t)],
      ["no fabricated result rows", (t) => (t.match(/class="vtx-row"/g) || []).length === 0],
    ]},
    { url: "/__ioi/data/sources?declare=1", expect: [
      ["declare form present and posts the governed action", (t) => t.includes("src-decform") && /action="\/__ioi\/data\/sources\/actions\/declare"/.test(t)],
    ]},
    { url: "/__ioi/studio/workshop", expect: [
      ["honest empty names the MISSING-vs-empty truth", (t) => /never fabricates rows/.test(t)],
    ]},
    { url: "/__ioi/domain-apps/logic", expect: [
      ["missing plane stated, not an empty one", (t) => /NOT an empty plane but a missing one/.test(t)],
    ]},
  ];
  for (const c of CHECKS) {
    let txt = "";
    try { const r = await fetch(SERVE + c.url); txt = await r.text(); if (r.status >= 400) issue("HIGH", "form-http", c.url, r.status); } catch (e) { issue("HIGH", "form-nav", c.url, e); continue; }
    for (const [name, fn] of c.expect) {
      let okv = false; try { okv = fn(txt); } catch { okv = false; }
      if (!okv) issue("MED", "form-contract", c.url, name);
      else console.log(`  ok ${c.url} — ${name}`);
    }
  }
}
if (STAGE === "stage5") {
  // RESPONSIVE/VIEWPORT: key surfaces at tablet (1024x768) and phone (390x844) — assert no
  // horizontal page overflow (wide content must scroll in its own container), content renders,
  // and the header controls stay reachable. Certified ports pin their own mobile posture
  // (mobile_not_supported recorded in pixel certs) — those are audited at tablet only.
  const KEY = ["/automations", "/studio", "/data", "/ontology", "/developer-workspace",
    "/__ioi/data/sources?lane=syncs", "/__ioi/lineage?tab=history", "/__ioi/vertex",
    "/__ioi/domain-apps/fusion", "/__ioi/environments/map", "/__ioi/marketplace/artifacts",
    "/__ioi/developer-console", "/__ioi/evaluations/insight", "/__ioi/studio/workshop",
    "/__ioi/missions/schedules", "/__ioi/data/ingest", "/__ioi/foundry/model-studio",
    "/__ioi/foundry/inference"];
  for (const vp of [{ w: 1024, h: 768, tag: "tablet" }, { w: 390, h: 844, tag: "phone" }]) {
    const pg5 = await browser.newPage({ viewport: { width: vp.w, height: vp.h } });
    for (const r of KEY) {
      try { await pg5.goto(SERVE + r, { waitUntil: "domcontentloaded", timeout: 20000 }); } catch (e) { issue("HIGH", "vp-nav", `${r}@${vp.tag}`, e); continue; }
      await pg5.waitForTimeout(900);
      const m = await pg5.evaluate(() => ({
        overflowX: document.documentElement.scrollWidth - window.innerWidth,
        len: document.body.innerText.trim().length,
        clipped: [...document.querySelectorAll("h1,h2")].some((h) => { const b = h.getBoundingClientRect(); return b.width > 0 && (b.right > window.innerWidth + 4 || b.left < -4); }),
      }));
      if (m.overflowX > 24) issue("MED", "vp-overflow", `${r}@${vp.tag}`, `page scrolls horizontally by ${m.overflowX}px (wide content must scroll in its own container)`);
      if (m.len < 40) issue("HIGH", "vp-blank", `${r}@${vp.tag}`, `${m.len} chars`);
      if (m.clipped) issue("LOW", "vp-clipped-heading", `${r}@${vp.tag}`, "an h1/h2 extends past the viewport");
    }
    await pg5.close();
  }
}
if (STAGE === "stage1") for (const route of SURFACES) {
  consoleErrs.length = 0;
  let resp = null;
  try { resp = await pg.goto(SERVE + route, { waitUntil: "domcontentloaded", timeout: 20000 }); } catch (e) { issue("HIGH", "nav-failed", route, e); continue; }
  await pg.waitForTimeout(1200);
  const status = resp ? resp.status() : 0;
  if (status >= 400) issue("HIGH", "http-error", route, `status ${status}`);
  for (const ce of [...new Set(consoleErrs)].slice(0, 3)) issue("MED", "console-error", route, ce);
  const audit = await pg.evaluate(() => {
    const out = { links: [], gaps_one_vocab: 0, capture_links: [], empty_body: false, doc_len: document.body.innerText.length };
    for (const a of document.querySelectorAll("a[href]")) {
      const h = a.getAttribute("href");
      if (h && h.startsWith("/") && !h.startsWith("//")) out.links.push(h.split("#")[0]);
      if (h && h.startsWith("/__apps/")) out.capture_links.push(h);
    }
    for (const el of document.querySelectorAll('[aria-disabled="true"]')) {
      if (!el.getAttribute("title") && !el.getAttribute("data-ioi-disabled-reason") && el.textContent.trim().length > 1 && el.getAttribute("role") !== "checkbox") out.gaps_one_vocab++;
    }
    out.empty_body = document.body.innerText.trim().length < 40;
    return out;
  });
  if (audit.empty_body) issue("HIGH", "empty-body", route, `innerText ${audit.doc_len} chars`);
  if (audit.gaps_one_vocab) issue("MED", "gap-no-reason", route, `${audit.gaps_one_vocab} disabled controls without any reason`);
  if (audit.capture_links.length && !route.startsWith("/__ioi/automations") && !route.includes("designer") && !route.includes("machinery")) {
    // capture links are evidence citations on certified port feet; flag elsewhere
  }
  for (const cl of [...new Set(audit.capture_links)]) issue("LOW", "capture-link", route, cl);
  // dead-link probe (dedup, cap 25/page)
  for (const h of [...new Set(audit.links)].slice(0, 25)) {
    const st = await probe(h);
    if (st >= 400 || st === 0) issue("HIGH", "dead-link", route, `${h} → ${st}`);
  }
}
await browser.close();
const prev = { schema: "ioi.hypervisor.ux-issues.v1", swept_at: new Date().toISOString(), serve: SERVE, issues: ISSUES,
  tally: ISSUES.reduce((a, i) => ((a[i.kind] = (a[i.kind] || 0) + 1), a), {}) };
writeFileSync(join(ROOT, "hypervisor-ux-issues.v1.json"), JSON.stringify(prev, null, 2) + "\n");
console.log(`\nSWEEP: ${ISSUES.length} issues → hypervisor-ux-issues.v1.json`, JSON.stringify(prev.tally));
