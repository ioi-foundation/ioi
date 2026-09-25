#!/usr/bin/env node
// TERMINAL ABSENCES verifier (ADR 0056 M7 + M7b, 2026-09-25) — the lanes the best-in-class
// autonomous-systems substrate keeps no place for (Amendment 1's re-adjudication), recorded and retired.
//
// M7 retires the two that shipped as landings — Contour (dataset BI) and Notepad (document authoring):
//   1. TYPED RETIREMENT — the route answers 410 with the registered refusal record (JSON: nothing read,
//      nothing written, no replacement) or the retired-route page (HTML) that says it is a terminal
//      absence, says WHY, names the adjudication, and links nowhere but Home — no successor, no alias.
//   2. NO FALLBACK — no registry row, no bound module, no canonical yield; the parity matrix no longer
//      claims the port and cites the amendment; the adjudication is RECORDED with its reason.
//   3. NOTHING LEADS THERE — the landings that listed it no longer do.
//   4. THE SEED IS PRESERVED — its rendering code stays in the serve, bound to nothing.
// M7b records the seven reference lanes that never shipped (Slate, SQL Studio, AIP Analyst, Carbon, Foundry
// Rules, AI FDE, Training) plus Quiver's BI half: each has a terminal_absence adjudication saying what
// covers it or why it is outside the substrate, and Slate's stale NOW designation is TERMINAL.
//
// Run against a sign-in-off serve (the census posture): IOI_HYPERVISOR_SERVE_URL=http://127.0.0.1:<port>
// Exit: 0 pass · 1 fail · 2 blocked (serve unreachable).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES, boundSurface, canonicalSurfaceRoute } from "./surface-registry.mjs";
import { retiredUiRouteFor } from "./v2-route-shell.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail: String(detail).slice(0, 220) });
const get = (p, accept) => fetch(`${SERVE}${p}`, { headers: { accept }, redirect: "manual" })
  .then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const readJson = (f) => JSON.parse(fs.readFileSync(path.join(APP, f), "utf8"));

const reachable = await get("/", "text/html");
if (!reachable.status) { console.error(`BLOCKED: no serve at ${SERVE}`); process.exit(2); }

const matrix = readJson("harvest-app-parity-matrix.json");
const bySeed = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
const adjudications = readJson("reference-seed-adjudications.v1.json").records || [];
const terminalRecord = (seed) => adjudications.find((r) => r.seed === seed && r.outcome === "terminal_absence");
const designations = readJson("landing-designations.v1.json").targets || [];
const serveSrc = fs.readFileSync(path.join(HERE, "serve-product-ui.mjs"), "utf8");

const RETIRED = [
  { slug: "contour", route: "/__ioi/domain-apps/contour", designation: "domain-apps:contour", linkers: ["/__ioi/domain-apps"],
    seed: () => serveSrc.includes('pathname === "/__ioi/domain-apps/contour"') && serveSrc.includes('"domain-apps/contour"') },
  { slug: "notepad", route: "/__ioi/developer-workspace/notepad", designation: null, linkers: ["/developer-workspace", "/__ioi/developer-workspace/workspaces"],
    seed: () => serveSrc.includes('if (pathname === "/__ioi/developer-workspace/notepad" && req.method === "GET")') },
];
for (const m of RETIRED) {
  const json = await get(m.route, "application/json");
  let refusal = {};
  try { refusal = JSON.parse(json.text); } catch { /* reported below */ }
  ok(`${m.slug}: TYPED RETIREMENT (JSON) — 410 with the registered refusal record, no replacement, nothing read, nothing written`,
    json.status === 410 && refusal.schema_version === "ioi.hypervisor.route_retirement_refusal.v1" && refusal.code === "hypervisor.route_retired"
      && refusal.requested_route === m.route && refusal.canonical_replacement_route === null
      && refusal.read_performed === false && refusal.mutation_performed === false && refusal.final_invocation_performed === false,
    `${json.status} ${json.text.slice(0, 120)}`);
  const retired = retiredUiRouteFor(m.route);
  const html = await get(m.route, "text/html");
  const hrefs = [...html.text.matchAll(/href="([^"]*)"/g)].map((x) => x[1]).filter((h) => h.startsWith("/"));
  ok(`${m.slug}: TYPED RETIREMENT (HTML) — the page says it is a terminal absence and WHY, names the adjudication, and links nowhere but Home`,
    html.status === 410 && /terminal absence/.test(html.text) && !!retired?.reason && html.text.includes(retired.reason.slice(0, 50))
      && /ADR 0056 Amendment 1/.test(html.text) && hrefs.every((h) => h === "/ai"), `${html.status} hrefs=${hrefs.join(",")}`);
  ok(`${m.slug}: NO FALLBACK — no registry row, no bound module, no canonical yield; the route shell marks it terminal with no successor`,
    !SURFACES.some((s) => s.slug === m.slug || s.route === m.route) && !boundSurface(m.route, "GET") && !canonicalSurfaceRoute(m.route)
      && retired?.terminal === true && retired?.replacement === null && !retired?.successor);
  const row = bySeed[m.slug];
  ok(`${m.slug}: the parity matrix no longer claims the port and cites the amendment; the adjudication is recorded with its reason`,
    row && row.parity_class !== "reference_ported" && !row.candidate_surface && /ADR 0056 Amendment 1/.test(row.adjudication_ref || "")
      && (terminalRecord(m.slug)?.reason || "").length > 40, `${row?.parity_class}`);
  if (m.designation) {
    const d = designations.find((t) => t.click_target === m.designation);
    ok(`${m.slug}: its landing designation is TERMINAL, cites the ADR, and names no route`, d?.status === "TERMINAL" && /0056/.test(d?.adjudication_ref || "") && !d?.route);
  }
  const linking = [];
  for (const p of m.linkers) {
    const r = await get(p, "text/html");
    if (new RegExp(`href="${esc(m.route)}(?:[?"#])`).test(r.text)) linking.push(p);
  }
  ok(`${m.slug}: NOTHING LEADS THERE — no landing that listed it still does`, linking.length === 0, linking.join(" "));
  ok(`${m.slug}: THE SEED IS PRESERVED — its rendering code stays in the serve, bound to nothing`, m.seed());
}

// M7b — the reference lanes that never shipped, plus Quiver's BI half: recorded, with what covers each.
for (const seed of ["slate", "sql-studio", "aip-analyst", "carbon", "foundry-rules", "ai-fde", "training", "quiver"]) {
  const r = terminalRecord(seed);
  ok(`M7b ${seed}: a terminal_absence adjudication records what covers it or why it is outside the substrate`,
    r && (r.reason || "").length > 40 && (r.estate_plane || "").length > 5 && /0056/.test(r.evidence || ""), r ? "" : "missing");
}
const slate = designations.find((t) => t.click_target === "domain-apps:slate");
ok("M7b slate: the stale NOW designation is TERMINAL (no port was ever built; the route answered a not-found page)", slate?.status === "TERMINAL" && !slate?.route);
ok("M7b quiver: only the BI half is terminal — the Quiver port keeps serving as the seed Operations / Telemetry is rebound from",
  SURFACES.some((s) => s.slug === "quiver") && /time-series core is NOT terminal/.test(terminalRecord("quiver")?.reason || ""));

const passed = results.filter((r) => r.pass).length;
for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.pass || !r.detail ? "" : `  (${r.detail})`}`);
console.log(`${passed}/${results.length} passed`);
process.exit(passed === results.length ? 0 : 1);
