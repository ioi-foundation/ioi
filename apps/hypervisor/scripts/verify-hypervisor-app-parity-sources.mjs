#!/usr/bin/env node
// PIXEL-CERTIFIED PARITY verifier — Data · Sources done-bar (#52, sources seed only).
//
// The ELEVENTH faithful port, the FOURTH from the origin-alignment queue, and the Data-family
// LANDING surface. The #44 sweep proved the Data Connection landing data-bearing on the
// capture-origin lane (localhost:9225/workspace/data-ingestion-app/) while the /__apps/sources
// proxy lane renders no data; #52 stamps reference_url_override onto the honest lane (the
// What's-new modal dismissed by a reference-only pre-capture hook) and builds /__ioi/data/sources
// as a DECLARED source catalog over the real DataSource registry.
//
// THE AUTHORITY BOUNDARY IS THE POINT OF THIS VERIFIER: declared sources, never extraction.
//   1. MATRIX/CERT/SWEEP: daemon_wired + origin-aligned + REAL non-pinned certification; census >= 11.
//   2. REGISTRY CROSS-CHECKS: rendered catalog count equals the registry; a real source's
//      ref/kind/posture renders; ingestion.wired:false renders LOUDLY (row flag + the daemon's own
//      note verbatim); the row cap is declared; empty lanes stay honest.
//   3. SECURITY: the daemon REJECTS credential-bearing endpoints with its typed code (probed with
//      a sentinel that is never created); rendered HTML + the committed cert artifact carry NO
//      userinfo/query fragments; endpoints render scheme+host+path only.
//   4. NO EXTRACTION SEMANTICS: read-only (no forms, no connect/test/sync affordance); the
//      set-up cards are verbatim reference chrome with disabled overlays; the governed path
//      stays the ODK ladder (linked first-class).
//   5. NO body pixel claim: the certification is SHELL-scoped; rows are masked live data.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-sources.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}

async function run() {
  const reg = (await jd("GET", "/v1/hypervisor/data-sources")).j;
  const sourcesAll = reg.data_sources || [];
  if (!Array.isArray(reg.data_sources)) { console.error("BLOCKED: daemon data-source registry not reachable at " + DAEMON); process.exit(2); }
  const cleanup = [];
  let fixture = null;
  if (!sourcesAll.length) {
    // Legitimate fixture through the existing daemon route (no secrets; local declared endpoint).
    fixture = (await jd("POST", "/v1/hypervisor/data-sources", { name: "sources-parity-fixture", kind: "rest_api", endpoint: "http://127.0.0.1:9/declared-only", credential_posture: "wallet_credential_lease" })).j.data_source;
    if (fixture?.source_id) cleanup.push(fixture.source_id);
  }
  const sources = (await jd("GET", "/v1/hypervisor/data-sources")).j.data_sources || [];

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  const row = bySlug.sources;
  ok("matrix: sources is daemon_wired at /__ioi/data/sources (Data) with Data-Connection-IA landmarks", row && row.parity_class === "daemon_wired" && row.candidate_surface === "/__ioi/data/sources" && row.surface_name === "Data" && Array.isArray(row.reference_landmarks) && row.reference_landmarks.length >= 8, row ? `class=${row.parity_class}` : "row missing");
  ok("matrix: the reference is ORIGIN-ALIGNED (reference_url_override → localhost:9225/workspace/data-ingestion-app/)", row && row.reference_url_override === "http://localhost:9225/workspace/data-ingestion-app/");
  ok("the estate census accepts sources among the certified daemon_wired surfaces (>= 11 since #52); reference_capture stays the honest majority", (matrix.by_parity_class?.daemon_wired || 0) >= 11 && (matrix.by_parity_class?.reference_capture || 0) >= 20, JSON.stringify(matrix.by_parity_class));

  // 0b. Certification is REAL, committed, non-pinned, SHELL-scoped.
  let cert = null, certRaw = "";
  try { certRaw = readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8"); cert = JSON.parse(certRaw); } catch { /* */ }
  ok("matrix: sources is shell_pixel_certified with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/sources.json" && row.parity_class === "daemon_wired");
  ok("the committed certification is REAL: sources slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "sources" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" | ") : "cert missing");
  ok("the certification passed the visual gates on BOTH viewports (theme + structure + landmarks, both sides valid, against the ORIGIN reference)", cert && cert.reference_url === "http://localhost:9225/workspace/data-ingestion-app/" && cert.viewports.every((v) => v.gates && v.gates.theme_match && v.gates.structural_parity && !v.gates.reference_errored && !v.gates.ioi_errored && v.gates.landmark_covered === v.gates.landmark_applicable));
  ok("NO full-body pixel claim: the certification is explicitly SHELL-scoped (source rows are the masked live data, verified semantically below)", cert && /SHELL/i.test(cert.note || "") && /body/i.test(cert.note || ""));

  // 0c. Sweep contract.
  let sweep = null;
  try { sweep = JSON.parse(readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8")); } catch { /* */ }
  const sw = sweep && (sweep.seeds || []).find((s) => s.slug === "sources");
  ok("clean sweep: sources classifies data_clean on the aligned (origin/override) lane, with real data evidence", sw && sw.clean_state === "data_clean" && ["origin", "override"].includes(sw.lane_used) && (sw.data_evidence?.table_rows > 0 || sw.data_evidence?.cards > 0), sw ? `${sw.clean_state} via ${sw.lane_used}` : "sweep row missing");
  ok("clean sweep: the proxy-lane no-data blocker stays documented (evidence, not hidden)", sw && (sw.lanes_summary || []).some((l) => l.lane === "proxy" && l.data_score === 0), sw ? JSON.stringify((sw.lanes_summary || []).map((l) => `${l.lane}:score${l.data_score}`)) : "");

  // 1. Reference lanes (the origin lane is an SPA shell — identity markers in raw HTML; data-bearing
  // rendering is proven by the sweep's Playwright evidence + the certification's reference gates).
  const origin = await page("http://localhost:9225/workspace/data-ingestion-app/");
  ok("origin-aligned reference serves the Data Connection workspace (valid; data-bearing per sweep + cert gates)", origin.status === 200 && /Data Connection|data-ingestion/.test(origin.text));
  const ref = await page(`${SERVE}/__apps/sources`);
  ok("the /__apps/sources proxy lane still serves (kept as the familiar baseline; documented insufficient — never silently removed)", ref.status === 200);

  // 2. The PORT = the faithful landing shell over the real registry.
  const sp = await page(`${SERVE}/__ioi/data/sources`);
  const t = sp.text;
  ok("the port renders the faithful Data Connection landing shell (tabbed header + hero + set-up card + View row + table + examples + catalog)", sp.status === 200 && /class="src-htitle">Data Connection</.test(t) && /class="src-tab" href="\/__ioi\/data\/sources"/.test(t) && /Synchronize and manage data flows/.test(t) && /Set up new connections/.test(t) && /class="src-thead"/.test(t) && /Explore reference examples/.test(t) && /id="sources-catalog"/.test(t));
  ok("all matrix reference landmarks render on the port", (row.reference_landmarks || []).every((l) => t.toLowerCase().includes(String(l).toLowerCase())), (row.reference_landmarks || []).filter((l) => !t.toLowerCase().includes(String(l).toLowerCase())).join(" · ") || "10/10");

  // 3. REGISTRY CROSS-CHECKS.
  ok("the declared-catalog count equals the daemon registry", new RegExp(`Declared source catalog <span class="src-count">${sources.length}</span>`).test(t), `registry=${sources.length}`);
  const newest = [...sources].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))[0];
  ok("a REAL declared source renders: ref + kind + credential_posture in the row path", newest && t.includes(newest.source_ref) && t.includes(newest.kind) && t.includes(newest.credential_posture || "no posture"), newest && newest.source_ref);
  ok("rendered rows equal the registry after the declared cap (newest 12)", (t.match(/class="src-row"/g) || []).length === Math.min(12, sources.length) && /newest 12 shown above/.test(t), `${(t.match(/class="src-row"/g) || []).length} rows vs ${Math.min(12, sources.length)}`);
  const wiredFalse = sources.filter((s) => s.ingestion && s.ingestion.wired === false).length;
  ok("ingestion.wired:false renders LOUDLY: per-row 'not wired' flags + the boundary census + the daemon's own note VERBATIM", (t.match(/class="src-wired"/g) || []).length === Math.min(12, wiredFalse >= 12 ? 12 : wiredFalse) && new RegExp(`${wiredFalse} of ${sources.length} source`).test(t) && /declaration only — extraction requires a future authority crossing/.test(t), `${wiredFalse}/${sources.length} wired:false`);
  ok("the sync-counter cluster is bound to REAL materializing-run truth (declared in place, not the capture's zeros)", /REAL sync activity — the estate's ODK materializing runs/.test(t) && /in-flight · \d+ executed · \d+ failed/.test(t));

  // 4. SECURITY — the boundary against credential material.
  const probe = await jd("POST", "/v1/hypervisor/data-sources", { name: "sources-verify-userinfo-probe", kind: "rest_api", endpoint: "http://sentinel-user:sentinel-pass-XyZZy@127.0.0.1:1/x", credential_posture: "wallet_credential_lease" });
  ok("the daemon REJECTS credential-bearing endpoints with its typed code (the probe record is never created)", probe.status === 400 && probe.j.error?.code === "data_source_endpoint_credentialed", `${probe.status}/${probe.j.error?.code}`);
  ok("no credential material anywhere: the rendered HTML and the committed cert artifact carry no userinfo sentinel and no query fragments in endpoints", !t.includes("XyZZy") && !certRaw.includes("XyZZy") && !/src-rowpath[^<]*[?@#]\w+=/.test(t));
  ok("endpoints render scheme+host+path ONLY (no '?', '@' or '#' inside any rendered endpoint)", (() => {
    const paths = t.match(/class="src-rowpath">[^<]+/g) || [];
    return paths.every((p) => { const ep = p.match(/https?:\/\/\S+/g) || []; return ep.every((u) => !/[?@#]/.test(u.replace(/^https?:\/\//, ""))); });
  })());
  ok("credential postures are declared postures only (the surface says so; no posture VALUE is a secret)", /Credential postures are declared postures/.test(t) && /credential VALUES never appear/.test(t));

  // 5. NO EXTRACTION SEMANTICS — the hard line.
  ok("the surface is READ-ONLY (no forms; no connect/test/sync/extract affordance)", !/<form/.test(t) && !/action="[^"]*\/(connect|test|sync|extract|materialize)"/.test(t));
  ok("the boundary is declared in place: no extraction / no connection test / no live connector read / no materialization on this surface", /no extraction, no connection test, no live connector read, no materialization/.test(t));
  ok("unsupported controls are DISABLED IN PLACE with named-gap titles (tabs ×4 · store · New source · Help · set-up options ×3 · example installs ×2)", (t.match(/aria-disabled="true"/g) || []).length >= 11 && /Live-connection setup is not a bound lane/.test(t) && /Static upload is a reference-only lane/.test(t) && /Data synthesis is a reference-only lane/.test(t) && /Source declaration from this surface is a reference-only lane/.test(t), `${(t.match(/aria-disabled="true"/g) || []).length} disabled controls`);
  ok("the verbatim strips are declared capture chrome and NOT extraction affordances", /verbatim capture chrome/.test(t) && /not an extraction affordance/i.test(t));

  // 6. Owner discoverability + brand.
  const odk = await page(`${SERVE}/__ioi/odk`);
  ok("owner discoverability: the ODK builder links the catalog first-class, and the port links the Data ladder + builder back", odk.status === 200 && odk.text.includes("/__ioi/data/sources") && t.includes('href="/__ioi/pipeline"') && t.includes('href="/__ioi/odk"'));
  ok("the origin-aligned reference + the insufficient proxy lane are BOTH linked and explained on the surface", t.includes("http://localhost:9225/workspace/data-ingestion-app/") && t.includes("/__apps/sources") && /renders no data/.test(t));
  ok("IOI surface brand-clean (no Palantir)", !/\bPalantir\b/.test(t));

  for (const id of cleanup) await jd("DELETE", `/v1/hypervisor/data-sources/${id}`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`app-parity-sources readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
