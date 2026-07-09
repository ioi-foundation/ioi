#!/usr/bin/env node
// OBJECT EXPLORER REFERENCE PORT — #35 done-bar (reference_ported: faithful shell + real wiring, NOT parity).
//
// /__ioi/ontology/explorer is a FAITHFUL source-neutral port of the reference Object Explorer (dark
// global rail + a light "Object Explorer search" header with the Filter/Search bar + a Shortcuts strip
// + an Object type CATALOG table + an Object set CATALOG), wired to the REAL ODK truth (object types
// across ontologies, materialized object sets, per-type object + usage counts, a working server-side
// object-type filter). Paired with #34 Ontology Manager (first-class linked both ways). READ-ONLY.
//
// It is HONESTLY `reference_ported`, NOT `daemon_wired`: the local /workspace/hubble reference does not
// cleanly boot — the /__apps/explorer proxy renders a BLANK body and the mirror's data lanes render
// "Failed to load" — so the hardened harness has NO valid reference to certify visual_parity against.
// This verifier proves: (a) the matrix says reference_ported (not daemon_wired) with a documented
// parity_blocked; (b) the shell is the faithful light Object-Explorer IA (not automationsShell / not a
// dark redesign); (c) real daemon truth is wired (object-type catalog + object-set catalog + counts +
// working filter cross-check the live daemon); (d) the hardened harness REFUSES to certify parity.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-object-explorer.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const jd = async (method, p, body) => { const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
// Retry once: a long harness spawn can leave an idle keep-alive socket that resets on the next fetch.
const page = async (url) => { for (let i = 0; i < 2; i++) { try { const r = await fetch(url); return { status: r.status, text: await r.text() }; } catch { if (i) return { status: 0, text: "" }; } } };
const rx = (s) => String(s == null ? "" : s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon ODK plane not reachable at " + DAEMON); process.exit(2); }

  // 0. Matrix — explorer is reference_ported (NOT daemon_wired), with a documented parity_blocked.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix classifies explorer as reference_ported → /__ioi/ontology/explorer (NOT daemon_wired)", bySlug.explorer?.parity_class === "reference_ported" && bySlug.explorer?.port_surface === "/__ioi/ontology/explorer" && bySlug.explorer?.candidate_surface === "/__ioi/ontology/explorer");
  ok("the block is documented (parity_blocked names the blank/failed local Hubble reference)", typeof bySlug.explorer?.parity_blocked === "string" && /hubble|blank|failed to load|no backend|re-?harvest/i.test(bySlug.explorer.parity_blocked));
  ok("daemon_wired stays sacred: schema is still the only daemon_wired; reference_capture is the majority", bySlug.schema?.parity_class === "daemon_wired" && (matrix.by_parity_class?.daemon_wired || 0) === 1 && (matrix.by_parity_class?.reference_capture || 0) > (matrix.by_parity_class?.reference_ported || 0));
  ok("explorer declares NO reference_landmarks (a blank reference has no IA to reproduce — it must not be gameable into parity)", !Array.isArray(bySlug.explorer?.reference_landmarks) || bySlug.explorer.reference_landmarks.length === 0);

  // Fixtures: TWO real DomainOntologies — GizmoKind (the match) + WidgetKind (a GUARANTEED non-matching
  // sibling), so the filter drop-test always executes (not behind an incidental-daemon-state guard).
  const DOM = `om-explorer-fixture-${process.pid}`;
  const OTHER = `om-explorer-other-${process.pid}`;
  const comOf = (oid, name) => ({ value_types: [{ id: "vt_n", name: "Nm", base: "string" }], object_types: [{ id: oid, name, title_property: "p_t", properties: [{ id: "p_t", name: "Tt", value_type: "vt_n", required: true }] }], link_types: [], action_types: [] });
  const created = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: DOM, version: "0.1.0", canonical_object_model: comOf("ot_gizmo", "GizmoKind") });
  const fix = created.j.ontology;
  const createdOther = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: OTHER, version: "0.1.0", canonical_object_model: comOf("ot_widget", "WidgetKind") });
  const other = createdOther.j.ontology;
  ok("fixture DomainOntologies created (GizmoKind + a guaranteed non-matching WidgetKind sibling)", created.status === 201 && fix?.id && createdOther.status === 201 && other?.id, `${fix?.id} · ${other?.id}`);

  // 1. Reference is honestly not-clean (proxy renders blank/nav-only OR the mirror fails to load data).
  const ref = await page(`${SERVE}/__apps/explorer`);
  ok("reference /__apps/explorer boots the Object-Explorer app chrome (the local capture is data-blank — that is WHY this is reference_ported)", ref.status === 200 && /Object Explorer/i.test(ref.text));

  // 2. FAITHFUL PORTED SHELL — the light Object-Explorer IA, not automationsShell / not a dark redesign.
  const port = await page(`${SERVE}/__ioi/ontology/explorer`);
  const t = port.text;
  ok("the port is the two-rail og-shell with the Object-Explorer header + body (not automationsShell)", port.status === 200 && /class="og-shell"/.test(t) && /class="og-grail"/.test(t) && /class="oe-header"/.test(t) && /<main class="oe-body"[^>]*role="main"/.test(t) && !/class="wrap"/.test(t) && !/max-width:920px/.test(t) && !/class="automations/.test(t));
  ok("the port is LIGHT-themed (matches the light reference)", /html\{color-scheme:light\}/.test(t) && /background:#f4f5f7/.test(t) && !/color-scheme:dark/.test(t));
  ok("<title>Object Explorer</title> + the reference IA sections (Object Explorer search · Shortcuts · Object type catalog · Object set catalog)", /<title>Object Explorer/.test(t) && /Object Explorer search/.test(t) && />Shortcuts</.test(t) && /Object type catalog/.test(t) && /Object set catalog/.test(t));
  ok("the object-type catalog table reproduces the reference columns (name · status · objects · usage · ontology · description)", ["Object type name", "Status", "Objects", "Usage", "Ontology", "Description"].every((c) => t.includes(c)));

  // 3. DAEMON TRUTH WIRED — real object types + object sets + counts cross-check the live daemon.
  // Parallel-safe: fetch the daemon totals and the rendered page in ONE settle window and require them
  // to agree (a concurrent verifier mutating the shared ontology count can't cause a false failure).
  let onts = [], sets = [], totalTypes = 0, tt = t;
  for (let i = 0; i < 5; i++) {
    onts = (await jd("GET", "/v1/hypervisor/odk/domain-ontologies")).j.ontologies || [];
    sets = (await jd("GET", "/v1/hypervisor/odk/materialized-object-sets")).j.materialized_object_sets || [];
    totalTypes = onts.reduce((n, oo) => n + (((oo.canonical_object_model || {}).object_types || []).length), 0);
    tt = (await page(`${SERVE}/__ioi/ontology/explorer`)).text;
    if (new RegExp(`Object type catalog <span class="oe-subn">${totalTypes}<`).test(tt) && new RegExp(`>All<span class="oe-c">${sets.length}</span>`).test(tt)) break;
  }
  ok("the fixture object type renders in the catalog (name · id · ontology domain) — real daemon truth", tt.includes("GizmoKind") && tt.includes("ot_gizmo") && tt.includes(DOM));
  ok("CROSS-CHECK: the object-type catalog count matches the live daemon (total object types across ontologies)", new RegExp(`Object type catalog <span class="oe-subn">${totalTypes}<`).test(tt), `catalog ${(tt.match(/Object type catalog <span class="oe-subn">(\d+)/) || [])[1]} · daemon ${totalTypes}`);
  ok("CROSS-CHECK: the object-set catalog count matches the live daemon materialized sets", new RegExp(`>All<span class="oe-c">${sets.length}</span>`).test(tt), `sets rendered vs daemon ${sets.length}`);
  // PER-ROW cross-check: an existing materialized set's rendered Objects count EQUALS the daemon's count
  // (proves the numbers are real daemon truth, not a fabricated/placeholder value). Honest-skip if the
  // estate has no materialized sets yet (this verifier does not build the full projection ladder).
  const aset = sets[0];
  ok(aset ? "CROSS-CHECK: a real materialized set's rendered Objects count equals the daemon count (per-row, not fabricated)" : "object-set object counts are wired (no materialized set in the estate to cross-check — honest skip)", !aset || new RegExp(`${rx(aset.name || aset.id || "object set")}[\\s\\S]{0,400}?<b>${aset.count || 0}</b>`).test(tt), aset ? `set ${aset.name || aset.id} → ${aset.count || 0}` : "no sets");

  // 4. The working, server-side object-type FILTER — proven with the GUARANTEED decoy: ?q=<domain> keeps
  // GizmoKind and unconditionally DROPS WidgetKind (a no-op / ignored filter would leave it, so this
  // half always executes — it does not depend on incidental daemon state).
  const filtered = await page(`${SERVE}/__ioi/ontology/explorer?q=${encodeURIComponent(DOM)}`);
  const ft = filtered.text;
  ok("the object-type filter is REAL + server-side: ?q=<domain> keeps GizmoKind and DROPS the guaranteed WidgetKind sibling", filtered.status === 200 && ft.includes(">GizmoKind</a>") && tt.includes(">WidgetKind</a>") && !ft.includes(">WidgetKind</a>"), `q=${DOM} · unfiltered-has-widget=${tt.includes(">WidgetKind</a>")} · filtered-has-widget=${ft.includes(">WidgetKind</a>")}`);

  // 5. THE HARDENED GATE REFUSES to certify — honest reference_ported. Corroborated from OBSERVED harness
  // behaviour (not just the config): the reference actually renders NO Object-Explorer IA (blank/failed
  // in the local mirror), so there is nothing faithful to certify against. This FAILS (forcing a promote-
  // or-declare-landmarks decision) the day /workspace/hubble is re-harvested into a data-rich reference.
  const artDir = path.join(appRoot, ".artifacts", "object-explorer-port-verify");
  const h = spawnSync("node", [path.join(here, "harness-reference-parity.mjs")], { encoding: "utf8", timeout: 90000, env: { ...process.env, IOI_HARNESS_SURFACES: "explorer", IOI_HARNESS_ARTIFACT_DIR: artDir } });
  let hp = null;
  if (h.status === 0 && existsSync(path.join(artDir, "result.json"))) hp = (JSON.parse(readFileSync(path.join(artDir, "result.json"), "utf8")).surfaces || [])[0];
  ok("HARDENED harness REFUSES parity: visual_parity is FALSE — honest reference_ported (schema declares no landmarks over a blank reference)", hp && hp.visual_parity === false, hp ? `visual=${hp.visual_parity} structural=${hp.structural_parity} lm_declared=${hp.landmark_declared}` : "harness did not run");
  ok("OBSERVED CORROBORATION: the reference renders NONE of its own Object-Explorer IA (data-blank in the local mirror) — the real reason for reference_ported, and this flips if it is ever re-harvested clean", hp && typeof hp.reference_visible_text === "string" && !/object type catalog|object set catalog/i.test(hp.reference_visible_text), hp ? `ref_text="${(hp.reference_visible_text || "").slice(0, 70)}…" ref_regions=[${hp.reference_regions}]` : "");
  ok("the IOI port itself is a clean, non-errored LIGHT surface (the block is the REFERENCE, not the port)", hp && hp.ioi_valid === true && hp.ioi_errored === false && hp.ioi_theme === "light", hp ? `ioi_valid=${hp.ioi_valid} ioi_theme=${hp.ioi_theme}` : "");

  // 6. READ-ONLY + named gaps disabled in place.
  ok("object-instance search + faceted Filter-by are named gaps disabled in place (no object-instance search plane)", /placeholder="Search for objects…" disabled/.test(t) && /class="oe-filterby" disabled/.test(t));
  ok("Recents / Favorites / sort / type-group+application / created-by-me+shared-with-me are named-gap lanes, not hidden", ["Recents", "Favorites", "Type group", "Application", "Created by me", "Shared with me"].every((l) => new RegExp(`class="oe-snav gap"[^>]*>${l}`).test(t)));

  // 7. Discoverability — first-class Manager <-> Explorer backlinks + substrate link; brand-clean.
  ok("the Explorer links the Ontology Manager first-class (rail + header)", t.includes('href="/__ioi/ontology/manager"') && /Ontology Manager →/.test(t));
  const mgr = await page(`${SERVE}/__ioi/ontology/manager`);
  ok("the Ontology Manager links the Object Explorer first-class (symmetric pair)", mgr.status === 200 && mgr.text.includes('href="/__ioi/ontology/explorer"'), `status=${mgr.status} bytes=${mgr.text.length} hasExplorer=${mgr.text.includes("/__ioi/ontology/explorer")}`);
  const odk = await page(`${SERVE}/__ioi/odk`);
  ok("the /__ioi/odk substrate links the ported Object Explorer; the surface is brand-clean", odk.status === 200 && odk.text.includes("/__ioi/ontology/explorer") && !/\bPalantir\b|\bFoundry\b/.test(t));

  // 8. Cleanup — delete BOTH fixtures.
  if (fix?.id) await jd("DELETE", `/v1/hypervisor/odk/domain-ontologies/${fix.id}`);
  if (other?.id) await jd("DELETE", `/v1/hypervisor/odk/domain-ontologies/${other.id}`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`object-explorer-port readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
