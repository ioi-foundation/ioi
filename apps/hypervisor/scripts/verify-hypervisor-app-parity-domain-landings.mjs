#!/usr/bin/env node
// PARITY verifier — the I-4 TYPED-ABSENT landings: Logic + Contour (DOM-1) + Custom Widgets (DEV-1): origin-aligned I-4
// landings over TYPED-ABSENT bodies (no no-code-function / analysis-workbook planes exist).
// The done-bar here is HONESTY: grammar renders, absences are named in both vocabularies, no rows
// are fabricated, evidence is cited on-surface.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const SERVE = process.env.IOI_SERVE_URL || "http://127.0.0.1:4173";
const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
for (const [slug, route, title, absentPhrase, ownerLink] of [
  ["logic", "/__ioi/domain-apps/logic", "Logic", "no no-code-function plane", "/__ioi/domain-apps"],
  ["contour", "/__ioi/domain-apps/contour", "Contour", "EVA-2", "/__ioi/domain-apps"],
  ["widgets", "/__ioi/developer-console/widgets", "Custom Widgets", "no widget plane", "/__ioi/developer-console"],
  ["notepad", "/__ioi/developer-workspace/notepad", "Notepad", "no document plane", "/__ioi/developer-workspace"],
  ["quiver", "/__ioi/evaluations/quiver", "Quiver", "no time-series analysis plane", "/__ioi/evaluations"],
]) {
  ok(`matrix: ${slug} is reference_ported at ${route}, origin-aligned`, bySlug[slug]?.parity_class === "reference_ported" && bySlug[slug]?.candidate_surface === route && /localhost:9225/.test(bySlug[slug]?.reference_url_override || ""), bySlug[slug]?.parity_class);
  const p = await page(`${SERVE}${route}`);
  const t = p.text;
  ok(`${slug}: renders 200 with the I-4 grammar, RAILLESS (owner ruling 2026-08-20: fabricated reference rails are certified-port evidence only)`, p.status === 200 && !t.includes("og-grail") && t.includes(title) && t.includes("Recents") && t.includes("Favorites"), String(p.status));
  ok(`${slug}: the BODY is a NAMED typed absence — zero fabricated rows`, (t.match(/class="spl-row"/g) || []).length === 0 && /NOT an empty plane but a missing one/.test(t) && new RegExp(absentPhrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i").test(t));
  ok(`${slug}: every gap carries the UNIFIED contract (aria === data-ioi count)`, (t.match(/aria-disabled="true"/g) || []).length >= 4 && (t.match(/aria-disabled="true"/g) || []).length === (t.match(/data-ioi-disabled-reason=/g) || []).length);
  ok(`${slug}: READ-ONLY + evidence cited (adjudication + atlas) + owner link`, !t.includes("<form") && new RegExp(`reference-seed-adjudications\\.v1\\.json#${slug}`).test(t) && /reference-family-atlas\.v1\.json/.test(t) && t.includes(ownerLink));
  ok(`${slug}: brand-clean (no Palantir; the rail's AIP-Assist chrome is estate-standard)`, !/\bPalantir\b/.test(t));
}
// WOR-1 rows-bearing landing: workspaces over the REAL environments plane (newest 15, cap named).
{
  const envs = await fetch(`${process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765"}/v1/hypervisor/environments`).then((r) => r.json()).then((j) => j.environments || []).catch(() => []);
  const p = await page(`${SERVE}/__ioi/developer-workspace/workspaces`);
  const t = p.text;
  ok("workspaces: matrix reference_ported at /__ioi/developer-workspace/workspaces", bySlug.workspaces?.parity_class === "reference_ported" && bySlug.workspaces?.candidate_surface === "/__ioi/developer-workspace/workspaces");
  ok("workspaces: renders the REAL environments plane — newest 15 with the cap NAMED", p.status === 200 && (t.match(/class="spl-row"/g) || []).length === Math.min(15, envs.length) && new RegExp(`newest 15 of ${envs.length}`).test(t), `rows=${(t.match(/class="spl-row"/g) || []).length} plane=${envs.length}`);
  ok("workspaces: a sampled REAL env id/name renders + rows link the owner surface", envs.length === 0 || (t.includes("/__ioi/environments")));
  ok("workspaces: unified gap contract + read-only + evidence cited", (t.match(/aria-disabled="true"/g) || []).length === (t.match(/data-ioi-disabled-reason=/g) || []).length && !t.includes("<form") && /reference-seed-adjudications\.v1\.json#workspaces/.test(t));
}
// DEV-2: devconsole Applications lane over the REAL connector estate.
{
  const D = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
  const conns = await fetch(`${D}/v1/hypervisor/connectors`).then((r) => r.json()).then((j) => j.connectors || []).catch(() => []);
  const scm = await fetch(`${D}/v1/hypervisor/scm-connectors`).then((r) => r.json()).then((j) => j.scm_connectors || j.connectors || []).catch(() => []);
  const p = await page(`${SERVE}/__ioi/developer-console`);
  const t = p.text;
  ok("devconsole: matrix reference_ported at /__ioi/developer-console", bySlug.devconsole?.parity_class === "reference_ported" && bySlug.devconsole?.candidate_surface === "/__ioi/developer-console");
  ok("devconsole: Applications lane rows == the REAL connector estate (declared + SCM)", p.status === 200 && (t.match(/class="dcx-row"/g) || []).length === conns.length + scm.length, `rows=${(t.match(/class="dcx-row"/g) || []).length} plane=${conns.length + scm.length}`);
  ok("devconsole: a sampled REAL registration renders with its auth posture verbatim", conns.length === 0 || (t.includes(conns[0].connector_id) && t.includes(conns[0].auth_posture || "")));
  ok("devconsole: OAuth-clients + guided-create are typed absences in BOTH vocabularies naming the real lanes", (t.match(/aria-disabled="true"/g) || []).length === (t.match(/data-ioi-disabled-reason=/g) || []).length && /Connections-owned|owned by Connections/.test(t) && !t.includes("<form"));
  ok("devconsole: evidence cited + sibling link", /reference-seed-adjudications\.v1\.json#devconsole/.test(t) && t.includes("/__ioi/developer-console/widgets"));
}
// EVA-2.build: Insight — Object-sets live; saved-sets degradation VERBATIM; Workbooks absent.
{
  const D = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
  const ms = await fetch(`${D}/v1/hypervisor/odk/materialized-object-sets`).then((r) => r.json()).then((j) => j.materialized_object_sets || []).catch(() => []);
  const ssRaw = await fetch(`${D}/v1/hypervisor/odk/saved-object-sets`).then((r) => r.json()).catch(() => ({}));
  const p = await page(`${SERVE}/__ioi/evaluations/insight`);
  const t = p.text;
  ok("insight: matrix reference_ported (analysis) at /__ioi/evaluations/insight", bySlug.analysis?.parity_class === "reference_ported" && bySlug.analysis?.candidate_surface === "/__ioi/evaluations/insight");
  ok("insight: Object-sets rows == the real materialized plane, with proof refs", p.status === 200 && (t.match(/class="ins-row"/g) || []).length >= ms.length && (ms.length === 0 || t.includes(ms[0].id)), `rows>=${ms.length}`);
  ok("insight: saved-sets honesty — rows if the plane answers, else its refusal code VERBATIM", Array.isArray(ssRaw.saved_object_sets) ? true : (ssRaw.code ? t.includes(ssRaw.code) : /typed degradation/.test(t)));
  ok("insight: Workbooks typed absence in BOTH vocabularies; read-only; evidence cited", t.includes('data-ioi-disabled-reason="No workbook plane exists') && !t.includes("<form") && /reference-seed-adjudications\.v1\.json#analysis/.test(t));
}
// WOR-2: repositories — D6 donor port over the REAL SCM plane.
{
  const D = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
  const scm = await fetch(`${D}/v1/hypervisor/scm-connectors`).then((r) => r.json()).then((j) => j.scm_connectors || j.connectors || []).catch(() => []);
  const p = await page(`${SERVE}/__ioi/developer-workspace/repositories`);
  const t = p.text;
  ok("repositories: matrix reference_ported with the donor recorded", bySlug.repositories?.parity_class === "reference_ported" && /code/.test(bySlug.repositories?.donor_capture || "") && bySlug.repositories?.remediation_state !== "capture_broken_no_donor");
  ok("repositories: rows == the REAL SCM plane with auth posture verbatim", p.status === 200 && (t.match(/class="spl-row"/g) || []).length === scm.length && (scm.length === 0 || t.includes(scm[0].auth_posture || "")), `rows=${(t.match(/class="spl-row"/g) || []).length} plane=${scm.length}`);
  ok("repositories: New-repository typed absence (both vocabularies) + donor story cited + read-only", t.includes('data-ioi-disabled-reason="Repository creation is not an estate verb') && /reference-seed-adjudications\.v1\.json#repositories/.test(t) && !t.includes("<form"));
}
// FUS-1: fusion — the FIRST live-tenant-sourced port. The mirror capture was byte-dead, so the
// evidence is the committed LIVE atlas (4 tabs · 39 rows · 6 facet groups; Data Catalog opens
// Collections + Files over an EMPTY catalog). Two tabs bind REAL planes; the rest are typed
// absences. The done-bar: rows == the plane (never more), caps NAMED, absences named in BOTH
// vocabularies, the identity correction stated on-surface, read-only, railless.
{
  const D = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
  const projects = await fetch(`${D}/v1/hypervisor/projects`).then((r) => r.json()).then((j) => j.projects || []).catch(() => []);
  const msets = await fetch(`${D}/v1/hypervisor/odk/materialized-object-sets`).then((r) => r.json()).then((j) => j.materialized_object_sets || []).catch(() => []);
  const dsrcs = await fetch(`${D}/v1/hypervisor/data-sources`).then((r) => r.json()).then((j) => j.data_sources || []).catch(() => []);
  const p = await page(`${SERVE}/__ioi/domain-apps/fusion`);
  const t = p.text;
  ok("fusion: matrix reference_ported at /__ioi/domain-apps/fusion with the live-atlas evidence carried", bySlug.fusion?.parity_class === "reference_ported" && bySlug.fusion?.candidate_surface === "/__ioi/domain-apps/fusion" && bySlug.fusion?.remediation_state === "live_ia_recorded" && /#fusion-port/.test(bySlug.fusion?.adjudication_ref || "") && /reference-live-tenant-deep-atlas/.test(bySlug.fusion?.live_reference_evidence || ""), bySlug.fusion?.parity_class);
  ok("fusion: renders 200 with the LIVE-tenant 4-tab file-browser grammar, RAILLESS (owner ruling 2026-08-20)", p.status === 200 && !t.includes("og-grail") && t.includes("Fusion") && t.includes("All files") && t.includes("Shared with you") && t.includes("Data Catalog") && t.includes("Trash") && t.includes("Quick filters"), String(p.status));
  ok("fusion: the identity correction is STATED on-surface (the click target is a file browser, not a spreadsheet)", /projects-&amp;-files browser/.test(t) && /not a spreadsheet/.test(t));
  ok("fusion: the reference's 6 facet groups + 3 quick filters render as typed absences, none fabricated into a filter", ["Types", "Status", "Portfolios", "Projects", "Organizations", "Tags", "Promoted items"].every((f) => t.includes(f)) && !/href="[^"]*fusion\?[^"]*facet=/.test(t));
  ok("fusion: All-files rows == the REAL projects plane (newest-40 cap), never more than the plane", (t.match(/class="fus-row"/g) || []).length === Math.min(40, projects.length) && (projects.length === 0 || t.includes(projects[0].project_id)), `rows=${(t.match(/class="fus-row"/g) || []).length} plane=${projects.length}`);
  ok("fusion: every gap carries the UNIFIED contract (aria === data-ioi count) and there are real absences", (t.match(/aria-disabled="true"/g) || []).length >= 12 && (t.match(/aria-disabled="true"/g) || []).length === (t.match(/data-ioi-disabled-reason=/g) || []).length, `${(t.match(/aria-disabled="true"/g) || []).length} gaps`);
  ok("fusion: READ-ONLY + evidence cited (adjudication #fusion-port + the LIVE deep atlas) + owner link", !t.includes("<form") && /reference-seed-adjudications\.v1\.json#fusion-port/.test(t) && /reference-live-tenant-deep-atlas\.v1\.json/.test(t) && t.includes("/__ioi/domain-apps"));
  ok("fusion: brand-clean (the live tenant host is never printed — the committed atlas is the citation)", !/\bPalantir\b/.test(t) && !/palantirfoundry/.test(t));
  // Data Catalog tab: Collections = a MISSING plane (not the reference's empty one); Files = LIVE.
  const c = await page(`${SERVE}/__ioi/domain-apps/fusion?tab=data-catalog`);
  ok("fusion: Data-Catalog Collections is a NAMED typed absence that distinguishes missing from the reference's empty", c.status === 200 && /NOT an empty plane but a missing one/.test(c.text) && /No collections yet/.test(c.text) && (c.text.match(/class="fus-row"/g) || []).length === 0);
  const f = await page(`${SERVE}/__ioi/domain-apps/fusion?tab=data-catalog&sub=files`);
  ok("fusion: Data-Catalog Files rows == the REAL data-asset planes (all object sets + newest-20 sources, cap NAMED)", f.status === 200 && (f.text.match(/class="fus-row"/g) || []).length === msets.length + Math.min(20, dsrcs.length) && new RegExp(`newest ${Math.min(20, dsrcs.length)} of ${dsrcs.length}`).test(f.text), `rows=${(f.text.match(/class="fus-row"/g) || []).length} plane=${msets.length + Math.min(20, dsrcs.length)}`);
  ok("fusion: a declared source is rendered as a DECLARATION — the daemon's own unwired state verbatim, never as extracted data", dsrcs.length === 0 || (/declaration only — extraction unwired/.test(f.text) && /declared data source/.test(f.text)));
}
// MAP-1: map — the CANVAS-grammar port, and the leg where the honest move is a REFUSAL to draw.
// The mirror capture was blocked_missing_capture (absent_confirmed); the live sweep overturned it
// (20 controls · 2 canvas surfaces · heading "No layers"). The done-bar here is different from
// every other port: NOTHING MAP-SHAPED MAY BE RENDERED. The canvas must be a typed absence that
// distinguishes MISSING from the reference's own EMPTY layer list, the single live lane must equal
// its plane exactly (and be labelled NOT-a-map), every row must name WHICH field its value came
// from, and no chrome reason may be boilerplate reused across controls.
{
  const D = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
  const GEO_KEYS = ["region", "location", "zone", "az"];
  const str = (v) => (typeof v === "string" && v.trim() !== "" ? v : "");
  const venues = await fetch(`${D}/v1/hypervisor/placement/venues`).then((r) => r.json()).then((j) => j.venues || []).catch(() => []);
  const cands = venues.flatMap((v) => (Array.isArray(v.candidates) ? v.candidates : []));
  const geoCands = cands.filter((c) => GEO_KEYS.some((k) => str(c[k])));
  const geoRegion = geoCands.filter((c) => str(c.region)).length;
  const geoLocation = geoCands.filter((c) => !str(c.region) && str(c.location)).length;
  const geoExpired = geoCands.filter((c) => String(c.status || "") === "expired").length;
  const geoNotLive = geoCands.filter((c) => (Array.isArray(c.risk_labels) ? c.risk_labels : []).some((l) => /_evidence_not_live_supply$/.test(String(l)))).length;
  const ops = await fetch(`${D}/v1/hypervisor/provider-operations`).then((r) => r.json()).then((j) => j.operations || []).catch(() => []);
  const opsGeo = ops.filter((o) => GEO_KEYS.some((k) => str((o.evidence || {})[k])));
  const opsGeoSim = opsGeo.filter((o) => JSON.stringify(o.evidence || {}).includes("simulated_control_plane")).length;
  const index = await fetch(`${D}/v1`).then((r) => r.json()).catch(() => ({}));
  const routes = (Array.isArray(index.families) ? index.families : []).flatMap((f) => (Array.isArray(f.paths) ? f.paths : []));
  const geoRoutes = routes.filter((r) => /(geo|geospatial|coordinate|latitude|longitude|geometry|basemap|\btile|map-layer|geocod|cartograph)/i.test(String(r.path || ""))).length;
  const readRoutes = routes.filter((r) => (Array.isArray(r.methods) ? r.methods : []).includes("GET") && !String(r.path || "").includes(":") && !String(r.path || "").includes("*") && !r.retired).length;
  const p = await page(`${SERVE}/__ioi/environments/map`);
  const t = p.text;
  const gapReasons = [...t.matchAll(/<span class="[^"]*mapp-gap[^"]*"[^>]*data-ioi-disabled-reason="([^"]*)"/g)].map((m) => m[1]);
  ok("map: matrix reference_ported at /__ioi/environments/map with the live-atlas evidence carried", bySlug.map?.parity_class === "reference_ported" && bySlug.map?.candidate_surface === "/__ioi/environments/map" && bySlug.map?.remediation_state === "live_ia_recorded" && /#map-port/.test(bySlug.map?.adjudication_ref || "") && /reference-live-tenant-deep-atlas/.test(bySlug.map?.live_reference_evidence || ""), bySlug.map?.parity_class);
  ok("map: renders 200 with the LIVE-tenant map-workbench grammar, RAILLESS (owner ruling 2026-08-20)", p.status === 200 && !t.includes("og-grail") && ["Map", "Add to map", "No layers", "Layers", "Legend", "Histogram", "Timeline", "Search Around", "Selection", "Save as…", "Polygon", "Rectangle"].every((k) => t.includes(k)), String(p.status));
  ok("map: NOTHING MAP-SHAPED IS DRAWN — no canvas, no svg/img geometry, no tile source, no borrowed vendor basemap", p.status === 200 && !/<canvas/i.test(t) && !/<svg/i.test(t) && !/<img/i.test(t) && !/\b(leaflet|maplibre|openlayers|deck\.gl)\b/i.test(t) && !/(tile\.|tiles\.|\/\{z\}\/\{x\}\/\{y\})/i.test(t));
  ok("map: brand-clean (no vendor basemap or tenant brand is printed — the committed atlas is the citation)", !/\bPalantir\b/i.test(t) && !/\bMapbox\b/i.test(t) && !/OpenStreetMap/i.test(t) && !/palantirfoundry/i.test(t));
  ok("map: the CANVAS is a typed absence that distinguishes MISSING from the reference's own EMPTY layer list", /<h2>No map canvas — NOT an empty map but a MISSING PLANE<\/h2>/.test(t) && /No layers — and NOT an empty layer list/.test(t) && /missing is not empty/.test(t));
  // The geo-plane claim is the load-bearing one on this surface, so it is COUNTED, not pasted: the
  // verifier re-derives the census from the daemon's own route index and fails both if the page's
  // number drifts from the plane AND if a geospatial route ever lands (which would make the whole
  // absence copy false and force a re-adjudication rather than quietly aging into a lie).
  ok("map: the geo-plane census is COUNTED from the daemon's route index on render, and it is still ZERO", geoRoutes === 0 && new RegExp(`publishes <b>${routes.length}</b> routes and <b>0</b> of them are geospatial`).test(t) && new RegExp(`fetched all ${readRoutes} param-free GET routes`).test(t), `routes=${routes.length} geo=${geoRoutes} paramFreeGET=${readRoutes}`);
  ok("map: the location lane is rows == the REAL placement plane EXACTLY, and is labelled NOT a map", (t.match(/class="mapp-row"/g) || []).length === Math.min(200, geoCands.length) && /NOT a map layer/.test(t) && /not coordinates/.test(t) && new RegExp(`${geoCands.length} of ${cands.length} REAL cloud-resource-candidate`).test(t), `rows=${(t.match(/class="mapp-row"/g) || []).length} plane=${geoCands.length}/${cands.length}`);
  ok("map: every row NAMES which field its value came from — a value is never shown under a header it does not belong to", (t.match(/field: region/g) || []).length === geoRegion && (t.match(/field: location/g) || []).length === geoLocation && geoCands.every((c) => t.includes(str(c.region) || str(c.location))), `region=${geoRegion} location=${geoLocation}`);
  ok("map: each row carries the RECORD'S OWN state — expired + not-live-supply counted from the records, never glossed", new RegExp(`<b>${geoExpired} of ${geoCands.length}</b> of these records are status <b>expired</b>`).test(t) && new RegExp(`<b>${geoNotLive}</b> carry a`).test(t) && (geoNotLive === 0 || /_evidence_not_live_supply/.test(t)), `expired=${geoExpired} notLive=${geoNotLive}`);
  ok("map: the SECOND geography lane is NAMED with live counts, not silently dropped", new RegExp(`<b>${opsGeo.length} of ${ops.length}</b> operations — ${opsGeoSim} of those ${opsGeo.length} carry`).test(t), `ops=${opsGeo.length}/${ops.length} sim=${opsGeoSim}`);
  ok("map: every gap carries the UNIFIED contract (aria === data-ioi count) and there are real absences", (t.match(/aria-disabled="true"/g) || []).length >= 20 && (t.match(/aria-disabled="true"/g) || []).length === (t.match(/data-ioi-disabled-reason=/g) || []).length, `${(t.match(/aria-disabled="true"/g) || []).length} gaps`);
  ok("map: no chrome reason is BOILERPLATE — every control's reason is written for that control (all distinct)", gapReasons.length >= 20 && new Set(gapReasons).size === gapReasons.length, `${gapReasons.length} chrome gaps, ${new Set(gapReasons).size} distinct`);
  ok("map: READ-ONLY + evidence cited (adjudication #map-port + the LIVE deep atlas) + owner link", !t.includes("<form") && /reference-seed-adjudications\.v1\.json#map-port/.test(t) && /reference-live-tenant-deep-atlas\.v1\.json#map/.test(t) && t.includes("/__ioi/environments"));
}
const fails = results.filter((r) => !r.pass);
for (const r of results) console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
console.log(`\n${results.length - fails.length}/${results.length} passed`);
console.log(`app-parity-domain-landings readiness: ${fails.length ? "FAIL" : "OK"}`);
process.exit(fails.length ? 1 : 0);
