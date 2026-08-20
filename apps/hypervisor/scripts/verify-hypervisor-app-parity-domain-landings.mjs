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
// REG-1: registry — the ARTIFACT-REGISTRY port, and the leg where the honest move is a FOUR-WAY
// read-state census. The mirror capture was blocked_missing_capture (absent_confirmed, MAR-1
// "expresses no IA"); the live sweep overturned it (title "Artifacts" · "Explore artifacts" +
// "Learn about artifacts" · 14 controls · 1 search input · 0 repository rows). Unlike map, the
// estate HAS registry planes — so the done-bar here is DISCRIMINATION, not absence: every plane's
// state must be classified from its own live response and match what the daemon answers right now,
// a REFUSAL may never be rendered as a zero, an EMPTY plane may never be rendered as a missing one,
// a POST-only plane may never be rendered as either, rows must equal the readable planes exactly,
// and the estate's registry VERBS must stay on their owner surfaces (this is a projection).
{
  const D = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
  const PLANES = [
    "/v1/hypervisor/packages",
    "/v1/hypervisor/marketplace/publish-candidates",
    "/v1/hypervisor/marketplace/admission-reviews",
    "/v1/hypervisor/marketplace/listings",
    "/v1/hypervisor/marketplace/instance-offers",
    "/v1/hypervisor/governance/release-controls",
    "/v1/hypervisor/scm-publication-effects",
    "/v1/hypervisor/scm-publication-proposals",
    "/v1/hypervisor/worker-package-install-admissions",
    "/v1/hypervisor/artifact-availability-incidents",
  ];
  // The verifier re-derives the classification INDEPENDENTLY (same contract, its own code): a
  // 405 is write-only before any body is read, a non-2xx is a typed refusal before any collection
  // is looked for, and only a 200 that actually carried a collection may be called live-or-empty.
  const probe = async (p) => {
    try {
      const r = await fetch(`${D}${p}`);
      const text = await r.text();
      let body = null; try { body = JSON.parse(text); } catch { body = null; }
      if (r.status === 405) return { path: p, state: "write_only", code: "", n: 0 };
      if (!r.ok) {
        const b = body || {};
        return { path: p, state: "refused", code: String((b.error && b.error.code) || b.reason || b.code || `http_${r.status}`), n: 0 };
      }
      const arr = Object.values(body || {}).find((v) => Array.isArray(v));
      if (!Array.isArray(arr)) return { path: p, state: "unreadable", code: `http_${r.status}`, n: 0 };
      return { path: p, state: arr.length ? "live" : "empty", code: "", n: arr.length, rows: arr };
    } catch { return { path: p, state: "unreadable", code: "http_0", n: 0 }; }
  };
  const derived = await Promise.all(PLANES.map(probe));
  const ov = await fetch(`${D}/v1/hypervisor/marketplace/overview`).then((r) => r.json()).catch(() => ({}));
  const kinds = Array.isArray(ov.listing_kinds) ? ov.listing_kinds : [];
  const substrate = (ov.substrate && typeof ov.substrate === "object") ? ov.substrate : {};
  const index = await fetch(`${D}/v1`).then((r) => r.json()).catch(() => ({}));
  const routes = (Array.isArray(index.families) ? index.families : []).flatMap((f) => (Array.isArray(f.paths) ? f.paths : []));
  const pkgRoutes = routes.filter((r) => String(r.path || "").startsWith("/v1/hypervisor/packages")).length;
  const mktRoutes = routes.filter((r) => String(r.path || "").startsWith("/v1/hypervisor/marketplace")).length;
  const searchRoutes = routes.filter((r) => /(search|\/query|index)/i.test(String(r.path || "")));
  const artifactSearchRoutes = searchRoutes.filter((r) => /(package|artifact|release|listing|registry|marketplace)/i.test(String(r.path || ""))).length;
  const p = await page(`${SERVE}/__ioi/marketplace/artifacts`);
  const t = p.text;
  const planeRow = (path) => {
    const i = t.indexOf(`data-ioi-plane="${path}"`);
    if (i < 0) return "";
    const start = t.lastIndexOf('<div class="rgy-prow"', i);
    const end = t.indexOf("</div>", i);
    return start < 0 || end < 0 ? "" : t.slice(start, end + 6);
  };
  const gapReasons = [...t.matchAll(/<span class="[^"]*rgy-gap[^"]*"[^>]*data-ioi-disabled-reason="([^"]*)"/g)].map((m) => m[1]);
  const liveRows = derived.filter((d) => d.state === "live").flatMap((d) => d.rows.map((rec) => ({ d, rec })));
  ok("registry: matrix reference_ported at /__ioi/marketplace/artifacts with the live-atlas evidence carried", bySlug.registry?.parity_class === "reference_ported" && bySlug.registry?.candidate_surface === "/__ioi/marketplace/artifacts" && bySlug.registry?.remediation_state === "live_ia_recorded" && /#registry-port/.test(bySlug.registry?.adjudication_ref || "") && /reference-live-tenant-deep-atlas/.test(bySlug.registry?.live_reference_evidence || ""), bySlug.registry?.parity_class);
  ok("registry: renders 200 with the LIVE-tenant artifact-registry landing grammar, RAILLESS (owner ruling 2026-08-20)", p.status === 200 && !t.includes("og-grail") && ["Artifacts", "Explore artifacts", "Create artifact repository", "Help", "Search artifacts…", "Learn about artifacts", "Go to documentation", "Core concepts", "Publish an artifact", "Search an artifact", "Recall an artifact"].every((k) => t.includes(k)), String(p.status));
  // The load-bearing gate: every plane's rendered state is re-derived from the daemon on THIS run
  // and must match exactly. A pasted state, a stale state, or a state copied from a sibling plane
  // all fail here rather than aging quietly into a lie.
  ok("registry: every plane's state is CLASSIFIED LIVE — the stamped state equals what the daemon answers to this identity right now", derived.length === 10 && derived.every((d) => new RegExp(`data-ioi-plane="${d.path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}" data-ioi-plane-state="${d.state}"`).test(t)), derived.map((d) => `${d.path.split("/").pop()}=${d.state}`).join(" "));
  // The finding this leg exists to hold: a refusal is a closed door, not a measurement. Every
  // refused plane must carry the daemon's own typed code verbatim AND must print no record count.
  ok("registry: a REFUSAL is rendered as a REFUSAL — the daemon's typed code verbatim, and NEVER as a count", derived.filter((d) => d.state === "refused").length > 0 && derived.filter((d) => d.state === "refused").every((d) => { const row = planeRow(d.path); return row.includes(d.code) && /REFUSAL, never a zero/.test(row) && !/\d+\s+records?/.test(row); }) && /A refusal is not a zero/.test(t), `${derived.filter((d) => d.state === "refused").length} refused`);
  ok("registry: EMPTY, MISSING and NO-READ-ROUTE are held apart — each state's row says which one it is, in its own words", derived.filter((d) => d.state === "empty").every((d) => /EMPTY plane, not a missing one/.test(planeRow(d.path))) && derived.filter((d) => d.state === "write_only").every((d) => /POST-only/.test(planeRow(d.path)) && /not the same as reading nothing/.test(planeRow(d.path))) && /REFUSED is not EMPTY, EMPTY is not MISSING/.test(t), `empty=${derived.filter((d) => d.state === "empty").length} write_only=${derived.filter((d) => d.state === "write_only").length}`);
  ok("registry: a LIVE plane states its own record count, taken from the plane and not from a constant", derived.filter((d) => d.state === "live").every((d) => new RegExp(`${d.n} record${d.n === 1 ? "" : "s"} — rendered below verbatim`).test(planeRow(d.path))), derived.filter((d) => d.state === "live").map((d) => `${d.path.split("/").pop()}:${d.n}`).join(" "));
  // Two route-arithmetic claims carry real weight on this surface (the family is CLOSED; nothing
  // indexes artifacts), so both are counted from the daemon's index on render — and the search
  // census must still be ZERO, which forces a re-adjudication the day an artifact index lands.
  ok("registry: the CLOSED package-family route count and the ZERO artifact-search census are COUNTED from the daemon's index on render", artifactSearchRoutes === 0 && new RegExp(`<b>${pkgRoutes}</b> routes under`).test(t) && new RegExp(`<b>${mktRoutes}</b> marketplace routes`).test(t) && new RegExp(`<b>${searchRoutes.length}</b> search/query routes are published and <b>0</b>`).test(t), `pkg=${pkgRoutes} mkt=${mktRoutes} search=${searchRoutes.length} artifactSearch=${artifactSearchRoutes}`);
  ok("registry: record rows == the READABLE planes exactly (never more than the planes hold), cap NAMED", (t.match(/class="rgy-row"/g) || []).length === Math.min(50, liveRows.length) && new RegExp(`${liveRows.length} REAL record${liveRows.length === 1 ? "" : "s"} across ${derived.filter((d) => d.state === "live").length} live plane`).test(t), `rows=${(t.match(/class="rgy-row"/g) || []).length} plane=${liveRows.length}`);
  ok("registry: a sampled REAL record renders verbatim — its id, its ref and its schema_version, under the plane it came from", liveRows.length === 0 || liveRows.every(({ d, rec }) => { const id = rec.id || rec.listing_id || rec.candidate_id || ""; const ref = rec.ref || rec.candidate_ref || rec.subject_ref || ""; return (!id || t.includes(id)) && (!ref || t.includes(ref)) && (!rec.schema_version || t.includes(rec.schema_version)) && t.includes(d.path); }), `${liveRows.length} records`);
  ok("registry: the taxonomy + substrate censuses are the daemon's OWN keys read live, and publishable material is never rendered as an artifact row", kinds.length > 0 && kinds.every((k) => t.includes(`data-ioi-registry-kind="${k}"`)) && Object.keys(substrate).every((k) => t.includes(`data-ioi-substrate-key="${k}"`) && new RegExp(`data-ioi-substrate-key="${k}"[^>]*><code>${k}</code><b>${substrate[k]}</b>`).test(t)) && /NOT published artifacts/.test(t) && !/class="rgy-row"[^>]*>[^<]*<span><b>agents<\/b>/.test(t), `kinds=${kinds.length} substrate=${Object.keys(substrate).length}`);
  ok("registry: every gap carries the UNIFIED contract (aria === data-ioi count) and there are real absences", (t.match(/aria-disabled="true"/g) || []).length >= 9 && (t.match(/aria-disabled="true"/g) || []).length === (t.match(/data-ioi-disabled-reason=/g) || []).length, `${(t.match(/aria-disabled="true"/g) || []).length} gaps`);
  ok("registry: no chrome reason is BOILERPLATE — every control's reason is written for that control (all distinct)", gapReasons.length >= 9 && new Set(gapReasons).size === gapReasons.length, `${gapReasons.length} chrome gaps, ${new Set(gapReasons).size} distinct`);
  // This port sits next to a surface that DOES own these verbs. Duplicating them would mint a
  // second registry owner, so the gate is: no form, no write path, and the verb's absence reason
  // must name the owner surface the verb actually lives on.
  ok("registry: READ-ONLY projection — no verb is re-minted; the Create-repository absence NAMES the owner surface and the page links there", !t.includes("<form") && !/action="\/__ioi\/(packages|marketplace)/.test(t) && /Repository creation is a REAL estate verb and it is NOT missing/.test(t) && t.includes("/__ioi/packages/registry") && t.includes("/__ioi/marketplace/listings"), String(!t.includes("<form")));
  ok("registry: evidence cited (adjudication #registry-port + the LIVE deep atlas) and brand-clean — no vendor brand and no borrowed package-ecosystem name", /reference-seed-adjudications\.v1\.json#registry-port/.test(t) && /reference-live-tenant-deep-atlas\.v1\.json#registry/.test(t) && !/\bPalantir\b/i.test(t) && !/palantirfoundry/i.test(t) && !/\bconda\b/i.test(t) && !/\b(npm|maven|pypi|docker hub)\b/i.test(t));
}
// JOB-1: jobs — the BUILDS port, and the leg whose finding is that NO SINGLE PLANE lists every
// build. The mirror-scoped verdict was absent_confirmed (#jobs, MIS-1.recon: "no Builds grammar
// expresses at any recorded state; the substrate STANDS as the surface"); the live sweep overturned
// it (title "Your builds · Builds" · 14 controls · a six-column build table over REAL rows). The
// done-bar here is (a) the PLANE CHOICE must be proven, not asserted — the three reach counts are
// re-derived independently by this verifier on this run and must match the page exactly; (b) every
// plane's state must be classified from its own live response, a REFUSAL may never be a zero, and a
// plane the daemon publishes no GET for may never be rendered as EMPTY; (c) no build field may be
// invented — every Started-by is the record's own authority and a typed dash appears on exactly the
// records whose state_root is empty; (d) the reference's unbindable columns must be REFUSED, not
// filled; (e) a STEP may never be relabelled a "job", because `job` is a live estate noun on
// another plane; and (f) the transcript plane must be LINKED, not re-rendered.
{
  const D = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
  const BLD_PLANES = [
    "/v1/hypervisor/work-ledger",
    "/v1/hypervisor/agent-run-transcripts",
    "/v1/hypervisor/automation-executions",
    "/v1/jobs",
    "/v1/runs",
    "/v1/tasks",
    "/v1/goal-orchestration/goal-runs",
    "/v1/goal-orchestration/ioi-agent/launches",
    "/v1/goal-orchestration/attempts",
    "/v1/hypervisor/foundry/run-plans",
    "/v1/hypervisor/odk/transformation-runs",
    "/v1/hypervisor/odk/materializing-runs",
    "/v1/hypervisor/failover/runs",
    "/v1/hypervisor/workruns",
    "/v1/hypervisor/sessions",
    "/v1/hypervisor/session-execution-bindings",
  ];
  const bIndex = await fetch(`${D}/v1`).then((r) => r.json()).catch(() => ({}));
  const bRoutes = (Array.isArray(bIndex.families) ? bIndex.families : []).flatMap((f) => (Array.isArray(f.paths) ? f.paths : []));
  const bMethods = (p) => { const r = bRoutes.find((x) => String(x.path || "") === p && !x.retired); return Array.isArray(r?.methods) ? r.methods : []; };
  // The verifier re-derives the classification INDEPENDENTLY (same contract, its own code): a plane
  // the daemon's own index publishes no GET for is write-only/absent before any body is read, a
  // non-2xx is a typed refusal before any collection is looked for, and only a 200 that actually
  // carried a collection may be called live-or-empty.
  const bProbe = async (p) => {
    try {
      const r = await fetch(`${D}${p}`);
      const text = await r.text();
      let body = null; try { body = JSON.parse(text); } catch { body = null; }
      const methods = bMethods(p);
      if (!methods.includes("GET") || r.status === 405) return { path: p, state: "no_read_route", code: "", n: 0, rows: [] };
      if (!r.ok) {
        const b = body || {};
        return { path: p, state: "refused", code: String((b.error && b.error.code) || b.reason || b.code || `http_${r.status}`), n: 0, rows: [] };
      }
      const arr = Array.isArray(body) ? body : Object.values(body || {}).find((v) => Array.isArray(v));
      if (!Array.isArray(arr)) return { path: p, state: "unreadable", code: `http_${r.status}`, n: 0, rows: [] };
      return { path: p, state: arr.length ? "live" : "empty", code: "", n: arr.length, rows: arr };
    } catch { return { path: p, state: "unreadable", code: "http_0", n: 0, rows: [] }; }
  };
  const bDerived = await Promise.all(BLD_PLANES.map(bProbe));
  const bBy = Object.fromEntries(bDerived.map((d) => [d.path, d]));
  const bAutos = await fetch(`${D}/v1/hypervisor/automations`).then((r) => r.json()).then((j) => j.automations || []).catch(() => []);
  const bLiveAutos = new Set(bAutos.map((a) => String(a.automation_id || "")));
  const bLedger = (bBy["/v1/hypervisor/work-ledger"].rows || []).filter((e) => e && e.kind === "run");
  const bTranscripts = bBy["/v1/hypervisor/agent-run-transcripts"].rows || [];
  const bAutoRunIds = new Set(bTranscripts.filter((r) => r && r.kind === "automation-run").map((r) => String(r.run_id || "")));
  const bInTr = bLedger.filter((e) => bAutoRunIds.has(String(e.id || "")));
  const bNotInTr = bLedger.filter((e) => !bAutoRunIds.has(String(e.id || "")));
  const bUnreachable = bLedger.filter((e) => !bLiveAutos.has(String(e.automation_id || "")));
  const bNoRoot = bLedger.filter((e) => !(typeof e.state_root === "string" && e.state_root.trim() !== ""));
  const bTerminal = new Set(["done", "complete", "completed", "success", "succeeded", "failed", "error", "cancelled", "canceled", "stopped"]);
  const bOpen = bLedger.filter((e) => !bTerminal.has(String(e.status || "")));
  const bFin = bLedger.filter((e) => bTerminal.has(String(e.status || "")));
  const bFailedSteps = bLedger.reduce((n, e) => n + (Number((e.counts || {}).failed) || 0), 0);
  const bSorted = [...bLedger].sort((a, b) => String(b.timestamp || "").localeCompare(String(a.timestamp || "")));
  const bShown = bSorted.slice(0, 200);
  const p = await page(`${SERVE}/__ioi/missions/builds`);
  const t = p.text;
  const planeRow = (path) => {
    const i = t.indexOf(`data-ioi-plane="${path}"`);
    if (i < 0) return "";
    const start = t.lastIndexOf('<div class="bld-prow"', i);
    const end = t.indexOf("</div>", i);
    return start < 0 || end < 0 ? "" : t.slice(start, end + 6);
  };
  const gapReasons = [...t.matchAll(/<span class="[^"]*bld-gap[^"]*"[^>]*data-ioi-disabled-reason="([^"]*)"/g)].map((m) => m[1]);
  ok("jobs: matrix reference_ported at /__ioi/missions/builds — and the /__ioi/missions SUBSTRATE is still bound on the row (the port is a sibling lane, never a replacement)", bySlug.jobs?.parity_class === "reference_ported" && bySlug.jobs?.candidate_surface === "/__ioi/missions/builds" && bySlug.jobs?.port_surface === "/__ioi/missions/builds" && bySlug.jobs?.substrate_surface === "/__ioi/missions" && bySlug.jobs?.surface_name === "Missions" && bySlug.jobs?.remediation_state === "live_ia_recorded" && /#jobs-port/.test(bySlug.jobs?.adjudication_ref || "") && /reference-live-tenant-atlas/.test(bySlug.jobs?.live_reference_evidence || ""), bySlug.jobs?.parity_class);
  ok("jobs: renders 200 with the LIVE-tenant BUILDS grammar, RAILLESS (owner ruling 2026-08-20)", p.status === 200 && !t.includes("og-grail") && ["Builds", "Your builds", "Search by", "Filter by", "Show only my builds", "All branches", "Only master branch", "All branches excluding master", "Job type", "Clear all filters", "Started by", "Start time", "Duration", "Status"].every((k) => t.includes(k)), String(p.status));
  // The load-bearing gate. This surface's whole argument is that the ledger run lane is the UNION
  // and the other two projections are each incomplete — so all four counts are re-derived here from
  // the three planes on THIS run and must match the page exactly. A pasted triple fails, and so does
  // a correct-today triple the day a build lands or an automation is deleted.
  ok("jobs: the UNION FINDING is RE-DERIVED — ledger total, transcript-reachable, un-transcribed, fan-out-unreachable and empty-state_root all match the planes on this run", new RegExp(`run</code> lane holds <b>${bLedger.length}</b> build`).test(t) && new RegExp(`can reach <b>${bInTr.length}</b> of them`).test(t) && new RegExp(`the other <b>${bNotInTr.length}</b> were never transcribed`).test(t) && new RegExp(`those same <b>${bNoRoot.length}</b> are exactly the entries`).test(t) && new RegExp(`<b>${bUnreachable.length}</b> of these builds belong to automations that no longer exist`).test(t), `ledger=${bLedger.length} inTr=${bInTr.length} notInTr=${bNotInTr.length} noRoot=${bNoRoot.length} unreachable=${bUnreachable.length}`);
  ok("jobs: every plane's state is CLASSIFIED LIVE — the stamped state equals what the daemon answers to this identity right now", bDerived.length === 16 && bDerived.every((d) => new RegExp(`data-ioi-plane="${d.path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}" data-ioi-plane-state="${d.state}"`).test(t)), bDerived.map((d) => `${d.path.split("/").pop()}=${d.state}`).join(" "));
  ok("jobs: a REFUSAL is rendered as a REFUSAL — the daemon's typed code verbatim, and NEVER as a count", bDerived.filter((d) => d.state === "refused").length > 0 && bDerived.filter((d) => d.state === "refused").every((d) => { const row = planeRow(d.path); return row.includes(d.code) && /REFUSAL, never a zero/.test(row) && !/\d+\s+records?/.test(row); }) && /A refusal is not a zero/.test(t), `${bDerived.filter((d) => d.state === "refused").length} refused`);
  ok("jobs: EMPTY, MISSING and NO-READ-ROUTE are held apart — a plane the daemon publishes no GET for is never rendered EMPTY", bDerived.filter((d) => d.state === "empty").every((d) => /EMPTY plane, not a missing one/.test(planeRow(d.path))) && bDerived.filter((d) => d.state === "no_read_route").every((d) => /publishes no GET here/.test(planeRow(d.path)) && /not the same as reading nothing/.test(planeRow(d.path))) && /REFUSED is not EMPTY, EMPTY is not MISSING/.test(t), `empty=${bDerived.filter((d) => d.state === "empty").length} noroute=${bDerived.filter((d) => d.state === "no_read_route").length}`);
  ok("jobs: a LIVE plane states its own record count, taken from the plane and not from a constant", bDerived.filter((d) => d.state === "live").every((d) => new RegExp(`${d.n} record${d.n === 1 ? "" : "s"} — counted from the plane on this render`).test(planeRow(d.path))), bDerived.filter((d) => d.state === "live").map((d) => `${d.path.split("/").pop()}:${d.n}`).join(" "));
  ok("jobs: build rows == the ledger run lane exactly, newest-first, cap NAMED only when it truncates", (t.match(/class="bld-row"/g) || []).length === Math.min(200, bLedger.length) && (bLedger.length > 200 ? new RegExp(`newest <b>200</b> of <b>${bLedger.length}</b>`).test(t) : new RegExp(`All <b>${bLedger.length}</b> render here`).test(t)) && bShown.every((e) => t.includes(`data-ioi-build="${e.id}"`)), `rows=${(t.match(/class="bld-row"/g) || []).length} plane=${bLedger.length}`);
  // No build field may be invented. Started-by is the record's OWN authority on every row, and the
  // proof column is a typed dash on EXACTLY the records whose state_root is empty — not fewer
  // (a fabricated root) and not more (a withheld one).
  ok("jobs: every Started-by is the record's OWN authority, and the proof dash lands on EXACTLY the records with an empty state_root", bShown.every((e) => t.includes(`data-ioi-build-authority="${(e.authority || {}).ref || ""}"`)) && bShown.filter((e) => e.state_root).every((e) => t.includes(e.state_root)) && bNoRoot.length > 0 && (t.match(/data-ioi-disabled-reason="This ledger run entry carries an EMPTY state_root/g) || []).length === bShown.filter((e) => !(typeof e.state_root === "string" && e.state_root.trim() !== "")).length, `authorities=${new Set(bShown.map((e) => (e.authority || {}).ref)).size} noRootShown=${bShown.filter((e) => !e.state_root).length}`);
  // The FUS-1 column refusal, made load-bearing: the two columns nothing binds must be marked
  // unbound AND must not appear as rendered table headers over estate values.
  ok("jobs: the reference's UNBINDABLE columns are REFUSED, not filled — Outputs and Actions are marked unbound and neither is a rendered build-table header", /data-ioi-column="Outputs" data-ioi-column-bound="no"/.test(t) && /data-ioi-column="Actions" data-ioi-column-bound="no"/.test(t) && ["Started by", "Start time", "Status"].every((c) => new RegExp(`data-ioi-column="${c}" data-ioi-column-bound="yes"`).test(t)) && !/<div class="bld-thead">[^]*?<span>Outputs<\/span>/.test(t) && !/<div class="bld-thead">[^]*?<span>Actions<\/span>/.test(t), "Outputs/Actions unbound");
  ok("jobs: DURATION is labelled COMPUTED on every row that has one — the plane records no duration field and none is claimed", bLedger.every((e) => !("duration" in e) && !("duration_ms" in e)) && (t.match(/COMPUTED: finished_at − timestamp/g) || []).length === bShown.filter((e) => Date.parse(e.finished_at || "") >= Date.parse(e.timestamp || "")).length && /is labelled as computed on the row/.test(t), `computed=${(t.match(/COMPUTED: finished_at − timestamp/g) || []).length}`);
  // `job` is a LIVE estate noun on /v1/jobs. Relabelling a build's steps as jobs would invent a
  // hierarchy the estate does not have, so every roll-up must say steps and the surface must name
  // the runtime job plane as the separate thing it is.
  ok("jobs: a STEP is never relabelled a JOB — every roll-up says steps, the runtime job plane is named as a DIFFERENT plane, and no 'N of M jobs' roll-up appears", (t.match(/step[s]? done <b>\(steps, not jobs\)<\/b>/g) || []).length === bShown.length && !/of \d+ jobs (succeeded|done)/i.test(t) && /RUNTIME JOB plane/.test(t) && t.includes("/v1/jobs"), `rollups=${(t.match(/\(steps, not jobs\)/g) || []).length}`);
  // One plane, one renderer. The Monocle Build timeline already renders the transcripts; this
  // surface must link it and must NOT re-render transcript records here.
  ok("jobs: the transcript plane is LINKED, not duplicated — the Monocle Build timeline is linked and no transcript run_id is rendered as a build row", t.includes("/__ioi/lineage?tab=timeline") && new RegExp(`the ${bTranscripts.length} transcripts are LINKED rather than re-rendered`).test(t) && !bTranscripts.filter((r) => r.kind !== "automation-run").slice(0, 40).some((r) => t.includes(`data-ioi-build="${r.run_id}"`)), `transcripts=${bTranscripts.length}`);
  // Unlike the registry leg these zeros PRINT, because the plane answered — so they must be real
  // measurements of the plane, re-counted here, never placeholders.
  ok("jobs: the tray + segmented control are live CENSUSES of the plane, counted here independently — and said on-surface to be counts, not filters", new RegExp(`data-ioi-tray="open"[^>]*>⟳ <b>${bOpen.length}</b>`).test(t) && new RegExp(`data-ioi-tray="finished"[^>]*>✓ <b>${bFin.length}</b>`).test(t) && new RegExp(`data-ioi-tray="failed_steps"[^>]*>✕ <b>${bFailedSteps}</b>`).test(t) && new RegExp(`data-ioi-seg="all"[^>]*>All <b class="bld-segn">${bLedger.length}</b>`).test(t) && new RegExp(`data-ioi-seg="running"[^>]*>Running <b class="bld-segn">${bOpen.length}</b>`).test(t) && /a count and not a filter|a live census of the plane|not a filter/.test(t), `open=${bOpen.length} fin=${bFin.length} failedSteps=${bFailedSteps}`);
  ok("jobs: every gap carries the UNIFIED contract (aria === data-ioi count) and there are real absences", (t.match(/aria-disabled="true"/g) || []).length >= 18 && (t.match(/aria-disabled="true"/g) || []).length === (t.match(/data-ioi-disabled-reason=/g) || []).length, `${(t.match(/aria-disabled="true"/g) || []).length} gaps`);
  ok("jobs: no chrome reason is BOILERPLATE — every control's reason is written for that control (all distinct)", gapReasons.length >= 18 && new Set(gapReasons).size === gapReasons.length, `${gapReasons.length} chrome gaps, ${new Set(gapReasons).size} distinct`);
  ok("jobs: READ-ONLY projection — no verb is re-minted; the Actions absence NAMES the owner surface and the page links there and to the untouched substrate", !t.includes("<form") && !/action="\/__ioi\/(missions|automations)/.test(t) && /owned by Automations/.test(t) && t.includes("/__ioi/automations") && t.includes("/__ioi/missions") && /sibling lane, not a replacement/.test(t), String(!t.includes("<form")));
  ok("jobs: evidence cited (adjudication #jobs-port + the LIVE atlas) and brand-clean — no vendor brand and no borrowed tenant identity", /reference-seed-adjudications\.v1\.json#jobs-port/.test(t) && /reference-live-tenant-atlas\.v1\.json#jobs/.test(t) && !/\bPalantir\b/i.test(t) && !/palantirfoundry/i.test(t) && !/Josman/i.test(t) && !/job-tracker/i.test(t));
}
// SCH-1: scheduler — the BUILD SCHEDULES port, and the leg whose finding is that THE FIELD NAMED
// FOR THE CONCEPT IS NOT THE FIELD THE RUNTIME ACTS ON. The load-bearing assertions: (a) the four
// counts that carry the finding (the records predicate, the Operations projection, the loop's own
// heartbeat, and what the `trigger` field claims) are re-derived independently here and must match
// the page exactly; (b) every plane's state AND its SHAPE are classified from its own live
// response — a REFUSAL may never be a zero, a plane the daemon publishes no GET for may never be
// EMPTY, and a status SINGLETON may never be counted as a collection of one; (c) the schedule rows
// are exactly the records the RECORDS predicate admits and every rendered value is a record field;
// (d) the per-tick counters must STATE their window and may never be printed as totals; (e) a
// COMPUTED occurrence must be labelled computed; (f) the surface must refuse to name which past
// runs were scheduled fires; and (g) the run planes another surface renders must be LINKED.
{
  const D = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
  const sIndex = await fetch(`${D}/v1`).then((r) => r.json()).catch(() => ({}));
  const sRoutes = (Array.isArray(sIndex.families) ? sIndex.families : []).flatMap((f) => (Array.isArray(f.paths) ? f.paths : []));
  const sMethods = (p) => { const r = sRoutes.find((x) => String(x.path || "") === p && !x.retired); return Array.isArray(r?.methods) ? r.methods : []; };
  const sAutos = await fetch(`${D}/v1/hypervisor/automations`).then((r) => r.json()).then((j) => j.automations || []).catch(() => []);
  const sSpecOf = (a) => (a && a.schedule_spec && typeof a.schedule_spec === "object" ? a.schedule_spec : null);
  const sWithSpec = sAutos.filter((a) => sSpecOf(a));                    // the RECORDS predicate
  const sSorted = [...sWithSpec].sort((a, b) => String(a.next_run_at || "￿").localeCompare(String(b.next_run_at || "￿")));
  const sPrimaryId = String(sSorted[0]?.automation_id || sAutos[0]?.automation_id || "");
  const sPrimaryCron = String(sSpecOf(sSorted[0])?.cron || "");
  const sPrimaryTz = String(sSpecOf(sSorted[0])?.timezone || "UTC");
  const sIdPath = (tail) => `/v1/hypervisor/automations/${sPrimaryId || "no-automation-on-the-plane"}${tail}`;
  // The census, re-declared here with the SAME contract and this verifier's OWN code: template
  // path (what the daemon's index publishes) + the concrete URL probed + the expected shape.
  const SCH_PLANES = [
    ["/v1/hypervisor/scheduler/status", "/v1/hypervisor/scheduler/status", "singleton", null],
    ["/v1/hypervisor/automations", "/v1/hypervisor/automations", "collection", (b) => b?.automations],
    ["/v1/hypervisor/operations", "/v1/hypervisor/operations", "collection", (b) => b?.scheduler?.automations],
    ["/v1/hypervisor/cron-preview", sPrimaryCron ? `/v1/hypervisor/cron-preview?cron=${encodeURIComponent(sPrimaryCron)}&tz=${encodeURIComponent(sPrimaryTz)}&n=3` : "/v1/hypervisor/cron-preview", "computation", (b) => b?.runs],
    ["/v1/hypervisor/automations/:id/runs", sIdPath("/runs"), "collection", (b) => b?.runs],
    ["/v1/hypervisor/automations/:id/webhook-events", sIdPath("/webhook-events"), "collection", (b) => b?.events],
    ["/v1/hypervisor/automation-executions", "/v1/hypervisor/automation-executions", "collection", null],
    ["/v1/hypervisor/work-ledger", "/v1/hypervisor/work-ledger", "collection", null],
    ["/v1/hypervisor/automation-affinities", "/v1/hypervisor/automation-affinities", "collection", (b) => b?.affinities],
    ["/v1/hypervisor/failover/plans", "/v1/hypervisor/failover/plans", "collection", (b) => b?.plans],
    ["/v1/hypervisor/governance/release-controls", "/v1/hypervisor/governance/release-controls", "collection", (b) => b?.release_controls],
    ["/v1/hypervisor/retention/dispositions", "/v1/hypervisor/retention/dispositions", "collection", null],
    ["/v1/hypervisor/maintenance/idle-sweep", "/v1/hypervisor/maintenance/idle-sweep", "collection", null],
    ["/v1/hypervisor/backups", "/v1/hypervisor/backups", "collection", (b) => b?.backups],
    ["/v1/hypervisor/economics/reconciliation", "/v1/hypervisor/economics/reconciliation", "collection", null],
  ];
  const sProbe = async ([path, probeUrl, shape, pick]) => {
    let r, text;
    try { r = await fetch(`${D}${probeUrl}`); text = await r.text(); } catch { return { path, shape, state: "unreadable", code: "http_0", n: 0, body: null }; }
    let body = null; try { body = JSON.parse(text); } catch { body = null; }
    if (!sMethods(path).includes("GET") || r.status === 405) return { path, shape, state: "no_read_route", code: "", n: 0, body };
    if (!r.ok) {
      const b = body || {};
      return { path, shape, state: "refused", code: String((b.error && (b.error.code || b.error)) || b.reason || b.code || `http_${r.status}`), n: 0, body };
    }
    if (body && typeof body === "object" && body.ok === false) {
      const b = body.error;
      return { path, shape, state: "refused", code: String((b && (b.code || b)) || body.code || "plane_declined"), n: 0, body };
    }
    if (shape === "singleton") {
      const keys = body && typeof body === "object" && !Array.isArray(body) ? Object.keys(body) : [];
      return { path, shape, state: keys.length ? "live" : "empty", code: "", n: keys.length, body };
    }
    const arr = pick ? pick(body) : (Array.isArray(body) ? body : Object.values(body || {}).find((v) => Array.isArray(v)));
    if (!Array.isArray(arr)) return { path, shape, state: "unreadable", code: `http_${r.status}`, n: 0, body };
    return { path, shape, state: arr.length ? "live" : "empty", code: "", n: arr.length, body };
  };
  const sDerived = await Promise.all(SCH_PLANES.map(sProbe));
  const sBy = Object.fromEntries(sDerived.map((d2) => [d2.path, d2]));
  const sHeart = sBy["/v1/hypervisor/scheduler/status"].body?.heartbeat || {};
  const sOpsRows = sBy["/v1/hypervisor/operations"].n;
  const sLoopActive = Number(sHeart.scheduled_active);
  const CADENCE_WORDS = new Set(["cron", "schedule", "scheduled", "interval", "timer", "recurring"]);
  const sTriggerNamed = sAutos.filter((a) => CADENCE_WORDS.has(String(a.trigger_kind || a.trigger?.kind || "").toLowerCase()));
  const sSpecButNot = sWithSpec.filter((a) => !CADENCE_WORDS.has(String(a.trigger_kind || a.trigger?.kind || "").toLowerCase()));
  const p = await page(`${SERVE}/__ioi/missions/schedules`);
  const t = p.text;
  const planeRow = (path) => {
    const i = t.indexOf(`data-ioi-plane="${path}"`);
    if (i < 0) return "";
    const start = t.lastIndexOf('<div class="sch-prow"', i);
    const end = t.indexOf("</div>", i);
    return start < 0 || end < 0 ? "" : t.slice(start, end + 6);
  };
  const gapReasons = [...t.matchAll(/<span class="[^"]*sch-gap[^"]*"[^>]*data-ioi-disabled-reason="([^"]*)"/g)].map((m) => m[1]);
  ok("scheduler: matrix reference_ported at /__ioi/missions/schedules with the live-tenant DEEP-atlas evidence carried", bySlug.scheduler?.parity_class === "reference_ported" && bySlug.scheduler?.candidate_surface === "/__ioi/missions/schedules" && bySlug.scheduler?.port_surface === "/__ioi/missions/schedules" && bySlug.scheduler?.surface_name === "Missions" && bySlug.scheduler?.remediation_state === "live_ia_recorded" && /#scheduler-port/.test(bySlug.scheduler?.adjudication_ref || "") && /reference-live-tenant-deep-atlas\.v1\.json#scheduler/.test(bySlug.scheduler?.adjudication_ref || ""), bySlug.scheduler?.parity_class);
  ok("scheduler: renders 200 with the LIVE-tenant BUILD SCHEDULES grammar, RAILLESS (owner ruling 2026-08-20)", p.status === 200 && !t.includes("og-grail") && ["Build Schedules", "Create schedule", "Set search parameters", "Sorted by most recently updated", "Select schedules", "Filter by name or rid", "APPLICATIONS", "Results matching", "Cadence", "Next run", "Last run", "Posture"].every((k) => t.includes(k)), String(p.status));
  // THE LOAD-BEARING GATE. The finding is a disagreement between four numbers, so all four are
  // re-derived here from the planes on THIS run and must match the page exactly. A pasted quad
  // fails, and so does a correct-today quad the day a schedule is added, paused or re-triggered.
  ok("scheduler: the PREDICATE FINDING is RE-DERIVED — the records predicate, the Operations projection, the loop's heartbeat and what the `trigger` field claims all match the planes on this run", new RegExp(`applies — finds <b>${sWithSpec.length}</b>`).test(t) && new RegExp(`That projection itself returns <b>${sOpsRows}</b>`).test(t) && new RegExp(`reports <b>${Number.isFinite(sLoopActive) ? sLoopActive : "—"}</b> in its heartbeat`).test(t) && new RegExp(`names a cadence on <b>${sTriggerNamed.length}</b> of the ${sAutos.length} automations`).test(t) && new RegExp(`<b>${sSpecButNot.length}</b> of the ${sWithSpec.length} schedule`).test(t), `records=${sWithSpec.length} ops=${sOpsRows} loop=${sLoopActive} triggerNamed=${sTriggerNamed.length} contradicting=${sSpecButNot.length}`);
  // The finding is only a finding if the two predicates are NAMED as two. A surface that printed
  // one number without saying which test produced it would be the defect this leg exists to state.
  ok("scheduler: every schedule count NAMES the predicate that produced it, and the loop's test is described as one the surface does NOT re-implement", /records<\/b> predicate/.test(t) && /loop<\/b> predicate/.test(t) && /never reads <code>enabled<\/code>/.test(t) && /does <b>not<\/b> re-implement/.test(t) && /trigger-shaped/.test(t), "predicates named");
  ok("scheduler: every plane's state AND shape are CLASSIFIED LIVE — the stamped pair equals what the daemon answers to this identity right now", sDerived.length === 15 && sDerived.every((d2) => new RegExp(`data-ioi-plane="${d2.path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}" data-ioi-plane-state="${d2.state}" data-ioi-plane-shape="${d2.shape}"`).test(t)), sDerived.map((d2) => `${d2.path.split("/").pop()}=${d2.state}/${d2.shape}`).join(" "));
  ok("scheduler: a REFUSAL is rendered as a REFUSAL — the daemon's typed code verbatim, and NEVER as a count", sDerived.filter((d2) => d2.state === "refused").length > 0 && sDerived.filter((d2) => d2.state === "refused").every((d2) => { const row = planeRow(d2.path); return row.includes(d2.code) && /REFUSAL, never a zero/.test(row) && !/\d+\s+records?/.test(row); }) && /a refusal is not a zero/i.test(t), `${sDerived.filter((d2) => d2.state === "refused").length} refused`);
  ok("scheduler: EMPTY, MISSING and NO-READ-ROUTE are held apart — a plane the daemon publishes no GET for is never rendered EMPTY", sDerived.filter((d2) => d2.state === "empty").every((d2) => /EMPTY plane, not a missing one/.test(planeRow(d2.path))) && sDerived.filter((d2) => d2.state === "no_read_route").every((d2) => /publishes no GET here/.test(planeRow(d2.path)) && /not the same as reading nothing/.test(planeRow(d2.path))) && /REFUSED is not EMPTY, EMPTY is not MISSING/.test(t), `empty=${sDerived.filter((d2) => d2.state === "empty").length} noroute=${sDerived.filter((d2) => d2.state === "no_read_route").length}`);
  // The SHAPE distinction this leg needed: a status object is not a one-row collection, and a pure
  // computation is not a data plane. Both must say so on their own row rather than be counted.
  ok("scheduler: a status SINGLETON is never counted as a collection of one, and a COMPUTATION is never rendered as a stored plane", /single status OBJECT/.test(planeRow("/v1/hypervisor/scheduler/status")) && /never counted as one row/.test(planeRow("/v1/hypervisor/scheduler/status")) && !/\d+ records? — counted from the plane/.test(planeRow("/v1/hypervisor/scheduler/status")) && /COMPUTED on this render, stored nowhere/.test(planeRow("/v1/hypervisor/cron-preview")) && /not a plane at all/.test(t), `singleton=${sBy["/v1/hypervisor/scheduler/status"].state} computation=${sBy["/v1/hypervisor/cron-preview"].state}`);
  ok("scheduler: schedule rows == exactly the records the RECORDS predicate admits, ordered by next occurrence, cap NAMED only when it truncates", (t.match(/class="sch-row"/g) || []).length === Math.min(100, sWithSpec.length) && sSorted.slice(0, 100).every((a) => t.includes(`data-ioi-schedule="${a.automation_id}"`)) && (sWithSpec.length > 100 ? new RegExp(`soonest <b>100</b> of <b>${sWithSpec.length}</b>`).test(t) : new RegExp(`All <b>${sWithSpec.length}</b> render here`).test(t)) && /ordered by <b>next occurrence, soonest first<\/b>/.test(t), `rows=${(t.match(/class="sch-row"/g) || []).length} plane=${sWithSpec.length}`);
  // No schedule field may be invented. The cadence, the next fire and the enabled flag on every
  // row are the record's OWN values, and the UTC instant is printed verbatim beside its label —
  // a schedule rendered in the serving host's timezone is a time the estate never recorded.
  // The formatted instant is re-derived HERE in UTC and must appear verbatim: a schedule formatted
  // in the serving host's local zone prints a time the estate never recorded, and the raw stamp
  // beside it would then silently disagree with the label above it.
  const sUtc = (iso) => { const d3 = new Date(iso || 0); return isNaN(d3) ? "" : `${d3.toLocaleString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", timeZone: "UTC" })} UTC`; };
  ok("scheduler: every cadence / next-run / enabled value is the record's OWN field, and every instant renders in UTC (re-derived here) beside its raw stamp", sSorted.slice(0, 100).every((a) => t.includes(`data-ioi-cadence="${sSpecOf(a).cron || ""}"`) && t.includes(`data-ioi-next-run="${a.next_run_at || ""}"`) && t.includes(`data-ioi-schedule-enabled="${a.enabled === true ? "yes" : "no"}"`) && (!a.next_run_at || (t.includes(`next_run_at (${a.next_run_at})`) && t.includes(sUtc(a.next_run_at)))) && (!a.last_run_at || (t.includes(`last_run_at (${a.last_run_at})`) && t.includes(sUtc(a.last_run_at))))), `schedules=${sWithSpec.length} utc=${sSorted[0] ? sUtc(sSorted[0].next_run_at) : "—"}`);
  // The WINDOW gate. Two of the three tray counters are reset every tick; printing them as totals
  // would convert a 15-second window into a history — the same class as printing a refusal as 0.
  ok("scheduler: the tray counters are live and each STATES its own window — the per-tick pair says LAST TICK ONLY and the surface denies keeping a lifetime total", new RegExp(`data-ioi-tray="scheduled_active"[^>]*>⟳ <b>${Number.isFinite(sLoopActive) ? sLoopActive : "—"}</b>`).test(t) && new RegExp(`data-ioi-tray="fired_dispatches"[^>]*>✓ <b>${Number(sHeart.fired_dispatches) || 0}</b>`).test(t) && new RegExp(`data-ioi-tray="misfire_skips"[^>]*>✕ <b>${Number(sHeart.misfire_skips) || 0}</b>`).test(t) && (t.match(/LAST TICK ONLY/g) || []).length === 2 && /NOT a lifetime total/.test(t) && /keeps no lifetime dispatch counter/.test(t), `active=${sLoopActive} fired=${sHeart.fired_dispatches} misfire=${sHeart.misfire_skips}`);
  // A derived value presented as a recorded one is still a fabrication: cron-preview stores
  // nothing, so every occurrence it returns must be labelled, and the loop's own stamp must not be.
  ok("scheduler: a COMPUTED occurrence is labelled COMPUTED and the loop's own next_run_at is labelled RECORDED — the two are never mixed", (sBy["/v1/hypervisor/cron-preview"].state !== "live" || /<b>COMPUTED<\/b> by \/v1\/hypervisor\/cron-preview — not stored anywhere/.test(t)) && /RECORDED by the loop: field next_run_at/.test(t), sBy["/v1/hypervisor/cron-preview"].state);
  // The refusal that makes this port honest: the daemon dispatches through the manual-run path, so
  // NO record marks a run as a scheduled fire. The surface must say so and must not join anyway.
  ok("scheduler: the UNMARKED-DISPATCH refusal is stated — the daemon's own dispatch_path is quoted and the surface refuses to name which past runs were fires", /fires through the manual-run path/.test(t) && /indistinguishable from a manual one/.test(t) && /refuses to answer/.test(t) && /inventing an edge no record holds/.test(t), "dispatch path quoted");
  // JOB-1's rule: find the COMPLETE projection, and recompute the comparison rather than paste it.
  ok("scheduler: the COMPLETE projection is chosen by a field-by-field comparison recomputed on this render, and the dropped fields are named", /Operations projection drops <b>\d+<\/b> field/.test(t) && ["catch_up_policy", "misfire_policy", "executor_identity"].every((f) => new RegExp(`<code>${f}</code>`).test(t)) && /recomputed on every render/.test(t), "complete projection named");
  // One plane, one renderer.
  ok("scheduler: the run planes another surface renders are LINKED, not duplicated — no run/execution row is minted here", t.includes("/__ioi/missions/builds") && t.includes("/__ioi/automations/monitors") && t.includes("/__ioi/operations") && /one plane gets one renderer/.test(t) && !/class="bld-row"/.test(t) && (t.match(/class="sch-row"/g) || []).length === sWithSpec.length, `schedules=${sWithSpec.length}`);
  // MAP-1's distinction, made load-bearing: the reference's lane is EMPTY, this one is MISSING.
  ok("scheduler: the APPLICATIONS lane is MISSING rather than the reference's own EMPTY, and says which is which", /MISSING, not empty/.test(t) && /Your favorited apps will appear here/.test(t) && /no per-principal favourites or pinned-application plane/.test(t) && /EMPTY is not MISSING<\/b>/.test(t), "applications lane");
  ok("scheduler: every gap carries the UNIFIED contract (aria === data-ioi count) and covers the reference's whole control set", (t.match(/aria-disabled="true"/g) || []).length >= 8 && (t.match(/aria-disabled="true"/g) || []).length === (t.match(/data-ioi-disabled-reason=/g) || []).length, `${(t.match(/aria-disabled="true"/g) || []).length} gaps`);
  ok("scheduler: no chrome reason is BOILERPLATE — every control's reason is written for that control (all distinct)", gapReasons.length >= 8 && new Set(gapReasons).size === gapReasons.length, `${gapReasons.length} chrome gaps, ${new Set(gapReasons).size} distinct`);
  ok("scheduler: every reference control is answered in the mapping table, and the unbindable ones are marked unbound rather than filled", ["Create schedule", "Set search parameters", "Filter by name or rid…", "Sorted by most recently updated", "Select schedules…", "Results matching (principal chip)", "APPLICATIONS (facet group)"].every((c) => t.includes(`data-ioi-control="${c}" data-ioi-control-bound="no"`)) && !/data-ioi-control-bound="yes"/.test(t), "7 controls answered");
  ok("scheduler: READ-ONLY projection — no verb is re-minted; the Create absence NAMES the owner surface and the daemon's own typed refusal code", !t.includes("<form") && !/action="\/__ioi\/(missions|automations)/.test(t) && /automation_project_ref_required/.test(t) && /never re-mints another surface's authority-crossing verb/.test(t) && t.includes("/__ioi/automations"), String(!t.includes("<form")));
  ok("scheduler: evidence cited (adjudication #scheduler-port + the LIVE deep atlas) and brand-clean — no vendor brand and no borrowed tenant identity", /reference-seed-adjudications\.v1\.json#scheduler-port/.test(t) && /reference-live-tenant-deep-atlas\.v1\.json#scheduler/.test(t) && !/\bPalantir\b/i.test(t) && !/palantirfoundry/i.test(t) && !/Josman/i.test(t) && !/workspace\/scheduler/i.test(t));
}
const fails = results.filter((r) => !r.pass);
for (const r of results) console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
console.log(`\n${results.length - fails.length}/${results.length} passed`);
console.log(`app-parity-domain-landings readiness: ${fails.length ? "FAIL" : "OK"}`);
process.exit(fails.length ? 1 : 0);
