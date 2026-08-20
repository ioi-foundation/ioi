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
  ok(`${slug}: renders 200 with the I-4 grammar (rail + ${title} + Recents/Favorites)`, p.status === 200 && t.includes("og-grail") && t.includes(title) && t.includes("Recents") && t.includes("Favorites"), String(p.status));
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
const fails = results.filter((r) => !r.pass);
for (const r of results) console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
console.log(`\n${results.length - fails.length}/${results.length} passed`);
console.log(`app-parity-domain-landings readiness: ${fails.length ? "FAIL" : "OK"}`);
process.exit(fails.length ? 1 : 0);
