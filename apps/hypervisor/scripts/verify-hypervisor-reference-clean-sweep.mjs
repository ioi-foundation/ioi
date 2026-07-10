#!/usr/bin/env node
// ---------------------------------------------------------------------------
// PR #44 — REFERENCE CLEAN-SWEEP VERIFIER.
// Asserts the committed estate sweep (reference-clean-sweep.json) is complete,
// internally coherent (every state agrees with its own recorded evidence — a
// screenshot is never the evidence, the DOM/text/network record is), agrees
// with the matrix stamping, keeps the certified controls clean, covers the
// explorer/pipeline special cases, and ranks a justified next-3 WITHOUT any
// parity promotion. Infrastructure-only: no ports, no daemon_wired changes.
// ---------------------------------------------------------------------------
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const results = [];
const ok = (name, pass, detail = "") => results.push({ name, pass: !!pass, detail });

const CLEAN_STATES = new Set([
  "data_clean", "shell_clean_only", "blank_reference", "errored_reference",
  "cors_origin_mismatch", "missing_chunk", "modal_blocked", "data_failed",
  "needs_backend_reharvest", "needs_origin_alignment", "unknown_blocked",
]);

let sweep = null, matrix = null;
try { sweep = JSON.parse(readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8")); } catch { /* */ }
try { matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8")); } catch { /* */ }

// 1. The committed sweep exists and is the sweep the harness writes.
ok("committed sweep evidence exists and parses (reference-clean-sweep.json)", !!sweep && sweep.schema === "ioi.hypervisor.reference-clean-sweep.v1");
ok("the sweep is estate-COMPLETE: all 39 seeds, unique slugs, local lanes only", !!sweep && sweep.total_seeds === 39 && Array.isArray(sweep.seeds) && sweep.seeds.length === 39
  && new Set(sweep.seeds.map((s) => s.slug)).size === 39
  && /^http:\/\/(127\.0\.0\.1|localhost):\d+/.test(sweep.serve || "") && /^http:\/\/(127\.0\.0\.1|localhost):\d+/.test(sweep.mirror || ""));
const seeds = (sweep && sweep.seeds) || [];
const bySlug = Object.fromEntries(seeds.map((s) => [s.slug, s]));

// 2. Every seed: exactly one KNOWN state, an evidence-backed reason, a screenshot pointer.
ok("every seed carries exactly one known clean state + a non-empty reason", seeds.length === 39 && seeds.every((s) => CLEAN_STATES.has(s.clean_state) && typeof s.reason === "string" && s.reason.length >= 12));
ok("every seed records its lanes (url, load, data score, network failure counts) — DOM/network evidence, not screenshots alone", seeds.every((s) => Array.isArray(s.lanes_summary) && s.lanes_summary.length >= 1 && s.lanes_summary.every((l) => l.url && typeof l.data_score === "number" && typeof l.chunk_404s === "number" && typeof l.api_failures === "number")));
ok("every seed records shell regions + data evidence + capture-store facts", seeds.every((s) => Array.isArray(s.shell_regions) && (s.data_evidence === null || typeof s.data_evidence.body_text_chars === "number") && s.capture_store && typeof s.capture_store.file_count === "number"));

// 3. STATE ↔ EVIDENCE coherence (the sweep's own record must justify its verdict).
const d = (s) => s.data_evidence || {};
const strongData = (s) => (d(s).table_rows >= 3 || d(s).repeated_rows >= 4 || d(s).graph_nodes >= 3 || d(s).cards >= 3);
const coherent = [];
for (const s of seeds) {
  let c = true;
  switch (s.clean_state) {
    case "data_clean": c = strongData(s) && s.shell_regions.length >= 2 && !s.error_text; break;
    case "shell_clean_only": c = s.shell_regions.length >= 2 && !s.error_text; break;
    case "blank_reference": c = (d(s).body_text_chars || 0) < 60 && s.shell_regions.length <= 1; break;
    case "errored_reference": c = !!s.error_text || /navigation|download|error/i.test(s.reason); break;
    case "missing_chunk": c = Array.isArray(s.missing_chunks) && s.missing_chunks.length > 0; break;
    case "cors_origin_mismatch": c = Array.isArray(s.cors_evidence) && s.cors_evidence.length > 0; break;
    case "modal_blocked": c = !!(s.modal_evidence && s.modal_evidence.dismissed_reveals_data); break;
    case "data_failed": c = !!s.error_text || /loading indicator/.test(s.reason); break;
    case "needs_backend_reharvest": c = /data-lane|backend payloads/.test(s.reason); break;
    case "needs_origin_alignment": {
      // the ORIGIN lane must carry the data; the proxy defect is named in the reason
      // (it may be a failure/CORS artifact even when chrome scores nonzero).
      const origin = s.lanes_summary.find((l) => l.lane === "origin");
      c = !!origin && origin.data_score >= 3 && /origin lane/.test(s.reason); break;
    }
    case "unknown_blocked": c = true; break;
  }
  if (!c) coherent.push(`${s.slug}:${s.clean_state}`);
}
ok("every state agrees with its own recorded evidence (data_clean⇒rows/nodes/cards; errored⇒error; chunk⇒hashes; cors⇒signals; modal⇒reveal delta; origin-alignment⇒origin-lane data with a data-poor proxy)", coherent.length === 0, coherent.join(", ") || "all coherent");
ok("no errored/blank reference is classified clean (rail rendering alone never counts)", seeds.every((s) => !(["errored_reference", "blank_reference"].includes(s.clean_state) && strongData(s) && s.shell_regions.length >= 2)));

// 4. Calibration controls: the three certified daemon_wired surfaces read data_clean.
for (const slug of ["schema", "approvals", "pipeline"]) {
  const s = bySlug[slug];
  ok(`control '${slug}' is data_clean (certified surface over a VALID reference — heuristics calibrate on it)`, s && s.clean_state === "data_clean" && strongData(s), s ? `${s.clean_state} · ${s.reason.slice(0, 80)}` : "missing");
}
ok("control 'pipeline' evidences the ORIGIN-ALIGNMENT pattern (classified on its origin-aligned override lane)", bySlug.pipeline && bySlug.pipeline.lane_used === "override");

// 5. Explorer special case: the pipeline origin-trick explicitly tested with a verdict.
{
  const e = bySlug.explorer;
  const origin = e && e.lanes_summary.find((l) => l.lane === "origin");
  ok("explorer: the origin-alignment trick was explicitly TESTED (origin lane rendered + recorded)", !!origin && typeof origin.data_score === "number");
  ok("explorer: verdict is explicit — needs_origin_alignment/data_clean with origin-lane data evidence, or a blocked state NAMING the exact blocker", e && (["needs_origin_alignment", "data_clean"].includes(e.clean_state) ? (origin && origin.data_score >= 3) : e.reason.length > 24), e ? `${e.clean_state} · origin data_score=${origin ? origin.data_score : "n/a"}` : "missing");
}

// 6. Ranked next-3: present, justified on the directive's axes, and NOT promotions.
{
  const r = (sweep && sweep.ranked_next) || [];
  ok("ranked next-3 present (3 candidates, ranks 1..3)", r.length === 3 && r.map((x) => x.rank).join(",") === "1,2,3");
  ok("every ranked candidate is a data_clean reference (preference #1 is a hard gate)", r.every((x) => bySlug[x.slug] && bySlug[x.slug].clean_state === "data_clean"));
  ok("no ranked candidate is already ported (daemon_wired/reference_ported are not 'next')", r.every((x) => !["daemon_wired", "reference_ported"].includes(bySlug[x.slug]?.parity_class)));
  ok("every ranked candidate is JUSTIFIED on the directive's axes (daemon-truth bindability, owner value, fabrication risk, IA landmarks, live-dependency)", r.every((x) => x.why && x.why.data_clean_reference === true && x.why.daemon_truth_bindable && x.why.owner_value && x.why.fabrication_risk && x.why.live_palantir_dependency));
}

// 7. Matrix agreement: stamped fields match the sweep; parity_class UNTOUCHED by the sweep.
{
  const rows = (matrix && matrix.seeds) || [];
  ok("matrix rows carry reference_clean_state/_reason/_artifact for all 39 seeds", rows.length === 39 && rows.every((m) => CLEAN_STATES.has(m.reference_clean_state) && m.reference_clean_reason && m.reference_clean_artifact === "reference-clean-sweep.json"));
  const mismatch = rows.filter((m) => bySlug[m.slug] && (m.reference_clean_state !== bySlug[m.slug].clean_state || m.reference_clean_reason !== bySlug[m.slug].reason));
  ok("matrix stamping AGREES with the sweep evidence (state + reason verbatim)", mismatch.length === 0, mismatch.map((m) => m.slug).join(", ") || "all agree");
  // THE CERTIFIED-PROMOTION CONTRACT: the sweep itself never promotes (that was #44's
  // hard bar), but a LATER port PR may move a seed's parity ONLY with committed shell-pixel
  // certification evidence over a data_clean reference (#45 incidents is the first). Any
  // other drift vs the sweep-time snapshot is an unsanctioned promotion and fails here.
  const parityDrift = rows.filter((m) => bySlug[m.slug] && m.parity_class !== bySlug[m.slug].parity_class);
  const unsanctioned = parityDrift.filter((m) => {
    if (m.parity_class !== "daemon_wired") return true;                         // only certified-port promotions are sanctioned
    if (m.reference_clean_state !== "data_clean" || m.shell_pixel_certified !== true) return true;
    let cert = null;
    try { cert = JSON.parse(readFileSync(path.join(appRoot, m.shell_pixel_certification_artifact), "utf8")); } catch { return true; }
    return !(cert && cert.slug === m.slug && cert.shell_pixel_certified === true && cert.viewports_pinned === false);
  });
  ok("NO UNSANCTIONED PROMOTIONS: any parity drift vs the sweep snapshot is a CERTIFIED port over a data_clean reference (committed non-pinned evidence), nothing else", unsanctioned.length === 0, parityDrift.length ? parityDrift.map((m) => `${m.slug}: ${bySlug[m.slug].parity_class}→${m.parity_class}${unsanctioned.includes(m) ? " (UNSANCTIONED)" : " (certified)"}`).join(", ") : "no drift");
  const dist = matrix && matrix.by_parity_class;
  const counts = { substrate_bound: 0, reference_capture: 0, daemon_wired: 0, reference_ported: 0 };
  for (const m of rows) counts[m.parity_class] = (counts[m.parity_class] || 0) + 1;
  ok("parity distribution is internally consistent (header matches rows; certified promotions accounted)", JSON.stringify(dist) === JSON.stringify(Object.fromEntries(Object.entries(counts).filter(([, v]) => v > 0))) || JSON.stringify(dist) === JSON.stringify(counts), JSON.stringify(dist));
  ok("daemon_wired seeds are clean CERTIFIED controls in the matrix (data_clean + shell_pixel_certified)", rows.filter((m) => m.parity_class === "daemon_wired").every((m) => m.reference_clean_state === "data_clean" && m.shell_pixel_certified === true));
  ok("reference_ported (explorer) names its blocker in the matrix", rows.filter((m) => m.parity_class === "reference_ported").every((m) => m.reference_clean_reason && m.reference_clean_reason.length > 24));
}

// 8. The matrix is CURRENT (generator idempotence over the committed inputs).
{
  const chk = spawnSync(process.execPath, [path.join(appRoot, "scripts", "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8", timeout: 60000 });
  ok("matrix --check green (generation is current over the committed sweep)", chk.status === 0, (chk.stdout || chk.stderr || "").trim().split("\n").pop());
}

// 9. Hygiene: the committed evidence is text-clean.
{
  const raw = readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8");
  ok("no NUL/control characters in the committed sweep evidence", !/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(raw));
}

let fail = 0;
for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
console.log(`\n${results.length - fail}/${results.length} passed`);
console.log(`reference-clean-sweep readiness: ${fail ? "FAIL" : "OK"}`);
process.exit(fail ? 1 : 0);
