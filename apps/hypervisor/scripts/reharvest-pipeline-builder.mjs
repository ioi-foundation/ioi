#!/usr/bin/env node
// PIPELINE BUILDER REFERENCE — REMEDIATION PLANNER (#37 infra; #38 DIAGNOSIS RE-BASELINE).
//
// Reads the data-clean PREFLIGHT (verify-pipeline-reference-data-clean.mjs) and prints the CORRECT
// remediation for whatever the gate actually diagnoses — it is DIAGNOSIS-DRIVEN, not a fixed re-harvest
// script. #37 assumed the only blocker was "missing lazy chunks needing a fresh-session re-harvest."
// #38 proved that WRONG: signature-based stub detection finds ZERO missing chunks (the earlier <400b
// heuristic false-positived genuinely-small REAL chunks like the 364b `splitPathsBySizeLoader`). The
// captured data is COMPLETE — from the MATCHING origin (localhost:9225) the canvas renders a clean
// pipeline graph. The real blocker is a CORS/ORIGIN MISMATCH: the app's captured fetch URLs are absolute
// localhost:9225, so loading the mirror from a different origin (127.0.0.1:9225 — the harness/proxy
// origin) makes every eddie/session fetch cross-origin → CORS-blocked → the canvas "Failed to initialize."
//
// Remediation therefore BRANCHES on the gate's `diagnosis`:
//   - cors_origin_mismatch : ALIGN THE ORIGIN (serve the mirror same-origin as the app's fetch URLs, or
//                            add permissive CORS on the mirror) + point the harness reference at the
//                            data-clean canvas. NO re-harvest, NO fresh Foundry auth. (← current state)
//   - missing_chunk        : re-harvest ONLY the signature-detected stub hash(es) — refresh auth (headful
//                            Foundry login) + backfill via download_missing_assets.js. Guarded (below).
//   - app_data_failure     : the eddie backend capture is genuinely incomplete → a broader recapture.
//   - data_clean           : the harness-path reference is certifiable → the promotion path is open.
//
// It DEFAULTS TO DRY-RUN and NEVER contacts Palantir on its own. The live re-harvest branch (only ever
// the fix for a genuine missing_chunk) is gated behind BOTH a fresh session AND an explicit opt-in
// (IOI_REHARVEST_LIVE=1); on a stale session it refuses. For the CURRENT (cors_origin_mismatch) blocker
// a live re-harvest is NOT the fix and is never triggered.
//
// Usage:  node apps/hypervisor/scripts/reharvest-pipeline-builder.mjs            # dry-run remediation plan
//         IOI_REHARVEST_LIVE=1 node …/reharvest-pipeline-builder.mjs             # live re-harvest branch (needs FRESH auth.json AND a missing_chunk diagnosis)

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const repoRoot = path.resolve(appRoot, "..", "..");
const palantirRoot = path.join(repoRoot, "internal-docs", "reverse-engineering", "palantir");
const authPath = process.env.AUTH_STATE || path.join(palantirRoot, "config", "auth.json");
const installer = path.join(palantirRoot, "tools", "harvesting", "install_application_examples.mjs");
const scaffolder = path.join(palantirRoot, "tools", "harvesting", "scaffold_examples.mjs");
const preflight = path.join(here, "verify-pipeline-reference-data-clean.mjs");
const artifactDir = process.env.IOI_HARNESS_ARTIFACT_DIR || path.join(appRoot, ".artifacts", "pipeline-reharvest");
const liveBase = process.env.LIVE_BASE || "https://test.usw-23.palantirfoundry.com";
const BUILDER_RIDS = ["ri.eddie.main.pipeline.e73d6ae7-f6fe-4ac5-82a2-320d9f188590", "ri.eddie.main.pipeline.5ef60976-74bb-4b67-b119-a4b6af284f09"];
const live = process.env.IOI_REHARVEST_LIVE === "1";

// Freshness is the PALANTIR_TOKEN JWT `exp`, not merely "some cookie unexpired" — the session token is
// what the capture tools authenticate with, and it expires well before the cookie envelope. (Only the
// missing_chunk branch needs it; assessed regardless so the plan can report readiness.)
function authFreshness(p) {
  if (!existsSync(p)) return { present: false, cookies: 0, tokenExp: null, fresh: false };
  try {
    const j = JSON.parse(readFileSync(p, "utf8"));
    const cs = Array.isArray(j.cookies) ? j.cookies : [];
    const tok = cs.find((c) => c.name === "PALANTIR_TOKEN");
    let tokenExp = null;
    if (tok && typeof tok.value === "string" && tok.value.split(".").length === 3) {
      try { const payload = JSON.parse(Buffer.from(tok.value.split(".")[1], "base64").toString("utf8")); if (typeof payload.exp === "number") tokenExp = payload.exp; } catch { /* */ }
    }
    const now = Date.now() / 1000;
    return { present: true, cookies: cs.length, tokenExp, fresh: tokenExp != null && tokenExp > now };
  } catch (e) { return { present: true, cookies: 0, tokenExp: null, fresh: false, parseError: String(e.message || e).slice(0, 60) }; }
}

async function reachable(url) { return fetch(url, { method: "HEAD" }).then((r) => r.status).catch(() => 0); }

async function runPreflight() {
  const rp = path.join(artifactDir, "result.json");
  // Remove any STALE artifact first, and parse ONLY on a clean exit (status 0). A BLOCKED (exit 2) /
  // crash / timeout preflight must NEVER let a prior run's result.json masquerade as the current state
  // (review: a stale {"data_clean":true} + a dead mirror printed "DATA-CLEAN"). Same pattern as the
  // pipeline verifier.
  try { if (existsSync(rp)) rmSync(rp); } catch { /* */ }
  const r = spawnSync("node", [preflight], { encoding: "utf8", timeout: 180000, env: { ...process.env, IOI_HARNESS_ARTIFACT_DIR: artifactDir } });
  let result = null;
  if (r.status === 0 && existsSync(rp)) { try { result = JSON.parse(readFileSync(rp, "utf8")); } catch { /* */ } }
  return { status: r.status, blocked: r.status === 2, ran: r.status === 0 && !!result, stdout: (r.stdout || "").trim(), result };
}

// The remediation for a given gate diagnosis — the branch table, as data.
function remediationFor(diagnosis) {
  switch (diagnosis) {
    case "data_clean":
      return { branch: "promotion_open", needs_live_capture: false, steps: ["the harness-path (proxy) reference is data-clean — declare pipeline reference_landmarks", "run the hardened parity harness (harness-reference-parity.mjs)", "if visual_parity passes: flip matrix reference_ported → daemon_wired (WITH side-by-side screenshots)"] };
    case "cors_origin_mismatch":
      return { branch: "origin_alignment", needs_live_capture: false, steps: ["the captured data is COMPLETE — do NOT re-harvest and do NOT refresh Foundry auth", "ALIGN THE ORIGIN: serve the mirror from the SAME origin the app's captured fetch URLs use (localhost:9225), or add permissive CORS headers on the mirror for the harness/proxy origin (127.0.0.1:9225)", "point the harness reference at the data-clean CANVAS (…/sandbox/…), not the data-partial builder landing list", "re-run verify-pipeline-reference-data-clean.mjs — data_clean flips TRUE when the proxy/harness lane renders the clean graph", "THEN the promotion path opens (declare reference_landmarks → hardened harness → daemon_wired)"] };
    case "missing_chunk":
      return { branch: "reharvest_missing_chunk", needs_live_capture: true, steps: ["refresh the Foundry session (headful login): node internal-docs/reverse-engineering/palantir/tools/harvesting/refresh_auth.js", "backfill ONLY the signature-detected stub hash(es) via download_missing_assets.js (set MISSING_ASSETS to those hashes under /assets/content-addressable-storage/frontend/)", "re-run the preflight — data_clean flips only when a canvas renders graph + toolbar + panel with no error/data-fail", "then declare reference_landmarks → hardened harness → daemon_wired"] };
    default:
      return { branch: "recapture_or_investigate", needs_live_capture: true, steps: ["the reference is neither data-clean nor a clean CORS/missing-chunk case — inspect the preflight lanes + screenshots", "if the matching-origin canvas is NOT data-complete, the eddie backend capture is incomplete → recapture via install_application_examples.mjs with a builder filter (needs a fresh session)"] };
  }
}

async function main() {
  mkdirSync(artifactDir, { recursive: true });
  const auth = authFreshness(authPath);
  const sessionFresh = auth.fresh;
  const toolsPresent = existsSync(installer) && existsSync(scaffolder);
  const expStr = auth.tokenExp ? new Date(auth.tokenExp * 1000).toISOString().slice(0, 16) + "Z" : "no PALANTIR_TOKEN";

  console.log("\n=== current reference state (data-clean preflight) ===");
  const pf = await runPreflight();
  // data_clean / diagnosis are null when the preflight did NOT complete cleanly (blocked / crash /
  // timeout) — never inferred from a stale artifact. Only a clean exit-0 result yields a real state.
  const dataClean = pf.ran && pf.result ? pf.result.data_clean : null;
  const diagnosis = pf.ran && pf.result ? pf.result.diagnosis : null;
  const dcState = pf.blocked ? "BLOCKED — the preflight could not reach the :9225 mirror / :4173 serve" : dataClean === null ? "UNKNOWN — the preflight did not complete (crash/timeout); re-run with the mirror + serve up" : dataClean ? "TRUE ✓" : "FALSE ✗";
  // The genuine missing-chunk set is the gate's SIGNATURE-detected stubs (empty when — as now — nothing
  // is actually missing). NOT a size heuristic.
  const missingChunks = pf.ran && pf.result ? (pf.result.generated_stub_chunks || []) : [];
  const referenceDataComplete = pf.ran && pf.result ? !!pf.result.reference_data_complete : null;
  console.log(`  data_clean        : ${dcState}`);
  console.log(`  diagnosis         : ${diagnosis || "(unknown)"}`);
  console.log(`  data complete?    : ${referenceDataComplete === null ? "unknown" : referenceDataComplete ? "YES — the matching-origin canvas renders a clean pipeline graph" : "no"}`);
  if (pf.ran && pf.result && !pf.result.data_clean) console.log(`  blocking reason   : ${pf.result.blocking_reason}`);
  console.log(`  missing chunks    : ${missingChunks.length ? missingChunks.join(", ") + " (signature-detected)" : "none (signature-detected → #37's missing-chunk claim is retracted)"}`);

  const rem = remediationFor(diagnosis);
  console.log(`\n=== remediation (branch: ${rem.branch}) ===`);
  rem.steps.forEach((s, i) => console.log(`  ${i + 1}. ${s}`));

  // The auth/live readiness only matters for the re-harvest branch; report it, but make clear it is not
  // the current path.
  console.log("\n=== re-harvest readiness (relevant ONLY to a missing_chunk diagnosis) ===");
  console.log(`  auth state        : ${auth.present ? `${auth.cookies} cookies; PALANTIR_TOKEN exp ${expStr}` : "MISSING"} (${path.relative(repoRoot, authPath)})`);
  console.log(`  session fresh     : ${sessionFresh ? "yes" : "NO — a stale token would block the re-harvest branch, but that branch is NOT the current fix"}`);
  console.log(`  capture tools     : ${toolsPresent ? "present" : "MISSING"} (install_application_examples.mjs / scaffold_examples.mjs)`);
  console.log(`  target RIDs       : ${BUILDER_RIDS.join(" · ")}`);

  let liveOutcome = "not_attempted";
  if (live) {
    if (!rem.needs_live_capture) {
      liveOutcome = "no_live_capture_needed_for_this_diagnosis";
      console.log(`\n[live] IOI_REHARVEST_LIVE=1 but the current diagnosis is '${diagnosis}', whose fix does NOT involve contacting Foundry (${rem.branch}). Refusing to contact Foundry — a re-harvest would not fix this blocker.`);
    } else if (!sessionFresh) {
      liveOutcome = "refused_stale_session";
      console.log("\n[live] IOI_REHARVEST_LIVE=1 + a missing_chunk diagnosis, but the session is STALE — refusing to contact Foundry. Refresh " + path.relative(repoRoot, authPath) + " first.");
    } else {
      liveOutcome = "would_run_live_capture";
      const liveStatus = await reachable(liveBase); // only probe when we would genuinely capture
      console.log(`\n[live] IOI_REHARVEST_LIVE=1 + missing_chunk + fresh session — a live backfill would run here (live Foundry ${liveBase} → HTTP ${liveStatus}, unauthenticated HEAD). Left as an explicit operator step: wire download_missing_assets.js with the stub hashes above, then re-run the preflight.`);
    }
  } else {
    console.log("\n[dry-run] default mode — no contact with Foundry. A live re-harvest is only ever the fix for a missing_chunk diagnosis; set IOI_REHARVEST_LIVE=1 (with a fresh session) then.");
  }

  const plan = {
    schema: "ioi.hypervisor.pipeline-remediation-plan.v2",
    generated_for: "#38 Pipeline Builder reference remediation planner (diagnosis-driven; supersedes the #37 fixed re-harvest plan)",
    readiness: { auth_present: auth.present, auth_cookies: auth.cookies, token_exp: auth.tokenExp, token_exp_iso: expStr, session_fresh: sessionFresh, tools_present: toolsPresent, live_base: liveBase, target_rids: BUILDER_RIDS },
    preflight_status: pf.blocked ? "blocked" : pf.ran ? "ran" : "did_not_complete",
    current_data_clean: dataClean,
    diagnosis,
    reference_data_complete: referenceDataComplete,
    current_blocking_reason: pf.ran && pf.result ? pf.result.blocking_reason : pf.blocked ? "BLOCKED — preflight could not reach the mirror/serve" : "preflight did not complete (crash/timeout)",
    missing_chunks_signature_detected: missingChunks,
    retraction: "#37's root cause ('missing lazy chunks needing a fresh-session re-harvest') is RETRACTED — signature stub detection finds ZERO missing chunks; the captured data is complete and the blocker is a CORS/origin mismatch (fix = origin alignment, no auth).",
    remediation_branch: rem.branch,
    remediation_needs_live_capture: rem.needs_live_capture,
    remediation_steps: rem.steps,
    live_mode: live, live_outcome: liveOutcome,
  };
  writeFileSync(path.join(artifactDir, "reharvest-plan.json"), JSON.stringify(plan, null, 2) + "\n");
  console.log(`\nartifact: ${path.relative(process.cwd(), path.join(artifactDir, "reharvest-plan.json"))}`);
  console.log(`\nSUMMARY: ${dataClean === true ? "reference is DATA-CLEAN — promotion path is open" : diagnosis === "cors_origin_mismatch" ? "reference DATA is complete; blocked by a CORS/origin mismatch — fix is ORIGIN ALIGNMENT (no re-harvest, no fresh auth); pipeline stays reference_ported" : diagnosis === "missing_chunk" ? "reference blocked by a genuinely missing chunk — the re-harvest branch applies (fresh session + backfill)" : pf.blocked ? "preflight BLOCKED (mirror/serve down) — state UNKNOWN; bring them up and re-run" : "preflight did not complete / other — state UNKNOWN; inspect lanes"}.`);
}

main().catch((e) => { console.error("remediation planner crashed:", e); process.exit(1); });
