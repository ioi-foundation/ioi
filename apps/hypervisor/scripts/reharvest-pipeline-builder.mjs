#!/usr/bin/env node
// PIPELINE BUILDER RE-HARVEST WORKFLOW (#37 infrastructure).
//
// The path to a DATA-CLEAN Pipeline Builder reference. It is honest about the hard requirement: the
// local :9225 mirror is a STATIC capture with no eddie/Foundry backend, so it cannot render the
// pipeline list, the marketplace examples, or a pipeline CANVAS (the graph editor). Making the builder
// reference data-clean requires RE-CAPTURING a working pipeline example from a LIVE authenticated
// Foundry session — the existing capture tools
// (internal-docs/reverse-engineering/palantir/tools/harvesting/{install_application_examples,scaffold_examples}.mjs)
// both drive Playwright against `liveBase` (test.usw-23.palantirfoundry.com) using
// config/auth.json. There is NO offline scaffold path.
//
// This workflow:
//   1. Assesses READINESS (auth-state freshness, tool presence, target RIDs, live reachability) —
//      WITHOUT authenticating to or mutating anything on Foundry.
//   2. Runs the data-clean PREFLIGHT (verify-pipeline-reference-data-clean.mjs) and reports the current
//      reference state + the exact blocking reason.
//   3. Prints the exact re-harvest PLAN to produce a data-clean capture.
//   4. Emits reharvest-plan.json.
//
// It DEFAULTS TO DRY-RUN and NEVER contacts Palantir on its own. A live capture is an outward-facing
// action against a third-party service and is gated behind BOTH a fresh session AND an explicit opt-in
// (IOI_REHARVEST_LIVE=1); on a stale session it refuses. This PR ships the workflow + the gate; it does
// not execute a live capture (the recorded session is stale).
//
// Usage:  node apps/hypervisor/scripts/reharvest-pipeline-builder.mjs            # dry-run assessment
//         IOI_REHARVEST_LIVE=1 node …/reharvest-pipeline-builder.mjs             # live capture (needs a FRESH auth.json)

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
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
// what the capture tools authenticate with, and it expires well before the cookie envelope.
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
  const r = spawnSync("node", [preflight], { encoding: "utf8", timeout: 120000, env: { ...process.env, IOI_HARNESS_ARTIFACT_DIR: artifactDir } });
  let result = null;
  const rp = path.join(artifactDir, "result.json");
  if (existsSync(rp)) { try { result = JSON.parse(readFileSync(rp, "utf8")); } catch { /* */ } }
  return { ran: r.status === 0 || existsSync(rp), stdout: (r.stdout || "").trim(), result };
}

async function main() {
  mkdirSync(artifactDir, { recursive: true });
  const auth = authFreshness(authPath);
  const sessionFresh = auth.fresh;
  const toolsPresent = existsSync(installer) && existsSync(scaffolder);
  const expStr = auth.tokenExp ? new Date(auth.tokenExp * 1000).toISOString().slice(0, 16) + "Z" : "no PALANTIR_TOKEN";
  // The DEFAULT dry-run contacts NOTHING external. Only probe Foundry reachability when a live capture
  // is actually being attempted (IOI_REHARVEST_LIVE=1) — and even then it is an UNauthenticated HEAD.
  const liveStatus = live ? await reachable(liveBase) : null;

  console.log("=== Pipeline Builder re-harvest — readiness ===");
  console.log(`  auth state        : ${auth.present ? `${auth.cookies} cookies; PALANTIR_TOKEN exp ${expStr}` : "MISSING"} (${path.relative(repoRoot, authPath)})`);
  console.log(`  session fresh     : ${sessionFresh ? "yes" : "NO — token stale/expired; re-harvest needs a FRESH Foundry login"}`);
  console.log(`  capture tools     : ${toolsPresent ? "present" : "MISSING"} (install_application_examples.mjs / scaffold_examples.mjs)`);
  console.log(`  live Foundry      : ${liveBase} → ${liveStatus === null ? "not probed (dry-run; zero external contact)" : `HTTP ${liveStatus} (unauthenticated HEAD)`}`);
  console.log(`  target RIDs       : ${BUILDER_RIDS.join(" · ")}`);

  console.log("\n=== current reference state (data-clean preflight) ===");
  const pf = await runPreflight();
  const dataClean = pf.result ? pf.result.data_clean : null;
  // The PRECISE blocker: the builder shell + eddie backend ARE captured; the canvas is a lazy webpack
  // chunk and the mirror serves an empty STUB for missing chunk hashes → the canvas crashes. The
  // preflight records the exact stubbed hashes per lane — the surgical backfill target.
  const missingChunks = pf.result ? [...new Set((pf.result.lanes || []).flatMap((l) => l.missing_lazy_chunks || []))] : [];
  console.log(`  data_clean        : ${dataClean === null ? "unknown (preflight did not run)" : dataClean ? "TRUE ✓" : "FALSE ✗"}`);
  if (pf.result && !pf.result.data_clean) console.log(`  blocking reason   : ${pf.result.blocking_reason}`);
  console.log(`  root cause        : the builder shell + eddie backend are captured; the canvas is a lazy JS chunk and ${missingChunks.length} chunk hash(es) are MISSING from the frontend asset store → the mirror serves an empty stub → crash.`);
  if (missingChunks.length) console.log(`  missing chunks    : ${missingChunks.join("\n                      ")}`);

  console.log("\n=== re-harvest plan (surgical — the eddie data is already captured) ===");
  console.log("  1. Refresh the Foundry session (the recorded token is stale/expired):");
  console.log("       node " + path.relative(repoRoot, path.join(palantirRoot, "tools", "harvesting", "refresh_auth.js")));
  console.log("     (headful login to " + liveBase + " → saves a fresh storageState to " + path.relative(repoRoot, authPath) + ").");
  console.log("  2. Backfill ONLY the missing lazy chunk(s) via download_missing_assets.js (set MISSING_ASSETS");
  console.log("     to the hashes above, under /assets/content-addressable-storage/frontend/):");
  console.log("       node " + path.relative(repoRoot, path.join(palantirRoot, "tools", "harvesting", "download_missing_assets.js")));
  console.log("     (or full recapture: node " + path.relative(repoRoot, installer) + " with a builder filter.)");
  console.log("  3. Re-run this workflow / the preflight — data_clean flips to TRUE only when a canvas");
  console.log("     renders graph nodes + toolbar + output panel + tray with no error/data-fail.");
  console.log("  4. THEN, and only then, the promotion path opens (declare pipeline reference_landmarks,");
  console.log("     run the hardened parity harness, flip matrix reference_ported → daemon_wired).");

  let liveOutcome = "not_attempted";
  if (live) {
    if (!sessionFresh) {
      liveOutcome = "refused_stale_session";
      console.log("\n[live] IOI_REHARVEST_LIVE=1 but the session is STALE — refusing to contact Foundry. Refresh " + path.relative(repoRoot, authPath) + " first.");
    } else {
      liveOutcome = "would_run_live_capture";
      console.log("\n[live] IOI_REHARVEST_LIVE=1 + fresh session — a live capture would run here. (Left as an explicit");
      console.log("       operator step; wire the spawn of install_application_examples.mjs with APP_FILTER for the");
      console.log("       builder once a fresh session is confirmed, then re-run the preflight.)");
    }
  } else {
    console.log("\n[dry-run] default mode — no contact with Foundry. Set IOI_REHARVEST_LIVE=1 (with a fresh session) to capture.");
  }

  const plan = {
    schema: "ioi.hypervisor.pipeline-reharvest-plan.v1",
    generated_for: "#37 Pipeline Builder re-harvest workflow",
    readiness: { auth_present: auth.present, auth_cookies: auth.cookies, token_exp: auth.tokenExp, token_exp_iso: expStr, session_fresh: sessionFresh, tools_present: toolsPresent, live_base: liveBase, live_status: liveStatus, target_rids: BUILDER_RIDS },
    current_data_clean: dataClean,
    current_blocking_reason: pf.result ? pf.result.blocking_reason : "preflight did not run",
    root_cause: "builder shell + eddie backend are captured; the canvas is a lazy webpack chunk and its chunk hash(es) are missing from the frontend asset store → the mirror serves an empty stub → the canvas crashes",
    missing_lazy_chunks: missingChunks,
    requires: "a FRESH authenticated Foundry session (config/auth.json is stale/expired) to backfill the missing chunk(s); no offline path — the mirror stubs absent chunks",
    live_mode: live, live_outcome: liveOutcome,
    plan: ["refresh config/auth.json via `node …/refresh_auth.js` (headful Foundry login)", "backfill the missing lazy chunk hash(es) via `node …/download_missing_assets.js` (set MISSING_ASSETS), or full recapture via install_application_examples.mjs with a builder filter", "re-run verify-pipeline-reference-data-clean.mjs", "if data_clean: declare pipeline reference_landmarks + run the hardened harness + flip matrix reference_ported→daemon_wired"],
  };
  writeFileSync(path.join(artifactDir, "reharvest-plan.json"), JSON.stringify(plan, null, 2) + "\n");
  console.log(`\nartifact: ${path.relative(process.cwd(), path.join(artifactDir, "reharvest-plan.json"))}`);
  console.log(`\nSUMMARY: reference is ${dataClean ? "DATA-CLEAN — promotion path is open" : "NOT data-clean — pipeline stays reference_ported until a fresh-session re-harvest"}.`);
}

main().catch((e) => { console.error("reharvest workflow crashed:", e); process.exit(1); });
