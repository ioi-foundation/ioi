#!/usr/bin/env node
// REGRESSION — the #37→#38 diagnosis re-baseline, made permanent.
//
// #37 concluded the Pipeline reference was blocked by "missing lazy chunks needing a fresh Foundry
// re-harvest." That rested on a <400b size heuristic that mis-classified genuinely-small REAL webpack
// chunks (the 364b/365b `foundryBlueprintIconsDllJsonp` chunks) as absent stubs. #38 replaced it with a
// SIGNATURE detector and an ORIGIN-AWARE diagnosis. This verifier is a fast, browserless unit test that
// pins the corrected behaviour so #37's mistake cannot regress:
//   A. isGeneratedStub keys on the server's generated-stub SIGNATURE, never on size — a real short chunk
//      is NOT a stub; a generated stub IS, at any size.
//   B. diagnose() is ORIGIN-DISCRIMINATING — a clean matching-origin canvas + a CORS-blocked cross-origin
//      lane ⇒ cors_origin_mismatch (data complete, NOT missing_chunk), while data_clean stays false.
//   C. the stale-artifact guard holds — a dead mirror + a pre-seeded stale {"data_clean":true} cannot be
//      consumed by the remediation planner (it reports UNKNOWN/BLOCKED, never the stale value).
//
// Usage: node apps/hypervisor/scripts/verify-pipeline-stub-detector.mjs   (no servers / no browser / no network for A+B)

import { readFileSync, existsSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isGeneratedStub, GENERATED_STUB_SIG, CSS_STUB_SIG, canvasClean, diagnose } from "./verify-pipeline-reference-data-clean.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const repoRoot = path.resolve(appRoot, "..", "..");
const frontendDir = path.join(repoRoot, "internal-docs", "reverse-engineering", "palantir", "public", "assets", "content-addressable-storage", "frontend");
const REAL_SHORT_CHUNKS = ["bfed3b6a0182adbb7508eeb19d62dcac3caf882c413db466f382fd87715cca6c.js", "c806694d4602b14a257c1a7a3bb3181bd5ad13c49788feda80cdd61c4828dc99.js"];

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

// ---- Fixtures --------------------------------------------------------------------------------------
// The EXACT server-generated stub (server.js): an IIFE that logs "[STUB CHUNK LOADER]" and pushes an
// EMPTY module map. A minified variant without the log line, to prove the empty-map signature alone
// suffices. A LARGE stub, to prove size is orthogonal.
const SERVER_STUB = `
(function() {
  let chunkId = "283";
  for (const key in self) {
    if (/jsonp/i.test(key) || /webpack/i.test(key)) {
      try {
        if (self[key] && typeof self[key].push === 'function') {
          self[key].push([[chunkId], {}]);
          console.log("[STUB CHUNK LOADER] Registered chunk " + chunkId + " via " + key);
        }
      } catch (e) {}
    }
  }
})();`;
const MINIFIED_STUB = `(function(){self.webpackChunk_foo=self.webpackChunk_foo||[];self.webpackChunk_foo.push([["283"],{}])})();`;
const LARGE_STUB = "/* " + "x".repeat(5000) + " */\n" + MINIFIED_STUB;
const CSS_STUB = `/* Stub CSS Chunk */`;
// The EXACT server.js template (a served JS stub), reconstructed faithfully — the empty-map push sits
// ~1000 chars after the IIFE open because of the currentScript/data-webpack fallback block. This is the
// REAL shape the earlier toy fixtures did NOT exercise. A copy with the [STUB CHUNK LOADER] MARKER REMOVED
// must STILL be detected via the STRUCTURAL alternation — proving the backstop is not dead on the real gap.
const FULL_SERVER_STUB = `
(function() {
  let chunkId = "283";
  if (!chunkId) {
    let currentScript = document.currentScript;
    if (!currentScript) {
      const scripts = document.getElementsByTagName('script');
      const targetPathname = "/assets/content-addressable-storage/frontend/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.js";
      for (let i = 0; i < scripts.length; i++) {
        const src = scripts[i].getAttribute('src');
        if (src && (src === targetPathname || src.endsWith(targetPathname))) {
          currentScript = scripts[i];
          break;
        }
      }
    }
    if (currentScript) {
      const dataWebpack = currentScript.getAttribute("data-webpack") || currentScript.getAttribute("data-rspack");
      if (dataWebpack) {
        const parts = dataWebpack.split(":");
        chunkId = parts[parts.length - 1];
      }
    }
  }
  if (!chunkId) return;
  for (const key in self) {
    if (/jsonp/i.test(key) || /webpack/i.test(key)) {
      try {
        if (self[key] && typeof self[key].push === 'function') {
          self[key].push([[chunkId], {}]);
          console.log("[STUB CHUNK LOADER] Registered chunk " + chunkId + " via " + key);
        }
      } catch (e) {}
    }
  }
})();`;
const FULL_SERVER_STUB_NO_MARKER = FULL_SERVER_STUB.replace('[STUB CHUNK LOADER] Registered chunk " + chunkId + " via " + key', 'registered chunk');
const iifeToPushGap = FULL_SERVER_STUB.indexOf(".push([[chunkId], {}])") - FULL_SERVER_STUB.indexOf("(function()");
// A genuinely-small REAL chunk (a webpack push with a NON-empty module map) — the #37 false-positive
// shape, controlled: short AND real.
const REAL_SHORT_SYNTH = `"use strict";(self.foundryBlueprintIconsDllJsonpFunction=self.foundryBlueprintIconsDllJsonpFunction||[]).push([["283"],{823:function(n,e,s){s.r(e),s.d(e,{loader:()=>i});const i=1}}]);`;
const REAL_LARGE = `"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[42],{100:function(n,e,s){` + "s.r(e);".repeat(400) + `}}]);`;

// ---- A. Signature, not size ------------------------------------------------------------------------
for (const f of REAL_SHORT_CHUNKS) {
  const p = path.join(frontendDir, f);
  const present = existsSync(p);
  const body = present ? readFileSync(p) : Buffer.from("");
  ok(`REAL on-disk chunk ${f.slice(0, 8)}… (${present ? body.length + "b" : "MISSING"}) is NOT a stub (short AND real — the #37 false-positive)`, present && body.length < 400 && isGeneratedStub(body) === false, present ? `len=${body.length} stub=${isGeneratedStub(body)}` : "fixture missing");
}
ok("the server-generated stub IS a stub (via the [STUB CHUNK LOADER] marker)", isGeneratedStub(SERVER_STUB) === true);
ok("the FULL server template (real ~1000-char IIFE→push gap) IS a stub", isGeneratedStub(FULL_SERVER_STUB) === true && iifeToPushGap > 800, `gap=${iifeToPushGap}`);
ok("the FULL server template with the [STUB CHUNK LOADER] MARKER REMOVED is STILL a stub — the STRUCTURAL backstop fires on the real gap (not just the marker)", isGeneratedStub(FULL_SERVER_STUB_NO_MARKER) === true && !/\[STUB CHUNK LOADER\]/.test(FULL_SERVER_STUB_NO_MARKER), `gap=${iifeToPushGap} marker_removed`);
ok("a minified empty-module-map IIFE IS a stub (via the signature, no log line needed)", isGeneratedStub(MINIFIED_STUB) === true);
ok("a LARGE (5KB+) generated stub is STILL a stub — size is orthogonal to the signature", isGeneratedStub(LARGE_STUB) === true && LARGE_STUB.length > 4000);
ok("the CSS stub /* Stub CSS Chunk */ IS a stub", isGeneratedStub(CSS_STUB) === true && CSS_STUB_SIG.test(CSS_STUB));
ok("a synthetic SHORT REAL chunk (non-empty module map, <400b) is NOT a stub", REAL_SHORT_SYNTH.length < 400 && isGeneratedStub(REAL_SHORT_SYNTH) === false);
ok("a large REAL chunk (real module code) is NOT a stub", isGeneratedStub(REAL_LARGE) === false);
ok("empty / whitespace bodies are NOT stubs", isGeneratedStub("") === false && isGeneratedStub("   \n  ") === false && isGeneratedStub(null) === false);
// The crux: size does NOT decide. Prove both directions at the SAME small size class the #37 heuristic used.
ok("SIZE-ORTHOGONALITY: at <400b, a real chunk is NOT a stub while a real generated stub IS — classification is by signature, not by <400b", isGeneratedStub(REAL_SHORT_SYNTH) === false && isGeneratedStub(MINIFIED_STUB) === true && REAL_SHORT_SYNTH.length < 400 && MINIFIED_STUB.length < 400);
ok("GENERATED_STUB_SIG is exported + is a RegExp (the detector is inspectable)", GENERATED_STUB_SIG instanceof RegExp);

// ---- B. Origin-discriminating diagnosis (synthetic lanes, no browser) ------------------------------
const cleanCanvas = { bodyLen: 1339, pageErr: false, dataFail: false, corsBlocked: false, crossOriginFetchFails: 0, corsHitCount: 0, generatedStubChunks: [], canvasBody: true, canvasNodes: 6, toolbar: true, panelPresent: true, outputPanel: true, error_reason: "" };
const corsBlockedLane = { bodyLen: 49, pageErr: true, dataFail: true, corsBlocked: true, crossOriginFetchFails: 8, corsHitCount: 40, generatedStubChunks: [], canvasBody: false, canvasNodes: 0, toolbar: false, panelPresent: false, outputPanel: false, error_reason: "Failed to initialize" };
const erroredProxy = { bodyLen: 112, pageErr: true, dataFail: false, corsBlocked: true, crossOriginFetchFails: 0, corsHitCount: 3, generatedStubChunks: [], canvasBody: false, canvasNodes: 0, toolbar: false, panelPresent: false, outputPanel: false, error_reason: "An error occurred" };

ok("canvasClean recognises the reference canvas (graph + ≥3 nodes + toolbar + panel, no error/CORS/stub)", canvasClean(cleanCanvas) === true);
ok("canvasClean rejects a CORS-blocked lane", canvasClean(corsBlockedLane) === false);
ok("canvasClean rejects an otherwise-clean canvas that is CORS-blocked (a CORS block alone disqualifies)", canvasClean({ ...cleanCanvas, corsBlocked: true }) === false);
ok("canvasClean rejects an otherwise-clean canvas serving a generated stub (a stub alone disqualifies)", canvasClean({ ...cleanCanvas, generatedStubChunks: ["deadbeef"] }) === false);
ok("canvasClean requires ≥3 distinct nodes (2 is not a graph)", canvasClean({ ...cleanCanvas, canvasNodes: 2 }) === false);

const dCors = diagnose({ proxyLanding: erroredProxy, matchCanvas: cleanCanvas, crossCanvas: corsBlockedLane, matchOrigin: "http://localhost:9225", crossOrigin: "http://127.0.0.1:9225" });
ok("DIAGNOSIS: matching-origin canvas CLEAN + cross-origin lane CORS-blocked ⇒ cors_origin_mismatch, data complete, NOT missing_chunk, and data_clean=false", dCors.diagnosis === "cors_origin_mismatch" && dCors.reference_data_complete === true && dCors.missing_chunk === false && dCors.data_clean === false && /CORS\/ORIGIN MISMATCH/.test(dCors.blocking_reason), JSON.stringify({ d: dCors.diagnosis, c: dCors.reference_data_complete, m: dCors.missing_chunk, dc: dCors.data_clean }));
ok("DIAGNOSIS: cors_origin_mismatch blocking_reason explicitly states NO re-harvest / NO fresh auth (retracts #37)", /no re-?harvest and no fresh/i.test(dCors.blocking_reason));

const dClean = diagnose({ proxyLanding: cleanCanvas, matchCanvas: cleanCanvas, crossCanvas: cleanCanvas });
ok("DIAGNOSIS: a clean PROXY/harness lane ⇒ data_clean=true, diagnosis=data_clean (the promotion trip-wire)", dClean.data_clean === true && dClean.diagnosis === "data_clean");

const dMissing = diagnose({ proxyLanding: erroredProxy, matchCanvas: { ...cleanCanvas, generatedStubChunks: ["abc123"] }, crossCanvas: corsBlockedLane });
ok("DIAGNOSIS: a genuine generated STUB on the MATCH lane ⇒ missing_chunk (outranks CORS — a real absent chunk is not masked as an origin issue)", dMissing.diagnosis === "missing_chunk" && dMissing.missing_chunk === true && dMissing.generated_stub_chunks.includes("abc123"));

// F2 regression: a stub appearing ONLY on the deliberately-broken cross-origin lane (a CORS-cascade
// artifact) must NOT be read as missing_chunk when the matching-origin canvas is clean — else #38 would
// resurrect the exact #37 misdiagnosis.
const dCrossStub = diagnose({ proxyLanding: erroredProxy, matchCanvas: cleanCanvas, crossCanvas: { ...corsBlockedLane, generatedStubChunks: ["ff00ff"] }, matchOrigin: "http://localhost:9225", crossOrigin: "http://127.0.0.1:9225" });
ok("F2: a stub only on the CROSS-origin (broken) lane ⇒ still cors_origin_mismatch, NOT missing_chunk (the stub-decision set excludes the broken cross lane)", dCrossStub.diagnosis === "cors_origin_mismatch" && dCrossStub.missing_chunk === false && !dCrossStub.generated_stub_chunks.includes("ff00ff"));

// F4 regression: a SINGLE benign cross-origin fetch failure (no CORS console error) must NOT trip
// cors_origin_mismatch; ≥2 cross-origin fails OR an explicit CORS block does.
const crossBenign = { ...corsBlockedLane, corsBlocked: false, crossOriginFetchFails: 1 };
const dBenign = diagnose({ proxyLanding: erroredProxy, matchCanvas: cleanCanvas, crossCanvas: crossBenign });
ok("F4: ONE benign cross-origin fetch failure (no CORS block) does NOT trip cors_origin_mismatch", dBenign.cors_origin_mismatch === false && dBenign.diagnosis !== "cors_origin_mismatch", `diagnosis=${dBenign.diagnosis}`);
const dTwoFails = diagnose({ proxyLanding: erroredProxy, matchCanvas: cleanCanvas, crossCanvas: { ...crossBenign, crossOriginFetchFails: 2 } });
ok("F4: ≥2 cross-origin fetch failures (or an explicit CORS block) DO trip cors_origin_mismatch", dTwoFails.cors_origin_mismatch === true);

const allFail = { bodyLen: 20, pageErr: true, dataFail: true, corsBlocked: false, crossOriginFetchFails: 0, generatedStubChunks: [], canvasBody: false, canvasNodes: 0, toolbar: false, panelPresent: false, outputPanel: false, error_reason: "An error occurred" };
const dFail = diagnose({ proxyLanding: allFail, matchCanvas: allFail, crossCanvas: allFail });
ok("DIAGNOSIS: no clean canvas + no CORS + no stub ⇒ app_data_failure (a genuine data failure is not mislabelled)", dFail.diagnosis === "app_data_failure" && dFail.reference_data_complete === false && dFail.missing_chunk === false);

// ---- C. Stale-artifact guard (the #37 review High, made permanent) ---------------------------------
// Point the planner at a DEAD mirror/serve and pre-seed a STALE {"data_clean":true}. The planner removes
// stale before spawn + parses only on exit 0, so it must report UNKNOWN/BLOCKED — never the stale value.
const staleDir = path.join(appRoot, ".artifacts", "stub-detector-stale-test");
try { rmSync(staleDir, { recursive: true, force: true }); } catch { /* */ }
mkdirSync(staleDir, { recursive: true });
writeFileSync(path.join(staleDir, "result.json"), JSON.stringify({ schema: "STALE-LIE", data_clean: true, diagnosis: "data_clean", reference_data_complete: true, lanes: [], blocking_reason: "" }) + "\n");
const dead = "http://127.0.0.1:59997";
const planner = spawnSync("node", [path.join(here, "reharvest-pipeline-builder.mjs")], { encoding: "utf8", timeout: 60000, env: { ...process.env, IOI_HARNESS_ARTIFACT_DIR: staleDir, IOI_MIRROR_MATCH_ORIGIN: dead, IOI_HYPERVISOR_SERVE_URL: dead, IOI_HARVEST_MIRROR_URL: dead } });
let plan = null;
try { plan = JSON.parse(readFileSync(path.join(staleDir, "reharvest-plan.json"), "utf8")); } catch { /* */ }
ok("STALE GUARD: with a dead mirror + a pre-seeded stale {data_clean:true}, the planner reports NOT-ran (blocked/incomplete), never the stale value", plan && plan.current_data_clean === null && plan.diagnosis === null && plan.preflight_status !== "ran", plan ? `data_clean=${plan.current_data_clean} diagnosis=${plan.diagnosis} status=${plan.preflight_status}` : "no plan emitted");
ok("STALE GUARD: the stale result.json was REMOVED (a dead preflight leaves no consumable artifact)", !existsSync(path.join(staleDir, "result.json")));
ok("STALE GUARD: the planner did NOT print a data-clean claim from the stale file", planner && !/data_clean\s*:\s*TRUE/i.test(planner.stdout || ""));
try { rmSync(staleDir, { recursive: true, force: true }); } catch { /* */ }

// ---- Report ----------------------------------------------------------------------------------------
const passed = results.filter((r) => r.pass).length;
for (const r of results) console.log(`${r.pass ? "✓" : "✗"} ${r.name}${r.detail ? `  — ${r.detail}` : ""}`);
console.log(`\n${passed}/${results.length} checks passed`);
process.exit(passed === results.length ? 0 : 1);
