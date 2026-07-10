#!/usr/bin/env node
// ---------------------------------------------------------------------------
// PR #48 — MARKETPLACE BROWSE (LISTINGS) PORT VERIFIER — the SEVENTH certified
// port and the LAST data_clean candidate from the #44 ranking (the clean pool
// is now EMPTY; the program pivots to origin-alignment seeds). Asserts:
//   1. MATRIX: listings is daemon_wired at /__ioi/marketplace/listings over a
//      data_clean reference, with Listings-IA landmarks declared.
//   2. VISUAL PARITY: the hardened harness certifies against /__apps/listings
//      (whose Stores lane is REBOUND to the same substrate; the What's-new
//      modal is dismissed by a UI-only pre-capture hook, error text read first).
//   3. DAEMON TRUTH: the store row is the estate's governed listing plane; the
//      product count = PUBLISHED listings only (the rebind's own wire
//      semantics); a legitimate draft fixture through the REAL daemon route
//      moves the listing count but NOT the published product count; honest
//      when empty; no fake marketplace products.
//   4. OWNER + GAPS: /__ioi/marketplace links the browse port first-class and
//      stays intact; publish/install/hire/settle/runtime lanes are named gaps.
//   5. SHELL-PIXEL CERTIFICATION: committed non-pinned 2-viewport evidence;
//      the store rows are the masked live data (no body pixel claim).
//   6. THE POOL IS CLOSED: the sweep's ranked list is empty — every remaining
//      candidate needs origin alignment or re-harvest, never invention.
// ---------------------------------------------------------------------------
import { readFileSync, existsSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
const jd = (method, p, body) => fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).then((r) => r.json()).catch(() => null);

async function run() {
  const lj = await jd("GET", "/v1/hypervisor/marketplace/listings");
  if (!lj) { console.error("BLOCKED: daemon marketplace plane not reachable at " + DAEMON); process.exit(2); }

  // 1. MATRIX
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const row = (matrix.seeds || []).find((s) => s.slug === "listings");
  ok("matrix: listings is daemon_wired at /__ioi/marketplace/listings with Listings-IA landmarks + the intact /__ioi/marketplace substrate", row && row.parity_class === "daemon_wired" && row.port_surface === "/__ioi/marketplace/listings" && row.candidate_surface === "/__ioi/marketplace/listings" && row.substrate_surface === "/__ioi/marketplace" && Array.isArray(row.reference_landmarks) && row.reference_landmarks.length >= 8, row ? `class=${row.parity_class}` : "row missing");
  ok("matrix: the listings REFERENCE is data_clean per the sweep (its Stores lane is rebound to the same substrate)", row && row.reference_clean_state === "data_clean", row ? row.reference_clean_reason?.slice(0, 80) : "");
  ok("the estate census accepts listings among the certified daemon_wired surfaces (>= 7 since #48); reference_capture stays the honest majority", (matrix.by_parity_class?.daemon_wired || 0) >= 7 && (matrix.by_parity_class?.reference_capture || 0) >= 20, JSON.stringify(matrix.by_parity_class));

  // 2. VISUAL PARITY (the pre-capture hook dismisses the What's-new modal; error text is read pre-hook by capture()).
  const artDir = path.join(appRoot, ".artifacts", "listings-port-verify");
  try { if (existsSync(path.join(artDir, "result.json"))) rmSync(path.join(artDir, "result.json")); } catch { /* */ }
  const h = spawnSync("node", [path.join(here, "harness-reference-parity.mjs")], { encoding: "utf8", timeout: 180000, env: { ...process.env, IOI_HARNESS_SURFACES: "listings", IOI_HARNESS_ARTIFACT_DIR: artDir } });
  let hp = null;
  if (h.status === 0 && existsSync(path.join(artDir, "result.json"))) hp = (JSON.parse(readFileSync(path.join(artDir, "result.json"), "utf8")).surfaces || [])[0];
  ok("harness ran + captured real screenshots (modal-dismissed reference vs the port)", hp && hp.evidence_ok === true, hp ? `ref ${hp.reference_screenshot_bytes}b · ioi ${hp.ioi_screenshot_bytes}b` : "harness did not run");
  ok("CERTIFIED: the hardened harness grants visual_parity (region geometry + theme + landmarks)", hp && hp.visual_parity === true && hp.structural_parity === true, hp ? `visual=${hp.visual_parity} structural=${hp.structural_parity}` : "n/a");
  ok("theme MATCH: reference LIGHT ≡ port LIGHT", hp && hp.theme_match === true && hp.reference_theme === "light" && hp.ioi_theme === "light");
  ok("IA landmarks reproduced (hero + Stores + wizard captions; coverage ≥ 0.8, none missing)", hp && hp.landmark_applicable >= 8 && hp.landmark_covered >= Math.ceil(hp.landmark_applicable * 0.8) && (hp.landmarks_missing || []).length === 0, hp ? `covered ${hp.landmark_covered}/${hp.landmark_applicable}` : "n/a");
  ok("BOTH sides VALID: neither the reference (post modal-dismiss) nor the port is errored", hp && hp.reference_valid === true && hp.reference_errored === false && hp.ioi_valid === true && hp.ioi_errored === false);

  // 3. DAEMON TRUTH — the governed plane row, published-only product count, fixture round-trip.
  const listings0 = (lj.listings || []);
  const published0 = listings0.filter((l) => l.public_state === "published").length;
  const port0 = await page(`${SERVE}/__ioi/marketplace/listings`);
  ok("the store row IS the estate's governed listing plane (linked to the substrate), never a captured store", port0.status === 200 && port0.text.includes("Estate Marketplace — governed listing plane") && port0.text.includes('href="/__ioi/marketplace"'));
  ok(`the product count = PUBLISHED listings only (${published0}) — the rebind's own wire semantics (drafts never count)`, port0.text.includes(`>${published0} product${published0 === 1 ? "" : "s"}`) || new RegExp(`${published0} product`).test(port0.text), `expected ${published0}`);
  ok(`the foot reports the full plane honestly (${listings0.length} listings · ${published0} published)`, new RegExp(`${listings0.length} listing`).test(port0.text) && new RegExp(`${published0} published`).test(port0.text));
  // fixture: a REAL draft over a REAL agent through the existing daemon route (the
  // established marketplace-verifier pattern) — moves the listing count, NOT the
  // published product count; cleaned up after.
  const agents = await fetch(`${DAEMON}/v1/agents`).then((r) => r.json()).catch(() => []);
  const agentId = Array.isArray(agents) && agents[0] && agents[0].id;
  if (agentId) {
    const marker = "verify-listings-port-fixture";
    const created = await jd("POST", "/v1/hypervisor/marketplace/listings", { listing_kind: "agent", subject_ref: agentId, name: marker, description: "draft fixture for the listings port verifier" });
    const fixtureId = created && created.listing && created.listing.id;
    ok("a legitimate draft fixture was created through the REAL daemon route (over a real agent subject)", !!fixtureId, fixtureId || JSON.stringify(created).slice(0, 80));
    const port1 = await page(`${SERVE}/__ioi/marketplace/listings`);
    ok("the fixture moves the LISTING count but not the PUBLISHED product count (a draft is not installable)", new RegExp(`${listings0.length + 1} listing`).test(port1.text) && new RegExp(`${published0} product`).test(port1.text), `listings ${listings0.length + 1} · products ${published0}`);
    if (fixtureId) await jd("DELETE", `/v1/hypervisor/marketplace/listings/${encodeURIComponent(fixtureId)}`);
    const port2 = await page(`${SERVE}/__ioi/marketplace/listings`);
    ok("the fixture is cleaned up and the surface returns to the prior truth", new RegExp(`${listings0.length} listing`).test(port2.text));
  } else {
    ok("no real agent exists to draft a fixture over — SKIPPED honestly (the count assertions above already bind the surface to daemon truth)", true, "no agents");
  }
  ok("no fake marketplace products: the captured store/vendor rows never render (rebind template names absent)", !/Palantir|Foundry DevOps|What's new in Marketplace/.test(port0.text));

  // 4. OWNER + GAPS
  const mk = await page(`${SERVE}/__ioi/marketplace`);
  ok("owner discoverability: /__ioi/marketplace (the substrate: drafts/publish/admission) links the certified browse port first-class", mk.status === 200 && mk.text.includes("/__ioi/marketplace/listings"));
  ok("publish/install/hire/settle/runtime lanes are NAMED GAPS or honestly routed to the substrate — the wizard is reference chrome with the governed path spelled out", /named gap/.test(port0.text) && /reference-only/.test(port0.text) && /draft/.test(port0.text) && (port0.text.match(/disabled|aria-disabled/g) || []).length >= 4);

  // 5. SHELL-PIXEL CERTIFICATION
  {
    let cert = null;
    try { cert = JSON.parse(readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8")); } catch { /* */ }
    ok("matrix: listings is shell_pixel_certified with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/listings.json" && row.parity_class === "daemon_wired");
    ok("the committed certification is REAL: listings slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "listings" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" | ") : "cert missing");
    ok("the certification is MEASUREMENT, not convenience: dilated <= 1.25% AND raw <= 3.0% on every certified viewport, with real certified-shell coverage", cert && cert.viewports.every((v) => v.metrics.shell_diff_dilated_pct <= 1.25 && v.metrics.shell_diff_raw_pct <= 3.0 && v.metrics.coverage.certified_fraction >= 0.05));
    ok("NO full-body pixel claim: the certification is explicitly SHELL-scoped (the store rows are the masked live data, verified semantically above)", cert && /SHELL/i.test(cert.note || "") && /body/i.test(cert.note || ""));
  }

  // 6. THE CLEAN POOL IS CLOSED.
  {
    const sweep = JSON.parse(readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8"));
    const qualifying = (sweep.seeds || []).filter((s) => s.clean_state === "data_clean" && !["daemon_wired", "reference_ported"].includes(s.parity_class));
    ok("the #44 data_clean pool is EMPTY (#45 incidents · #46 explorer · #47 models · #48 listings consumed it) — every remaining candidate needs origin alignment or re-harvest, never invention", (sweep.ranked_next || []).length === 0 && qualifying.length === 0, `${qualifying.length} qualifying · ranked ${(sweep.ranked_next || []).length}`);
  }

  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`listings-port readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}
run().catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
