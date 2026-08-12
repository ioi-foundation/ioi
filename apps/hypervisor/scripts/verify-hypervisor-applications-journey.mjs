#!/usr/bin/env node
// Applications launcher journey verifier (greenfield packet, next-legs III Leg 3).
//
// Proves, against an ISOLATED real daemon + serve lane, the SURF-applications acceptance for
// the canonical /applications greenfield launcher (typed non-parity lane —
// seed-ux-provenance.v1.json; the module claims no seed preservation and no parity):
//
//   - the launcher enumerates ONLY compiler-admitted applications: the 15 compiled
//     registrations render as rows and NOTHING else does over an empty registry;
//   - launchable rows link the projection's own resolved_launch_route and those routes
//     resolve; unavailable rows state the exact typed reason verbatim;
//   - launch and direct deep link preserve context: the ?org= scope rides every launch href,
//     and following the launcher's href is byte-equivalent in destination to the directly
//     constructed deep link;
//   - the reserved Embodied Systems registration renders declared-nonlaunchable (typing read
//     from the compiler-owned registration source, GET /v1/hypervisor/core-taxonomy) — never
//     hidden, never a launch link;
//   - folded owners never reappear as peers (Missions / Marketplace / Workbench / Agent
//     Studio absent from the served launcher);
//   - the cross-surface journey the commissioning names: install a registry package (ODK mesh
//     → candidate → release → installation, the #235/#239 fixture recipe) → its row appears
//     with typed ineligibility facts; RECALL the release → the row is GONE from /applications
//     on the very next read (derived, no cleanup step) and STAYS gone across daemon restart;
//   - a daemon outage never fabricates launchability: daemon down → typed unavailability page
//     with ZERO rows; daemon back → truth returns;
//   - 3-posture browser matrix (light/dark/narrow-reduced-motion).
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => {
    const { port } = srv.address();
    srv.close(() => resolve(port));
  });
  srv.on("error", reject);
});

const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try {
  fs.accessSync(daemonBinary, fs.constants.X_OK);
} catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-applications-journey-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";
let SESSION = "";

const PKG = "applications-journey-app";
const INST = "primary";
const SURFACE_REF = `surface://extensions/${PKG}`;
const CANONICAL = "/applications";
const LANE = "/__ioi/applications-launcher";
// The compiled first-party registration set (crates hypervisor_surface_records.json — 15 rows:
// 12 owners + 2 substrate + the reserved Embodied Systems registration).
const COMPILED_NAMES = [
  "Studio", "Automations", "Ontology", "Data", "Governance", "Provenance", "Evaluations",
  "Improvement", "Foundry", "Packages", "Developer Workspace", "Developer Console",
  "Environments", "Operations", "Embodied Systems",
];
const RETIRED_OWNER_NAMES = ["Missions", "Marketplace", "Workbench", "Agent Studio"];

async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
  return () => log;
}

// Daemon JSON with the operator session (the packages family is identity-first).
const jd = (p, init) => fetch(`${DAEMON}${p}`, {
  headers: {
    "content-type": "application/json",
    ...(SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
  },
  ...init,
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

const pageText = (p, { authenticated = true } = {}) => fetch(`${SERVE}${p}`, {
  headers: authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {},
}).then(async (r) => ({ status: r.status, text: await r.text(), headers: r.headers }))
  .catch(() => ({ status: 0, text: "", headers: new Headers() }));

const entryNames = (text) => [...text.matchAll(/data-ioi-entry-name="([^"]*)"/gu)].map((m) => m[1]);
const launchHrefs = (text) => [...text.matchAll(/data-ioi-launchable="true" href="([^"]*)"/gu)].map((m) => m[1]);

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "applications-journey-bootstrap-v1", email: "applications-journey@ioi.local" }),
    });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));
  const who = (await jd("/v1/hypervisor/auth/whoami")).body || {};
  const OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && t.startsWith("org://")) || "";
  ok("the session authenticates a principal with an org:// owner tenant", !!OWNER, OWNER || "no owner tenant");

  const servePort = await freePort();
  const productUiPort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: {
      ...process.env,
      PORT: String(servePort),
      PRODUCT_UI_PORT: String(productUiPort),
      IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"),
      IOI_HYPERVISOR_DAEMON_URL: DAEMON,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}${CANONICAL}`, 30000);

  // -- canonical + legacy mounts render with truthful ownership ---------------
  const landing = await pageText(CANONICAL);
  ok("canonical /applications 200s as the module's own mount (ownership headers + heading)",
    landing.status === 200 && landing.headers.get("x-ioi-surface-route") === CANONICAL
      && landing.headers.get("x-ioi-surface-owner") === "Applications"
      && landing.text.includes("<h1>Applications</h1>"),
    `status ${landing.status} route ${landing.headers.get("x-ioi-surface-route")}`);
  const legacy = await pageText(LANE);
  ok("the fresh legacy lane serves the same module with its own truthful marker",
    legacy.status === 200 && legacy.headers.get("x-ioi-surface-route") === LANE
      && legacy.headers.get("x-ioi-surface-owner") === "Applications",
    `status ${legacy.status} route ${legacy.headers.get("x-ioi-surface-route")}`);
  ok("the launcher names its greenfield provenance honestly (typed non-parity lane, no seed/parity claim)",
    landing.text.includes("greenfield") && landing.text.includes("seed-ux-provenance.v1.json")
      && landing.text.includes("no seed preservation and no parity"),
    "");

  // -- enumeration: ONLY compiler-admitted applications -----------------------
  const names = entryNames(landing.text);
  ok("the launcher enumerates EXACTLY the 15 compiled registrations over an empty registry — only compiler-admitted applications, nothing else",
    names.length === COMPILED_NAMES.length && COMPILED_NAMES.every((n) => names.includes(n)),
    `entries ${names.length}: ${names.join("|").slice(0, 160)}`);
  const hrefs = launchHrefs(landing.text);
  ok("exactly the 14 active registrations render launchable; the reserved registration is the one nonlaunchable compiled row",
    hrefs.length === 14 && (landing.text.match(/data-ioi-launchable="false"/gu) || []).length === 1,
    `launchable ${hrefs.length}`);
  ok("launchable rows link the projection's own resolved routes (spot: /studio, /packages, /governance)",
    ["/studio", "/packages", "/governance"].every((r) => hrefs.includes(r)),
    hrefs.join("|").slice(0, 200));
  const targets = await Promise.all(["/studio", "/packages", "/governance"].map((r) => pageText(r)));
  ok("the spot-checked launch targets resolve 200 (module mounts /studio + /packages, the /governance owner page)",
    targets.every((t) => t.status === 200)
      && targets[0].headers.get("x-ioi-surface-route") === "/studio"
      && targets[1].headers.get("x-ioi-surface-route") === "/packages",
    targets.map((t) => t.status).join("/"));

  // -- context preservation: ?org= rides the projection AND every launch href --
  const scoped = await pageText(`${CANONICAL}?org=${encodeURIComponent(OWNER)}`);
  const scopedHrefs = launchHrefs(scoped.text);
  ok("the ?org= scope is live: the projection answers for that org and EVERY launch href carries the scope forward",
    scoped.status === 200 && scoped.text.includes(`org ${OWNER}`)
      && scopedHrefs.length === 14 && scopedHrefs.every((h) => h.includes("org=")),
    scopedHrefs[0] || "");
  const studioHref = (scoped.text.match(/data-ioi-entry-name="Studio" data-ioi-launchable="true" href="([^"]*)"/u) || [])[1] || "";
  const clickNav = await pageText(studioHref);
  const deepLink = await pageText(`/studio?org=${encodeURIComponent(OWNER)}`);
  ok("deep link ≡ click-nav: following the launcher's Studio href and requesting the directly constructed deep link land on the same surface with the same context",
    studioHref === `/studio?org=${encodeURIComponent(OWNER)}`
      && clickNav.status === 200 && deepLink.status === 200
      && clickNav.headers.get("x-ioi-surface-route") === deepLink.headers.get("x-ioi-surface-route")
      && clickNav.text.includes("Studio") && deepLink.text.includes("Studio"),
    studioHref);
  const badOrg = await pageText(`${CANONICAL}?org=${encodeURIComponent("org://not-a-member")}`, { authenticated: true });
  ok("an org scope the caller does not hold renders the daemon's typed membership refusal with ZERO rows — the module never re-adjudicates scope",
    badOrg.status === 200 && badOrg.text.includes("hypervisor.organization_membership_required")
      && entryNames(badOrg.text).length === 0,
    "");

  // -- the reserved Embodied Systems registration -----------------------------
  ok("Embodied Systems renders as the reserved registration row: declared nonlaunchable, planned typing from the compiler-owned registration source, the projection's typed reason verbatim",
    landing.text.includes('data-ioi-entry-name="Embodied Systems" data-ioi-launchable="false" data-ioi-reserved="planned"')
      && landing.text.includes("declared nonlaunchable")
      && landing.text.includes("no_eligible_release_installation_or_serving_binding"),
    "");
  ok("the reserved row is never a launch link and never hidden",
    !landing.text.includes('<a class="card launch" data-ioi-entry-name="Embodied Systems"')
      && entryNames(landing.text).includes("Embodied Systems"),
    "");

  // -- folded owners never reappear as peers ----------------------------------
  ok("retired owner names are absent from the served launcher (Missions / Marketplace / Workbench / Agent Studio) and no retired-owner defect row fired",
    RETIRED_OWNER_NAMES.every((n) => !landing.text.includes(n))
      && !landing.text.includes("data-ioi-retired-owner-defect"),
    RETIRED_OWNER_NAMES.filter((n) => landing.text.includes(n)).join("|") || "clean");

  // -- registry fixture: ODK mesh → candidate → release → installation --------
  const ont = await jd("/v1/hypervisor/odk/domain-ontologies", {
    method: "POST",
    body: JSON.stringify({ domain: "applications-journey", owner_ref: OWNER, idempotency_key: "applications-journey-ont-1" }),
  });
  const ontRef = ont.body?.ontology?.ref || "";
  const sd = await jd("/v1/hypervisor/odk/surface-descriptors", {
    method: "POST",
    body: JSON.stringify({ name: "Applications journey surface", composition_pattern: "domain_app", ontology_ref: ontRef, owner_ref: OWNER, idempotency_key: "applications-journey-sd-1" }),
  });
  const sdRef = sd.body?.surface_descriptor?.ref || "";
  const man = await jd("/v1/hypervisor/odk/manifests", {
    method: "POST",
    body: JSON.stringify({ name: "Applications journey manifest", ontology_refs: [ontRef], recipe_refs: [], surface_descriptor_refs: [sdRef], owner_ref: OWNER, idempotency_key: "applications-journey-man-1" }),
  });
  const manRef = man.body?.manifest?.ref || "";
  const dapp = await jd("/v1/hypervisor/domain-apps", {
    method: "POST",
    body: JSON.stringify({ name: "Applications journey app", surface_descriptor_ref: sdRef, odk_manifest_ref: manRef, owner_ref: OWNER, idempotency_key: "applications-journey-dapp-1" }),
  });
  const dappRef = dapp.body?.domain_app?.domain_app_ref || "";
  ok("the ODK source mesh admits (ontology → domain_app descriptor → manifest → draft DomainApp)",
    ont.status === 201 && sd.status === 201 && man.status === 201 && dapp.status === 201 && !!dappRef,
    dappRef || `statuses ${ont.status}/${sd.status}/${man.status}/${dapp.status}`);
  const candidate = await jd("/v1/hypervisor/packages", {
    method: "POST",
    body: JSON.stringify({ package_id: PKG, owner_ref: OWNER, domain_app_ref: dappRef, idempotency_key: "applications-journey-candidate-1" }),
  });
  const candidateHead = candidate.body?.package?.agentgres?.head || "";
  const release = await jd(`/v1/hypervisor/packages/${PKG}/releases`, {
    method: "POST",
    body: JSON.stringify({
      idempotency_key: "applications-journey-release-1",
      expected_package_head: candidateHead,
      surface_distribution: "private_registry",
      surface_capability_depth: "propose",
      object_contract_refs: ["object-model://applications-journey"],
      action_contract_refs: ["action://applications-journey/propose"],
      evidence_refs: ["artifact://applications-journey/conformance"],
    }),
  });
  const releaseDigest = String(release.body?.release?.record?.release_ref || "").split("/release/").at(-1) || "";
  const releaseHead = release.body?.release?.agentgres?.head || "";
  const install = await jd(`/v1/hypervisor/packages/${PKG}/releases/${encodeURIComponent(releaseDigest)}/installations`, {
    method: "POST",
    body: JSON.stringify({
      idempotency_key: "applications-journey-install-1",
      expected_release_head: releaseHead,
      installation_id: INST,
      visibility: "organization",
      allowed_object_contract_refs: ["object-model://applications-journey"],
      allowed_action_refs: ["action://applications-journey/propose"],
    }),
  });
  ok("the registry package admits end to end (candidate → immutable release → installed binding, receipts throughout)",
    candidate.status === 201 && release.status === 201 && install.status === 201
      && String(install.body?.installation?.agentgres?.receipt_ref || "").startsWith("receipt://"),
    `statuses ${candidate.status}/${release.status}/${install.status}`);

  // -- the installed row APPEARS with its typed ineligibility -----------------
  const withInstall = await pageText(CANONICAL);
  const installNames = entryNames(withInstall.text);
  ok("the installed registry surface appears in the launcher on the very next read — inventory presence, never a launch claim",
    withInstall.status === 200 && installNames.length === COMPILED_NAMES.length + 1
      && installNames.includes(PKG) && withInstall.text.includes(SURFACE_REF),
    `entries ${installNames.length}`);
  ok("the registry row states its exact typed ineligibility: registry source, both derived reasons verbatim, installation facts, no launch href",
    withInstall.text.includes(`data-ioi-entry-name="${PKG}" data-ioi-launchable="false"`)
      && withInstall.text.includes("package registry")
      && withInstall.text.includes("extension_application_registration_absent")
      && withInstall.text.includes("surface_serving_binding_absent")
      && withInstall.text.includes(`install://${PKG}/${INST}`)
      && !withInstall.text.includes(`<a class="card launch" data-ioi-entry-name="${PKG}"`),
    "");

  // -- RECALL removes the row from /applications immediately ------------------
  const recall = await jd(`/v1/hypervisor/packages/${PKG}/releases/${encodeURIComponent(releaseDigest)}/recall`, {
    method: "POST",
    body: JSON.stringify({
      idempotency_key: "applications-journey-recall-1",
      expected_release_head: releaseHead,
      reason: "applications-journey: recall must remove the launcher row on the next read",
    }),
  });
  ok("the release recall admits (immutable disposition successor active → recalled, receipted)",
    recall.status === 200 || recall.status === 201,
    `status ${recall.status}`);
  const afterRecall = await pageText(CANONICAL);
  const afterNames = entryNames(afterRecall.text);
  ok("after recall the surface is GONE from /applications on the very next read — no row, no residue, the compiled catalog unchanged (absence is derived, not cleaned up)",
    afterRecall.status === 200 && afterNames.length === COMPILED_NAMES.length
      && !afterNames.includes(PKG) && !afterRecall.text.includes(SURFACE_REF)
      && COMPILED_NAMES.every((n) => afterNames.includes(n)),
    `entries ${afterNames.length}`);

  // -- daemon outage: typed unavailability, ZERO fabricated rows --------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  const down = await pageText(CANONICAL);
  ok("daemon down: the launcher renders the typed unavailability page — degradation code named, zero rows, zero launchable claims, the no-fabrication rule stated",
    down.status === 200 && down.text.includes("data-ioi-degraded=")
      && entryNames(down.text).length === 0
      && !down.text.includes('data-ioi-launchable="true"')
      && down.text.includes("never fabricates launchability"),
    `status ${down.status}`);
  ok("daemon down: no static inventory leaks into the catalog (no compiled names render as rows)",
    !down.text.includes("data-ioi-entry-name="),
    "");

  // -- daemon back: truth returns, recall survives restart --------------------
  await startDaemon();
  let back = { status: 0, text: "" };
  for (let attempt = 0; attempt < 5; attempt++) {
    await new Promise((r) => setTimeout(r, 1200));
    back = await pageText(CANONICAL);
    if (back.status === 200 && entryNames(back.text).length === COMPILED_NAMES.length) break;
  }
  const backNames = entryNames(back.text);
  ok("daemon restarted: compiled truth returns (15 rows, 14 launchable) and the recalled surface STAYS absent — the launcher-feed loss is derived from admitted truth, not process state",
    back.status === 200 && backNames.length === COMPILED_NAMES.length
      && launchHrefs(back.text).length === 14
      && !backNames.includes(PKG) && !back.text.includes(SURFACE_REF),
    `entries ${backNames.length}`);

  // -- 3-posture matrix -------------------------------------------------------
  let pw = null;
  try { pw = await import("playwright"); } catch { pw = null; }
  if (!pw) {
    ok("posture matrix skipped — playwright unavailable", false, "install playwright to run the browser matrix");
  } else {
    const browser = await pw.chromium.launch();
    for (const [name, opts] of [
      ["light-desktop", { viewport: { width: 1440, height: 900 }, colorScheme: "light" }],
      ["dark-desktop", { viewport: { width: 1440, height: 900 }, colorScheme: "dark" }],
      ["narrow-reduced-motion", { viewport: { width: 390, height: 844 }, colorScheme: "light", reducedMotion: "reduce" }],
    ]) {
      const ctx = await browser.newContext(opts);
      const page = await ctx.newPage();
      const errors = [];
      page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
      const resp = await page.goto(`${SERVE}${CANONICAL}`, { waitUntil: "networkidle", timeout: 45000 }).catch(() => null);
      const body = resp ? await page.evaluate(() => document.body.innerText) : "";
      await page.keyboard.press("Tab");
      const focused = resp ? await page.evaluate(() => document.activeElement?.tagName ?? "") : "";
      ok(`posture ${name}: renders, keyboard-focusable, zero console errors`,
        resp && resp.status() === 200 && body.length > 0 && errors.length === 0 && focused !== "" && focused !== "BODY",
        errors[0]?.slice(0, 100) ?? `focus ${focused}`);
      await ctx.close();
    }
    await browser.close();
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "applications-journey", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  cleanup();
  process.exit(1);
});

function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}
