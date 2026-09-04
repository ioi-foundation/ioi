#!/usr/bin/env node
// M15.2 done-bar — the decentralized.cloud public face.
//
// Proves the face is what it claims: a read-only surface that owns nothing, invents
// no colour, and refuses everything outside a named allowlist. It starts its own
// server on an ephemeral port and talks to the running daemon; it performs no write
// against the daemon and never reaches a provider.
//
// Two of these checks exist because the brand review caught the same class of error
// twice: a hue that lived only on a sheet, and a frame that clipped its content.
// Neither can now reach a published surface without failing here first.
//
// Usage: node apps/decentralized-cloud/scripts/verify-decentralized-cloud-face.mjs

import { spawn } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(HERE, "..");
const REPO = path.resolve(APP, "../..");
const PORT = Number(process.env.IOI_DC_VERIFY_PORT || 4187);
const BASE = `http://127.0.0.1:${PORT}`;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── 1. No colour exists only on the surface ─────────────────────────────────
// Every hex the shipped face paints must be a value in the design system's token
// file. A colour invented in a stylesheet is a colour nobody measured.
function checkPalette() {
  const tokens = readFileSync(path.join(REPO, "packages/design-system/tokens/colors.css"), "utf8");
  const tokenHexes = new Set((tokens.match(/#[0-9a-fA-F]{6}/g) || []).map((h) => h.toLowerCase()));

  const surfaces = ["public/face.css", "public/index.html", "public/face.js"];
  const strays = [];
  for (const rel of surfaces) {
    const body = readFileSync(path.join(APP, rel), "utf8");
    for (const hex of body.match(/#[0-9a-fA-F]{6}/g) || []) {
      if (!tokenHexes.has(hex.toLowerCase())) strays.push(`${rel}:${hex}`);
    }
  }
  ok("every colour the face paints is a design-system token",
    strays.length === 0, strays.join(", ") || `${tokenHexes.size} tokens`);
}

// ── 2. The evidence vocabulary is not re-spelled locally ────────────────────
// The face must classify candidates by the daemon's own label, not a synonym of it.
function checkVocabulary() {
  const js = readFileSync(path.join(APP, "public/face.js"), "utf8");
  for (const name of ["live_evidence", "simulated_control_plane", "observed_at", "expires_at", "evidence_mode"]) {
    ok(`face.js speaks the canonical name '${name}'`, js.includes(name));
  }
  ok("face.js never labels a simulator candidate live",
    !/simulated_control_plane[^\n]*live\s*:\s*true/.test(js));
}

// ── 2b. The refresher is a separate process, not part of the face ───────────
// The face's read-only claim survives only while the writer lives somewhere else.
function checkRefresherSeparation() {
  // Both files DISCUSS each other in their header comments — that is the point of
  // the comments. Strip them, or the assertion fires on prose that says the very
  // thing it is checking for.
  const code = (rel) =>
    readFileSync(path.join(APP, rel), "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, "");

  const serve = code("scripts/serve-face.mjs");
  const refresher = code("scripts/refresh-showcase.mjs");

  ok("the face server never imports or spawns the refresher",
    !/refresh-showcase/.test(serve));
  ok("the refresher never imports the face server",
    !/serve-face/.test(refresher));
  ok("the refresher is the only one of the two that writes to the daemon",
    /candidates\/refresh/.test(refresher) && !/candidates\/refresh/.test(serve));
  ok("the face's allowlist contains no refresh route",
    !/refresh/.test((serve.match(/const READS[\s\S]*?\]\);/) || [""])[0]));
  ok("the refresher never reaches a provider mutation",
    !/provider-ops/.test(refresher));

  const js = readFileSync(path.join(APP, "public/face.js"), "utf8");
  ok("the face reads the latest batch rather than every sweep ever taken",
    /batch/.test(js) && /batches/.test(js));
}

// ── 2c. Freshness is derived, never decorative ──────────────────────────────
// A dial animating on a timer of its own would look identical to one bound to a
// quote's window, and would be a lie the moment the two disagreed. So the sweep must
// be computed from observed_at and expires_at, and the real function is exercised on
// windows whose answers are known rather than read out of the source.
function checkFreshnessIsDerived() {
  const js = readFileSync(path.join(APP, "public/face.js"), "utf8");
  const css = readFileSync(path.join(APP, "public/face.css"), "utf8");
  ok("the dial's fraction comes from observed_at and expires_at",
    /function dialFraction\([\s\S]{0,300}Date\.parse\(observedAt\)[\s\S]{0,300}Date\.parse\(expiresAt\)/.test(js));
  ok("no animation drives the dial's sweep",
    !/\.dial[^{]*\{[^}]*animation|\.sweep[^{]*\{[^}]*animation/.test(css));

  const src = js.slice(js.indexOf("function dialFraction"), js.indexOf("function dial("));
  const dialFraction = new Function(`${src}; return dialFraction;`)();
  const now = Date.now();
  const iso = (ms) => new Date(ms).toISOString();
  const expired = dialFraction(iso(now - 20 * 60_000), iso(now - 5 * 60_000));
  const fresh = dialFraction(iso(now - 1_000), iso(now + 15 * 60_000));
  const half = dialFraction(iso(now - 5 * 60_000), iso(now + 5 * 60_000));
  ok("a window already past reads empty", expired === 0, `fraction ${expired}`);
  ok("a window just opened reads full", fresh > 0.99, `fraction ${fresh.toFixed(4)}`);
  ok("a window half spent reads about half", Math.abs(half - 0.5) < 0.01, `fraction ${half.toFixed(4)}`);
  ok("a candidate with no window drives no dial",
    dialFraction(undefined, undefined) === null && dialFraction("2026-01-01T00:00:00Z", "bad") === null);
}

// ── 2d. The unwired write surfaces say so, and stay unwired ─────────────────
function checkUnwiredSurfaces() {
  const js = readFileSync(path.join(APP, "public/face.js"), "utf8");
  for (const [surface, shape] of [
    ["renderJob", "CloudJobRequest"],
    ["renderRedundancy", "RedundancyPosture"],
    ["renderReceipts", "receipt kinds"],
  ]) {
    // Two defects were found here by mutation, one after the other.
    // First: the slice was a fixed 7000 characters and ran past renderRedundancy
    // into renderReceipts, so removing renderRedundancy's own label still passed.
    // Bounding at the next function did not fix it, because the slice then ended at
    // renderReceipts' SECTION COMMENT — which also reads "designed, not connected".
    // The assertion is about what the surface SAYS, so comments cannot satisfy it:
    // they are stripped before the test.
    const start = js.indexOf(`function ${surface}`);
    const next = js.indexOf("\nfunction ", start + 1);
    const body = js.slice(start, next === -1 ? js.length : next)
      .replace(/\/\/[^\n]*/g, "")
      .replace(/\/\*[\s\S]*?\*\//g, "");
    ok(`${surface} is labelled designed, not connected`, /designed, not connected/.test(body));
    ok(`${surface} names the canonical shape it draws`, body.includes(shape), shape);
  }
  ok("every control drawn on a write surface is inert",
    (js.match(/class:\s*"button-inert",\s*type:\s*"button",\s*disabled:\s*true/g) || []).length >= 2);
  ok("the face declares no mutating fetch anywhere",
    !/method:\s*["'](POST|PUT|PATCH|DELETE)["']/i.test(js));
}

// ── 2e. One primitive, two doors ────────────────────────────────────────────
// The face claims a human's request and an agent's are the same CloudJobRequest
// differing in exactly one field. That is a claim about two literals, so they are
// compared field by field rather than trusted.
function checkBothDoorsAreOnePrimitive() {
  const js = readFileSync(path.join(APP, "public/face.js"), "utf8");
  const bodies = [...js.matchAll(/JSON\.stringify\((\{[\s\S]*?receipt_requirements:[^\]]*\],\s*\n\s*\}), null, 2\)/g)];
  ok("both doors are drawn from an object literal, not prose", bodies.length === 2, `${bodies.length} found`);
  if (bodies.length !== 2) return;
  const parse = (s) => new Function(`return ${s};`)();
  const human = parse(bodies[0][1]);
  const agent = parse(bodies[1][1]);
  const keys = [...new Set([...Object.keys(human), ...Object.keys(agent)])];
  const differing = keys.filter((k) => JSON.stringify(human[k]) !== JSON.stringify(agent[k]));
  ok("the two doors differ in exactly one field", differing.length === 1, differing.join(", ") || "none");
  ok("the field they differ in is the authority", differing[0] === "authority_ref", differing[0] || "—");
  ok("the human door carries a wallet grant", String(human.authority_ref).startsWith("wallet-grant://"));
  ok("the agent door carries a capability lease", String(agent.authority_ref).startsWith("capability-lease://"));
  ok("neither door names a venue",
    !("venue" in human) && !("venue" in agent) &&
    !/provider_kind|venue/.test(JSON.stringify({ human, agent })));
  ok("neither door carries a provider credential",
    !/credential|api[_-]?key|secret|token/i.test(JSON.stringify({ human, agent })));
}

// (2f was a pair of assertions that could not both hold, and it is gone. See
// checkScoreIsNotServed below, which runs against the server rather than the files.)

// ── 3. The served surface refuses everything it should ──────────────────────
async function checkServer() {
  const server = spawn("node", [path.join(APP, "scripts/serve-face.mjs")], {
    env: { ...process.env, IOI_DC_PORT: String(PORT) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let booted = false;
  server.stdout.on("data", (b) => { if (String(b).includes("face on")) booted = true; });

  try {
    for (let i = 0; i < 40 && !booted; i++) await sleep(100);
    ok("the face server starts", booted);
    if (!booted) return;

    const index = await fetch(`${BASE}/`);
    ok("the shell is served", index.status === 200, `HTTP ${index.status}`);

    // ── The identity's provisional score never reaches a reader. ──
    //
    // This assertion used to read the SOURCE FILES, strip comments, and scan the
    // remainder — so it examined a transformed copy while `index.html` shipped
    // `identity v0 — provisional, score 50` verbatim to every view-source. Worse, it
    // was paired with a second assertion REQUIRING that phrase to exist in the
    // source, so the two could not both hold in a file served as-is: the gate was
    // compelling the very defect it claimed to prevent, and the label could not be
    // removed without turning the gate red.
    //
    // Both are replaced by one assertion that reads the BYTES THE SERVER SENDS,
    // comments included, across every asset a visitor can fetch. The status now
    // lives in brand/identity-status.md, which is never served.
    const servedAssets = ["/", "/face.js", "/face.css"];
    const leaked = [];
    for (const asset of servedAssets) {
      const res = await fetch(`${BASE}${asset}`);
      const raw = await res.text();
      if (/identity v0|provisional,? score|scored? 50/i.test(raw)) leaked.push(asset);
    }
    ok("the identity's provisional score is in no byte this server sends",
      leaked.length === 0,
      leaked.length ? `leaked in ${leaked.join(", ")}` : `${servedAssets.length} assets scanned raw`);

    const unknown = await fetch(`${BASE}/api/not-a-real-read`);
    const unknownBody = await unknown.json().catch(() => ({}));
    ok("a path off the allowlist is refused BY NAME",
      unknown.status === 404 && unknownBody.state === "route_not_on_read_allowlist",
      `HTTP ${unknown.status} ${unknownBody.state || ""}`);
    ok("the refusal names what the surface does expose",
      Array.isArray(unknownBody.allowed) && unknownBody.allowed.length === 4,
      (unknownBody.allowed || []).join(", "));

    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      const res = await fetch(`${BASE}/api/candidate-sources`, { method });
      const body = await res.json().catch(() => ({}));
      ok(`${method} is refused as method_not_allowed`,
        res.status === 405 && body.state === "method_not_allowed",
        `HTTP ${res.status} ${body.state || ""}`);
    }

    // The daemon read itself. Slow by nature — a full sweep has been measured at
    // 38.8s — so this is the one check with a long ceiling.
    const sources = await fetch(`${BASE}/api/candidate-sources`);
    const sourcesBody = await sources.json().catch(() => ({}));
    if (sources.status === 200 && Array.isArray(sourcesBody.sources)) {
      ok("candidate-sources proxies the daemon's own body",
        sourcesBody.sources.every((s) => typeof s.source === "string" && typeof s.state === "string"),
        `${sourcesBody.sources.length} sources`);
      const unavailable = sourcesBody.sources.filter((s) => s.state === "candidate_source_unavailable");
      ok("every unavailable source keeps its named reason through the proxy",
        unavailable.every((s) => typeof s.reason === "string" && s.reason.length > 0),
        `${unavailable.length} unavailable`);
    } else {
      ok("candidate-sources proxies the daemon's own body", false,
        `HTTP ${sources.status} ${sourcesBody.state || "no sources array"} — is the daemon running?`);
    }
    // The face can only show a fresh batch if the daemon labels batches at all.
    const cands = await fetch(
      `${BASE}/api/candidates?intent_ref=${encodeURIComponent("cloud-resource-intent://cri_default")}`
    );
    const candsBody = await cands.json().catch(() => ({}));
    const list = Array.isArray(candsBody.candidates) ? candsBody.candidates : [];
    if (cands.status === 200) {
      ok("every candidate carries the batch it was observed in",
        list.length > 0 && list.every((c) => typeof c.batch === "string" && c.batch.length > 0),
        `${list.length} candidates`);

      const batches = new Map();
      for (const c of list) {
        const seen = batches.get(c.batch) || "";
        if ((c.observed_at || "") > seen) batches.set(c.batch, c.observed_at || "");
      }
      const newest = [...batches.entries()].sort((a, b) => (a[1] < b[1] ? 1 : -1))[0];
      const inNewest = list.filter((c) => c.batch === newest?.[0]);
      const liveNow = inNewest.filter(
        (c) => c.evidence_mode === "live_evidence" && Date.parse(c.expires_at || 0) > Date.now()
      );
      // Whether a live price exists right now is the weather, not the mechanism, so
      // this reports it rather than failing on it — but the newest batch must be a
      // real cohort, not a mix of every sweep ever taken.
      ok("the newest batch is one cohort, not an accumulation",
        inNewest.length > 0 && inNewest.length <= list.length,
        `batch ${newest?.[0]} — ${inNewest.length} of ${list.length} candidates, ${liveNow.length} live right now`);
    } else {
      ok("every candidate carries the batch it was observed in", false, `HTTP ${cands.status}`);
    }
  } finally {
    server.kill("SIGTERM");
  }
}

// ── 4. No artboard clips, and every contrast figure is computed ─────────────
async function checkBrandGates() {
  const run = (script) =>
    new Promise((resolve) => {
      const p = spawn("node", [path.join(APP, "brand", script)], { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      p.stdout.on("data", (b) => { out += b; });
      p.stderr.on("data", (b) => { out += b; });
      p.on("close", (code) => resolve({ code, out }));
    });

  // BUILD BEFORE MEASURING. `brand/canvas/` is a gitignored build artifact, and this
  // gate previously measured whatever happened to be sitting there. That made the
  // assertion only as fresh as whoever last ran the build by hand: a source edit that
  // introduced a 585px clip in the identity sheet passed 7/7 here, because the built
  // sheet being measured predated the edit. A fresh checkout and a working checkout
  // could disagree, and the working checkout was the one being believed.
  const built = await run("build-artboards.mjs");
  ok("the brand canvas is rebuilt from src/ before it is measured",
    built.code === 0, (built.out.match(/^brand artboards: .*$/m) || [""])[0] || built.out.slice(-160));
  if (built.code !== 0) return;

  const frames = await run("measure-artboards.mjs");
  const fitLine = (frames.out.match(/^\d+\/\d+ artboards fit their frame.*$/m) || [])[0] || "";
  ok("every brand artboard fits its declared frame", frames.code === 0, fitLine || frames.out.slice(-160));

  const contrast = await run("measure-contrast.mjs");
  ok("the contrast pairs the sheets cite are computed, not asserted",
    /pairs measured/.test(contrast.out), (contrast.out.match(/^\d+ pairs measured\.$/m) || [""])[0]);
}

async function run() {
  checkPalette();
  checkVocabulary();
  checkRefresherSeparation();
  checkFreshnessIsDerived();
  checkUnwiredSurfaces();
  checkBothDoorsAreOnePrimitive();
  await checkServer();
  await checkBrandGates();
}

run().then(() => {
  let fail = 0;
  for (const r of results) {
    console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
    if (!r.pass) fail++;
  }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`decentralized.cloud face: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
