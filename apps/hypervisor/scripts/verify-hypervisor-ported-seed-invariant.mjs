#!/usr/bin/env node

// verify-hypervisor-ported-seed-invariant — the ported-seed preservation invariant.
//
// CENSUS SHAPE (next-legs IX Leg 4). This verifier was one of three typed exclusions from
// `check:verifier-floors`: it kept an integer counter and printed `N/N checks passed`, but built no
// NAMED assertion records, so the floors gate had no per-assertion evidence to bind. It now emits a
// census and carries a floor.
//
// WHY THE NAMED COUNT IS SMALL AND THE ASSERTION COUNT IS LARGE. Nothing this verifier checks was
// removed or weakened — every assertion still executes, and `assert.ok` still throws on the first
// failure. What changed is RECORDING GRANULARITY: the per-file and per-route sweeps record ONE named
// result each rather than one per item. That is deliberate. A census of ~400 per-asset results would
// pin the floor to the owned bundle's file COUNT, and that fact already has an owner —
// `check:shipped-products` pins the exact file count and tree sha256. A second floor over the same
// number would churn on every asset change while proving nothing the first one does not. The named
// results below are the distinct INVARIANTS; the raw assertion total is reported alongside them so a
// reader can see both numbers.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "../..");
const read = (relative) => fs.readFileSync(path.join(ROOT, relative), "utf8");
const exists = (relative) => fs.existsSync(path.join(ROOT, relative));
const record = JSON.parse(read("apps/hypervisor/ported-seed-preservation.v1.json"));
const matrix = JSON.parse(read("apps/hypervisor/harvest-app-parity-matrix.json"));
const vendorManifest = JSON.parse(read("apps/hypervisor/product-ui/owned/vendor-manifest.json"));
const packageJson = JSON.parse(read("apps/hypervisor/package.json"));
const serveSource = read("apps/hypervisor/scripts/serve-product-ui.mjs");
const agentGuide = read("apps/hypervisor/AGENTS.md");

let checks = 0;
const results = [];

/** One raw assertion. Throws on failure exactly as before; the census counts what EXECUTED. */
function assertOne(value, message) {
  assert.ok(value, message);
  checks += 1;
}

/** One raw assertion that is ALSO a named invariant in the census. */
function check(value, message, name) {
  assertOne(value, message);
  results.push({ name: name ?? message, pass: true });
}

/**
 * A sweep over many items recorded as ONE named invariant.
 *
 * Every item is still asserted individually — `predicate` failing on any item throws with that
 * item's own message, so the failure still names the exact file or route. Only the census entry is
 * singular. See the header for why per-item census entries would duplicate `check:shipped-products`.
 */
function checkEvery(items, predicate, message, name) {
  for (const item of items) assertOne(predicate(item), message(item));
  results.push({ name, pass: true });
}

check(record.status === "active_invariant", "seed preservation must be an active invariant");
check(record.whole_estate_retirement_allowed === false, "whole-estate retirement must remain locked");
checkEvery(
  record.seed_roots,
  (seedRoot) => exists(seedRoot),
  (seedRoot) => `required seed root is missing: ${seedRoot}`,
  "every declared seed root is present on disk",
);
checkEvery(
  record.forbidden_parallel_replacements,
  (forbidden) => !exists(forbidden),
  (forbidden) => `observation-based parallel replacement is present: ${forbidden}`,
  "no observation-based parallel replacement has appeared beside the seed",
);
check(packageJson.scripts?.["serve:product-ui"] === "node scripts/serve-product-ui.mjs", "ported product serve command is missing");
check(!Object.hasOwn(packageJson.scripts || {}, "serve:app"), "parallel app serve command must not replace the ported seed");
check(agentGuide.includes("The ported app UX is the executable product seed"), "repository contributor memory lost the seed invariant");

const manifestFiles = Object.keys(vendorManifest.files || {});
check(manifestFiles.length >= 383, "owned vendor manifest unexpectedly shrank");
checkEvery(
  manifestFiles,
  (relative) => exists(path.posix.join("apps/hypervisor/product-ui/owned/public", relative)),
  (relative) => `owned ported asset is missing: ${relative}`,
  "every asset the owned vendor manifest declares exists on disk",
);

const protectedClasses = new Set(record.protected_seed_classes);
const protectedSlugs = new Set(record.protected_seed_slugs || []);
const matrixProtected = matrix.seeds
  .filter((seed) => protectedClasses.has(seed.parity_class) || protectedSlugs.has(seed.slug))
  .map((seed) => ({
    slug: seed.slug,
    route: protectedSlugs.has(seed.slug) && seed.substrate_surface
      ? seed.substrate_surface
      : seed.candidate_surface || seed.substrate_surface,
    class: protectedSlugs.has(seed.slug) && seed.substrate_surface
      ? "substrate_bound"
      : seed.parity_class,
  }))
  .sort((a, b) => a.slug.localeCompare(b.slug));
const recordProtected = [...record.protected_routes].sort((a, b) => a.slug.localeCompare(b.slug));
check(JSON.stringify(recordProtected) === JSON.stringify(matrixProtected), "protected-route record must exactly match the current ported-seed census");
checkEvery(
  recordProtected,
  (seed) => serveSource.includes(seed.route),
  (seed) => `${seed.slug}: ported route is no longer dispatched by the product server`,
  "every protected ported route is still dispatched by the product server",
);

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

async function waitForReady(url, processHandle) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (processHandle.exitCode !== null) throw new Error(`ported seed server exited early with ${processHandle.exitCode}`);
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`ported seed server did not become ready: ${url}`);
}

async function runLiveProof() {
  const [port, productUiPort] = await Promise.all([freePort(), freePort()]);
  const child = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), PRODUCT_UI_PORT: String(productUiPort) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  try {
    await waitForReady(`http://127.0.0.1:${port}/`, child);
    // Each served route is asserted on all four properties; the four INVARIANTS are the named
    // results, so the live census does not scale with how many protected routes exist.
    const served = [];
    for (const seed of recordProtected) {
      const response = await fetch(`http://127.0.0.1:${port}${seed.route}`, { signal: AbortSignal.timeout(10_000) });
      served.push({ seed, response, body: await response.text() });
    }
    checkEvery(served, ({ response }) => response.status === 200,
      ({ seed, response }) => `${seed.slug}: expected HTTP 200, received ${response.status}`,
      "live: every protected ported route answers HTTP 200");
    checkEvery(served, ({ response }) => (response.headers.get("content-type") || "").includes("text/html"),
      ({ seed }) => `${seed.slug}: expected a rendered HTML app`,
      "live: every protected ported route renders HTML");
    checkEvery(served, ({ body }) => body.length > 1_500,
      ({ seed, body }) => `${seed.slug}: rendered body is too small to be the rich ported UX (${body.length} bytes)`,
      "live: every protected ported route renders the rich ported body, not a stub");
    checkEvery(served, ({ body }) => !/RouteRefusalSurface|hypervisor[.]route_retired|route retirement refusal|<title>Route retired/iu.test(body),
      ({ seed }) => `${seed.slug}: ported route rendered a retirement/refusal substitute`,
      "live: no protected ported route rendered a retirement/refusal substitute");
  } catch (error) {
    throw new Error(`${error.message}\nserver output:\n${output.slice(-8_000)}`);
  } finally {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await new Promise((resolve) => child.once("exit", resolve));
    }
  }
}

const live = process.argv.includes("--live");
if (live) await runLiveProof();
// The live lane executes MORE named invariants than CI does, so — exactly as
// check:provider-transport does — it emits no census: one from it would collide with the floor
// pinned for the lane CI actually runs.
if (!live) {
  emitVerifierCensus({
    verifierId: "ported-seed",
    sourceUrl: import.meta.url,
    results,
  });
}
console.log(
  `verify-hypervisor-ported-seed-invariant: ${results.length}/${results.length} named invariants passed ` +
    `over ${checks} raw assertions${live ? " (live)" : ""}`,
);
