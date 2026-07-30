#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

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
function check(value, message) {
  assert.ok(value, message);
  checks += 1;
}

check(record.status === "active_invariant", "seed preservation must be an active invariant");
check(record.whole_estate_retirement_allowed === false, "whole-estate retirement must remain locked");
for (const seedRoot of record.seed_roots) check(exists(seedRoot), `required seed root is missing: ${seedRoot}`);
for (const forbidden of record.forbidden_parallel_replacements) check(!exists(forbidden), `observation-based parallel replacement is present: ${forbidden}`);
check(packageJson.scripts?.["serve:product-ui"] === "node scripts/serve-product-ui.mjs", "ported product serve command is missing");
check(!Object.hasOwn(packageJson.scripts || {}, "serve:app"), "parallel app serve command must not replace the ported seed");
check(agentGuide.includes("The ported app UX is the executable product seed"), "repository contributor memory lost the seed invariant");

const manifestFiles = Object.keys(vendorManifest.files || {});
check(manifestFiles.length >= 383, "owned vendor manifest unexpectedly shrank");
for (const relative of manifestFiles) {
  check(exists(path.posix.join("apps/hypervisor/product-ui/owned/public", relative)), `owned ported asset is missing: ${relative}`);
}

const protectedClasses = new Set(record.protected_seed_classes);
const matrixProtected = matrix.seeds
  .filter((seed) => protectedClasses.has(seed.parity_class))
  .map((seed) => ({
    slug: seed.slug,
    route: seed.candidate_surface || seed.substrate_surface,
    class: seed.parity_class,
  }))
  .sort((a, b) => a.slug.localeCompare(b.slug));
const recordProtected = [...record.protected_routes].sort((a, b) => a.slug.localeCompare(b.slug));
check(JSON.stringify(recordProtected) === JSON.stringify(matrixProtected), "protected-route record must exactly match the current ported-seed census");
for (const seed of recordProtected) {
  check(serveSource.includes(seed.route), `${seed.slug}: ported route is no longer dispatched by the product server`);
}

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
    for (const seed of recordProtected) {
      const response = await fetch(`http://127.0.0.1:${port}${seed.route}`, { signal: AbortSignal.timeout(10_000) });
      const body = await response.text();
      check(response.status === 200, `${seed.slug}: expected HTTP 200, received ${response.status}`);
      check((response.headers.get("content-type") || "").includes("text/html"), `${seed.slug}: expected a rendered HTML app`);
      check(body.length > 1_500, `${seed.slug}: rendered body is too small to be the rich ported UX (${body.length} bytes)`);
      check(!/RouteRefusalSurface|hypervisor[.]route_retired|route retirement refusal|<title>Route retired/iu.test(body), `${seed.slug}: ported route rendered a retirement/refusal substitute`);
    }
  } catch (error) {
    throw new Error(`${error.message}\nserver output:\n${output.slice(-8_000)}`);
  } finally {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await new Promise((resolve) => child.once("exit", resolve));
    }
  }
}

if (process.argv.includes("--live")) await runLiveProof();
console.log(`verify-hypervisor-ported-seed-invariant: ${checks}/${checks} checks passed${process.argv.includes("--live") ? " (live)" : ""}`);
