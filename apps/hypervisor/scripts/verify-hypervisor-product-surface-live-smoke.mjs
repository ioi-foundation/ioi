#!/usr/bin/env node
// Self-contained live integration smoke for the taxonomy-v2 product-surface projection.
//
// The compiler verifier proves registration and placement invariants in-process. This verifier
// additionally proves that a freshly spawned product serve exposes that projection through the
// public adapter, preserves the safe bundled first-party catalog, and presents compatibility
// roots under their current canonical product identities.

import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..");
const SERVE = join(HERE, "serve-product-ui.mjs");
const results = [];

function check(name, condition, detail = "") {
  results.push({ name, pass: Boolean(condition), detail });
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : null;
      server.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

async function waitForServe(base) {
  let lastError = null;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try {
      const response = await fetch(`${base}/__ioi/api/applications`);
      if (response.ok) return;
      lastError = new Error(`status ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`product serve did not become ready: ${lastError?.message || "unknown error"}`);
}

async function stop(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  const exited = new Promise((resolve) => child.once("exit", resolve));
  const timedOut = await Promise.race([
    exited.then(() => false),
    new Promise((resolve) => setTimeout(() => resolve(true), 2000)),
  ]);
  if (timedOut && child.exitCode === null) child.kill("SIGKILL");
}

function headingMatches(html, identity) {
  return new RegExp(`<h1[^>]*>\\s*${identity}(?:\\s|<)`).test(html);
}

async function run() {
  const [port, productUiPort] = await Promise.all([freePort(), freePort()]);
  const base = `http://127.0.0.1:${port}`;
  let logs = "";
  const child = spawn(process.execPath, [SERVE], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      PRODUCT_UI_PORT: String(productUiPort),
      IOI_HYPERVISOR_DAEMON_URL: "http://127.0.0.1:1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => { logs += chunk.toString(); });
  child.stderr.on("data", (chunk) => { logs += chunk.toString(); });

  try {
    await waitForServe(base);

    const catalogResponse = await fetch(`${base}/__ioi/api/applications`);
    const catalog = await catalogResponse.json();
    const applications = Array.isArray(catalog.applications) ? catalog.applications : [];
    const enduring = applications.filter((entry) => entry.registration_kind === "owner_application" && entry.owner_cohort === "enduring");
    const conditional = applications.filter((entry) => entry.registration_kind === "owner_application" && entry.owner_cohort === "conditional");
    const substrate = applications.filter((entry) => entry.registration_kind === "substrate_application");

    check("live catalog endpoint serves taxonomy v2", catalogResponse.ok && catalog.schema === "ioi.hypervisor.application-catalog.v2");
    check("live projection names its transitional boundaries", catalog.projection_state === "transitional_static" && catalog.policy_filtering_state === "not_connected" && catalog.extension_inventory_state === "not_connected");
    check("live target census is exact", (catalog.core_workspaces || []).length === 5 && enduring.length === 12 && conditional.length === 1 && substrate.length === 2);
    check("live contextual census is exact", (catalog.tools || []).length === 12 && (catalog.workspace_views || []).length === 1);
    check("legacy flattened catalog shape is absent", !Object.prototype.hasOwnProperty.call(catalog, "apps"));
    check("retired peer identities are absent live", !applications.some((entry) => ["application:missions", "application:marketplace", "application:workbench"].includes(entry.ref)));

    const routes = [
      ["/__ioi/applications", "Applications"],
      ["/__ioi/missions", "Work"],
      ["/__ioi/marketplace", "Packages"],
      ["/__ioi/workbench", "Developer Workspace"],
    ];
    for (const [route, identity] of routes) {
      const response = await fetch(`${base}${route}`);
      const html = await response.text();
      check(`${route} presents ${identity}`, response.ok && headingMatches(html, identity), `status ${response.status}`);
    }

    const augmentationResponse = await fetch(`${base}/ioi-augmentation.js`);
    const augmentation = await augmentationResponse.text();
    const syntax = spawnSync(process.execPath, ["--check"], { input: augmentation, encoding: "utf8" });
    check("augmentation is syntactically valid", augmentationResponse.ok && syntax.status === 0, syntax.stderr || "");
    check("augmentation carries a safe first-party baseline", augmentation.includes("window.__ioiStaticProductSurfaceCatalog="));
  } finally {
    await stop(child);
  }

  for (const result of results) {
    console.log(`${result.pass ? "PASS" : "FAIL"}  ${result.name}${result.detail ? ` — ${result.detail.trim()}` : ""}`);
  }
  const passed = results.filter((result) => result.pass).length;
  console.log(`\n${passed}/${results.length} passed`);
  if (passed !== results.length) {
    if (logs.trim()) console.error(`\nspawned serve output:\n${logs.trim()}`);
    process.exit(1);
  }
  console.log("product-surface live smoke: OK");
}

run().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
