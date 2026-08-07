import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  DEFAULT_REPO_ROOT,
  loadShippedProductsManifest,
  routeInventorySha256,
  validateShippedProductsManifest as validateManifest,
} from "./shipped-products-manifest.mjs";

const clone = (value) => structuredClone(value);
const execFileAsync = promisify(execFile);
const validateShippedProductsManifest = (manifest, options = {}) =>
  validateManifest(manifest, { phase: "structure-only", ...options });

test("the authoritative shipped-products manifest covers and verifies the executable estate", async () => {
  const manifest = await loadShippedProductsManifest();
  const report = await validateShippedProductsManifest(manifest);
  // Seven, not eight: the owner's 2026-08-07 ruling is that there is ONE ioi.ai application, so
  // the dual runtime invented beside apps/ioi-ai stopped being a tracked product lane and its
  // manifest entry was removed. These counts were left at the old value when that landed.
  assert.equal(report.product_count, 7);
  assert.equal(report.nonshipped_root_count, 5);
  assert.equal(report.source_graphs.length, 7);
  assert.equal(report.artifacts[0].verified, true);
});

test("validator rejects duplicate and missing products", async (t) => {
  const source = await loadShippedProductsManifest();
  await t.test("duplicate", async () => {
    const manifest = clone(source);
    manifest.products.push(clone(manifest.products[0]));
    await assert.rejects(
      validateShippedProductsManifest(manifest, {
        laneId: "hypervisor-vite-workbench",
      }),
      /duplicate product id hypervisor-owned-served-ui/u,
    );
  });
  await t.test("missing", async () => {
    const manifest = clone(source);
    manifest.products = manifest.products.filter(
      (product) => product.id !== "sas-xyz",
    );
    await assert.rejects(
      validateShippedProductsManifest(manifest, {
        laneId: "hypervisor-vite-workbench",
      }),
      /missing shipped products: sas-xyz/u,
    );
  });
});

test("validator rejects unknown dispositions, modes, and release posture", async (t) => {
  const source = await loadShippedProductsManifest();
  for (const [field, value, expected] of [
    ["disposition", "maybe-shipped", /unknown disposition maybe-shipped/u],
    [
      "state_authority_mode",
      "browser-trust",
      /unknown state authority mode browser-trust/u,
    ],
    [
      "release_posture",
      "sort-of-live",
      /unknown release posture sort-of-live/u,
    ],
  ]) {
    await t.test(field, async () => {
      const manifest = clone(source);
      const product = manifest.products.find(
        (candidate) => candidate.id === "hypervisor-web",
      );
      product[field] = value;
      await assert.rejects(
        validateShippedProductsManifest(manifest, { laneId: product.id }),
        expected,
      );
    });
  }
  await t.test("static boundary mode", async () => {
    const manifest = clone(source);
    const product = manifest.products.find(
      (candidate) => candidate.id === "hypervisor-web",
    );
    product.permitted_static_boundary.mode = "anything-goes";
    await assert.rejects(
      validateShippedProductsManifest(manifest, { laneId: product.id }),
      /unknown static boundary mode anything-goes/u,
    );
  });
  await t.test("nonshipped disposition", async () => {
    const manifest = clone(source);
    manifest.nonshipped_roots[0].disposition = "quietly-shipped";
    await assert.rejects(
      validateShippedProductsManifest(manifest, {
        laneId: "hypervisor-web",
      }),
      /unknown disposition quietly-shipped/u,
    );
  });
});

test("validator rejects nonexistent entries and an unverified shipped lane", async (t) => {
  const source = await loadShippedProductsManifest();
  await t.test("nonexistent entry", async () => {
    const manifest = clone(source);
    const product = manifest.products.find(
      (candidate) => candidate.id === "hypervisor-vite-workbench",
    );
    product.production_entries.push("apps/hypervisor/src/does-not-exist.tsx");
    await assert.rejects(
      validateShippedProductsManifest(manifest, { laneId: product.id }),
      /production entry does not exist/u,
    );
  });
  await t.test("unverified lane", async () => {
    const manifest = clone(source);
    const product = manifest.products.find(
      (candidate) => candidate.id === "hypervisor-web",
    );
    product.required_verification = [];
    await assert.rejects(
      validateShippedProductsManifest(manifest, { laneId: product.id }),
      /shipped lane is unverified/u,
    );
  });
});

test("validator rejects a quarantined fixture as a production graph entry", async () => {
  const manifest = await loadShippedProductsManifest();
  const product = manifest.products.find(
    (candidate) => candidate.id === "aiagent-xyz",
  );
  product.source_graph.entries.push("fixtures/legacy-ui/pages/Home.jsx");
  await assert.rejects(
    validateShippedProductsManifest(manifest, { laneId: product.id }),
    /quarantined fixture entered the production graph/u,
  );
});

test("validator rejects a verification command that is not backed by a package script", async () => {
  const manifest = await loadShippedProductsManifest();
  const product = manifest.products.find(
    (candidate) => candidate.id === "benchmarks",
  );
  product.required_verification.find(
    (verification) => verification.id === "generated-evidence-tests",
  ).command = "npm run definitely-not-a-real-script";
  await assert.rejects(
    validateShippedProductsManifest(manifest, { laneId: product.id }),
    /references missing package script package\.json#definitely-not-a-real-script/u,
  );
});

test("validator rejects a cross-lane production entry even when the file exists", async () => {
  const manifest = await loadShippedProductsManifest();
  const product = manifest.products.find(
    (candidate) => candidate.id === "aiagent-xyz",
  );
  product.production_entries.push("apps/sas-xyz/src/main.js");
  await assert.rejects(
    validateShippedProductsManifest(manifest, { laneId: product.id }),
    /production entry crosses its declared lane ownership: apps\/sas-xyz\/src\/main\.js/u,
  );
});

test("validator rejects a route-list shrink against its immutable count and digest", async () => {
  const manifest = await loadShippedProductsManifest();
  const product = manifest.products.find(
    (candidate) => candidate.id === "developers-ioi-ai",
  );
  product.route_inventory.routes.pop();
  await assert.rejects(
    validateShippedProductsManifest(manifest, { laneId: product.id }),
    /route_inventory count mismatch[\s\S]*route_inventory digest mismatch/u,
  );
});

async function fixtureRepository(t, { buildArtifact = false } = {}) {
  const repoRoot = await mkdtemp(
    path.join(os.tmpdir(), "ioi-shipped-products-manifest-test-"),
  );
  t.after(() => rm(repoRoot, { recursive: true, force: true }));
  await mkdir(path.join(repoRoot, "app"), { recursive: true });
  await Promise.all([
    writeFile(
      path.join(repoRoot, "package.json"),
      `${JSON.stringify(
        {
          private: true,
          scripts: {
            browser: "node verify-browser.mjs",
            build: "node build.mjs",
            test: "node verify-test.mjs",
          },
          workspaces: [],
        },
        null,
        2,
      )}\n`,
    ),
    writeFile(path.join(repoRoot, "owner.md"), "# Fixture owner\n"),
    writeFile(
      path.join(repoRoot, "app", "index.html"),
      '<script type="module" src="./main.js"></script>\n',
    ),
    writeFile(
      path.join(repoRoot, "app", "main.js"),
      'export const fixtureMarker = "fixture-owned-route";\n',
    ),
    writeFile(path.join(repoRoot, "build.mjs"), "// fixture build producer\n"),
    writeFile(
      path.join(repoRoot, "verify-browser.mjs"),
      "// fixture browser check\n",
    ),
    writeFile(
      path.join(repoRoot, "verify-test.mjs"),
      "// fixture integration check\n",
    ),
  ]);
  const routes = ["/"];
  const manifest = {
    schema_version: "ioi.shipped-products.v1",
    authority: "Fixture authority",
    required_shipped_product_ids: ["fixture-product"],
    products: [
      {
        id: "fixture-product",
        name: "Fixture product",
        owner: "Fixture owner",
        owner_ref: "owner.md",
        disposition: "shipped",
        release_posture: "development_only",
        root: "app",
        path_ownership: {
          lane_roots: ["app"],
          shared_dependencies: [],
        },
        production_entries: ["app/index.html", "app/main.js"],
        build_artifacts: [
          {
            path: "app/dist",
            materialization: "generated",
            digest_policy: "record",
            producer: { package_json: "package.json", script: "build" },
          },
        ],
        route_sources: ["app/main.js"],
        route_inventory: {
          inventory_version: 1,
          routes,
          expected_count: routes.length,
          sha256: routeInventorySha256(routes),
          browser_verification_id: "browser",
        },
        state_authority_mode: "presentation_only",
        source_graph: {
          root: "app",
          entries: ["index.html"],
          allowed_source_roots: [],
          quarantined_roots: [],
        },
        permitted_static_boundary: {
          mode: "source_addressed_illustration",
          summary: "A source-addressed test fixture.",
          source_assertions: [
            { path: "app/main.js", contains: ["fixture-owned-route"] },
          ],
        },
        required_verification: [
          {
            id: "production-source-graph",
            kind: "scanner",
            implementation: "builtin:production-source-graph",
          },
          {
            id: "browser",
            kind: "browser",
            entry: "verify-browser.mjs",
            command: "npm run browser",
          },
          {
            id: "integration",
            kind: "integration",
            entry: "verify-test.mjs",
            command: "npm test",
          },
        ],
      },
    ],
    nonshipped_roots: [],
  };
  await writeFile(
    path.join(repoRoot, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  await execFileAsync("git", ["init", "--quiet"], { cwd: repoRoot });
  await execFileAsync("git", ["add", "."], { cwd: repoRoot });
  if (buildArtifact) {
    await mkdir(path.join(repoRoot, "app", "dist"), { recursive: true });
    await writeFile(
      path.join(repoRoot, "app", "dist", "index.html"),
      "fixture output\n",
    );
  }
  return { manifest, repoRoot };
}

const fixtureOptions = (repoRoot, phase) => ({
  repoRoot,
  phase,
  manifestPath: "manifest.json",
  canonicalProductIds: ["fixture-product"],
  requiredNonshippedRoots: new Map(),
});

test("tracked preflight admits a clean fixture without requiring generated output", async (t) => {
  const { manifest, repoRoot } = await fixtureRepository(t);
  const report = await validateManifest(
    manifest,
    fixtureOptions(repoRoot, "preflight"),
  );
  assert.equal(report.phase, "preflight");
  assert.ok(report.tracked_path_count >= 7);
  assert.deepEqual(report.artifacts, [
    {
      product_id: "fixture-product",
      path: "app/dist",
      materialization: "generated",
      status: "declared",
    },
  ]);
});

test("post-build requires, records, and hashes generated artifact bytes", async (t) => {
  const { manifest, repoRoot } = await fixtureRepository(t, {
    buildArtifact: true,
  });
  const report = await validateManifest(
    manifest,
    fixtureOptions(repoRoot, "post-build"),
  );
  const [artifact] = report.artifacts;
  assert.equal(artifact.status, "hashed");
  assert.equal(artifact.file_count, 1);
  assert.equal(artifact.verified, true);
  assert.match(artifact.sha256, /^[a-f0-9]{64}$/u);
});

test("post-build rejects a declared generated artifact that does not exist", async (t) => {
  const { manifest, repoRoot } = await fixtureRepository(t);
  await assert.rejects(
    validateManifest(manifest, fixtureOptions(repoRoot, "post-build")),
    /generated build artifact does not exist in post-build: app\/dist/u,
  );
});

test("preflight rejects a declared file that is present but untracked", async (t) => {
  const { manifest, repoRoot } = await fixtureRepository(t);
  await writeFile(
    path.join(repoRoot, "app", "untracked.js"),
    "export const untracked = true;\n",
  );
  manifest.products[0].production_entries.push("app/untracked.js");
  await assert.rejects(
    validateManifest(manifest, fixtureOptions(repoRoot, "preflight")),
    /declared path is not tracked in the Git index: app\/untracked\.js/u,
  );
});

async function productionRefusal(appRoot, expected) {
  const cwd = path.join(DEFAULT_REPO_ROOT, appRoot);
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd,
    env: {
      ...process.env,
      NODE_ENV: "production",
      IOI_ENABLE_DEVELOPMENT_AUTHORITY: "1",
      HOST: "127.0.0.1",
      PORT: "0",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    output += chunk.toString();
  });
  const result = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(
        new Error(
          `${appRoot} did not refuse production startup within 5 seconds\n${output}`,
        ),
      );
    }, 5_000);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
  assert.notEqual(
    result.code,
    0,
    `${appRoot} unexpectedly admitted production startup`,
  );
  assert.equal(
    result.signal,
    null,
    `${appRoot} was killed instead of refusing itself`,
  );
  assert.match(output, expected);
  assert.doesNotMatch(output, /listening on/u);
}

test("aiagent.xyz refuses production process startup while canonical owners are incomplete", async () => {
  await productionRefusal(
    "apps/aiagent-xyz",
    /production is refused: canonical package-release, benchmark, settlement, authority, and managed-instance owner contracts are not all registered/u,
  );
});

test("sas.xyz refuses production process startup while canonical owners are incomplete", async () => {
  await productionRefusal(
    "apps/sas-xyz",
    /production is refused: canonical ServiceOrder runtime, settlement, authority, artifact-storage, and governed-production owner contracts are not all registered/u,
  );
});
