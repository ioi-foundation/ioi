#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { SURFACES } from "../apps/hypervisor/scripts/surface-registry.mjs";
import { V2_ROUTE_TABLE } from "../apps/hypervisor/scripts/v2-route-shell.mjs";
import { isFencedWatchEventsAbort } from "./lib/watchevents-fence.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const shippedProductsManifestPath = path.join(
  root,
  "docs/architecture/_meta/shipped-products.v1.json",
);
const shippedProductsManifest = JSON.parse(
  fs.readFileSync(shippedProductsManifestPath, "utf8"),
);
const shippedProductsById = new Map(
  shippedProductsManifest.products.map((product) => [product.id, product]),
);
const expectedBrowserVerificationIds = new Map([
  ["hypervisor-owned-served-ui", "served-surface-smoke"],
  ["hypervisor-vite-workbench", "workbench-browser-smoke"],
  ["hypervisor-web", "public-surface-smoke"],
  ["developers-ioi-ai", "route-smoke"],
  ["benchmarks", "benchmark-browser-census"],
  ["aiagent-xyz", "marketplace-browser-census"],
  ["sas-xyz", "outcome-market-browser-census"],
]);
const artifactRoot = path.join(
  root,
  ".artifacts",
  "implementation",
  "browser-smoke",
);
fs.rmSync(artifactRoot, { recursive: true, force: true });
fs.mkdirSync(artifactRoot, { recursive: true });

const mimeTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".png", "image/png"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"],
]);

function normalizedRoute(value) {
  const trimmed = value.replace(/\/+$/u, "");
  return trimmed || "/";
}

function routeInventoryDigest(routes) {
  return crypto
    .createHash("sha256")
    .update(`${JSON.stringify(routes)}\n`)
    .digest("hex");
}

function manifestInventory(productId) {
  const product = shippedProductsById.get(productId);
  if (!product) throw new Error(`shipped product ${productId} is not declared`);
  const inventory = product.route_inventory;
  const expectedVerificationId = expectedBrowserVerificationIds.get(productId);
  const verification = product.required_verification?.find(
    (candidate) => candidate.id === inventory?.browser_verification_id,
  );
  if (
    !inventory ||
    inventory.inventory_version !== 1 ||
    inventory.browser_verification_id !== expectedVerificationId ||
    verification?.kind !== "browser"
  ) {
    throw new Error(
      `${productId} route inventory is not bound to the expected browser verification ${expectedVerificationId}`,
    );
  }
  const routes = [...inventory.routes];
  if (
    routes.length !== inventory.expected_count ||
    routeInventoryDigest(routes) !== inventory.sha256
  ) {
    throw new Error(`${productId} route inventory count or digest is invalid`);
  }
  return inventory;
}

function assertManifestRoutes(target, routePatterns) {
  const inventory = manifestInventory(target.name);
  const actual = [...routePatterns].sort();
  if (JSON.stringify(actual) !== JSON.stringify(inventory.routes)) {
    throw new Error(
      `${target.name} browser routes diverge from the shipped manifest: ${JSON.stringify({ missing: inventory.routes.filter((route) => !actual.includes(route)), extra: actual.filter((route) => !inventory.routes.includes(route)) })}`,
    );
  }
  target.routeInventory = inventory;
  target.routePatterns = actual;
}

function staticServer(rootDirectory, allowedRoutes) {
  if (!fs.existsSync(path.join(rootDirectory, "index.html"))) {
    throw new Error(
      `missing production artifact ${path.relative(root, rootDirectory)}`,
    );
  }
  return http.createServer((request, response) => {
    let pathname = "/";
    try {
      pathname = decodeURIComponent(
        new URL(request.url ?? "/", "http://local").pathname,
      );
    } catch {
      response.writeHead(400).end("invalid URL");
      return;
    }
    const requested = pathname === "/" ? "index.html" : pathname.slice(1);
    let filePath = path.resolve(rootDirectory, requested);
    const insideRoot = filePath.startsWith(`${rootDirectory}${path.sep}`);
    if (!insideRoot) {
      response.writeHead(404).end("not found");
      return;
    }
    if (!fs.existsSync(filePath)) {
      if (!allowedRoutes.has(normalizedRoute(pathname))) {
        response.writeHead(404).end("not found");
        return;
      }
      filePath = path.join(rootDirectory, "index.html");
    }
    if (fs.statSync(filePath).isDirectory())
      filePath = path.join(filePath, "index.html");
    response.writeHead(200, {
      "cache-control": "no-store",
      "content-type":
        mimeTypes.get(path.extname(filePath)) ?? "application/octet-stream",
    });
    fs.createReadStream(filePath).pipe(response);
  });
}

function listen(server, port) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
}

async function closeServer(server) {
  await new Promise((resolve) => {
    server.close(resolve);
    server.closeAllConnections?.();
  });
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  await new Promise((resolve) => {
    let force;
    const finished = () => {
      clearTimeout(force);
      resolve();
    };
    child.once("exit", finished);
    if (child.exitCode !== null) {
      finished();
      return;
    }
    force = setTimeout(() => {
      if (child.exitCode === null) child.kill("SIGKILL");
    }, 2_000);
    child.kill("SIGTERM");
  });
}

async function waitFor(url, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError = "not ready";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`${url} did not become ready: ${lastError}`);
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close((error) => {
        if (error) reject(error);
        else resolve(address.port);
      });
    });
  });
}

function safeName(value) {
  return (
    value
      .replace(/^https?:\/\/[^/]+/u, "")
      .replace(/[^a-z0-9]+/giu, "-")
      .replace(/^-|-$/gu, "") || "root"
  );
}

const staticTargets = [
  {
    name: "hypervisor-vite-workbench",
    port: 44179,
    dist: "apps/hypervisor/dist",
    semantics: {
      "/": ["Hypervisor", "product UI is served by the IOI /api adapter"],
      "/workspace-preview": ["WORKSPACE-CORE", "No editor open"],
    },
  },
  {
    name: "hypervisor-web",
    port: 44176,
    dist: "apps/hypervisor-web/dist",
    semantics: {
      "/": ["The operating environment for autonomous systems"],
      "/platform": ["Many surfaces, one truth"],
      "/solutions": ["Put workers to work across your SDLC"],
      "/developers": ["Build on the runtime substrate"],
      "/pricing": ["Priced to scale with your autonomous work"],
      "/background-work": ["Fleets of agents, working while you don't"],
      "/automations-fleets": [
        "Turn any engineering task into a repeatable workflow",
      ],
      "/code-modernization": ["Code migration &", "modernization at scale"],
      "/code-review": ["Review that runs your code, not just reads it"],
      "/runtime-security": ["Give agents autonomy", "the kernel keeps control"],
      "/worker-training": ["Train a specialist", "for the work you do"],
      "/docs": ["What is Hypervisor"],
      "/hv-app": ["Hypervisor App", "Local-first sessions"],
      "/hv-web": ["Hypervisor Web", "Shared projects"],
      "/hv-cli": ["Hypervisor CLI", "Headless by design"],
      "/hv-sdk": ["Hypervisor SDK", "Runtime primitives"],
      "/hv-adk": ["Hypervisor ADK", "Workers & harnesses"],
      "/hv-odk": ["Hypervisor ODK", "Ontology as source"],
      "/hv-mcp": ["Hypervisor MCP", "Scoped profiles"],
      "/hv-os": ["HypervisorOS", "Unavailable today"],
      "/hv-embodied": ["Embodied Runtime", "Safety gates"],
    },
  },
  {
    name: "developers-ioi-ai",
    port: 44177,
    dist: "apps/developers-ioi-ai/dist",
    semantics: {
      "/": ["Start Here"],
      "/quickstart": ["Quickstart"],
      "/api": ["API Reference"],
      "/setup": ["Local Setup"],
      "/sdks": ["SDKs & Libraries"],
      "/examples": ["Examples & Templates"],
      "/tutorials": ["Tutorials"],
      "/cli": ["IOI CLI"],
      "/hypervisor": ["Hypervisor"],
      "/runtime": ["Runtime Daemon"],
      "/model-mounting": ["Model Mounting"],
      "/mcp-tools": ["MCP Tools"],
      "/benchmarks": ["Benchmarks"],
      "/ship/service-candidate": ["Service Candidate Packaging"],
      "/ship/sas": ["sas.xyz"],
      "/ship/aiagent": ["aiagent.xyz"],
      "/ship/sovereign-domain": ["Sovereign Domain Flows"],
      "/ship/worker-training-mow": ["Worker Training / MoW"],
    },
  },
  {
    name: "benchmarks",
    port: 44178,
    dist: "apps/benchmarks/dist",
    semantics: { "/": ["Benchmarks", "Benchmark matrix"] },
  },
];

const applicationTargets = [
  {
    name: "aiagent-xyz",
    port: 44174,
    entry: "apps/aiagent-xyz/server.mjs",
    storeEnvironment: "IOI_AIAGENT_STORE_PATH",
    semantics: {
      "/": ["Admitted workers.", "A listing is discoverable metadata."],
      "/agents": ["Admitted workers.", "A listing is discoverable metadata."],
      "/builder": ["Build an immutable worker package.", "New draft"],
      "/my-workers": ["My workers", "Private and organization registrations"],
      "/instances": [
        "Managed instances",
        "Desired lifecycle and observed runtime",
      ],
    },
  },
  {
    name: "sas-xyz",
    port: 44175,
    entry: "apps/sas-xyz/server.mjs",
    storeEnvironment: "IOI_SAS_STORE_PATH",
    semantics: {
      "/": [
        "Contract the result, not the machinery.",
        "Discoverable is not executable.",
      ],
      "/services": [
        "Contract the result, not the machinery.",
        "Discoverable is not executable.",
      ],
      "/orders": [
        "Outcome orders.",
        "Operational, delivery, and settlement state",
      ],
      "/provider": [
        "Publish a governed release.",
        "Two honest enforcement modes.",
      ],
    },
  },
];

for (const target of staticTargets) {
  target.routes = Object.keys(target.semantics);
  target.routePatternByRoute = Object.fromEntries(
    target.routes.map((route) => [route, route]),
  );
  assertManifestRoutes(target, target.routes);
}

const rawProductFilter =
  process.env.IOI_PRODUCT_SMOKE_PRODUCT?.trim() || null;
const legacyProductAliases = new Map([
  ["hypervisor", "hypervisor-owned-served-ui"],
  ["developers", "developers-ioi-ai"],
  ["aiagent", "aiagent-xyz"],
  ["sas", "sas-xyz"],
]);
const productFilter = rawProductFilter
  ? legacyProductAliases.get(rawProductFilter) || rawProductFilter
  : null;
const modeFilter = process.env.IOI_PRODUCT_SMOKE_MODE?.trim() || null;
const routeFilter = process.env.IOI_PRODUCT_SMOKE_ROUTE
  ? normalizedRoute(process.env.IOI_PRODUCT_SMOKE_ROUTE.trim())
  : null;
const productNames = new Set([
  "hypervisor-owned-served-ui",
  ...applicationTargets.map((target) => target.name),
  ...staticTargets.map((target) => target.name),
]);
const modeNames = new Set([
  "api-contract",
  "functional",
  "light",
  "dark",
  "narrow",
]);
if (productFilter && !productNames.has(productFilter)) {
  throw new Error(
    `unknown IOI_PRODUCT_SMOKE_PRODUCT ${JSON.stringify(rawProductFilter)}`,
  );
}
if (modeFilter && !modeNames.has(modeFilter)) {
  throw new Error(
    `unknown IOI_PRODUCT_SMOKE_MODE ${JSON.stringify(modeFilter)}`,
  );
}

function includesProduct(name) {
  return !productFilter || productFilter === name;
}

function includesVisualRoute(target, route) {
  return (
    !routeFilter ||
    normalizedRoute(route) === routeFilter ||
    target.routePatternByRoute?.[route] === routeFilter
  );
}

function includesApiContract(target) {
  return (
    includesProduct(target.name) &&
    !routeFilter &&
    (!modeFilter || modeFilter === "api-contract")
  );
}

function includesFunctionalJourney(target) {
  return (
    includesProduct(target.name) &&
    !routeFilter &&
    (!modeFilter || modeFilter === "functional")
  );
}

let productMutationSequence = 0;

async function productApi(target, apiPath, { method = "GET", body } = {}) {
  if (!target.session?.cookie || !target.session?.csrfToken) {
    throw new Error(`${target.name} has no authenticated product session`);
  }
  const mutation = method !== "GET";
  const response = await fetch(`http://127.0.0.1:${target.port}${apiPath}`, {
    method,
    headers: {
      accept: "application/json",
      cookie: target.session.cookie,
      ...(mutation
        ? {
            "content-type": "application/json",
            "idempotency-key": `browser-census-${target.name}-${++productMutationSequence}`,
            origin: `http://127.0.0.1:${target.port}`,
            "sec-fetch-site": "same-origin",
            "x-ioi-csrf": target.session.csrfToken,
          }
        : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      `${target.name} ${method} ${apiPath} failed (${response.status}): ${JSON.stringify(payload)}`,
    );
  }
  return payload;
}

async function seedAiagentBrowserRoutes(target) {
  const draft = await productApi(target, "/v1/worker-package-drafts", {
    method: "POST",
    body: {
      template_ref: "worker-template://telesupport/v1",
      name: "Census Telesupport operator",
      description:
        "Typed support triage and bounded reply worker used by the shipped-route census.",
      task_contract: { input: "SupportTicket", output: "SupportResolution" },
      model_route_ref: "model-route://support/default",
      harness_ref: "harness://worker/v1",
      runtime_profile_ref: "runtime-profile://zero-to-idle/v1",
      integration_surfaces: ["helpdesk"],
      authority_scopes: ["ticket:read", "reply:draft"],
      pricing: { asset: "USD", amount_minor: 4900, cadence: "month" },
    },
  });
  await productApi(
    target,
    `/v1/worker-package-drafts/${encodeURIComponent(draft.draft_ref)}/validate`,
    { method: "POST", body: { expected_revision: draft.revision } },
  );
  await productApi(
    target,
    `/v1/worker-package-drafts/${encodeURIComponent(draft.draft_ref)}/package-candidates`,
    {
      method: "POST",
      body: {
        version: "1.0.0",
        sbom_ref: "sbom://census/telesupport-v1",
        provenance_ref: "provenance://census/telesupport-v1",
      },
    },
  );
  const registration = await productApi(target, "/v1/worker-registrations", {
    method: "POST",
    body: { draft_ref: draft.draft_ref, visibility: "private" },
  });
  const promotion = await productApi(
    target,
    `/v1/worker-registrations/${encodeURIComponent(registration.registration_ref)}/promotion-proposals`,
    {
      method: "POST",
      body: {
        disclosure_allowlist: ["name", "description", "task_contract", "pricing"],
        license: "commercial-managed",
        pricing: { asset: "USD", amount_minor: 4900, cadence: "month" },
      },
    },
  );
  const submission = await productApi(
    target,
    `/v1/worker-registrations/${encodeURIComponent(registration.registration_ref)}/promotion-proposals/${encodeURIComponent(promotion.promotion_ref)}/submit`,
    { method: "POST", body: {} },
  );
  await productApi(
    target,
    `/v1/marketplace/submissions/${encodeURIComponent(submission.submission_id)}/benchmark`,
    {
      method: "POST",
      body: {
        evaluation_plan_ref: "evaluation-plan://telesupport/adversarial-v1",
      },
    },
  );
  const listing = await productApi(
    target,
    `/v1/marketplace/submissions/${encodeURIComponent(submission.submission_id)}/publish`,
    { method: "POST", body: {} },
  );
  const quote = await productApi(
    target,
    `/v1/marketplace/workers/${encodeURIComponent(listing.worker_id)}/quote`,
    { method: "POST", body: { intent: "hire" } },
  );
  const hired = await productApi(
    target,
    `/v1/marketplace/workers/${encodeURIComponent(listing.worker_id)}/instances`,
    {
      method: "POST",
      body: {
        quote_ref: quote.quote_ref,
        runtime_profile_ref: "runtime-profile://zero-to-idle/v1",
        persistence_profile_ref: "storage-profile://encrypted-backup/v1",
        authority_grant_refs: [],
      },
    },
  );
  target.routes = [
    "/",
    "/agents",
    `/agents/${encodeURIComponent(listing.worker_id)}`,
    "/builder",
    "/instances",
    `/instances/${encodeURIComponent(hired.instance.worker_instance_id)}`,
    "/my-workers",
  ];
  target.routePatternByRoute = {
    "/": "/",
    "/agents": "/agents",
    [target.routes[2]]: "/agents/:id",
    "/builder": "/builder",
    "/instances": "/instances",
    [target.routes[5]]: "/instances/:id",
    "/my-workers": "/my-workers",
  };
  target.semantics[target.routes[2]] = [
    "Census Telesupport operator",
    "Quote and Hire",
  ];
  target.semantics[target.routes[5]] = [
    "Managed instance",
    hired.instance.worker_instance_id,
    "Owner-bound state",
  ];
  assertManifestRoutes(target, Object.values(target.routePatternByRoute));
}

async function seedSasBrowserRoutes(target) {
  const service = await productApi(target, "/v1/provider/services", {
    method: "POST",
    body: {
      name: "Census engineering CAD outcome",
      version: "1.0.0",
      summary: "Validated mechanical CAD and evidence for the shipped-route census.",
      outcome_contract: {
        output: "STEP CAD and validation report",
        acceptance: "Hashes resolve and declared validation passes",
      },
      deliverable_kind: "cad",
      price: { asset: "USD", amount_minor: 250000, decimals: 2 },
      sla: "10 business days",
      artifact_rights: {
        enforcement_modes: [
          "contractual_audit",
          "governed_remote_production",
        ],
        production_limit_units: 100,
        granted_rights: {
          inspect: true,
          download: true,
          modify: true,
          manufacture: true,
          sublicense: false,
          transfer: false,
        },
      },
    },
  });
  const order = await productApi(target, "/v1/orders", {
    method: "POST",
    body: {
      service_id: service.service_id,
      objective: "Produce a census-verified bracket",
      acceptance_criteria: "STEP hash and validation evidence pass",
      settlement_rail: "settlement-rail://development/escrow",
      production_limit_units: 100,
      enforcement_mode: "governed_remote_production",
    },
  });
  await productApi(
    target,
    `/v1/provider/orders/${encodeURIComponent(order.order_id)}/claim`,
    { method: "POST", body: {} },
  );
  const delivery = await productApi(
    target,
    `/v1/provider/orders/${encodeURIComponent(order.order_id)}/submit-delivery`,
    {
      method: "POST",
      body: {
        kind: "final",
        artifacts: [
          {
            artifact_ref: "artifact://cad/census-bracket.step",
            content_hash: "sha256:census-cad-bracket",
          },
        ],
        evidence_refs: ["evidence://cad/census-validation"],
        verifier_result_refs: ["verifier-result://cad/census-pass"],
      },
    },
  );
  await productApi(
    target,
    `/v1/deliveries/${encodeURIComponent(delivery.delivery_id)}/accept`,
    { method: "POST", body: {} },
  );
  const serviceRoute = `/services/${encodeURIComponent(service.service_id)}`;
  const orderRoute = `/orders/${encodeURIComponent(order.order_id)}`;
  const rightsRoute = `/rights/${encodeURIComponent(order.order_id)}`;
  target.routes = [
    "/",
    "/orders",
    orderRoute,
    "/provider",
    rightsRoute,
    "/services",
    serviceRoute,
  ];
  target.routePatternByRoute = {
    "/": "/",
    "/orders": "/orders",
    [orderRoute]: "/orders/:id",
    "/provider": "/provider",
    [rightsRoute]: "/rights/:id",
    "/services": "/services",
    [serviceRoute]: "/services/:id",
  };
  target.semantics[serviceRoute] = [
    "Census engineering CAD outcome",
    "Freeze exact terms.",
  ];
  target.semantics[orderRoute] = [
    "Produce a census-verified bracket",
    "ORDER: COMPLETED",
    "DELIVERY: ACCEPTED",
    "Open artifact and production rights",
  ];
  target.semantics[rightsRoute] = [
    "ARTIFACT RIGHTS",
    "100 controlled units remaining",
    "Reserve a batch.",
  ];
  assertManifestRoutes(target, Object.values(target.routePatternByRoute));
}

const functionalTargets = [
  ...applicationTargets,
  ...staticTargets.filter(
    (target) => target.name === "hypervisor-vite-workbench",
  ),
];

const servers = [];
const applications = [];
const applicationDataRoots = [];
let hypervisor;
let daemon;
let daemonDataRoot;
let daemonSessionToken =
  process.env.IOI_HYPERVISOR_DAEMON_SESSION?.trim() || null;
let daemonAuthEvidence = null;
let browser;
let hypervisorArtifactIdentity;
const report = [];

try {
  for (const target of staticTargets) {
    const server = staticServer(
      path.join(root, target.dist),
      new Set(target.routes.map(normalizedRoute)),
    );
    await listen(server, target.port);
    servers.push(server);
    const unknown = await fetch(
      `http://127.0.0.1:${target.port}/__ioi_browser_smoke_unknown_route__`,
    );
    if (unknown.status !== 404) {
      throw new Error(
        `${target.name} static server returned ${unknown.status} for an undeclared route`,
      );
    }
  }

  for (const target of applicationTargets) {
    const dataRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), `ioi-${target.name}-browser-smoke-`),
    );
    applicationDataRoots.push(dataRoot);
    const application = spawn(
      process.execPath,
      [path.join(root, target.entry)],
      {
        cwd: root,
        env: {
          ...process.env,
          HOST: "127.0.0.1",
          PORT: String(target.port),
          IOI_ENABLE_DEVELOPMENT_AUTHORITY: "1",
          IOI_SERVE_BUILT_UI: "1",
          IOI_SESSION_SECRET: "implementation-browser-smoke-session-secret-v1",
          [target.storeEnvironment]: path.join(dataRoot, "state.json"),
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let log = "";
    application.stdout.on("data", (chunk) => {
      log = `${log}${chunk}`.slice(-32_000);
    });
    application.stderr.on("data", (chunk) => {
      log = `${log}${chunk}`.slice(-32_000);
    });
    applications.push({ child: application, log: () => log, target });
    try {
      await waitFor(`http://127.0.0.1:${target.port}/v1/session`);
    } catch (error) {
      throw new Error(
        `${target.name} BFF failed to start: ${error.message}\n${log}`,
      );
    }
    const sessionResponse = await fetch(
      `http://127.0.0.1:${target.port}/v1/session`,
    );
    const session = await sessionResponse.json();
    const cookie = sessionResponse.headers.get("set-cookie")?.split(";", 1)[0];
    if (
      !sessionResponse.ok ||
      !cookie ||
      session.authenticated !== true ||
      !session.csrf_token
    ) {
      throw new Error(`${target.name} did not issue a usable product session`);
    }
    target.session = {
      cookie,
      csrfToken: session.csrf_token,
    };
    const statusResponse = await fetch(
      `http://127.0.0.1:${target.port}/v1/status`,
      { headers: { cookie } },
    );
    const status = await statusResponse.json();
    if (
      !statusResponse.ok ||
      status.authority_mode !== "development" ||
      status.receipt_chain_valid !== true
    ) {
      throw new Error(`${target.name} authenticated status contract failed`);
    }
    if (includesApiContract(target)) {
      report.push({
        product: target.name,
        mode: "api-contract",
        route: "/v1/session -> /v1/status",
        status: statusResponse.status,
        authority_mode: status.authority_mode,
        receipt_chain_valid: status.receipt_chain_valid,
      });
    }
  }

  for (const target of applicationTargets) {
    if (target.name === "aiagent-xyz") await seedAiagentBrowserRoutes(target);
    else if (target.name === "sas-xyz") await seedSasBrowserRoutes(target);
  }

  let daemonEndpoint = process.env.IOI_HYPERVISOR_DAEMON_URL?.replace(
    /\/$/u,
    "",
  );
  if (daemonEndpoint) {
    await waitFor(`${daemonEndpoint}/healthz`, 30_000);
    if (!daemonSessionToken) {
      throw new Error(
        "IOI_HYPERVISOR_DAEMON_SESSION is required when browser smoke targets an external daemon",
      );
    }
    daemonAuthEvidence = {
      mode: "provided-daemon-session",
      authenticated: true,
    };
  } else {
    const daemonBinary = path.resolve(
      root,
      process.env.IOI_HYPERVISOR_DAEMON_BINARY ??
        "target/debug/hypervisor-daemon",
    );
    fs.accessSync(daemonBinary, fs.constants.X_OK);
    daemonDataRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "ioi-product-browser-daemon-"),
    );
    const daemonPort = await freePort();
    daemonEndpoint = `http://127.0.0.1:${daemonPort}`;
    daemon = spawn(daemonBinary, [], {
      cwd: root,
      env: {
        ...process.env,
        IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
        IOI_HYPERVISOR_DATA_DIR: daemonDataRoot,
        IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let daemonLog = "";
    daemon.stdout.on("data", (chunk) => {
      daemonLog = `${daemonLog}${chunk}`.slice(-64_000);
    });
    daemon.stderr.on("data", (chunk) => {
      daemonLog = `${daemonLog}${chunk}`.slice(-64_000);
    });
    try {
      await waitFor(`${daemonEndpoint}/healthz`, 30_000);
    } catch (error) {
      throw new Error(
        `Hypervisor daemon failed to start: ${error.message}\n${daemonLog}`,
      );
    }
    const bootstrapToken =
      daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
    if (!bootstrapToken) {
      throw new Error(
        `Hypervisor daemon did not emit a one-boot bootstrap credential:\n${daemonLog}`,
      );
    }
    const bootstrapResponse = await fetch(
      `${daemonEndpoint}/v1/hypervisor/auth/bootstrap`,
      {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          token: bootstrapToken,
          password: "product-browser-smoke-bootstrap-password-v1",
          email: "product-browser-smoke@ioi.local",
        }),
      },
    );
    const bootstrap = await bootstrapResponse.json();
    if (
      !bootstrapResponse.ok ||
      typeof bootstrap.session_token !== "string" ||
      !bootstrap.session_token.startsWith("ioi_sess_")
    ) {
      throw new Error(
        `Hypervisor daemon bootstrap failed (${bootstrapResponse.status}): ${JSON.stringify(bootstrap)}`,
      );
    }
    daemonSessionToken = bootstrap.session_token;
    daemonAuthEvidence = {
      mode: "one-boot-bootstrap",
      authenticated: true,
      principal_id: bootstrap.principal?.principal_id ?? null,
      tenant_refs: bootstrap.principal?.tenant_refs ?? [],
    };
  }

  hypervisor = spawn(
    process.execPath,
    [path.join(root, "apps/hypervisor/scripts/serve-product-ui.mjs")],
    {
      cwd: root,
      env: {
        ...process.env,
        PORT: "44173",
        PRODUCT_UI_PORT: "49301",
        IOI_HYPERVISOR_DAEMON_URL: daemonEndpoint,
        IOI_PRODUCT_UI_PUBLIC: path.join(
          root,
          "apps/hypervisor/product-ui/owned/public",
        ),
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let hypervisorLog = "";
  hypervisor.stdout.on("data", (chunk) => {
    hypervisorLog += chunk.toString();
  });
  hypervisor.stderr.on("data", (chunk) => {
    hypervisorLog += chunk.toString();
  });
  await waitFor("http://127.0.0.1:44173/");
  const identityResponse = await fetch(
    "http://127.0.0.1:44173/__ioi/product-ui-identity",
  );
  hypervisorArtifactIdentity = await identityResponse.json();
  const expectedOwnedIndexSha256 = crypto
    .createHash("sha256")
    .update(
      fs.readFileSync(
        path.join(
          root,
          "apps/hypervisor/product-ui/owned/public/index.html",
        ),
      ),
    )
    .digest("hex");
  const identityHeaders = {
    tree: identityResponse.headers.get("x-ioi-product-ui-tree"),
    index_sha256: identityResponse.headers.get(
      "x-ioi-product-ui-index-sha256",
    ),
  };
  if (
    !identityResponse.ok ||
    identityHeaders.tree !== "owned" ||
    identityHeaders.index_sha256 !== expectedOwnedIndexSha256 ||
    hypervisorArtifactIdentity?.schema_version !==
      "ioi.hypervisor-product-ui-tree.v1" ||
    hypervisorArtifactIdentity?.tree !== "owned" ||
    hypervisorArtifactIdentity?.public_dir !== "owned/public" ||
    hypervisorArtifactIdentity?.index_sha256 !== expectedOwnedIndexSha256
  ) {
    throw new Error(
      `Hypervisor served-tree identity mismatch: ${JSON.stringify({ expected_index_sha256: expectedOwnedIndexSha256, response: hypervisorArtifactIdentity, headers: identityHeaders })}`,
    );
  }

  browser = await chromium.launch({ headless: true });
  async function newBrowserContext(options) {
    const context = await browser.newContext(options);
    await context.addCookies([
      {
        name: "ioi_session",
        value: daemonSessionToken,
        domain: "127.0.0.1",
        path: "/",
        httpOnly: true,
        sameSite: "Lax",
      },
    ]);
    return context;
  }
  const contexts = [
    { name: "light", colorScheme: "light", width: 1440, height: 1000 },
    { name: "dark", colorScheme: "dark", width: 1440, height: 1000 },
    { name: "narrow", colorScheme: "light", width: 390, height: 844 },
  ].filter((context) => !modeFilter || modeFilter === context.name);
  const canonicalSurfaceRows = V2_ROUTE_TABLE.filter(
    (surface) => surface.disposition !== "reserved",
  );
  // W2.1 rehome: a bound surface may ALSO serve at its canonical v2 route (surface-registry
  // canonical_route). Both mounts are shipped browser routes and both are smoked.
  const canonicalSurfaceMounts = SURFACES.filter((surface) => surface.canonical_route);
  // W2.1 Leg 1b: a registry canonical mount may COINCIDE with its v2 route-table row (the bound
  // module now serves the canonical route the shell page used to render — /studio). One served
  // route is ONE inventory row, so the enumeration deduplicates; the later registry-canonical
  // semantics/contract entries below win for such a route, which is exactly the ownership the
  // serve now emits for it.
  const hypervisorRoutes = [...new Set([
    "/",
    ...canonicalSurfaceRows.map((surface) => surface.route),
    ...SURFACES.map((surface) => surface.route),
    ...canonicalSurfaceMounts.map((surface) => surface.canonical_route),
  ])];
  const hypervisorTarget = {
    name: "hypervisor-owned-served-ui",
    port: 44173,
    routes: hypervisorRoutes,
    expectedPaths: { "/": "/projects" },
    semantics: Object.fromEntries([
      ["/", ["Projects"]],
      ...canonicalSurfaceRows.map((surface) => [
        surface.route,
        [surface.surface],
      ]),
      ...SURFACES.map((surface) => [surface.route, [surface.title]]),
      ...canonicalSurfaceMounts.map((surface) => [surface.canonical_route, [surface.title]]),
    ]),
    surfaceContracts: Object.fromEntries([
      ...canonicalSurfaceRows.map((surface) => [
        surface.route,
        {
          heading: surface.surface,
          owner: surface.kind,
          source: "v2-route-table",
          require_owned_marker: surface.disposition !== "vendor_spa",
          require_heading: true,
        },
      ]),
      ...SURFACES.map((surface) => [
        surface.route,
        {
          heading: surface.title,
          owner: surface.owner,
          source: "surface-registry",
          require_owned_marker: true,
          require_heading: false,
        },
      ]),
      ...canonicalSurfaceMounts.map((surface) => [
        surface.canonical_route,
        {
          heading: surface.title,
          owner: surface.owner,
          source: "surface-registry-canonical-mount",
          require_owned_marker: true,
          require_heading: false,
        },
      ]),
    ]),
    namedGaps: new Set([
      "/api/gitpod.v1.OrganizationService/GetTermsOfService:503",
      "/api/gitpod.v1.OrganizationService/GetOrganizationPolicies:503",
    ]),
  };
  hypervisorTarget.routePatternByRoute = Object.fromEntries(
    hypervisorRoutes.map((route) => [route, route]),
  );
  // DEF-SPA-WATCHEVENTS-1: the smoke's own route classification, verbatim from the
  // canonical route table — a FINAL route is a vendored-SPA route exactly when its
  // V2_ROUTE_TABLE row declares disposition "vendor_spa" (e.g. "/" lands on
  // /projects, a vendor_spa row). Consumed by the typed WatchEvents fence below.
  hypervisorTarget.routeDispositionByRoute = Object.fromEntries(
    V2_ROUTE_TABLE.map((surface) => [
      surface.route,
      surface.disposition ?? "shell",
    ]),
  );
  assertManifestRoutes(hypervisorTarget, hypervisorRoutes);
  const expectedVisualRows =
    contexts.length *
    [hypervisorTarget, ...applicationTargets, ...staticTargets]
      .filter((target) => includesProduct(target.name))
      .reduce(
        (count, target) =>
          count +
          target.routes.filter((route) => includesVisualRoute(target, route))
            .length,
        0,
      );
  const expectedApiRows = applicationTargets.filter(includesApiContract).length;
  const expectedFunctionalRows = functionalTargets.filter(
    includesFunctionalJourney,
  ).length;
  const expectedReportRows =
    expectedVisualRows + expectedApiRows + expectedFunctionalRows;
  if (expectedReportRows === 0) {
    throw new Error(
      `product browser smoke selection matched no declared checks: ${JSON.stringify({ product: productFilter, mode: modeFilter, route: routeFilter })}`,
    );
  }

  async function inspectRoute(page, target, contextSpec, route) {
    const url = `http://127.0.0.1:${target.port}${route}`;
    const pageErrors = [];
    const consoleErrors = [];
    const requestFailures = [];
    const responseFailures = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    page.on("console", (message) => {
      if (
        message.type() === "error" &&
        !message.text().startsWith("Failed to load resource:")
      ) {
        consoleErrors.push(message.text());
      }
    });
    page.on("requestfailed", (request) => {
      // Collected structured so the DEF-SPA-WATCHEVENTS-1 fence can match the full
      // tuple (url, method, failure class) at the error gate below; every failure
      // outside that one tuple still fails the smoke with the original message.
      requestFailures.push({
        url: request.url(),
        method: request.method(),
        error_text: request.failure()?.errorText ?? "failed",
      });
    });
    page.on("response", (response) => {
      if (response.status() >= 400) {
        const responseUrl = new URL(response.url());
        responseFailures.push({
          key: `${responseUrl.pathname}:${response.status()}`,
          message: `${response.url()} (HTTP ${response.status()})`,
        });
      }
    });
    const response = await page.goto(url, { waitUntil: "domcontentloaded" });
    await page.locator("body").waitFor({ state: "visible" });
    await page
      .waitForLoadState("networkidle", { timeout: 2_000 })
      .catch(() => undefined);
    if (applicationTargets.includes(target)) {
      await page.waitForFunction(
        () =>
          document.body.innerText.trim().length > 0 &&
          !document.body.innerText.includes("Loading owner state"),
      );
    }
    const evidence = await page.locator("body").evaluate((body) => ({
      text: body.innerText.trim(),
      body_background: getComputedStyle(body).backgroundColor,
      body_color: getComputedStyle(body).color,
      document_width: document.documentElement.scrollWidth,
      document_height: Math.max(
        document.documentElement.scrollHeight,
        body.scrollHeight,
      ),
      viewport_width: document.documentElement.clientWidth,
      overflow_elements: [...document.querySelectorAll("body *")]
        .map((element) => {
          const rect = element.getBoundingClientRect();
          return {
            selector: `${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ""}${[
              ...element.classList,
            ]
              .slice(0, 3)
              .map((name) => `.${name}`)
              .join("")}`,
            left: Math.round(rect.left),
            right: Math.round(rect.right),
            width: Math.round(rect.width),
          };
        })
        .filter(
          (element) =>
            element.left < -1 ||
            element.right > document.documentElement.clientWidth + 1,
        )
        .slice(0, 8),
      right_overflow_elements: [...document.querySelectorAll("body *")]
        .map((element) => {
          const rect = element.getBoundingClientRect();
          return {
            selector: `${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ""}${[
              ...element.classList,
            ]
              .slice(0, 3)
              .map((name) => `.${name}`)
              .join("")}`,
            left: Math.round(rect.left),
            right: Math.round(rect.right),
            width: Math.round(rect.width),
          };
        })
        .filter(
          (element) => element.right > document.documentElement.clientWidth + 1,
        )
        .sort((left, right) => right.right - left.right)
        .slice(0, 12),
    }));
    const screenshot = `${safeName(target.name)}-${contextSpec.name}-${safeName(route)}.png`;
    const screenshotPath = path.join(artifactRoot, screenshot);
    let screenshotCapture =
      evidence.document_height <= 16_000 ? "full-page" : "viewport";
    try {
      await page.screenshot({
        path: screenshotPath,
        fullPage: screenshotCapture === "full-page",
      });
    } catch (error) {
      if (screenshotCapture !== "full-page") throw error;
      screenshotCapture = "viewport-fallback";
      await page.screenshot({ path: screenshotPath, fullPage: false });
    }
    if (!response || response.status() >= 400 || evidence.text.length === 0) {
      throw new Error(`${contextSpec.name} ${url} failed to render`);
    }
    const finalPath = normalizedRoute(new URL(page.url()).pathname);
    const expectedPath = normalizedRoute(
      target.expectedPaths?.[route] ?? route,
    );
    if (finalPath !== expectedPath) {
      throw new Error(
        `${contextSpec.name} ${url} normalized to ${finalPath}; expected the declared final route ${expectedPath}`,
      );
    }
    const semanticAssertions = target.semantics?.[route] ?? [];
    const missingSemantics = semanticAssertions.filter(
      (expected) => !evidence.text.includes(expected),
    );
    if (missingSemantics.length > 0) {
      throw new Error(
        `${contextSpec.name} ${url} rendered the wrong route semantics; missing ${JSON.stringify(missingSemantics)}`,
      );
    }
    const ownerContract = target.surfaceContracts?.[expectedPath];
    if (ownerContract) {
      const headings = ownerContract.require_heading
        ? await page.locator("h1").allTextContents()
        : [];
      if (
        ownerContract.require_heading &&
        !headings.some((heading) =>
          heading.trim().startsWith(ownerContract.heading),
        )
      ) {
        throw new Error(
          `${contextSpec.name} ${url} did not render the page-owned heading ${JSON.stringify(ownerContract.heading)}; headings=${JSON.stringify(headings)}`,
        );
      }
      if (ownerContract.require_owned_marker) {
        const ownerMarker = page.locator(
          `[data-ioi-surface-route="${expectedPath}"]`,
        );
        if ((await ownerMarker.count()) !== 1) {
          throw new Error(
            `${contextSpec.name} ${url} did not render its unique owned surface marker`,
          );
        }
        const renderedOwner = await ownerMarker.getAttribute(
          "data-ioi-surface-owner",
        );
        if (renderedOwner !== ownerContract.owner) {
          throw new Error(
            `${contextSpec.name} ${url} rendered owner ${JSON.stringify(renderedOwner)}; expected ${JSON.stringify(ownerContract.owner)}`,
          );
        }
      }
      if (ownerContract.source === "surface-registry") {
        const renderedRoute = response.headers()["x-ioi-surface-route"];
        const renderedOwner = response.headers()["x-ioi-surface-owner"];
        if (
          renderedRoute !== expectedPath ||
          renderedOwner !== ownerContract.owner
        ) {
          throw new Error(
            `${contextSpec.name} ${url} registry dispatch identity mismatch: ${JSON.stringify({ rendered_route: renderedRoute, rendered_owner: renderedOwner, expected_route: expectedPath, expected_owner: ownerContract.owner })}`,
          );
        }
      }
    }
    if (
      target.name === "hypervisor-owned-served-ui" &&
      evidence.text.includes("Daemon unavailable")
    ) {
      throw new Error(
        `${contextSpec.name} ${url} rendered the disconnected daemon fallback`,
      );
    }
    const unexpectedResponseFailures = responseFailures.filter(
      (failure) => !target.namedGaps?.has(failure.key),
    );
    // DEF-SPA-WATCHEVENTS-1 typed fence: the vendored SPA's event-stream teardown
    // race (POST /api/gitpod.v1.EventService/WatchEvents → net::ERR_ABORTED on the
    // served origin, hypervisor lane, vendor_spa final route) is admitted by the
    // full-tuple predicate and reported, never fatal. Reproductions: #235, #237 ×2,
    // #241 + CI run 31444686784. REMOVAL: deleted in the same PR that lands the SPA
    // event-stream teardown fix (see scripts/lib/watchevents-fence.mjs).
    const fenceRouteContext = {
      product_lane: target.name,
      final_route_disposition:
        target.routeDispositionByRoute?.[finalPath] ?? null,
      served_origin: new URL(url).origin,
    };
    const fencedRequestFailures = requestFailures.filter((failure) =>
      isFencedWatchEventsAbort(failure, fenceRouteContext),
    );
    const unexpectedRequestFailures = requestFailures.filter(
      (failure) => !isFencedWatchEventsAbort(failure, fenceRouteContext),
    );
    if (
      pageErrors.length > 0 ||
      consoleErrors.length > 0 ||
      unexpectedRequestFailures.length > 0 ||
      unexpectedResponseFailures.length > 0
    ) {
      throw new Error(
        `${contextSpec.name} ${url} emitted browser errors: ${[
          ...pageErrors,
          ...consoleErrors,
          ...unexpectedRequestFailures.map(
            (failure) => `${failure.url} (${failure.error_text})`,
          ),
          ...unexpectedResponseFailures.map((failure) => failure.message),
        ].join("; ")}`,
      );
    }
    if (
      contextSpec.name === "narrow" &&
      evidence.document_width > evidence.viewport_width + 1
    ) {
      throw new Error(
        `${url} overflows the narrow viewport (${evidence.document_width}px > ${evidence.viewport_width}px): ${JSON.stringify({ right: evidence.right_overflow_elements, all: evidence.overflow_elements })}`,
      );
    }
    report.push({
      product: target.name,
      browser_verification_id: target.routeInventory.browser_verification_id,
      mode: contextSpec.name,
      route,
      route_pattern: target.routePatternByRoute[route],
      status: response.status(),
      body_bytes: Buffer.byteLength(evidence.text),
      document_width: evidence.document_width,
      document_height: evidence.document_height,
      viewport_width: evidence.viewport_width,
      named_gaps: responseFailures
        .filter((failure) => target.namedGaps?.has(failure.key))
        .map((failure) => failure.key),
      fenced_request_failures: fencedRequestFailures.map(
        (failure) =>
          `${failure.method} ${failure.url} (${failure.error_text}) [DEF-SPA-WATCHEVENTS-1]`,
      ),
      semantic_assertions: semanticAssertions,
      owner_contract: ownerContract || null,
      final_path: finalPath,
      screenshot,
      screenshot_capture: screenshotCapture,
      rendered_theme: {
        requested_color_scheme: contextSpec.colorScheme,
        body_background: evidence.body_background,
        body_color: evidence.body_color,
      },
    });
  }

  async function runFunctionalJourney(target) {
    const context = await newBrowserContext({
      colorScheme: "light",
      viewport: { width: 1280, height: 900 },
      reducedMotion: "reduce",
    });
    const page = await context.newPage();
    const pageErrors = [];
    const consoleErrors = [];
    const responseFailures = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    page.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text());
    });
    page.on("response", (response) => {
      if (response.status() >= 400) {
        responseFailures.push(`${response.url()} (HTTP ${response.status()})`);
      }
    });
    let finalPath;
    let assertion;
    try {
      if (target.name === "aiagent-xyz") {
        const name = `Browser-audited Telesupport ${Date.now()}`;
        await page.goto(`http://127.0.0.1:${target.port}/builder`, {
          waitUntil: "domcontentloaded",
        });
        await page.getByRole("heading", { name: "New draft" }).waitFor();
        await page.getByLabel("Name").fill(name);
        await page.getByRole("button", { name: "Create durable draft" }).click();
        const draft = page.locator("article").filter({ hasText: name });
        await draft.getByText("draft", { exact: true }).waitFor();
        await draft.getByRole("button", { name: "Validate" }).click();
        await draft.getByText("validated", { exact: true }).waitFor();
        const projection = await page.evaluate(async () => {
          const response = await fetch("/v1/creator/supply");
          return { status: response.status, body: await response.json() };
        });
        const persisted = projection.body?.drafts?.find(
          (item) => item.name === name,
        );
        if (projection.status !== 200 || persisted?.state !== "validated") {
          throw new Error(
            `aiagent.xyz functional projection mismatch: ${JSON.stringify(projection)}`,
          );
        }
        assertion = {
          journey: "create durable worker draft -> validate",
          draft_ref: persisted.draft_ref,
          state: persisted.state,
        };
      } else if (target.name === "sas-xyz") {
        const name = `Browser-audited CAD outcome ${Date.now()}`;
        await page.goto(`http://127.0.0.1:${target.port}/provider`, {
          waitUntil: "domcontentloaded",
        });
        await page.locator('#service-form input[name="name"]').fill(name);
        await page
          .getByRole("button", { name: "Publish service release" })
          .click();
        await page.waitForURL(/\/services\/[^/]+$/u);
        await page.getByRole("heading", { name }).waitFor();
        await page.getByRole("button", { name: "Reserve and order" }).click();
        await page.waitForURL(/\/orders\/[^/]+$/u);
        await page.getByText("order: awaiting_provider", { exact: true }).waitFor();
        await page.getByRole("button", { name: "Claim order" }).click();
        await page.getByText("order: in_progress", { exact: true }).waitFor();
        const orderId = new URL(page.url()).pathname.split("/").at(-1);
        const projection = await page.evaluate(async (id) => {
          const response = await fetch(`/v1/orders/${encodeURIComponent(id)}`);
          return { status: response.status, body: await response.json() };
        }, orderId);
        if (projection.status !== 200 || projection.body?.state !== "in_progress") {
          throw new Error(
            `sas.xyz functional projection mismatch: ${JSON.stringify(projection)}`,
          );
        }
        assertion = {
          journey: "publish CAD service -> reserve order -> provider claim",
          service_name: name,
          order_id: orderId,
          state: projection.body.state,
          terms_root: projection.body.terms_root,
        };
      } else if (target.name === "hypervisor-vite-workbench") {
        await page.goto(
          `http://127.0.0.1:${target.port}/workspace-preview`,
          { waitUntil: "domcontentloaded" },
        );
        await page.getByText("No editor open", { exact: true }).waitFor();
        const projectPath = "WORKSPACE-CORE/workspace-core";
        await page
          .locator(
            `[data-inspection-target="workspace-explorer-row"][data-workspace-path="${projectPath}"]`,
          )
          .click();
        const sourcePath = `${projectPath}/src`;
        const sourceRow = page.locator(
          `[data-inspection-target="workspace-explorer-row"][data-workspace-path="${sourcePath}"]`,
        );
        await sourceRow.waitFor();
        await sourceRow.click();
        const expanded = await sourceRow.evaluate((element) =>
          element.parentElement?.classList.contains("is-expanded"),
        );
        if (!expanded) {
          throw new Error(
            "Hypervisor workbench preview did not apply the directory interaction",
          );
        }
        assertion = {
          journey: "expand workspace project -> inspect source directory",
          workspace_path: sourcePath,
          expanded,
        };
      } else {
        throw new Error(`no functional journey for ${target.name}`);
      }
      finalPath = normalizedRoute(new URL(page.url()).pathname);
      if (
        pageErrors.length ||
        consoleErrors.length ||
        responseFailures.length
      ) {
        throw new Error(
          `${target.name} functional journey emitted browser errors: ${[
            ...pageErrors,
            ...consoleErrors,
            ...responseFailures,
          ].join("; ")}`,
        );
      }
      const screenshot = `${safeName(target.name)}-functional.png`;
      await page.screenshot({
        path: path.join(artifactRoot, screenshot),
        fullPage: true,
      });
      report.push({
        product: target.name,
        browser_verification_id:
          target.routeInventory.browser_verification_id,
        mode: "functional",
        route: "stateful-journey",
        status: 200,
        final_path: finalPath,
        assertion,
        screenshot,
      });
    } finally {
      await context.close();
    }
  }

  if (includesProduct(hypervisorTarget.name)) {
    for (const contextSpec of contexts) {
      const context = await newBrowserContext({
        colorScheme: contextSpec.colorScheme,
        viewport: { width: contextSpec.width, height: contextSpec.height },
        reducedMotion: "reduce",
      });
      for (const route of hypervisorRoutes.filter((route) =>
        includesVisualRoute(hypervisorTarget, route),
      )) {
        const page = await context.newPage();
        await inspectRoute(page, hypervisorTarget, contextSpec, route);
        await page.close();
      }
      await context.close();
    }
  }

  for (const contextSpec of contexts) {
    const context = await newBrowserContext({
      colorScheme: contextSpec.colorScheme,
      viewport: { width: contextSpec.width, height: contextSpec.height },
      reducedMotion: "reduce",
    });
    for (const target of [...applicationTargets, ...staticTargets].filter(
      (target) => includesProduct(target.name),
    )) {
      for (const route of target.routes.filter((route) =>
        includesVisualRoute(target, route),
      )) {
        const page = await context.newPage();
        await inspectRoute(page, target, contextSpec, route);
        await page.close();
      }
    }
    await context.close();
  }

  for (const target of functionalTargets.filter(includesFunctionalJourney)) {
    await runFunctionalJourney(target);
  }

  if (report.length !== expectedReportRows) {
    throw new Error(
      `product browser smoke produced ${report.length} report rows; expected ${expectedReportRows}`,
    );
  }
  fs.writeFileSync(
    path.join(artifactRoot, "report.json"),
    `${JSON.stringify(
      {
        schema_version: "ioi.product-browser-smoke.v2",
        status: "passed",
        expected_rows: expectedReportRows,
        selection: {
          product: productFilter,
          mode: modeFilter,
          route: routeFilter,
        },
        hypervisor_artifact: hypervisorArtifactIdentity,
        hypervisor_daemon_auth: daemonAuthEvidence,
        routes: report,
      },
      null,
      2,
    )}\n`,
  );
  console.log(`product browser smoke: ${report.length} route renders passed`);
} catch (error) {
  fs.writeFileSync(
    path.join(artifactRoot, "report.json"),
    `${JSON.stringify(
      {
        schema_version: "ioi.product-browser-smoke.v2",
        status: "failed",
        selection: {
          product: productFilter,
          mode: modeFilter,
          route: routeFilter,
        },
        hypervisor_artifact: hypervisorArtifactIdentity,
        hypervisor_daemon_auth: daemonAuthEvidence,
        error: error instanceof Error ? error.stack : String(error),
        routes: report,
      },
      null,
      2,
    )}\n`,
  );
  throw error;
} finally {
  if (browser) await browser.close();
  await Promise.all([
    ...applications.map((application) => stopChild(application.child)),
    stopChild(hypervisor),
    stopChild(daemon),
  ]);
  await Promise.all(servers.map(closeServer));
  for (const dataRoot of applicationDataRoots) {
    fs.rmSync(dataRoot, { recursive: true, force: true });
  }
  if (daemonDataRoot) {
    fs.rmSync(daemonDataRoot, { recursive: true, force: true });
  }
}
