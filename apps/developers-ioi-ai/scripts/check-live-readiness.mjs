import fs from "node:fs";
import path from "node:path";

const appRoot = process.cwd();
const repoRoot = path.resolve(appRoot, "../..");

const read = (relativePath) =>
  fs.readFileSync(path.join(appRoot, relativePath), "utf8");

const failures = [];

function assert(condition, message) {
  if (!condition) {
    failures.push(message);
  }
}

const docs = read("src/content/docs.tsx");
const header = read("src/components/Header.tsx");
const app = read("src/App.tsx");
const pkg = JSON.parse(read("package.json"));

for (const label of ["Get Started", "Build", "Run", "Ship"]) {
  assert(docs.includes(`label: '${label}'`), `Missing primary IA label: ${label}`);
}

for (const routePath of [
  "/quickstart",
  "/api",
  "/sdks",
  "/hypervisor",
  "/runtime",
  "/model-mounting",
  "/mcp-tools",
  "/benchmarks",
  "/ship/sas",
  "/ship/aiagent",
]) {
  assert(docs.includes(`routePath: '${routePath}'`), `Missing stable route path: ${routePath}`);
}

for (const legacyHash of [
  "choose-the-right-surface",
  "build-your-first-agent-with-ioi-agent-sdk",
  "run-hypervisor-locally",
  "package-a-service-candidate",
  "sas-xyz-provider-path",
  "aiagent-xyz-distribution-path",
]) {
  assert(docs.includes(`'${legacyHash}'`), `Missing legacy hash alias: ${legacyHash}`);
}

assert(app.includes("docPageByRoutePath"), "App is not using route-path resolution.");
assert(app.includes("docPageByLegacyHash"), "App is not preserving old hash aliases.");
assert(app.includes("history.pushState"), "App is not pushing stable path routes.");

for (const forbidden of [
  "Coming Soon",
  "Protocol docs",
  "Kernel / Runtime",
  "Node / operator docs",
]) {
  assert(!header.includes(forbidden), `Primary nav regression contains forbidden label: ${forbidden}`);
}

assert(docs.includes("IOI_DAEMON_ENDPOINT"), "SDK docs must mention IOI_DAEMON_ENDPOINT.");
assert(
  docs.includes("createMockRuntimeSubstrateClient"),
  "SDK docs must mention createMockRuntimeSubstrateClient for explicit mocks.",
);
assert(
  docs.includes("not the canonical live runtime"),
  "Offline SDK fixture must explicitly say it is not the canonical live runtime.",
);
assert(
  docs.includes("fails closed") || docs.includes("fail-closed"),
  "SDK docs must describe fail-closed daemon-backed behavior.",
);
assert(docs.includes("Agentgres v0 local store"), "Runtime docs must mention Agentgres v0 local store.");

for (const apiNeedle of [
  "/v1/agents",
  "/v1/model-mount/snapshot",
  "/v1/chat/completions",
  "/v1/mcp/tools",
  "/v1/memory",
  "/v1/runs/{'{run_id}'}/trace",
]) {
  assert(docs.includes(apiNeedle), `API Reference missing route family: ${apiNeedle}`);
}

const previewPageCount = [...docs.matchAll(/status: 'Preview'/g)].length;
const whatExistsCount = [...docs.matchAll(/title: 'What Exists Today'/g)].length;
assert(previewPageCount > 0, "Expected at least one Preview page.");
assert(
  whatExistsCount >= previewPageCount,
  `Preview pages need what-exists-today framing: ${whatExistsCount}/${previewPageCount}`,
);

for (const futureShape of [
  "sas.xyz",
  "aiagent.xyz",
  "sovereign-domain",
  "Worker Training",
  "MoW",
]) {
  assert(docs.includes(futureShape), `Future shape was dropped instead of status-framed: ${futureShape}`);
}

for (const hypervisorWorkflowNeedle of [
  "Workflow Snapshots",
  "Compositor Workflows",
  "safety-boundary.png",
  "workflow-terminal-coding-loop-run-button-proof.json",
  "workflow-telemetry-budget-chain-run-inspector-proof.json",
  "promotion-transition-gui-behavior-proof.json",
]) {
  assert(
    docs.includes(hypervisorWorkflowNeedle),
    `Hypervisor docs missing workflow evidence: ${hypervisorWorkflowNeedle}`,
  );
}

assert(
  pkg.scripts?.["validate:live"] === "node scripts/check-live-readiness.mjs",
  "package.json missing validate:live script.",
);
assert(
  pkg.scripts?.["validate:seo"] === "node scripts/check-seo-routing.mjs",
  "package.json missing validate:seo script.",
);
assert(
  pkg.scripts?.["smoke:routes"] === "node scripts/smoke-routes.mjs",
  "package.json missing smoke:routes script.",
);

for (const obtuseCopy of [
  "mock quickstart",
  "Mock quickstart",
  "Explicit mock",
  "mock-only",
  "runnable today",
  "framed surface",
  "Source freshness",
  "Source Provenance",
  "Canonical Depth",
]) {
  assert(!docs.includes(obtuseCopy), `Developer-facing docs still contain obtuse copy: ${obtuseCopy}`);
}

const manifestPath = path.join(
  appRoot,
  "public/media/screenshots/hypervisor/manifest.json",
);
assert(fs.existsSync(manifestPath), "Hypervisor screenshot manifest is missing.");

if (fs.existsSync(manifestPath)) {
  const manifestText = fs.readFileSync(manifestPath, "utf8");
  const manifest = JSON.parse(manifestText);
  assert(
    manifest.public_docs_review?.reviewed_for_public_docs === true,
    "Screenshot manifest must be reviewed for public docs.",
  );
  assert(
    manifest.public_docs_review?.reviewed_for_private_local_data === true,
    "Screenshot manifest must be reviewed for private local data.",
  );
  assert(!manifestText.includes("/home/"), "Manifest must not include private absolute paths.");

  const items = Array.isArray(manifest.items) ? manifest.items : [];
  assert(items.length > 0, "Screenshot manifest must include items.");

  const manifestPublicPaths = new Set();
  for (const item of items) {
    assert(item.public_path, "Screenshot manifest item missing public_path.");
    assert(item.source_path, "Screenshot manifest item missing source_path.");
    assert(item.sha256, "Screenshot manifest item missing sha256.");
    const repoPath = item.repo_path ? path.join(repoRoot, item.repo_path) : null;
    assert(repoPath && fs.existsSync(repoPath), `Manifest asset missing on disk: ${item.repo_path}`);
    manifestPublicPaths.add(item.public_path);
  }

  const screenshotDir = path.join(appRoot, "public/media/screenshots/hypervisor");
  const publicPngs = fs
    .readdirSync(screenshotDir)
    .filter((file) => file.endsWith(".png"))
    .map((file) => `/media/screenshots/hypervisor/${file}`);

  for (const publicPng of publicPngs) {
    assert(
      manifestPublicPaths.has(publicPng),
      `Public screenshot asset lacks manifest entry: ${publicPng}`,
    );
  }
}

if (failures.length > 0) {
  console.error("developers.ioi.ai live-readiness check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("developers.ioi.ai live-readiness check passed.");
