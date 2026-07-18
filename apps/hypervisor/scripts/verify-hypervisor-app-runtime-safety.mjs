#!/usr/bin/env node
// App-runtime safety verifier (functional-runtime wave — route isolation + static gate + registry).
//
// Proves the three PR-55 guarantees that make interaction work safe to build on:
//   1. ROUTE ISOLATION — one surface's renderer exception 500s THAT route and the estate process
//      keeps serving (the #46 incident class: DOMAIN_APP_VIS/ODK_UI deleted with call sites left
//      behind, one GET killed all ~100 surfaces). Proven against an ISOLATED serve spawned with
//      IOI_APP_RUNTIME_TEST_ROUTE=1, whose /__ioi/__test/boom route throws on purpose; the live
//      serve is never touched, and the fault route must NOT exist without the flag.
//   2. STATIC GATE — the no-undef lint (eslint.config.mjs) passes over the serve runtime set
//      (serve + transitively imported local modules) AND the concatenated augmentation bundle,
//      and the gate has TEETH (a planted dangling-identifier fixture must fail it).
//   3. REGISTRY — surface-registry.mjs covers every parity matrix certified seed and permits only
//      explicit read-only-by-contract additions beyond that evidence set; verifier files exist,
//      the app catalog reads registry presentation, and modules serve through the registry mount.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-runtime-safety.mjs
// Exit 0 = all assertions pass; exit 1 = one or more failed.

import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { SURFACES, boundSurface } from "./surface-registry.mjs";
import { buildAppCatalog, contractCatalogAdmission } from "./app-catalog.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const HERE = dirname(fileURLToPath(import.meta.url));
const APP = join(HERE, "..");
const ROOT = join(APP, "..", "..");
const ARTIFACTS = join(APP, ".artifacts");
const FAULT_PORT = 4604;
const FAULT_UI_PORT = 9404;
const OPERATIONS_FAULT_PORT = 4605;
const OPERATIONS_FAULT_UI_PORT = 9405;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function sGet(path, base = SERVE) {
  const r = await fetch(`${base}${path}`);
  return { status: r.status, text: await r.text() };
}

// The serve runtime set: serve-product-ui.mjs plus every local module it transitively imports —
// derived, not hand-listed, so a new import is linted the moment it appears.
function runtimeSet() {
  const seen = new Set();
  const queue = [join(HERE, "serve-product-ui.mjs")];
  while (queue.length) {
    const f = queue.pop();
    const abs = resolve(f);
    if (seen.has(abs) || !existsSync(abs)) continue;
    seen.add(abs);
    const src = readFileSync(abs, "utf8");
    for (const m of src.matchAll(/from\s+"(\.\.?\/[^"]+\.mjs)"/g)) queue.push(join(dirname(abs), m[1]));
  }
  return [...seen];
}

function eslintRun(files) {
  const r = spawnSync(process.execPath, [
    join(ROOT, "node_modules", "eslint", "bin", "eslint.js"),
    "--no-config-lookup", "--config", join(APP, "eslint.config.mjs"),
    ...files,
  ], { cwd: ROOT, encoding: "utf8" });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

async function startHostileOperationsDaemon() {
  const maliciousTimeline = '"><img src=x onerror="document.body.dataset.pwned=1">';
  const sockets = new Set();
  const server = createServer((req, res) => {
    const pathname = new URL(req.url || "/", "http://x").pathname;
    if (pathname === "/v1/hypervisor/auth/policy") {
      res.writeHead(200, { "content-type": "application/json" });
      res.write('{"partial":');
      return;
    }
    if (pathname === "/v1/hypervisor/providers") return;
    const emptyPlanes = {
      "/v1/hypervisor/provider-receipts": { receipts: [] },
      "/v1/hypervisor/provider-spend/reconciliation": {
        rows: [],
        incomplete_teardown_warnings: [],
        budget: {},
        estimated_open_exposure_rate: {},
        teardown_finalized: {},
      },
      "/v1/hypervisor/storage-backends": { backends: {} },
      "/v1/hypervisor/storage-incidents": { incidents: [], repair_receipts: [] },
      "/v1/hypervisor/akash-deployments": { deployments: [], leases: [], redeploy_plans: [] },
      "/v1/hypervisor/failover/runs": { runs: [] },
      "/v1/hypervisor/failover/plans": { plans: [] },
      "/v1/hypervisor/goal-runs": { goal_runs: [] },
      "/v1/hypervisor/work-ledger": { entries: [] },
    };
    const payload = pathname === "/v1/hypervisor/operations"
      ? {
          scheduler: { automations: [] },
          runs: {
            total: 2,
            done: 0,
            failed: 1,
            running: 1,
            recent: [
              {
                execution_id: "exec_safe",
                automation_id: "automation_safe",
                name: "Safe run",
                project_id: "project:test",
                status: "running",
                started_at: "2026-07-18T00:00:00Z",
                timeline_ref: "/__ioi/run-timeline/exec_safe",
              },
              {
                execution_id: "exec_injected",
                automation_id: "automation_injected",
                name: '</script><img src=x onerror="document.body.dataset.namePwned=1">',
                project_id: "project:test",
                status: "failed",
                started_at: "2026-07-18T00:00:01Z",
                finished_at: "2026-07-18T00:00:02Z",
                timeline_ref: maliciousTimeline,
              },
            ],
            failures: [],
          },
          webhooks: { accepted: 0, rejected: 0, recent: [] },
        }
      : emptyPlanes[pathname] || {};
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(payload));
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    maliciousTimeline,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolveClose) => server.close(resolveClose));
    },
  };
}

async function run() {
  // 1. Registry ⇔ matrix agreement (code identity vs certification evidence, joined by slug).
  const matrix = JSON.parse(readFileSync(join(APP, "harvest-app-parity-matrix.json"), "utf8"));
  const atlas = JSON.parse(readFileSync(join(APP, "application-operational-depth.json"), "utf8"));
  const certified = (matrix.seeds || []).filter((s) => s.shell_pixel_certified && s.candidate_surface);
  const regBySlug = new Map(SURFACES.map((s) => [s.slug, s]));
  ok("registry covers every certified seed", certified.every((s) => regBySlug.has(s.slug)), `${SURFACES.length} registry vs ${certified.length} certified`);
  const certifiedSlugs = new Set(certified.map((s) => s.slug));
  const contractReadOnly = SURFACES.filter((s) => !certifiedSlugs.has(s.slug));
  ok("registry additions beyond certified seeds resolve committed contract evidence and a bound read-only module",
    contractReadOnly.every((s) => contractCatalogAdmission(s, atlas).admitted),
    contractReadOnly.map((s) => s.slug).join(",") || "none");
  const unproven = {
    ...contractReadOnly[0],
    slug: "__unproven_read_only",
    title: "Unproven",
    route: "/__ioi/__unproven-read-only",
    catalog_evidence: {
      ...contractReadOnly[0]?.catalog_evidence,
      evidence_key: "__unproven_read_only",
    },
  };
  const adversarialCatalog = buildAppCatalog({
    matrix,
    atlas,
    surfaces: [...SURFACES, unproven],
    resolveBinding: (route) => route === unproven.route
      ? boundSurface(contractReadOnly[0].route, "GET")
      : boundSurface(route, "GET"),
  });
  ok("negative control: a second self-labeled read-only surface cannot enter the catalog without exact evidence",
    !adversarialCatalog.apps.some((app) => app.slug === unproven.slug));
  ok("registry routes match matrix candidate surfaces", certified.every((s) => regBySlug.get(s.slug)?.route === s.candidate_surface.split("?")[0]));
  ok("registry certification paths match matrix artifacts", certified.every((s) => regBySlug.get(s.slug)?.certification === s.shell_pixel_certification_artifact));
  ok("registry entries carry owner + title + icon", SURFACES.every((s) => s.owner && s.title && s.icon));
  ok("every registry verifier exists on disk", SURFACES.every((s) => existsSync(join(APP, s.verifier))), SURFACES.filter((s) => !existsSync(join(APP, s.verifier))).map((s) => s.verifier).join(" ") || "all present");

  // 2. Catalog reads registry presentation; pipeline serves through the registry mount.
  const cat = JSON.parse((await sGet("/__ioi/api/applications")).text);
  ok("catalog titles come from the registry", (cat.apps || []).every((a) => regBySlug.get(a.slug)?.title === a.title), `${(cat.apps || []).length} catalog apps`);
  const admittedCatalogSlugs = new Set([
    ...certified.map((surface) => surface.slug),
    ...contractReadOnly.filter((surface) => contractCatalogAdmission(surface, atlas).admitted).map((surface) => surface.slug),
  ]);
  ok("catalog membership equals certified surfaces plus exact contract-evidence admissions",
    (cat.apps || []).length === admittedCatalogSlugs.size
      && (cat.apps || []).every((app) => admittedCatalogSlugs.has(app.slug))
      && [...admittedCatalogSlugs].every((slug) => (cat.apps || []).some((app) => app.slug === slug)));
  const pipe = await sGet("/__ioi/pipeline");
  ok("pipeline serves through the registry mount", pipe.status === 200 && pipe.text.includes("<title>Pipeline Builder</title>") && pipe.text.includes("Pipeline outputs"), `status ${pipe.status}`);
  const boomLive = await sGet("/__ioi/__test/boom");
  ok("fault route does NOT exist without the flag", boomLive.status !== 500, `status ${boomLive.status} (must not be a mounted throwing route)`);

  // 3. Route isolation on an ISOLATED serve (dead daemon; fault route mounted via the flag).
  const child = spawn(process.execPath, [join(HERE, "serve-product-ui.mjs")], {
    env: { ...process.env, PORT: String(FAULT_PORT), PRODUCT_UI_PORT: String(FAULT_UI_PORT), IOI_HYPERVISOR_DAEMON_URL: "http://127.0.0.1:1", IOI_APP_RUNTIME_TEST_ROUTE: "1" },
    stdio: "ignore",
  });
  try {
    const base = `http://127.0.0.1:${FAULT_PORT}`;
    let up = null;
    for (let i = 0; i < 30 && !up; i++) {
      await new Promise((r) => setTimeout(r, 500));
      up = await sGet("/__ioi/applications", base).catch(() => null);
    }
    ok("isolated serve reachable", !!up && up.status === 200, up ? `status ${up.status}` : "never came up");
    const boom1 = await sGet("/__ioi/__test/boom", base).catch(() => null);
    ok("throwing route fails as a 500 on that route", !!boom1 && boom1.status === 500 && boom1.text.includes("Surface error"), boom1 ? `status ${boom1.status}` : "no response");
    const sib1 = await sGet("/__ioi/pipeline", base).catch(() => null);
    ok("sibling surface still serves after the fault", !!sib1 && sib1.status === 200, sib1 ? `status ${sib1.status}` : "process died — isolation failed");
    const boom2 = await sGet("/__ioi/__test/boom", base).catch(() => null);
    ok("fault is repeatable, still isolated", !!boom2 && boom2.status === 500);
    // Regression pins for the #46 incident class (both routes crashed the process before PR 55).
    const da = await sGet("/__ioi/domain-apps", base).catch(() => null);
    ok("#46 pin: /__ioi/domain-apps renders (DOMAIN_APP_VIS restored)", !!da && da.status === 200, da ? `status ${da.status}` : "no response");
    const odk = await sGet("/__ioi/odk/ontologies/new", base).catch(() => null);
    ok("#46 pin: /__ioi/odk family routes render (ODK_UI restored)", !!odk && odk.status === 200, odk ? `status ${odk.status}` : "no response");
    ok("estate process survived every fault", child.exitCode === null, child.exitCode === null ? "alive" : `exited ${child.exitCode}`);
  } finally {
    child.kill("SIGTERM");
  }

  // 4. Operations owner boundary: hostile timeline data cannot become markup, and a daemon lane
  // that stalls before headers or during body parsing cannot hang the embedded route.
  const hostileDaemon = await startHostileOperationsDaemon();
  const operationsChild = spawn(process.execPath, [join(HERE, "serve-product-ui.mjs")], {
    env: {
      ...process.env,
      PORT: String(OPERATIONS_FAULT_PORT),
      PRODUCT_UI_PORT: String(OPERATIONS_FAULT_UI_PORT),
      IOI_HYPERVISOR_DAEMON_URL: hostileDaemon.base,
    },
    stdio: "ignore",
  });
  try {
    const base = `http://127.0.0.1:${OPERATIONS_FAULT_PORT}`;
    let up = null;
    for (let i = 0; i < 30 && !up; i++) {
      await new Promise((r) => setTimeout(r, 250));
      up = await sGet("/__ioi/applications", base).catch(() => null);
    }
    ok("hostile-daemon serve reachable", !!up && up.status === 200, up ? `status ${up.status}` : "never came up");
    const startedAt = Date.now();
    const operations = await fetch(`${base}/__ioi/operations?embed=1`, {
      signal: AbortSignal.timeout(7_000),
    }).then(async (response) => ({ status: response.status, text: await response.text() })).catch(() => null);
    const elapsed = Date.now() - startedAt;
    ok("Operations returns within its bounded deadline when header and body lanes stall",
      !!operations && operations.status === 200 && elapsed < 6_000 && operations.text.includes("<h1>Operations</h1>"),
      operations ? `${operations.status} in ${elapsed}ms` : `no response after ${elapsed}ms`);
    ok("Operations preserves a canonical internal timeline link",
      !!operations && operations.text.includes('href="/__ioi/run-timeline/exec_safe"'));
    ok("Operations drops a hostile daemon timeline ref instead of emitting executable markup",
      !!operations
        && !operations.text.includes(hostileDaemon.maliciousTimeline)
        && !operations.text.includes("<img src=x")
        && !operations.text.includes("document.body.dataset.pwned")
        && !operations.text.includes('</script><img src=x onerror="document.body.dataset.namePwned=1">'));
    ok("Operations names unavailable projections and preserves unknown-not-zero semantics",
      !!operations
        && operations.text.includes('data-operations-unavailable="auth-policy,providers,storage-backends"')
        && operations.text.includes("unknown, not zero")
        && operations.text.includes("Authentication-policy projection unavailable")
        && operations.text.includes("Provider-account projection unavailable")
        && operations.text.includes("Storage-backend inventory unavailable"));
    ok("Operations never turns unavailable provider or malformed storage planes into empty-state claims",
      !!operations
        && !operations.text.includes("No BYO provider accounts yet")
        && !operations.text.includes("No storage backends yet"));
    const sibling = await sGet("/__ioi/applications", base).catch(() => null);
    ok("estate remains available after bounded Operations degradation",
      !!sibling && sibling.status === 200 && operationsChild.exitCode === null,
      sibling ? `status ${sibling.status}` : "serve exited");
  } finally {
    operationsChild.kill("SIGTERM");
    await hostileDaemon.close();
  }

  // 5. Static no-undef gate over the derived runtime set + the shipped augmentation bundle.
  const files = runtimeSet();
  ok("runtime set derived (serve + transitive imports)", files.length >= 14, `${files.length} modules`);
  const lint = eslintRun(files);
  ok("no-undef gate clean over the serve runtime", lint.code === 0, lint.code === 0 ? `${files.length} modules clean` : lint.out.split("\n").filter((l) => l.includes("error")).slice(0, 5).join(" | "));
  mkdirSync(ARTIFACTS, { recursive: true });
  const bundlePath = join(ARTIFACTS, "ioi.aug-bundle.js");
  const AUG = join(HERE, "augmentation");
  writeFileSync(bundlePath, readdirSync(AUG).filter((f) => f.endsWith(".js")).sort().map((f) => readFileSync(join(AUG, f), "utf8")).join(""));
  const lintAug = eslintRun([bundlePath]);
  ok("no-undef gate clean over the augmentation bundle", lintAug.code === 0, lintAug.code === 0 ? "bundle clean" : lintAug.out.split("\n").filter((l) => l.includes("error")).slice(0, 5).join(" | "));
  // Teeth: a planted dangling identifier must FAIL the gate (an always-green gate proves nothing).
  const teethPath = join(ARTIFACTS, "app-runtime-teeth-fixture.mjs");
  writeFileSync(teethPath, "export function f() { return UNDEFINED_REF_TEETH_FIXTURE; }\n");
  const teeth = eslintRun([teethPath]);
  rmSync(teethPath, { force: true });
  ok("gate has teeth (planted dangling ref fails it)", teeth.code === 1 && teeth.out.includes("no-undef"), `exit ${teeth.code}`);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("app-runtime safety: OK");
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
