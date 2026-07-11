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
//   3. REGISTRY — surface-registry.mjs agrees 1:1 with the parity matrix's certified seeds
//      (slug, route, certification artifact), its verifier files exist, the app catalog reads
//      registry presentation, and the pipeline pilot actually serves through the registry mount.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-runtime-safety.mjs
// Exit 0 = all assertions pass; exit 1 = one or more failed.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { SURFACES } from "./surface-registry.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const HERE = dirname(fileURLToPath(import.meta.url));
const APP = join(HERE, "..");
const ROOT = join(APP, "..", "..");
const ARTIFACTS = join(APP, ".artifacts");
const FAULT_PORT = 4604;
const FAULT_UI_PORT = 9404;

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

async function run() {
  // 1. Registry ⇔ matrix agreement (code identity vs certification evidence, joined by slug).
  const matrix = JSON.parse(readFileSync(join(APP, "harvest-app-parity-matrix.json"), "utf8"));
  const certified = (matrix.seeds || []).filter((s) => s.shell_pixel_certified && s.candidate_surface);
  const regBySlug = new Map(SURFACES.map((s) => [s.slug, s]));
  ok("registry covers every certified seed", certified.every((s) => regBySlug.has(s.slug)), `${SURFACES.length} registry vs ${certified.length} certified`);
  ok("registry invents no surfaces beyond the matrix", SURFACES.length === certified.length);
  ok("registry routes match matrix candidate surfaces", certified.every((s) => regBySlug.get(s.slug)?.route === s.candidate_surface.split("?")[0]));
  ok("registry certification paths match matrix artifacts", certified.every((s) => regBySlug.get(s.slug)?.certification === s.shell_pixel_certification_artifact));
  ok("registry entries carry owner + title + icon", SURFACES.every((s) => s.owner && s.title && s.icon));
  ok("every registry verifier exists on disk", SURFACES.every((s) => existsSync(join(APP, s.verifier))), SURFACES.filter((s) => !existsSync(join(APP, s.verifier))).map((s) => s.verifier).join(" ") || "all present");

  // 2. Catalog reads registry presentation; pipeline serves through the registry mount.
  const cat = JSON.parse((await sGet("/__ioi/api/applications")).text);
  ok("catalog titles come from the registry", (cat.apps || []).every((a) => regBySlug.get(a.slug)?.title === a.title), `${(cat.apps || []).length} catalog apps`);
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

  // 4. Static no-undef gate over the derived runtime set + the shipped augmentation bundle.
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
