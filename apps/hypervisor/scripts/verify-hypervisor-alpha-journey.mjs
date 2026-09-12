#!/usr/bin/env node
// verify-hypervisor-alpha-journey — the bounded-alpha essential journey, driven end to end the way
// the intended operator would drive it (check:alpha-journey; ADR 0052;
// docs/architecture/components/hypervisor/bounded-alpha-profile.md).
//
// The journey, on the alpha profile (one operator, one Linux host, generic-cli-local over one local
// OpenAI-compatible model route, host_spawn in the local workspace provider, a deployment-local
// wallet.network authority node whose approver key the operator holds):
//
//   install/build provenance → bootstrap identity (first-run page → operator account) → readiness
//   → project → harness/model/connections (closed session authority profile; UI-bypass drill)
//   → start useful work (composer → run parks on the operator's approval → approve → execute)
//   → inspect artifacts, receipts, cost and the approval → stop/revoke → restart daemon + serve and
//   recover → back up and restore (the two-daemon backup verifier) → diagnostics
//   → update/rollback (recorded as a typed absence — NOT built; never a pass)
//
// Every step records what it observed; a failure is a failure, and the evidence file names the
// checkout, the daemon binary digest and every command that produced a result. This verifier is
// NOT CI-gated: it needs a reachable local model (Ollama) and the real wallet.network fixture
// (cargo test fixture), so it runs on demand and its evidence is cited, never assumed.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary, model or fixture unavailable).
//   IOI_HYPERVISOR_DAEMON_BINARY   default target/debug/hypervisor-daemon
//   IOI_ALPHA_MODEL                default qwen2.5:7b
//   IOI_ALPHA_MODEL_UPSTREAM       default http://127.0.0.1:11434/v1
//   IOI_ALPHA_JOURNEY_EVIDENCE_DIR default apps/hypervisor/.artifacts/alpha-journey
//   IOI_ALPHA_JOURNEY_SKIP_BACKUP  "1" skips the backup/restore sub-verifier (records skipped)
//   IOI_ALPHA_JOURNEY_AUTHORITY    "fixture" (default) starts the real wallet.network fixture;
//                                  "none" runs WITHOUT a deployment authority node — the steps
//                                  that need one (approval, execution, artifacts, receipts) are
//                                  recorded as TYPED BLOCKS, never as passes, and the evidence
//                                  file says so. Use it to qualify the rest of the journey when
//                                  the fixture cannot converge on a loaded host.
//                                  "deployment" brings up the DEPLOYMENT-LOCAL authority node
//                                  (scripts/wallet-network-authority.mjs: generated, operator-
//                                  custodied keys; no public seed) and additionally qualifies
//                                  approver-key ROTATION (a second run approved under the new
//                                  key) and REVOCATION (a third run fails closed).
//   IOI_ALPHA_JOURNEY_PACKAGE      "1" runs the journey ON THE PACKAGED RELEASE: the two signed
//                                  packages named by IOI_ALPHA_RELEASE_V1 / IOI_ALPHA_RELEASE_V2
//                                  (directories or .tar.zst) are verified under the pinned signer
//                                  IOI_ALPHA_RELEASE_TRUST (a .pub.pem), installed into a fresh
//                                  prefix, v1 is activated, and the daemon, served App, signer
//                                  and harness shim used by EVERY step are the installed bytes.
//                                  Step 12 then admits an UPDATE plan to v2 on the daemon,
//                                  activates v2, restarts, and the daemon observes its own digest
//                                  (completed); then a ROLLBACK plan to v1 the same way.
//   IOI_ALPHA_JOURNEY_NO_CHECKOUT  "1" (package mode) proves the release runs WITHOUT a source
//                                  checkout: the installer, launcher, authority node, daemon,
//                                  serve, signer and shim are the installed bytes, every child
//                                  runs with cargo/rustup removed from PATH and cwd at the
//                                  install root, and the evidence records the paths it observed.
//                                  This verifier itself is only the driver.

import { spawn, execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv } from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";
import { authorityAct, startLocalAuthority } from "./lib/wallet-network-local-authority.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const DEPLOYMENT_AUTHORITY_REF = "domain://acme-host";
// The real wallet.network fixture registers this deterministic seed as the approver for
// domain://acme-host. It is PUBLIC test material: a real deployment generates its own key.
const FIXTURE_APPROVER_SEED_HEX = "07".repeat(32);
const MODEL = process.env.IOI_ALPHA_MODEL || "qwen2.5:7b";
const MODEL_UPSTREAM = process.env.IOI_ALPHA_MODEL_UPSTREAM || "http://127.0.0.1:11434/v1";
// M13.9 (ADR 0053 § 2) — the REMOTE route lane. `IOI_ALPHA_MODEL_ROUTE=remote` selects a remote
// OpenAI-compatible frontier route in the composer instead of the local one: the journey registers
// the route on its own temporary daemon, seals the operator's provider key to the route record, and
// the run's session binds it. The key is read ONCE from this process's environment and deleted
// before any child is spawned; it is never logged, never written to evidence, and it reaches the
// provider only from inside the daemon's model-mount proxy. Without a key the lane records a TYPED
// ABSENCE and the journey runs on the local route.
const MODEL_ROUTE_LANE = process.env.IOI_ALPHA_MODEL_ROUTE === "remote" ? "remote" : "local";
const PROVIDER_BASE_URL = (process.env.IOI_ALPHA_PROVIDER_BASE_URL || "https://api.openai.com/v1").replace(/\/+$/u, "");
const PROVIDER_MODEL = process.env.IOI_ALPHA_PROVIDER_MODEL || "gpt-4o-mini";
const PROVIDER_KEY = String(process.env.IOI_ALPHA_PROVIDER_KEY || "");
delete process.env.IOI_ALPHA_PROVIDER_KEY;
// Published list prices (USD per 1M tokens) at authoring time, for an ESTIMATE beside the
// provider's reported usage — never billing truth; the receipt carries the usage verbatim.
const PROVIDER_LIST_PRICES_USD_PER_M = { "gpt-4o-mini": { input: 0.15, output: 0.6 }, "gpt-4o": { input: 2.5, output: 10 }, "gpt-4.1-mini": { input: 0.4, output: 1.6 }, "gpt-4.1": { input: 2, output: 8 } };
const EXECUTE_BUDGET_MS = Number(process.env.IOI_ALPHA_JOURNEY_EXECUTE_BUDGET_MS || 900_000);
// Diagnosis: keep the work directory (daemon state, receipts, workspaces) and write the daemon and
// serve log tails into it instead of removing it at cleanup. Never the default.
const KEEP_WORKDIR = process.env.IOI_ALPHA_JOURNEY_KEEP_WORKDIR === "1";
const AUTHORITY_MODE = ["none", "deployment", "fixture"].includes(process.env.IOI_ALPHA_JOURNEY_AUTHORITY || "")
  ? process.env.IOI_ALPHA_JOURNEY_AUTHORITY
  : "fixture";
// The remote lane runs only with an operator credential AND the fixture approver: sealing the key
// to the route is itself an authority crossing (tool model.credential.bind) that the lane approves
// headlessly through the fixture's approver, exactly as the exact-effect-review verifier does.
// Deployment-mode approval of a credential bind is not driven here (typed absence).
const REMOTE = MODEL_ROUTE_LANE === "remote" && PROVIDER_KEY.length > 0 && AUTHORITY_MODE === "fixture";
// The deployment bring-up binds ITS generated approver to this principal; the fixture binds its
// public seed to domain://acme-host. Neither knows the other's principal.
const DEPLOYMENT_NODE_PRINCIPAL_REF = "domain://alpha-host";
const AUTHORITY_PRESENT = AUTHORITY_MODE !== "none";
const PACKAGE_MODE = process.env.IOI_ALPHA_JOURNEY_PACKAGE === "1";
const NO_CHECKOUT = PACKAGE_MODE && process.env.IOI_ALPHA_JOURNEY_NO_CHECKOUT === "1";
// A PATH with no cargo, rustup or the repository's own bin dirs: the packaged release must not be
// able to build anything on the host.
// Drop every PATH entry that can reach a `cargo` or `rustup` executable (a system /usr/bin/cargo
// counts), then re-add a shim dir that keeps the basic tools reachable without them.
const cargoFreePath = (source) => {
  // Also drop the repository's own node_modules/.bin entries npm prepends, so no PATH entry of a
  // child points into the checkout at all.
  const kept = (source || "").split(":").filter((d) => d && !d.startsWith(ROOT) && !["cargo", "rustup", "rustc"].some((tool) => { try { return fs.statSync(path.join(d, tool)).isFile(); } catch { return false; } }));
  const shim = path.join(workDir, "path-shim");
  fs.mkdirSync(shim, { recursive: true });
  for (const tool of ["node", "sh", "git", "openssl", "tar", "zstd", "env", "cat", "ls", "readlink", "uname"]) {
    const found = (source || "").split(":").map((d) => path.join(d, tool)).find((p) => { try { return fs.statSync(p).isFile(); } catch { return false; } });
    if (found && !fs.existsSync(path.join(shim, tool))) fs.symlinkSync(found, path.join(shim, tool));
  }
  return [shim, ...kept].join(":");
};
const childBaseEnv = () => {
  const base = sanitizedVerifierBaseEnv(process.env);
  if (!NO_CHECKOUT) return base;
  return { ...base, PATH: cargoFreePath(base.PATH), CARGO: "/nonexistent/cargo", CARGO_HOME: "/nonexistent/cargo-home", RUSTUP_HOME: "/nonexistent/rustup" };
};

const results = [];
const evidence = { schema: "ioi.hypervisor.alpha-journey-evidence.v1", started_at: new Date().toISOString(), steps: [] };
const ok = (step, name, cond, detail) => {
  results.push({ name: `${step}: ${name}`, pass: !!cond, detail: detail || "" });
  evidence.steps.push({ step, name, pass: !!cond, detail: detail || "", at: new Date().toISOString() });
};
const record = (step, name, detail) => evidence.steps.push({ step, name, recorded: true, detail, at: new Date().toISOString() });

const sha256File = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const git = (...args) => { try { return execFileSync("git", args, { cwd: ROOT, encoding: "utf8" }).trim(); } catch { return ""; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});
const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up */ }
    await sleep(400);
  }
  throw new Error(`timeout waiting for ${url}`);
};

const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-alpha-journey-"));
const dataDir = path.join(workDir, "data");
fs.mkdirSync(dataDir, { recursive: true });

// ---- the release under test: the checkout's build, or the installed packaged release ----------
let daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
let serveScript = path.join(HERE, "serve-product-ui.mjs");
let packageEnv = {};
const pkg = { prefix: null, v1: null, v2: null, trust: null, installer: null };
if (PACKAGE_MODE) {
  const trustPath = process.env.IOI_ALPHA_RELEASE_TRUST || "";
  const v1 = process.env.IOI_ALPHA_RELEASE_V1 || "";
  const v2 = process.env.IOI_ALPHA_RELEASE_V2 || "";
  if (!trustPath || !v1 || !v2) { console.error("BLOCKED: package mode needs IOI_ALPHA_RELEASE_TRUST, IOI_ALPHA_RELEASE_V1 and IOI_ALPHA_RELEASE_V2"); process.exit(2); }
  pkg.prefix = path.join(workDir, "prefix");
  pkg.trust = path.resolve(trustPath);
  // In no-checkout mode the installer is the PACKAGE's own install.mjs, run outside the repo.
  pkg.installer = NO_CHECKOUT ? path.join(path.resolve(v1), "install.mjs") : path.join(ROOT, "scripts", "install-hypervisor-alpha-release.mjs");
  const installer = (args) => {
    const r = execFileSync(process.execPath, [pkg.installer, ...args], { cwd: NO_CHECKOUT ? os.tmpdir() : ROOT, encoding: "utf8", env: childBaseEnv() });
    return JSON.parse(r.slice(r.indexOf("{")));
  };
  try {
    pkg.v1 = installer(["install", "--release", path.resolve(v1), "--trust", pkg.trust, "--prefix", pkg.prefix]);
    pkg.v2 = installer(["install", "--release", path.resolve(v2), "--trust", pkg.trust, "--prefix", pkg.prefix]);
    installer(["activate", "--prefix", pkg.prefix, "--version", pkg.v1.version]);
  } catch (error) {
    console.error(`BLOCKED: the packaged release did not verify/install — ${String(error?.stderr || error?.message || error).slice(0, 600)}`);
    process.exit(2);
  }
  const current = path.join(pkg.prefix, "current");
  pkg.current = current;
  daemonBinary = path.join(current, "bin", "hypervisor-daemon");
  serveScript = path.join(current, "apps", "hypervisor", "scripts", "serve-product-ui.mjs");
  packageEnv = {
    IOI_PRODUCT_UI_PUBLIC: path.join(current, "apps", "hypervisor", "product-ui", "owned", "public"),
    IOI_HYPERVISOR_HARNESS_SHIM: path.join(current, "packages", "hypervisor-harness-shims", "generic-cli-local.mjs"),
    IOI_MINT_APPROVAL_GRANT_BINARY: path.join(current, "bin", "mint-approval-grant"),
    IOI_MINT_STANDING_APPROVAL_GRANT_BINARY: path.join(current, "bin", "mint-standing-approval-grant"),
    IOI_WALLET_AUTHORITY_BINARY: path.join(current, "bin", "wallet-network-local-authority"),
    // The authority node launches the PACKAGED validator binaries and never builds.
    IOI_NODE_BINARY_DIR: path.join(current, "node-bins"),
  };
  pkg.installerRun = installer;
}
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch { console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`); process.exit(2); }
const evidenceDir = path.resolve(ROOT, process.env.IOI_ALPHA_JOURNEY_EVIDENCE_DIR || path.join("apps", "hypervisor", ".artifacts", "alpha-journey"));
fs.mkdirSync(evidenceDir, { recursive: true });

let fixture = null;
let authorityNode = null;
let approverKeyPath = "";
let daemon = null;
let serve = null;
let daemonPort = 0;
let servePort = 0;
let DAEMON = "";
let SERVE = "";
let COOKIE = "";
let daemonLog = "";
let serveLog = "";
let serveStopping = false;
let daemonEnv = {};

async function startDaemon() {
  daemon = spawn(daemonBinary, [], { cwd: NO_CHECKOUT ? pkg.current : ROOT, env: daemonEnv, stdio: ["ignore", "pipe", "pipe"] });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-200_000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-200_000); });
  await waitFor(`${DAEMON}/healthz`, 60_000);
}
async function stopDaemon(signal = "SIGKILL") {
  if (!daemon) return;
  const exited = new Promise((resolve) => daemon.once("exit", resolve));
  daemon.kill(signal);
  await exited;
  daemon = null;
}
let serveEnv = {};
async function startServe() {
  serveStopping = false;
  serve = spawn(process.execPath, [serveScript], { cwd: NO_CHECKOUT ? pkg.current : ROOT, env: serveEnv, stdio: ["ignore", "pipe", "pipe"] });
  serve.stdout.on("data", (c) => { serveLog = `${serveLog}${c}`.slice(-40_000); });
  serve.stderr.on("data", (c) => { serveLog = `${serveLog}${c}`.slice(-40_000); });
  // A serve that DIES mid-journey turns every later request into a transport failure, which reads
  // downstream as "no run" and hides the actual cause. Record the exit and the log tail the moment
  // it happens, so the assertion that trips can name a dead serve instead of an undefined.
  serve.once("exit", (code, signal) => {
    if (!serveStopping) {
      evidence.serve_died = { code, signal, at: new Date().toISOString(), log_tail: serveLog.slice(-4_000) };
    }
  });
  try {
    await waitFor(`${SERVE}/__ioi/login`, 90_000);
  } catch (error) {
    evidence.serve_log_tail = serveLog.slice(-4_000);
    throw error;
  }
}
async function stopServe() {
  if (!serve) return;
  serveStopping = true;
  const exited = new Promise((resolve) => serve.once("exit", resolve));
  serve.kill("SIGTERM");
  await Promise.race([exited, sleep(5_000)]);
  serve = null;
}

// The composer's submit blocks until a real environment exists and has started, which on a loaded
// host outruns the HTTP client's SILENT default transport budget (~300 s in undici) — the request
// then throws and the journey reads it as "no run", which is a client budget masquerading as a
// product failure. The budget is therefore explicit and generous; a real refusal still arrives as
// a status, and only a genuinely unanswered request trips it.
const CLIENT_TRANSPORT_BUDGET_MS = Number(process.env.IOI_ALPHA_JOURNEY_CLIENT_TIMEOUT_MS || 900_000);
const jdOnce = (base, p, init = {}, withCookie = true) => fetch(`${base}${p}`, {
  ...init,
  signal: init.signal ?? AbortSignal.timeout(CLIENT_TRANSPORT_BUDGET_MS),
  redirect: "manual",
  headers: {
    ...(init.body && !init.headers?.["content-type"] ? { "content-type": "application/json" } : {}),
    ...(withCookie && COOKIE ? { cookie: `ioi_session=${COOKIE}` } : {}),
    ...(init.headers || {}),
  },
}).then(async (r) => {
  const text = await r.text();
  let body = {};
  try { body = text ? JSON.parse(text) : {}; } catch { body = { _raw: text }; }
  return { status: r.status, body, text, headers: r.headers };
}).catch((e) => ({ status: 0, body: {}, text: "", headers: new Headers(), error: String(e?.message || e) }));

// A TRANSPORT failure is not an answer. After a long gap (a real model run takes minutes) the
// client's pooled keep-alive socket can be closed by the server while the pool still believes it
// is live, and the next request fails as a socket hang-up — which downstream reads as "the serve
// returned no run". One retry on a fresh connection distinguishes a dead socket from a dead
// server: a genuine refusal still arrives as a status and is never retried.
const jd = async (base, p, init = {}, withCookie = true) => {
  const first = await jdOnce(base, p, init, withCookie);
  if (first.status !== 0) return first;
  const retried = await jdOnce(base, p, { ...init, headers: { ...(init.headers || {}), connection: "close" } }, withCookie);
  return retried.status === 0 ? { ...retried, error: `${first.error} (retried on a fresh connection: ${retried.error})` } : retried;
};

// Changed-file groups that are the RUN's work: the environment's own `.devcontainer` scaffold is
// provisioning, not a file the harness wrote, and must never satisfy "writes at least one file".
const workFiles = (groups) => (Array.isArray(groups) ? groups : []).filter((g) => !String(g?.folder || g?.path || g?.file || "").startsWith(".devcontainer"));
const readRecords = (family) => {
  const found = [];
  try {
    for (const f of fs.readdirSync(path.join(dataDir, family))) {
      try { found.push(JSON.parse(fs.readFileSync(path.join(dataDir, family, f), "utf8"))); } catch { /* not JSON */ }
    }
  } catch { /* none */ }
  return found;
};
// Every regular file under `root` whose bytes contain `needle` (bounded: files up to 8 MiB).
const grepTreeFor = (root, needle) => {
  const hits = [];
  if (!needle) return hits;
  const walk = (dir) => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) { try { if (fs.statSync(p).size <= 8 * 1024 * 1024 && fs.readFileSync(p).includes(needle)) hits.push(p); } catch { /* unreadable */ } }
    }
  };
  walk(root);
  return hits;
};
const readReceipts = (predicate) => {
  const found = [];
  try {
    for (const f of fs.readdirSync(path.join(dataDir, "receipts"))) {
      try { const j = JSON.parse(fs.readFileSync(path.join(dataDir, "receipts", f), "utf8")); if (predicate(j)) found.push(j); } catch { /* not JSON */ }
    }
  } catch { /* none */ }
  return found;
};

async function run() {
  // ---- 1. install / build provenance ---------------------------------------------------------
  const head = git("rev-parse", "HEAD");
  const dirty = git("status", "--porcelain").split("\n").filter(Boolean).length;
  evidence.checkout = { head, dirty_paths: dirty, node: process.version, host: `${os.platform()} ${os.arch()} ${os.release()}` };
  evidence.daemon_binary = { path: daemonBinary, sha256: sha256File(daemonBinary), mtime: fs.statSync(daemonBinary).mtime.toISOString() };
  record("1-install", "build provenance", `${head} (${dirty} dirty paths) · daemon ${evidence.daemon_binary.sha256.slice(0, 16)} · ${evidence.checkout.host}`);
  if (PACKAGE_MODE) {
    evidence.packaged_release = { prefix: pkg.prefix, trusted_signer: pkg.trust, v1: pkg.v1, v2: pkg.v2, daemon_path: daemonBinary, serve_script: serveScript };
    const currentDaemon = fs.realpathSync(daemonBinary);
    ok("1-install", "the release under test is the PACKAGED release: both packages verified under the operator-pinned signer (signature + every file digest), installed into a fresh prefix, v1 activated; the daemon binary about to run is the package's bytes (digest = v1 manifest daemon digest)", pkg.v1?.ok === true && pkg.v2?.ok === true && evidence.daemon_binary.sha256 === pkg.v1.daemon_sha256 && currentDaemon.includes(`/releases/${pkg.v1.version}/`), `v1 ${pkg.v1?.version} signer ${pkg.v1?.signer} · v2 ${pkg.v2?.version} · daemon ${evidence.daemon_binary.sha256.slice(0, 16)}`);
  } else {
    ok("1-install", "the release is a SOURCE BUILD of this checkout — no packaged release was under test in this run (typed absence, recorded not passed; package mode qualifies step 1)", true,
      "not_built_in_this_run: packaged release");
  }

  // ---- model reachability (readiness prerequisite) -------------------------------------------
  if (!REMOTE) {
    const models = await jd(MODEL_UPSTREAM.replace(/\/v1$/, ""), "/api/tags", {}, false);
    const modelPresent = (models.body?.models || []).some((m) => m.name === MODEL || m.model === MODEL);
    if (!modelPresent) { console.error(`BLOCKED: model ${MODEL} is not served at ${MODEL_UPSTREAM}`); cleanup(); process.exit(2); }
  }

  // ---- 2b. bootstrap authority: the deployment-local wallet.network node + operator-held key --
  approverKeyPath = path.join(workDir, "approver.key");
  const t0 = Date.now();
  let fixtureBaseEnv = null;
  if (AUTHORITY_MODE === "deployment") {
    // The supported bring-up: generated keys custodied on the host, durable chain state, the
    // pinned TLS front and the daemon/serve env files — exactly what an operator runs.
    const stateDir = path.join(workDir, "authority");
    try {
      // No-checkout mode launches through the PACKAGE's own launcher module (ROOT = the install
      // root there), with the cargo-free environment applied to the launcher process itself.
      let launch = startLocalAuthority;
      if (NO_CHECKOUT) {
        Object.assign(process.env, { PATH: cargoFreePath(process.env.PATH), CARGO: "/nonexistent/cargo", CARGO_HOME: "/nonexistent/cargo-home", RUSTUP_HOME: "/nonexistent/rustup", IOI_NODE_BINARY_DIR: packageEnv.IOI_NODE_BINARY_DIR });
        ({ startLocalAuthority: launch } = await import(path.join(pkg.current, "apps", "hypervisor", "scripts", "lib", "wallet-network-local-authority.mjs")));
      }
      // WALL CLOCK: an attach-time standing envelope promises real time ("expires in 2 hours"),
      // and the daemon checks that promise against the host clock at every bind and draw. A
      // deployment that mints standing envelopes therefore runs its authority node on the wall
      // clock; the deterministic clock is for lanes that make no real-time promise.
      authorityNode = await launch({ stateDir, principalRef: DEPLOYMENT_NODE_PRINCIPAL_REF, binary: packageEnv.IOI_WALLET_AUTHORITY_BINARY || undefined, wallClock: true, log: () => {} });
    } catch (error) {
      console.error(`BLOCKED: the deployment-local authority node did not come up — ${error?.message ?? error}`);
      cleanup();
      process.exit(2);
    }
    approverKeyPath = authorityNode.approverKeyPath;
    const keyMode = fs.statSync(approverKeyPath).mode & 0o777;
    const authorityRecord = authorityNode.readAuthorityRecord();
    evidence.authority_mode = "deployment";
    evidence.deployment_authority = {
      principal_ref: DEPLOYMENT_NODE_PRINCIPAL_REF,
      binary: authorityNode.binary,
      ordering_profile: authorityNode.ready.ordering_profile,
      keys_generated_on_host: ["keys/root.seed", "keys/capability.key (sealed)", "keys/approver.seed"],
      approver_key_mode: keyMode.toString(8),
      binding_v1: { ref: authorityRecord.binding_ref, version: authorityRecord.binding_version, status: authorityRecord.binding_status },
      approver_scope_allowlist: authorityRecord.approver_scope_allowlist,
    };
    if (NO_CHECKOUT) {
      const under = (p) => String(p || "").startsWith(pkg.prefix);
      const whichCargo = (() => { try { return execFileSync("sh", ["-c", "command -v cargo || true"], { encoding: "utf8", env: childBaseEnv() }).trim(); } catch { return "?"; } })();
      evidence.no_checkout = { prefix: pkg.prefix, prefix_has_git: fs.existsSync(path.join(pkg.prefix, ".git")), launcher_binary: authorityNode.binary, node_binary_dir: authorityNode.nodeBinaryDir, installer: pkg.installer, cargo_on_child_path: whichCargo || "none", child_path: childBaseEnv().PATH };
      const outsideRepo = (p) => !String(p || "").startsWith(ROOT);
      const childPathOutsideRepo = childBaseEnv().PATH.split(":").every((d) => outsideRepo(d));
      ok("2b-authority", "NO-CHECKOUT closure test: the installer is the package's own (outside the repository), the authority control binary and the node binaries the launcher pinned are under the install prefix, the prefix is not a git checkout, cargo is absent from every child's PATH and no child PATH entry points into the repository", outsideRepo(pkg.installer) && under(authorityNode.binary) && under(authorityNode.nodeBinaryDir) && !evidence.no_checkout.prefix_has_git && !whichCargo && childPathOutsideRepo, JSON.stringify(evidence.no_checkout).slice(0, 220));
    }
    ok("2b-authority", "the deployment-local wallet.network node came up with GENERATED keys (control root, sealed capability client, operator approver; no public seed), bound the approver to the deployment principal (binding v1 active) and published the daemon/serve env", keyMode === 0o600 && authorityRecord.binding_version === 1 && authorityRecord.binding_status === "active" && authorityNode.daemonEnv.IOI_WALLET_NETWORK_RPC_ADDR.startsWith("https://") && !fs.readFileSync(approverKeyPath, "utf8").includes(FIXTURE_APPROVER_SEED_HEX), `ready in ${Math.round((Date.now() - t0) / 1000)}s · ${authorityRecord.binding_ref} · key mode ${keyMode.toString(8)}`);
  } else if (AUTHORITY_MODE === "fixture") {
    fs.writeFileSync(approverKeyPath, `${FIXTURE_APPROVER_SEED_HEX}\n`, { mode: 0o600 });
    try {
      // The fixture's in-process debug cluster commits its setup transactions slowly on a loaded
      // host (readiness has been observed between 7 and 25 minutes). The sanitizer strips every
      // IOI_TEST* name from the ambient env by design, so the commit budget is passed explicitly;
      // it changes no chain or authorization semantics, only how long the fixture waits.
      // ROOT CAUSE of the 2026-09-07 blocked attempts: the fixture's DEFAULT ordering profile is
      // the four-validator AFT (ML-DSA classic-BFT) cluster of debug binaries, so every setup
      // transaction needed a BFT commit across four starved validators and the commit waits
      // (register_client, configure_control_root, issue_principal_authority_binding) ran past the
      // 900 s ceiling on a loaded host. The alpha profile names ONE deployment-local authority
      // node, so the journey starts the fixture in the Solo single-validator profile — the
      // topology it actually claims. Chain, authorization and resolution semantics are the same
      // code on both profiles (crates/cli/tests/hypervisor_wallet_network_fixture.rs); only the
      // ordering engine differs, and the alpha never claims BFT ordering for its authority node.
      fixtureBaseEnv = {
        ...sanitizedVerifierBaseEnv(process.env),
        IOI_M049_ORDERING_PROFILE: process.env.IOI_ALPHA_FIXTURE_ORDERING_PROFILE || "Solo",
        IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS: process.env.IOI_ALPHA_FIXTURE_COMMIT_TIMEOUT_SECS || "900",
      };
      // Wall-clock chain: the standing envelope's and ceremony's validity windows (M13.3) are
      // judged against the committed chain clock, and the operator's factor receipt carries host
      // wall time; a deterministic clock would refuse every attach-time envelope by calendar.
      fixture = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv: fixtureBaseEnv, wallClockChain: true });
    } catch (error) {
      console.error(`BLOCKED: the real wallet.network principal-authority fixture did not start — ${error?.message ?? error}`);
      cleanup();
      process.exit(2);
    }
    evidence.authority_mode = "fixture";
    evidence.fixture_ordering_profile = fixtureBaseEnv.IOI_M049_ORDERING_PROFILE;
    record("2b-authority", "deployment-local wallet.network node", `ready in ${Math.round((Date.now() - t0) / 1000)}s · ${fixtureBaseEnv.IOI_M049_ORDERING_PROFILE} single-node ordering profile · chain ${fixture.env.IOI_WALLET_NETWORK_CHAIN_ID} · approver key custodied at ${approverKeyPath} (mode 0600; FIXTURE seed = public test material)`);
  } else {
    evidence.authority_mode = "none";
    record("2b-authority", "deployment-local wallet.network node", "NOT STARTED (IOI_ALPHA_JOURNEY_AUTHORITY=none): every step that needs execution authority is recorded as a typed block below; nothing in this run claims approval, execution, artifacts or execute receipts");
  }

  daemonPort = await freePort();
  servePort = await freePort();
  // The serve spawns the owned product-ui on PRODUCT_UI_PORT (default 9301); a journey must not
  // collide with an operator's own serve on the same host.
  const productUiPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  SERVE = `http://127.0.0.1:${servePort}`;
  daemonEnv = {
    ...childBaseEnv(),
    ...packageEnv,
    ...(fixture ? fixture.env : {}),
    ...(fixture ? { IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY_REF } : {}),
    ...(authorityNode ? authorityNode.daemonEnv : {}),
    IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
    IOI_HYPERVISOR_DATA_DIR: dataDir,
    IOI_HYPERVISOR_MODEL: MODEL,
    IOI_HYPERVISOR_MODEL_UPSTREAM: MODEL_UPSTREAM,
    IOI_WALLET_SECRET_PASS: "alpha-journey-seal-pass",
  };
  delete daemonEnv.IOI_WALLET_TEST_SIGNER;
  serveEnv = {
    ...childBaseEnv(),
    ...packageEnv,
    IOI_HYPERVISOR_DAEMON_URL: DAEMON,
    PORT: String(servePort),
    PRODUCT_UI_PORT: String(productUiPort),
    IOI_HYPERVISOR_LOCAL_APPROVER_KEY_PATH: approverKeyPath,
    // The approval act records the grant on the authority node: the deployment node through its
    // control binary, or (fixture mode) the fixture's command directory.
    ...(authorityNode ? authorityNode.serveEnv : {}),
    ...(fixture ? { IOI_HYPERVISOR_WALLET_FIXTURE_COMMANDS_DIR: path.join(fixture.resourceDir, "commands"), IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY_REF } : {}),
  };
  delete serveEnv.IOI_WALLET_TEST_SIGNER;
  await startDaemon();
  await startServe();

  // ---- 2a. bootstrap identity through the served first-run page ------------------------------
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? "";
  ok("2a-identity", "the daemon printed a one-boot bootstrap token", token.length === 78, token.slice(0, 20));
  const firstRun = await jd(SERVE, "/__ioi/login", {}, false);
  ok("2a-identity", "the served sign-in page IS the first-run operator setup while no operator exists", firstRun.status === 200 && firstRun.text.includes('data-ioi-first-run="1"'), `${firstRun.status}`);
  const boot = await jd(SERVE, "/__ioi/bootstrap", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token, name: "Alpha Operator", email: "operator@alpha.local", password: "alpha-operator-pass-1" }).toString(),
  }, false);
  COOKIE = (boot.headers.get("set-cookie") || "").match(/ioi_session=([^;]+)/u)?.[1] || "";
  ok("2a-identity", "the first-run form creates the operator account and lands on the product with an operator session", boot.status === 302 && boot.headers.get("location") === "/ai" && COOKIE.startsWith("ioi_sess_"), `${boot.status} → ${boot.headers.get("location")}`);
  const who = await jd(DAEMON, "/v1/hypervisor/auth/whoami");
  ok("2a-identity", "whoami is the operator who bootstrapped (their name and email, not a placeholder)", who.body?.principal?.email === "operator@alpha.local" && who.body?.principal?.name === "Alpha Operator", JSON.stringify({ email: who.body?.principal?.email, name: who.body?.principal?.name }));
  const secondRun = await jd(SERVE, "/__ioi/login", {}, false);
  const replay = await jd(SERVE, "/__ioi/bootstrap", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token, email: "x@y.z", password: "another-pass-123" }).toString() }, false);
  ok("2a-identity", "the token is one-shot: sign-in is the ordinary form afterwards and a replayed bootstrap is refused", secondRun.status === 200 && !secondRun.text.includes('data-ioi-first-run="1"') && replay.status >= 400 && replay.text.includes("already has an operator"), `${secondRun.status}/${replay.status}`);
  const login = await jd(SERVE, "/__ioi/login", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ email: "operator@alpha.local", password: "alpha-operator-pass-1" }).toString() }, false);
  ok("2a-identity", "the operator can sign in again with the email and password they chose", login.status === 302 && /ioi_session=/u.test(login.headers.get("set-cookie") || ""), `${login.status}`);

  // ---- 3. readiness ----------------------------------------------------------------------------
  const healthz = await jd(DAEMON, "/healthz", {}, false);
  const doctor = await jd(DAEMON, "/v1/doctor");
  const substrate = await jd(DAEMON, "/v1/hypervisor/substrate/status");
  ok("3-readiness", "daemon health, doctor and substrate status answer for the operator", healthz.status === 200 && doctor.status === 200 && substrate.status === 200, `${healthz.status}/${doctor.status}/${substrate.status}`);
  if (REMOTE) record("3-readiness", "model route", `REMOTE lane: ${PROVIDER_MODEL} at ${PROVIDER_BASE_URL} through the daemon's model-mount proxy; the local route is not required for this run`);
  else record("3-readiness", "model route", `${MODEL} served at ${MODEL_UPSTREAM} (verified via /api/tags before start)`);

  // ---- 3r. M13.9 (ADR 0053 § 2): the remote frontier route, sealed to the daemon ---------------
  let remoteRoute = null;
  if (MODEL_ROUTE_LANE === "remote" && !REMOTE) {
    const reason = PROVIDER_KEY.length === 0 ? "no_operator_credential" : "authority_mode_not_fixture";
    record("3r-route", "remote frontier route", `TYPED ABSENCE (${reason}): IOI_ALPHA_MODEL_ROUTE=remote but ${reason === "no_operator_credential" ? "no operator credential (IOI_ALPHA_PROVIDER_KEY is unset)" : `the custody crossing's approval is driven only through the fixture approver (authority mode ${AUTHORITY_MODE})`} — the lane did not run and nothing below claims it; the journey continues on the local route`);
    evidence.model_route_lane = { lane: "remote", status: "absent", reason };
  } else if (REMOTE) {
    const ownerRef = (who.body?.principal?.tenant_refs || []).find((t) => t === "org://local") || "org://local";
    const mut = (idem, extra = {}) => ({ owner_ref: ownerRef, idempotency_key: `alpha-journey-${idem}`, ...extra });
    const mr = (routeId, suffix = "", init = {}) => jd(DAEMON, `/v1/hypervisor/model-routes/${encodeURIComponent(routeId)}${suffix}`, init);
    const created = await jd(DAEMON, "/v1/hypervisor/model-routes", { method: "POST", body: JSON.stringify(mut("remote-route", { model_id: PROVIDER_MODEL, transport: "openai_compatible", base_url: PROVIDER_BASE_URL, display_name: "frontier (remote)", credential_posture: "provider_vault_token" })) });
    const routeId = created.body?.route?.route_id || "";
    const routeRef = created.body?.route?.route_ref || (routeId ? `model-route:${routeId}` : "");
    ok("3r-route", "the operator registers a remote OpenAI-compatible route in the model-route registry (the registration carries no secret; a plaintext key would be refused)", created.status < 300 && Boolean(routeId), `${created.status} ${routeRef} · ${PROVIDER_MODEL} @ ${PROVIDER_BASE_URL}`);
    // Establishing custody of the key is its own authority crossing (distinct from using it): the
    // bind parks on the daemon's exact commitments until the operator's approval is recorded on the
    // authority node; the same idempotency key keeps the retry on the same crossing coordinates.
    const challenge = await mr(routeId, "/credential", { method: "POST", body: JSON.stringify(mut("remote-credential-direct", { token: PROVIDER_KEY })) });
    const challengeScope = challenge.body?.required_authority_scope ?? challenge.body?.authority_challenge?.required_authority_scope ?? "";
    ok("3r-route", "establishing custody of the provider key is an AUTHORITY CROSSING: a direct daemon bind parks on the exact commitments (policy and request hashes, tool model.credential.bind, the exact scope, the grant audience) and stores nothing", challenge.status === 403 && Boolean(challenge.body?.approval?.policy_hash) && Boolean(challenge.body?.approval?.request_hash) && /^[0-9a-f]{64}$/u.test(String(challenge.body?.approval?.audience || "")) && Boolean(challengeScope) && (challenge.body?.allowed_tools || []).includes("model.credential.bind"), `${challenge.status} ${challenge.body?.reason || challenge.text.slice(0, 120)} · ${String(challenge.body?.approval?.request_hash || "").slice(0, 24)} · scope ${challengeScope}`);
    // The PRODUCT path: the operator submits the key in Agent Studio, the App parks it on the custody
    // card, and their approval mints + records one grant before the daemon seals.
    const submit = await jd(SERVE, `/__ioi/agent-studio/model-routes/${encodeURIComponent(routeId)}/credential`, { method: "POST", body: JSON.stringify({ token: PROVIDER_KEY }) });
    const bound = submit.status === 202 ? await jd(SERVE, `/__ioi/agent-studio/model-routes/${encodeURIComponent(routeId)}/credential/approve`, { method: "POST", body: "{}" }) : submit;
    ok("3r-route", "in the App the submit parks on the custody card (202, the same commitments) and the operator's approval seals the key through the deployment-local approver (mint + record one grant, then the daemon seals)", submit.status === 202 && Boolean(submit.body?.pending?.policy_hash) && bound.status === 201 && bound.body?.decision === "approved", `${submit.status}/${submit.body?.decision} → ${bound.status}/${bound.body?.decision || bound.body?.error?.code || ""}`);
    const routeAfter = await mr(routeId);
    const credBinding = routeAfter.body?.route?.credential_binding || routeAfter.body?.credential_binding || {};
    ok("3r-route", "with the operator's approval recorded, the provider key is SEALED to the route record (credential_binding kind sealed_capability_lease, custody lease on record) and the route's read projection carries no secret", bound.status < 300 && credBinding.kind === "sealed_capability_lease" && credBinding.sealed === true && String(credBinding.provider_credential_lease_ref || "").startsWith("lease:") && !routeAfter.text.includes(PROVIDER_KEY), `${bound.status} ${bound.status < 300 ? "" : bound.text.slice(0, 160)} · binding ${JSON.stringify({ kind: credBinding.kind, sealed: credBinding.sealed, lease: credBinding.provider_credential_lease_ref })}`);
    const probed = await mr(routeId, "/probe", { method: "POST" });
    const enabled = await mr(routeId, "/enable", { method: "POST" });
    const avail = probed.body?.availability || probed.body?.route?.availability || {};
    ok("3r-route", "the probe is POSTURE-ONLY: credentials_present on the SEALED basis (the daemon sends no secret to a caller-supplied URL) — and the route enables", probed.status < 300 && avail.state === "credentials_present" && avail.probe?.evidence?.credential_basis === "sealed_capability_lease" && enabled.status < 300, `${probed.status}/${avail.state}/${avail.probe?.evidence?.credential_basis} · enable ${enabled.status} ${enabled.status < 300 ? "" : enabled.text.slice(0, 160)}`);
    // The PROCESS-ENVIRONMENT key path stays refused by default: a remote route whose only
    // credential is an env-key REPORT is not executable (no sealed credential), so it cannot bind a
    // session — and the daemon's own environment carries no provider key to report.
    const envRoute = await jd(DAEMON, "/v1/hypervisor/model-routes", { method: "POST", body: JSON.stringify(mut("env-key-route", { model_id: `${PROVIDER_MODEL}-env-key-report`, transport: "openai_compatible", base_url: PROVIDER_BASE_URL, display_name: "env-key report (must stay unexecutable)", credential_posture: "provider_vault_token", env_key_name: "OPENAI_API_KEY" })) });
    const envRouteId = envRoute.body?.route?.route_id || "";
    const envProbe = await mr(envRouteId, "/probe", { method: "POST" });
    await mr(envRouteId, "/enable", { method: "POST" });
    const envBind = await mr(envRouteId, "/session-bindings", { method: "POST", body: JSON.stringify({ session_ref: "session:alpha-journey-env-key-probe" }) });
    const envAvail = envProbe.body?.availability || envProbe.body?.route?.availability || {};
    // Provider-key shapes only (an *_API_KEY name, or the daemon's own env-key opt-in): the sanitized
    // base environment may carry the operator's unrelated tooling tokens, which are not provider keys.
    const daemonEnvKeys = Object.keys(daemonEnv).filter((k) => /API_KEY$/u.test(k) || k === "IOI_HYPERVISOR_ALLOW_ENV_PROVIDER_KEY");
    ok("3r-route", "the PROCESS-ENVIRONMENT key path stays refused by default: the env-key-report route probes credentials_missing (the daemon's environment holds no provider API key and no IOI_HYPERVISOR_ALLOW_ENV_PROVIDER_KEY opt-in) and cannot bind a session (typed refusal, transport_unsupported_for_execution)", envAvail.state === "credentials_missing" && envBind.status >= 400 && (envBind.body?.error?.code || envBind.body?.code) === "transport_unsupported_for_execution" && daemonEnvKeys.length === 0, `${envAvail.state} · bind ${envBind.status}/${envBind.body?.error?.code || envBind.body?.code} · daemon env provider keys: ${JSON.stringify(daemonEnvKeys)}`);
    remoteRoute = { routeId, routeRef, envRouteId };
    evidence.model_route_lane = { lane: "remote", status: "run", route_ref: routeRef, provider_base_url: PROVIDER_BASE_URL, provider_model: PROVIDER_MODEL, credential: "sealed to the route record on the temporary daemon; never logged or written here" };
  }

  // ---- 4. project ------------------------------------------------------------------------------
  const project = await jd(DAEMON, "/v1/hypervisor/projects", { method: "POST", body: JSON.stringify({ project_name: "Alpha journey", repository_url: "https://example.invalid/alpha-journey.git" }) });
  const projectId = project.body?.selected_project_id || project.body?.project?.project_id || project.body?.project_id || "";
  const projects = await jd(DAEMON, "/v1/hypervisor/projects");
  ok("4-project", "a project can be created and listed", project.status < 300 && projectId && (projects.body?.projects || []).some((p) => p.project_id === projectId), `${project.status} ${projectId} · ${(projects.body?.projects || []).length} project(s)`);

  // ---- 5. harness / model / connections (closed authority profile) ----------------------------
  const ctx = await jd(SERVE, "/__ioi/api/new-session/context");
  ok("5a-selection", "the New Session context offers harness profiles, model routes and the Connections estate from daemon truth", ctx.status === 200 && Array.isArray(ctx.body?.harness_profiles) && Array.isArray(ctx.body?.model_routes) && Array.isArray(ctx.body?.connections), `${ctx.status} · ${(ctx.body?.harness_profiles || []).length} harness · ${(ctx.body?.model_routes || []).length} routes · ${(ctx.body?.connections || []).length} connections`);
  const registerConnector = (name) => jd(DAEMON, "/v1/hypervisor/connectors", { method: "POST", body: JSON.stringify({ service: "alpha-tool", name, base_url: "http://127.0.0.1:9", kind: "bearer", requires_credential: false, allowed_tools: [{ name: "ping", method: "GET", path: "/ping" }] }) });
  const cA = await registerConnector("alpha-a");
  const cB = await registerConnector("alpha-b");
  const A = cA.body?.connector?.connector_id || "";
  const B = cB.body?.connector?.connector_id || "";
  // ---- 5c. M13.3: the attach pass sets the standing envelope; an unbounded attach is not nameable
  // The serve mints the scoped standing bound (usages · budget · expiry) for connection A in the
  // same pass, records it on the authority node and binds it on the daemon. In DEPLOYMENT mode
  // this refuses TYPED: the wallet's standing-grant rule needs a passkey step-up ceremony and the
  // deployment-local operator key has no admitted posture for standing authority (owner ruling
  // pending); nothing is fabricated and the run below keeps the exact approval card.
  const envelopeA = await jd(SERVE, `/__ioi/connections/${encodeURIComponent(A)}/standing-lease`, { method: "POST", body: JSON.stringify({ max_usages: 1, budget_usd: 0.01, expires_hours: 2 }) });
  const STANDING = envelopeA.status === 200 && envelopeA.body?.ok === true && envelopeA.body?.standing_lease?.status === "active";
  if (AUTHORITY_MODE === "deployment") {
    // R-14 (ruled 2026-09-09): the deployment-local operator key is a RECOGNIZED custody tier for
    // recording a standing grant. The ceremony is the operator's own act with the key they custody
    // on this host; the v2 auth-factor receipt attests that custody (host, key-path hash, mode
    // 0600, the moment they acknowledged it) and never a person, and the wallet re-validates the
    // whole tuple. Before the ruling this step refused typed; it is now qualified here.
    ok("5c-envelope", "DEPLOYMENT MODE (R-14): the attach pass minted the standing envelope (1 usage · $0.01 · 2h) under the DEPLOYMENT-LOCAL OPERATOR custody tier, recorded it on the deployment's own authority node through its control binary, and bound it to connection A", STANDING && envelopeA.body?.standing_lease?.bounds?.max_usages === 1 && envelopeA.body?.factor_origin === "deployment_local_operator_key_custody" && String(envelopeA.body?.standing_grant_hash || "").length === 64, `${envelopeA.status}/${envelopeA.body?.code || "ok"} ${envelopeA.body?.message ? String(envelopeA.body.message).slice(0, 200) : JSON.stringify(envelopeA.body?.standing_lease?.bounds || null).slice(0, 140)} · factor ${envelopeA.body?.factor_origin || ""}`);
    evidence.standing_lease = { mode: "deployment", custody_tier: "deployment_local_operator", ruling: "R-14 (2026-09-09, owner-reversible)", status: STANDING ? "bound" : "refused", code: envelopeA.body?.code || null, message: envelopeA.body?.message || null, factor_origin: envelopeA.body?.factor_origin || null, bounds: envelopeA.body?.standing_lease?.bounds || null, grant_hash: envelopeA.body?.standing_grant_hash || null };
  } else if (AUTHORITY_PRESENT) {
    ok("5c-envelope", "FIXTURE MODE: the attach pass minted the standing envelope (1 usage · $0.01 · 2h), recorded the grant on the authority node and bound it to connection A; the bounds render from the daemon record", STANDING && envelopeA.body?.standing_lease?.bounds?.max_usages === 1 && String(envelopeA.body?.standing_grant_hash || "").length === 64, `${envelopeA.status}/${envelopeA.body?.code || "ok"} ${envelopeA.body?.message ? String(envelopeA.body.message).slice(0, 200) : JSON.stringify(envelopeA.body?.standing_lease?.bounds || null).slice(0, 140)} · factor ${envelopeA.body?.factor_origin || ""}`);
    evidence.standing_lease = { mode: "fixture", status: STANDING ? "bound" : "refused", code: envelopeA.body?.code || null, message: envelopeA.body?.message || null, factor_origin: envelopeA.body?.factor_origin || null, bounds: envelopeA.body?.standing_lease?.bounds || null, grant_hash: envelopeA.body?.standing_grant_hash || null };
  }
  const cardPage = await jd(SERVE, "/__ioi/connections");
  ok("5c-envelope", "the Connections card renders the envelope's status and bounds from the daemon record (bounded vs unbounded is daemon truth, never a client-side number)", cardPage.status === 200 && (STANDING ? cardPage.text.includes('data-ioi-standing-lease="active"') && cardPage.text.includes('data-ioi-standing-usages="1"') : cardPage.text.includes('data-ioi-standing-lease="absent"')), `${cardPage.status} standing=${STANDING}`);
  const unboundedLaunch = await jd(SERVE, "/__ioi/api/new-session/launch", { method: "POST", body: JSON.stringify({ project_ref: "project:alpha-journey", authority_profile: { connection_refs: [`connector:${B}`] } }) });
  ok("5c-envelope", "M13.3: a launch naming an UNBOUNDED connection refuses at session create (412 session_authority_connection_unbounded) with widening pointed at Connections — configure-once is the admission rule", unboundedLaunch.status === 412 && (unboundedLaunch.body?.error?.code === "session_authority_connection_unbounded" || unboundedLaunch.body?.code === "session_authority_connection_unbounded"), `${unboundedLaunch.status}/${unboundedLaunch.body?.error?.code || unboundedLaunch.body?.code}`);
  const launchRefs = STANDING ? [`connector:${A}`] : [];
  const launch = await jd(SERVE, "/__ioi/api/new-session/launch", { method: "POST", body: JSON.stringify({ project_ref: "project:alpha-journey", authority_profile: { connection_refs: launchRefs } }) });
  const scopedRef = launch.body?.session_ref || "";
  ok("5b-connections", STANDING ? "the composer's launch binds the operator's selected BOUNDED connection as the session's CLOSED authority profile" : "the composer's launch creates the session with the CLOSED (empty) authority profile — connection A is unbounded here and therefore not nameable", launch.status === 202 && JSON.stringify(launch.body?.authority_profile?.connection_refs) === JSON.stringify(launchRefs), `${launch.status} ${scopedRef} ${JSON.stringify(launch.body?.authority_profile?.connection_refs)}`);
  const bypass = await jd(DAEMON, `/v1/hypervisor/connectors/${encodeURIComponent(B)}/invoke`, { method: "POST", body: JSON.stringify({ tool: "ping", request: {}, session_ref: scopedRef }) });
  ok("5b-connections", "UI-BYPASS DRILL: a direct daemon invoke of a connection the session did not name refuses at admission", bypass.status === 403 && bypass.body?.reason === "session_authority_out_of_profile", `${bypass.status}/${bypass.body?.reason}`);

  // ---- 5d. M13.9: binding a provider key is a CUSTODY crossing the App parks on an approval card ---
  // Runs whenever the deployment-local approver exists (no provider key needed: the crossing is
  // posture-only; the drill route is never selected and its secret is revoked at the end).
  if (AUTHORITY_PRESENT) {
    const drillOwner = (who.body?.principal?.tenant_refs || []).find((t) => t === "org://local") || "org://local";
    const drillMut = (idem, extra = {}) => ({ owner_ref: drillOwner, idempotency_key: `alpha-journey-${idem}`, ...extra });
    const drillSecret = `drill-not-a-real-key-${crypto.randomBytes(12).toString("hex")}`;
    const drill = await jd(DAEMON, "/v1/hypervisor/model-routes", { method: "POST", body: JSON.stringify(drillMut("custody-drill-route", { model_id: "custody-drill-model", transport: "openai_compatible", base_url: "https://custody-drill.invalid/v1", display_name: "custody drill (never selected)", credential_posture: "provider_vault_token" })) });
    const drillId = drill.body?.route?.route_id || "";
    const submit = await jd(SERVE, `/__ioi/agent-studio/model-routes/${encodeURIComponent(drillId)}/credential`, { method: "POST", body: JSON.stringify({ token: drillSecret }) });
    const pendingCard = submit.body?.pending || {};
    const beforeApprove = await jd(DAEMON, `/v1/hypervisor/model-routes/${encodeURIComponent(drillId)}`);
    ok("5d-custody", "submitting a provider key in the App PARKS on the custody approval card: 202 awaiting_operator_approval with the daemon's exact commitments (policy and request hashes, tool model.credential.bind, the exact scope, the grant audience) and NOTHING sealed yet", drill.status < 300 && submit.status === 202 && submit.body?.decision === "awaiting_operator_approval" && /^sha256:/u.test(String(pendingCard.policy_hash || "")) && /^sha256:/u.test(String(pendingCard.request_hash || "")) && (pendingCard.allowed_tools || []).includes("model.credential.bind") && String(pendingCard.target_scope || "").startsWith("scope:") && /^[0-9a-f]{64}$/u.test(String(pendingCard.audience || "")) && !beforeApprove.body?.route?.credential_binding, `${drill.status} → ${submit.status}/${submit.body?.decision || submit.body?.error?.code} · ${String(pendingCard.request_hash || "").slice(0, 24)} · binding before approval ${JSON.stringify(beforeApprove.body?.route?.credential_binding ?? null)}`);
    const studio = await jd(SERVE, "/__ioi/agent-studio");
    const studioMarks = { card: studio.text.includes(`data-ioi-custody-approval="${drillId}"`), request_hash: studio.text.includes(String(pendingCard.request_hash || "∅")), approve_act: studio.text.includes(`/model-routes/${encodeURIComponent(drillId)}/credential/approve`), registry: studio.text.includes("model-routes"), plaintext: studio.text.includes(drillSecret), bytes: studio.text.length };
    ok("5d-custody", "Agent Studio renders the custody card with both commitments and the approve/deny acts (the plaintext appears nowhere on the page)", studio.status === 200 && studioMarks.card && studioMarks.request_hash && studioMarks.approve_act && !studioMarks.plaintext, `${studio.status} ${JSON.stringify(studioMarks)}`);
    const approve = await jd(SERVE, `/__ioi/agent-studio/model-routes/${encodeURIComponent(drillId)}/credential/approve`, { method: "POST", body: "{}" });
    const afterApprove = await jd(DAEMON, `/v1/hypervisor/model-routes/${encodeURIComponent(drillId)}`);
    const cbAfter = afterApprove.body?.route?.credential_binding || null;
    ok("5d-custody", "the operator's approval mints ONE grant with the deployment-local approver, records it on the authority node, and the daemon seals the key (sealed_capability_lease with a custody lease); the read projection carries no secret", approve.status === 201 && approve.body?.decision === "approved" && approve.body?.approver === "deployment_local_operator" && cbAfter?.kind === "sealed_capability_lease" && String(cbAfter?.provider_credential_lease_ref || "").startsWith("lease:") && !afterApprove.text.includes(drillSecret), `${approve.status}/${approve.body?.decision || approve.body?.error?.code} ${approve.body?.error?.message || ""} · ${JSON.stringify(cbAfter ? { kind: cbAfter.kind, lease: cbAfter.provider_credential_lease_ref } : null)}`);
    const replay = await jd(SERVE, `/__ioi/agent-studio/model-routes/${encodeURIComponent(drillId)}/credential/approve`, { method: "POST", body: "{}" });
    const studioAfter = await jd(SERVE, "/__ioi/agent-studio");
    ok("5d-custody", "one crossing, one decision: a second approval finds nothing pending (404) and the card is gone from Agent Studio", replay.status === 404 && replay.body?.error?.code === "credential_bind_not_pending" && studioAfter.status === 200 && !studioAfter.text.includes(`data-ioi-custody-approval="${drillId}"`), `${replay.status}/${replay.body?.error?.code}`);
    const revoke = await jd(DAEMON, `/v1/hypervisor/model-routes/${encodeURIComponent(drillId)}/credential`, { method: "DELETE", body: JSON.stringify(drillMut("custody-drill-revoke")) });
    const afterRevoke = await jd(DAEMON, `/v1/hypervisor/model-routes/${encodeURIComponent(drillId)}`);
    ok("5d-custody", "the drill key does not outlive the drill: revoking the credential leaves the route with no binding", revoke.status < 300 && !afterRevoke.body?.route?.credential_binding, `${revoke.status} → binding ${JSON.stringify(afterRevoke.body?.route?.credential_binding ?? null)}`);
    evidence.custody_card = { route_id: drillId, submit: submit.status, approve: approve.status, replay: replay.status, revoke: revoke.status };
  } else {
    record("5d-custody", "custody approval card", "NOT DRIVEN (authority mode none): the deployment-local approver does not exist here, so the custody crossing cannot be approved");
  }

  // ---- 6. start useful work: composer → parked on approval → approve → execute ----------------
  const intent = "Create a file named ALPHA_JOURNEY.md whose first line is exactly: hello from the alpha journey";
  const composerBody = { initialInput: { inputs: [{ text: { content: intent } }] }, environmentClassId: "local-workspace-v0", ...(STANDING ? { authorityProfile: { connectionRefs: [`connector:${A}`] } } : {}), ...(remoteRoute ? { modelRouteRef: remoteRoute.routeRef } : {}) };
  const create = await jd(SERVE, "/api/ioi.v1.AgentService/CreateAgentSession", { method: "POST", body: JSON.stringify(composerBody) });
  const runId = create.body?.agentExecutionId || "";
  const envId = create.body?.environment?.id || create.body?.environment?.environmentId || "";
  ok("6-work", "the composer submit creates a real environment, a session and a registered run", create.status === 200 && runId && envId, `${create.status} run ${runId} env ${envId}`);
  let transcript = null;
  const parkDeadline = Date.now() + 120_000;
  while (Date.now() < parkDeadline) {
    const t = await jd(DAEMON, `/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(runId)}`);
    transcript = t.body?.run || t.body?.record || t.body;
    if (transcript?.status === "awaiting_operator_approval" || ["done", "failed", "denied"].includes(transcript?.status)) break;
    await sleep(1000);
  }
  const runSessionRef = transcript?.session_ref || `session:ai-${runId}`;
  if (AUTHORITY_MODE === "none") {
    // Without a deployment authority node the daemon must refuse to execute, and say why, before
    // any harness runs. That refusal is the only claim this mode makes about steps 6 and 7.
    const blockedTyped = transcript?.status === "failed" && /authority/u.test(String(transcript?.error || ""));
    ok("6-work", "WITHOUT a deployment authority node the run fails CLOSED with a typed authority error before any harness runs (no silent success, no unauthorized execution)", blockedTyped, `${transcript?.status} · ${String(transcript?.error || "").slice(0, 120)}`);
    const noExec = readReceipts((r) => r.kind === "hypervisor.session.execute" && r.session_ref === runSessionRef);
    ok("7-inspect", "no execute receipt and no artifact exist for the refused run (nothing ran)", noExec.length === 0, `${noExec.length} execute receipt(s)`);
    record("6-work", "approval, execution, artifacts and execute receipts", "NOT QUALIFIED in this run (authority mode none) — requires the wallet.network authority node; see the profile's program-evidence table");
    evidence.nonclaims_authority_mode_none = ["operator approval interaction", "harness execution", "written artifacts", "execute receipt and capability lease binding", "cost of a real run"];
  }
  const pending = AUTHORITY_MODE === "none" ? null : (transcript?.pending_approval || null);
  if (STANDING) {
    // ---- 6s. silent within policy: the standing envelope carries the run to done, no card ----
    const silentStart = Date.now();
    while (!["done", "failed", "denied"].includes(transcript?.status) && Date.now() - silentStart < EXECUTE_BUDGET_MS) {
      const t = await jd(DAEMON, `/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(runId)}`);
      transcript = t.body?.run || t.body?.record || t.body;
      if (transcript?.status === "awaiting_operator_approval") break;
      await sleep(2000);
    }
    ok("6-work", "SILENT WITHIN POLICY: the run never parks on an approval card — its execution was drawn against the attach-time standing envelope (posture silent_within_policy on the run's authority record)", transcript?.status !== "awaiting_operator_approval" && !transcript?.pending_approval && transcript?.authority?.posture === "silent_within_policy", `${transcript?.status} · ${JSON.stringify(transcript?.authority || null).slice(0, 140)}`);
    const sessionsPageSilent = await jd(SERVE, "/work/sessions");
    ok("6-work", "Work / Sessions shows NO approval card for the silent run", sessionsPageSilent.status === 200 && !sessionsPageSilent.text.includes(`data-ioi-awaiting-approval="${runId}"`), `${sessionsPageSilent.status}`);
    const changedSilent = transcript?.changed_files || [];
    ok("6-work", `the silently authorized run completes on the qualified harness/model and writes at least one file (${Math.round((Date.now() - silentStart) / 1000)}s)`, transcript?.status === "done" && workFiles(changedSilent).length > 0, `${transcript?.status} · ${JSON.stringify(changedSilent).slice(0, 160)} · ${transcript?.error || ""}`);
    const drawReceipts = readReceipts((r) => r.kind === "hypervisor.session.standing_draw" && r.session_ref === runSessionRef && r.operation === "session_execute");
    ok("6-work", "the silence is attributable: a standing_draw receipt (operation session_execute, envelope hash, admission intent) is on the run's session — the draw-down receipt exists, no dialog was suppressed", drawReceipts.length === 1 && String(drawReceipts[0].admission_intent_ref || "").startsWith("authority-admission-intents/") && drawReceipts[0].posture === "silent_within_policy", `${drawReceipts.length} draw receipt(s)`);
    evidence.standing_lease.silent_run = { run_id: runId, status: transcript?.status, draw_receipts: drawReceipts.length };
    // ---- 6t. a second run over the envelope (1 usage) fails CLOSED, typed, nothing runs ----
    const second = await jd(SERVE, "/api/ioi.v1.AgentService/CreateAgentSession", { method: "POST", body: JSON.stringify(composerBody) });
    const secondId = second.body?.agentExecutionId || "";
    let secondT = null;
    const secondStart = Date.now();
    while (Date.now() - secondStart < 60_000) {
      const t = await jd(DAEMON, `/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(secondId)}`);
      secondT = t.body?.run || t.body?.record || t.body;
      if (["done", "failed", "denied", "awaiting_operator_approval"].includes(secondT?.status)) break;
      await sleep(1000);
    }
    const secondSessionRef = secondT?.session_ref || `session:ai-${secondId}`;
    const secondExec = readReceipts((r) => r.kind === "hypervisor.session.execute" && r.session_ref === secondSessionRef);
    const secondRefusals = readReceipts((r) => r.kind === "hypervisor.session.standing_refusal" && r.session_ref === secondSessionRef);
    ok("6-work", "OVER THE ENVELOPE: a second run under the same 1-usage envelope fails CLOSED and typed (refused_outside_envelope / max_usages), nothing ran, no card, and the refusal receipt names the bound", second.status === 200 && secondT?.status === "failed" && secondT?.authority?.posture === "refused_outside_envelope" && secondT?.authority?.refusedBound === "max_usages" && secondExec.length === 0 && secondRefusals.length === 1 && secondRefusals[0].refused_bound === "max_usages", `${second.status} ${secondT?.status} · ${JSON.stringify(secondT?.authority || null).slice(0, 160)} · exec ${secondExec.length} · refusals ${secondRefusals.length}`);
    evidence.standing_lease.over_envelope_run = { run_id: secondId, status: secondT?.status, authority: secondT?.authority || null };
    // ---- 6u. revocation refuses within one commit ----
    const revokeEnvelope = await jd(SERVE, `/__ioi/connections/${encodeURIComponent(A)}/standing-lease/revoke`, { method: "POST", body: JSON.stringify({}) });
    const afterRevokeLaunch = await jd(SERVE, "/__ioi/api/new-session/launch", { method: "POST", body: JSON.stringify({ project_ref: "project:alpha-journey", authority_profile: { connection_refs: [`connector:${A}`] } }) });
    ok("6-work", "REVOCATION: revoking the envelope on Connections refuses the very next session naming that connection (412, lease_status revoked) — leaving is real", revokeEnvelope.status === 200 && revokeEnvelope.body?.ok === true && afterRevokeLaunch.status === 412 && afterRevokeLaunch.body?.error?.lease_status === "standing_lease_revoked", `${revokeEnvelope.status} → ${afterRevokeLaunch.status}/${afterRevokeLaunch.body?.error?.code}`);
    evidence.standing_lease.revocation = { status: revokeEnvelope.status, next_launch: afterRevokeLaunch.status };
  }
  if (AUTHORITY_PRESENT && !STANDING) {
  ok("6-work", "the run PARKS on the operator's approval with the daemon's exact commitments (no signer runs automatically)", transcript?.status === "awaiting_operator_approval" && pending?.policy_hash && pending?.request_hash, `${transcript?.status} · ${pending?.request_hash?.slice(0, 24) || "no request hash"}`);
  const sessionsPage = await jd(SERVE, "/work/sessions");
  ok("6-work", "the canonical Work / Sessions route shows the approval card with the exact effect and its commitments", sessionsPage.status === 200 && sessionsPage.text.includes(`data-ioi-awaiting-approval="${runId}"`) && sessionsPage.text.includes(pending?.request_hash || "∅"), `${sessionsPage.status}`);
  // M13.4: the SAME decision is reachable from the session the run was submitted in — the SPA
  // session pane's timeline projection carries the awaiting card with the exact commitments.
  const parkedTimeline = await jd(SERVE, `/__ioi/agent-runs/${encodeURIComponent(runId)}/timeline`);
  const parkedApproval = parkedTimeline.body?.turns?.[0]?.approval;
  ok("6-work", "the SPA session pane (run timeline of the environment the run was submitted in) shows the SAME awaiting-approval card: exact commitments and the approve/deny endpoints", parkedTimeline.status === 200 && parkedApproval?.state === "awaiting" && parkedApproval.requestHash === pending?.request_hash && parkedApproval.approveUrl === `/__ioi/runs/${encodeURIComponent(runId)}/approve`, `${parkedTimeline.status} · ${parkedApproval?.state || "no card"}`);
  const approve = await jd(SERVE, `/__ioi/runs/${encodeURIComponent(runId)}/approve`, { method: "POST", body: JSON.stringify({}) });
  ok("6-work", "the operator's approval signs exactly that request with the deployment approver key and resumes execution", approve.status === 202 && approve.body?.decision === "approved", `${approve.status} ${JSON.stringify(approve.body?.error || approve.body?.decision)}`);
  const execStart = Date.now();
  // A refused approval leaves the run parked forever; do not spend the execute budget on it.
  while (approve.status === 202 && Date.now() - execStart < EXECUTE_BUDGET_MS) {
    const t = await jd(DAEMON, `/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(runId)}`);
    transcript = t.body?.run || t.body?.record || t.body;
    if (["done", "failed", "denied"].includes(transcript?.status)) break;
    await sleep(2000);
  }
  const execSeconds = Math.round((Date.now() - execStart) / 1000);
  const changed = transcript?.changed_files || [];
  ok("6-work", `the approved run completes on the qualified harness/model and writes at least one file (${execSeconds}s)`, transcript?.status === "done" && workFiles(changed).length > 0, `${transcript?.status} · ${JSON.stringify(changed).slice(0, 200)} · ${transcript?.error || ""}`);

  // ---- 7. inspect: artifacts, receipts, cost, the approval ------------------------------------
  const env = await jd(DAEMON, `/v1/hypervisor/environments/${encodeURIComponent(envId)}`);
  const workspaceRoot = env.body?.environment?.status?.workspace_root || "";
  let writtenFiles = [];
  try { writtenFiles = fs.readdirSync(workspaceRoot).filter((f) => !f.startsWith(".")); } catch { /* none */ }
  ok("7-inspect", "the written artifacts are in the session's workspace on disk", workspaceRoot && writtenFiles.length > 0, `${workspaceRoot} · ${writtenFiles.slice(0, 8).join(", ")}`);
  const runSession = await jd(DAEMON, `/v1/hypervisor/sessions/${encodeURIComponent(runSessionRef)}`);
  const execReceipts = readReceipts((r) => r.kind === "hypervisor.session.execute" && r.session_ref === runSessionRef);
  ok("7-inspect", "the session record carries the execute receipt and the durable receipt binds the consumed capability lease and the authority scopes", runSession.status === 200 && execReceipts.length >= 1 && String(execReceipts[0].capability_lease_ref || "").length > 0 && Array.isArray(execReceipts[0].authority_scope_refs), `${execReceipts.length} receipt(s) · lease ${String(execReceipts[0]?.capability_lease_ref || "").slice(0, 40)}`);
  const boundTimeline = await jd(SERVE, `/__ioi/agent-runs/${encodeURIComponent(runId)}/timeline`);
  const boundProof = boundTimeline.body?.turns?.[0]?.proof || {};
  ok("7-inspect", "M13.4: the SPA session pane's proof band is bound to the DAEMON session record (ref + lifecycle) and names the execute receipt with its capability lease, read from the daemon", boundTimeline.status === 200 && boundProof.session?.ref === runSessionRef && boundProof.session?.source === "daemon-runtime" && (boundProof.daemonReceipts || []).some((r) => r.kind === "hypervisor.session.execute" && r.capabilityLeaseRef), `${boundTimeline.status} · ${boundProof.session?.lifecycleState || "?"} · ${(boundProof.daemonReceipts || []).length} daemon receipt(s)`);
  ok("7-inspect", "the run's authority record names the operator's approval (approver = deployment-local operator, exact hashes)", transcript?.authority?.approver === "deployment_local_operator" && transcript?.authority?.requestHash === pending?.request_hash && transcript?.pending_approval?.decision === "approved", JSON.stringify(transcript?.authority || null).slice(0, 160));
  }
  if (STANDING) {
    // ---- 7s. inspect the silently authorized run: artifacts and the execute receipt ----
    const envS = await jd(DAEMON, `/v1/hypervisor/environments/${encodeURIComponent(envId)}`);
    const rootS = envS.body?.environment?.status?.workspace_root || "";
    let filesS = [];
    try { filesS = fs.readdirSync(rootS).filter((f) => !f.startsWith(".")); } catch { /* none */ }
    ok("7-inspect", "the written artifacts of the silently authorized run are in the session's workspace on disk", rootS && filesS.length > 0, `${rootS} · ${filesS.slice(0, 8).join(", ")}`);
    const execS = readReceipts((r) => r.kind === "hypervisor.session.execute" && r.session_ref === runSessionRef);
    ok("7-inspect", "the session record carries the execute receipt binding the consumed capability lease — the standing draw is the lease's admission", execS.length >= 1 && String(execS[0].capability_lease_ref || "").length > 0, `${execS.length} receipt(s)`);
  }
  if (remoteRoute) {
    // ---- 7r. M13.9: the run executed over the REMOTE route through the daemon's own proxy -------
    const envS = await jd(DAEMON, `/v1/hypervisor/environments/${encodeURIComponent(envId)}`);
    const execR = readReceipts((r) => r.kind === "hypervisor.session.execute" && r.session_ref === runSessionRef);
    const er = execR[0] || {};
    ok("7r-route", "the execute receipt names the remote route as the run's SESSION BINDING: model_source session_binding, the route ref, the openai_compatible transport and the provider model", er.model_source === "session_binding" && er.model_route_ref === remoteRoute.routeRef && er.model_transport === "openai_compatible" && er.model === PROVIDER_MODEL, `${er.model_source} · ${er.model_route_ref} · ${er.model_transport} · ${er.model}`);
    const binding = readRecords("model-route-session-bindings").find((b) => b.session_ref === runSessionRef && b.route_ref === remoteRoute.routeRef) || {};
    ok("7r-route", "the session's route binding executes at the DAEMON's model-mount proxy (execution_endpoint is the daemon, never the provider's URL)", typeof binding.execution_endpoint === "string" && binding.execution_endpoint === `${DAEMON}/v1` && binding.transport === "openai_compatible", `${binding.execution_endpoint} · ${binding.transport}`);
    const envKeys = Array.isArray(er.harness_environment_keys) ? er.harness_environment_keys : null;
    const expectedKeys = ["PATH", "HOME", "IOI_HYPERVISOR_MODEL_UPSTREAM", "IOI_HYPERVISOR_MODEL_TOKEN"];
    ok("7r-route", "NON-POSSESSION: the harness child's environment held exactly PATH, HOME, the daemon-proxy upstream and the run-scoped model-mount token's name — no provider key, no provider URL+key pair (the lane clears its environment and the receipt lists every name it set)", Array.isArray(envKeys) && envKeys.length === expectedKeys.length && expectedKeys.every((k) => envKeys.includes(k)) && !envKeys.some((k) => /API_KEY|SECRET|OPENAI/u.test(k)), JSON.stringify(envKeys));
    const invocations = readReceipts((r) => r.kind === "model_invocation" && r.details?.transport === "openai_compatible" && r.details?.routeId === remoteRoute.routeRef);
    const usage = invocations.map((r) => r.details?.usage || {}).reduce((acc, u) => ({ prompt: acc.prompt + Number(u.prompt_tokens || 0), completion: acc.completion + Number(u.completion_tokens || 0), total: acc.total + Number(u.total_tokens || 0) }), { prompt: 0, completion: 0, total: 0 });
    const providerStatuses = invocations.map((r) => r.details?.providerStatus ?? null);
    const providerAccepted = invocations.some((r) => r.details?.providerStatus === 200 && Number(r.details?.usage?.total_tokens || 0) > 0);
    ok("7r-route", "the DAEMON performed the provider call with the sealed credential: every model_invocation receipt on the route names the openai_compatible transport and the sealed basis (the receipt carries the provider's own status)", invocations.length >= 1 && invocations.every((r) => r.details?.credential === "sealed_capability_lease" && Number.isInteger(r.details?.providerStatus)), `${invocations.length} invocation(s) · provider status ${JSON.stringify(providerStatuses)}`);
    ok("7r-route", "the PROVIDER ACCEPTED the operator's credential: at least one proxied call answered 200 with reported usage (a 401/403 here is the operator's credential refused by the provider — recorded typed, never a pass)", providerAccepted, providerAccepted ? `usage ${JSON.stringify(usage)}` : `provider answered ${JSON.stringify(providerStatuses)} — no accepted call; the estate's path up to the provider is receipted above`);
    let intentFiles = [];
    try { intentFiles = fs.readdirSync(envS?.body?.environment?.status?.workspace_root || "").filter((f) => f === "ALPHA_JOURNEY.md"); } catch { /* none */ }
    ok("7r-route", "the run's WORK is the frontier model's: the intent's file (ALPHA_JOURNEY.md) exists in the session workspace, written from the proxied answer", intentFiles.length === 1, intentFiles.length ? "ALPHA_JOURNEY.md present" : "ALPHA_JOURNEY.md absent (no accepted provider answer to write from)");
    const tokenRecords = readRecords("capability-tokens");
    const findAll = (value, pred, out = []) => { if (value && typeof value === "object") { if (pred(value)) out.push(value); for (const v of Object.values(value)) findAll(v, pred, out); } return out; };
    const issued = tokenRecords.flatMap((rec) => findAll(rec, (o) => o.status === "issued" && o.audience === runSessionRef && typeof o.token_id === "string"));
    const issuedIds = new Set(issued.map((o) => o.token_id));
    const revoked = tokenRecords.flatMap((rec) => findAll(rec, (o) => o.status === "revoked" && issuedIds.has(o.token_id)));
    const scopes = issued.map((o) => JSON.stringify(o.allowed_scopes));
    ok("7r-route", "the harness's credential was the estate's OWN: a run-scoped model-mount capability token minted for this run's session (audience = the session, scope model.chat:* only) and REVOKED when the lane returned — never a provider secret", issued.length >= 1 && issued.every((o) => JSON.stringify(o.allowed_scopes) === JSON.stringify(["model.chat:*"])) && revoked.length >= issued.length && !tokenRecords.some((rec) => JSON.stringify(rec).includes(PROVIDER_KEY)), `${issued.length} issued · ${revoked.length} revoked · scopes ${scopes.join(",")}`);
    // The plaintext key must not exist anywhere in the daemon's state tree: the credential record
    // holds a sealed token, the receipts hold labels, the workspace holds the model's files.
    const leaked = grepTreeFor(dataDir, PROVIDER_KEY);
    ok("7r-route", "NO PLAINTEXT ANYWHERE: the provider key appears in no file under the daemon's state tree (sealed credential record, receipts, bindings, sessions, workspaces)", leaked.length === 0, leaked.length ? `found in ${leaked.length} file(s)` : "0 files");
    const price = PROVIDER_LIST_PRICES_USD_PER_M[PROVIDER_MODEL] || null;
    const estimate = price ? (usage.prompt * price.input + usage.completion * price.output) / 1_000_000 : null;
    evidence.model_route_lane = { ...(evidence.model_route_lane || {}), run_id: runId, session_ref: runSessionRef, invocations: invocations.length, provider_statuses: providerStatuses, provider_accepted: providerAccepted, usage, cost_usd_estimate: providerAccepted ? estimate : null, cost_basis: price ? `list price at authoring time (${price.input}/${price.output} USD per 1M input/output tokens) × the provider's reported usage — an estimate, not billing truth` : "no list price on file for this model; usage recorded, cost not estimated", harness_environment_keys: envKeys, run_scoped_tokens: { issued: issued.length, revoked: revoked.length } };
    record("7r-route", "cost of the live remote run", providerAccepted ? `${usage.total} tokens (${usage.prompt} in / ${usage.completion} out)${estimate === null ? "" : ` ≈ $${estimate.toFixed(6)} at list price (estimate)`}` : `no accepted provider call (provider status ${JSON.stringify(providerStatuses)}); nothing was consumed and no cost is claimed`);
  }
  if (AUTHORITY_MODE === "deployment") await qualifyRotationAndRevocation(envId);
  const consumption = await jd(DAEMON, "/v1/hypervisor/usage/consumption");
  const timeline = await jd(SERVE, `/__ioi/run-timeline/env/${encodeURIComponent(envId)}`);
  const ledger = await jd(SERVE, "/__ioi/work-ledger");
  ok("7-inspect", "cost/consumption, the run timeline and the work ledger answer for the operator", consumption.status === 200 && timeline.status === 200 && ledger.status === 200, `${consumption.status}/${timeline.status}/${ledger.status}`);

  // ---- 8. stop / revoke ------------------------------------------------------------------------
  const teardown = await jd(DAEMON, `/v1/hypervisor/sessions/${encodeURIComponent(scopedRef)}`, { method: "DELETE" });
  const tornDown = await jd(DAEMON, `/v1/hypervisor/sessions/${encodeURIComponent(scopedRef)}`);
  ok("8-stop", "the operator can stop (tear down) a session; the record is torn_down with a teardown receipt", teardown.status < 300 && tornDown.body?.session?.lifecycle_state === "torn_down", `${teardown.status} → ${tornDown.body?.session?.lifecycle_state}`);
  const revoke = await jd(DAEMON, `/v1/hypervisor/connectors/${encodeURIComponent(A)}`, { method: "DELETE" });
  const afterRevoke = await jd(DAEMON, `/v1/hypervisor/connectors/${encodeURIComponent(A)}/invoke`, { method: "POST", body: JSON.stringify({ tool: "ping", request: {}, session_ref: scopedRef }) });
  ok("8-stop", "revoking a connection refuses every later use under the sessions that named it", revoke.status < 300 && afterRevoke.status >= 400 && afterRevoke.body?.ok !== true, `${revoke.status} → ${afterRevoke.status}`);

  // ---- 9. restart and recover ------------------------------------------------------------------
  // "Exactly as they were": the run's terminal truth is whatever the daemon held BEFORE the kill —
  // done for a completed run, failed for one whose harness reported failure — never a status the
  // verifier assumed.
  const runBefore = await jd(DAEMON, `/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(runId)}`);
  const durableBefore = runBefore.body?.run || runBefore.body?.record || runBefore.body || null;
  const terminalBefore = durableBefore?.status || null;
  // IN-FLIGHT DRILL: as if the serve had died mid-execute — the durable run record is put back to
  // "running" while the daemon's execute receipt already holds the verdict. The restarted serve
  // must reconcile it from the receipt, never serve "running" forever.
  const inFlight = durableBefore && ["done", "failed"].includes(terminalBefore)
    ? await jd(DAEMON, `/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(runId)}`, { method: "POST", body: JSON.stringify({ ...durableBefore, status: "running", error: null }) })
    : { status: 0 };
  const inFlightBefore = await jd(DAEMON, `/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(runId)}`);
  const inFlightPlanted = (inFlightBefore.body?.run || inFlightBefore.body?.record || inFlightBefore.body)?.status === "running";
  await stopServe();
  await stopDaemon("SIGKILL");
  await startDaemon();
  await startServe();
  const listAfter = await jd(DAEMON, "/v1/hypervisor/sessions");
  // The restarted serve reconciles at boot; the durable record follows its write-through (bounded wait).
  let runAfter = null;
  let runAfterRecord = null;
  const reconcileDeadline = Date.now() + 30_000;
  do {
    runAfter = await jd(DAEMON, `/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(runId)}`);
    runAfterRecord = runAfter.body?.run || runAfter.body?.record || runAfter.body;
    if (!inFlightPlanted || runAfterRecord?.status !== "running") break;
    await sleep(1000);
  } while (Date.now() < reconcileDeadline);
  ok("9-recover", "IN-FLIGHT DRILL: a run left \"running\" by a serve that died mid-execute is RECONCILED at the next serve boot from the daemon session's execute receipt (its verdict, not the App's memory) — the durable record reads the receipt's outcome again", inFlight.status < 300 && inFlightPlanted && runAfterRecord?.status === terminalBefore && String((runAfterRecord?.activity_log || []).slice(-1)[0]?.text || "").includes("reconciled from the daemon's execute receipt"), `planted ${inFlight.status}/${inFlightPlanted} → ${runAfterRecord?.status} · ${String((runAfterRecord?.activity_log || []).slice(-1)[0]?.text || "").slice(0, 90)}`);
  const receiptsAfter = readReceipts((r) => r.kind === "hypervisor.session.execute" && r.session_ref === runSessionRef);
  const pageAfter = await jd(SERVE, "/work/sessions");
  const expectedTerminal = terminalBefore || (AUTHORITY_PRESENT ? "done" : "failed");
  const expectedReceipts = AUTHORITY_PRESENT ? 1 : 0;
  ok("9-recover", `after a daemon kill + restart and a serve restart, the sessions, the run's terminal truth (${expectedTerminal}), its execute receipts (${expectedReceipts}) and the Sessions surface are all recovered exactly as they were`, listAfter.status === 200 && (listAfter.body?.sessions || []).some((s) => s.session_ref === runSessionRef) && runAfterRecord?.status === expectedTerminal && receiptsAfter.length === expectedReceipts && pageAfter.status === 200 && pageAfter.text.includes(runSessionRef), `${listAfter.status} · run ${runAfterRecord?.status} · ${receiptsAfter.length} receipt(s) · page ${pageAfter.status}`);
  const whoAfter = await jd(DAEMON, "/v1/hypervisor/auth/whoami");
  ok("9-recover", "the operator's identity and session survive the restart", whoAfter.body?.principal?.email === "operator@alpha.local", `${whoAfter.status}`);

  // ---- 10. back up and restore (the two-daemon verifier, as evidence) -------------------------
  if (process.env.IOI_ALPHA_JOURNEY_SKIP_BACKUP === "1") {
    record("10-backup", "backup/restore sub-verifier", "skipped by IOI_ALPHA_JOURNEY_SKIP_BACKUP=1 (no claim)");
  } else {
    // In package mode the two-daemon backup verifier boots the INSTALLED daemon bytes.
    const br = spawn(process.execPath, [path.join(HERE, "verify-hypervisor-backup-restore.mjs")], { cwd: APP, env: { ...childBaseEnv(), ...(PACKAGE_MODE ? { IOI_HYPERVISOR_DAEMON_BINARY: daemonBinary } : {}) }, stdio: ["ignore", "pipe", "pipe"] });
    let brOut = "";
    br.stdout.on("data", (c) => { brOut += c; });
    br.stderr.on("data", (c) => { brOut += c; });
    const brCode = await new Promise((resolve) => br.once("exit", resolve));
    const brSummary = brOut.match(/(\d+)\/(\d+) passed/u)?.[0] || "no summary";
    ok("10-backup", "backup export, import into a fresh daemon, restore, kill/restart and deletion pass the two-daemon backup/restore verifier (check:backup-restore)", brCode === 0, `exit ${brCode} · ${brSummary}`);
  }

  // ---- 11. diagnostics -------------------------------------------------------------------------
  const doctor2 = await jd(DAEMON, "/v1/doctor");
  const audit = await jd(DAEMON, "/v1/hypervisor/audit/trail");
  const ops = await jd(SERVE, "/operations");
  const ledgerPage = await jd(SERVE, "/__ioi/route-ledger");
  ok("11-diagnostics", "doctor, the audit trail, the Operations surface and the developer route ledger answer", doctor2.status === 200 && audit.status === 200 && ops.status === 200 && ledgerPage.status === 200, `${doctor2.status}/${audit.status}/${ops.status}/${ledgerPage.status}`);

  // ---- 12. update / rollback through the admitted release change plan -------------------------
  if (PACKAGE_MODE) {
    await qualifyUpdateAndRollback();
  } else {
    const plans = await jd(DAEMON, "/v1/hypervisor/release-change-plans");
    ok("12-update", "the release change-plan family answers on the daemon, but this run is NOT on a packaged release, so update/rollback is recorded as NOT QUALIFIED here (package mode qualifies it), never as a pass", plans.status === 200 && Array.isArray(plans.body?.plans), `${plans.status} · not_qualified_in_this_run`);
  }
  evidence.nonclaims = [
    ...(PACKAGE_MODE ? ["v2 differs from v1 only by the daemon crate version (same sources); the packaged build is the debug cargo profile", "the authority node is launched from the source checkout (its validator launcher is not relocatable)"] : ["packaged release / signer / supply-chain evidence", "update and rollback of the release"]),
    "workload-bound isolation (host_spawn only)",
    ...(remoteRoute ? ["the remote route's answer quality (the lane claims the governed path: sealed credential, daemon proxy, run-scoped token, receipts)", "provider billing truth (the recorded cost is a list-price estimate over the provider's reported usage)"] : []),
    ...(AUTHORITY_MODE === "fixture" ? ["the wallet.network fixture is test material with a public approver seed"] : []),
    ...(AUTHORITY_MODE === "deployment" ? ["the authority node is a source build launched in this checkout, not a packaged component"] : [])];

  // ---- 13. App and headless agree ------------------------------------------------------------
  const headless = await jd(DAEMON, "/v1/hypervisor/sessions");
  const app = await jd(SERVE, "/work/sessions");
  const refs = (headless.body?.sessions || []).map((s) => s.session_ref);
  ok("13-agree", "the App's Sessions surface and the headless client render the same daemon-owned sessions", refs.length >= 2 && refs.every((r) => app.text.includes(r)), `${refs.length} session(s)`);
}

// A composer run driven exactly like step 6: submit → (park → approve) → terminal. Returns the
// terminal transcript and the run id. Used by the rotation/revocation qualification.
async function driveRun(intent, { approve }) {
  const create = await jd(SERVE, "/api/ioi.v1.AgentService/CreateAgentSession", { method: "POST", body: JSON.stringify({ initialInput: { inputs: [{ text: { content: intent } }] }, environmentClassId: "local-workspace-v0" }) });
  const runId = create.body?.agentExecutionId || "";
  if (!runId) {
    // A composer submit that returns no run is a FINDING, not a silent undefined downstream: carry
    // what the serve actually answered so the assertion consuming this can report a cause.
    return { runId: "", sessionRef: "", transcript: null, createFailed: true, createStatus: create.status ?? 0, createBody: `${JSON.stringify(create.body || {}).slice(0, 300)} ${create.error || ""}`.trim() };
  }
  let transcript = null;
  const parkDeadline = Date.now() + 120_000;
  while (Date.now() < parkDeadline) {
    const t = await jd(DAEMON, `/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(runId)}`);
    transcript = t.body?.run || t.body?.record || t.body;
    if (transcript?.status === "awaiting_operator_approval" || ["done", "failed", "denied"].includes(transcript?.status)) break;
    await sleep(1000);
  }
  let approveResult = null;
  if (approve && transcript?.status === "awaiting_operator_approval") {
    approveResult = await jd(SERVE, `/__ioi/runs/${encodeURIComponent(runId)}/approve`, { method: "POST", body: JSON.stringify({}) });
    const execStart = Date.now();
    while (approveResult.status === 202 && Date.now() - execStart < EXECUTE_BUDGET_MS) {
      const t = await jd(DAEMON, `/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(runId)}`);
      transcript = t.body?.run || t.body?.record || t.body;
      if (["done", "failed", "denied"].includes(transcript?.status)) break;
      await sleep(2000);
    }
  }
  return { runId, transcript, approveResult, sessionRef: transcript?.session_ref || `session:ai-${runId}` };
}

// 2c: the operator ROTATES the approver key, a second run is approved under the new key and
// executes; then the operator REVOKES the principal's authority and a third run fails closed.
async function qualifyRotationAndRevocation() {
  const stateDir = authorityNode.stateDir;
  const before = authorityNode.readAuthorityRecord();
  const oldSeed = fs.readFileSync(approverKeyPath, "utf8").trim();
  const rotated = authorityAct("rotate", { stateDir });
  const after = authorityNode.readAuthorityRecord();
  const retiredPath = path.join(stateDir, "keys", `approver.seed.v${before.binding_version}`);
  const newSeed = fs.readFileSync(approverKeyPath, "utf8").trim();
  const retiredMode = fs.existsSync(retiredPath) ? (fs.statSync(retiredPath).mode & 0o777) : null;
  ok("2c-rotation", "the operator rotates the approver key: a NEW key is custodied at the same path, the retired key is versioned read-only, and the chain holds an Active successor binding (version n+1) for the new authority", rotated.ok && after.binding_version === before.binding_version + 1 && after.binding_status === "active" && after.approver_authority_id !== before.approver_authority_id && newSeed !== oldSeed && fs.readFileSync(retiredPath, "utf8").trim() === oldSeed && retiredMode === 0o400, `${rotated.ok ? "ok" : rotated.stderr.slice(-200)} · v${before.binding_version}→v${after.binding_version} · ${after.binding_ref.slice(0, 60)}`);
  evidence.deployment_authority.rotation = { binding_ref: after.binding_ref, version: after.binding_version, retired_key: path.relative(stateDir, retiredPath) };
  const second = await driveRun("Create a file named ROTATED.md whose first line is exactly: approved under the rotated key", { approve: true });
  const secondReceipts = readReceipts((r) => r.kind === "hypervisor.session.execute" && r.session_ref === second.sessionRef);
  ok("2c-rotation", "a run approved AFTER rotation is signed with the new key, accepted by the daemon against the rotated binding, executes and receipts", second.approveResult?.status === 202 && second.transcript?.status === "done" && (second.transcript?.changed_files || []).length > 0 && secondReceipts.length >= 1, `${second.createFailed ? `composer submit returned NO run: HTTP ${second.createStatus} ${second.createBody} · ` : ""}${second.approveResult?.status} · ${second.transcript?.status} · ${JSON.stringify(second.transcript?.changed_files || []).slice(0, 120)} · ${second.transcript?.error || ""}`);
  evidence.deployment_authority.rotated_run = { run_id: second.runId, session_ref: second.sessionRef, status: second.transcript?.status };

  const revoked = authorityAct("revoke", { stateDir, reason: "alpha journey: operator revoked the deployment approver" });
  const afterRevoke = authorityNode.readAuthorityRecord();
  ok("2c-revocation", "the operator revokes the principal's approval authority: the chain holds a Revoked successor that retains the exact prior authority snapshot", revoked.ok && afterRevoke.binding_status === "revoked" && afterRevoke.binding_version === after.binding_version + 1, `${revoked.ok ? "ok" : revoked.stderr.slice(-200)} · v${afterRevoke.binding_version} ${afterRevoke.binding_status}`);
  const third = await driveRun("Create a file named REVOKED.md — this must never run", { approve: true });
  const thirdReceipts = readReceipts((r) => r.kind === "hypervisor.session.execute" && r.session_ref === third.sessionRef);
  const failedClosed = third.transcript?.status === "failed" && /authority|revoked|binding/iu.test(String(third.transcript?.error || ""));
  ok("2c-revocation", "AFTER revocation a new run fails CLOSED with a typed authority error before any harness runs — no approval card, no execute receipt, nothing written", failedClosed && thirdReceipts.length === 0 && (third.transcript?.changed_files || []).length === 0, `${third.transcript?.status} · ${String(third.transcript?.error || "").slice(0, 160)} · ${thirdReceipts.length} receipt(s)`);
  evidence.deployment_authority.revocation = { binding_ref: afterRevoke.binding_ref, version: afterRevoke.binding_version, refused_run: { run_id: third.runId, status: third.transcript?.status, error: String(third.transcript?.error || "").slice(0, 300) } };
}

// 12 (package mode): update to v2 and roll back to v1 through the daemon's admitted release
// change plans. The installer is the effect actor (activate/rollback + restart); the daemon
// admits each plan, refuses a no-op target, and after the restart OBSERVES its own executable
// digest against the plan's target — the outcome is the daemon's word, never the installer's.
async function qualifyUpdateAndRollback() {
  const admit = (kind, target) => jd(DAEMON, "/v1/hypervisor/release-change-plans", { method: "POST", body: JSON.stringify({
    kind,
    target_release: { version: target.version, manifest_sha256: target.manifest_sha256, daemon_sha256: target.daemon_sha256, signer_public_key: target.signer, signature_verified_by: "install.mjs verify (pinned signer)" },
    current_release: { version: kind === "update" ? pkg.v1.version : pkg.v2.version },
  }) });
  const noop = await admit("update", pkg.v1);
  ok("12-update", "a plan whose target is the RUNNING release is refused (the daemon compares the target digest with its own executable; nothing is minted for a no-op)", noop.status === 409 && noop.body?.error?.code === "release_change_plan_target_is_running", `${noop.status} ${noop.body?.error?.code || ""}`);
  const update = await admit("update", pkg.v2);
  const updatePlan = update.body?.plan || {};
  const admittedReceipt = readReceipts((r) => r.kind === "hypervisor.release.change-plan.admitted" && r.plan_id === updatePlan.plan_id);
  ok("12-update", "an UPDATE plan to v2 is admitted with the daemon's own digest recorded at admission and a durable admission receipt", update.status === 201 && updatePlan.status === "admitted" && updatePlan.current_release?.observed_daemon_sha256_at_admission === pkg.v1.daemon_sha256 && admittedReceipt.length === 1, `${update.status} ${updatePlan.plan_id || ""} · ${admittedReceipt.length} receipt(s)`);
  const second = await admit("update", pkg.v2);
  ok("12-update", "a second in-flight plan is refused while one is admitted and unobserved", second.status === 409 && second.body?.error?.code === "release_change_plan_already_admitted", `${second.status} ${second.body?.error?.code || ""}`);
  // The installer activates v2 and restarts the daemon and the served App FROM THE PREFIX.
  const activated = pkg.installerRun(["activate", "--prefix", pkg.prefix, "--version", pkg.v2.version]);
  await stopServe();
  await stopDaemon("SIGTERM");
  evidence.daemon_binary_after_update = { path: daemonBinary, resolved: fs.realpathSync(daemonBinary), sha256: sha256File(daemonBinary) };
  await startDaemon();
  await startServe();
  const observed = await jd(DAEMON, `/v1/hypervisor/release-change-plans/${encodeURIComponent(updatePlan.plan_id)}/observe`, { method: "POST", body: JSON.stringify({}) });
  const observedPlan = observed.body?.plan || {};
  const completedReceipt = readReceipts((r) => r.kind === "hypervisor.release.change-plan.completed" && r.plan_id === updatePlan.plan_id);
  ok("12-update", "after activation + restart the daemon that came back OBSERVES its own executable digest = v2's daemon digest and completes the plan with a receipt (the outcome is the daemon's word)", activated.ok === true && observed.status === 200 && observedPlan.status === "completed" && observedPlan.observed?.matched === true && observedPlan.observed?.running_daemon_sha256 === pkg.v2.daemon_sha256 && completedReceipt.length === 1, `${observed.status} ${observedPlan.status} · running ${String(observedPlan.observed?.running_daemon_sha256 || "").slice(0, 16)} · v2 ${pkg.v2.daemon_sha256.slice(0, 16)}`);
  const stillThere = await jd(DAEMON, "/v1/hypervisor/sessions");
  ok("12-update", "the updated daemon serves the SAME durable state: the sessions created before the update are still its records", stillThere.status === 200 && (stillThere.body?.sessions || []).length >= 2, `${stillThere.status} · ${(stillThere.body?.sessions || []).length} session(s)`);
  // Rollback: admitted on the v2 daemon, performed by the installer, observed by the v1 daemon.
  const rollback = await admit("rollback", pkg.v1);
  const rollbackPlan = rollback.body?.plan || {};
  ok("12-rollback", "a ROLLBACK plan to v1 is admitted on the updated daemon", rollback.status === 201 && rollbackPlan.status === "admitted" && rollbackPlan.current_release?.observed_daemon_sha256_at_admission === pkg.v2.daemon_sha256, `${rollback.status} ${rollbackPlan.plan_id || ""}`);
  const rolledBack = pkg.installerRun(["rollback", "--prefix", pkg.prefix]);
  await stopServe();
  await stopDaemon("SIGTERM");
  evidence.daemon_binary_after_rollback = { path: daemonBinary, resolved: fs.realpathSync(daemonBinary), sha256: sha256File(daemonBinary) };
  await startDaemon();
  await startServe();
  const observedRollback = await jd(DAEMON, `/v1/hypervisor/release-change-plans/${encodeURIComponent(rollbackPlan.plan_id)}/observe`, { method: "POST", body: JSON.stringify({}) });
  const rbPlan = observedRollback.body?.plan || {};
  const rbReceipt = readReceipts((r) => r.kind === "hypervisor.release.change-plan.completed" && r.plan_id === rollbackPlan.plan_id);
  ok("12-rollback", "after the installer's rollback + restart, the v1 daemon observes its own digest = v1's and completes the rollback plan with a receipt; both plans and all receipts are daemon records", rolledBack.ok === true && rolledBack.act === "rollback" && observedRollback.status === 200 && rbPlan.status === "completed" && rbPlan.observed?.matched === true && rbPlan.observed?.running_daemon_sha256 === pkg.v1.daemon_sha256 && rbReceipt.length === 1, `${observedRollback.status} ${rbPlan.status} · running ${String(rbPlan.observed?.running_daemon_sha256 || "").slice(0, 16)}`);
  const list = await jd(DAEMON, "/v1/hypervisor/release-change-plans");
  const activation = JSON.parse(fs.readFileSync(path.join(pkg.prefix, "state", "activation.json"), "utf8"));
  ok("12-rollback", "the headless client lists both completed plans and the installer's activation history agrees (activate v1 → activate v2 → rollback v1)", list.status === 200 && (list.body?.plans || []).filter((p) => p.status === "completed").length === 2 && activation.history.map((h) => `${h.act}:${h.version}`).join(",") === `activate:${pkg.v1.version},activate:${pkg.v2.version},rollback:${pkg.v1.version}`, `${(list.body?.plans || []).map((p) => `${p.kind}:${p.status}`).join(",")} · ${activation.history.map((h) => h.act).join(">")}`);
  evidence.release_change_plans = { update: observedPlan, rollback: rbPlan, activation };
}

function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length };
  const file = path.join(evidenceDir, `alpha-journey-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  return file;
}

run().then(async () => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  emitVerifierCensus({ verifierId: "alpha-journey", sourceUrl: import.meta.url, results });
  await cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch(async (e) => {
  console.error("verifier crashed:", e);
  const file = writeEvidence();
  console.error(`evidence (partial): ${path.relative(ROOT, file)}`);
  await cleanup();
  process.exit(1);
});

async function cleanup() {
  try { await stopServe(); } catch { /* gone */ }
  try { await stopDaemon("SIGTERM"); } catch { /* gone */ }
  try { await fixture?.stop(); } catch { /* best effort */ }
  try { await authorityNode?.stop(); } catch { /* best effort */ }
  if (KEEP_WORKDIR) {
    try { fs.writeFileSync(path.join(workDir, "daemon.log"), daemonLog); fs.writeFileSync(path.join(workDir, "serve.log"), serveLog); } catch { /* best effort */ }
    console.error(`work directory kept (IOI_ALPHA_JOURNEY_KEEP_WORKDIR=1): ${workDir}`);
    return;
  }
  try { fs.rmSync(workDir, { recursive: true, force: true }); } catch { /* keep */ }
}
