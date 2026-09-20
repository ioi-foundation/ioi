#!/usr/bin/env node
// check:zero-to-operable — M12.2: the zero-to-operable product journey, App and CLI/headless, as a
// pass-or-fail check (core-clients-surfaces.md § Zero-To-Operable Local Deployment; register R-206).
//
// CANON. The journey is one non-object sequence — verify → preview → install → bootstrap identity
// and authority → start client, daemon and the declared Agentgres posture → bounded readiness → open
// → inspect → update or roll back through an admitted change plan → stop or uninstall → separately
// authorize any wipe → preserve backup, export and restore material — and it is a product and
// conformance journey, not a plane, profile or tier. Preview, status and doctor are read-only.
// Uninstall never implies deletion of user data, Agentgres truth, keys, packages, backups or restore
// material. App and headless projections resolve the same deployment state.
//
// WHAT IS MEASURED HERE, AND HOW. The installer (scripts/install-hypervisor-alpha-release.mjs) is
// driven as a child process against a synthetic signed release built with the release library:
// preview must write nothing (a prefix that did not exist still does not; a prefix holding foreign
// material is byte-identical afterwards) and must name what install + activate would write, the
// endpoints, data custody, supervisor and egress posture; uninstall after install + activate must
// remove exactly the installer's footprint (releases/, current, state/) and leave foreign material
// under the prefix byte-identical AND listed; a wipe flag must be refused before anything is touched.
// The daemon's DECLARED Agentgres posture is read from an isolated daemon's own substrate status
// against the data dir it was started with — and read again after a restart on the same data dir,
// because a posture that changes across restarts was incidental, not declared. The alpha journey's
// source is held to drive the same verbs (steps 0-preview, 2d-posture, 14-uninstall) so the drills
// and the journey cannot drift apart silently.
//
// WHAT THE FULL CHECK IS (on demand — the unit's scheduled release qualification, R-206). The
// packaged alpha journey on a release built from THIS tree with no source checkout (deployment-local
// authority, package mode, no-checkout mode): preview before install, the declared posture at start,
// update and rollback through the daemon's change plans, App/headless agreement on daemon records,
// and uninstall after stop with the data dir digested before and after. Needs Ollama, the authority
// node and the two release packages outside the repository — two packages whose daemon bytes DIFFER,
// because the daemon refuses an update to its own digest; an equal pairing is refused here, typed.
//
// THE ORACLES ARE INDEPENDENT. "Byte-identical" is a digest computed HERE over every regular file
// before and after; "writes nothing" is the absence of a directory; the daemon's posture is compared
// to the data dir THIS check chose. --mutation copies the installer with a planted defect (uninstall
// that reaches into foreign material, a preview that creates the prefix, the wipe refusal removed,
// an uninstall that reports removal without removing) and requires the drill that owns each to go red.
//
// Exit: 0 pass · 1 fail · 2 blocked (the daemon binary, Ollama or the packages missing) — a blocked
// run claims nothing.
//
//   --drills               the CI-bound subset: the installer verbs, the daemon's declared posture
//                          across a restart, the journey's structural binding. Needs the daemon binary.
//   --mutation             the planted defects against the drills' oracles (no daemon).
//   (default)              the drills, then the full packaged journey.
//   --evidence <path>      also write the evidence there (default .artifacts/mvp-finish-line/).
//
//   IOI_HYPERVISOR_DAEMON_BINARY   the isolated daemon (default: built by the isolated-plane helper)
//   IOI_ALPHA_RELEASE_V1/V2/TRUST  the full check's packages and the pinned signer key, or the two
//                                  newest releases and signer under ~/.local/share/ioi-l0-packages

import { execFileSync, spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  MANIFEST_FILE, RELEASE_SCHEMA, RELEASE_TARGET, SIGNATURE_FILE, canonicalManifestBytes, digestTree,
  generateSignerKey, signManifestBytes, signerKeyId,
} from "./lib/hypervisor-alpha-release.mjs";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv, startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const INSTALLER = path.join(ROOT, "scripts", "install-hypervisor-alpha-release.mjs");
const JOURNEY = path.join(ROOT, "apps", "hypervisor", "scripts", "verify-hypervisor-alpha-journey.mjs");
const CANON_SURFACES = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "core-clients-surfaces.md");
const CANON_DOCTRINE = path.join(ROOT, "docs", "architecture", "components", "daemon-runtime", "doctrine.md");
const FOOTPRINT = ["releases", "current", "state"];

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";

const results = [];
const evidence = { schema: "ioi.zero-to-operable-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], mutation: null, journey: null };
let sink = results;
function ok(name, cond, detail) {
  const row = { name, pass: !!cond, detail: detail == null ? "" : String(detail) };
  sink.push(row);
  if (sink === results) evidence.drills.push({ ...row, at: new Date().toISOString() });
  if (sink === results) console.log(`${row.pass ? "PASS" : "FAIL"}  ${name}${row.detail ? ` — ${row.detail.slice(0, 220)}` : ""}`);
  return row.pass;
}
function blocked(reason) {
  console.error(`BLOCKED: ${reason}`);
  writeEvidence();
  process.exit(2);
}
function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length };
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `zero-to-operable-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}

// ---- the oracles -----------------------------------------------------------------------------------

/** Every regular file under `dir`, sorted, digested and folded into one digest. */
function treeDigest(dir) {
  const files = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const f = path.join(d, e.name);
      if (e.isDirectory()) walk(f);
      else if (e.isFile()) files.push(f);
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  const h = crypto.createHash("sha256");
  for (const f of files) h.update(`${path.relative(dir, f)}\0${crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex")}\n`);
  return { files: files.length, digest: h.digest("hex") };
}

/** A synthetic signed release: a daemon stand-in, an installer stand-in, a manifest and a signature. */
function makeRelease(scratch) {
  const dir = fs.mkdtempSync(path.join(scratch, "release-"));
  fs.mkdirSync(path.join(dir, "bin"));
  fs.writeFileSync(path.join(dir, "bin", "hypervisor-daemon"), "#!/bin/sh\necho daemon\n", { mode: 0o755 });
  fs.writeFileSync(path.join(dir, "install.mjs"), "// installer stand-in\n");
  const signer = generateSignerKey();
  const files = digestTree(dir);
  const daemon = files.find((f) => f.path === "bin/hypervisor-daemon");
  const manifest = {
    schema: RELEASE_SCHEMA, version: "0.0.0-zero-to-operable", target: RELEASE_TARGET,
    components: { daemon: { path: daemon.path, sha256: daemon.sha256, size: daemon.size } },
    files,
    signer: { algorithm: "ed25519", key_id: signerKeyId(signer.publicKeyPem), public_key_pem: signer.publicKeyPem },
  };
  const bytes = canonicalManifestBytes(manifest);
  fs.writeFileSync(path.join(dir, MANIFEST_FILE), bytes);
  fs.writeFileSync(path.join(dir, SIGNATURE_FILE), `${signManifestBytes(bytes, signer.privateKeyPem)}\n`);
  const trust = path.join(scratch, `trust-${path.basename(dir)}.pem`);
  fs.writeFileSync(trust, signer.publicKeyPem);
  return { dir, trust, version: manifest.version };
}

/** A prefix that already holds what an operator keeps beside an installation: keys, truth, backups. */
function makeForeignPrefix(scratch) {
  const prefix = fs.mkdtempSync(path.join(scratch, "prefix-"));
  fs.mkdirSync(path.join(prefix, "data", "keys"), { recursive: true });
  fs.writeFileSync(path.join(prefix, "data", "keys", "identity.pem"), "-----BEGIN PRIVATE KEY-----\nnot-really\n-----END PRIVATE KEY-----\n");
  fs.writeFileSync(path.join(prefix, "data", "agentgres.db"), "truth\n");
  fs.mkdirSync(path.join(prefix, "backups"));
  fs.writeFileSync(path.join(prefix, "backups", "snapshot-1.tar"), "backup bytes\n");
  return prefix;
}

function runInstaller(installer, args) {
  const r = spawnSync(process.execPath, [installer, ...args], { cwd: os.tmpdir(), encoding: "utf8", env: sanitizedVerifierBaseEnv() });
  let body = null;
  try { body = JSON.parse(r.stdout.slice(r.stdout.indexOf("{"))); } catch { body = null; }
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, body };
}

// ---- the drills (each is one function so the mutation mode can run it against a mutant) ------------

function drillPreview(installer, scratch) {
  const rel = makeRelease(scratch);
  const missing = path.join(scratch, `preview-missing-${crypto.randomBytes(4).toString("hex")}`);
  const p1 = runInstaller(installer, ["preview", "--release", rel.dir, "--trust", rel.trust, "--prefix", missing]);
  const plan = p1.body || {};
  ok("PREVIEW is read-only and names the plan: what install + activate WOULD write (release dir, current link, activation state), the endpoints, data custody, supervisor and egress posture, for the verified release", p1.status === 0 && plan.read_only === true && plan.version === rel.version && plan.would_write?.release_dir === path.join(missing, "releases", rel.version) && plan.would_write?.current_link === path.join(missing, "current") && plan.would_write?.activation_state === path.join(missing, "state", "activation.json") && typeof plan.endpoints?.daemon === "string" && typeof plan.data_custody?.data_dir === "string" && typeof plan.data_custody?.keys === "string" && typeof plan.supervisor === "string" && /^none during/u.test(plan.egress || ""), `${plan.version} → ${plan.would_write?.release_dir}`);
  ok("PREVIEW wrote nothing: a prefix that did not exist still does not exist after the preview", !fs.existsSync(missing), missing);
  const foreign = makeForeignPrefix(scratch);
  const before = treeDigest(foreign);
  const p2 = runInstaller(installer, ["preview", "--release", rel.dir, "--trust", rel.trust, "--prefix", foreign]);
  const after = treeDigest(foreign);
  const preserved = Array.isArray(p2.body?.preserved_if_present) ? [...p2.body.preserved_if_present].sort() : null;
  ok("PREVIEW over a prefix holding foreign material (keys, truth, backups) leaves every byte as it found it and LISTS what install would preserve", p2.status === 0 && before.digest === after.digest && before.files === after.files && !!preserved && preserved.join("|") === [path.join(foreign, "backups"), path.join(foreign, "data")].join("|") && !fs.existsSync(path.join(foreign, "state")) && !fs.existsSync(path.join(foreign, "releases")), `${before.files} files · ${before.digest.slice(0, 16)}`);
}

function drillUninstall(installer, scratch) {
  const rel = makeRelease(scratch);
  const prefix = makeForeignPrefix(scratch);
  const foreignBefore = { data: treeDigest(path.join(prefix, "data")), backups: treeDigest(path.join(prefix, "backups")) };
  const installed = runInstaller(installer, ["install", "--release", rel.dir, "--trust", rel.trust, "--prefix", prefix]);
  const activated = installed.status === 0 ? runInstaller(installer, ["activate", "--prefix", prefix, "--version", rel.version]) : { status: -1 };
  const footprintPresent = FOOTPRINT.every((e) => fs.existsSync(path.join(prefix, e)));
  ok("INSTALL + ACTIVATE write exactly the installer's footprint under the prefix (releases/<version>, current, state/activation.json) beside the foreign material", installed.status === 0 && activated.status === 0 && footprintPresent && fs.existsSync(path.join(prefix, "releases", rel.version, "bin", "hypervisor-daemon")), `${prefix}`);
  const u = runInstaller(installer, ["uninstall", "--prefix", prefix]);
  const removed = Array.isArray(u.body?.removed) ? [...u.body.removed].sort() : null;
  const preserved = Array.isArray(u.body?.preserved) ? [...u.body.preserved].sort() : null;
  const footprintGone = FOOTPRINT.every((e) => !fs.existsSync(path.join(prefix, e)));
  ok("UNINSTALL removes exactly the installer's footprint — releases/, current, state/ are gone — and reports it", u.status === 0 && u.body?.ok === true && footprintGone && !!removed && removed.join("|") === [path.join(prefix, "current"), path.join(prefix, "releases"), path.join(prefix, "state")].join("|"), `removed ${removed?.length ?? "?"}`);
  const foreignAfter = { data: treeDigest(path.join(prefix, "data")), backups: treeDigest(path.join(prefix, "backups")) };
  ok("UNINSTALL leaves the foreign material under the prefix BYTE-IDENTICAL (keys, Agentgres truth, backups) and LISTS it as preserved; the prefix itself stays because it holds it", foreignAfter.data.digest === foreignBefore.data.digest && foreignAfter.data.files === foreignBefore.data.files && foreignAfter.backups.digest === foreignBefore.backups.digest && foreignAfter.backups.files === foreignBefore.backups.files && !!preserved && preserved.join("|") === [path.join(prefix, "backups"), path.join(prefix, "data")].join("|") && fs.existsSync(prefix) && /not performed and not a verb/u.test(u.body?.data_wipe || ""), `data ${foreignBefore.data.files} files · backups ${foreignBefore.backups.files} files`);
  const again = runInstaller(installer, ["uninstall", "--prefix", prefix]);
  const gone = runInstaller(installer, ["uninstall", "--prefix", path.join(scratch, `never-installed-${crypto.randomBytes(4).toString("hex")}`)]);
  ok("UNINSTALL is idempotent and typed: a second uninstall removes nothing and still lists the preserved material; a prefix that never existed answers 'nothing to remove' and is not created", again.status === 0 && Array.isArray(again.body?.removed) && again.body.removed.length === 0 && Array.isArray(again.body?.preserved) && again.body.preserved.length === 2 && gone.status === 0 && Array.isArray(gone.body?.removed) && gone.body.removed.length === 0 && /does not exist/u.test(gone.body?.note || ""), `${again.body?.preserved?.length ?? "?"} preserved on the second pass`);
}

function drillWipeRefusal(installer, scratch) {
  const rel = makeRelease(scratch);
  const prefix = makeForeignPrefix(scratch);
  const installed = runInstaller(installer, ["install", "--release", rel.dir, "--trust", rel.trust, "--prefix", prefix]);
  const before = treeDigest(prefix);
  const refused = runInstaller(installer, ["uninstall", "--prefix", prefix, "--wipe-data", "yes"]);
  const after = treeDigest(prefix);
  ok("the installer has NO data-wipe verb: uninstall with a wipe flag is refused by name before anything is touched — the installed release and the foreign material are both still there", installed.status === 0 && refused.status !== 0 && /no data-wipe verb/u.test(refused.stderr || "") && before.digest === after.digest && before.files === after.files && fs.existsSync(path.join(prefix, "releases", rel.version)), `exit ${refused.status} · ${before.files} files unchanged`);
}

function drillStructure() {
  const journey = fs.readFileSync(JOURNEY, "utf8");
  const installerSrc = fs.readFileSync(INSTALLER, "utf8");
  const steps = ["0-preview", "2d-posture", "14-uninstall"].filter((id) => journey.includes(`"${id}"`));
  ok("the alpha journey drives the SAME verbs: it declares steps 0-preview, 2d-posture and 14-uninstall, runs the installer's preview and uninstall, probes the wipe refusal, reads the declared posture from the daemon's substrate status and digests the data dir before and after uninstall", steps.length === 3 && /installerRun\(\["preview"/u.test(journey) && /installerRun\(\["uninstall"/u.test(journey) && journey.includes('"--wipe-data"') && journey.includes("/v1/hypervisor/substrate/status") && /treeDigest\(dataDir\)/u.test(journey), steps.join(", "));
  ok("the installer's verb set is verify, preview, install, activate, rollback, status, uninstall — and no wipe verb — and its uninstall names its footprint as releases, current and state", /usage: install\.mjs <verify\|preview\|install\|activate\|rollback\|status\|uninstall>/u.test(installerSrc) && /const FOOTPRINT = \["releases", "current", "state"\];/u.test(installerSrc) && !/command === "wipe"/u.test(installerSrc), "verbs read from the installer's dispatch");
  const surfaces = fs.readFileSync(CANON_SURFACES, "utf8");
  const doctrine = fs.readFileSync(CANON_DOCTRINE, "utf8");
  const section = surfaces.slice(surfaces.indexOf("## Zero-To-Operable Local Deployment"), surfaces.indexOf("## Hypervisor Lineage And Operator Entry Contract"));
  ok("canon binds the check: core-clients-surfaces.md § Zero-To-Operable Local Deployment names check:zero-to-operable, the preview and uninstall verbs and the typed absences (R-206), and doctrine.md no longer calls the journey unimplemented", section.includes("`check:zero-to-operable`") && section.includes("`preview`") && section.includes("`uninstall`") && section.includes("R-206") && /typed absences/u.test(section) && !/not yet implemented or conformance-proven/u.test(doctrine) && doctrine.includes("`check:zero-to-operable`"), "read from the two canon files");
}

async function drillDeclaredPosture() {
  const baseEnv = sanitizedVerifierBaseEnv();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-zero-to-operable-posture-"));
  const read = async (plane) => {
    const r = await fetch(`${plane.daemonUrl}/v1/hypervisor/substrate/status`);
    return { status: r.status, body: await r.json().catch(() => null) };
  };
  const names = (xs) => (Array.isArray(xs) ? xs.map((x) => (typeof x === "string" ? x : x?.domain ?? x?.name ?? "")) : xs && typeof xs === "object" ? Object.keys(xs) : []);
  const posture = (body) => {
    const sub = body || {};
    const promoted = names(sub.promoted_domains);
    const engineDomains = names(sub.engine_domains);
    const errors = typeof sub.errors === "number" ? sub.errors : Array.isArray(sub.errors) ? sub.errors.length : -1;
    const underDataDir = typeof sub.engine_dir === "string" && (path.resolve(sub.engine_dir) + path.sep).startsWith(fs.realpathSync(dataDir) + path.sep);
    return { engine_dir: sub.engine_dir ?? null, promoted, engineDomains, errors, underDataDir, openError: sub.engine_open_error ?? null, required: names(sub.required_admission_domains) };
  };
  let plane = await startIsolatedPlane({ dataDir, baseEnv, env: {}, serve: false });
  if (!plane) blocked("the isolated daemon could not be started (binary absent)");
  let first;
  let second;
  try {
    const s1 = await read(plane);
    first = posture(s1.body);
    const declared = (p) => p.engineDomains.every((d) => p.promoted.includes(d) || p.required.includes(d));
    ok(`an isolated daemon serves the DECLARED Agentgres posture: its engine dir is under the data dir this check started it with, the engine opened without error, the promoted (${first.promoted.length}) and required-admission (${first.required.length}) domains are declared, zero substrate errors, and every domain the engine holds is a declared one (${first.engineDomains.length} opened so far — the engine's map lists only domains with state)`, s1.status === 200 && first.underDataDir && !first.openError && first.promoted.length > 0 && first.required.length > 0 && first.errors === 0 && declared(first), `${first.engine_dir} · engine ${first.engineDomains.length} · promoted ${first.promoted.join(",")} · required ${first.required.length}`);
    await plane.stop();
    plane = await startIsolatedPlane({ dataDir, baseEnv, env: {}, serve: false });
    if (!plane) blocked("the isolated daemon could not be restarted on the same data dir");
    const s2 = await read(plane);
    second = posture(s2.body);
    ok(`the posture is DECLARED, not incidental: after a stop and a fresh start on the same data dir the daemon serves the same engine dir, the same promoted and required-admission lists, no open error, zero errors, every engine domain still declared and none of the ${first.engineDomains.length} opened domains lost (${second.engineDomains.length} now)`, s2.status === 200 && second.engine_dir === first.engine_dir && second.promoted.join("|") === first.promoted.join("|") && second.required.join("|") === first.required.join("|") && !second.openError && second.errors === 0 && declared(second) && first.engineDomains.every((d) => second.engineDomains.includes(d)), `${second.engine_dir} · engine ${second.engineDomains.join(",") || "(none)"}`);
  } finally {
    try { await plane?.stop(); } catch { /* gone */ }
  }
  evidence.declared_posture = { data_dir: dataDir, first, second };
}

async function drills() {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-zero-to-operable-"));
  try {
    drillPreview(INSTALLER, scratch);
    drillUninstall(INSTALLER, scratch);
    drillWipeRefusal(INSTALLER, scratch);
    drillStructure();
    await drillDeclaredPosture();
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

// ---- mutation: the drills must go red against a planted defect -------------------------------------

function mutantInstaller(scratch, label, mutate) {
  const src = fs.readFileSync(INSTALLER, "utf8");
  // The installer finds its library beside itself (scripts/lib in the package, ./lib in the checkout);
  // a mutant lives in scratch, so its LIB resolution is pinned to the checkout's library by absolute URL.
  const libLine = /^const LIB = \[[^\n]*\n/mu;
  const rewired = src.replace(libLine, () => `const LIB = ${JSON.stringify(pathToFileURL(path.join(ROOT, "scripts", "lib", "hypervisor-alpha-release.mjs")).href)};\n`);
  if (rewired === src) throw new Error("the installer's LIB resolution line was not found; the mutant cannot be rewired");
  const mutated = mutate(rewired);
  if (mutated === rewired) throw new Error(`mutation ${label} planted nothing (the anchor it edits is gone)`);
  const file = path.join(scratch, `install-${label}.mjs`);
  fs.writeFileSync(file, mutated);
  return file;
}

async function mutation() {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-zero-to-operable-mutation-"));
  const plants = [
    ["uninstall reaches into foreign material (FOOTPRINT gains data and backups)", drillUninstall, (s) => s.replace('const FOOTPRINT = ["releases", "current", "state"];', 'const FOOTPRINT = ["releases", "current", "state", "data", "backups"];')],
    ["preview creates the prefix's state dir (no longer read-only)", drillPreview, (s) => s.replace("  const version = manifest.version;\n", '  const version = manifest.version;\n  fs.mkdirSync(path.join(prefix, "state"), { recursive: true });\n')],
    ["the wipe refusal is removed (a wipe flag is silently accepted)", drillWipeRefusal, (s) => s.replace(/    if \(options\["wipe-data"\] !== undefined\) throw new Error\([^\n]*\n/u, "")],
    ["uninstall reports removal without removing (a lying footprint report)", drillUninstall, (s) => s.replace("fs.rmSync(full, { recursive: true, force: true }); removed.push(full);", "removed.push(full);")],
  ];
  const rows = [];
  try {
    for (const [label, drill, mutate] of plants) {
      const installer = mutantInstaller(scratch, rows.length.toString(), mutate);
      const collected = [];
      sink = collected;
      try { drill(installer, scratch); } catch (error) { collected.push({ name: `threw: ${String(error?.message || error).slice(0, 160)}`, pass: false }); }
      sink = results;
      const failed = collected.filter((r) => !r.pass);
      rows.push({ label, detected: failed.length > 0, failed: failed.map((r) => r.name.slice(0, 120)) });
      console.log(`${failed.length > 0 ? "DETECTED" : "MISSED  "}  ${label}${failed.length ? ` — ${failed[0].name.slice(0, 120)}` : ""}`);
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  evidence.mutation = rows;
  const detected = rows.filter((r) => r.detected).length;
  console.log(`\nMUTATION ${detected}/${rows.length} planted defects detected`);
  return detected === rows.length;
}

// ---- the full check: the packaged journey on a release built from this tree ------------------------

function resolvePackages() {
  const env = { trust: process.env.IOI_ALPHA_RELEASE_TRUST, v1: process.env.IOI_ALPHA_RELEASE_V1, v2: process.env.IOI_ALPHA_RELEASE_V2 };
  if (env.trust && env.v1 && env.v2) return { trust: path.resolve(env.trust), v1: path.resolve(env.v1), v2: path.resolve(env.v2), source: "environment" };
  const home = path.join(os.homedir(), ".local", "share", "ioi-l0-packages");
  const releases = path.join(home, "releases");
  const trust = path.join(home, "signer", "release-signer.pub.pem");
  if (!fs.existsSync(releases) || !fs.existsSync(trust)) return null;
  const dirs = fs.readdirSync(releases).filter((d) => fs.existsSync(path.join(releases, d, MANIFEST_FILE))).map((d) => ({ dir: path.join(releases, d), mtime: fs.statSync(path.join(releases, d, MANIFEST_FILE)).mtimeMs })).sort((a, b) => a.mtime - b.mtime);
  if (dirs.length < 2) return null;
  return { trust, v1: dirs[dirs.length - 2].dir, v2: dirs[dirs.length - 1].dir, source: home };
}

async function fullJourney() {
  const pkg = resolvePackages();
  if (!pkg) blocked("no release packages: set IOI_ALPHA_RELEASE_TRUST/V1/V2 or place two releases and the signer under ~/.local/share/ioi-l0-packages");
  for (const rel of [pkg.v1, pkg.v2]) {
    const installer = path.join(rel, "install.mjs");
    if (!fs.existsSync(installer) || !/command === "preview"/u.test(fs.readFileSync(installer, "utf8")) || !/command === "uninstall"/u.test(fs.readFileSync(installer, "utf8"))) {
      blocked(`the package at ${rel} predates the preview/uninstall verbs (its install.mjs has neither): rebuild the packages from this tree`);
    }
  }
  // The pairing must be able to exercise an update: the daemon refuses a plan whose target digest equals
  // its own executable (release_change_plan_target_is_running), so two packages carrying the same daemon
  // bytes would fail steps 12-update and 12-rollback for a reason that is the pairing's, not the product's
  // (run of 2026-09-20 06:05Z: alpha.10 and alpha.11 packaged from one build — 52/59). Refused at the door.
  const daemonDigest = (rel) => { try { return JSON.parse(fs.readFileSync(path.join(rel, MANIFEST_FILE), "utf8")).components?.daemon?.sha256 ?? null; } catch { return null; } };
  const d1 = daemonDigest(pkg.v1);
  const d2 = daemonDigest(pkg.v2);
  if (!d1 || !d2) blocked(`a package manifest names no daemon digest (v1 ${d1}, v2 ${d2})`);
  if (d1 === d2) blocked(`the pairing cannot exercise an update: v1 and v2 carry the same daemon bytes (${d1.slice(0, 16)}); package v2 from a build whose daemon differs`);
  const evidenceDir = path.join(ROOT, "apps", "hypervisor", ".artifacts", "zero-to-operable");
  fs.mkdirSync(evidenceDir, { recursive: true });
  const before = new Set(fs.readdirSync(evidenceDir));
  const env = {
    ...process.env,
    IOI_ALPHA_JOURNEY_AUTHORITY: process.env.IOI_ALPHA_JOURNEY_AUTHORITY || "deployment",
    IOI_ALPHA_JOURNEY_PACKAGE: "1",
    IOI_ALPHA_JOURNEY_NO_CHECKOUT: process.env.IOI_ALPHA_JOURNEY_NO_CHECKOUT || "1",
    IOI_ALPHA_RELEASE_TRUST: pkg.trust, IOI_ALPHA_RELEASE_V1: pkg.v1, IOI_ALPHA_RELEASE_V2: pkg.v2,
    IOI_ALPHA_JOURNEY_EVIDENCE_DIR: evidenceDir,
  };
  console.log(`\n=== the packaged journey (${pkg.source}): v1 ${path.basename(pkg.v1)} → v2 ${path.basename(pkg.v2)}`);
  const t0 = Date.now();
  const status = await new Promise((resolve) => {
    const child = spawn(process.execPath, [JOURNEY], { cwd: path.join(ROOT, "apps", "hypervisor"), env, stdio: "inherit" });
    child.on("exit", (code) => resolve(code));
  });
  const files = fs.readdirSync(evidenceDir).filter((f) => !before.has(f) && f.endsWith(".json")).map((f) => path.join(evidenceDir, f));
  const ev = files.length ? JSON.parse(fs.readFileSync(files[files.length - 1], "utf8")) : null;
  const steps = ev?.steps || [];
  const stepRows = (id) => steps.filter((s) => s.step === id && !s.recorded);
  const allPass = (id, n) => stepRows(id).length >= n && stepRows(id).every((s) => s.pass);
  evidence.journey = { exit: status, seconds: Math.round((Date.now() - t0) / 1000), evidence: ev ? path.relative(ROOT, files[files.length - 1]) : null, summary: ev?.summary ?? null, packages: { ...pkg, v1_daemon_sha256: d1, v2_daemon_sha256: d2 } };
  ok(`the packaged alpha journey PASSES on a release built from this tree with no source checkout (${ev?.summary?.passed ?? "?"}/${ev?.summary?.total ?? "?"}, exit ${status}, ${evidence.journey.seconds}s)`, status === 0 && ev?.summary && ev.summary.passed === ev.summary.total && ev.summary.total > 0, evidence.journey.evidence || "no evidence file");
  ok("inside it, the PREVIEW ran before anything was mutated and wrote nothing (step 0-preview, 2 assertions, from the journey's own evidence)", allPass("0-preview", 2) && ev?.preview?.read_only === true, stepRows("0-preview").map((s) => s.detail).join(" · ").slice(0, 200));
  ok("inside it, the daemon served the DECLARED Agentgres posture at start (step 2d-posture, from the journey's evidence: engine dir under the journey's data dir)", allPass("2d-posture", 1) && typeof ev?.declared_posture?.engine_dir === "string" && ev.declared_posture.engine_dir.startsWith(ev.declared_posture.data_dir), ev?.declared_posture?.engine_dir || "");
  ok("inside it, UNINSTALL after stop removed exactly the installer's footprint, refused a wipe flag by name and left the data dir BYTE-IDENTICAL (step 14-uninstall, 3 assertions; the digests are in the journey's evidence)", allPass("14-uninstall", 3) && ev?.uninstall && ev.uninstall.data_dir_digest_before === ev.uninstall.data_dir_digest_after && ev.uninstall.data_dir_files > 0 && ev.uninstall.wipe_refused_exit !== 0, ev?.uninstall ? `${ev.uninstall.data_dir_files} files · ${String(ev.uninstall.data_dir_digest_before).slice(0, 16)}` : "no uninstall evidence");
  ok("inside it, the App and the headless client agreed on daemon-owned records and update + rollback went through admitted change plans (steps 13-agree, 12-update, 12-rollback)", allPass("13-agree", 1) && allPass("12-update", 1) && allPass("12-rollback", 1), `${stepRows("13-agree").length}/${stepRows("12-update").length}/${stepRows("12-rollback").length} assertions`);
}

// ---- main -------------------------------------------------------------------------------------------

(async () => {
  let passed = true;
  if (MODE === "mutation") {
    passed = await mutation();
  } else {
    await drills();
    if (MODE === "full") await fullJourney();
  }
  const file = writeEvidence();
  if (MODE !== "mutation") {
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} passed`);
    // The census is the CI-bound drill subset in every non-mutation mode: the floor pins what CI runs.
    emitVerifierCensus({ verifierId: "zero-to-operable", sourceUrl: import.meta.url, results: results.filter((r) => evidence.drills.some((d) => d.name === r.name)) });
    passed = fails.length === 0;
  }
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(passed ? 0 : 1);
})().catch((error) => {
  console.error("verifier crashed:", error);
  writeEvidence();
  process.exit(1);
});
