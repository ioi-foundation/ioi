#!/usr/bin/env node
// check:standalone-conformance — M12.1: the declared standalone envelope as a pass-or-fail check
// under the sovereign-local fixture, with the negative half executed rather than described.
//
// CANON. execution-horizons.md § Required sovereign-local fixture names `embedded_single_operator_
// offline`: every IOI-managed endpoint denied (no ioi.ai account, hosted wallet.network login,
// marketplace, IOI Network enrollment, IOI L1, license heartbeat, telemetry, update service or
// external model provider), loopback and explicit local IPC allowed, optional planes typed
// unavailable rather than fabricated. core-clients-surfaces.md § Standalone Local Completeness is
// the posture. bounded-alpha-profile.md § Intended user and supported deployment is the DECLARED
// envelope this check is scoped to. The instantiated profile is a registered ConformanceProfile
// (ecosystem-assurance-certification-liability.md), and it is loaded and pinned here, never
// restated.
//
// WHAT THE POSITIVE HALF IS. The bounded-alpha essential journey on the PACKAGED release with NO
// source checkout (deployment-local authority node, package mode, no-checkout mode), run INSIDE the
// isolated-egress harness (scripts/lib/egress-harness.mjs): a user+network namespace holding only
// loopback, a seccomp-filtered strace ledger of every connect/sendto from every descendant, the DNS
// question names parsed from it, and a unix-socket bridge for the one declared loopback dependency
// (Ollama). Backup/restore across two daemons runs inside that journey; portable evidence replay
// runs under the same ledger afterwards. Every IOI-managed family must read typed unavailable on
// the daemon's own readiness projection (`connected_capabilities[]`, the M12.1 read model).
//
// WHAT THE NEGATIVE HALF IS — THE LOAD-BEARING HALF. (a) The declared model route is severed
// MID-RUN by the harness bridge (the alpha journey's fault lane): the run must terminate typed —
// failed, never done, no artifact, no successful execute receipt — and readiness must read the
// route failed. (b) A deployment pointed at a NON-LOOPBACK dependency must FAIL the profile: the
// daemon's own reachability probe attempts the connect, the ledger records it, and the verdict is
// `undeclared_egress` naming the process and destination. (b) and the daemon-level availability
// proof are the CI-bound drills; the alpha journey is not CI-gated and runs on demand.
//
// THE ORACLES ARE INDEPENDENT. The ledger is parsed and classified HERE from strace's bytes; the
// dispositions are validated HERE against the registered schema and the profile's denied set; the
// profile document is validated HERE against its registered schema. Nothing is read back from the
// deployment and called verified. --mutation plants a reach, a fabricated success, an available-
// without-a-host disposition and a re-familied profile into the oracles' inputs and requires each
// to go red.
//
// Exit: 0 pass · 1 fail · 2 blocked (strace, the daemon binary, Ollama or the packages missing) —
// a blocked run claims nothing.
//   (default)              the full check: drills + the alpha journey under the harness + the fault
//                          lane + portable replay. Needs: Ollama serving IOI_ALPHA_MODEL, the two
//                          release packages (IOI_ALPHA_RELEASE_V1/V2/TRUST or ~/.local/share/
//                          ioi-l0-packages), the deployment authority binaries, load < 6.
//   --drills               the CI-bound subset: profile, host, harness oracles, the daemon's typed
//                          availability, the undeclared-reach drill. Needs the daemon binary only.
//   --mutation             the planted defects against the oracles (no daemon, no harness run).
//   --evidence <path>      also write the evidence there (default .artifacts/mvp-finish-line/).
//   --keep                 keep the work directory.
//   --legs <a,b,c>         (full mode) run only these of positive,fault,replay after the drills —
//                          an ITERATION aid; the run of record is the one with every leg, and the
//                          evidence names what was selected so a partial run cannot pose as it.
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon (drills); the full run
//                                 boots the PACKAGED daemon through the alpha journey.
//   IOI_STANDALONE_OLLAMA         host:port of the host's Ollama (default 127.0.0.1:11434).

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { classifyLedger, isLoopbackHost, parseStraceLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--inner") ? "inner" : flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const KEEP = flag("--keep");
const LEGS = new Set((flagValue("--legs") || "positive,fault,replay").split(",").map((x) => x.trim()).filter(Boolean));

const SCHEMAS = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const PROFILE_PATH = path.join(SCHEMAS, "fixtures", "conformance-profile-v1", "positive-standalone-embedded-single-operator-offline.json");
const PROFILE_SCHEMA = path.join(SCHEMAS, "conformance-profile.v1.schema.json");
const DISPOSITION_SCHEMA = path.join(SCHEMAS, "connected-capability-disposition.v1.schema.json");
const PROFILE_ID = "conformance_profile://ioi/standalone/embedded-single-operator-offline/v1";
const FAMILIES = ["ioi_ai_account", "hosted_wallet_network_login", "marketplace", "ioi_network_enrollment", "ioi_l1", "license_heartbeat", "telemetry", "update_service", "external_model_provider"];
// The alpha journey's OWN inputs name two BYO-shaped hosts (a project repository URL and a custody
// drill route) that never resolve; they are the journey's declared endpoints, not the product's.
const JOURNEY_DECLARED_NAMES = ["example.invalid", "custody-drill.invalid"];
const UNDECLARED_HOST = "10.255.255.1"; // RFC 1918, unrouted on this fixture: the non-loopback dependency of drill (b)

const results = [];
const drillResults = [];
let section = "drills";
const ok = (name, cond, detail = "") => {
  const row = { name, pass: !!cond, detail: String(detail ?? "").slice(0, 600) };
  results.push(row);
  if (section === "drills") drillResults.push(row);
  console.log(`${row.pass ? "PASS" : "FAIL"}  ${name}${row.detail ? `  (${row.detail})` : ""}`);
  return row.pass;
};
const note = (label, detail) => console.log(`NOTE  ${label}${detail ? ` — ${detail}` : ""}`);
const sha256 = (buf) => `sha256:${crypto.createHash("sha256").update(buf).digest("hex")}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const freePort = () => new Promise((resolve, reject) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); }); s.on("error", reject); });

// ------------------------------------------------------------------------------ the oracles
const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats(ajv);
const validators = new Map();
const validateAgainst = (schemaPath, value) => {
  if (!validators.has(schemaPath)) validators.set(schemaPath, ajv.compile(readJson(schemaPath)));
  const v = validators.get(schemaPath);
  const valid = v(value);
  return { valid, errors: valid ? [] : (v.errors || []).map((e) => `${e.instancePath || "$"} ${e.message}`) };
};

/** The profile document, validated against its registered schema and pinned. */
export function loadProfile(profilePath = PROFILE_PATH) {
  const bytes = fs.readFileSync(profilePath);
  const profile = JSON.parse(bytes.toString("utf8"));
  const schema = validateAgainst(PROFILE_SCHEMA, profile);
  return { profile, digest: sha256(bytes), schema, path: path.relative(ROOT, profilePath) };
}

/** The profile's own preconditions for THIS runner: the standalone runtime_node profile with the fixture and both negative tests. */
export function profileFindings({ profile, schema }) {
  const findings = [];
  if (!schema.valid) findings.push(`profile_schema_invalid: ${schema.errors.join("; ")}`);
  if (profile?.profile_id !== PROFILE_ID) findings.push(`profile_id_mismatch: ${profile?.profile_id}`);
  if (profile?.family !== "runtime_node") findings.push(`family_not_runtime_node: ${profile?.family}`);
  if (profile?.fixture?.fixture_id !== "embedded_single_operator_offline") findings.push(`fixture_mismatch: ${profile?.fixture?.fixture_id}`);
  const denied = profile?.fixture?.denied_endpoint_families ?? [];
  if (denied.length !== FAMILIES.length || FAMILIES.some((f) => !denied.includes(f))) findings.push(`denied_families_incomplete: ${JSON.stringify(denied)}`);
  const expected = (profile?.negative_tests ?? []).map((t) => t.expected).sort();
  if (JSON.stringify(expected) !== JSON.stringify(["fail_closed", "reject"])) findings.push(`negative_tests_incomplete: ${JSON.stringify(expected)}`);
  return findings;
}

/** One disposition: registered schema + the rules the runner enforces beyond it. */
export function dispositionFindings(d) {
  const findings = [];
  const schema = validateAgainst(DISPOSITION_SCHEMA, d);
  if (!schema.valid) findings.push(`disposition_shape_invalid: ${schema.errors.join("; ")}`);
  if (["available", "degraded"].includes(d?.disposition) && !d?.declared_endpoint_host) findings.push(`available_without_a_host: ${d?.capability}`);
  if (d?.disposition === "unavailable" && d?.declared_endpoint_host) findings.push(`unavailable_with_a_host: ${d?.capability}`);
  if (d?.reason_code === "declared_endpoint" && d?.disposition !== "available") findings.push(`declared_endpoint_not_available: ${d?.capability}`);
  if (d?.reason_code === "declared_endpoint_not_executable" && d?.disposition !== "degraded") findings.push(`not_executable_not_degraded: ${d?.capability}`);
  return findings;
}

/**
 * THE VERDICT over one deployment observed under the fixture: the ledger's classification against
 * allowed egress, and the daemon's dispositions against the profile's denied families. `fail`
 * names every finding; `pass` is the absence of findings, never a default.
 */
export function profileVerdict({ classified, dispositions, deniedFamilies, allowedAvailable = [] }) {
  const findings = [];
  for (const u of classified?.undeclared ?? []) findings.push({ code: "undeclared_egress", detail: `pid ${u.pid} ${u.syscall} → ${u.destination} (${u.errno})` });
  for (const q of classified?.dns_undeclared ?? []) findings.push({ code: "undeclared_name_resolution", detail: `pid(s) ${q.pids.join(",")} asked the resolver for ${q.name}${q.search_variants?.length ? ` (+${q.search_variants.length} search variants)` : ""}` });
  const byName = Object.fromEntries((dispositions ?? []).map((d) => [d?.capability, d]));
  for (const family of deniedFamilies ?? []) {
    const d = byName[family];
    if (!d) { findings.push({ code: "connected_capability_untyped", detail: `${family} has no disposition on the readiness projection` }); continue; }
    for (const f of dispositionFindings(d)) findings.push({ code: "disposition_invalid", detail: f });
    if (d.disposition === "available" && !allowedAvailable.includes(family)) findings.push({ code: "connected_capability_available_under_denial", detail: `${family} reads available (${d.reason_code}, ${d.declared_endpoint_host}) under a fixture that denies it` });
  }
  return { verdict: findings.length ? "fail" : "pass", findings };
}

// A ledger the way strace writes one: the fixture of the harness oracles' own drill. Every shape
// the parser must handle is present: a loopback connect, an unfinished/resumed non-loopback
// connect, an IPv6 loopback, a unix socket, netlink, and a DNS question on a connected datagram.
const SYNTHETIC_LEDGER = [
  '4242 connect(21, {sa_family=AF_INET, sin_port=htons(11434), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
  '4242 connect(22, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.7")}, 16 <unfinished ...>',
  '4243 connect(9, {sa_family=AF_UNIX, sun_path="/run/user/1000/bus"}, 110) = 0',
  '4242 <... connect resumed>) = -1 ENETUNREACH (Network is unreachable)',
  '4244 connect(5, {sa_family=AF_INET6, sin6_port=htons(8765), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0',
  '4245 sendto(21, [{nlmsg_len=20, nlmsg_type=RTM_GETADDR, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=1, nlmsg_pid=0}, {ifa_family=AF_UNSPEC, ...}], 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 20',
  '4246 connect(21, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 0',
  '4246 sendmmsg(21, [{msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\\255\\f\\1 \\0\\1\\0\\0\\0\\0\\0\\1\\3api\\3ioi\\2ai\\0\\0\\1\\0\\1\\0\\0)\\4\\260\\0\\0\\0\\0\\0\\0", iov_len=40}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, msg_len=40}], 1, MSG_NOSIGNAL) = 1',
  '4246 sendto(21, "\\277\\t\\1 \\0\\1\\0\\0\\0\\0\\0\\1\\3api\\3ioi\\2ai\\ntail025d2d\\2ts\\3net\\0\\0\\34\\0\\1\\0\\0)\\4\\260\\0\\0\\0\\0\\0\\0", 58, MSG_NOSIGNAL, NULL, 0) = 58',
  '4247 connect(7, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.9")}, 16) = -1 EINPROGRESS (Operation now in progress)',
].join("\n");

// ------------------------------------------------------------------------------ the inner legs
// Executed INSIDE the harness by re-invoking this script: boot a daemon, drive one seam, write a
// JSON result. They decide nothing; the outer half asserts over the result and the ledger.
async function innerLeg(leg, outPath) {
  const binary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), `ioi-standalone-${leg}-`));
  const port = await freePort();
  const DAEMON = `http://127.0.0.1:${port}`;
  const upstream = leg === "undeclared-reach" ? `http://${UNDECLARED_HOST}:11434/v1` : (process.env.IOI_ALPHA_MODEL_UPSTREAM || "http://127.0.0.1:11434/v1");
  const env = { ...sanitizedVerifierBaseEnv(process.env), IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: upstream, IOI_WALLET_SECRET_PASS: "standalone-conformance-seal-pass" };
  for (const k of Object.keys(env)) if (/^IOI_WALLET_NETWORK_|^IOI_HYPERVISOR_WALLET_|^IOI_WALLET_TEST_SIGNER$/u.test(k)) delete env[k];
  const out = { leg, binary, binary_sha256: sha256(fs.readFileSync(binary)), upstream, data_dir: dataDir, started_at: new Date().toISOString() };
  let log = "";
  const daemon = spawn(binary, [], { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-200_000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-200_000); });
  let SESSION = "";
  const jd = async (p, init = {}, auth = true) => {
    try {
      const r = await fetch(`${DAEMON}${p}`, { ...init, signal: AbortSignal.timeout(60_000), headers: { "content-type": "application/json", ...(auth && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}), ...(init.headers || {}) } });
      const text = await r.text();
      let body = {}; try { body = text ? JSON.parse(text) : {}; } catch { body = { _raw: text.slice(0, 300) }; }
      return { status: r.status, body };
    } catch (e) { return { status: 0, body: {}, error: String(e?.message || e) }; }
  };
  try {
    const until = Date.now() + 90_000;
    let up = false;
    while (Date.now() < until) { const h = await jd("/healthz", {}, false); if (h.status === 200) { up = true; break; } await sleep(400); }
    out.healthz = up;
    if (!up) { out.daemon_log_tail = log.slice(-4_000); throw new Error("daemon did not answer /healthz within 90s"); }
    const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
    const boot = token ? await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "standalone-conformance-pass-1", email: "standalone@conformance.local" }) }, false) : { status: 0, body: {} };
    SESSION = boot.body?.session_token || boot.body?.session?.token || "";
    out.bootstrap = { status: boot.status, session: SESSION.startsWith("ioi_sess_") };
    if (leg === "undeclared-reach") {
      // Session create runs the daemon's honest reachability probe against the configured model
      // upstream (a 300 ms TCP connect): the reach the ledger must show.
      const create = await jd("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({ project_ref: "project:ioi", initial_input: "standalone conformance: undeclared-reach drill" }) });
      out.session_create = { status: create.status, session_ref: create.body?.session_ref ?? null, code: create.body?.code ?? create.body?.error?.code ?? null, reason: create.body?.reason ?? null };
    }
    const substrate = await jd("/v1/hypervisor/substrate/status");
    out.substrate_status = substrate.status;
    out.connected_capabilities = Array.isArray(substrate.body?.connected_capabilities) ? substrate.body.connected_capabilities : null;
    const doctor = await jd("/v1/doctor");
    out.doctor_status = doctor.status;
  } catch (error) {
    out.error = String(error?.message || error);
  } finally {
    daemon.kill("SIGTERM");
    await Promise.race([new Promise((r) => daemon.once("exit", r)), sleep(8_000)]);
    if (daemon.exitCode === null && daemon.signalCode === null) { try { daemon.kill("SIGKILL"); } catch { /* gone */ } }
    out.finished_at = new Date().toISOString();
    fs.writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`);
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  process.exit(out.error ? 1 : 0);
}

// ------------------------------------------------------------------------------ the outer run
const evidence = { schema: "ioi.standalone-conformance-evidence.v1", mode: MODE, started_at: new Date().toISOString(), profile: null, host: null, legs: {}, results };
const git = (...a) => { try { return spawnSync("git", a, { cwd: ROOT, encoding: "utf8" }).stdout.trim(); } catch { return ""; } };
let workDir = null;
let isolation = null;

function blocked(reason) {
  console.error(`BLOCKED: ${reason}`);
  evidence.blocked = reason;
  writeEvidence();
  process.exit(2);
}
function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length, drills_executed: drillResults.length };
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `standalone-conformance-${evidence.started_at.replace(/[:.]/gu, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}

async function runInner(leg, { label, bridges = [], env = {}, timeoutMs = 10 * 60_000 }) {
  const outPath = path.join(workDir, `${label}.result.json`);
  const run = await runIsolated({ label, argv: [process.execPath, fileURLToPath(import.meta.url), "--inner", leg, "--out", outPath], cwd: ROOT, env: { ...process.env, ...env }, workDir, bridges, timeoutMs, isolation });
  let result = null;
  try { result = readJson(outPath); } catch { result = null; }
  const classified = classifyLedger(run.ledger, { declaredNames: [] });
  return { run, result, classified };
}

function legRecord(label, run, classified, extra = {}) {
  return {
    status: run.status, signal: run.signal, timed_out: run.timedOut, seconds: run.seconds, isolation: run.isolation,
    ledger: { path: path.relative(ROOT, run.ledgerPath), bytes: run.ledger_bytes, counts: classified.counts, loopback_ports: classified.loopback_ports, undeclared: classified.undeclared, dns_undeclared: classified.dns_undeclared, dns_declared: classified.dns_declared },
    bridges: run.bridges, log: path.relative(ROOT, run.logPath), ...extra,
  };
}

async function drills(profileLoaded) {
  section = "drills";
  // ---- D0. the profile: loaded, validated against its registered schema, pinned -----------------
  const findings = profileFindings(profileLoaded);
  evidence.profile = { id: profileLoaded.profile?.profile_id, path: profileLoaded.path, digest: profileLoaded.digest, family: profileLoaded.profile?.family, fixture: profileLoaded.profile?.fixture, negative_tests: profileLoaded.profile?.negative_tests, envelope: profileLoaded.profile?.declared_envelope_ref };
  ok("the standalone profile is a registered ConformanceProfile instance: valid against schema://ioi/foundations/conformance-profile/v1, family runtime_node, fixture embedded_single_operator_offline naming the nine denied families, and both negative tests declared (fail_closed + reject)", findings.length === 0, findings.length ? findings.join("; ") : `${profileLoaded.digest.slice(0, 23)} · ${profileLoaded.profile.required_interfaces.length} interfaces · envelope ${profileLoaded.profile.declared_envelope_ref}`);
  ok("the profile's envelope is the bounded alpha's declared deployment (the check claims exactly that envelope, never the selected minimum-L0 OutcomeRoom profile)", profileLoaded.profile?.declared_envelope_ref === "canon://docs/architecture/components/hypervisor/bounded-alpha-profile.md#intended-user-and-supported-deployment", String(profileLoaded.profile?.declared_envelope_ref));

  // ---- D1. the host: what the harness can give -------------------------------------------------
  isolation = probeIsolation();
  evidence.host = { ...isolation, load: os.loadavg().map((n) => n.toFixed(2)), cpus: os.cpus().length, kernel: os.release(), checkout: git("rev-parse", "HEAD"), dirty_paths: git("status", "--porcelain").split("\n").filter(Boolean).length };
  if (!isolation.strace.available) blocked(`the harness cannot record: ${isolation.strace.detail}`);
  ok("the isolation property is TYPED for this run (refused_and_recorded where unprivileged nested namespaces exist — every non-loopback destination refused by the kernel; recorded_only where the host refuses them — the ledger still proves zero reach and only the refusal half is typed absent), and never a skipped assertion", ["refused_and_recorded", "recorded_only"].includes(isolation.isolation), `${isolation.isolation} · strace ${isolation.strace.version ? "present" : "absent"} · namespaces ${isolation.network_namespace ? "available" : "unavailable"} · ${isolation.network_namespace_detail}`);

  // ---- D2. the harness oracles over a ledger written the way strace writes one -----------------
  const parsed = parseStraceLedger(SYNTHETIC_LEDGER);
  const classified = classifyLedger(parsed, { declaredHosts: ["198.51.100.9"], declaredNames: [] });
  ok("the ledger parser reads every shape strace writes: loopback IPv4 and IPv6 connects (the resolver's own 127.0.0.53 among them), an unfinished non-loopback connect whose ENETUNREACH arrives on the resumed line, a unix socket and a netlink datagram counted as local IPC, and a DNS question name parsed from a connected datagram's bytes (with its search-domain variant folded onto it)", parsed.attempts.length === 5 && parsed.attempts.some((a) => a.host === "203.0.113.7" && a.errno === "ENETUNREACH") && parsed.attempts.some((a) => a.family === "inet6" && a.loopback) && parsed.unix === 1 && parsed.netlink === 1 && parsed.dns_questions.length === 2 && classified.dns_undeclared.length === 1 && classified.dns_undeclared[0].name === "api.ioi.ai" && classified.dns_undeclared[0].search_variants.length === 1, `${parsed.attempts.length} attempts · unix ${parsed.unix} · netlink ${parsed.netlink} · dns ${parsed.dns_questions.map((q) => q.name).join(",")}`);
  ok("the classifier allows loopback and a DECLARED host, and names every other destination and every undeclared name as a reach", classified.counts.loopback === 3 && classified.declared.length === 1 && classified.undeclared.length === 1 && classified.undeclared[0].destination === "203.0.113.7:443" && classified.clean === false, JSON.stringify(classified.counts));
  const verdictRed = profileVerdict({ classified, dispositions: [], deniedFamilies: [] });
  const verdictGreen = profileVerdict({ classified: classifyLedger(parseStraceLedger(SYNTHETIC_LEDGER.split("\n").filter((l) => !/203\.0\.113\.7|198\.51\.100\.9|api|ioi/u.test(l)).join("\n"))), dispositions: [], deniedFamilies: [] });
  ok("the verdict is the absence of findings, never a default: the same ledger with the reach and the name lookup removed passes, and with them present it fails naming undeclared_egress and undeclared_name_resolution", verdictGreen.verdict === "pass" && verdictRed.verdict === "fail" && verdictRed.findings.map((f) => f.code).sort().join(",") === "undeclared_egress,undeclared_name_resolution", verdictRed.findings.map((f) => f.detail).join(" · "));
  const bad = dispositionFindings({ schema_version: "ioi.connected-capability-disposition.v1", capability: "telemetry", disposition: "available", reason_code: "declared_endpoint", basis: "planted", declared_endpoint_host: null });
  const good = dispositionFindings({ schema_version: "ioi.connected-capability-disposition.v1", capability: "telemetry", disposition: "unavailable", reason_code: "not_configured", basis: "no sink", declared_endpoint_host: null });
  ok("a disposition is validated against the registered schema AND the runner's own rules: available without a host is a finding, unavailable with none is not", bad.length >= 1 && good.length === 0, bad.join("; "));

  // ---- D3. the daemon's typed availability under the fixture (an isolated daemon, offline) -----
  const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  if (!fs.existsSync(daemonBinary)) blocked(`daemon binary absent at ${daemonBinary}`);
  const avail = await runInner("availability", { label: "availability" });
  const caps = avail.result?.connected_capabilities ?? [];
  const byName = Object.fromEntries(caps.map((c) => [c.capability, c]));
  const capFindings = caps.flatMap((c) => dispositionFindings(c).map((f) => `${c.capability}: ${f}`));
  evidence.legs.availability = legRecord("availability", avail.run, avail.classified, { result: avail.result });
  ok("an isolated daemon under the fixture boots, bootstraps its operator and answers readiness with the typed-availability read model (connected_capabilities on /v1/hypervisor/substrate/status)", avail.run.status === 0 && avail.result?.healthz === true && avail.result?.bootstrap?.session === true && avail.result?.substrate_status === 200 && Array.isArray(avail.result?.connected_capabilities), `exit ${avail.run.status} · ${avail.run.seconds}s · ${avail.result?.error || `${caps.length} dispositions`}`);
  ok("every one of the nine IOI-managed families is present exactly once and validates against schema://ioi/components/hypervisor/connected-capability-disposition/v1 plus the runner's coupling rules", caps.length === FAMILIES.length && FAMILIES.every((f) => byName[f]) && capFindings.length === 0, capFindings.length ? capFindings.join("; ") : caps.map((c) => `${c.capability}=${c.disposition}/${c.reason_code}`).join(" "));
  ok("under the fixture every denied family reads UNAVAILABLE with its reason and no family reads available: no hosted login (not_configured), no remote provider (no_remote_route_declared), updates are operator-supplied packages only, enrollment/L1/license/telemetry/marketplace/account not configured", FAMILIES.every((f) => byName[f]?.disposition === "unavailable") && byName.hosted_wallet_network_login?.reason_code === "not_configured" && byName.external_model_provider?.reason_code === "no_remote_route_declared" && byName.update_service?.reason_code === "operator_supplied_packages_only" && byName.ioi_network_enrollment?.reason_code === "not_enrolled", FAMILIES.map((f) => `${f}:${byName[f]?.reason_code}`).join(" "));
  const availVerdict = profileVerdict({ classified: avail.classified, dispositions: caps, deniedFamilies: profileLoaded.profile.fixture.denied_endpoint_families });
  ok("the offline daemon's whole life is on the ledger and it reached NOTHING outside loopback: zero undeclared connects, zero undeclared name lookups; the profile verdict over this deployment is pass", availVerdict.verdict === "pass" && avail.classified.counts.attempts >= 1, `${JSON.stringify(avail.classified.counts)} · ports ${avail.classified.loopback_ports.join(",")} · ${availVerdict.findings.map((f) => f.detail).join(" · ")}`);

  // ---- D4. NEGATIVE (b): a deployment pointed at a NON-LOOPBACK dependency fails the profile ---
  const reach = await runInner("undeclared-reach", { label: "undeclared-reach" });
  const reachCaps = reach.result?.connected_capabilities ?? [];
  const reachModel = reachCaps.find((c) => c.capability === "external_model_provider");
  const reachAttempts = reach.run.ledger.attempts.filter((a) => a.host === UNDECLARED_HOST);
  const reachVerdict = profileVerdict({ classified: reach.classified, dispositions: reachCaps, deniedFamilies: profileLoaded.profile.fixture.denied_endpoint_families });
  evidence.legs.undeclared_reach = legRecord("undeclared-reach", reach.run, reach.classified, { result: reach.result, verdict: reachVerdict });
  ok(`NEGATIVE (b): a deployment whose model upstream names the non-loopback host ${UNDECLARED_HOST} ATTEMPTS the reach — the daemon's own readiness probe at session create connects to it, and the ledger records the attempt from the daemon process`, reach.run.status === 0 && reachAttempts.length >= 1 && reachAttempts.every((a) => a.port === 11434), `${reachAttempts.length} attempt(s) ${reachAttempts.map((a) => `pid ${a.pid} ${a.errno}`).join(",")} · session create ${reach.result?.session_create?.status}/${reach.result?.session_create?.code || reach.result?.session_create?.reason || ""}`);
  ok(isolation.network_namespace ? "the KERNEL refused it: every attempt to the non-loopback host failed ENETUNREACH inside the namespace, before any packet existed" : "isolation is recorded_only on this host: the attempt is recorded (the refusal half is typed absent, not claimed)", isolation.network_namespace ? reachAttempts.length >= 1 && reachAttempts.every((a) => a.errno === "ENETUNREACH") : true, reachAttempts.map((a) => a.errno).join(","));
  ok("the profile FAILS that deployment, typed: undeclared_egress naming the process and destination — the load-bearing half of the standalone contract", reachVerdict.verdict === "fail" && reachVerdict.findings.some((f) => f.code === "undeclared_egress" && f.detail.includes(`${UNDECLARED_HOST}:11434`)), reachVerdict.findings.map((f) => `${f.code}: ${f.detail}`).join(" · "));
  ok("and the daemon's own read model told the truth about the same fact: external_model_provider reads DEGRADED (declared_endpoint_not_executable) naming the non-loopback host — declared, not executable, never available", reachModel?.disposition === "degraded" && reachModel?.reason_code === "declared_endpoint_not_executable" && reachModel?.declared_endpoint_host === UNDECLARED_HOST, JSON.stringify(reachModel || null));
  section = "full";
}

function discoverPackages() {
  const trust = process.env.IOI_ALPHA_RELEASE_TRUST;
  const v1 = process.env.IOI_ALPHA_RELEASE_V1;
  const v2 = process.env.IOI_ALPHA_RELEASE_V2;
  if (trust && v1 && v2) return { trust, v1, v2, source: "environment" };
  const base = path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), ".local", "share"), "ioi-l0-packages");
  const releases = path.join(base, "releases");
  const signer = path.join(base, "signer", "release-signer.pub.pem");
  if (!fs.existsSync(releases) || !fs.existsSync(signer)) return null;
  const dirs = fs.readdirSync(releases).filter((d) => fs.existsSync(path.join(releases, d, "release.json"))).sort();
  if (dirs.length < 2) return null;
  return { trust: signer, v1: path.join(releases, dirs[dirs.length - 2]), v2: path.join(releases, dirs[dirs.length - 1]), source: base };
}

async function fullRun(profileLoaded) {
  section = "full";
  const ollama = process.env.IOI_STANDALONE_OLLAMA || "127.0.0.1:11434";
  const [ollamaHost, ollamaPort] = ollama.split(":");
  const model = process.env.IOI_ALPHA_MODEL || "qwen2.5:7b";
  let tags = null;
  try { tags = await (await fetch(`http://${ollama}/api/tags`, { signal: AbortSignal.timeout(5_000) })).json(); } catch { tags = null; }
  if (!(tags?.models || []).some((m) => m.name === model || m.model === model)) blocked(`the host's Ollama at ${ollama} does not serve ${model}`);
  const pkg = discoverPackages();
  if (!pkg) blocked("no release packages: set IOI_ALPHA_RELEASE_TRUST/V1/V2 or place two releases and the signer under ~/.local/share/ioi-l0-packages");
  if (String(pkg.v1).startsWith(ROOT) || String(pkg.v2).startsWith(ROOT)) blocked("the release packages must live OUTSIDE the repository (the no-checkout clause)");
  const load = os.loadavg()[0];
  if (load >= 6) blocked(`host load ${load.toFixed(2)} ≥ 6: the journey's fixture cannot converge honestly under that load`);
  const releaseIdentity = (dir) => { try { const r = readJson(path.join(dir, "release.json")); return { version: r.version, daemon_sha256: (r.files || []).find((f) => f.path === "bin/hypervisor-daemon")?.sha256 || null, files: (r.files || []).length, signer: r.signer?.key_id || r.signer?.fingerprint || (typeof r.signer === "string" ? r.signer : null) }; } catch { return null; } };
  evidence.packages = { source: pkg.source, trust: pkg.trust, v1: pkg.v1, v2: pkg.v2, v1_release: releaseIdentity(pkg.v1), v2_release: releaseIdentity(pkg.v2) };
  const journey = path.join(ROOT, "apps", "hypervisor", "scripts", "verify-hypervisor-alpha-journey.mjs");
  const alphaEnvBase = {
    IOI_ALPHA_JOURNEY_AUTHORITY: "deployment", IOI_ALPHA_JOURNEY_PACKAGE: "1", IOI_ALPHA_JOURNEY_NO_CHECKOUT: "1",
    IOI_ALPHA_RELEASE_TRUST: pkg.trust, IOI_ALPHA_RELEASE_V1: pkg.v1, IOI_ALPHA_RELEASE_V2: pkg.v2,
    IOI_ALPHA_MODEL: model, IOI_ALPHA_MODEL_UPSTREAM: "http://127.0.0.1:11434/v1",
  };
  const bridge = (fault) => [{ name: "ollama", listenPort: 11434, target: { host: ollamaHost, port: Number(ollamaPort) }, ...(fault ? { fault } : {}) }];
  const latestEvidence = (dir) => { try { const f = fs.readdirSync(dir).filter((x) => x.endsWith(".json")).sort().at(-1); return f ? readJson(path.join(dir, f)) : null; } catch { return null; } };
  const step = (ev, id, re) => (ev?.steps || []).filter((s) => s.step === id && (!re || re.test(s.name)));
  const allPass = (rows) => rows.length > 0 && rows.every((s) => s.pass === true);

  evidence.legs_selected = [...LEGS];
  if (LEGS.size < 3) note("partial full run", `legs selected: ${[...LEGS].join(",")} — an iteration run, never the run of record`);
  // ---- F1. THE POSITIVE HALF: the alpha journey, packaged, no checkout, under the harness -------
  if (LEGS.has("positive")) {
  const posDir = path.join(workDir, "alpha-positive");
  fs.mkdirSync(posDir, { recursive: true });
  console.log(`# F1 the bounded-alpha essential journey on ${path.basename(pkg.v1)} → ${path.basename(pkg.v2)}, no checkout, inside the harness (this takes ~15–20 minutes)`);
  const pos = await runIsolated({ label: "alpha-positive", argv: [process.execPath, journey], cwd: path.join(ROOT, "apps", "hypervisor"), env: { ...process.env, ...alphaEnvBase, IOI_ALPHA_JOURNEY_EVIDENCE_DIR: posDir }, workDir, bridges: bridge(null), timeoutMs: 75 * 60_000, isolation, onOutput: (c) => { for (const l of String(c).split("\n")) if (/^(PASS|FAIL|BLOCKED|evidence:)/u.test(l)) console.log(`  │ ${l.slice(0, 200)}`); } });
  const posEv = latestEvidence(posDir);
  const posClass = classifyLedger(pos.ledger, { declaredNames: JOURNEY_DECLARED_NAMES });
  const posCaps = posEv?.connected_capabilities || [];
  const posVerdict = profileVerdict({ classified: posClass, dispositions: posCaps, deniedFamilies: profileLoaded.profile.fixture.denied_endpoint_families });
  evidence.legs.alpha_positive = legRecord("alpha-positive", pos, posClass, { evidence: posEv ? { started_at: posEv.started_at, finished_at: posEv.finished_at, summary: posEv.summary, checkout: posEv.checkout, daemon_binary: posEv.daemon_binary, packaged_release: posEv.packaged_release ? { v1: posEv.packaged_release.v1?.version, v2: posEv.packaged_release.v2?.version, prefix: posEv.packaged_release.prefix } : null, authority_mode: posEv.authority_mode, no_checkout: posEv.no_checkout, nonclaims: posEv.nonclaims, steps: posEv.steps } : null, verdict: posVerdict });
  ok(`POSITIVE: the bounded-alpha essential journey PASSES on the packaged release with no source checkout inside the harness (${posEv?.summary?.passed ?? "?"}/${posEv?.summary?.total ?? "?"} in ${pos.seconds}s): verified packages installed by the package's own installer outside the repository, the deployment-local authority node up with generated keys, first-run identity, readiness, a governed run completed on the local model, rotation and revocation, stop, restart and recovery, backup/restore across two daemons, diagnostics, update to v2 and rollback to v1 observed by the daemon's own digest`, pos.status === 0 && !pos.timedOut && posEv?.summary && posEv.summary.passed === posEv.summary.total && posEv.summary.total >= 40, `exit ${pos.status}${pos.timedOut ? " TIMED OUT" : ""} · ${posEv ? `${posEv.summary?.passed}/${posEv.summary?.total}` : "no evidence file"} · ${pos.output_tail.split("\n").filter((l) => l.startsWith("FAIL")).slice(0, 3).join(" | ").slice(0, 300)}`);
  ok("the journey's own steps prove the envelope's interfaces under the fixture: 1-install (PACKAGED, signer-verified), 2b-authority (NO-CHECKOUT closure + generated keys), 6-work (a run completed on the qualified harness/model and wrote a file), 9-recover, 10-backup (the two-daemon verifier), 12-update and 12-rollback (admitted change plans, digest observed)", allPass(step(posEv, "1-install", /PACKAGED/u)) && allPass(step(posEv, "2b-authority")) && allPass(step(posEv, "6-work")) && allPass(step(posEv, "9-recover")) && allPass(step(posEv, "10-backup")) && allPass(step(posEv, "12-update")) && allPass(step(posEv, "12-rollback")), ["1-install", "2b-authority", "6-work", "9-recover", "10-backup", "12-update", "12-rollback"].map((id) => `${id} ${step(posEv, id).filter((s) => s.pass).length}/${step(posEv, id).length}`).join(" · "));
  const posByName = Object.fromEntries(posCaps.map((c) => [c.capability, c]));
  ok("with the deployment-local authority bound, the daemon's readiness read model types every IOI-managed family: hosted wallet.network login is deployment_local_authority_bound (a loopback node, not a hosted login), the external model provider is not declared, nothing reads available — and the journey's own 3-readiness assertion over the same projection passed", posCaps.length === FAMILIES.length && posCaps.every((c) => dispositionFindings(c).length === 0) && posCaps.every((c) => c.disposition !== "available") && posByName.hosted_wallet_network_login?.reason_code === "deployment_local_authority_bound" && posByName.external_model_provider?.reason_code === "no_remote_route_declared" && allPass(step(posEv, "3-readiness", /TYPED/u)), posCaps.map((c) => `${c.capability}=${c.disposition}/${c.reason_code}`).join(" "));
  const ollamaBridge = pos.bridges?.ollama?.inner;
  ok("the ONE declared loopback dependency was reached only through the harness bridge — the model served the run (bytes flowed back from Ollama) — and the ledger's loopback ports are the deployment's own: daemon, served App, product UI, the authority node and its TLS front, the backup verifier's daemons, the bridge", (ollamaBridge?.connections ?? 0) >= 2 && (ollamaBridge?.bytes_from_dependency ?? 0) > 0 && posClass.loopback_ports.includes(11434), `bridge connections ${ollamaBridge?.connections} · bytes from the model ${ollamaBridge?.bytes_from_dependency} · loopback ports ${posClass.loopback_ports.length}`);
  ok(`ZERO REACH beyond loopback across the whole journey (${posClass.counts.attempts} recorded attempts, ${posClass.counts.dns_questions} resolver questions): no undeclared connect, no undeclared name lookup (the journey's own example.invalid / custody-drill.invalid inputs are its declared BYO names); the profile verdict over the deployment is PASS — and connection alone completed nothing: every managed family stayed typed unavailable while the local System bootstrapped, governed, executed, preserved and restored (ACC-14 N2)`, posVerdict.verdict === "pass" && posClass.counts.attempts > 0, `${JSON.stringify(posClass.counts)} · ${posVerdict.findings.map((f) => `${f.code}: ${f.detail}`).join(" · ") || "no findings"} · declared names ${posClass.dns_declared.map((q) => q.name).join(",") || "none seen"}`);

  }
  // ---- F2. NEGATIVE (a): the declared dependency dies mid-run — the fault lane -----------------
  if (LEGS.has("fault")) {
  const faultDir = path.join(workDir, "alpha-fault");
  fs.mkdirSync(faultDir, { recursive: true });
  const triggerPath = path.join(workDir, "alpha-fault-control", "sever");
  const statsPath = path.join(workDir, "alpha-fault-control", "bridge-ollama.json");
  fs.mkdirSync(path.dirname(triggerPath), { recursive: true });
  console.log("# F2 the fault lane: the same journey, the model route severed while the run executes (~5–8 minutes)");
  const fault = await runIsolated({ label: "alpha-fault", argv: [process.execPath, journey], cwd: path.join(ROOT, "apps", "hypervisor"), env: { ...process.env, ...alphaEnvBase, IOI_ALPHA_JOURNEY_EVIDENCE_DIR: faultDir, IOI_ALPHA_JOURNEY_FAULT: "model_route_mid_run", IOI_ALPHA_JOURNEY_FAULT_TRIGGER: triggerPath, IOI_ALPHA_JOURNEY_FAULT_STATS: statsPath }, workDir, bridges: bridge({ triggerPath }), timeoutMs: 40 * 60_000, isolation, onOutput: (c) => { for (const l of String(c).split("\n")) if (/^(PASS|FAIL|BLOCKED|evidence:)/u.test(l)) console.log(`  │ ${l.slice(0, 200)}`); } });
  const faultEv = latestEvidence(faultDir);
  const faultClass = classifyLedger(fault.ledger, { declaredNames: JOURNEY_DECLARED_NAMES });
  const lane = faultEv?.fault_lane || null;
  const faultSteps = step(faultEv, "6f-fault");
  evidence.legs.alpha_fault = legRecord("alpha-fault", fault, faultClass, { evidence: faultEv ? { started_at: faultEv.started_at, finished_at: faultEv.finished_at, summary: faultEv.summary, fault_lane: lane, nonclaims: faultEv.nonclaims, steps: faultEv.steps } : null });
  ok(`NEGATIVE (a): with the declared model route SEVERED while the run executed, the run terminated TYPED — status failed, an error naming the failure — never done, never left running (${lane?.seconds_to_terminal ?? "?"}s to terminal; journey ${faultEv?.summary?.passed ?? "?"}/${faultEv?.summary?.total ?? "?"})`, fault.status === 0 && !fault.timedOut && lane?.terminal_status === "failed" && String(lane?.error || "").length > 0 && faultSteps.length >= 5 && allPass(faultSteps), `exit ${fault.status} · ${lane?.terminal_status} · ${String(lane?.error || "").slice(0, 120)} · ${faultSteps.filter((s) => !s.pass).map((s) => s.name.slice(0, 80)).join(" | ")}`);
  ok("the harness bridge did the severing, not the deployment, and it was MID-STREAM: at least one in-flight model stream was destroyed and every later connect refused, and the ledger shows no reach beyond loopback while the deployment failed closed", fault.bridges?.ollama?.inner?.severed === true && (fault.bridges?.ollama?.inner?.severed_active ?? 0) >= 1 && faultClass.counts.undeclared === 0 && faultClass.counts.dns_undeclared === 0, `severed ${fault.bridges?.ollama?.inner?.severed} at ${fault.bridges?.ollama?.inner?.severed_at} · in-flight ${fault.bridges?.ollama?.inner?.severed_active} · refused after ${fault.bridges?.ollama?.inner?.refused_after_sever} · ${JSON.stringify(faultClass.counts)}`);
  // A success CLAIM is `exit_status: success` or a written file; a refusal before any process ran
  // carries exit_code 0 beside `exit_status: failure` and a typed error, which is "nothing ran".
  ok("no fabricated success: the session workspace holds no artifact of the failed run and no execute receipt claims success or a written file — every receipt carries a typed failure (the journey counted the things themselves)", lane && (lane.workspace_files?.length ?? 1) === 0 && (lane.execute_receipts ?? []).every((r) => r.exit_status !== "success" && (Array.isArray(r.files_written) ? r.files_written.length : Number(r.files_written || 0)) === 0 && String(r.error || "").length > 0), `workspace ${JSON.stringify(lane?.workspace_files)} · receipts ${JSON.stringify(lane?.execute_receipts)}`);

  }
  // ---- F3. portable evidence replay, offline, under the ledger --------------------------------
  if (LEGS.has("replay")) {
  const verifierBin = path.join(ROOT, "target", "debug", "aft-c8-verifier");
  if (process.env.IOI_STANDALONE_SKIP_CARGO !== "1") {
    const build = spawnSync("cargo", ["build", "-p", "aft-c8-verifier"], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 30 * 60_000 });
    if (build.status !== 0) blocked(`cargo build -p aft-c8-verifier failed: ${String(build.stderr).slice(-400)}`);
  }
  if (!fs.existsSync(verifierBin)) blocked(`the offline relying party is absent at ${verifierBin}`);
  const replay = await runIsolated({ label: "portable-replay", argv: [process.execPath, path.join(ROOT, "scripts", "check-portable-evidence-replay.mjs")], cwd: ROOT, env: { ...process.env }, workDir, bridges: [], timeoutMs: 20 * 60_000, isolation });
  const replayClass = classifyLedger(replay.ledger, { declaredNames: [] });
  evidence.legs.portable_replay = legRecord("portable-replay", replay, replayClass);
  ok("portable evidence replay (M06.4's check: a bundle reproduces its decision on the standalone relying party, reordered accepted byte-identically, every missing or substituted member refused) passes under the ledger with NO network attempt at all — offline means offline (and the ledger is empty because nothing was attempted, not because nothing was traced: the harness's inner summary carries the child's exit under strace)", replay.status === 0 && replay.inner?.child?.exit?.code === 0 && replayClass.counts.attempts === 0 && replayClass.counts.dns_questions === 0, `exit ${replay.status} · ${replay.seconds}s · ${JSON.stringify(replayClass.counts)} · ${replay.output_tail.split("\n").filter((l) => /\d+\/\d+|PASS|FAIL/u.test(l)).at(-1)?.slice(0, 160) || ""}`);
  }
  note("System genesis + governance under this fixture", "NOT composed here — typed remainder owned by M12.3 (the undeniable-product gate composes genesis, constitution and the room under the same fixture); the profile declares the genesis interfaces and the bounded alpha (ADR 0052) contains no System");
}

async function mutation() {
  section = "mutation";
  const profileLoaded = loadProfile();
  const plant = [];
  // 1. a reach planted into a clean ledger must fail the verdict
  const clean = classifyLedger(parseStraceLedger('7 connect(3, {sa_family=AF_INET, sin_port=htons(9301), sin_addr=inet_addr("127.0.0.1")}, 16) = 0'));
  const planted = classifyLedger(parseStraceLedger('7 connect(3, {sa_family=AF_INET, sin_port=htons(9301), sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n8 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.7")}, 16) = -1 ENETUNREACH (Network is unreachable)'));
  plant.push(["a planted non-loopback connect turns a passing verdict into undeclared_egress", profileVerdict({ classified: clean, dispositions: [], deniedFamilies: [] }).verdict === "pass" && profileVerdict({ classified: planted, dispositions: [], deniedFamilies: [] }).findings.some((f) => f.code === "undeclared_egress")]);
  // 2. a planted name lookup for a first-party host
  const named = classifyLedger(parseStraceLedger('9 connect(5, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 0\n9 sendto(5, "\\1\\2\\1 \\0\\1\\0\\0\\0\\0\\0\\0\\3api\\3ioi\\2ai\\0\\0\\1\\0\\1", 27, MSG_NOSIGNAL, NULL, 0) = 27'), { declaredNames: JOURNEY_DECLARED_NAMES });
  plant.push(["a planted resolver question for api.ioi.ai is undeclared_name_resolution even with no connect after it", profileVerdict({ classified: named, dispositions: [], deniedFamilies: [] }).findings.some((f) => f.code === "undeclared_name_resolution" && f.detail.includes("api.ioi.ai"))]);
  // 3. a disposition that claims availability under denial, and one without a host
  const caps = FAMILIES.map((f) => ({ schema_version: "ioi.connected-capability-disposition.v1", capability: f, disposition: "unavailable", reason_code: "not_configured", basis: "planted", declared_endpoint_host: null }));
  const availableTelemetry = caps.map((c) => (c.capability === "telemetry" ? { ...c, disposition: "available", reason_code: "declared_endpoint", declared_endpoint_host: "telemetry.ioi.ai" } : c));
  const hostless = caps.map((c) => (c.capability === "ioi_l1" ? { ...c, disposition: "degraded", reason_code: "declared_endpoint_not_executable" } : c));
  plant.push(["a denied family reading available fails connected_capability_available_under_denial; a degraded family without a host fails disposition_invalid", profileVerdict({ classified: clean, dispositions: caps, deniedFamilies: FAMILIES }).verdict === "pass" && profileVerdict({ classified: clean, dispositions: availableTelemetry, deniedFamilies: FAMILIES }).findings.some((f) => f.code === "connected_capability_available_under_denial") && profileVerdict({ classified: clean, dispositions: hostless, deniedFamilies: FAMILIES }).findings.some((f) => f.code === "disposition_invalid")]);
  // 4. the profile re-familied or with a negative test dropped
  const refamilied = { ...profileLoaded, profile: { ...profileLoaded.profile, family: "worker_endpoint" } };
  const dropped = { ...profileLoaded, profile: { ...profileLoaded.profile, negative_tests: profileLoaded.profile.negative_tests.slice(0, 1) } };
  const unknown = { profile: { ...profileLoaded.profile, planted_member: true }, schema: validateAgainst(PROFILE_SCHEMA, { ...profileLoaded.profile, planted_member: true }) };
  plant.push(["the profile pin is a pin: a re-familied profile, one with a negative test dropped, and one with an unknown member are each refused", profileFindings(profileLoaded).length === 0 && profileFindings(refamilied).length >= 1 && profileFindings(dropped).length >= 1 && profileFindings(unknown).length >= 1]);
  // 5. a fabricated success in the fault lane's evidence
  const laneOk = { terminal_status: "failed", error: "no_model_route", workspace_files: [], execute_receipts: [{ exit_status: "failure", exit_code: 0, files_written: [], error: "no_model_route" }] };
  const laneFabricated = { ...laneOk, terminal_status: "done", error: "" };
  const laneWrittenFile = { ...laneOk, execute_receipts: [{ exit_status: "failure", exit_code: 0, files_written: ["ALPHA_JOURNEY.md"], error: "no_model_route" }] };
  const laneSuccessReceipt = { ...laneOk, execute_receipts: [{ exit_status: "success", exit_code: 0, files_written: [], error: "" }] };
  const laneAssert = (lane) => lane.terminal_status === "failed" && String(lane.error || "").length > 0 && (lane.workspace_files?.length ?? 1) === 0 && lane.execute_receipts.every((r) => r.exit_status !== "success" && (r.files_written?.length ?? 0) === 0 && String(r.error || "").length > 0);
  plant.push(["the fault lane's oracle refuses a fabricated success: a refusal receipt (exit_status failure, exit_code 0, a typed error) passes, while a run that read done, a receipt with a written file and a receipt claiming success are each red", laneAssert(laneOk) && !laneAssert(laneFabricated) && !laneAssert(laneWrittenFile) && !laneAssert(laneSuccessReceipt)]);
  let red = 0;
  for (const [name, detected] of plant) { console.log(`${detected ? "PASS" : "FAIL"}  planted: ${name}`); if (detected) red += 1; }
  console.log(`\n${red}/${plant.length} planted defects detected`);
  process.exit(red === plant.length ? 0 : 1);
}

async function main() {
  if (MODE === "inner") { await innerLeg(flagValue("--inner"), flagValue("--out")); return; }
  if (MODE === "mutation") { await mutation(); return; }
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-standalone-conformance-"));
  evidence.work_dir = workDir;
  const profileLoaded = loadProfile();
  console.log(`# check:standalone-conformance · ${MODE} · profile ${profileLoaded.digest.slice(0, 23)} · ${git("rev-parse", "--short", "HEAD")}`);
  await drills(profileLoaded);
  if (MODE === "full") await fullRun(profileLoaded);
  else note("full run not executed (--drills)", "the alpha journey under the harness, the fault lane and portable replay need Ollama, the deployment authority binaries and release packages outside the repository — run without --drills on a qualified host");
  const fails = results.filter((r) => !r.pass);
  console.log(`\n${results.length - fails.length}/${results.length} passed (${drillResults.filter((r) => r.pass).length}/${drillResults.length} CI-bound drills)`);
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  // The census is the CI-bound drill subset in EVERY mode: the floor pins what CI executes, and the
  // full run's extra assertions live in its evidence file, never in a floor they could inflate.
  emitVerifierCensus({ verifierId: "standalone-conformance", sourceUrl: import.meta.url, results: drillResults });
  if (!KEEP) { try { fs.rmSync(workDir, { recursive: true, force: true }); } catch { /* keep */ } } else console.log(`work directory kept: ${workDir}`);
  process.exit(fails.length ? 1 : 0);
}

main().catch((error) => {
  console.error(`verifier crashed: ${error?.stack || error}`);
  try { writeEvidence(); } catch { /* best effort */ }
  process.exit(error?.code === "strace_unavailable" ? 2 : 1);
});
