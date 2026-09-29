// No verifier writes the owner's data (R-240, verifier hygiene, 2026-09-29).
//
// WHY THIS EXISTS. Thirteen provider-adapter verifiers defaulted to the owner's data dir: each deleted and (through
// the daemon) wrote `~/.ioi/hypervisor/data/resource-budgets/*-verify.json`, several deleted exposure records out of
// it, and all wrote offer fixtures under `~/.ioi/hypervisor/vast-fixture` (the SSH fixture lived beside them). They now
// run on their own isolated stack with a temp fixture dir (lib/verifier-stack.mjs). This guard keeps the class closed:
// a verifier, check, mutation battery or fixture helper that names the owner's Hypervisor home — `~/.ioi/hypervisor`,
// spelled as a path string or as `".ioi", "hypervisor"` segments — FAILS here, unless it is a READ-ONLY audit named
// below with its reason; for those, no write call may take a path derived from the owner's home.
//
// Out of scope by design: operator tools that the owner runs on purpose against their own data (admit-*, provision-*,
// extract-retained-*), which are neither verifiers nor checks.
//
// NOR THE OWNER'S STACK (R-240, verifier hazard sweep 2, 2026-09-29). After the auth sweep and the provider-adapter cut,
// seven verifiers still read `IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765"` / `… || "http://127.0.0.1:4173"`
// (action-runtime, filecoin-cas-archive-custody, harness-adapter-drivers, editor-harness-model-e2e,
// new-session-launcher, home-surface, the pipeline data-clean preflight) and ported-seed's live lane and
// action-runtime's fault serve started a serve with NO daemon URL, which reads the owner's :8765. Run by habit, the
// write-capable ones wrote into the owner's daemon. They run on their own stacks now; the second half of this file
// keeps that class closed: a script whose code names an owner-stack origin (:8765 daemon, :4173/:36173 serves) or falls
// back to one FAILS, unless it is a READ-ONLY owner audit named below with its reason (which may fall back to it), or
// a file that spells such an origin as DATA (recorded bytes, a redirect_uri, prose) and never falls back to it; and a
// script that starts serve-product-ui.mjs must hand that serve a daemon.
//
// Run: node --test apps/hypervisor/scripts/lib/verifier-owner-data-guard.test.mjs
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..", "..");
const ROOTS = [join(REPO, "apps", "hypervisor", "scripts"), join(REPO, "scripts")];
const SELF = fileURLToPath(import.meta.url);

// READ-ONLY by name. `vars` are the identifiers that hold (or derive from) the owner's path; the write-call check
// below taints everything assigned from them and refuses a write whose target mentions one.
export const READ_ONLY_OWNER_AUDITS = Object.freeze({
  "apps/hypervisor/scripts/verify-c7-c8-capstone.mjs": {
    reason: "audits the owner's retained C7/C8 capstone certificate read-only (the certificate lives in the owner's data dir)",
    vars: ["dataDir"],
  },
  "apps/hypervisor/scripts/verify-u1-real-campaign-relying-party.mjs": {
    reason: "re-verifies the retained U1 campaign evidence and registry read-only; every file it writes is in its own temp dir",
    vars: ["evidenceRoot", "dataDir"],
  },
  "apps/hypervisor/scripts/verify-governed-effect-packet.mjs": {
    reason: "reads the retained U1 registry admission read-only; its packet is built in its own temp dir",
    vars: ["evidenceRoot"],
  },
  "apps/hypervisor/scripts/verify-hypervisor-sources-action.mjs": {
    reason: "isolation proof: counts the owner's data-source record files before and after its own isolated run, read-only",
    vars: ["REAL_DATA_DIR"],
  },
  "apps/hypervisor/scripts/verify-hypervisor-data-source-plane.mjs": {
    reason: "isolation proof: counts the owner's data-source record files before and after its own isolated run, read-only",
    vars: ["REAL_DATA_DIR"],
  },
  "apps/hypervisor/scripts/verify-hypervisor-system-genesis-admission.mjs": {
    reason: "isolation proof: counts the owner's System genesis record families before and after its isolated runs, read-only",
    vars: ["REAL_DATA_DIR"],
  },
  "apps/hypervisor/scripts/verify-agentgres-substrate-bench.mjs": {
    reason: "reads the repo-local legacy provider-receipts dir (<repo>/.ioi/hypervisor/data, not the owner's home) as read-only input to a shadow run",
    vars: ["localReceipts"],
  },
  "apps/hypervisor/scripts/lib/verifier-stack.mjs": {
    reason: "defines the owner's Hypervisor home in order to REFUSE it (ownerHypervisorHome / ownerDataRefusal)",
    vars: [],
  },
});

const OWNER_HOME_SPELLINGS = [
  // "~/.ioi/hypervisor/data", `${HOME}/.ioi/hypervisor`, ".ioi/hypervisor/vast-fixture" — not ".ioi/hypervisor-app-local".
  /\.ioi\/hypervisor(?![-\w])/u,
  // path.join(os.homedir(), ".ioi", "hypervisor", ...)
  /["'`]\.ioi["'`]\s*,\s*["'`]hypervisor["'`]/u,
];

const WRITE_CALLS = /\b(?:writeFileSync|appendFileSync|rmSync|rmdirSync|unlinkSync|mkdirSync|mkdtempSync|renameSync|copyFileSync|cpSync|symlinkSync|chmodSync|truncateSync|createWriteStream|writeFile|appendFile|unlink|rename|mkdir|rm)\s*\(\s*([^,)]*)/gu;

/** Source with comments removed (strings and templates kept verbatim), so a comment naming the old path is not a use. */
export function stripComments(source) {
  let out = "";
  let i = 0;
  let quote = null;
  while (i < source.length) {
    const c = source[i];
    const next = source[i + 1];
    if (quote) {
      out += c;
      if (c === "\\") { out += next ?? ""; i += 2; continue; }
      if (c === quote) quote = null;
      i += 1;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") { quote = c; out += c; i += 1; continue; }
    if (c === "/" && next === "/") {
      while (i < source.length && source[i] !== "\n") i += 1;
      continue;
    }
    if (c === "/" && next === "*") {
      const end = source.indexOf("*/", i + 2);
      const block = source.slice(i, end < 0 ? source.length : end + 2);
      out += block.replace(/[^\n]/gu, "");
      i = end < 0 ? source.length : end + 2;
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
}

/** Identifiers holding a path derived from `seeds`: every `const|let|var X = …seed…` to a fixpoint. */
export function taintedIdentifiers(code, seeds) {
  const tainted = new Set(seeds);
  const assignment = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]*)/gu;
  let grew = true;
  while (grew) {
    grew = false;
    for (const [, name, rhs] of code.matchAll(assignment)) {
      if (tainted.has(name)) continue;
      if ([...tainted].some((t) => new RegExp(`(?<![\\w$.])${t.replace(/\$/gu, "\\$")}(?![\\w$])`, "u").test(rhs))) {
        tainted.add(name);
        grew = true;
      }
    }
  }
  return tainted;
}

/** The write calls whose target names an owner-derived identifier (or spells the owner's home inline). */
export function ownerWrites(code, seeds) {
  const tainted = taintedIdentifiers(code, seeds);
  const found = [];
  for (const match of code.matchAll(WRITE_CALLS)) {
    const target = match[1];
    const named = [...tainted].find((t) => new RegExp(`(?<![\\w$.])${t.replace(/\$/gu, "\\$")}(?![\\w$])`, "u").test(target));
    if (named || OWNER_HOME_SPELLINGS.some((re) => re.test(target))) {
      const line = code.slice(0, match.index).split("\n").length;
      found.push(`line ${line}: ${match[0].trim()}${named ? ` (via ${named})` : ""}`);
    }
  }
  return found;
}

function inScope(file) {
  const name = basename(file);
  if (!/\.(?:mjs|cjs|js)$/u.test(name)) return false;
  if (file === SELF) return false;
  return /^(?:verify|check|mutate|ensure)-/u.test(name) || basename(dirname(file)) === "lib";
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry.startsWith(".")) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (inScope(full)) out.push(full);
  }
  return out;
}

const FILES = ROOTS.flatMap((root) => walk(root));

test("the scan sees the estate: the verifiers, checks and fixture helpers the guard is about", () => {
  const names = new Set(FILES.map((f) => relative(REPO, f)));
  for (const expected of [
    "apps/hypervisor/scripts/verify-hypervisor-aws-enterprise-vm-adapter.mjs",
    "apps/hypervisor/scripts/verify-hypervisor-vast-candidate-adapter.mjs",
    "apps/hypervisor/scripts/ensure-ssh-fixture.mjs",
    "apps/hypervisor/scripts/lib/isolated-daemon.mjs",
    "scripts/check-dead-controls.mjs",
  ]) {
    assert.ok(names.has(expected), `${expected} is outside the scan`);
  }
  assert.ok(FILES.length > 300, `only ${FILES.length} files scanned`);
});

test("no verifier, check, battery or fixture helper names the owner's ~/.ioi/hypervisor unless it is a read-only audit named here", () => {
  const offenders = [];
  for (const file of FILES) {
    const rel = relative(REPO, file);
    if (READ_ONLY_OWNER_AUDITS[rel]) continue;
    const code = stripComments(readFileSync(file, "utf8"));
    const lines = code.split("\n");
    lines.forEach((line, index) => {
      if (OWNER_HOME_SPELLINGS.some((re) => re.test(line))) offenders.push(`${rel}:${index + 1}: ${line.trim().slice(0, 160)}`);
    });
  }
  assert.deepEqual(offenders, [], `these name the owner's Hypervisor home — run on a stack and fixture dir the verifier owns (lib/verifier-stack.mjs: verifierStack, verifierFixtureDir, refuseOwnerPath), or, for a READ-ONLY audit, name it in READ_ONLY_OWNER_AUDITS with its reason:\n${offenders.join("\n")}`);
});

test("every read-only audit named here still exists, still names the owner's home, and never writes a path derived from it", () => {
  for (const [rel, { reason, vars }] of Object.entries(READ_ONLY_OWNER_AUDITS)) {
    assert.ok(reason.length > 20, `${rel}: a read-only exception states its reason`);
    const code = stripComments(readFileSync(join(REPO, rel), "utf8"));
    assert.ok(OWNER_HOME_SPELLINGS.some((re) => re.test(code)), `${rel} no longer names the owner's home — drop its exception`);
    for (const v of vars) assert.match(code, new RegExp(`\\b${v}\\b`, "u"), `${rel}: exception names ${v}, which the file no longer declares`);
    assert.deepEqual(ownerWrites(code, vars), [], `${rel} is excepted as READ-ONLY but writes an owner-derived path`);
  }
});

// ---- the owner's STACK ------------------------------------------------------------------------------------------------

/** An owner-stack origin: the daemon (:8765), the sign-in-required serve (:36173), the development serve (:4173). */
export const OWNER_STACK_URL = /(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]):(?:8765|4173|36173)(?!\d)/u;
/** A fallback TO the owner's stack: `… || "http://127.0.0.1:8765"`, `… ?? "localhost:4173"`, `process.env.PORT || 4173`. */
export const OWNER_STACK_FALLBACK = /(?:\|\||\?\?)\s*\(?\s*(?:["'`](?:https?:\/\/)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]):(?:8765|4173|36173)(?!\d)|["'`]?(?:8765|4173|36173)(?![\w]))/u;

// READ-ONLY audits of the owner's own stack, by name: they may default to it. Each reads, never writes.
export const READ_ONLY_OWNER_STACK_AUDITS = Object.freeze({
  "apps/hypervisor/scripts/verify-c7-c8-capstone.mjs": {
    reason: "audits the owner's retained C7/C8 certificate against the provider receipts the owner's daemon promoted — one GET of /v1/hypervisor/provider-receipts (--daemon names another daemon); it writes nothing",
  },
});

// Files that spell an owner-stack origin as DATA — never a request target, never a fallback.
export const OWNER_STACK_LITERALS_NOT_TARGETS = Object.freeze({
  "apps/hypervisor/scripts/lib/verifier-stack.test.mjs": "the owner origins verifierStack and gateDaemon must refuse, as the refusal tests' inputs",
  "apps/hypervisor/scripts/verify-hypervisor-provider-connection-lifecycle.mjs": "the product's OAuth callback as the redirect_uri its stub provider echoes; the verifier parses the redirect, never fetches it, on a daemon it spawned",
  "scripts/check-dead-controls.mjs": "the serve origin inside element records measured from the live estate on 2026-09-24, kept verbatim for the pure drills; its live leg reads its own serve (gateDaemon)",
  "scripts/check-editor-challenge-relay.mjs": "the serveBase the relay library builds approve/card URLs from, over a stub transport, and the URLs it asserts; its live leg runs on its own stack",
  "scripts/check-acceptance-bounded-improvement.mjs": "prose: the NOT_ISOLATED reason a cited verifier carries",
  "scripts/check-acceptance-conformance-ladder.mjs": "prose: the NOT_ISOLATED reason a cited verifier carries",
  "scripts/check-acceptance-environment-lifecycle-spend.mjs": "prose: a clause's note on why a cited verifier is not isolated",
  "scripts/check-acceptance-external-effect-reconciliation.mjs": "prose: a clause's note on why a cited verifier is not isolated",
});

/** The owner-stack uses in `code` (comments already stripped): fallbacks, and — for a file not excepted — any origin. */
export function ownerStackUses(code, { audit = false, literal = false } = {}) {
  const found = [];
  code.split("\n").forEach((line, index) => {
    if (audit) return;
    if (OWNER_STACK_FALLBACK.test(line)) found.push(`${index + 1}: falls back to the owner's stack: ${line.trim().slice(0, 160)}`);
    else if (!literal && OWNER_STACK_URL.test(line)) found.push(`${index + 1}: names the owner's stack: ${line.trim().slice(0, 160)}`);
  });
  return found;
}

const SPAWN_CALL = /\b(?:spawn|spawnSync|fork|execFile|execFileSync)\s*\(/gu;
const HANDS_A_DAEMON = /IOI_HYPERVISOR_DAEMON_URL|childEnv\(|serveEnv/u;
/** Each call that starts serve-product-ui.mjs without handing it a daemon (in the call, or the env built just before it). */
export function daemonlessServeSpawns(code) {
  const found = [];
  for (const match of code.matchAll(SPAWN_CALL)) {
    let depth = 0;
    let end = match.index + match[0].length - 1;
    for (; end < code.length; end += 1) {
      if (code[end] === "(") depth += 1;
      else if (code[end] === ")" && --depth === 0) break;
    }
    const call = code.slice(match.index, end + 1);
    if (!/serve-product-ui/u.test(call)) continue;
    if (HANDS_A_DAEMON.test(call) || HANDS_A_DAEMON.test(code.slice(Math.max(0, match.index - 1500), match.index))) continue;
    found.push(`${code.slice(0, match.index).split("\n").length}: ${call.replace(/\s+/gu, " ").slice(0, 160)}`);
  }
  return found;
}

test("no verifier, check, battery or fixture helper defaults to the owner's stack (:8765, :4173, :36173) unless it is a read-only audit named here", () => {
  const offenders = [];
  for (const file of FILES) {
    const rel = relative(REPO, file);
    const code = stripComments(readFileSync(file, "utf8"));
    for (const use of ownerStackUses(code, { audit: !!READ_ONLY_OWNER_STACK_AUDITS[rel], literal: !!OWNER_STACK_LITERALS_NOT_TARGETS[rel] })) offenders.push(`${rel}:${use}`);
  }
  assert.deepEqual(offenders, [], `these default to (or name) the owner's stack — run on a stack the verifier owns (lib/verifier-stack.mjs: verifierStack; gateDaemon for a census gate's own serve), or, for a READ-ONLY owner audit, name it in READ_ONLY_OWNER_STACK_AUDITS with its reason (an origin spelled only as data goes in OWNER_STACK_LITERALS_NOT_TARGETS):\n${offenders.join("\n")}`);
});

test("a script that starts its own serve hands it a daemon — a serve with no IOI_HYPERVISOR_DAEMON_URL reads the owner's :8765", () => {
  const offenders = [];
  for (const file of FILES) {
    for (const spawnCall of daemonlessServeSpawns(stripComments(readFileSync(file, "utf8")))) offenders.push(`${relative(REPO, file)}:${spawnCall}`);
  }
  assert.deepEqual(offenders, [], `these start serve-product-ui.mjs with no daemon URL — pass IOI_HYPERVISOR_DAEMON_URL (a daemon this script owns: STACK.daemonUrl), or use verifierStack({ serve: true }):\n${offenders.join("\n")}`);
});

test("every owner-stack exception still exists, states its reason, and still spells the owner's stack", () => {
  for (const [rel, entry] of [...Object.entries(READ_ONLY_OWNER_STACK_AUDITS).map(([r, e]) => [r, e.reason]), ...Object.entries(OWNER_STACK_LITERALS_NOT_TARGETS)]) {
    assert.ok(entry.length > 20, `${rel}: an owner-stack exception states its reason`);
    const code = stripComments(readFileSync(join(REPO, rel), "utf8"));
    assert.ok(OWNER_STACK_URL.test(code), `${rel} no longer spells an owner-stack origin — drop its exception`);
  }
});

test("the owner-stack detectors fire: an env fallback, a numeric port fallback and a daemonless serve are caught; a comment, a free port and a handed daemon are not", () => {
  const uses = (src, opts) => ownerStackUses(stripComments(src), opts);
  assert.equal(uses('const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\\/$/, "");').length, 1);
  assert.equal(uses('const SHELL = process.env.IOI_HYPERVISOR_APP_URL ?? `http://localhost:4173`;').length, 1);
  assert.equal(uses("const port = process.env.PORT || 36173;").length, 1);
  assert.equal(uses('const daemon = arg("--daemon") || "http://127.0.0.1:8765";', { audit: true }).length, 0, "a named audit may fall back to the owner's daemon");
  assert.equal(uses('const REDIRECT = "http://127.0.0.1:4173/cb";', { literal: true }).length, 0, "an origin spelled as data is allowed in a named file");
  assert.equal(uses('const base = process.env.X || "http://127.0.0.1:4173";', { literal: true }).length, 1, "a named data file still may not fall back to it");
  assert.equal(uses('// this used to read http://127.0.0.1:8765\nconst url = "http://127.0.0.1:47123";').length, 0);
  assert.equal(uses('const bin = process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon"; const t = 87650;').length, 0);
  const daemonless = 'const child = spawn(process.execPath, [join(HERE, "serve-product-ui.mjs")], {\n  env: { ...process.env, PORT: String(p), IOI_APP_RUNTIME_TEST_ROUTE: "1" },\n});';
  assert.equal(daemonlessServeSpawns(daemonless).length, 1);
  assert.equal(daemonlessServeSpawns(daemonless.replace('IOI_APP_RUNTIME_TEST_ROUTE: "1"', "IOI_HYPERVISOR_DAEMON_URL: DAEMON")).length, 0);
  assert.equal(daemonlessServeSpawns('const env = { ...base, IOI_HYPERVISOR_DAEMON_URL: daemonUrl };\nconst child = spawn(process.execPath, [path.join(APP, "scripts", "serve-product-ui.mjs")], { env });').length, 0);
  assert.equal(daemonlessServeSpawns('const src = readFileSync(join(HERE, "serve-product-ui.mjs"), "utf8"); spawn("node", ["other.mjs"]);').length, 0);
});

test("the guard's own detectors fire: a comment is not a use, a spelled path is, and a derived write is caught", () => {
  assert.equal(OWNER_HOME_SPELLINGS.some((re) => re.test(stripComments('// used to write ~/.ioi/hypervisor/data\nconst x = 1;'))), false);
  assert.equal(OWNER_HOME_SPELLINGS.some((re) => re.test(stripComments('const url = "http://127.0.0.1:1"; const d = path.join(os.homedir(), ".ioi", "hypervisor", "data");'))), true);
  assert.equal(OWNER_HOME_SPELLINGS.some((re) => re.test('const DATA = `${process.env.HOME}/.ioi/hypervisor/data`;')), true);
  assert.equal(OWNER_HOME_SPELLINGS.some((re) => re.test('join(REPO_ROOT, ".ioi", "hypervisor-app-local")')), false);
  const planted = [
    "const DATA = process.env.IOI_HYPERVISOR_DATA_DIR || path.join(os.homedir(), '.ioi', 'hypervisor', 'data');",
    'const BUDGET_FILE = path.join(DATA, "resource-budgets", "aws-verify.json");',
    "rmSync(BUDGET_FILE, { force: true });",
    'const temp = mkdtempSync(join(tmpdir(), "x-"));',
    'writeFileSync(join(temp, "ok.json"), "{}");',
    'const n = readdirSync(join(DATA, "provider-spend-exposures")).length;',
  ].join("\n");
  assert.deepEqual(ownerWrites(planted, ["DATA"]), ["line 3: rmSync(BUDGET_FILE (via BUDGET_FILE)"]);
});
