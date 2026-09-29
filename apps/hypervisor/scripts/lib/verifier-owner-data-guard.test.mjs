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
  "apps/hypervisor/scripts/verify-hypervisor-action-runtime.mjs": {
    reason: "reads governance approval-transition receipt files of the stack it measures (IOI_HYPERVISOR_DATA_DIR, else the owner's), read-only",
    vars: ["DATA_DIR"],
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
