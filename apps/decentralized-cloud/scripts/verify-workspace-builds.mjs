#!/usr/bin/env node
// EVERY WORKSPACE THAT BUILDS, BUILT — before and after the React bump.
//
// The bump unifies four different React versions living in one npm workspace
// (19.2.0, 19.0.0, 18.3.1, 18.2.0), and unifying them upward is a MAJOR version
// change for the largest surface in the estate. A claim that "the bump is fine"
// is worth exactly as much as the set of things that were built to check it, so
// this builds every workspace member that declares a build script and prints the
// list, the versions, and the failures.
//
// It is run TWICE — once before the bump and once after — and the two runs are
// compared. That ordering is not ceremony: a build that was already red before I
// touched anything is not evidence about my change, and absorbing someone else's
// drift as your own is a mistake this program has made before.
//
// Usage:
//   node apps/decentralized-cloud/scripts/verify-workspace-builds.mjs --label before
//   node apps/decentralized-cloud/scripts/verify-workspace-builds.mjs --label after
//   node apps/decentralized-cloud/scripts/verify-workspace-builds.mjs --compare

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const OUT = path.join(HERE, "../.artifacts/builds");
mkdirSync(OUT, { recursive: true });

const labelArg = process.argv.indexOf("--label");
const LABEL = labelArg > -1 ? process.argv[labelArg + 1] : null;
const COMPARE = process.argv.includes("--compare");

// The workspace members are read from the root package.json rather than listed
// here, so a member added later is built by this without anyone remembering to
// add it. A hand-maintained list is a list that goes stale silently.
function members() {
  const root = JSON.parse(readFileSync(path.join(REPO, "package.json"), "utf8"));
  const out = [];
  for (const pattern of root.workspaces || []) {
    if (pattern.endsWith("/*")) {
      const dir = path.join(REPO, pattern.slice(0, -2));
      if (!existsSync(dir)) continue;
      for (const name of readdirSync(dir)) {
        const p = path.join(dir, name);
        if (existsSync(path.join(p, "package.json"))) out.push(path.relative(REPO, p));
      }
    } else if (existsSync(path.join(REPO, pattern, "package.json"))) {
      out.push(pattern);
    }
  }
  return out;
}

function describe(rel) {
  const pkg = JSON.parse(readFileSync(path.join(REPO, rel, "package.json"), "utf8"));
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  return {
    dir: rel,
    name: pkg.name,
    react: deps.react || null,
    reactDom: deps["react-dom"] || null,
    hasBuild: Boolean(pkg.scripts && pkg.scripts.build),
  };
}

if (COMPARE) {
  const before = JSON.parse(readFileSync(path.join(OUT, "before.json"), "utf8"));
  const after = JSON.parse(readFileSync(path.join(OUT, "after.json"), "utf8"));
  const byDir = (r) => Object.fromEntries(r.results.map((x) => [x.dir, x]));
  const B = byDir(before), A = byDir(after);
  const dirs = [...new Set([...Object.keys(B), ...Object.keys(A)])].sort();
  let regressions = 0, stillRed = 0, fixed = 0;
  console.log("── before vs after ──");
  for (const d of dirs) {
    const b = B[d], a = A[d];
    if (!b || !a) { console.log(`  ?     ${d}  (present in only one run)`); continue; }
    if (!b.hasBuild && !a.hasBuild) continue;
    const was = b.ok, is = a.ok;
    if (was && !is) { regressions++; console.log(`  BROKE ${d}  ${b.react} -> ${a.react}`); }
    else if (!was && !is) { stillRed++; console.log(`  red   ${d}  (red BEFORE the bump too — not mine)`); }
    else if (!was && is) { fixed++; console.log(`  fixed ${d}`); }
    else console.log(`  ok    ${d}  ${b.react || "-"} -> ${a.react || "-"}`);
  }
  console.log(`\n${regressions} regression(s), ${fixed} fixed, ${stillRed} red before and after.`);
  if (stillRed) console.log(`A build that was already red is reported as red, not as a pass and not as mine.`);
  process.exit(regressions ? 1 : 0);
}

if (!LABEL) {
  console.error("--label <before|after> or --compare");
  process.exit(2);
}

const results = [];
for (const rel of members()) {
  const d = describe(rel);
  if (!d.hasBuild) {
    console.log(`  skip  ${d.dir}  (${d.name}: no build script)`);
    results.push({ ...d, ok: null, ms: 0 });
    continue;
  }
  const t0 = Date.now();
  let ok = true, err = "";
  try {
    execFileSync("npm", ["run", "build", "--workspace", d.name], {
      cwd: REPO, stdio: "pipe", timeout: 15 * 60 * 1000,
      env: { ...process.env, CI: "1" },
    });
  } catch (e) {
    ok = false;
    err = String((e.stderr || e.stdout || e.message) || "").split("\n").slice(-6).join(" | ").slice(0, 500);
  }
  const ms = Date.now() - t0;
  results.push({ ...d, ok, ms, err });
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${d.dir}  react ${d.react || "-"}  ${(ms / 1000).toFixed(1)}s${ok ? "" : `\n        ${err}`}`);
}

const built = results.filter((r) => r.hasBuild);
const failed = built.filter((r) => !r.ok);
writeFileSync(
  path.join(OUT, `${LABEL}.json`),
  JSON.stringify({ label: LABEL, at: new Date().toISOString(), results }, null, 2)
);
console.log(`\n${built.length - failed.length}/${built.length} workspace builds passed (${LABEL})`);
console.log(`react versions seen: ${[...new Set(results.map((r) => r.react).filter(Boolean))].sort().join(", ") || "none"}`);
console.log(`written: ${path.join(OUT, `${LABEL}.json`)}`);
