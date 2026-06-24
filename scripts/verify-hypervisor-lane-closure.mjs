#!/usr/bin/env node
// T1 — Hypervisor lane-closure verifier.
//
// Makes the repo state report TRUTHFULLY distinguish four things that are easy to conflate:
//   feature lane complete · whole checkout clean · user WIP present · ignored local artifacts.
// "lane complete" and "checkout clean" are SEPARATE booleans — a green feature lane never implies
// a clean checkout, and user WIP (docs/architecture/*) is never auto-cleaned or mislabeled clean.
//
// Usage:
//   node scripts/verify-hypervisor-lane-closure.mjs [--json] [--range <a>..<b>] [--allow <glob,glob>]
// Exit code: 0 on PASS or BLOCKED_USER_WIP (lane is closed; checkout has only user-owned WIP);
//            1 on FAIL (lane files uncommitted, or unknown/unowned dirty files present).
import { execSync } from "node:child_process";

const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const RANGE = args[args.indexOf("--range") + 1] && !args[args.indexOf("--range") + 1].startsWith("--") ? args[args.indexOf("--range") + 1] : null;
const ALLOW = (args[args.indexOf("--allow") + 1] && !args[args.indexOf("--allow") + 1].startsWith("--") ? args[args.indexOf("--allow") + 1] : "").split(",").filter(Boolean);

const git = (c) => execSync(`git ${c}`, { encoding: "utf8" }).trim();

// Path ownership classes. Order matters: first match wins.
const CLASSES = [
  ["user_wip", [/^docs\/architecture\//]],
  ["lane", [
    /^crates\/node\/src\/bin\/hypervisor/,
    /^scripts\/phase1\//,
    /^scripts\/verify-hypervisor-/,
    /^scripts\/verify-phase1-/,
    /^apps\/hypervisor\/scripts\/ioi-/,
    /^apps\/hypervisor\/scripts\/serve-live-reference/,
    /^apps\/hypervisor\/src\//,
    /^packages\/(workspace-substrate|hypervisor-workbench|agent-sdk|wallet-sdk|wallet-protocol)\//,
  ]],
  ["generated", [/^target\//, /\/dist\//, /^dist\//, /node_modules\//, /\.tsbuildinfo$/, /(package-lock\.json|pnpm-lock\.yaml)$/]],
];

function classify(path) {
  for (const [name, pats] of CLASSES) if (pats.some((re) => re.test(path))) return name;
  return "unknown";
}
const allowed = (path) => ALLOW.some((g) => { const re = new RegExp("^" + g.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$"); return re.test(path); });

const branch = git("rev-parse --abbrev-ref HEAD");
const head = git("rev-parse --short HEAD");
// NB: do NOT trim — the first porcelain line's leading status space must be preserved.
const porcelain = execSync("git status --porcelain", { encoding: "utf8" }).replace(/\n$/, "");
const tracked = [];
const untracked = [];
for (const line of porcelain.split("\n").filter(Boolean)) {
  const status = line.slice(0, 2);
  const path = line.slice(3).replace(/^.* -> /, ""); // handle renames
  const cls = classify(path);
  if (status === "??") untracked.push({ path, class: cls });
  else tracked.push({ path, status: status.trim(), class: cls });
}

const laneDirty = tracked.filter((t) => t.class === "lane");
const generatedDirty = tracked.filter((t) => t.class === "generated");
const userWip = [...tracked, ...untracked].filter((t) => t.class === "user_wip");
const unknownDirty = [...tracked, ...untracked].filter((t) => t.class === "unknown" && !allowed(t.path));

const laneComplete = laneDirty.length === 0 && generatedDirty.length === 0;
const checkoutClean = tracked.length === 0 && untracked.length === 0;

let verdict;
if (checkoutClean) verdict = "PASS";
else if (laneComplete && unknownDirty.length === 0) verdict = "BLOCKED_USER_WIP";
else verdict = "FAIL";

const report = {
  branch, head, expected_range: RANGE,
  lane_complete: laneComplete,
  checkout_clean: checkoutClean,
  user_wip_present: userWip.length > 0,
  blocking: {
    lane_uncommitted: laneDirty.map((t) => `${t.status} ${t.path}`),
    generated_uncommitted: generatedDirty.map((t) => `${t.status} ${t.path}`),
    unknown_dirty: unknownDirty.map((t) => t.path),
  },
  user_wip: userWip.map((t) => t.path),
  verdict,
};

if (JSON_OUT) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`Hypervisor lane closure`);
  console.log(`  branch / HEAD:   ${branch} @ ${head}${RANGE ? ` (expected ${RANGE})` : ""}`);
  console.log(`  lane complete:   ${laneComplete}`);
  console.log(`  checkout clean:  ${checkoutClean}`);
  console.log(`  user WIP present:${userWip.length > 0} ${userWip.length ? `(${userWip.length} files, e.g. ${userWip[0].path})` : ""}`);
  if (laneDirty.length) console.log(`  ✗ lane uncommitted:\n${laneDirty.map((t) => `      ${t.status} ${t.path}`).join("\n")}`);
  if (generatedDirty.length) console.log(`  ✗ generated uncommitted:\n${generatedDirty.map((t) => `      ${t.status} ${t.path}`).join("\n")}`);
  if (unknownDirty.length) console.log(`  ✗ unknown/unowned dirty (allowlist or commit):\n${unknownDirty.map((t) => `      ${t.path}`).join("\n")}`);
  console.log(`  VERDICT: ${verdict}`);
  if (verdict === "BLOCKED_USER_WIP") {
    console.log(`\n  Phase lane: terminal`);
    console.log(`  Whole checkout: not clean`);
    console.log(`  Blocking files (user-owned WIP): ${userWip.map((t) => t.path).join(", ")}`);
    console.log(`  Resolution: commit/stash/park by user direction. Lane completion is NOT a clean-checkout claim.`);
  }
}
process.exit(verdict === "FAIL" ? 1 : 0);
