#!/usr/bin/env node
// Declared discovery exclusions: printed every run, and their dormancy checked.
//
// An exclusion is a blind spot in the census. This gate makes the blind spot
// impossible to hold without reading it, and impossible to hold falsely:
//
//  * every declared exclusion PRINTS on every run — path, grounds, ruling date,
//    pin sha, expiry, and the live file count it is hiding;
//  * the dormancy the exclusion ASSERTS is CHECKED. Any reachability edge into
//    an excluded tree — cross-boundary import, serve mount, workspace or build
//    wiring, route registration — refuses as undeclared-reachable-excluded-tree.
//
// The refusal is deliberate in both directions: the gate will not silently widen
// discovery to walk a reachable tree, and it will not keep excluding one. Either
// is a decision an owner makes, not a tool.

import { execSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DECLARED_DISCOVERY_EXCLUSIONS,
  reachabilityIntoExcludedTrees,
} from "./lib/m0-program-control-model.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function main() {
  const tracked = execSync("git ls-files", { cwd: REPO, maxBuffer: 1e9 })
    .toString().split("\n").filter(Boolean);
  const findings = [];

  for (const e of DECLARED_DISCOVERY_EXCLUSIONS) {
    const count = tracked.filter((p) => p.startsWith(e.path)).length;
    console.log(
      `[WARN] discovery-exclusion: ${e.path} — ${count} tracked file(s) hidden from discovery. ` +
      `Grounds: ${e.grounds}. Ruled ${e.ruling_date}. Pin ${e.pin_sha}. Expires: ${e.drops_at}`,
    );
  }

  // Teeth. Only non-excluded sources are scanned for edges INTO excluded trees.
  const candidates = tracked.filter(
    (p) => /\.(mjs|js|ts|tsx|json|toml|rs)$/.test(p) &&
      !DECLARED_DISCOVERY_EXCLUSIONS.some((e) => p.startsWith(e.path)) &&
      !p.startsWith("docs/evidence/") &&
      !p.startsWith("internal-docs/implementation/evidence/") &&
      p !== "scripts/check-discovery-exclusions.mjs" &&
      p !== "scripts/lib/m0-program-control-model.mjs",
  );
  findings.push(...reachabilityIntoExcludedTrees(REPO, candidates));

  for (const f of findings) console.log(`[ERROR] discovery-exclusion: ${f}`);
  console.log(
    `discovery exclusions: ${DECLARED_DISCOVERY_EXCLUSIONS.length} declared; ` +
    `${findings.length} reachability violation(s)`,
  );
  console.log(
    `check-discovery-exclusions: ${findings.length === 0 ? "PASS" : "FAIL"} (${findings.length} error, ${DECLARED_DISCOVERY_EXCLUSIONS.length} warn, 0 skip)`,
  );
  process.exit(findings.length === 0 ? 0 : 1);
}

main();
