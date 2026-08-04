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

import { execFileSync, execSync } from "node:child_process";
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

  // WORKSPACE REACHABILITY, ASKED OF THE RESOLVER — never grepped from config.
  //
  // A literal path match against package.json is a guess about what npm will
  // do. The resolver is the authority on what resolves, so the tooth asks it.
  //
  // AND IT MUST NOT ASK VIA THE LOCK. `npm query .workspace` answers from
  // package-lock.json, which is a CACHED resolution: it reported apps/ioi-ai
  // absent while `workspaces: ["apps/*"]` and apps/ioi-ai/package.json both
  // existed, purely because the lock had not been regenerated since adoption.
  // A stale cache reporting "not reachable" is the most dangerous possible
  // answer. `npm pkg get --workspace <path>` resolves against the CONFIG and
  // errors "No workspaces found" for a path the resolver does not admit.
  for (const e of DECLARED_DISCOVERY_EXCLUSIONS) {
    const target = e.path.replace(/\/$/, "");
    let resolved = false;
    try {
      execFileSync("npm", ["pkg", "get", "name", "--workspace", target],
        { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] });
      resolved = true;
    } catch { resolved = false; }
    if (resolved) {
      findings.push(
        `undeclared-reachable-excluded-tree: npm resolves ${target} as a WORKSPACE, but it is ` +
        `declared EXCLUDED on the grounds that it is dormant. The resolver's view is the ` +
        `reachability: a tree the package manager will install, link, and hoist is not dormant. ` +
        `Remove it from the workspace globs, or drop the exclusion and bring it into discovery.`,
      );
    }
  }

  // Teeth. Only non-excluded sources are scanned for edges INTO excluded trees.
  // Teeth scan CODE AND BUILD WIRING ONLY.
  //
  // Work-item records and prose describe reachability; they do not create it.
  // The narrowed edge predicate still matched a record whose text reads
  // "...can contain a route -- the file that exposed this defect is literally
  // apps/ioi-ai/src/api/routes/...", which is a record doing its job. Scanning
  // declarations for edges is the same mistake as scanning them for mentions,
  // one level finer: the question is what MAKES the tree reachable, and a
  // record makes nothing reachable.
  const candidates = tracked.filter(
    (p) => /\.(mjs|js|ts|tsx|json|toml|rs)$/.test(p) &&
      !p.startsWith("internal-docs/implementation/work-items/") &&
      !p.startsWith("internal-docs/architecture/") &&
      !p.startsWith("docs/architecture/") &&
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
