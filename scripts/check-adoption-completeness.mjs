#!/usr/bin/env node
// Adoption completeness: the adopted tree is upstream bytes, exactly.
//
// WHY A SCRIPT AND NOT A ONE-TIME DIFF. The adoption shipped incomplete by a
// mechanism nobody declared: three upstream `.gitignore` files were never
// added, because `git add -A` honours a `.gitignore` inside the tree being
// added. The strip list was true about what was REMOVED and silent about what
// git DECLINED TO ADD. A one-time diff finds today's instance; a bar closes
// every silent-skip mechanism generically, including that one.
//
// TWO DIRECTIONS, BOTH REFUSED:
//   * every adopted file is byte-identical to upstream (blob SHA) or on the
//     declared per-file deviation list;
//   * every upstream file is adopted or on the declared exclusion list.
//
// THE VERIFIER MUST NOT INHERIT THE SUBJECT'S ENUMERATION. The upstream side is
// rebuilt from the pin with `git ls-tree` against a bare clone -- bytes only,
// no checkout, no script execution. An earlier pass diffed against a working
// COPY that had been produced by the same skip mechanism it was meant to
// detect, and so reported 1222 upstream files where the pin has 1277.
//
// A DEVIATION IS DECLARED PER FILE, WITH A REASON. Rebranding touches display
// strings only. Anything a resolver, package manager, or test consumes stays
// upstream bytes: a rewritten tarball URL is a forged identity, not a rebrand,
// and the one this cut produced pointed at a repository that does not exist.

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const ADOPTIONS = Object.freeze([
  Object.freeze({
    tree: "apps/ioi-ai",
    upstream: "https://github.com/yc-software/qm.git",
    pin: "5eb3393315b45b338b860572ab516db9f6eae6da",
    bare: "/var/tmp/qm-bare",
    // Declared exclusions. Exhaustive-or-false: an independent diff against the
    // pin must reproduce exactly this set, nothing undeclared in either
    // direction.
    exclusions: Object.freeze([
      ".github/", "deploy/", "fly/", "aws/", ".claude/", ".codex/",
      ".dockerignore", ".env.example", ".git/",
    ]),
    // Declared per-file deviations: display-string rebrands only.
    deviations: Object.freeze([
      "CLAUDE.md", "README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md",
      "deployment.md", "docs/deploy-directory.md", "cli/README.md",
      "cli/templates/deployment/SKILL.md", "cli/templates/deployment/deployment.md",
      "skills-seed/README.md", "docs/architecture.md", "docs/plugins.md",
      "local/README.md",
    ]),
    // Files this repository adds and upstream never had.
    additions: Object.freeze(["IOI-ADOPTION-PROVENANCE.md"]),
  }),
]);

const git = (args, cwd = REPO) =>
  execFileSync("git", args, { cwd, maxBuffer: 1e9 }).toString();

export function evaluate({ upstreamBlobs, adoptedBlobs, adoption }) {
  const findings = [];
  const excluded = (p) => adoption.exclusions.some((e) => (e.endsWith("/") ? p.startsWith(e) : p === e));
  const deviation = new Set(adoption.deviations);
  const addition = new Set(adoption.additions);

  for (const [path, sha] of upstreamBlobs) {
    if (excluded(path)) continue;
    if (!adoptedBlobs.has(path)) {
      findings.push(
        `upstream file ${path} is NOT adopted and NOT on the declared exclusion list — ` +
        `the adoption is incomplete by an undeclared mechanism`,
      );
      continue;
    }
    if (adoptedBlobs.get(path) !== sha && !deviation.has(path)) {
      findings.push(
        `adopted file ${path} DIFFERS from upstream bytes and is not a declared deviation — ` +
        `rebranding touches display strings only; anything a resolver, package manager, or ` +
        `test consumes stays upstream bytes`,
      );
    }
  }
  for (const path of adoptedBlobs.keys()) {
    if (addition.has(path)) continue;
    if (!upstreamBlobs.has(path)) {
      findings.push(`adopted file ${path} does not exist upstream and is not a declared addition`);
    }
  }
  for (const path of deviation) {
    if (!adoptedBlobs.has(path)) continue;
    if (adoptedBlobs.get(path) === upstreamBlobs.get(path)) {
      findings.push(
        `${path} is declared a deviation but is byte-identical to upstream — a stale deviation ` +
        `entry widens what may differ without anyone noticing`,
      );
    }
  }
  return findings;
}

function main() {
  const findings = [];
  let checked = 0;

  for (const adoption of ADOPTIONS) {
    if (!existsSync(resolve(REPO, adoption.tree))) continue;
    if (!existsSync(adoption.bare)) {
      console.log(
        `[ERROR] adoption-completeness: no bare clone at ${adoption.bare}; the upstream side must be ` +
        `rebuilt from the pin (git clone --bare ${adoption.upstream}) and never from a working copy`,
      );
      console.log("check-adoption-completeness: FAIL (1 error, 0 warn, 0 skip)");
      process.exit(1);
    }
    const upstreamBlobs = new Map(
      git(["ls-tree", "-r", "--format=%(objectname) %(path)", adoption.pin], adoption.bare)
        .split("\n").filter(Boolean)
        .map((line) => { const i = line.indexOf(" "); return [line.slice(i + 1), line.slice(0, i)]; }),
    );
    const adoptedBlobs = new Map(
      git(["ls-tree", "-r", "--format=%(objectname) %(path)", "HEAD", adoption.tree])
        .split("\n").filter(Boolean)
        .map((line) => { const i = line.indexOf(" "); return [line.slice(i + 1).slice(adoption.tree.length + 1), line.slice(0, i)]; }),
    );
    checked += adoptedBlobs.size;
    findings.push(...evaluate({ upstreamBlobs, adoptedBlobs, adoption }));
    console.log(
      `[WARN] adoption-completeness: ${adoption.tree} — ${adoptedBlobs.size} adopted file(s) against pin ` +
      `${adoption.pin.slice(0, 12)}; ${adoption.exclusions.length} declared exclusion(s), ` +
      `${adoption.deviations.length} declared deviation(s)`,
    );
  }

  for (const f of findings) console.log(`[ERROR] adoption-completeness: ${f}`);
  console.log(`adoption completeness: ${checked} file(s) compared by blob SHA; ${findings.length} discrepancy(ies)`);
  console.log(
    `check-adoption-completeness: ${findings.length === 0 ? "PASS" : "FAIL"} (${findings.length} error, ${ADOPTIONS.length} warn, 0 skip)`,
  );
  process.exit(findings.length === 0 ? 0 : 1);
}

main();
