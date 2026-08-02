#!/usr/bin/env node
// Structural integrity of the active estate: front matter, links, boundary,
// single-sequencer, work-item shape, and the reader-path budget.
//
//   node tools/check-estate.mjs [--scope <glob-prefix>] [--json]
//
// --scope restricts every file-walking check to one prefix, which is what makes
// the fast lane fast: an ordinary source-only edit never triggers a whole-estate
// or whole-repository scan.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import {
  boundary,
  ESTATE_ROOT,
  finding,
  inScope,
  listEstateFiles,
  parseFrontMatter,
  readJson,
  repoFileExists,
  report,
} from "./lib/estate.mjs";

const REQUIRED_FRONT_MATTER = [
  "module_id",
  "module_class",
  "title",
  "sequencer",
  "status_owner",
  "canon_owners",
];

// One sequencer, one status owner, one orientation view. These strings are the
// machine-checked identity of each role; a second file claiming a role fails.
const ROLE_CLAIMS = [
  {
    role: "sequencer",
    path: "program/sequence.v1.json",
    marker: (text) => JSON.parse(text).format === "ioi.program.sequence.v1",
  },
  {
    role: "canon map",
    path: "program/canon-map.v1.json",
    marker: (text) => JSON.parse(text).format === "ioi.program.canon_map.v1",
  },
  {
    role: "estate boundary",
    path: "program/estate-boundary.v1.json",
    marker: (text) => JSON.parse(text).format === "ioi.program.estate_boundary.v1",
  },
];

// Prose that would make a module a second status owner.
const STATUS_VOICE = [
  /\bis (?:now )?(?:currently )?(?:merged|verified|landed|shipped)\b/iu,
  /\bas of \d{4}-\d{2}-\d{2}\b/iu,
  /\bcurrently (?:active|blocked|in progress)\b/iu,
];

// A link target absent here but present on origin/master is CHECKOUT DIVERGENCE,
// not a broken link. The distinction matters: one is a defect in the estate, the
// other is a fact about which branch is checked out.
function existsOnMaster(repoRel) {
  try {
    execFileSync("git", ["cat-file", "-e", `origin/master:${repoRel}`], {
      cwd: path.join(ESTATE_ROOT, "..", ".."),
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

function scopeArg(argv) {
  const i = argv.indexOf("--scope");
  return i === -1 ? null : argv[i + 1];
}

export function runEstateChecks({ scope = null } = {}) {
  const findings = [];
  const b = boundary();
  const files = listEstateFiles().filter((f) =>
    scope ? f.startsWith(scope) : true
  );

  // --- root budget
  if (!scope) {
    const rootFiles = files.filter((f) => !f.includes("/"));
    if (rootFiles.length > 8) {
      findings.push(
        finding(
          "error",
          "root-budget",
          `active root holds ${rootFiles.length} files (budget is 8): ${
            rootFiles.join(", ")
          }`,
        ),
      );
    }
    for (const f of rootFiles) {
      if (!["README.md", "NOW.md"].includes(f)) {
        findings.push(
          finding(
            "warn",
            "root-entry",
            `root file is not one of the two declared entry points: ${f}`,
          ),
        );
      }
    }
  }

  // --- role uniqueness
  if (!scope) {
    for (const claim of ROLE_CLAIMS) {
      const absolute = path.join(ESTATE_ROOT, claim.path);
      if (!fs.existsSync(absolute)) {
        findings.push(
          finding("error", "role-missing", `${claim.role} missing: ${claim.path}`),
        );
        continue;
      }
      const claimants = [];
      for (const f of files.filter((f) => f.endsWith(".json"))) {
        if (f.startsWith("_archive/") || f.startsWith("generated/")) continue;
        try {
          if (claim.marker(fs.readFileSync(path.join(ESTATE_ROOT, f), "utf8"))) {
            claimants.push(f);
          }
        } catch {
          // not this role's format
        }
      }
      if (claimants.length !== 1 || claimants[0] !== claim.path) {
        findings.push(
          finding(
            "error",
            "role-uniqueness",
            `expected exactly one ${claim.role} at ${claim.path}, found: ${
              claimants.join(", ") || "(none)"
            }`,
          ),
        );
      }
    }
  }

  // --- module front matter and voice
  const modules = files.filter((f) =>
    (f.startsWith("stages/") || f.startsWith("modules/")) && f.endsWith(".md")
  );
  for (const rel of modules) {
    const text = fs.readFileSync(path.join(ESTATE_ROOT, rel), "utf8");
    const fm = parseFrontMatter(text);
    if (!fm) {
      findings.push(
        finding("error", "front-matter", `${rel} has no front matter block`),
      );
      continue;
    }
    for (const key of REQUIRED_FRONT_MATTER) {
      if (fm.data[key] === undefined) {
        findings.push(
          finding("error", "front-matter", `${rel} is missing "${key}"`),
        );
      }
    }
    for (const owner of fm.data.canon_owners ?? []) {
      if (!repoFileExists(owner)) {
        findings.push(
          finding(
            "error",
            "canon-owner-missing",
            `${rel} names a canon owner that does not exist: ${owner}`,
          ),
        );
      }
    }
    for (const pattern of STATUS_VOICE) {
      const m = pattern.exec(fm.body);
      if (m) {
        findings.push(
          finding(
            "error",
            "status-voice",
            `${rel} states current status ("${m[0]}"); status lives only in work-item records`,
          ),
        );
      }
    }
  }

  // --- every work item must be visible in its stage module.
  // A record that exists on disk but is absent from its stage's work-items table
  // cannot be found by a reader of the sequence, which is the whole point of the
  // stage module. This bar exists because exactly that drift occurred while the
  // coverage gaps were being closed.
  if (!scope) {
    const stageBodies = new Map();
    for (const rel of files.filter((f) => f.startsWith("stages/") && f.endsWith(".md"))) {
      stageBodies.set(
        path.basename(rel, ".md").toUpperCase(),
        fs.readFileSync(path.join(ESTATE_ROOT, rel), "utf8"),
      );
    }
    for (const rel of files.filter((f) =>
      f.startsWith("work-items/") && f.endsWith(".v1.json")
    )) {
      let record;
      try {
        record = JSON.parse(fs.readFileSync(path.join(ESTATE_ROOT, rel), "utf8"));
      } catch {
        continue;
      }
      const body = stageBodies.get(String(record.stage_id ?? "").toUpperCase());
      if (body === undefined) continue;
      if (!body.includes(record.work_item_id)) {
        findings.push(
          finding(
            "error",
            "work-item-unlisted",
            `${record.work_item_id} is not named in stages/${
              String(record.stage_id).toLowerCase()
            }.md; a record invisible in its stage module cannot be found by a reader of the sequence`,
          ),
        );
      }
    }
  }

  // --- every command a module tells an implementer to run must EXIST.
  // The retiring master guide's validation floor named 18 commands of which 10
  // did not exist. Rewriting the modules without this bar would only reset that
  // clock, so command existence is checked, not asserted.
  {
    const repoRoot = path.join(ESTATE_ROOT, "..", "..");
    const packageJson = JSON.parse(
      fs.readFileSync(path.join(repoRoot, "package.json"), "utf8"),
    );
    const scripts = new Set(Object.keys(packageJson.scripts ?? {}));
    // A command absent here but present on origin/master is checkout
    // divergence, not a stale reference. The estate is calibrated to merged
    // canon, so on a branch that is behind master this must SKIP, not fail —
    // the same rule the link and canon-subject bars apply.
    let masterScripts = new Set();
    try {
      masterScripts = new Set(
        Object.keys(
          JSON.parse(
            execFileSync("git", ["show", "origin/master:package.json"], {
              cwd: repoRoot,
              encoding: "utf8",
              maxBuffer: 8 * 1024 * 1024,
            }),
          ).scripts ?? {},
        ),
      );
    } catch {
      // no origin/master available; every absence is then a hard error
    }
    for (const rel of files.filter((f) =>
      (f.startsWith("stages/") || f.startsWith("modules/") || f === "README.md") &&
      f.endsWith(".md")
    )) {
      const text = fs.readFileSync(path.join(ESTATE_ROOT, rel), "utf8");
      for (const m of text.matchAll(/`npm run ([a-z0-9:._-]+)[^`]*`/gu)) {
        if (!scripts.has(m[1])) {
          const onMasterOnly = masterScripts.has(m[1]);
          findings.push(
            finding(
              onMasterOnly ? "skip" : "error",
              "command-missing",
              onMasterOnly
                ? `${rel} names \`npm run ${m[1]}\`, which is defined on origin/master but not in this checkout; checkout divergence, not a stale reference. SKIP is not success.`
                : `${rel} names \`npm run ${m[1]}\`, which is not defined in package.json`,
            ),
          );
        }
      }
      for (const m of text.matchAll(/`node ([^`\s]+\.mjs)[^`]*`/gu)) {
        const target = m[1].replace(/^\.\//, "");
        const absolute = target.startsWith("internal-docs/implementation/")
          ? path.join(ESTATE_ROOT, target.replace("internal-docs/implementation/", ""))
          : path.join(ESTATE_ROOT, "..", "..", target);
        if (!fs.existsSync(absolute)) {
          let onMaster = false;
          try {
            execFileSync("git", ["cat-file", "-e", `origin/master:${target}`], {
              cwd: repoRoot,
              stdio: "ignore",
            });
            onMaster = true;
          } catch { /* absent on master too */ }
          findings.push(
            finding(
              onMaster ? "skip" : "error",
              "command-missing",
              onMaster
                ? `${rel} names \`node ${target}\`, which exists on origin/master but not in this checkout; checkout divergence. SKIP is not success.`
                : `${rel} names \`node ${target}\`, which does not exist`,
            ),
          );
        }
      }
    }
  }

  // --- internal links, over the declared link-checked scope only
  const linkScope = scope ? [scope] : b.link_checked;
  const linkTargets = new Set(listEstateFiles());
  for (const rel of files) {
    if (!rel.endsWith(".md")) continue;
    if (!inScope(rel, linkScope)) continue;
    const text = fs.readFileSync(path.join(ESTATE_ROOT, rel), "utf8");
    for (const m of text.matchAll(/\[[^\]]*\]\((\.[^)\s#]*)(#[^)\s]*)?\)/gu)) {
      const target = m[1];
      const resolved = path.normalize(
        path.join(path.dirname(rel), target),
      );
      if (resolved.startsWith("..")) {
        // points outside the estate — resolve against the repo
        const repoRel = path.normalize(
          path.join(path.dirname(path.join("internal-docs/implementation", rel)), target),
        );
        if (!repoFileExists(repoRel) &&
          !fs.existsSync(path.join(ESTATE_ROOT, "..", "..", repoRel))
        ) {
          const onMaster = existsOnMaster(repoRel.replace(/\/$/, ""));
          findings.push(
            finding(
              onMaster ? "skip" : "error",
              "link",
              onMaster
                ? `${rel} -> ${target} is absent from this checkout but present on origin/master; this is checkout divergence, not a broken link. SKIP is not success.`
                : `${rel} -> ${target} (missing: ${repoRel})`,
            ),
          );
        }
        continue;
      }
      const cleaned = resolved.replace(/\/$/, "");
      if (
        !linkTargets.has(cleaned) &&
        !linkTargets.has(`${cleaned}/README.md`) &&
        !fs.existsSync(path.join(ESTATE_ROOT, cleaned))
      ) {
        findings.push(finding("error", "link", `${rel} -> ${target}`));
      }
    }
  }

  // --- sequence integrity
  if (!scope || scope.startsWith("program")) {
    const sequence = readJson(
      path.join(ESTATE_ROOT, "program", "sequence.v1.json"),
    );
    const ids = new Set(sequence.stages.map((s) => s.id));
    for (const stage of sequence.stages) {
      for (const dep of stage.depends_on ?? []) {
        if (!ids.has(dep)) {
          findings.push(
            finding(
              "error",
              "sequence",
              `stage ${stage.id} depends on unknown stage ${dep}`,
            ),
          );
        }
      }
      if (stage.module && !fs.existsSync(path.join(ESTATE_ROOT, stage.module))) {
        findings.push(
          finding(
            "error",
            "sequence",
            `stage ${stage.id} names a missing module: ${stage.module}`,
          ),
        );
      }
    }
    // A module file that the sequence does not declare is unbound doctrine: no
    // stage can pull it, so nothing routes review to it when canon changes.
    const declared = new Set(sequence.modules.map((m) => m.path));
    for (const rel of files.filter((f) => f.startsWith("modules/") && f.endsWith(".md"))) {
      if (!declared.has(rel)) {
        findings.push(
          finding(
            "error",
            "module-undeclared",
            `${rel} exists but is not declared in program/sequence.v1.json modules[]; no stage can pull it`,
          ),
        );
      }
    }
    for (const mod of sequence.modules) {
      if (!fs.existsSync(path.join(ESTATE_ROOT, mod.path))) {
        findings.push(
          finding("error", "sequence", `module ${mod.id} file missing: ${mod.path}`),
        );
      }
      for (const stage of mod.applies_to_stages ?? []) {
        if (!ids.has(stage)) {
          findings.push(
            finding(
              "error",
              "sequence",
              `module ${mod.id} applies to unknown stage ${stage}`,
            ),
          );
        }
      }
    }
  }

  return findings;
}

function main() {
  const findings = runEstateChecks({ scope: scopeArg(process.argv) });
  process.exit(
    report("check-estate", findings, { json: process.argv.includes("--json") }),
  );
}

if (import.meta.url === `file://${process.argv[1]}`) main();
