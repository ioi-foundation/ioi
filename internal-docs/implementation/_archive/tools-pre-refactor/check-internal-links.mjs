#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import {
  failWith,
  implementationRoot,
  listTreeFiles,
  markdownAnchor,
  readJson,
  repoRoot,
  repoRelative,
  sha256File,
} from "./lib.mjs";

const errors = [];
const markdownFiles = listTreeFiles(implementationRoot).filter((file) => file.endsWith(".md"));
const registry = readJson(path.join(implementationRoot, "source-dispositions.v1.json"));
const archivedOriginByPath = new Map();
const archivedPathByOrigin = new Map();
for (const source of registry.sources ?? []) {
  if (!source.preserved_body_path) continue;
  const archived = path.resolve(implementationRoot, source.preserved_body_path);
  const origin = path.resolve(implementationRoot, source.source_path);
  archivedOriginByPath.set(archived, { origin, source });
  archivedPathByOrigin.set(origin, archived);
}

// This byte-frozen artifact deliberately preserves the one link that existed
// immediately before its live successor was repaired. It is not silently
// ignored: the exact archived body, repaired successor, replacement target,
// and replacement resolution must all remain valid.
const historicalRepairExceptions = new Map([
  [
    "_archive/originals/2026-07-16-canon-sota-improvement-review.pre-link-repair.md\u0000../components/model-router/doctrine.md",
    {
      archived_sha256: "cdd8f1077926e7aabb0f99414c2222accdf4d27bff766ec9fae285bded4113ef",
      repaired_file: "audits/history/2026-07-16-canon-sota-improvement-review.md",
      repaired_target: "../../../../docs/architecture/components/model-router/doctrine.md",
    },
  ],
]);
const consumedHistoricalRepairs = new Set();

function headings(file) {
  const anchors = new Set();
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/u)) {
    const match = /^(#{1,6})\s+(.+?)\s*#*$/u.exec(line);
    if (match) anchors.add(markdownAnchor(match[2]));
    const explicit = /<a\s+(?:name|id)=["']([^"']+)["']/gu;
    for (const item of line.matchAll(explicit)) anchors.add(item[1]);
  }
  return anchors;
}

for (const file of markdownFiles) {
  const relative = repoRelative(file);
  const archivedOrigin = archivedOriginByPath.get(file);
  const logicalFile = archivedOrigin?.origin ?? file;
  const resolutionBase = path.dirname(logicalFile);
  const source = fs.readFileSync(file, "utf8");
  const linkPattern = /\[[^\]]*\]\(([^)]+)\)/gu;
  for (const match of source.matchAll(linkPattern)) {
    let target = match[1].trim();
    if (target.startsWith("<") && target.endsWith(">")) target = target.slice(1, -1);
    if (!target || /^(?:https?:|mailto:|data:|javascript:)/u.test(target)) continue;
    const [rawPath, rawAnchor] = target.split("#", 2);
    const decodedPath = decodeURIComponent(rawPath || "");
    const logicalTarget = decodedPath ? path.resolve(resolutionBase, decodedPath) : logicalFile;
    const targetFile = archivedOrigin
      ? (archivedPathByOrigin.get(logicalTarget) ?? logicalTarget)
      : logicalTarget;
    if (!fs.existsSync(targetFile)) {
      const implementationRelative = path.relative(implementationRoot, file).split(path.sep).join("/");
      const exceptionKey = `${implementationRelative}\u0000${target}`;
      const repair = historicalRepairExceptions.get(exceptionKey);
      if (repair) {
        const repairedFile = path.join(implementationRoot, repair.repaired_file);
        const repairedTarget = path.resolve(path.dirname(repairedFile), repair.repaired_target);
        const archivedDigest = archivedOrigin?.source?.baseline_sha256;
        const repairedSource = fs.existsSync(repairedFile) ? fs.readFileSync(repairedFile, "utf8") : "";
        if (
          archivedDigest !== repair.archived_sha256
          || sha256File(file) !== repair.archived_sha256
          || !repairedSource.includes(`](${repair.repaired_target})`)
          || !fs.existsSync(repairedTarget)
        ) {
          errors.push(`${relative} -> historical repair contract is stale for ${target}`);
        } else {
          consumedHistoricalRepairs.add(exceptionKey);
        }
        continue;
      }
      errors.push(`${relative} -> missing ${target}`);
      continue;
    }
    if (rawAnchor && targetFile.endsWith(".md") && !headings(targetFile).has(decodeURIComponent(rawAnchor).toLowerCase())) {
      errors.push(`${relative} -> missing heading #${rawAnchor} in ${repoRelative(targetFile)}`);
    }
  }
}

for (const exceptionKey of historicalRepairExceptions.keys()) {
  if (!consumedHistoricalRepairs.has(exceptionKey)) {
    errors.push(`historical link-repair exception was not exercised: ${exceptionKey.replace("\u0000", " -> ")}`);
  }
}

failWith("internal-link check", errors);
process.stdout.write(`internal-link check passed: ${markdownFiles.length} private Markdown files resolved from live or preserved logical locations; ${consumedHistoricalRepairs.size} exact historical repair contract(s) verified\n`);
