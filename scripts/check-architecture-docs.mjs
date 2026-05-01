#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const architectureRoot = path.join(root, "docs/architecture");
const failures = [];

function allMarkdownFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const absolute = path.join(dir, entry.name);
    if (entry.isDirectory()) return allMarkdownFiles(absolute);
    return entry.name.endsWith(".md") ? [absolute] : [];
  });
}

function relative(file) {
  return path.relative(root, file);
}

function isImportedConsensusCorpus(file) {
  return relative(file).startsWith("docs/architecture/consensus/aft/");
}

function fail(message) {
  failures.push(message);
}

const markdownFiles = allMarkdownFiles(architectureRoot);
const rootMarkdownFiles = fs
  .readdirSync(architectureRoot, { withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
  .map((entry) => entry.name);
const allowedRootMarkdown = new Set(["README.md"]);
for (const file of rootMarkdownFiles) {
  if (!allowedRootMarkdown.has(file)) {
    fail(`docs/architecture/${file} must live in a subject directory or be moved to README.md.`);
  }
}

for (const file of markdownFiles) {
  if (isImportedConsensusCorpus(file)) continue;
  const content = fs.readFileSync(file, "utf8");
  const firstLines = content.split(/\r?\n/).slice(0, 12).join("\n");
  if (!/^Status:/m.test(firstLines)) {
    fail(`${relative(file)} is missing a status block near the top.`);
  }
}

const markdownLinkPattern = /\[[^\]]+\]\(([^)\n]+)\)/g;
for (const file of markdownFiles) {
  if (isImportedConsensusCorpus(file)) continue;
  const content = fs.readFileSync(file, "utf8");
  for (const match of content.matchAll(markdownLinkPattern)) {
    const rawTarget = match[1].trim();
    if (
      rawTarget.startsWith("http://") ||
      rawTarget.startsWith("https://") ||
      rawTarget.startsWith("mailto:") ||
      rawTarget.startsWith("#")
    ) {
      continue;
    }
    const targetWithoutHash = rawTarget.split("#")[0];
    if (!targetWithoutHash) continue;
    const resolved = path.resolve(path.dirname(file), targetWithoutHash);
    if (!resolved.startsWith(root)) {
      fail(`${relative(file)} links outside the repository: ${rawTarget}`);
      continue;
    }
    if (!fs.existsSync(resolved)) {
      fail(`${relative(file)} has broken local link: ${rawTarget}`);
    }
  }
}

const staleLinePatterns = [
  { name: "legacy cap prefix", pattern: /\bcap:[A-Za-z0-9_.-]+/ },
  { name: "legacy capgrant", pattern: /\bcapgrant\b/ },
  { name: "legacy capability_grant", pattern: /\bcapability_grant\b/ },
  { name: "legacy capability_policy", pattern: /\bcapability_policy\b/ },
  { name: "legacy capabilities_required", pattern: /\bcapabilities_required\b/ },
  { name: "legacy wallet_capabilities_required", pattern: /\bwallet_capabilities_required\b/ },
  { name: "legacy CapabilityEnvelope", pattern: /\bCapabilityEnvelope\b/ },
  { name: "legacy capability grant phrase", pattern: /\bcapability grants?\b/i },
  { name: "legacy capability request phrase", pattern: /\bcapability request\b/i },
  { name: "legacy scoped capability phrase", pattern: /\bscoped capabilities\b/i },
];

function lineIsAllowedLegacyNote(file, line) {
  const rel = relative(file);
  if (
    rel.endsWith("documentation-contradiction-log.md") ||
    rel.endsWith("documentation-refactor-report.md")
  ) {
    return true;
  }
  return /older|legacy|historical|supersedes|pre-split|watchlist/i.test(line);
}

for (const file of markdownFiles) {
  if (isImportedConsensusCorpus(file)) continue;
  const content = fs.readFileSync(file, "utf8");
  const lines = content.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    for (const { name, pattern } of staleLinePatterns) {
      if (pattern.test(line) && !lineIsAllowedLegacyNote(file, line)) {
        fail(`${relative(file)}:${index + 1} contains ${name}: ${line.trim()}`);
      }
    }
  }
}

const index = fs.readFileSync(path.join(architectureRoot, "README.md"), "utf8");
for (const required of [
  "operations/source-of-truth-map.md",
  "operations/documentation-contradiction-log.md",
  "operations/documentation-refactor-report.md",
  "runtime/ioi-daemon-runtime-api.md",
  "state/agentgres-api-and-object-model.md",
  "runtime/low-level-implementation-milestones.md",
]) {
  if (!index.includes(required)) {
    fail(`README.md must link ${required}.`);
  }
}

const sourceMap = fs.readFileSync(
  path.join(architectureRoot, "operations/source-of-truth-map.md"),
  "utf8",
);
for (const required of [
  "`prim:*`",
  "`scope:*`",
  "SDK, CLI, GUI, harness, benchmark, compositor boundaries",
  "Smarter-agent runtime loop",
  "Legacy Context Policy",
]) {
  if (!sourceMap.includes(required)) {
    fail(`operations/source-of-truth-map.md missing ${required}.`);
  }
}

const contradictionLog = fs.readFileSync(
  path.join(architectureRoot, "operations/documentation-contradiction-log.md"),
  "utf8",
);
for (const required of [
  "Split into primitive execution capabilities (`prim:*`) and authority scopes (`scope:*`)",
  "CLI vs daemon",
  "Agentgres role",
  "Swarm naming",
]) {
  if (!contradictionLog.includes(required)) {
    fail(`documentation-contradiction-log.md missing ${required}.`);
  }
}

if (failures.length > 0) {
  console.error("Architecture documentation check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Architecture documentation check passed.");
