#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const architectureRoot = path.join(root, "docs/architecture");
const internalDocsRoot = path.join(root, "internal-docs");
const failures = [];

function allMarkdownFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const absolute = path.join(dir, entry.name);
    if (entry.isDirectory()) return allMarkdownFiles(absolute);
    return entry.name.endsWith(".md") ? [absolute] : [];
  });
}

function allFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const absolute = path.join(dir, entry.name);
    if (entry.isDirectory()) return allFiles(absolute);
    return [absolute];
  });
}

function relative(file) {
  return path.relative(root, file);
}

function isImportedConsensusCorpus(file) {
  return relative(file).startsWith("internal-docs/architecture/protocols/aft/");
}

function isGeneratedArchitectureArtifact(file) {
  const rel = relative(file);
  return (
    rel.includes("/states/") ||
    /_TTrace_/.test(rel) ||
    /\.(st|fp|bin|aux|log|out|pdf)$/.test(rel)
  );
}

function fail(message) {
  failures.push(message);
}

function trackedFilesUnder(...paths) {
  const result = spawnSync("git", ["ls-files", ...paths], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    fail(`Unable to inspect tracked docs/formal files: ${result.stderr || result.stdout}`);
    return [];
  }
  return result.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && fs.existsSync(path.join(root, line)));
}

const markdownFiles = allMarkdownFiles(architectureRoot);
const internalMarkdownFiles = fs.existsSync(internalDocsRoot)
  ? allMarkdownFiles(internalDocsRoot)
  : [];
for (const file of allFiles(architectureRoot)) {
  if (isGeneratedArchitectureArtifact(file)) {
    fail(`${relative(file)} is generated proof/evidence output and must live outside docs/architecture/.`);
  }
}

for (const file of trackedFilesUnder("docs/formal", "docs/formal-artifacts")) {
  fail(`${file} is tracked under public docs formal output; use internal-docs/ or .internal/formal-cache/.`);
}

for (const file of internalMarkdownFiles) {
  const content = fs.readFileSync(file, "utf8");
  if (/^Status:\s*canonical\b/im.test(content)) {
    fail(`${relative(file)} declares canonical status inside internal-docs/.`);
  }
  if (/^Canonical owner:/im.test(content)) {
    fail(`${relative(file)} declares a canonical owner inside internal-docs/.`);
  }
}
const rootMarkdownFiles = fs
  .readdirSync(architectureRoot, { withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
  .map((entry) => entry.name);
const allowedRootMarkdown = new Set(["README.md", "START_HERE.md"]);
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
  if (rel.includes("_meta/changelog/")) {
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
  "_meta/source-of-truth-map.md",
  "../decisions/README.md",
  "_meta/doc-classes.md",
  "components/daemon-runtime/api.md",
  "components/agentgres/api-object-model.md",
  "components/daemon-runtime/events-receipts-delivery-bundles.md",
  "IOI daemon = hypervisor/control plane for autonomous execution",
  "Hypervisor App/Web/CLI-headless = first-class clients over Hypervisor Core",
  "Hypervisor Workbench/Automations/Foundry = application surfaces over Hypervisor Core",
  "IOI Authority Gateway = compatibility adapter profile",
  "physical-action-safety.md",
]) {
  if (!index.includes(required)) {
    fail(`README.md must link ${required}.`);
  }
}
if (
  /aiagent\.xyz\s*\|\s*Canonical Web4 marketplace for portable digital workers/.test(
    index,
  )
) {
  fail(
    "README.md must describe aiagent.xyz as ontology-bound digital and embodied workers, not portable digital workers only.",
  );
}
if (!index.includes("ontology-bound digital and embodied workers")) {
  fail("README.md must describe aiagent.xyz as ontology-bound digital and embodied workers.");
}

const sourceMap = fs.readFileSync(
  path.join(architectureRoot, "_meta/source-of-truth-map.md"),
  "utf8",
);
for (const required of [
  "`prim:*`",
  "`scope:*`",
  "Hypervisor App, Hypervisor Web, and Hypervisor CLI/headless are",
  "Hypervisor Workbench is the live code/systems surface term",
  "adapter targets, not Hypervisor's product identity",
  "IOI Authority Gateway is the daemon sidecar/compatibility profile",
  "the daemon authorizes anything",
  "PhysicalActionPolicy",
  "ActuatorCommandReceipt",
  "SDK, CLI/headless, GUI, harness, benchmark, compositor, and agent-harness-adapter boundaries",
  "Smarter-agent runtime loop",
  "Decision History Policy",
]) {
  if (!sourceMap.includes(required)) {
    fail(`_meta/source-of-truth-map.md missing ${required}.`);
  }
}

const decisionsIndex = fs.readFileSync(path.join(root, "docs/decisions/README.md"), "utf8");
for (const required of [
  "ADR 0002",
  "ADR 0003",
  "ADR 0004",
  "ADR 0005",
  "ADR 0006",
  "ADR 0007",
  "ADR 0008",
  "ADR 0009",
  "ADR 0010",
  "ADR 0011",
  "ADR 0012",
  "ADR 0013",
]) {
  if (!decisionsIndex.includes(required)) {
    fail(`docs/decisions/README.md missing ${required}.`);
  }
}

const vocabulary = fs.readFileSync(
  path.join(architectureRoot, "_meta/vocabulary.md"),
  "utf8",
);
for (const required of [
  "`HypervisorWorkbench`",
  "`IOIAuthorityGateway`",
  "`HypervisorGuard`",
  "`CompatibilityAdapter`",
  "`HypervisorAppShell`",
  "`GuestWorkload`",
  "`TrustAuditSubstrate`",
  "`PhysicalActionPolicy`",
  "`SafetyEnvelope`",
  "`EmergencyStopAuthority`",
  "`ActuatorCommandReceipt`",
]) {
  if (!vocabulary.includes(required)) {
    fail(`_meta/vocabulary.md missing ${required}.`);
  }
}

const aiagentBroadLaborDocs = [
  {
    rel: "domains/aiagent/worker-marketplace.md",
    required: [
      "ontology-bound digital and embodied workers",
      "DigitalWorkerOntology",
      "VerticalOntologyPacks",
      "IntegrationSurfaces",
      "ManagedWorkerInstance",
    ],
  },
  {
    rel: "domains/aiagent/digital-worker-ontology.md",
    required: [
      "DigitalWorkerOntology",
      "VerticalOntologyPack",
      "IntegrationSurface",
      "ManagedWorkerInstance",
      "physical-action",
    ],
  },
  {
    rel: "domains/aiagent/vertical-ontology-packs.md",
    required: [
      "VerticalOntologyPack",
      "DigitalWorkerOntology",
      "safety envelopes",
      "forbidden actions",
      "receipt schemas",
    ],
  },
  {
    rel: "domains/aiagent/integration-surface-taxonomy.md",
    required: [
      "IntegrationSurface",
      "robotics_physical",
      "embodied_humanoid",
      "voice_sms",
      "authority scopes",
    ],
  },
  {
    rel: "domains/aiagent/managed-worker-instance-lifecycle.md",
    required: [
      "ManagedWorkerInstanceLifecycle",
      "payment",
      "archive",
      "restore",
      "Agentgres",
    ],
  },
  {
    rel: "domains/aiagent/managed-agent-console-contract.md",
    required: [
      "Managed Agent Console",
      "ManagedWorkerInstance",
      "projection",
      "wallet.network",
      "Agentgres",
    ],
  },
];

for (const { rel, required } of aiagentBroadLaborDocs) {
  const file = path.join(architectureRoot, rel);
  if (!fs.existsSync(file)) {
    fail(`aiagent broad-labor canon missing ${rel}.`);
    continue;
  }
  const content = fs.readFileSync(file, "utf8");
  for (const phrase of required) {
    if (!content.includes(phrase)) {
      fail(`${rel} missing aiagent broad-labor phrase: ${phrase}.`);
    }
  }
}

for (const [rel, content] of [
  ["_meta/source-of-truth-map.md", sourceMap],
  ["_meta/implementation-matrix.md", fs.readFileSync(path.join(architectureRoot, "_meta/implementation-matrix.md"), "utf8")],
  ["_meta/vocabulary.md", vocabulary],
]) {
  for (const phrase of [
    "DigitalWorkerOntology",
    "VerticalOntologyPack",
    "IntegrationSurface",
    "ManagedWorkerInstance",
  ]) {
    if (!content.includes(phrase)) {
      fail(`${rel} missing aiagent broad-labor concept: ${phrase}.`);
    }
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
