import fs from "node:fs";
import path from "node:path";

export const DOCTRINE_STATUSES = new Set([
  "canonical",
  "draft",
  "reference",
  "archived",
]);

export const IMPLEMENTATION_STATUS_TOKENS = new Set([
  "built",
  "partial",
  "planned",
  "speculative",
  "mixed",
]);

const METADATA_FIELD = /^[A-Z][A-Za-z ]+:/;
const RFC3986_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*$/;
const PATH_ROOTS = [
  ".github/",
  "apps/",
  "crates/",
  "docs/",
  "internal-docs/",
  "packages/",
  "scripts/",
];

function normalizeRel(root, file) {
  return path.relative(root, file).split(path.sep).join("/");
}

function headerLines(content) {
  const lines = content.split(/\r?\n/);
  const heading = lines.findIndex((line, index) => index > 0 && /^##\s+/.test(line));
  return lines.slice(0, heading < 0 ? Math.min(lines.length, 80) : heading);
}

function metadataValues(content, name) {
  const lines = headerLines(content);
  const prefix = `${name}:`;
  const values = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (!lines[index].startsWith(prefix)) continue;
    const parts = [lines[index].slice(prefix.length).trim()];
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      if (METADATA_FIELD.test(lines[cursor]) || /^##\s+/.test(lines[cursor])) break;
      if (!lines[cursor].trim()) break;
      parts.push(lines[cursor].trim());
    }
    values.push(parts.join(" ").trim());
  }
  return values;
}

function normalizedDoctrineStatus(value) {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

export function checkStatusMetadata(rel, content) {
  const failures = [];
  const doctrineValues = metadataValues(content, "Doctrine status");
  const implementationValues = metadataValues(content, "Implementation status");

  if (doctrineValues.length !== 1) {
    failures.push(`${rel} must declare exactly one Doctrine status in its metadata header.`);
  }
  if (implementationValues.length !== 1) {
    failures.push(`${rel} must declare exactly one Implementation status in its metadata header.`);
  }
  if (doctrineValues.length !== 1 || implementationValues.length !== 1) return failures;

  const doctrine = normalizedDoctrineStatus(doctrineValues[0]);
  if (!DOCTRINE_STATUSES.has(doctrine)) {
    failures.push(
      `${rel} has invalid Doctrine status ${JSON.stringify(doctrineValues[0])}; expected canonical, draft, reference, or archived.`,
    );
  }

  const implementation = implementationValues[0].trim().toLowerCase();
  if (doctrine === "archived" && /^n\/a(?:\b|\s|\()/i.test(implementation)) {
    return failures;
  }
  const token = implementation.match(/^([a-z]+)/)?.[1] ?? "";
  if (!IMPLEMENTATION_STATUS_TOKENS.has(token)) {
    failures.push(
      `${rel} has invalid Implementation status ${JSON.stringify(implementationValues[0])}; expected a leading built, partial, planned, speculative, or mixed token${doctrine === "archived" ? ", or n/a for archived doctrine" : ""}.`,
    );
  }
  return failures;
}

function implementationRefLines(content) {
  const lines = headerLines(content);
  const start = lines.findIndex((line) => /^Implementation refs:\s*$/.test(line));
  if (start < 0) return [];
  const refs = [];
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (METADATA_FIELD.test(line) || /^##\s+/.test(line) || !line.trim()) break;
    refs.push({ line, lineNumber: index + 1 });
  }
  return refs;
}

function historicalEvidenceRef(line, candidate) {
  return (
    /(?:^|[/_-])archive(?:d)?(?:[/_.-]|$)|(?:^|[/_-])histor(?:y|ical)(?:[/_.-]|$)|(?:^|[/_-])evidence(?:[/_.-]|$)/i.test(candidate) ||
    /\b(?:archive|archived|historical|history|evidence-only|evidence ref|retired)\b/i.test(line)
  );
}

function pathLookingRef(candidate) {
  if (!candidate || candidate.includes("://")) return false;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(candidate)) return false;
  if (candidate.startsWith("/")) return false;
  return (
    candidate.startsWith("./") ||
    candidate.startsWith("../") ||
    PATH_ROOTS.some((prefix) => candidate.startsWith(prefix))
  );
}

function cleanPathRef(candidate) {
  return candidate
    .replace(/^<|>$/g, "")
    .split("#")[0]
    .replace(/:(?:L)?\d+(?::\d+)?$/, "")
    .replace(/[),.;]+$/, "");
}

function staticGlobPrefix(candidate) {
  const glob = candidate.search(/[?*[\]{}]/);
  if (glob < 0) return candidate;
  const prefix = candidate.slice(0, glob);
  return prefix.endsWith("/") ? prefix : path.dirname(prefix);
}

export function checkImplementationRefs({ root, file, rel, content }) {
  const failures = [];
  for (const { line, lineNumber } of implementationRefLines(content)) {
    const inline = [...line.matchAll(/`([^`]+)`/g)].map((match) => match[1].trim());
    const candidates = inline.length > 0
      ? inline
      : [line.replace(/^\s*[-*]\s*/, "").trim()];
    for (const rawCandidate of candidates) {
      const candidate = cleanPathRef(rawCandidate);
      if (!pathLookingRef(candidate) || historicalEvidenceRef(line, candidate)) continue;
      const base = candidate.startsWith("./") || candidate.startsWith("../")
        ? path.dirname(file)
        : root;
      const resolved = path.resolve(base, staticGlobPrefix(candidate));
      if (!resolved.startsWith(`${root}${path.sep}`) && resolved !== root) {
        failures.push(`${rel}:${lineNumber} Implementation ref escapes the repository: ${rawCandidate}.`);
      } else if (!fs.existsSync(resolved)) {
        failures.push(`${rel}:${lineNumber} has missing live Implementation ref: ${rawCandidate}.`);
      }
    }
  }
  return failures;
}

function fencedBlocks(content) {
  const blocks = [];
  const lines = content.split(/\r?\n/);
  let active = null;
  for (let index = 0; index < lines.length; index += 1) {
    const opening = lines[index].match(/^```([A-Za-z0-9_-]*)\s*$/);
    if (!active && opening) {
      active = { language: opening[1].toLowerCase(), startLine: index + 2, lines: [] };
      continue;
    }
    if (active && /^```\s*$/.test(lines[index])) {
      blocks.push({ ...active, content: active.lines.join("\n") });
      active = null;
      continue;
    }
    if (active) active.lines.push(lines[index]);
  }
  return blocks;
}

function duplicateValues(entries, label, rel) {
  const failures = [];
  const first = new Map();
  for (const entry of entries) {
    if (first.has(entry.value)) {
      failures.push(
        `${rel}:${entry.line} duplicates ${label} ${entry.value} first declared at line ${first.get(entry.value)}.`,
      );
    } else {
      first.set(entry.value, entry.line);
    }
  }
  return failures;
}

export function checkOwningRegistryDuplicates(rel, content) {
  const failures = [];
  const blocks = fencedBlocks(content).filter(({ language }) =>
    language === "yaml" || language === "yml" || language === "json"
  );

  if (rel === "docs/architecture/foundations/common-objects-and-envelopes.md") {
    const declarations = [];
    for (const block of blocks) {
      block.lines.forEach((line, index) => {
        const match = line.match(/^([A-Z][A-Za-z0-9]*(?:Envelope|Receipt|Event|Manifest|Profile|Contract|Object|Record)):\s*$/);
        if (match) declarations.push({ value: match[1], line: block.startLine + index });
      });
    }
    failures.push(...duplicateValues(declarations, "canonical object declaration", rel));
  }

  if (rel === "docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md") {
    const receiptNames = [];
    const receiptTypes = [];
    for (const block of blocks) {
      block.lines.forEach((line, index) => {
        const name = line.match(/^([A-Z][A-Za-z0-9]*Receipt(?:Envelope|Bundle)?):\s*$/);
        if (name) receiptNames.push({ value: name[1], line: block.startLine + index });
        const type = line.match(/^\s*(?:receipt_type:|"receipt_type"\s*:)\s*["']?([a-z][a-z0-9_]*)["']?\s*[,#]?\s*$/);
        if (type) receiptTypes.push({ value: type[1], line: block.startLine + index });
      });
    }
    failures.push(...duplicateValues(receiptNames, "canonical receipt declaration", rel));
    failures.push(...duplicateValues(receiptTypes, "canonical receipt_type", rel));
  }

  if (rel === "docs/architecture/foundations/canonical-enums.md") {
    const declarations = [];
    content.split(/\r?\n/).forEach((line, index) => {
      const heading = line.match(/^#{2,6}\s+.*\(`([a-z][a-z0-9_]*)`\)\s*$/);
      if (heading) declarations.push({ value: heading[1], line: index + 1 });
    });
    failures.push(...duplicateValues(declarations, "canonical enum declaration", rel));
  }
  return failures;
}

function schemaIdentityRecord(file, content) {
  if (file.endsWith(".json")) {
    let value;
    try {
      value = JSON.parse(content);
    } catch (error) {
      return { parseFailure: `${file} is invalid JSON: ${error.message}` };
    }
    return {
      identity: value.$id ?? value.schemaId ?? value.schema_id ?? value.id ?? null,
      version: value.schemaVersion ?? value.schema_version ?? value.version ?? null,
    };
  }
  const identity = content.match(/^\s*(?:\$id|schemaId|schema_id|id):\s*["']?([^\s"']+)/m)?.[1] ?? null;
  const version = content.match(/^\s*(?:schemaVersion|schema_version|version):\s*["']?([^\s"']+)/m)?.[1] ?? null;
  return { identity, version };
}

export function checkSchemaIdentities(schemaFiles, display = (file) => file) {
  const failures = [];
  const first = new Map();
  for (const file of schemaFiles) {
    const record = schemaIdentityRecord(file, fs.readFileSync(file, "utf8"));
    if (record.parseFailure) {
      failures.push(record.parseFailure);
      continue;
    }
    if (!record.identity && !record.version) continue;
    const key = record.identity && record.version
      ? `${record.identity}@${record.version}`
      : record.identity ?? record.version;
    if (first.has(key)) {
      failures.push(
        `${display(file)} duplicates schema identity/version ${key} first declared by ${display(first.get(key))}.`,
      );
    } else {
      first.set(key, file);
    }
  }
  return failures;
}

function commonIdSchemes(content) {
  const start = content.indexOf("## Common ID Conventions");
  const end = content.indexOf("## Capability and Authority Tiers", start);
  if (start < 0 || end < 0) return null;
  const schemes = new Set();
  for (const match of content.slice(start, end).matchAll(/^([A-Za-z][A-Za-z0-9+._-]*):\/\//gm)) {
    schemes.add(match[1]);
  }
  return schemes;
}

export function checkSchemeRegistry({
  commonObjectsContent,
  aliasRegistryContent,
  machineSchemaFiles = [],
  display = (file) => file,
}) {
  const failures = [];
  const schemes = commonIdSchemes(commonObjectsContent);
  if (!schemes) return ["common-objects-and-envelopes.md is missing its bounded Common ID Conventions registry."];

  let registry;
  try {
    registry = JSON.parse(aliasRegistryContent);
  } catch (error) {
    return [`legacy ref-scheme alias registry is invalid JSON: ${error.message}`];
  }
  if (registry.readPolicy !== "read_only" || registry.writePolicy !== "forbid_legacy_schemes") {
    failures.push("legacy ref-scheme alias registry must declare read_only and forbid_legacy_schemes policies.");
  }
  const aliases = registry.aliases ?? {};
  for (const scheme of schemes) {
    if (RFC3986_SCHEME.test(scheme)) continue;
    const canonical = aliases[scheme];
    if (!canonical) {
      failures.push(`non-RFC3986 shared ref scheme ${scheme} is missing from the read-side legacy alias registry.`);
    } else if (!RFC3986_SCHEME.test(canonical)) {
      failures.push(`legacy ref scheme ${scheme} maps to invalid canonical scheme ${canonical}.`);
    }
  }
  for (const [legacy, canonical] of Object.entries(aliases)) {
    if (RFC3986_SCHEME.test(legacy)) {
      failures.push(`legacy alias key ${legacy} is already RFC3986-valid and must not be a legacy alias.`);
    }
    if (!schemes.has(legacy)) {
      failures.push(`legacy alias ${legacy} is not declared in the shared Common ID Conventions registry.`);
    }
    if (!RFC3986_SCHEME.test(canonical)) {
      failures.push(`legacy ref scheme ${legacy} maps to invalid canonical scheme ${canonical}.`);
    }
  }

  const invalid = new Set(Object.keys(aliases));
  for (const file of machineSchemaFiles) {
    if (display(file).endsWith("legacy-ref-scheme-aliases.json")) continue;
    const content = fs.readFileSync(file, "utf8");
    for (const match of content.matchAll(/\b([A-Za-z][A-Za-z0-9+._-]*):\/\//g)) {
      if (invalid.has(match[1])) {
        failures.push(`${display(file)} writes read-only legacy ref scheme ${match[1]}:// in a machine schema.`);
      }
    }
  }
  return failures;
}

function stripFencedCode(content) {
  return content.replace(/^```[^\n]*\n[\s\S]*?^```\s*$/gm, "");
}

export function checkRecencyPrecedence(rel, content) {
  const doctrine = metadataValues(content, "Doctrine status");
  const status = doctrine.length === 1 ? normalizedDoctrineStatus(doctrine[0]) : "";
  if (status !== "canonical" && status !== "draft") return [];
  const failures = [];
  const paragraphs = stripFencedCode(content).split(/\n\s*\n/);
  for (const paragraph of paragraphs) {
    const text = paragraph.replace(/\s+/g, " ").trim();
    if (!/(?:conflict|precedence|authority|owner|doctrine|canonical|disagree)/i.test(text)) continue;
    if (/(?:do(?:es)? not|must not|never|cannot|not choose|doesn't)\b.{0,100}\b(?:newer|newest|latest|most recent|recency|publication date)/i.test(text) ||
        /\b(?:newer|newest|latest|most recent|recency|publication date)\b.{0,100}\b(?:does not|do not|must not|never|cannot|doesn't)\b/i.test(text)) {
      continue;
    }
    if (/(?:prefer|choose|select|resolve|determine|outrank|wins?)\b.{0,120}\b(?:newer|newest|latest|most recent|recency|publication date)\b/i.test(text) ||
        /\b(?:newer|newest|latest|most recent|recency|publication date)\b.{0,120}\b(?:prefer|choose|select|resolve|determine|outrank|wins?)\b/i.test(text)) {
      const line = content.slice(0, content.indexOf(paragraph)).split(/\r?\n/).length;
      failures.push(`${rel}:${line} uses recency to resolve canonical precedence.`);
    }
  }
  return failures;
}

function markdownLinks(cell) {
  return [...cell.matchAll(/\[[^\]]+\]\(([^)#]+)(?:#[^)]+)?\)/g)].map((match) => match[1]);
}

function sourceMapRows(content) {
  const start = content.indexOf("## Subject Ownership");
  if (start < 0) return [];
  const nextHeading = content.indexOf("\n## ", start + 3);
  const section = content.slice(start, nextHeading < 0 ? content.length : nextHeading);
  return section.split(/\r?\n/).flatMap((line, index) => {
    if (!/^\|/.test(line) || /^\|\s*(?:Subject|---)/.test(line)) return [];
    const cells = line.slice(1, -1).split("|").map((cell) => cell.trim());
    if (cells.length < 2) return [];
    return [{ subject: cells[0].replace(/\s+/g, " "), ownerCell: cells[1], line: index + 1 }];
  });
}

export function checkOwnerMetadata({ root, sourceMapFile, sourceMapContent, contentsByFile }) {
  const failures = [];
  const firstBySubject = new Map();
  for (const row of sourceMapRows(sourceMapContent)) {
    const ownerFiles = markdownLinks(row.ownerCell)
      .map((target) => path.resolve(path.dirname(sourceMapFile), target))
      .filter((file) => file.endsWith(".md"));
    const ownerKey = [...new Set(ownerFiles)].sort().join("|");
    if (firstBySubject.has(row.subject) && firstBySubject.get(row.subject).ownerKey !== ownerKey) {
      failures.push(
        `${normalizeRel(root, sourceMapFile)} has conflicting owner rows for exact subject ${JSON.stringify(row.subject)}.`,
      );
    } else if (!firstBySubject.has(row.subject)) {
      firstBySubject.set(row.subject, { ownerKey, line: row.line });
    }

    for (const ownerFile of ownerFiles) {
      const content = contentsByFile.get(ownerFile);
      if (!content) continue;
      const ownerValues = metadataValues(content, "Canonical owner");
      if (ownerValues.length === 0) {
        continue;
      }
      if (ownerValues.length > 1) {
        failures.push(`${normalizeRel(root, ownerFile)} declares conflicting Canonical owner metadata in its header.`);
        continue;
      }
      const ownerValue = ownerValues[0];
      if (/^none\b/i.test(ownerValue)) {
        failures.push(`${normalizeRel(root, ownerFile)} is mapped as an owner but its header declares Canonical owner: none.`);
        continue;
      }
      if (/\bthis file\b/i.test(ownerValue)) continue;
      const redirect = markdownLinks(ownerValue)[0] ?? ownerValue.match(/`([^`]+\.md)`/)?.[1];
      if (!redirect) continue;
      const resolved = path.resolve(path.dirname(ownerFile), redirect);
      if (resolved !== ownerFile && !ownerFiles.includes(resolved)) {
        failures.push(
          `${normalizeRel(root, ownerFile)} is mapped as an owner but its header redirects canonical ownership to ${normalizeRel(root, resolved)}.`,
        );
      }
    }
  }
  return failures;
}

function implementationMatrixRows(content) {
  return content.split(/\r?\n/u).flatMap((line, index) => {
    if (!line.startsWith("| `")) return [];
    const cells = line
      .split("|")
      .slice(1, -1)
      .map((cell) => cell.trim());
    return cells.length === 6
      ? [{ cells, line: index + 1 }]
      : [];
  });
}

export function checkImplementationMatrixEvidence({
  root,
  matrixFile,
  content,
}) {
  const rel = normalizeRel(root, matrixFile);
  const failures = [];
  for (const stale of [
    ["deleted JavaScript daemon path", /packages\/runtime-daemon/u],
    ["deleted Step/Module bridge path", /ioi[_-]step_module_bridge/u],
    ["stale live JavaScript-remains claim", /\b(?:JS|JavaScript)\s+remains?\b/iu],
  ]) {
    if (stale[1].test(content)) {
      failures.push(`${rel} contains ${stale[0]}.`);
    }
  }

  const rows = implementationMatrixRows(content);
  if (rows.some(({ cells }) => cells[0].startsWith("`RuntimeDaemonCore"))) {
    failures.push(
      `${rel} carries RuntimeDaemonCore migration-mechanism rows; keep migration sequencing/status in the non-doctrinal migration matrix.`,
    );
  }
  for (const { cells, line } of rows) {
    for (const rawCandidate of [...cells[4].matchAll(/`([^`]+)`/gu)].map(
      (match) => match[1],
    )) {
      const candidate = cleanPathRef(rawCandidate);
      if (!pathLookingRef(candidate)) continue;
      const resolved = path.resolve(root, staticGlobPrefix(candidate));
      if (
        (!resolved.startsWith(`${root}${path.sep}`) && resolved !== root) ||
        !fs.existsSync(resolved)
      ) {
        failures.push(
          `${rel}:${line} has missing current-evidence path: ${rawCandidate}.`,
        );
      }
    }
  }

  const byConcept = new Map(rows.map(({ cells }) => [cells[0], cells]));
  const requiredOwners = new Map([
    [
      "`ModelCapabilityTokenControl`",
      ["model-router/doctrine.md", "wallet-network/doctrine.md"],
    ],
    [
      "`ModelVaultControl`",
      [
        "model-router/doctrine.md",
        "wallet-network/doctrine.md",
        "daemon-runtime/private-workspace-ctee.md",
      ],
    ],
    [
      "`RuntimeThreadMemoryControl`",
      [
        "daemon-runtime/doctrine.md",
        "daemon-runtime/portable-memory-vault.md",
        "agentgres/doctrine.md",
      ],
    ],
    [
      "`RuntimeManagedSessionControl`",
      ["daemon-runtime/doctrine.md", "hypervisor/core-clients-surfaces.md"],
    ],
    [
      "`RuntimeWorkflowEditControl`",
      ["daemon-runtime/doctrine.md", "hypervisor/core-clients-surfaces.md"],
    ],
    [
      "`RuntimeSkillHookRegistryControl`",
      [
        "foundations/common-objects-and-envelopes.md",
        "daemon-runtime/doctrine.md",
        "connectors-tools/contracts.md",
      ],
    ],
  ]);
  for (const [concept, ownerFragments] of requiredOwners) {
    const row = byConcept.get(concept);
    if (!row) {
      failures.push(`${rel} is missing owner-audited row ${concept}.`);
      continue;
    }
    for (const fragment of ownerFragments) {
      if (!row[1].includes(fragment)) {
        failures.push(`${rel} ${concept} is missing owner boundary ${fragment}.`);
      }
    }
  }

  const migration = byConcept.get("`HypervisorKernelSubstrateMigration`");
  if (
    !migration ||
    !migration[1].includes(
      "hypervisor-kernel-substrate-migration-matrix.md",
    ) ||
    !/non-doctrinal migration\/status evidence/iu.test(migration[2]) ||
    !/may not define daemon doctrine/iu.test(migration[3])
  ) {
    failures.push(
      `${rel} must classify HypervisorKernelSubstrateMigration under the explicitly non-doctrinal migration/status matrix, not daemon doctrine.`,
    );
  }

  return failures;
}

function allSchemaFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(dir, entry.name);
    if (entry.isDirectory()) return allSchemaFiles(absolute);
    return /\.(?:json|ya?ml)$/.test(entry.name) ? [absolute] : [];
  });
}

export function checkArchitectureIntegrity({ root, architectureRoot, markdownFiles }) {
  const failures = [];
  const contentsByFile = new Map(
    markdownFiles.map((file) => [file, fs.readFileSync(file, "utf8")]),
  );
  for (const [file, content] of contentsByFile) {
    const rel = normalizeRel(root, file);
    failures.push(...checkStatusMetadata(rel, content));
    failures.push(...checkImplementationRefs({ root, file, rel, content }));
    failures.push(...checkOwningRegistryDuplicates(rel, content));
    failures.push(...checkRecencyPrecedence(rel, content));
  }

  const schemaRoot = path.join(architectureRoot, "_meta/schemas");
  const schemaFiles = allSchemaFiles(schemaRoot);
  const schemaDefinitionFiles = schemaFiles.filter(
    (file) => !normalizeRel(schemaRoot, file).startsWith("fixtures/"),
  );
  failures.push(...checkSchemaIdentities(schemaDefinitionFiles, (file) => normalizeRel(root, file)));

  const commonObjectsFile = path.join(architectureRoot, "foundations/common-objects-and-envelopes.md");
  const aliasRegistryFile = path.join(schemaRoot, "legacy-ref-scheme-aliases.json");
  if (!fs.existsSync(aliasRegistryFile)) {
    failures.push("docs/architecture/_meta/schemas/legacy-ref-scheme-aliases.json is required for read-side legacy ref schemes.");
  } else {
    failures.push(...checkSchemeRegistry({
      commonObjectsContent: contentsByFile.get(commonObjectsFile) ?? "",
      aliasRegistryContent: fs.readFileSync(aliasRegistryFile, "utf8"),
      machineSchemaFiles: schemaFiles,
      display: (file) => normalizeRel(root, file),
    }));
  }

  const sourceMapFile = path.join(architectureRoot, "_meta/source-of-truth-map.md");
  failures.push(...checkOwnerMetadata({
    root,
    sourceMapFile,
    sourceMapContent: contentsByFile.get(sourceMapFile) ?? "",
    contentsByFile,
  }));
  const implementationMatrixFile = path.join(
    architectureRoot,
    "_meta/implementation-matrix.md",
  );
  failures.push(
    ...checkImplementationMatrixEvidence({
      root,
      matrixFile: implementationMatrixFile,
      content: contentsByFile.get(implementationMatrixFile) ?? "",
    }),
  );
  return failures;
}
