#!/usr/bin/env node
// Read-only validator for the object-level canon-to-code delta. Only the
// explicit machine manifest may declare repository anchors and their roles;
// table prose cannot carry cut/stage delivery status or become a sequencer.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const defaultRepoRoot = path.resolve(path.dirname(scriptPath), "..");
const DELTA_FILE = "docs/architecture/_meta/canon-to-code-delta.md";
const ARCHITECTURE_ROOT = "docs/architecture";
const EVIDENCE_FORMAT = "ioi.canon_to_code_delta.machine_check.v2";
const OBJECT_ANCHOR_COVERAGE = new Set(["none", "partial"]);
const ANCHOR_ROLES = new Set(["implementation", "precedent"]);
const PROOF_STATUS_POINTER = "[work-item records](./work-items/README.md)";
const PROHIBITED_TABLE_STATUS_NARRATIVES = Object.freeze([
  /\b(?:merged|landed)\b/iu,
  /\bnot[- ]started\b/iu,
  /\b(?:implemented|built)\b/iu,
  /\bcurrent\s+(?:code|implementation|master|checkout|verified state)\b/iu,
  /\blive\s+(?:implementation|plane|route|path|journey|runtime|service|cohort|chain)\b/iu,
  /\b(?:planned|future|next)\s+(?:proof|build|implementation|stage|cut|slice)\b/iu,
  /\bm\d+(?:\.\d+)?\s+(?:is|are|remains?|merged|implemented|complete|built|live|held)\b/iu,
]);
const TABLE_HEADERS = Object.freeze([
  "Canonical object",
  "Canonical owner",
  "Durable form (target)",
  "Repository anchors (machine-verified)",
  "Anchor coverage (non-status)",
  "Authority crossing (contract relation)",
  "Owning application projection",
  "Proof/status routing",
]);

function splitTableRow(line) {
  if (!line.startsWith("|") || !line.endsWith("|")) return null;
  const cells = [];
  let cell = "";
  for (let index = 1; index < line.length - 1; index += 1) {
    const character = line[index];
    if (character === "|" && line[index - 1] !== "\\") {
      cells.push(cell.trim());
      cell = "";
    } else {
      cell += character;
    }
  }
  cells.push(cell.trim());
  return cells;
}

function isInside(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) && relative !== "..")
  );
}

function normalizeRepoPath(repoRoot, value) {
  const segments = typeof value === "string" ? value.split("/") : [];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    path.isAbsolute(value) ||
    value.includes("\\") ||
    segments.some(
      (segment) => segment === "" || segment === "." || segment === "..",
    )
  ) {
    return null;
  }
  const absolute = path.resolve(repoRoot, value);
  return isInside(repoRoot, absolute) ? absolute : null;
}

function renderedAnchorCell(anchors) {
  if (!Array.isArray(anchors)) return null;
  if (anchors.length === 0) return "none";
  if (
    anchors.some(
      (anchor) =>
        !anchor ||
        typeof anchor !== "object" ||
        Array.isArray(anchor) ||
        typeof anchor.path !== "string" ||
        typeof anchor.role !== "string",
    )
  ) {
    return null;
  }
  return anchors
    .map((anchor) => `\`${anchor.path}\` (\`${anchor.role}\`)`)
    .join("; ");
}

function parseManifest(source, errors) {
  const matches = [
    ...source.matchAll(
      /<!-- canon-to-code-delta-machine-check:v2\n([\s\S]*?)\n-->/gu,
    ),
  ];
  if (matches.length !== 1) {
    errors.push(
      `expected exactly one machine-check manifest, found ${matches.length}`,
    );
    return null;
  }
  try {
    return JSON.parse(matches[0][1]);
  } catch (error) {
    errors.push(`machine-check manifest is not valid JSON: ${error.message}`);
    return null;
  }
}

function parseDeltaTable(source, errors) {
  const lines = source.split(/\r?\n/u);
  const headerIndexes = [];
  for (let index = 0; index < lines.length; index += 1) {
    const cells = splitTableRow(lines[index]);
    if (cells?.join("\u0000") === TABLE_HEADERS.join("\u0000")) {
      headerIndexes.push(index);
    }
  }
  if (headerIndexes.length !== 1) {
    errors.push(
      `expected exactly one delta table, found ${headerIndexes.length}`,
    );
    return [];
  }

  const headerIndex = headerIndexes[0];
  const separator = splitTableRow(lines[headerIndex + 1] ?? "");
  if (
    separator?.length !== TABLE_HEADERS.length ||
    !separator.every((cell) => /^:?-{3,}:?$/u.test(cell))
  ) {
    errors.push("delta table has a missing or malformed separator row");
    return [];
  }

  const rows = [];
  for (let index = headerIndex + 2; index < lines.length; index += 1) {
    if (!lines[index].startsWith("|")) break;
    const cells = splitTableRow(lines[index]);
    if (cells?.length !== TABLE_HEADERS.length) {
      errors.push(
        `delta table line ${index + 1} has ${cells?.length ?? 0} cells; expected ${TABLE_HEADERS.length}`,
      );
      continue;
    }
    if (cells.some((cell) => cell.length === 0)) {
      errors.push(`delta table line ${index + 1} has an empty required cell`);
    }
    const objectMatch = /^`([^`]+)`/u.exec(cells[0]);
    if (!objectMatch) {
      errors.push(
        `delta table line ${index + 1} lacks a primary canonical-object identity`,
      );
      continue;
    }
    rows.push({ cells, line: index + 1, object: objectMatch[1] });
  }
  if (rows.length === 0) errors.push("delta table has no data rows");
  return rows;
}

export function validateCanonToCodeDelta({
  repoRoot = defaultRepoRoot,
  source,
} = {}) {
  const errors = [];
  const deltaPath = path.join(repoRoot, DELTA_FILE);
  let deltaSource = source;
  if (deltaSource === undefined) {
    try {
      deltaSource = fs.readFileSync(deltaPath, "utf8");
    } catch (error) {
      return {
        anchorCount: 0,
        errors: [`cannot read ${DELTA_FILE}: ${error.message}`],
        rowCount: 0,
      };
    }
  }

  const manifest = parseManifest(deltaSource, errors);
  const tableRows = parseDeltaTable(deltaSource, errors);
  const manifestRows = Array.isArray(manifest?.rows) ? manifest.rows : [];
  if (manifest && manifest.evidence_format !== EVIDENCE_FORMAT) {
    errors.push(
      `machine-check manifest has unknown evidence_format ${manifest.evidence_format}`,
    );
  }
  if (manifest && !Array.isArray(manifest.rows)) {
    errors.push("machine-check manifest rows must be an array");
  }
  if (manifestRows.length === 0) {
    errors.push("machine-check manifest has no required delta rows");
  }

  const rowsByObject = new Map();
  for (const row of tableRows) {
    if (rowsByObject.has(row.object)) {
      errors.push(
        `delta table line ${row.line} duplicates canonical-object identity ${row.object}`,
      );
    } else {
      rowsByObject.set(row.object, row);
    }
  }

  const seenIds = new Set();
  const seenManifestObjects = new Set();
  let anchorCount = 0;
  for (const record of manifestRows) {
    const label = typeof record?.id === "string" ? record.id : "<missing-id>";
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      errors.push("machine-check manifest contains a malformed row record");
      continue;
    }
    if (!/^delta-[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(record.id ?? "")) {
      errors.push(`${label} has a missing or malformed row identity`);
    }
    if (seenIds.has(record.id)) errors.push(`${label} duplicates row identity`);
    seenIds.add(record.id);
    if (typeof record.object !== "string" || record.object.length === 0) {
      errors.push(`${label} lacks canonical object`);
    }
    if (seenManifestObjects.has(record.object)) {
      errors.push(`${label} duplicates canonical object ${record.object}`);
    }
    seenManifestObjects.add(record.object);
    if (!OBJECT_ANCHOR_COVERAGE.has(record.coverage)) {
      errors.push(
        `${label} has unknown object-anchor coverage ${record.coverage}`,
      );
    }
    if (!Array.isArray(record.anchors)) {
      errors.push(`${label} anchors must be an array`);
      continue;
    }

    const row = rowsByObject.get(record.object);
    if (!row) {
      errors.push(`${label} requires missing delta row ${record.object}`);
    } else if (row.cells[4] !== record.coverage) {
      errors.push(
        `${label} manifest coverage ${record.coverage} disagrees with exact table coverage ${row.cells[4]}`,
      );
    }

    const seenAnchorPaths = new Set();
    let implementationAnchors = 0;
    for (const anchor of record.anchors) {
      anchorCount += 1;
      if (!anchor || typeof anchor !== "object" || Array.isArray(anchor)) {
        errors.push(`${label} contains a malformed code anchor`);
        continue;
      }
      if (!ANCHOR_ROLES.has(anchor.role)) {
        errors.push(
          `${label} anchor ${anchor.path ?? "<missing-path>"} has unknown role ${anchor.role}`,
        );
      }
      if (anchor.role === "implementation") implementationAnchors += 1;
      if (seenAnchorPaths.has(anchor.path)) {
        errors.push(`${label} duplicates code anchor ${anchor.path}`);
      }
      seenAnchorPaths.add(anchor.path);
      const absolute = normalizeRepoPath(repoRoot, anchor.path);
      if (!absolute) {
        errors.push(
          `${label} has invalid repo-relative code anchor ${anchor.path}`,
        );
      } else if (!fs.existsSync(absolute)) {
        errors.push(`${label} code anchor does not exist: ${anchor.path}`);
      } else if (!fs.statSync(absolute).isFile()) {
        errors.push(`${label} code anchor is not a file: ${anchor.path}`);
      }
    }
    if (record.coverage === "partial" && implementationAnchors === 0) {
      errors.push(`${label} is partial but has no implementation code anchor`);
    }
    if (record.coverage === "none" && implementationAnchors > 0) {
      errors.push(
        `${label} has no object anchor but claims an implementation code anchor`,
      );
    }

    const expectedAnchorCell = renderedAnchorCell(record.anchors);
    if (row && expectedAnchorCell && row.cells[3] !== expectedAnchorCell) {
      errors.push(
        `${label} table anchors do not exactly match the machine manifest`,
      );
    }
  }

  for (const row of tableRows) {
    if (!seenManifestObjects.has(row.object)) {
      errors.push(
        `delta table line ${row.line} has no machine row identity for ${row.object}`,
      );
    }

    const prohibitedNarrative = PROHIBITED_TABLE_STATUS_NARRATIVES.find(
      (pattern) => pattern.test(row.cells.join(" ")),
    );
    if (prohibitedNarrative) {
      errors.push(
        `delta table line ${row.line} contains prohibited live/merged implementation-status narrative`,
      );
    }
    if (row.cells[7] !== PROOF_STATUS_POINTER) {
      errors.push(
        `delta table line ${row.line} must route proof/status by work-item pointer only`,
      );
    }

    const ownerCell = row.cells[1];
    const links = [...ownerCell.matchAll(/\[[^\]]+\]\(([^)]+)\)/gu)];
    const residual = ownerCell
      .replace(/\[[^\]]+\]\([^)]+\)/gu, "")
      .replace(/[\s,]/gu, "");
    if (links.length === 0 || residual.length > 0) {
      errors.push(
        `delta table line ${row.line} has malformed canonical-owner links`,
      );
      continue;
    }
    const seenOwners = new Set();
    for (const match of links) {
      const target = match[1];
      if (seenOwners.has(target)) {
        errors.push(
          `delta table line ${row.line} duplicates canonical-owner link ${target}`,
        );
      }
      seenOwners.add(target);
      const pathPart = target.split("#", 1)[0];
      const absolute = path.resolve(path.dirname(deltaPath), pathPart);
      const architectureRoot = path.join(repoRoot, ARCHITECTURE_ROOT);
      if (
        path.isAbsolute(pathPart) ||
        !pathPart.endsWith(".md") ||
        !isInside(architectureRoot, absolute) ||
        !fs.existsSync(absolute) ||
        !fs.statSync(absolute).isFile()
      ) {
        errors.push(
          `delta table line ${row.line} has invalid canonical-owner link ${target}`,
        );
      }
    }
  }

  return { anchorCount, errors, rowCount: tableRows.length };
}

export function runCanonToCodeDeltaCheck(options) {
  const result = validateCanonToCodeDelta(options);
  if (result.errors.length > 0) {
    process.stderr.write(
      `canon-to-code delta check failed with ${result.errors.length} error(s):\n${result.errors
        .map((message) => `- ${message}`)
        .join("\n")}\n`,
    );
    return 1;
  }
  process.stdout.write(
    `canon-to-code delta check passed: ${result.rowCount} rows, ${result.anchorCount} explicit code anchors.\n`,
  );
  return 0;
}

if (path.resolve(process.argv[1] ?? "") === scriptPath) {
  process.exitCode = runCanonToCodeDeltaCheck();
}
