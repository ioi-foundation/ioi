#!/usr/bin/env node
// The sole implementation sequencer is intentionally machine-local and
// gitignored. Its approved stateless rewrite is retained as a tracked,
// hash-bound work record so a clean checkout can validate the review artifact
// without pretending that the private guide itself is present.
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const defaultRepoRoot = path.resolve(path.dirname(scriptPath), "..");
export const GUIDE_FILE =
  "internal-docs/implementation/ioi-target-end-state-master-implementation-guide.md";
export const GUIDE_PATCH_MANIFEST_FILE =
  "docs/architecture/_meta/reconciliation/stateless-master-guide.v1.json";
export const GUIDE_PATCH_FILE =
  "docs/architecture/_meta/reconciliation/stateless-master-guide.v1.patch";

const GUIDE_PATCH_FORMAT = "ioi.program.stateless_master_guide_patch.v1";
const GUIDE_BASE_SHA256 =
  "291be5dce69c71bd09abc029450ef79723a3346968bd2e78b6f31f1744aa56e0";
const SHA256 = /^[a-f0-9]{64}$/u;
const FORBIDDEN_LIVE_STATUS_PATTERNS = Object.freeze([
  [/^Status:/mu, "contains a live Status: field"],
  [
    /^Current implementation evidence\b/mu,
    "contains a current implementation-evidence narrative",
  ],
  [
    /^Last reconciled against the live worktree\b/mu,
    "contains a dated live-worktree baseline",
  ],
  [
    /^## 5\. Current Starting Truth\b/mu,
    "contains the former current-starting-truth section",
  ],
  [
    /^## 16\. Initial Program State\b/mu,
    "contains the former initial-program-state snapshot",
  ],
  [
    /^\s*(?:[-*]\s+)?(?:\*\*)?Current (?:state|status)(?:\*\*)?\s*:/imu,
    "contains an ordinary current-state narrative",
  ],
  [
    /\bM(?:[0-9]|1[0-4])\b(?:\s+stage)?\s+(?:is|remains|stays|became|continues to be)\s+(?:currently\s+)?(?:active|verified|pending|scoped|blocked|evidence[_ -]?ready|superseded|rejected|complete(?:d)?)\b/imu,
    "contains an ordinary stage-state narrative",
  ],
  [
    /\bImplementation\s+(?:has\s+)?(?:merged|landed)\s+(?:in|via)\s+(?:PR|pull request)\s*#?\d+\b/imu,
    "contains a merged-implementation PR narrative",
  ],
  [
    /\b(?:Implementation|Canon absorption|Track\s+\d+)\s+(?:is|was)\s+complete\b/imu,
    "contains a live implementation-completion narrative",
  ],
  [
    /`[^`\n]+`\s+exists\s+and\s+[^.\n]{0,120}\bconsumes\s+it\b/imu,
    "contains a live code-existence and consumer-adoption narrative",
  ],
  [
    /\bbuilt\s+effect-fence\s+v\d+\b/imu,
    "contains a live built-contract narrative",
  ],
]);

function sha256(source) {
  return createHash("sha256").update(source).digest("hex");
}

function readOptional(repoRoot, relativePath, provided) {
  if (provided !== undefined) return provided;
  const absolutePath = path.join(repoRoot, relativePath);
  return fs.existsSync(absolutePath)
    ? fs.readFileSync(absolutePath, "utf8")
    : null;
}

function parseManifest(source, errors) {
  if (source === null) {
    errors.push(
      `missing tracked guide-patch manifest ${GUIDE_PATCH_MANIFEST_FILE}`,
    );
    return null;
  }
  try {
    return JSON.parse(source);
  } catch (error) {
    errors.push(`guide-patch manifest is not valid JSON: ${error.message}`);
    return null;
  }
}

function materializeFullContextPatch(patchSource) {
  if (!patchSource.endsWith("\n")) {
    throw new Error("tracked guide patch must end with a newline");
  }
  const patchLines = patchSource.slice(0, -1).split("\n");
  const header = patchLines[2] ?? "";
  const match = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/u.exec(header);
  if (!match) throw new Error(`unexpected unified-diff hunk header: ${header}`);
  const oldStart = Number(match[1]);
  const oldCount = Number(match[2] ?? "1");
  const newStart = Number(match[3]);
  const newCount = Number(match[4] ?? "1");
  if (oldStart !== 1 || newStart !== 1) {
    throw new Error(
      "guide patch must begin both full-file representations at line 1",
    );
  }

  const baseLines = [];
  const resultLines = [];
  let changedLines = 0;
  for (const line of patchLines.slice(3)) {
    if (line.startsWith("@@ ")) {
      throw new Error("guide patch must contain exactly one full-context hunk");
    }
    if (line === "\\ No newline at end of file") {
      throw new Error("guide patch base and result must end with newlines");
    }
    const prefix = line[0];
    const content = line.slice(1);
    if (prefix === " ") {
      baseLines.push(content);
      resultLines.push(content);
    } else if (prefix === "-") {
      baseLines.push(content);
      changedLines += 1;
    } else if (prefix === "+") {
      resultLines.push(content);
      changedLines += 1;
    } else {
      throw new Error(`unexpected unified-diff body line: ${line}`);
    }
  }
  if (baseLines.length !== oldCount || resultLines.length !== newCount) {
    throw new Error(
      `full-context hunk count mismatch (old ${baseLines.length}/${oldCount}, new ${resultLines.length}/${newCount})`,
    );
  }
  if (changedLines === 0)
    throw new Error("guide patch contains no changed lines");
  return {
    baseSource: `${baseLines.join("\n")}\n`,
    resultSource: `${resultLines.join("\n")}\n`,
  };
}

export function validateTrackedGuidePatch({
  repoRoot = defaultRepoRoot,
  manifestSource,
  patchSource,
  resultSource,
} = {}) {
  const errors = [];
  const manifestText = readOptional(
    repoRoot,
    GUIDE_PATCH_MANIFEST_FILE,
    manifestSource,
  );
  const patchText = readOptional(repoRoot, GUIDE_PATCH_FILE, patchSource);
  const manifest = parseManifest(manifestText, errors);
  let reviewedResult = null;

  if (patchText === null)
    errors.push(`missing tracked guide patch ${GUIDE_PATCH_FILE}`);
  if (manifest) {
    if (manifest.evidence_format !== GUIDE_PATCH_FORMAT) {
      errors.push("guide-patch manifest has an unknown evidence_format");
    }
    if (manifest.classification !== "WORK-RECORD") {
      errors.push("guide-patch manifest must be classified WORK-RECORD");
    }
    if (manifest.authority !== "none") {
      errors.push("guide-patch work record must disclaim authority");
    }
    if (
      manifest.base?.path !== GUIDE_FILE ||
      manifest.result?.path !== GUIDE_FILE
    ) {
      errors.push(
        "guide-patch base and result must name the sole master-guide path",
      );
    }
    if (!SHA256.test(manifest.base?.sha256 ?? "")) {
      errors.push("guide-patch manifest has a malformed base sha256");
    }
    if (manifest.base?.sha256 !== GUIDE_BASE_SHA256) {
      errors.push(
        "guide-patch manifest does not retain the reviewed estate-base sha256",
      );
    }
    if (!SHA256.test(manifest.result?.sha256 ?? "")) {
      errors.push("guide-patch manifest has a malformed result sha256");
    }
    if (manifest.base?.sha256 === manifest.result?.sha256) {
      errors.push("guide-patch base and result sha256 must differ");
    }
    if (
      manifest.patch?.path !== GUIDE_PATCH_FILE ||
      manifest.patch?.format !== "unified-diff" ||
      manifest.patch?.coverage !== "full-context" ||
      manifest.patch?.strip !== 1
    ) {
      errors.push(
        "guide-patch manifest has an invalid patch path, format, coverage, or strip count",
      );
    }
    if (!SHA256.test(manifest.patch?.sha256 ?? "")) {
      errors.push("guide-patch manifest has a malformed patch sha256");
    }
    if (
      manifest.validation_command !== "npm run check:stateless-master-guide"
    ) {
      errors.push("guide-patch manifest must name its validation command");
    }
  }

  if (patchText !== null) {
    const expectedOldHeader = `--- a/${GUIDE_FILE}`;
    const expectedNewHeader = `+++ b/${GUIDE_FILE}`;
    const oldHeaders = patchText.match(/^--- .+$/gmu) ?? [];
    const newHeaders = patchText.match(/^\+\+\+ .+$/gmu) ?? [];
    if (
      oldHeaders.length !== 1 ||
      newHeaders.length !== 1 ||
      oldHeaders[0] !== expectedOldHeader ||
      newHeaders[0] !== expectedNewHeader
    ) {
      errors.push(
        "guide patch must be one unified diff over the sole master-guide path",
      );
    }
    if (!/^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@/mu.test(patchText)) {
      errors.push("guide patch contains no unified-diff hunk");
    }
    if (manifest && sha256(patchText) !== manifest.patch?.sha256) {
      errors.push("guide patch sha256 does not match its manifest");
    }
    try {
      const materialized = materializeFullContextPatch(patchText);
      reviewedResult = materialized.resultSource;
      if (
        manifest &&
        sha256(materialized.baseSource) !== manifest.base?.sha256
      ) {
        errors.push(
          "guide patch full-context base does not match the manifest sha256",
        );
      }
      if (
        manifest &&
        sha256(materialized.resultSource) !== manifest.result?.sha256
      ) {
        errors.push(
          "guide patch reconstructed result does not match the manifest sha256",
        );
      }
    } catch (error) {
      errors.push(
        `guide patch cannot reconstruct full base and result: ${error.message}`,
      );
    }
  }

  if (resultSource !== undefined && resultSource !== null && manifest) {
    if (sha256(resultSource) !== manifest.result?.sha256) {
      errors.push(
        "local master guide does not match the reviewed result sha256",
      );
    }
  }

  return { errors, manifest, reviewedResult };
}

export function validateStatelessMasterGuide({
  repoRoot = defaultRepoRoot,
  source,
} = {}) {
  const guidePath = path.join(repoRoot, GUIDE_FILE);
  let guide = source;
  if (guide === undefined) {
    if (!fs.existsSync(guidePath)) {
      return { errors: [], skipped: true, stageCount: 0 };
    }
    guide = fs.readFileSync(guidePath, "utf8");
  }

  const errors = [];
  if (
    !/^Document role: sole internal M0–M14 implementation sequencer\.$/mu.test(
      guide,
    )
  ) {
    errors.push("does not declare the sole M0–M14 sequencer role");
  }
  if (
    !/Status truth rule: durable cut status lives in machine-checked/u.test(
      guide,
    )
  ) {
    errors.push("does not declare the Status Truth Rule");
  }
  if (!/ioi\.program\.work_item\.v1/u.test(guide)) {
    errors.push("does not point durable cut status to work-item records");
  }
  if (
    !/program-state\.json[^\n]*derived local[\s\S]{0,240}not a second sequencer/u.test(
      guide,
    )
  ) {
    errors.push(
      "does not bound program-state.json as a derived non-sequencer projection",
    );
  }

  for (const [pattern, message] of FORBIDDEN_LIVE_STATUS_PATTERNS) {
    if (pattern.test(guide)) errors.push(message);
  }

  const stageIds = [...guide.matchAll(/^### (M\d+) — /gmu)].map(
    (match) => match[1],
  );
  const expected = Array.from({ length: 15 }, (_, index) => `M${index}`);
  if (JSON.stringify(stageIds) !== JSON.stringify(expected)) {
    errors.push(
      `stage headings must list exactly M0–M14 in order (got ${stageIds.join(",")})`,
    );
  }

  return { errors, skipped: false, stageCount: stageIds.length };
}

export function validateStatelessMasterGuideBundle({
  repoRoot = defaultRepoRoot,
  guideSource,
  manifestSource,
  patchSource,
} = {}) {
  const localGuide = readOptional(repoRoot, GUIDE_FILE, guideSource);
  const patchResult = validateTrackedGuidePatch({
    repoRoot,
    manifestSource,
    patchSource,
    resultSource: localGuide,
  });
  const semanticSource = localGuide ?? patchResult.reviewedResult;
  const guideResult =
    semanticSource === null
      ? {
          errors: [
            "cannot validate master-guide semantics without a reconstructed reviewed result",
          ],
          skipped: false,
          stageCount: 0,
        }
      : validateStatelessMasterGuide({ repoRoot, source: semanticSource });
  return {
    errors: [...patchResult.errors, ...guideResult.errors],
    skipped: localGuide === null,
    stageCount: guideResult.stageCount,
  };
}

export function runStatelessMasterGuideCheck(options) {
  const result = validateStatelessMasterGuideBundle(options);
  if (result.errors.length > 0) {
    process.stderr.write(
      `stateless master-guide check failed with ${result.errors.length} error(s):\n${result.errors
        .map((message) => `- ${message}`)
        .join("\n")}\n`,
    );
    return 1;
  }
  if (result.skipped) {
    process.stdout.write(
      `stateless master-guide check passed: tracked patch manifest and reconstructed result semantics verified; ${GUIDE_FILE} is intentionally gitignored and absent.\n`,
    );
    return 0;
  }
  process.stdout.write(
    `stateless master-guide check passed: tracked patch manifest and result hash verified; ${result.stageCount} stage definitions, no live status narratives.\n`,
  );
  return 0;
}

if (path.resolve(process.argv[1] ?? "") === scriptPath) {
  process.exitCode = runStatelessMasterGuideCheck();
}
