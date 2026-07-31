#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { failWith, implementationRoot, listTreeFiles, readJson } from "./lib.mjs";

const errors = [];
const skips = [];
const ignoredPrefixes = ["audits/", "_archive/", "work-items/logs/"];
const allowedPaths = new Set(["program-state.json"]);
const registry = readJson(path.join(implementationRoot, "source-dispositions.v1.json"));
const compatibilityHolds = new Map(
  registry.sources
    .filter((entry) => entry.compatibility_hold !== null)
    .map((entry) => [entry.source_path, entry.compatibility_hold]),
);

function statusKeyPaths(value, relative, prefix = "$") {
  if (Array.isArray(value)) return value.flatMap((entry, index) => statusKeyPaths(entry, relative, `${prefix}[${index}]`));
  if (value === null || typeof value !== "object") return [];
  const found = [];
  for (const [key, entry] of Object.entries(value)) {
    // Only the route-level numeric HTTP observation in the retained live-crawl
    // artifact is exempt. A numeric `status` anywhere else remains a status
    // voice and is rejected by the same rule as a string/object value.
    const statusPath = `${prefix}.status`;
    const isHttpObservation = relative === "evidence/hypervisor-live-read-only-crawl.v1.json"
      && typeof entry === "number"
      && /^\$\.results\[\d+\]\.status$/u.test(statusPath);
    if (key === "status" && !isHttpObservation) found.push(statusPath);
    found.push(...statusKeyPaths(entry, relative, `${prefix}.${key}`));
  }
  return found;
}

for (const file of listTreeFiles(implementationRoot)) {
  const relative = path.relative(implementationRoot, file).split(path.sep).join("/");
  if (relative.startsWith("work-items/") && relative.endsWith(".v1.json")) continue;
  if (allowedPaths.has(relative) || ignoredPrefixes.some((prefix) => relative.startsWith(prefix))) continue;
  if (!/\.(?:md|json)$/u.test(relative)) continue;
  const raw = fs.readFileSync(file, "utf8");
  if (relative.endsWith(".json")) {
    try {
      const paths = statusKeyPaths(JSON.parse(raw), relative);
      if (paths.length > 0 && compatibilityHolds.has(relative)) {
        const hold = compatibilityHolds.get(relative);
        skips.push({
          check: "status-truth-compatibility-hold",
          path: relative,
          status_key_paths: paths,
          reason: hold.reason,
          approval_needed: hold.approval_needed,
          nonclaim: "The compatibility-held field is not current private status authority. Physical status-voice cleanup remains unproven, and this SKIP changes no status or stage.",
        });
      } else {
        for (const statusPath of paths) errors.push(`${relative}: live status key at ${statusPath}`);
      }
    } catch (error) {
      errors.push(`${relative}: invalid JSON: ${error.message}`);
    }
  }
  // Schema examples may enumerate the allowed status vocabulary. They are
  // contracts, not live status assertions, so ignore fenced blocks while
  // still rejecting prose-level current-status ownership.
  const source = relative.endsWith(".md")
    ? raw.replace(/^```[^\n]*\n[\s\S]*?^```\s*$/gmu, "")
    : raw;
  if (relative.endsWith(".md") && compatibilityHolds.has(relative)) {
    const hold = compatibilityHolds.get(relative);
    const statusSignals = [
      ...[...source.matchAll(/^Status:\s*.+$/gmiu)].map((match) => match[0].trim()),
      ...(/\bimplementation cut is complete\b/iu.test(source) ? ["implementation cut is complete"] : []),
      ...(/\bphysical namespace shrink is also not complete\b/iu.test(source) ? ["physical namespace shrink is also not complete"] : []),
      ...(/^##\s+Disposition summary\s*$/gmiu.test(source) ? ["Disposition summary"] : []),
      ...(/^##\s+Completion condition\s*$/gmiu.test(source) ? ["Completion condition"] : []),
    ];
    if (statusSignals.length > 0) {
      skips.push({
        check: "status-truth-compatibility-hold",
        path: relative,
        status_signals: [...new Set(statusSignals)],
        reason: hold.reason,
        approval_needed: hold.approval_needed,
        nonclaim: "This point-in-time legacy body is not current status authority. Physical status-voice cleanup remains unproven, and this SKIP changes no status or stage.",
      });
      continue;
    }
  }
  for (const match of source.matchAll(/^Status:\s*(active|verified|blocked|pending|evidence_ready|scoped|proposed)\b.*$/gmiu)) {
    errors.push(`${relative}: live status line "${match[0].trim()}"`);
  }
  if (/^Current next action:/gmiu.test(source)) errors.push(`${relative}: owns a current next action`);
  if (/^Active cut:/gmiu.test(source)) errors.push(`${relative}: owns an active cut`);
}
failWith("status-truth check", errors);
for (const skip of skips) {
  process.stdout.write(`${JSON.stringify({
    result: "SKIP",
    ...skip,
  })}\n`);
}
const physicalResult = skips.length === 0
  ? "no active compatibility-held status prose or fields remain"
  : "physical cleanup of held legacy status prose/fields remains unproven";
process.stdout.write(`status-truth check passed with ${skips.length} explicit compatibility-hold SKIP(s): durable live status is confined to records and program-state.json; ${physicalResult}; dated audit/archive/log evidence was not interpreted as current truth\n`);
