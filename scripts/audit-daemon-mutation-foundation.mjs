#!/usr/bin/env node

import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const routeRoot = path.join(repoRoot, "crates/node/src/bin/hypervisor_daemon_routes");
const registryPath = path.join(
  repoRoot,
  "docs/architecture/_meta/mutation-event-foundation-coverage.v1.json",
);

const relative = (absolute) => path.relative(repoRoot, absolute).split(path.sep).join("/");
const occurrences = (source, pattern) => [...source.matchAll(pattern)].length;

const routeFiles = (await readdir(routeRoot, { withFileTypes: true }))
  .filter((entry) => entry.isFile() && entry.name.endsWith(".rs"))
  .map((entry) => path.join(routeRoot, entry.name));
const sourceFiles = [path.join(repoRoot, "crates/node/src/bin/hypervisor-daemon.rs"), ...routeFiles];

const modules = [];
for (const sourcePath of sourceFiles) {
  const source = await readFile(sourcePath, "utf8");
  const discardedDirectPersists = occurrences(
    source,
    /let\s+_\s*=\s*(?:super::)?persist_record\s*\(/gu,
  );
  const discardedDirectRemovals = occurrences(
    source,
    /let\s+_\s*=\s*(?:super::)?remove_record\s*\(/gu,
  );
  const publicAsyncHandlers = occurrences(source, /pub\(crate\)\s+async\s+fn\s+handle_/gu);
  const sharedFoundationAdmissions = occurrences(source, /admit_owner_scoped_mutation\s*\(/gu);
  const directEventAdmissions = occurrences(source, /admit_event_stream_operation\s*\(/gu);
  const scopeBindings = occurrences(source, /bind_request_resource_scope\s*\(/gu);
  if (
    discardedDirectPersists > 0 ||
    discardedDirectRemovals > 0 ||
    sharedFoundationAdmissions > 0 ||
    directEventAdmissions > 0
  ) {
    modules.push({
      source: relative(sourcePath),
      public_async_handlers: publicAsyncHandlers,
      discarded_direct_persist_results: discardedDirectPersists,
      discarded_direct_remove_results: discardedDirectRemovals,
      shared_foundation_admissions: sharedFoundationAdmissions,
      direct_event_admissions: directEventAdmissions,
      request_scope_bindings: scopeBindings,
    });
  }
}
modules.sort((left, right) => left.source.localeCompare(right.source));

const registry = JSON.parse(await readFile(registryPath, "utf8"));
const bySource = Object.fromEntries(
  modules
    .filter((module) => module.discarded_direct_persist_results > 0)
    .map((module) => [module.source, module.discarded_direct_persist_results]),
);
const totalOccurrences = Object.values(bySource).reduce((sum, count) => sum + count, 0);
const declared = registry.direct_persistence_indicator_census;
const sortedEntries = (value) =>
  Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
const censusMatches =
  declared.total_occurrences === totalOccurrences &&
  declared.source_files === Object.keys(bySource).length &&
  JSON.stringify(sortedEntries(declared.by_source)) === JSON.stringify(sortedEntries(bySource));

const output = {
  schema_version: "ioi.hypervisor.mutation_event_foundation_source_audit.v1",
  coverage_registry: relative(registryPath),
  coverage_status: registry.status,
  coverage_status_is_complete: registry.status === "complete",
  open_gap_ids: registry.open_gaps
    .filter((gap) => gap.status !== "closed")
    .map((gap) => gap.id),
  discarded_direct_persistence_indicator: {
    total_occurrences: totalOccurrences,
    source_files: Object.keys(bySource).length,
    registry_matches_source: censusMatches,
  },
  modules,
};

process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);

if (process.argv.includes("--check") && !censusMatches) {
  process.stderr.write(
    "mutation-event coverage registry census is stale; regenerate and classify the changed source indicators\n",
  );
  process.exitCode = 1;
}
