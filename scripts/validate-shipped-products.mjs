#!/usr/bin/env node

import {
  DEFAULT_MANIFEST_PATH,
  DEFAULT_REPO_ROOT,
  loadShippedProductsManifest,
  validateShippedProductsManifest,
} from "./lib/shipped-products-manifest.mjs";

const args = process.argv.slice(2);
let laneId = null;
let phase = "preflight";
let json = false;
for (let index = 0; index < args.length; index += 1) {
  const argument = args[index];
  if (argument === "--lane") {
    laneId = args[index + 1] ?? null;
    if (!laneId || laneId.startsWith("--"))
      throw new Error("--lane requires a product id");
    index += 1;
  } else if (argument === "--post-build") {
    phase = "post-build";
  } else if (argument === "--preflight") {
    phase = "preflight";
  } else if (argument === "--structure-only") {
    phase = "structure-only";
  } else if (argument === "--json") {
    json = true;
  } else if (argument === "--help") {
    console.log(`Usage: node scripts/validate-shipped-products.mjs [options]

  --preflight       Validate structure and require every declared input in Git's index (default).
                    Generated artifacts are validated as build intentions and need not exist yet.
  --post-build      Apply preflight checks, require every generated artifact, and emit its SHA-256.
  --structure-only  Inspect manifest/files/source graphs without Git or generated-output admission.
                    This is a drafting aid, not a release gate.
  --lane ID         Validate one product lane (the complete product inventory is still checked).
  --json            Emit the complete machine-readable report.`);
    process.exit(0);
  } else {
    throw new Error(`unknown argument ${argument}`);
  }
}

const manifest = await loadShippedProductsManifest();
const report = await validateShippedProductsManifest(manifest, {
  laneId,
  phase,
  manifestPath: DEFAULT_MANIFEST_PATH,
});
const graphFiles = report.source_graphs.reduce(
  (total, graph) => total + graph.files.length,
  0,
);

if (json) {
  console.log(JSON.stringify(report, null, 2));
} else {
  const hashedArtifacts = report.artifacts.filter(
    (artifact) => artifact.status === "hashed",
  );
  console.log(
    `shipped-products ${report.phase} passed: ${report.product_count} product lane(s), ` +
      `${report.nonshipped_root_count} nonshipped root(s), ${graphFiles} source-graph file(s), ` +
      `${report.tracked_path_count ?? "not enforced"} tracked input(s), ${hashedArtifacts.length} hashed artifact(s) ` +
      `(${DEFAULT_MANIFEST_PATH} under ${DEFAULT_REPO_ROOT})`,
  );
  for (const artifact of hashedArtifacts)
    console.log(
      `  ${artifact.product_id}: ${artifact.path} · ${artifact.file_count} file(s) · sha256:${artifact.sha256}`,
    );
  if (report.phase === "structure-only")
    console.log(
      "  structure-only is a drafting aid; it is not a release preflight",
    );
}
