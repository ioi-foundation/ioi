#!/usr/bin/env node

// Generate the private runtime-kernel residual projection from the preserved
// dated method census and current Rust owners. The private verifier derives the
// residual fields directly; no root compatibility body or live status field is
// an input.

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  checkDeterministic,
  git,
  implementationRoot,
  listTreeFiles,
  readJson,
  repoRelative,
  repoRoot,
  sha256,
  sha256File,
  stableJson,
  writeDeterministic,
} from "./lib.mjs";

export const GENERATED_RESIDUAL_PATH = path.join(
  implementationRoot,
  "generated/runtime-kernel-namespace-residual.v1.json",
);
const HISTORICAL_AUDIT_PATH = path.join(
  implementationRoot,
  "audits/history/2026-07-21-runtime-kernel-service-trust-boundary-audit.md",
);
const HISTORICAL_RESIDUAL_PATH = path.join(
  implementationRoot,
  "_archive/pre-unification-baseline/runtime-kernel-namespace-residual.v1.json",
);
const PRIVATE_VERIFIER_PATH = path.join(
  implementationRoot,
  "tools/verify-runtime-kernel-trust-audit.mjs",
);
const SERVICES_SOURCE_ROOT = path.join(repoRoot, "crates/services/src");
const PRIMARY_OWNER_PATHS = [
  "crates/services/src/agentic/runtime/kernel/mod.rs",
  "crates/services/src/agentic/runtime/owner_services.rs",
  "crates/services/src/agentic/runtime/projection_service.rs",
  "crates/services/src/agentic/runtime/kernel/runtime_effect_compatibility_gateway.rs",
];

function fail(message) {
  throw new Error(message);
}

function checkoutCommit() {
  const result = git(["rev-parse", "HEAD"]);
  const commit = result.stdout.trim();
  if (result.status !== 0 || !/^[0-9a-f]{40}$/u.test(commit)) {
    fail(`cannot resolve checkout commit: ${result.stderr.trim() || "unknown git error"}`);
  }
  return commit;
}

function runPrivateVerifier() {
  const result = spawnSync(process.execPath, [PRIVATE_VERIFIER_PATH, "--json"], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    fail(
      `private runtime trust verifier failed: ${(result.stderr || result.stdout || "no output").trim()}`,
    );
  }
  let census;
  try {
    census = JSON.parse(result.stdout);
  } catch (error) {
    fail(`private runtime trust verifier returned invalid JSON: ${error.message}`);
  }
  if (census.schema_version !== "ioi.runtime-kernel-trust-census.v1") {
    fail(`private runtime trust verifier returned unknown schema ${census.schema_version ?? "missing"}`);
  }
  return census;
}

function servicesRustTreeDigest() {
  const files = listTreeFiles(SERVICES_SOURCE_ROOT)
    .filter((file) => file.endsWith(".rs"));
  const entries = files.map((file) => ({
    path: repoRelative(file),
    sha256: sha256File(file),
  }));
  return {
    rust_file_count: entries.length,
    aggregate_sha256: sha256(stableJson(entries)),
  };
}

export function buildRuntimeKernelResidual() {
  const census = runPrivateVerifier();
  const historicalResidual = readJson(HISTORICAL_RESIDUAL_PATH);
  if (historicalResidual.schema_version !== "ioi.runtime-kernel-namespace-residual.v1") {
    fail(`${repoRelative(HISTORICAL_RESIDUAL_PATH)} has an unknown historical schema_version`);
  }
  const sourceTree = servicesRustTreeDigest();
  const inputs = [
    HISTORICAL_AUDIT_PATH,
    HISTORICAL_RESIDUAL_PATH,
    PRIVATE_VERIFIER_PATH,
    ...PRIMARY_OWNER_PATHS.map((relative) => path.join(repoRoot, relative)),
  ].map((file) => ({ path: repoRelative(file), sha256: sha256File(file) }));
  return {
    schema_version: "ioi.runtime-kernel-namespace-residual-projection.v1",
    projection_class: "derived_private_runtime_residual",
    architecture_authority: false,
    implementation_status_authority: false,
    generator: {
      path: repoRelative(fileURLToPath(import.meta.url)),
      version: "2",
      write_command: "node internal-docs/implementation/tools/generate-runtime-kernel-residual.mjs --write",
      check_command: "node internal-docs/implementation/tools/generate-runtime-kernel-residual.mjs --check",
    },
    source: {
      checkout_commit: checkoutCommit(),
      inputs,
      services_rust_tree: sourceTree,
      verifier: repoRelative(PRIVATE_VERIFIER_PATH),
      verifier_result: "PASS",
      verifier_summary: census.summary,
    },
    baseline_provenance: {
      audit_ref: repoRelative(HISTORICAL_AUDIT_PATH),
      audit_count_marker: `runtime-kernel-method-count: ${census.baseline_snapshot_method_count}`,
      residual_ref: repoRelative(HISTORICAL_RESIDUAL_PATH),
      residual_schema: historicalResidual.schema_version,
      root_audit_pointer: "internal-docs/implementation/runtime-kernel-service-trust-boundary-audit.md",
      root_residual_pointer: "internal-docs/implementation/runtime-kernel-namespace-residual.v1.json",
    },
    baseline_snapshot_method_count: census.baseline_snapshot_method_count,
    current_inventory: census.current_inventory,
    residual_delegate_modules: census.residual_delegate_modules,
    mixed_trust_delegate_modules: census.mixed_trust_delegate_modules,
    effect_compatibility_methods: census.effect_compatibility_methods,
    closure_rule: census.closure_rule,
    nonclaims: [
      "This projection owns neither architecture doctrine nor implementation status.",
      "A passing census proves only exact agreement among current Rust owners and the preserved dated 198-row classification.",
      "Namespace extraction, stage exit, runtime capability, and product authority are not established by this projection.",
    ],
  };
}

export function writeRuntimeKernelResidual() {
  const projection = buildRuntimeKernelResidual();
  writeDeterministic(GENERATED_RESIDUAL_PATH, projection);
  return projection;
}

export function checkRuntimeKernelResidual() {
  const projection = buildRuntimeKernelResidual();
  const result = checkDeterministic(GENERATED_RESIDUAL_PATH, projection);
  if (!result.ok) fail(result.reason);
  return projection;
}

function parseMode(argv) {
  if (argv.length !== 1 || !["--write", "--check"].includes(argv[0])) {
    fail("choose exactly one of --write or --check");
  }
  return argv[0];
}

export function runRuntimeKernelResidualCli(argv) {
  const mode = parseMode(argv);
  const projection = mode === "--write"
    ? writeRuntimeKernelResidual()
    : checkRuntimeKernelResidual();
  process.stdout.write(
    `runtime-kernel residual projection ${mode === "--write" ? "written" : "checked"}: ${projection.baseline_snapshot_method_count} baseline methods, ${projection.residual_delegate_modules.length} residual modules, verifier ${projection.source.verifier_result}; root compatibility bodies are not inputs.\n`,
  );
}

const isMain = process.argv[1] !== undefined
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    runRuntimeKernelResidualCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`runtime-kernel residual generation failed: ${error.message}\n`);
    process.exit(1);
  }
}
