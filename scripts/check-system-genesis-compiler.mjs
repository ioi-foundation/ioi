#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(scriptPath), "..");
const compilerPath = path.join(root, "crates/types/src/app/system_genesis.rs");
const sourcePolicyPath = path.join(
  root,
  "crates/types/tests/system_genesis_source_policy.rs",
);
const corpusPath = path.join(
  root,
  "docs/architecture/_meta/schemas/fixtures/system-genesis-compiler-v1/adversarial-cases.json",
);

const SYNTAX_AWARE_PURITY_CLASSES = Object.freeze([
  "filesystem",
  "network",
  "clock",
  "random",
  "environment",
  "process",
  "daemon",
  "wallet",
  "agentgres",
]);

function main(args) {
  if (args.length !== 1 || args[0] !== "--check") {
    process.stderr.write(
      "Usage: node scripts/check-system-genesis-compiler.mjs --check\n",
    );
    return 2;
  }

  const compilerSource = fs.readFileSync(compilerPath, "utf8");
  for (const requiredMarker of [
    "compile_system_genesis_proposal",
    "serde_jcs::to_vec",
    "SYSTEM_COMPONENT_SET_HASH_PROFILE",
    "SYSTEM_RELEASE_ROOT_HASH_PROFILE",
    "SYSTEM_INITIAL_PROFILE_BUNDLE_HASH_PROFILE",
    "SYSTEM_GENESIS_OPERATION_HASH_PROFILE",
    "SYSTEM_GENESIS_PROPOSAL_ROOT_HASH_PROFILE",
    "SYSTEM_GENESIS_PROPOSAL_AUTHORITY_BOUNDARY",
  ]) {
    if (!compilerSource.includes(requiredMarker)) {
      throw new Error(`pure compiler lacks required marker ${requiredMarker}`);
    }
  }
  const sourcePolicy = fs.readFileSync(sourcePolicyPath, "utf8");
  for (const requiredProbe of [
    "use std::{fs as disk}",
    "extern crate std as runtime",
    "fake_marker",
    "classify_token_paths",
    "system_genesis_source_policy_descends_into_macro_tokens",
    "ALLOWED_PRODUCTION_IMPORTS",
    "FORBIDDEN_CAPABILITY_PREFIXES",
  ]) {
    if (!sourcePolicy.includes(requiredProbe)) {
      throw new Error(
        `syntax-aware production source policy lacks probe ${requiredProbe}`,
      );
    }
  }

  const corpus = JSON.parse(fs.readFileSync(corpusPath, "utf8"));
  if (
    corpus.schema_version !==
    "ioi.system-genesis-compiler-adversarial-corpus.v1"
  ) {
    throw new Error("system genesis adversarial corpus version drifted");
  }
  if (!Array.isArray(corpus.cases) || corpus.cases.length !== 93) {
    throw new Error("system genesis adversarial corpus must contain 93 cases");
  }
  const caseIds = new Set(corpus.cases.map((candidate) => candidate.id));
  if (caseIds.size !== corpus.cases.length) {
    throw new Error("system genesis adversarial case ids must be unique");
  }

  process.stdout.write(
    `${JSON.stringify(
      {
        ok: true,
        purity_verifier: "rust_syn_production_item_and_import_analysis",
        purity_classes: SYNTAX_AWARE_PURITY_CLASSES,
        adversarial_cases: corpus.cases.length,
        authority_effect_boundary:
          "unverified_proposal_only_no_authority_admission_activation_or_effect",
      },
      null,
      2,
    )}\n`,
  );
  return 0;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
}
