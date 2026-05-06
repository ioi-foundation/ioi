#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const guidePath = path.join(repoRoot, "docs/specs/runtime/lm-studio-model-mounting-master-guide.md");
const guide = fs.readFileSync(guidePath, "utf8");
const failures = [];

function fail(message) {
  failures.push(message);
}

function requireText(text, description = text) {
  if (!guide.includes(text)) {
    fail(`Guide is missing ${description}.`);
  }
}

function forbid(pattern, description) {
  if (pattern.test(guide)) {
    fail(`Guide contains forbidden ${description}.`);
  }
}

requireText("Status: remaining-work closeout contract", "remaining-work status");
requireText("Deterministic fixture parity is useful, but it is not enough to close this", "fixture-not-enough doctrine");
requireText("docs/evidence/model-mounting-closeout/", "closeout evidence location");
requireText("## Remaining Implementation Work", "remaining implementation section");
requireText("### 1. Canonical Closeout Evidence And Guide Hygiene");
requireText("### 2. Compatibility Surface Parity");
requireText("### 3. Live Backend Parity");
requireText("### 4. Catalog And Download Production Parity");
requireText("### 5. Production Wallet.Network, Vault, And Agentgres");
requireText("### 6. MCP Production Lifecycle");
requireText("### 7. Workflow Canvas And Harness Product UX");
requireText("### 8. Provider And Product Expansion");
requireText("### 9. Adjacent LM Studio-Class Developer Primitives");
requireText("LM Studio-class live/product parity: not closed.", "explicit not-closed status");

forbid(/^Status:\s*(complete|closed|done|final)/im, "closed status claim");
forbid(/\bLM Studio-class live\/product parity:\s*(closed|complete|done)\b/i, "closed parity claim");
forbid(/\bImmediate Backlog\b/, "obsolete immediate backlog section");
forbid(/\bCommit Ledger\b/, "obsolete commit ledger section");
forbid(/\bCompleted In Repo\b/, "obsolete completed ledger section");
forbid(/\bLocal LM Studio Trace\b/, "obsolete local trace section");

if (failures.length > 0) {
  console.error("Model mounting master guide check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Model mounting master guide check passed.");
