#!/usr/bin/env node
import path from "node:path";

import {
  assertReferenceInventoryComplete,
  collectCursorSdkReference,
} from "./lib/cursor-sdk-reference-contract.mjs";

const repoRoot = process.cwd();
const evidenceDir = path.join(
  repoRoot,
  "docs",
  "evidence",
  "cursor-sdk-parity",
  new Date().toISOString().replace(/[:.]/g, "-"),
);

const reference = collectCursorSdkReference({ repoRoot, evidenceDir });
assertReferenceInventoryComplete(reference);
console.log(JSON.stringify({ evidenceDir, version: reference.npmVersion }, null, 2));
