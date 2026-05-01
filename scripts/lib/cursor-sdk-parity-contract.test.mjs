import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { validateCursorSdkParity } from "./cursor-sdk-parity-contract.mjs";

test("Cursor SDK parity contract validates local SDK proof and external blockers", async () => {
  const evidenceDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-cursor-sdk-parity-"));
  const result = await validateCursorSdkParity({
    evidenceDir,
    includeReference: false,
  });
  assert.equal(result.status, "complete_plus_local_external_blockers");
  assert.ok(result.checks.every((check) => check.pass), JSON.stringify(result.checks, null, 2));
  assert.equal(result.proof.quickstart.stopReason, "evidence_sufficient");
  assert.equal(result.proof.cloudBlocker.code, "external_blocker");
  assert.ok(fs.existsSync(path.join(evidenceDir, "sdk-local-proof.json")));
});
