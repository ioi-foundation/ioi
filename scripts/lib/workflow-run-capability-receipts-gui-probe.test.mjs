import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const repoRoot = resolve(new URL("../..", import.meta.url).pathname);

test("workflow run capability receipt probe renders canonical run inspector evidence", () => {
  const outputRoot = mkdtempSync(join(tmpdir(), "workflow-run-capability-receipts-"));
  const outputPath = join(outputRoot, "proof.json");
  try {
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        "tsx",
        "scripts/lib/workflow-run-capability-receipts-gui-probe.mjs",
        outputPath,
      ],
      {
        cwd: repoRoot,
        encoding: "utf8",
        env: {
          ...process.env,
          TSX_TSCONFIG_PATH: resolve(
            repoRoot,
            "packages/agent-ide/tsconfig.json",
          ),
        },
        timeout: 60_000,
        maxBuffer: 8 * 1024 * 1024,
      },
    );
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const proof = JSON.parse(readFileSync(outputPath, "utf8"));
    assert.equal(proof.passed, true, JSON.stringify(proof, null, 2));
    assert.equal(proof.checks.schemaVersion, true);
    assert.equal(proof.checks.sectionVisible, true);
    assert.equal(proof.checks.canonicalCapabilityRefs, true);
    assert.equal(proof.checks.runtimeEvidenceRefs, true);
    assert.equal(proof.checks.failClosedBlockers, true);
    assert.equal(proof.projection.status, "blocked");
    assert.equal(proof.projection.readyCount, 3);
    assert.equal(proof.projection.failClosedCount, 1);
  } finally {
    rmSync(outputRoot, { recursive: true, force: true });
  }
});
