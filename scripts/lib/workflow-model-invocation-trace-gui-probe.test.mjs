import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const repoRoot = resolve(new URL("../..", import.meta.url).pathname);

test("workflow model invocation trace renders the prompt pipeline in the run shelf", () => {
  const outputRoot = mkdtempSync(join(tmpdir(), "workflow-model-trace-"));
  const outputPath = join(outputRoot, "proof.json");
  try {
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        "tsx",
        "scripts/lib/workflow-model-invocation-trace-gui-probe.mjs",
        outputPath,
      ],
      {
        cwd: repoRoot,
        encoding: "utf8",
        env: {
          ...process.env,
          TSX_TSCONFIG_PATH: resolve(repoRoot, "packages/agent-ide/tsconfig.json"),
        },
        timeout: 60_000,
        maxBuffer: 8 * 1024 * 1024,
      },
    );
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const proof = JSON.parse(readFileSync(outputPath, "utf8"));
    assert.equal(proof.passed, true, JSON.stringify(proof, null, 2));
    assert.equal(proof.checks.promptVisible, true);
    assert.equal(proof.checks.traceStepsRendered, true);
    assert.equal(proof.checks.runsPanelTraceRendered, true);
    assert.equal(proof.checks.runsPanelSearchFindsPrompt, true);
    assert.equal(proof.checks.railTraceStepsRendered, true);
    assert.equal(proof.expectedEventKind, "model_invocation_succeeded");
  } finally {
    rmSync(outputRoot, { recursive: true, force: true });
  }
});
