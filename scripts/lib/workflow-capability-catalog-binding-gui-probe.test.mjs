import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const repoRoot = resolve(new URL("../..", import.meta.url).pathname);

test("workflow capability catalog binding probe exercises canonical clickthrough projection", () => {
  const outputRoot = mkdtempSync(join(tmpdir(), "workflow-catalog-binding-"));
  const outputPath = join(outputRoot, "proof.json");
  try {
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        "tsx",
        "scripts/lib/workflow-capability-catalog-binding-gui-probe.mjs",
        outputPath,
      ],
      {
        cwd: repoRoot,
        encoding: "utf8",
        env: {
          ...process.env,
          TSX_TSCONFIG_PATH: resolve(
            repoRoot,
            "packages/hypervisor-workbench/tsconfig.json",
          ),
        },
        timeout: 60_000,
        maxBuffer: 8 * 1024 * 1024,
      },
    );
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const proof = JSON.parse(readFileSync(outputPath, "utf8"));
    assert.equal(proof.passed, true, JSON.stringify(proof, null, 2));
    assert.equal(proof.checks.modalHasCatalogPickerAndApply, true);
    assert.equal(proof.checks.simulatedToolClickApplied, true);
    assert.equal(proof.checks.simulatedConnectorClickApplied, true);
    assert.equal(
      proof.manifestProjection.tool.toolCapabilityRef,
      "tool-capability:mcp.tool.catalog.read",
    );
    assert.equal(
      proof.manifestProjection.connector.connectorCapabilityRef,
      "connector-capability:agent.connector.catalog",
    );
    assert.equal(proof.checks.failClosedWhenReadinessMissing, true);
  } finally {
    rmSync(outputRoot, { recursive: true, force: true });
  }
});
