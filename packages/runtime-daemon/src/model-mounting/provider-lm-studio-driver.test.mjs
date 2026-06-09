import assert from "node:assert/strict";
import fs from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { LmStudioModelProviderDriver } from "./provider-lm-studio-driver.mjs";

function provider(lmsPath = null) {
  return {
    id: "provider.lmstudio",
    kind: "lm_studio",
    discovery: lmsPath ? { publicCli: { path: lmsPath } } : {},
  };
}

function fakeState(homeDir) {
  return {
    homeDir,
    nowIso() {
      return "2026-06-03T00:00:00.000Z";
    },
  };
}

async function withFakeLms(handler) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "ioi-lms-fixture-"));
  const lmsPath = path.join(dir, "lms");
  fs.writeFileSync(
    lmsPath,
    [
      "#!/bin/sh",
      "case \"$1 $2\" in",
      "  \"server status\") echo ON; exit 0 ;;",
      "  \"server start\") echo started; exit 0 ;;",
      "  \"server stop\") echo stopped; exit 0 ;;",
      "  \"load model-a\") echo loaded; exit 0 ;;",
      "  \"unload model-a\") echo unloaded; exit 0 ;;",
      "esac",
      "exit 1",
      "",
    ].join("\n"),
  );
  fs.chmodSync(lmsPath, 0o755);
  try {
    return await handler({ dir, lmsPath });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("LM Studio driver reports absent CLI without leaking local probes", async () => {
  const driver = new LmStudioModelProviderDriver({ state: fakeState("/tmp/no-lmstudio") });
  const selectedProvider = provider();

  const health = await driver.health(selectedProvider);
  assert.equal(health.status, "absent");
  assert.deepEqual(health.evidenceRefs, ["lm_studio_public_cli_absent"]);

  await assert.rejects(
    () => driver.start({ provider: selectedProvider }),
    (error) => {
      assert.equal(error.status, 424);
      assert.equal(error.code, "external_blocker");
      assert.equal(error.details.provider_id, "provider.lmstudio");
      assert.deepEqual(error.details.evidence_refs, ["lm_studio_public_cli_absent"]);
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
});

test("LM Studio driver uses public CLI path for health and lifecycle commands", async () => {
  await withFakeLms(async ({ dir, lmsPath }) => {
    const driver = new LmStudioModelProviderDriver({ state: fakeState(dir) });
    const selectedProvider = provider(lmsPath);
    const endpoint = {
      id: "endpoint.lmstudio",
      modelId: "model-a",
      backendId: "backend.lmstudio",
      loadPolicy: { mode: "on_demand" },
    };

    assert.equal(driver.lmsPath(selectedProvider), lmsPath);
    const health = await driver.health(selectedProvider);
    assert.equal(health.status, "running");
    assert.equal(health.publicCli.path, lmsPath);

    const started = await driver.start({ provider: selectedProvider });
    assert.equal(started.status, "running");

    const loaded = await driver.load({
      provider: selectedProvider,
      endpoint,
      body: {
        loadOptions: { context_length: 9999 },
        contextLength: 8888,
        ttlSeconds: 777,
      },
    });
    assert.equal(loaded.status, "loaded");
    assert.equal(loaded.backend, "lm_studio");
    assert.equal(loaded.backendId, "backend.lmstudio");
    assert.equal(loaded.commandExitCode, 0);
    assert.equal(typeof loaded.commandArgsHash, "string");

    const unloaded = await driver.unload({ provider: selectedProvider, endpoint });
    assert.equal(unloaded.status, "unloaded");
    assert.equal(unloaded.commandExitCode, 0);

    const stopped = await driver.stop({ provider: selectedProvider });
    assert.equal(stopped.status, "stopped");
  });
});

test("LM Studio driver fails closed for retired JS invocation before CLI transport", async () => {
  await withFakeLms(async ({ dir, lmsPath }) => {
    const driver = new LmStudioModelProviderDriver({ state: fakeState(dir) });
    const selectedProvider = provider(lmsPath);
    const endpoint = {
      id: "endpoint.lmstudio",
      modelId: "model-a",
      backendId: "backend.lmstudio",
    };

    await assert.rejects(
      () => driver.invoke({ provider: selectedProvider, endpoint, body: { input: "hello" }, input: "hello" }),
      (error) =>
        error.code === "model_mount_provider_js_invocation_retired" &&
        error.details.provider_kind === "lm_studio" &&
        error.details.stream === false,
    );
    await assert.rejects(
      () => driver.streamInvoke({ provider: selectedProvider, endpoint, body: { input: "hello" } }),
      (error) =>
        error.code === "model_mount_provider_js_invocation_retired" &&
        error.details.provider_kind === "lm_studio" &&
        error.details.stream === true,
    );
    assert.equal(driver.supportsStream("responses"), false);
  });
});
