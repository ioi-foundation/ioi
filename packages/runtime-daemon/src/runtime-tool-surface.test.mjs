import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeToolSurface } from "./runtime-tool-surface.mjs";

test("runtime tool surface delegates account, nodes, and tool catalog with env and coding contracts", () => {
  const env = {
    IOI_OPERATOR_EMAIL: "operator@example.test",
    IOI_AGENT_SDK_HOSTED_ENDPOINT: "https://provider.example.test",
  };
  const calls = [];
  const surface = createRuntimeToolSurface({
    codingToolContracts() {
      return [{ stableToolId: "coding.apply_patch", pack: "coding" }];
    },
    processEnv: env,
    runtimeAccount(inputEnv) {
      calls.push({ name: "runtimeAccount", env: inputEnv });
      return { email: inputEnv.IOI_OPERATOR_EMAIL };
    },
    runtimeNodes(inputEnv) {
      calls.push({ name: "runtimeNodes", env: inputEnv });
      return [{ endpoint: inputEnv.IOI_AGENT_SDK_HOSTED_ENDPOINT }];
    },
    runtimeTools(options, deps) {
      calls.push({
        name: "runtimeTools",
        options,
        contracts: deps.codingToolContracts(),
      });
      return [{ stableToolId: "fs.read", pack: options.pack ?? "runtime" }];
    },
  });

  assert.deepEqual(surface.getAccount(), { email: "operator@example.test" });
  assert.deepEqual(surface.listRuntimeNodes(), [
    { endpoint: "https://provider.example.test" },
  ]);
  assert.deepEqual(surface.listTools({ pack: "coding" }), [
    { stableToolId: "fs.read", pack: "coding" },
  ]);

  assert.deepEqual(calls, [
    { name: "runtimeAccount", env },
    { name: "runtimeNodes", env },
    {
      name: "runtimeTools",
      options: { pack: "coding" },
      contracts: [{ stableToolId: "coding.apply_patch", pack: "coding" }],
    },
  ]);
});
