import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import { discoverAutopilotLlamaServer, llamaCppGpuLayersArg } from "./local-runtime-engines.mjs";

test("discoverAutopilotLlamaServer prefers accelerated native bundles", () => {
  const home = mkdtempSync(path.join(tmpdir(), "ioi-llama-runtime-"));
  try {
    const root = path.join(home, ".cache", "ioi", "llama-cpp-live");
    const cpu = path.join(root, "b9000", "llama-b9000");
    const vulkan = path.join(root, "b9001-vulkan", "llama-b9001");
    mkdirSync(cpu, { recursive: true });
    mkdirSync(vulkan, { recursive: true });
    for (const dir of [cpu, vulkan]) {
      const binary = path.join(dir, "llama-server");
      writeFileSync(binary, "#!/bin/sh\nexit 0\n");
      chmodSync(binary, 0o755);
      writeFileSync(path.join(dir, "libllama-common.so.0"), "");
      writeFileSync(path.join(dir, "libggml-cpu-x64.so"), "");
    }
    writeFileSync(path.join(vulkan, "libggml-vulkan.so"), "");

    assert.equal(discoverAutopilotLlamaServer(home), path.join(vulkan, "llama-server"));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("llamaCppGpuLayersArg maps product gpu modes to llama.cpp flags", () => {
  assert.equal(llamaCppGpuLayersArg("auto"), "999");
  assert.equal(llamaCppGpuLayersArg("max"), "999");
  assert.equal(llamaCppGpuLayersArg("off"), "0");
  assert.equal(llamaCppGpuLayersArg("cpu"), "0");
  assert.equal(llamaCppGpuLayersArg(28), "28");
});
