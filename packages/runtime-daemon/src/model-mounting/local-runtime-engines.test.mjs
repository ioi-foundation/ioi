import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import { discoverAutopilotLlamaServer } from "./local-runtime-engines.mjs";

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
