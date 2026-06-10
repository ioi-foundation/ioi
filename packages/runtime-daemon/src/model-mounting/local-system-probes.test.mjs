import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  commandProbe,
  estimateNativeLocalResources,
  findExecutable,
  hardwareSnapshot,
  inspectLocalArtifact,
  listFiles,
  parseLocalModelMetadata,
  readLines,
  runPublicCommand,
} from "./local-system-probes.mjs";

test("local artifact inspection and metadata read stable model fields", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-local-probes-"));
  const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-local-probes-empty-"));
  const textPath = path.join(tempDir, "notes.txt");
  const modelPath = path.join(tempDir, "TinyLlama.Q4_K_M.gguf");
  fs.writeFileSync(textPath, "ignored");
  fs.writeFileSync(modelPath, "family=tiny-llama\ncontextWindow=4096\n");

  const inspected = inspectLocalArtifact(tempDir);
  assert.equal(inspected.path, modelPath);
  assert.equal(inspected.sizeBytes, 37);
  assert.match(inspected.checksum, /^sha256:[a-f0-9]{64}$/);

  assert.deepEqual(parseLocalModelMetadata(inspected.path), {
    format: "gguf",
    family: "tiny-llama",
    quantization: "Q4_K_M",
    contextWindow: 4096,
  });

  assert.throws(
    () => inspectLocalArtifact(path.join(tempDir, "missing.gguf")),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.details.source_path, path.join(tempDir, "missing.gguf"));
      assert.equal(Object.hasOwn(error.details, "sourcePath"), false);
      return true;
    },
  );
  assert.throws(
    () => inspectLocalArtifact(emptyDir),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.details.dir_path, emptyDir);
      assert.equal(Object.hasOwn(error.details, "dir"), false);
      return true;
    },
  );
});

test("file helpers and resource estimates are deterministic", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-local-probes-"));
  const first = path.join(tempDir, "a.jsonl");
  const second = path.join(tempDir, "b.txt");
  fs.writeFileSync(first, "one\n\ntwo\n");
  fs.writeFileSync(second, "skip");

  assert.deepEqual(listFiles(tempDir, ".jsonl"), [first]);
  assert.deepEqual(readLines(first), ["one", "two"]);
  assert.deepEqual(estimateNativeLocalResources({ sizeBytes: 1234, contextWindow: 1024 }), {
    sizeBytes: 1234,
    contextWindow: 1024,
    estimatedVramBytes: 64 * 1024 * 1024 + 1024 * 1024,
    backend: "autopilot.native_local.fixture",
    realInference: false,
  });
});

test("public command probes do not leak command output", () => {
  const result = runPublicCommand(process.execPath, ["-e", "process.stdout.write('ok')"], { timeout: 1500 });
  assert.equal(result.status, 0);
  assert.equal(result.stdout, "ok");
  assert.equal(result.stderr, "");
  assert.equal(result.error, null);

  assert.equal(findExecutable("__ioi_missing_binary__"), null);
  assert.deepEqual(commandProbe("__ioi_missing_binary__", ["--version"]), { available: false });
  const hardware = hardwareSnapshot();
  assert.equal(Number.isInteger(hardware.cpuCount), true);
  assert.equal(typeof hardware.platform, "string");
  assert.equal(typeof hardware.nvidiaSmi.available, "boolean");
});
