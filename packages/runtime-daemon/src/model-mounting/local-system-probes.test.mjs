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
  lmStudioArtifact,
  parseLmStudioList,
  parseLmStudioProcessList,
  parseLocalModelMetadata,
  readLines,
  runPublicCommand,
} from "./local-system-probes.mjs";

test("LM Studio list parser preserves model shape for chat and embeddings", () => {
  const models = parseLmStudioList(`
LLM MODELS
You have 1 model
PARAMS         ARCH          SIZE
llama-3.2 (2 variants)     3B     llama     2.0 GB

EMBEDDING MODELS
nomic-embed-text           137M   nomic     274 MB
`);

  assert.deepEqual(models, [
    {
      kind: "llm",
      modelId: "llama-3.2",
      displayName: "llama-3.2 (2 variants)",
      params: "3B",
      arch: "llama",
      size: "2.0 GB",
    },
    {
      kind: "embedding",
      modelId: "nomic-embed-text",
      displayName: "nomic-embed-text",
      params: "137M",
      arch: "nomic",
      size: "274 MB",
    },
  ]);
});

test("LM Studio process parser normalizes public CLI output", () => {
  assert.deepEqual(parseLmStudioProcessList(`
MODEL               PID      PORT
llama-3.2           1234     49231
No loaded models
`), [{ modelId: "llama-3.2", raw: "llama-3.2           1234     49231" }]);
});

test("LM Studio artifact projection remains product-scoped", () => {
  const artifact = lmStudioArtifact(
    { id: "provider.lmstudio", status: "running" },
    { kind: "llm", modelId: "llama-3.2", displayName: "llama-3.2", arch: "llama" },
    "2026-06-03T00:00:00.000Z",
  );

  assert.deepEqual(artifact, {
    id: "lmstudio.llama.3.2",
    providerId: "provider.lmstudio",
    modelId: "llama-3.2",
    displayName: "llama-3.2",
    family: "lm-studio",
    quantization: "llama",
    sizeBytes: null,
    contextWindow: null,
    capabilities: ["chat", "responses"],
    privacyClass: "local_private",
    source: "lm_studio_public_lms_ls",
    state: "available",
    discoveredAt: "2026-06-03T00:00:00.000Z",
  });
});

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
