import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  modelFileScore,
  parseModelQuantization,
} from "./catalog-helpers.mjs";
import {
  fileSha256,
  isExecutable,
  notFound,
  safeId,
  stableHash,
} from "./io.mjs";

export function runPublicCommand(command, args, options = {}) {
  try {
    const result = childProcess.spawnSync(command, args, {
      encoding: "utf8",
      timeout: options.timeout ?? 1500,
      killSignal: "SIGKILL",
      maxBuffer: options.maxBuffer ?? 1024 * 1024,
      windowsHide: true,
    });
    return {
      status: result.status,
      stdout: result.stdout ?? "",
      stderr: result.stderr ?? "",
      error: result.error ? String(result.error.message ?? result.error) : null,
    };
  } catch (error) {
    return {
      status: null,
      stdout: "",
      stderr: "",
      error: String(error?.message ?? error),
    };
  }
}

export function parseLmStudioList(text) {
  const models = [];
  let section = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (/^LLM\s+/i.test(line)) {
      section = "llm";
      continue;
    }
    if (/^EMBEDDING\s+/i.test(line)) {
      section = "embedding";
      continue;
    }
    if (!section || /^You have /i.test(line) || /^PARAMS\s+/i.test(line)) continue;
    const columns = line.split(/\s{2,}/).map((item) => item.trim()).filter(Boolean);
    if (columns.length < 2) continue;
    const displayName = columns[0];
    const modelId = displayName.replace(/\s+\(\d+\s+variants?\)$/i, "");
    models.push({
      kind: section,
      modelId,
      displayName,
      params: columns[1] ?? null,
      arch: columns[2] ?? null,
      size: columns[3] ?? null,
    });
  }
  return models;
}

export function parseLmStudioProcessList(text) {
  const models = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || /^MODEL\b/i.test(line) || /^No loaded/i.test(line)) continue;
    const columns = line.split(/\s{2,}|\t+/).map((item) => item.trim()).filter(Boolean);
    const modelId = columns[0] ?? line.split(/\s+/)[0];
    if (!modelId || /^(pid|port|identifier)$/i.test(modelId)) continue;
    models.push({ modelId, raw: line });
  }
  return models;
}

export function lmStudioArtifact(provider, model, checkedAt) {
  return {
    id: `lmstudio.${safeId(model.modelId)}`,
    providerId: provider.id,
    modelId: model.modelId,
    displayName: model.displayName,
    family: model.kind === "embedding" ? "embedding" : "lm-studio",
    quantization: model.arch,
    sizeBytes: null,
    contextWindow: null,
    capabilities: model.kind === "embedding" ? ["embeddings"] : ["chat", "responses"],
    privacyClass: "local_private",
    source: "lm_studio_public_lms_ls",
    state: provider.status === "running" ? "available" : "installed",
    discoveredAt: checkedAt,
  };
}

export function inspectLocalArtifact(sourcePath) {
  const absolutePath = path.resolve(String(sourcePath));
  if (!fs.existsSync(absolutePath)) {
    throw notFound(`Local model artifact path not found: ${sourcePath}`, { source_path: absolutePath });
  }
  const stats = fs.statSync(absolutePath);
  const filePath = stats.isDirectory() ? firstModelFile(absolutePath) : absolutePath;
  const fileStats = fs.statSync(filePath);
  return {
    path: filePath,
    sizeBytes: fileStats.size,
    checksum: fileSha256(filePath),
  };
}

function firstModelFile(dir) {
  const candidates = fs
    .readdirSync(dir)
    .map((file) => path.join(dir, file))
    .filter((filePath) => fs.statSync(filePath).isFile())
    .sort((left, right) => {
      const leftScore = modelFileScore(left);
      const rightScore = modelFileScore(right);
      if (leftScore !== rightScore) return rightScore - leftScore;
      return left.localeCompare(right);
    });
  if (candidates.length === 0) {
    throw notFound(`No model artifact files found in ${dir}`, { dir_path: dir });
  }
  return candidates[0];
}

export function parseLocalModelMetadata(filePath) {
  const name = path.basename(String(filePath));
  const lower = name.toLowerCase();
  const format = lower.endsWith(".gguf")
    ? "gguf"
    : lower.endsWith(".safetensors")
      ? "safetensors"
      : lower.endsWith(".onnx")
        ? "onnx"
        : null;
  const quantization = parseModelQuantization(name);
  let text = "";
  try {
    const fd = fs.openSync(filePath, "r");
    const buffer = Buffer.alloc(Math.min(4096, fs.statSync(filePath).size));
    fs.readSync(fd, buffer, 0, buffer.length, 0);
    fs.closeSync(fd);
    text = buffer.toString("utf8");
  } catch {
    text = "";
  }
  const family =
    text.match(/family=([^\n\r]+)/)?.[1]?.trim() ??
    lower.replace(/\.(gguf|safetensors|onnx|bin)$/i, "").split(/[._-]+/).filter(Boolean).slice(0, 3).join("-");
  const contextWindow = Number(text.match(/context(?:Window)?=([0-9]+)/i)?.[1] ?? 0) || null;
  return {
    format,
    family: family || null,
    quantization,
    contextWindow,
  };
}

export function hardwareSnapshot() {
  return {
    cpuCount: os.cpus().length,
    totalMemoryBytes: os.totalmem(),
    freeMemoryBytes: os.freemem(),
    platform: os.platform(),
    arch: os.arch(),
    nvidiaSmi: commandProbe("nvidia-smi", ["--query-gpu=name,memory.total", "--format=csv,noheader"]),
    vulkanInfo: commandProbe("vulkaninfo", ["--summary"]),
    memoryPressure: os.freemem() / Math.max(1, os.totalmem()) < 0.15 ? "high" : "normal",
  };
}

export function parseLmStudioRuntimeEngines(text) {
  return String(text ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("LLM ENGINE"))
    .map((line) => {
      const columns = line.split(/\s{2,}/).filter(Boolean);
      const name = columns[0] ?? "";
      if (!name) return null;
      const selected = columns.some((column) => column === "yes" || column === "selected" || column.includes("\u2713"));
      const modelFormat = columns.at(-1) ?? "unknown";
      return {
        id: `lmstudio.runtime.${safeId(name)}`,
        kind: "lm_studio_runtime",
        label: name,
        status: "installed",
        selected,
        modelFormat,
        source: "lm_studio_public_lms_runtime_ls",
        processStatus: selected ? "selected" : "installed",
      };
    })
    .filter(Boolean);
}

export function parseLmStudioRuntimeSurvey(text) {
  const lines = String(text ?? "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const selectedRuntime = lines.find((line) => line.startsWith("Survey by "))?.replace(/^Survey by\s+/, "") ?? null;
  const cpu = lines.find((line) => line.startsWith("CPU:"))?.replace(/^CPU:\s*/, "") ?? null;
  const ram = lines.find((line) => line.startsWith("RAM:"))?.replace(/^RAM:\s*/, "") ?? null;
  const accelerators = lines
    .filter((line) => !line.startsWith("Survey by ") && !line.startsWith("GPU/") && !line.startsWith("CPU:") && !line.startsWith("RAM:"))
    .map((line) => {
      const match = line.match(/^(.+?)\s{2,}([0-9.]+\s+[A-Za-z]+)$/);
      if (!match) return null;
      return {
        label: match[1].trim(),
        vram: match[2].trim(),
      };
    })
    .filter(Boolean);
  return { selectedRuntime, cpu, ram, accelerators };
}

export function commandProbe(command, args) {
  const executable = findExecutable(command);
  if (!executable) return { available: false };
  const result = runPublicCommand(executable, args, { timeout: 1200 });
  return {
    available: result.status === 0,
    path: executable,
    exitCode: result.status,
    outputHash: stableHash(`${result.stdout}\n${result.stderr}`),
  };
}

export function findExecutable(command) {
  if (!command) return null;
  if (command.includes(path.sep) && isExecutable(command)) return command;
  for (const dir of String(process.env.PATH ?? "").split(path.delimiter).filter(Boolean)) {
    const candidate = path.join(dir, command);
    if (isExecutable(candidate)) return candidate;
  }
  return null;
}

export function listFiles(dir, suffix) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .map((file) => path.join(dir, file))
    .filter((filePath) => fs.statSync(filePath).isFile() && (!suffix || filePath.endsWith(suffix)))
    .sort();
}

export function readLines(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, "utf8").split(/\r?\n/).filter(Boolean);
}

export function estimateNativeLocalResources(artifact) {
  const sizeBytes = Number(artifact.sizeBytes ?? 0);
  const contextWindow = Number(artifact.contextWindow ?? 8192);
  return {
    sizeBytes,
    contextWindow,
    estimatedVramBytes: Math.max(sizeBytes, 64 * 1024 * 1024) + Math.min(contextWindow, 32768) * 1024,
    backend: "autopilot.native_local.fixture",
    realInference: false,
  };
}
