import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  fileSha256,
  isExecutable,
  notFound,
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

function modelFileScore(filePath) {
  const name = path.basename(filePath).toLowerCase();
  if (name.endsWith(".gguf")) return 3;
  if (name.endsWith(".safetensors")) return 2;
  if (name.endsWith(".onnx") || name.endsWith(".bin")) return 1;
  return 0;
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

function parseModelQuantization(value) {
  return String(value ?? "").match(/\b(Q[0-9]_[A-Za-z0-9_]+|Q[0-9]+|F16|BF16|IQ[0-9]_[A-Za-z0-9_]+)\b/i)?.[1] ?? null;
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
