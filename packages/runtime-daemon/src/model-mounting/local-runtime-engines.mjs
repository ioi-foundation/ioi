import fs from "node:fs";
import path from "node:path";

import { isExecutable } from "./io.mjs";

export function discoverAutopilotLlamaServer(homeDir) {
  const roots = [
    path.join(homeDir, ".local", "share", "ioi", "runtime-engines"),
    path.join(homeDir, ".cache", "ioi", "llama-cpp-live"),
  ];
  const candidates = roots.flatMap((root) => findExecutableByName(root, "llama-server", 5));
  return candidates.sort((left, right) => llamaServerCandidateScore(right) - llamaServerCandidateScore(left))[0] ?? null;
}

export function llamaCppLibraryPathEnv(binaryPath, existing = "") {
  const dirs = llamaCppLibraryDirs(binaryPath);
  return [...dirs, ...String(existing ?? "").split(path.delimiter).filter(Boolean)]
    .filter((dir, index, all) => dir && all.indexOf(dir) === index)
    .join(path.delimiter);
}

export function llamaCppGpuLayersArg(gpu) {
  const raw = String(gpu ?? "").trim();
  const value = raw.toLowerCase();
  if (!value) return null;
  if (["auto", "max", "all", "gpu"].includes(value)) return "999";
  if (["off", "cpu", "false", "none"].includes(value)) return "0";
  return raw;
}

export function backendBindAddress(baseUrl) {
  try {
    const parsed = new URL(baseUrl ?? "http://127.0.0.1:8080/v1");
    return {
      host: parsed.hostname || "127.0.0.1",
      port: parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80,
    };
  } catch {
    return { host: null, port: null };
  }
}

function findExecutableByName(root, name, maxDepth = 4) {
  if (!root || !fs.existsSync(root)) return [];
  const matches = [];
  const visit = (dir, depth) => {
    if (depth > maxDepth) return;
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const candidate = path.join(dir, entry.name);
      if (entry.isFile() && entry.name === name && isExecutable(candidate)) {
        matches.push(candidate);
      } else if (entry.isDirectory() && !entry.name.startsWith(".")) {
        visit(candidate, depth + 1);
      }
    }
  };
  visit(root, 0);
  return matches;
}

function llamaServerCandidateScore(candidate) {
  const binaryDir = path.dirname(candidate ?? "");
  const hasCommonLibBesideBinary = hasFilePrefix(binaryDir, "libllama-common");
  const acceleratorScore = llamaServerAcceleratorScore(binaryDir);
  const hasBackendLibBesideBinary = hasFilePrefix(binaryDir, "libggml-cpu") || acceleratorScore > 0;
  const hasDiscoverableLibraryDir = llamaCppLibraryDirs(candidate).length > 0;
  const underRuntimeEngines = String(candidate ?? "").includes(`${path.sep}runtime-engines${path.sep}`);
  return (
    (hasCommonLibBesideBinary ? 200 : 0) +
    (hasBackendLibBesideBinary ? 150 : 0) +
    acceleratorScore +
    (hasDiscoverableLibraryDir ? 50 : 0) +
    (underRuntimeEngines ? 25 : 0) -
    String(candidate ?? "").length / 1000
  );
}

function llamaServerAcceleratorScore(binaryDir) {
  if (hasFilePrefix(binaryDir, "libggml-cuda")) return 400;
  if (hasFilePrefix(binaryDir, "libggml-vulkan")) return 350;
  if (hasFilePrefix(binaryDir, "libggml-hip")) return 325;
  if (hasFilePrefix(binaryDir, "libggml-kompute")) return 300;
  if (hasFilePrefix(binaryDir, "libggml-opencl")) return 275;
  if (hasFilePrefix(binaryDir, "libggml-sycl")) return 250;
  return 0;
}

function llamaCppLibraryDirs(binaryPath) {
  if (!binaryPath) return [];
  const binaryDir = path.dirname(binaryPath);
  const dirs = [binaryDir, ...childDirsWithFilePrefix(binaryDir, "libllama-common")];
  return dirs.filter((dir, index, all) => dir && all.indexOf(dir) === index);
}

function hasFilePrefix(dir, prefix) {
  if (!dir || !fs.existsSync(dir)) return false;
  try {
    return fs.readdirSync(dir).some((file) => file.startsWith(prefix));
  } catch {
    return false;
  }
}

function childDirsWithFilePrefix(root, prefix) {
  if (!root || !fs.existsSync(root)) return [];
  let entries = [];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(root, entry.name))
    .filter((dir) => {
      try {
        return fs.readdirSync(dir).some((file) => file.startsWith(prefix));
      } catch {
        return false;
      }
    });
}
