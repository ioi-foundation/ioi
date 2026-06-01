import { existsSync, readdirSync, statSync } from "node:fs";
import { basename, join } from "node:path";

export const DEFAULT_NATIVE_LLAMA_CPP_CONTEXT_LENGTH = 16384;

function firstNonEmptyEnv(env, names) {
  for (const name of names) {
    const value = env?.[name];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return null;
}

function walkFiles(rootDir, { maxDepth = 5, match } = {}) {
  const results = [];
  const seen = new Set();
  function visit(dir, depth) {
    if (!dir || depth > maxDepth || seen.has(dir) || !existsSync(dir)) return;
    seen.add(dir);
    let entries = [];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        visit(fullPath, depth + 1);
      } else if (!match || match(fullPath, entry.name)) {
        results.push(fullPath);
      }
    }
  }
  visit(rootDir, 0);
  return results;
}

function fileMtimeMs(filePath) {
  try {
    return statSync(filePath).mtimeMs;
  } catch {
    return 0;
  }
}

export function discoverNativeLlamaServerPath({ env = process.env } = {}) {
  const configured = firstNonEmptyEnv(env, ["IOI_LLAMA_CPP_SERVER_PATH"]);
  if (configured) return configured;
  const home = env.HOME || process.env.HOME;
  const roots = [
    home ? join(home, ".cache", "ioi", "llama-cpp-live") : null,
    home ? join(home, ".unsloth", "llama.cpp", "build", "bin") : null,
  ].filter(Boolean);
  const candidates = roots.flatMap((rootDir) =>
    walkFiles(rootDir, {
      maxDepth: 4,
      match: (_fullPath, name) => name === "llama-server",
    }),
  );
  return candidates
    .sort((left, right) => {
      const leftVulkan = /vulkan/i.test(left) ? 1 : 0;
      const rightVulkan = /vulkan/i.test(right) ? 1 : 0;
      if (leftVulkan !== rightVulkan) return rightVulkan - leftVulkan;
      return fileMtimeMs(right) - fileMtimeMs(left);
    })[0] || null;
}

export function discoverNativeGgufModelPath({ env = process.env } = {}) {
  const configured = firstNonEmptyEnv(env, ["IOI_LLAMA_CPP_MODEL_PATH"]);
  if (configured) return configured;
  const home = env.HOME || process.env.HOME;
  const roots = [
    home ? join(home, ".lmstudio", "models") : null,
    home ? join(home, ".cache", "ioi", "models") : null,
    home ? join(home, ".cache", "huggingface", "hub") : null,
  ].filter(Boolean);
  const candidates = roots.flatMap((rootDir) =>
    walkFiles(rootDir, {
      maxDepth: 7,
      match: (fullPath, name) => /\.gguf$/i.test(name) && !/mmproj/i.test(fullPath),
    }),
  );
  return candidates
    .sort((left, right) => {
      const leftQwen = /qwen/i.test(left) ? 1 : 0;
      const rightQwen = /qwen/i.test(right) ? 1 : 0;
      if (leftQwen !== rightQwen) return rightQwen - leftQwen;
      return fileMtimeMs(right) - fileMtimeMs(left);
    })[0] || null;
}

export function inferNativeModelId(modelPath, { env = process.env, fallback = "native:local-gguf" } = {}) {
  const configured = firstNonEmptyEnv(env, ["IOI_LLAMA_CPP_MODEL_ID", "IOI_DAEMON_MODEL_ID", "IOI_RUNTIME_MODEL"]);
  if (configured) return configured;
  const normalized = basename(modelPath || "").replace(/\.gguf$/i, "");
  if (/qwen3\.?5.*9b/i.test(normalized)) return "qwen/qwen3.5-9b";
  return normalized || fallback;
}

export function nativeLlamaCppContextLength({ env = process.env, fallback = DEFAULT_NATIVE_LLAMA_CPP_CONTEXT_LENGTH } = {}) {
  const configured = firstNonEmptyEnv(env, ["IOI_LLAMA_CPP_CONTEXT_LENGTH"]);
  const parsed = Number(configured ?? fallback);
  return Number.isFinite(parsed) && parsed > 0
    ? Math.floor(parsed)
    : DEFAULT_NATIVE_LLAMA_CPP_CONTEXT_LENGTH;
}

export function configureNativeLlamaCppEnvDefaults({ env = process.env } = {}) {
  const serverPath = discoverNativeLlamaServerPath({ env });
  const modelPath = discoverNativeGgufModelPath({ env });
  if (serverPath && !firstNonEmptyEnv(env, ["IOI_LLAMA_CPP_SERVER_PATH"])) {
    env.IOI_LLAMA_CPP_SERVER_PATH = serverPath;
  }
  if (modelPath && !firstNonEmptyEnv(env, ["IOI_LLAMA_CPP_MODEL_PATH"])) {
    env.IOI_LLAMA_CPP_MODEL_PATH = modelPath;
  }
  return {
    serverPath: firstNonEmptyEnv(env, ["IOI_LLAMA_CPP_SERVER_PATH"]) || serverPath,
    modelPath: firstNonEmptyEnv(env, ["IOI_LLAMA_CPP_MODEL_PATH"]) || modelPath,
  };
}
