#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startRuntimeDaemonService } from "../packages/runtime-daemon/src/index.mjs";
import {
  AUTOPILOT_ELECTRON,
  envFlag,
  syncWorkbenchExtensionTargets,
} from "./lib/autopilot-electron-app-paths.mjs";
import { applyAutopilotWorkbenchShellPatch } from "./lib/autopilot-workbench-shell-patch.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");

const binary = AUTOPILOT_ELECTRON.binary;
const extensionSyncEnabled =
  !envFlag("AUTOPILOT_SKIP_EXTENSION_SYNC");
const args = process.argv.slice(2);
const launchArgs = args.length > 0 ? args : [repoRoot];
const managedDaemonEnabled =
  !process.env.IOI_DAEMON_ENDPOINT &&
  !envFlag("AUTOPILOT_SKIP_DAEMON");
const localModelDiscoveryEnabled =
  !envFlag("AUTOPILOT_SKIP_MODEL_AUTODISCOVERY");
const runtimeBridgeEnabled =
  !envFlag("AUTOPILOT_SKIP_RUNTIME_BRIDGE");
const RUNTIME_BRIDGE_ID = "autopilot-ide-runtime-agent-service";
const RUNTIME_BRIDGE_TIMEOUT_MS = "300000";
const RUNTIME_COGNITION_INFERENCE_TIMEOUT_SECS = "140";
const RUNTIME_BRIDGE_ROUTE_ID = "route.local-first";
const DEFAULT_NATIVE_LLAMA_CPP_CONTEXT_LENGTH = 16384;

if (process.env.IOI_LIVE_MODEL_CATALOG === undefined) {
  process.env.IOI_LIVE_MODEL_CATALOG = "1";
}
if (process.env.IOI_MODEL_CATALOG_HF_BASE_URL === undefined) {
  process.env.IOI_MODEL_CATALOG_HF_BASE_URL = "https://huggingface.co";
}

const DAEMON_SCOPES = [
  "model.chat:*",
  "model.responses:*",
  "model.embeddings:*",
  "model.import:*",
  "model.download:*",
  "model.mount:*",
  "model.unmount:*",
  "model.load:*",
  "model.unload:*",
  "route.write:*",
  "route.use:*",
  "server.control:*",
  "server.logs:*",
  "backend.control:*",
  "provider.read:*",
  "provider.write:*",
  "provider.control:provider.lmstudio",
  "provider.control:provider.ollama",
];

function defaultRuntimeBridgeBinary() {
  return resolve(
    repoRoot,
    "target",
    "debug",
    process.platform === "win32" ? "ioi-runtime-bridge.exe" : "ioi-runtime-bridge",
  );
}

function firstNonEmptyEnv(names) {
  for (const name of names) {
    const value = process.env[name];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return null;
}

function setRuntimeEnvDefault(primaryName, aliasNames, value) {
  if (value === undefined || value === null || value === "") return false;
  if (firstNonEmptyEnv([primaryName, ...aliasNames])) return false;
  process.env[primaryName] = String(value);
  return true;
}

function firstMountedModelId(discovery) {
  const mounted = Array.isArray(discovery?.mounted) ? discovery.mounted : [];
  for (const endpoint of mounted) {
    if (!isProductRuntimeEndpoint(endpoint)) {
      continue;
    }
    const modelId = endpoint?.modelId ?? endpoint?.model_id ?? endpoint?.model;
    if (typeof modelId === "string" && modelId.trim()) {
      return modelId.trim();
    }
  }
  return null;
}

function isProductRuntimeEndpoint(endpoint = {}) {
  const haystack = [
    endpoint.id,
    endpoint.modelId,
    endpoint.model_id,
    endpoint.providerId,
    endpoint.provider_id,
    endpoint.backendId,
    endpoint.backend_id,
    endpoint.driver,
    endpoint.apiFormat,
    endpoint.api_format,
    endpoint.artifactId,
    endpoint.artifact_id,
    endpoint.baseUrl,
    endpoint.base_url,
  ]
    .map((value) => String(value || "").toLowerCase())
    .join(" ");
  if (
    !haystack.trim() ||
    haystack.includes("lmstudio:detected") ||
    haystack.includes("lmstudio.detected") ||
    haystack.includes("local:auto") ||
    haystack.includes("autopilot:native-fixture") ||
    haystack.includes("endpoint.local.auto") ||
    haystack.includes("endpoint.autopilot.native-fixture") ||
    /\bfixture\b/.test(haystack)
  ) {
    return false;
  }
  return /provider\.llama-cpp|backend\.llama-cpp|llama_cpp|llama-cpp/.test(haystack);
}

function walkFiles(rootDir, { maxDepth = 5, match } = {}) {
  const results = [];
  const seen = new Set();
  function visit(dir, depth) {
    if (!dir || depth > maxDepth || seen.has(dir)) return;
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

function discoverNativeLlamaServerPath() {
  const configured = firstNonEmptyEnv(["IOI_LLAMA_CPP_SERVER_PATH"]);
  if (configured) return configured;
  const home = process.env.HOME;
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

function discoverNativeGgufModelPath() {
  const configured = firstNonEmptyEnv(["IOI_LLAMA_CPP_MODEL_PATH"]);
  if (configured) return configured;
  const home = process.env.HOME;
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

function inferNativeModelId(modelPath) {
  const configured = firstNonEmptyEnv(["IOI_LLAMA_CPP_MODEL_ID", "IOI_DAEMON_MODEL_ID", "IOI_RUNTIME_MODEL"]);
  if (configured) return configured;
  const normalized = basename(modelPath || "").replace(/\.gguf$/i, "");
  if (/qwen3\.?5.*9b/i.test(normalized)) return "qwen/qwen3.5-9b";
  return normalized || "native:local-gguf";
}

function nativeLlamaCppContextLength() {
  const parsed = Number(firstNonEmptyEnv(["IOI_LLAMA_CPP_CONTEXT_LENGTH"]) ?? DEFAULT_NATIVE_LLAMA_CPP_CONTEXT_LENGTH);
  return Number.isFinite(parsed) && parsed > 0
    ? Math.floor(parsed)
    : DEFAULT_NATIVE_LLAMA_CPP_CONTEXT_LENGTH;
}

function configureNativeLlamaCppEnvDefaults() {
  const serverPath = discoverNativeLlamaServerPath();
  const modelPath = discoverNativeGgufModelPath();
  if (serverPath && !firstNonEmptyEnv(["IOI_LLAMA_CPP_SERVER_PATH"])) {
    process.env.IOI_LLAMA_CPP_SERVER_PATH = serverPath;
  }
  if (modelPath && !firstNonEmptyEnv(["IOI_LLAMA_CPP_MODEL_PATH"])) {
    process.env.IOI_LLAMA_CPP_MODEL_PATH = modelPath;
  }
  return { serverPath, modelPath };
}

function ensureDefaultRuntimeBridgeBinary(command) {
  if (existsSync(command)) return true;
  if (envFlag("AUTOPILOT_SKIP_RUNTIME_BRIDGE_BUILD")) return false;
  console.log(
    `[Autopilot IDE] Building RuntimeAgentService bridge at ${command}.`,
  );
  const result = spawnSync(
    "cargo",
    [
      "build",
      "-p",
      "ioi-node",
      "--bin",
      "ioi-runtime-bridge",
      "--features",
      "local-mode",
    ],
    {
      cwd: repoRoot,
      env: process.env,
      stdio: "inherit",
    },
  );
  return result.status === 0 && existsSync(command);
}

function configureRuntimeBridgeEnv(stateDir) {
  if (!runtimeBridgeEnabled) {
    return { configured: false, reason: "disabled" };
  }

  const configuredCommand = firstNonEmptyEnv([
    "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND",
    "IOI_RUNTIME_BRIDGE_COMMAND",
  ]);
  const command = configuredCommand ?? defaultRuntimeBridgeBinary();
  if (!configuredCommand && !ensureDefaultRuntimeBridgeBinary(command)) {
    console.warn(
      `[Autopilot IDE] RuntimeAgentService bridge not found at ${command}; ` +
        "runtime_service Studio turns will fail until it is built with `cargo build -p ioi-node --bin ioi-runtime-bridge`.",
    );
    return { configured: false, reason: "missing_binary", command };
  }

  const dataDir = resolve(stateDir, "runtime-agent-service-bridge");
  mkdirSync(dataDir, { recursive: true });
  setRuntimeEnvDefault(
    "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND",
    ["IOI_RUNTIME_BRIDGE_COMMAND"],
    command,
  );
  setRuntimeEnvDefault(
    "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS",
    ["IOI_RUNTIME_BRIDGE_ARGS"],
    JSON.stringify(["--data-dir", dataDir, "--workspace", repoRoot]),
  );
  setRuntimeEnvDefault(
    "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID",
    ["IOI_RUNTIME_BRIDGE_ID"],
    RUNTIME_BRIDGE_ID,
  );
  setRuntimeEnvDefault(
    "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_TIMEOUT_MS",
    ["IOI_RUNTIME_BRIDGE_TIMEOUT_MS"],
    RUNTIME_BRIDGE_TIMEOUT_MS,
  );
  setRuntimeEnvDefault(
    "IOI_COGNITION_INFERENCE_TIMEOUT_SECS",
    [],
    RUNTIME_COGNITION_INFERENCE_TIMEOUT_SECS,
  );

  return {
    configured: true,
    command: firstNonEmptyEnv([
      "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND",
      "IOI_RUNTIME_BRIDGE_COMMAND",
    ]),
    dataDir,
    bridgeId: firstNonEmptyEnv([
      "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID",
      "IOI_RUNTIME_BRIDGE_ID",
    ]),
    timeoutMs: Number(
      firstNonEmptyEnv([
        "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_TIMEOUT_MS",
        "IOI_RUNTIME_BRIDGE_TIMEOUT_MS",
      ]) ?? RUNTIME_BRIDGE_TIMEOUT_MS,
    ),
    cognitionTimeoutSecs: Number(
      firstNonEmptyEnv(["IOI_COGNITION_INFERENCE_TIMEOUT_SECS"]) ??
        RUNTIME_COGNITION_INFERENCE_TIMEOUT_SECS,
    ),
  };
}

function configureRuntimeBridgeInferenceEnv(endpoint, token, discovery) {
  if (!endpoint || !token) {
    return { configured: false, reason: "missing_daemon_endpoint" };
  }

  const modelId =
    firstMountedModelId(discovery) ??
    firstNonEmptyEnv([
      "IOI_DAEMON_MODEL_ID",
      "IOI_RUNTIME_AGENT_SERVICE_MODEL",
      "IOI_RUNTIME_MODEL",
    ]) ??
    "auto";
  const inferenceUrl = `${endpoint}/v1/chat/completions`;

  setRuntimeEnvDefault(
    "IOI_RUNTIME_AGENT_SERVICE_INFERENCE_URL",
    ["IOI_RUNTIME_INFERENCE_URL"],
    inferenceUrl,
  );
  setRuntimeEnvDefault(
    "IOI_RUNTIME_AGENT_SERVICE_INFERENCE_API_KEY",
    ["IOI_RUNTIME_INFERENCE_API_KEY"],
    token,
  );
  setRuntimeEnvDefault(
    "IOI_RUNTIME_AGENT_SERVICE_MODEL",
    ["IOI_RUNTIME_MODEL"],
    modelId,
  );
  setRuntimeEnvDefault(
    "IOI_RUNTIME_AGENT_SERVICE_ROUTE_ID",
    ["IOI_RUNTIME_MODEL_ROUTE_ID"],
    RUNTIME_BRIDGE_ROUTE_ID,
  );
  setRuntimeEnvDefault(
    "IOI_RUNTIME_MODEL_ROUTE_ID",
    [],
    RUNTIME_BRIDGE_ROUTE_ID,
  );

  return {
    configured: true,
    inferenceUrl,
    modelId: firstNonEmptyEnv([
      "IOI_RUNTIME_AGENT_SERVICE_MODEL",
      "IOI_RUNTIME_MODEL",
    ]),
    routeId: firstNonEmptyEnv([
      "IOI_RUNTIME_AGENT_SERVICE_ROUTE_ID",
      "IOI_RUNTIME_MODEL_ROUTE_ID",
    ]),
  };
}

function safeId(value) {
  return String(value || "model")
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "model";
}

async function requestJson(endpoint, route, { method = "GET", body, token } = {}) {
  const response = await fetch(`${endpoint}${route}`, {
    method,
    headers: {
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  const json = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(`${method} ${route} -> ${response.status} ${JSON.stringify(json)}`);
  }
  return json;
}

async function discoverProviderModels(endpoint, token, providerId) {
  try {
    const models = await requestJson(
      endpoint,
      `/api/v1/providers/${encodeURIComponent(providerId)}/models`,
      { token },
    );
    return Array.isArray(models) ? models : [];
  } catch (error) {
    console.warn(
      `[Autopilot IDE] ${providerId} model discovery skipped: ${error?.message || String(error)}`,
    );
    return [];
  }
}

async function mountDiscoveredModels(endpoint, token, providerId, models, mountedCount) {
  const mounted = [];
  for (const model of models) {
    const modelId = model?.modelId || model?.id;
    if (!modelId) continue;
    const endpointId =
      providerId === "provider.llama-cpp" && mountedCount + mounted.length === 0
        ? "endpoint.electron.model-gui"
        : `endpoint.autodiscovered.${safeId(providerId)}.${safeId(modelId)}`;
    try {
      const endpointRecord = await requestJson(endpoint, "/api/v1/models/mount", {
        method: "POST",
        token,
        body: {
          id: endpointId,
          model_id: modelId,
          provider_id: providerId,
          load_policy: { mode: "manual", idleTtlSeconds: 900, autoEvict: false },
        },
      });
      mounted.push(endpointRecord);
    } catch (error) {
      console.warn(
        `[Autopilot IDE] ${modelId} mount projection skipped: ${error?.message || String(error)}`,
      );
    }
  }
  return mounted;
}

async function bootstrapConfiguredLlamaCppModel(endpoint, token, mountedCount) {
  configureNativeLlamaCppEnvDefaults();
  const modelPath = discoverNativeGgufModelPath();
  if (!modelPath) {
    return { mounted: [], route: null, loaded: null, reason: "No local GGUF model discovered for llama.cpp" };
  }
  if (!existsSync(modelPath)) {
    console.warn(`[Autopilot IDE] llama.cpp model path does not exist: ${modelPath}`);
    return { mounted: [], route: null, loaded: null, reason: "model_path_missing" };
  }
  if (!firstNonEmptyEnv(["IOI_LLAMA_CPP_MODEL_PATH"])) {
    process.env.IOI_LLAMA_CPP_MODEL_PATH = modelPath;
  }

  const modelId = inferNativeModelId(modelPath);
  const endpointId =
    mountedCount === 0
      ? "endpoint.electron.model-gui"
      : `endpoint.autodiscovered.provider.llama-cpp.${safeId(modelId)}`;
  const contextLength = nativeLlamaCppContextLength();
  const parallel = Number(firstNonEmptyEnv(["IOI_LLAMA_CPP_PARALLEL"]) ?? 1);
  const gpu = firstNonEmptyEnv(["IOI_LLAMA_CPP_GPU"]) ?? "auto";

  await requestJson(endpoint, "/api/v1/models/import", {
    method: "POST",
    token,
    body: {
      model_id: modelId,
      provider_id: "provider.llama-cpp",
      path: modelPath,
      import_mode: "reference",
      context_window: contextLength,
      capabilities: ["chat", "responses"],
    },
  });
  const mounted = await requestJson(endpoint, "/api/v1/models/mount", {
    method: "POST",
    token,
    body: {
      id: endpointId,
      model_id: modelId,
      provider_id: "provider.llama-cpp",
      backend_id: "backend.llama-cpp",
      load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: false },
    },
  });
  const route = await requestJson(endpoint, "/api/v1/routes", {
    method: "POST",
    token,
    body: {
      id: "route.local-first",
      role: "default",
      description: "Autopilot IDE native local model route from configured llama.cpp runtime.",
      privacy: "local_only",
      quality: "local_native",
      fallback: [mounted.id],
      provider_eligibility: ["llama_cpp"],
      denied_providers: ["lm_studio", "ollama", "openai", "anthropic", "gemini"],
      max_cost_usd: 0,
    },
  });
  await requestJson(endpoint, "/api/v1/routes", {
    method: "POST",
    token,
    body: {
      id: "route.native-local",
      role: "default",
      description: "Autopilot-native local route backed by configured llama.cpp runtime.",
      privacy: "local_only",
      quality: "local_native",
      fallback: [mounted.id],
      provider_eligibility: ["llama_cpp"],
      denied_providers: ["lm_studio", "ollama", "openai", "anthropic", "gemini"],
      max_cost_usd: 0,
    },
  });
  const loaded = await requestJson(endpoint, "/api/v1/models/load", {
    method: "POST",
    token,
    body: {
      endpoint_id: mounted.id,
      load_policy: { mode: "manual", autoEvict: false },
      load_options: {
        gpu,
        contextLength,
        parallel,
        ttlSeconds: 900,
        identifier: "autopilot-ide-configured-llama-cpp",
        embeddings: process.env.IOI_LLAMA_CPP_ENABLE_EMBEDDINGS === "1",
      },
    },
  }).catch((error) => {
    console.warn(`[Autopilot IDE] configured llama.cpp pre-load skipped: ${error?.message || String(error)}`);
    return null;
  });

  return { mounted: [mounted], route, loaded, reason: "configured_llama_cpp" };
}

async function bootstrapLocalModelDiscovery(endpoint, token) {
  if (!localModelDiscoveryEnabled) {
    return { providers: [], models: [], mounted: [], route: null };
  }

  const configuredLlamaCpp = await bootstrapConfiguredLlamaCppModel(endpoint, token, 0);
  const referenceProviderDiscoveryEnabled =
    configuredLlamaCpp.mounted.length === 0 ||
    envFlag("AUTOPILOT_INCLUDE_REFERENCE_MODEL_DISCOVERY");
  const providerIds = referenceProviderDiscoveryEnabled
    ? ["provider.lmstudio", "provider.ollama"]
    : [];
  const discovered = [];
  const mounted = [...configuredLlamaCpp.mounted];
  for (const providerId of providerIds) {
    const models = await discoverProviderModels(endpoint, token, providerId);
    discovered.push({ providerId, modelCount: models.length });
    mounted.push(
      ...(await mountDiscoveredModels(endpoint, token, providerId, models, mounted.length)),
    );
  }

  let route = configuredLlamaCpp.route;
  const productMounted = mounted.find((endpointRecord) => isProductRuntimeEndpoint(endpointRecord));
  if (productMounted?.id && configuredLlamaCpp.mounted.length === 0) {
    route = await requestJson(endpoint, "/api/v1/routes", {
      method: "POST",
      token,
      body: {
        id: "route.native-local",
        role: "default",
        description: "Autopilot IDE local model route from startup discovery.",
        privacy: "local_only",
        provider_eligibility: ["llama_cpp"],
        fallback: [productMounted.id],
        denied_providers: ["lm_studio", "ollama", "ioi_native_local", "openai", "anthropic", "gemini"],
      },
    }).catch((error) => {
      console.warn(
        `[Autopilot IDE] route.native-local projection skipped: ${error?.message || String(error)}`,
      );
      return null;
    });
  }

  return { providers: discovered, models: discovered, mounted, route, configuredLlamaCpp };
}

async function startManagedDaemon() {
  if (!managedDaemonEnabled) {
    return {
      daemon: null,
      endpoint: process.env.IOI_DAEMON_ENDPOINT || null,
      token: process.env.IOI_DAEMON_TOKEN || null,
      discovery: null,
    };
  }

  const stateDir = resolve(
    process.env.AUTOPILOT_DAEMON_STATE_DIR || resolve(repoRoot, ".ioi", "autopilot-daemon"),
  );
  mkdirSync(stateDir, { recursive: true });
  configureNativeLlamaCppEnvDefaults();
  const runtimeBridge = configureRuntimeBridgeEnv(stateDir);
  const daemon = await startRuntimeDaemonService({ cwd: repoRoot, stateDir });
  const grant = await requestJson(daemon.endpoint, "/api/v1/tokens", {
    method: "POST",
    body: { allowed: DAEMON_SCOPES },
  });
  const discovery = await bootstrapLocalModelDiscovery(daemon.endpoint, grant.token);
  const runtimeInference = configureRuntimeBridgeInferenceEnv(
    daemon.endpoint,
    grant.token,
    discovery,
  );
  const ready = {
    schemaVersion: "ioi.autopilot-ide.daemon-ready.v1",
    endpoint: daemon.endpoint,
    stateDir: daemon.stateDir,
    modelDiscovery: discovery,
    runtimeBridge,
    runtimeInference: {
      ...runtimeInference,
      token: runtimeInference.configured ? "redacted" : undefined,
    },
    generatedAt: new Date().toISOString(),
  };
  writeFileSync(
    resolve(stateDir, "autopilot-ide-daemon-ready.json"),
    `${JSON.stringify(ready, null, 2)}\n`,
  );
  console.log(
    `[Autopilot IDE] IOI daemon ready at ${daemon.endpoint}; discovered ${discovery.mounted.length} local model mount(s).`,
  );
  if (runtimeBridge.configured) {
    console.log(
      `[Autopilot IDE] RuntimeAgentService bridge wired to ${runtimeBridge.command}; ` +
        `inference route ${runtimeInference.routeId ?? "unconfigured"} model ${runtimeInference.modelId ?? "unconfigured"}.`,
    );
  }
  return { daemon, endpoint: daemon.endpoint, token: grant.token, discovery };
}

if (!existsSync(binary)) {
  console.error(
    `Autopilot VS Code/Electron fork binary not found at ${binary}. Set AUTOPILOT_VSCODE_FORK_BIN to override.`,
  );
  process.exit(1);
}

function syncWorkbenchExtension() {
  if (!extensionSyncEnabled) return;
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  const copied = sync.copied.map((target) => target.kind).join(", ");
  const skipped = sync.skipped.map((target) => target.kind).join(", ");
  console.log(
    `[Autopilot IDE] Synced ioi-workbench extension into ${copied}.` +
      (skipped ? ` Skipped optional ${skipped}.` : "") +
      ` Installed Workbench shell patch at ${shellPatch.installedAt}.`,
  );
}

let managedDaemon = null;
let exiting = false;

syncWorkbenchExtension();
const boot = await startManagedDaemon();
managedDaemon = boot.daemon;

const child = spawn(binary, launchArgs, {
  cwd: repoRoot,
  env: {
    ...process.env,
    IOI_AUTOPILOT_CANONICAL_SHELL: "vscode-electron-fork",
    IOI_WORKBENCH_NATIVE_SHELL: "1",
    ...(boot.endpoint ? { IOI_DAEMON_ENDPOINT: boot.endpoint } : {}),
    ...(boot.token ? { IOI_DAEMON_TOKEN: boot.token } : {}),
    ...(boot.discovery?.mounted?.[0]?.modelId
      ? { IOI_DAEMON_MODEL_ID: boot.discovery.mounted[0].modelId }
      : {}),
  },
  stdio: "inherit",
});

async function closeManagedDaemon() {
  if (!managedDaemon) return;
  const daemon = managedDaemon;
  managedDaemon = null;
  await daemon.close();
}

const forwardSignal = async (signal) => {
  if (exiting) return;
  exiting = true;
  if (!child.killed) {
    child.kill(signal);
  }
  await closeManagedDaemon();
  process.kill(process.pid, signal);
};

process.on("SIGINT", () => forwardSignal("SIGINT"));
process.on("SIGTERM", () => forwardSignal("SIGTERM"));

child.on("exit", async (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  if (code && code !== 0) {
    await closeManagedDaemon();
    process.exit(code);
  }
  if (!managedDaemon) {
    process.exit(code ?? 0);
  }
  console.log("[Autopilot IDE] Electron fork handed off to the desktop session; daemon sidecar remains supervised. Press Ctrl+C to stop it.");
});
