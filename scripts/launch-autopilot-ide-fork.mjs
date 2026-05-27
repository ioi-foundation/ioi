#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
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
const RUNTIME_BRIDGE_TIMEOUT_MS = "120000";
const RUNTIME_BRIDGE_ROUTE_ID = "route.local-first";

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
    const modelId = endpoint?.modelId ?? endpoint?.model_id ?? endpoint?.model;
    if (typeof modelId === "string" && modelId.trim()) {
      return modelId.trim();
    }
  }
  return null;
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
      mountedCount + mounted.length === 0
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

async function bootstrapLocalModelDiscovery(endpoint, token) {
  if (!localModelDiscoveryEnabled) {
    return { providers: [], models: [], mounted: [], route: null };
  }

  const providerIds = ["provider.lmstudio", "provider.ollama"];
  const discovered = [];
  const mounted = [];
  for (const providerId of providerIds) {
    const models = await discoverProviderModels(endpoint, token, providerId);
    discovered.push({ providerId, modelCount: models.length });
    mounted.push(
      ...(await mountDiscoveredModels(endpoint, token, providerId, models, mounted.length)),
    );
  }

  let route = null;
  if (mounted[0]?.id) {
    route = await requestJson(endpoint, "/api/v1/routes", {
      method: "POST",
      token,
      body: {
        id: "route.native-local",
        role: "default",
        description: "Autopilot IDE local model route from startup discovery.",
        privacy: "local_only",
        provider_eligibility: ["lm_studio", "ollama", "ioi_native_local"],
        fallback: [mounted[0].id],
        denied_providers: ["openai", "anthropic", "gemini"],
      },
    }).catch((error) => {
      console.warn(
        `[Autopilot IDE] route.native-local projection skipped: ${error?.message || String(error)}`,
      );
      return null;
    });
  }

  return { providers: discovered, models: discovered, mounted, route };
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
