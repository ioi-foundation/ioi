#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startRuntimeDaemonService } from "../packages/runtime-daemon/src/index.mjs";
import {
  AUTOPILOT_ELECTRON,
  envFlag,
  syncWorkbenchExtensionTargets,
} from "./lib/autopilot-electron-app-paths.mjs";

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

const DAEMON_SCOPES = [
  "model.chat:*",
  "model.responses:*",
  "model.embeddings:*",
  "model.import:*",
  "model.mount:*",
  "model.unmount:*",
  "model.load:*",
  "model.unload:*",
  "route.write:*",
  "route.use:*",
  "server.control:*",
  "server.logs:*",
  "backend.control:*",
  "provider.control:provider.lmstudio",
  "provider.control:provider.ollama",
];

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
  const daemon = await startRuntimeDaemonService({ cwd: repoRoot, stateDir });
  const grant = await requestJson(daemon.endpoint, "/api/v1/tokens", {
    method: "POST",
    body: { allowed: DAEMON_SCOPES },
  });
  const discovery = await bootstrapLocalModelDiscovery(daemon.endpoint, grant.token);
  const ready = {
    schemaVersion: "ioi.autopilot-ide.daemon-ready.v1",
    endpoint: daemon.endpoint,
    stateDir: daemon.stateDir,
    modelDiscovery: discovery,
    generatedAt: new Date().toISOString(),
  };
  writeFileSync(
    resolve(stateDir, "autopilot-ide-daemon-ready.json"),
    `${JSON.stringify(ready, null, 2)}\n`,
  );
  console.log(
    `[Autopilot IDE] IOI daemon ready at ${daemon.endpoint}; discovered ${discovery.mounted.length} local model mount(s).`,
  );
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
  const copied = sync.copied.map((target) => target.kind).join(", ");
  const skipped = sync.skipped.map((target) => target.kind).join(", ");
  console.log(
    `[Autopilot IDE] Synced ioi-workbench extension into ${copied}.` +
      (skipped ? ` Skipped optional ${skipped}.` : ""),
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
