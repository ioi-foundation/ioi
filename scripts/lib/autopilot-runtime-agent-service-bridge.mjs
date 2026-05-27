import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

export const DEFAULT_RUNTIME_BRIDGE_ID = "autopilot-ide-runtime-agent-service";
export const DEFAULT_RUNTIME_BRIDGE_TIMEOUT_MS = 120_000;
export const DEFAULT_RUNTIME_MODEL_ID = "stories260k";
export const DEFAULT_RUNTIME_ENDPOINT_ID = "endpoint.stories260k";
export const DEFAULT_RUNTIME_ROUTE_ID = "route.local-first";
export const DEFAULT_RUNTIME_PROVIDER_ID = "provider.autopilot.local";
export const DEFAULT_RUNTIME_BACKEND_ID = "backend.autopilot.native-local.fixture";

export function defaultRuntimeBridgeBinary(repoRoot) {
  return resolve(
    repoRoot,
    "target",
    "debug",
    process.platform === "win32" ? "ioi-runtime-bridge.exe" : "ioi-runtime-bridge",
  );
}

export function firstNonEmptyEnv(env, names) {
  for (const name of names) {
    const value = env[name];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return null;
}

function setEnvValue(env, primaryName, aliasNames, value, { overwrite = false } = {}) {
  if (value === undefined || value === null || value === "") return false;
  if (!overwrite && firstNonEmptyEnv(env, [primaryName, ...aliasNames])) return false;
  env[primaryName] = String(value);
  return true;
}

export function ensureDefaultRuntimeBridgeBinary({
  repoRoot,
  command = defaultRuntimeBridgeBinary(repoRoot),
  env = process.env,
  build = true,
  stdio = "inherit",
} = {}) {
  if (existsSync(command)) {
    return { ok: true, built: false, command };
  }
  if (!build) {
    return { ok: false, built: false, command, reason: "missing_binary" };
  }
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
      env,
      stdio,
    },
  );
  return {
    ok: result.status === 0 && existsSync(command),
    built: true,
    command,
    status: result.status,
    signal: result.signal,
  };
}

export function configureRuntimeAgentServiceBridgeEnv({
  repoRoot,
  stateDir,
  env = process.env,
  bridgeId = DEFAULT_RUNTIME_BRIDGE_ID,
  timeoutMs = DEFAULT_RUNTIME_BRIDGE_TIMEOUT_MS,
  overwrite = false,
  build = true,
} = {}) {
  const configuredCommand = firstNonEmptyEnv(env, [
    "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND",
    "IOI_RUNTIME_BRIDGE_COMMAND",
  ]);
  const command = configuredCommand ?? defaultRuntimeBridgeBinary(repoRoot);
  const binary = configuredCommand
    ? { ok: true, built: false, command }
    : ensureDefaultRuntimeBridgeBinary({ repoRoot, command, env, build });
  if (!binary.ok) {
    return { configured: false, reason: binary.reason || "missing_binary", binary };
  }

  const dataDir = resolve(stateDir, "runtime-agent-service-bridge");
  mkdirSync(dataDir, { recursive: true });
  setEnvValue(env, "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", ["IOI_RUNTIME_BRIDGE_COMMAND"], command, { overwrite });
  setEnvValue(
    env,
    "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS",
    ["IOI_RUNTIME_BRIDGE_ARGS"],
    JSON.stringify(["--data-dir", dataDir, "--workspace", repoRoot]),
    { overwrite },
  );
  setEnvValue(env, "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", ["IOI_RUNTIME_BRIDGE_ID"], bridgeId, { overwrite });
  setEnvValue(
    env,
    "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_TIMEOUT_MS",
    ["IOI_RUNTIME_BRIDGE_TIMEOUT_MS"],
    String(timeoutMs),
    { overwrite },
  );

  return {
    configured: true,
    command: firstNonEmptyEnv(env, ["IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", "IOI_RUNTIME_BRIDGE_COMMAND"]),
    dataDir,
    bridgeId: firstNonEmptyEnv(env, ["IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", "IOI_RUNTIME_BRIDGE_ID"]),
    timeoutMs: Number(
      firstNonEmptyEnv(env, [
        "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_TIMEOUT_MS",
        "IOI_RUNTIME_BRIDGE_TIMEOUT_MS",
      ]) ?? timeoutMs,
    ),
    binary,
  };
}

export function configureRuntimeAgentServiceInferenceEnv({
  daemonEndpoint,
  token,
  modelId = DEFAULT_RUNTIME_MODEL_ID,
  routeId = DEFAULT_RUNTIME_ROUTE_ID,
  env = process.env,
  overwrite = false,
} = {}) {
  if (!daemonEndpoint || !token) {
    return { configured: false, reason: "missing_daemon_endpoint_or_token" };
  }
  const inferenceUrl = `${daemonEndpoint}/v1/chat/completions`;
  setEnvValue(env, "IOI_RUNTIME_AGENT_SERVICE_INFERENCE_URL", ["IOI_RUNTIME_INFERENCE_URL"], inferenceUrl, { overwrite });
  setEnvValue(env, "IOI_RUNTIME_AGENT_SERVICE_INFERENCE_API_KEY", ["IOI_RUNTIME_INFERENCE_API_KEY"], token, { overwrite });
  setEnvValue(env, "IOI_RUNTIME_AGENT_SERVICE_MODEL", ["IOI_RUNTIME_MODEL"], modelId, { overwrite });
  setEnvValue(env, "IOI_RUNTIME_AGENT_SERVICE_ROUTE_ID", ["IOI_RUNTIME_MODEL_ROUTE_ID"], routeId, { overwrite });
  setEnvValue(env, "IOI_RUNTIME_MODEL_ROUTE_ID", [], routeId, { overwrite });

  return {
    configured: true,
    inferenceUrl,
    modelId: firstNonEmptyEnv(env, ["IOI_RUNTIME_AGENT_SERVICE_MODEL", "IOI_RUNTIME_MODEL"]),
    routeId: firstNonEmptyEnv(env, ["IOI_RUNTIME_AGENT_SERVICE_ROUTE_ID", "IOI_RUNTIME_MODEL_ROUTE_ID"]),
  };
}

export async function requestJson(endpoint, route, { method = "GET", body, token } = {}) {
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

export async function bootstrapNativeRuntimeModelRoute({
  repoRoot,
  daemonEndpoint,
  token,
  workspaceDir,
  modelId = DEFAULT_RUNTIME_MODEL_ID,
  endpointId = DEFAULT_RUNTIME_ENDPOINT_ID,
  routeId = DEFAULT_RUNTIME_ROUTE_ID,
  providerId = DEFAULT_RUNTIME_PROVIDER_ID,
  backendId = DEFAULT_RUNTIME_BACKEND_ID,
} = {}) {
  const artifactDir = workspaceDir || join(repoRoot, ".ioi", "autopilot-runtime-fixtures");
  mkdirSync(artifactDir, { recursive: true });
  const artifactPath = join(artifactDir, `${modelId.replace(/[^a-zA-Z0-9_.-]+/g, "-")}.Q4_K_M.gguf`);
  writeFileSync(
    artifactPath,
    [
      `family=${modelId}`,
      "quantization=Q4_K_M",
      "context=4096",
      "fixture=daemon-owned-runtime-agent-service-route",
    ].join("\n"),
  );

  const imported = await requestJson(daemonEndpoint, "/api/v1/models/import", {
    method: "POST",
    token,
    body: {
      model_id: modelId,
      provider_id: providerId,
      path: artifactPath,
      capabilities: ["chat", "responses", "embeddings", "structured_output", "code"],
    },
  });
  const mounted = await requestJson(daemonEndpoint, "/api/v1/models/mount", {
    method: "POST",
    token,
    body: {
      id: endpointId,
      model_id: modelId,
      provider_id: providerId,
      backend_id: backendId,
    },
  });
  const estimate = await requestJson(daemonEndpoint, "/api/v1/models/load", {
    method: "POST",
    token,
    body: {
      endpoint_id: endpointId,
      estimate_only: true,
      load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true },
      load_options: {
        estimateOnly: true,
        gpu: "auto",
        contextLength: 4096,
        parallel: 2,
        ttlSeconds: 900,
        identifier: modelId,
      },
    },
  });
  const loaded = await requestJson(daemonEndpoint, "/api/v1/models/load", {
    method: "POST",
    token,
    body: {
      endpoint_id: endpointId,
      load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true },
      load_options: {
        gpu: "auto",
        contextLength: 4096,
        parallel: 2,
        ttlSeconds: 900,
        identifier: modelId,
      },
    },
  });
  const route = await requestJson(daemonEndpoint, "/api/v1/routes", {
    method: "POST",
    token,
    body: {
      id: routeId,
      role: "agent",
      privacy: "local_only",
      max_cost_usd: 0,
      fallback: [endpointId],
      provider_eligibility: ["ioi_native_local"],
      denied_providers: [
        "openai",
        "anthropic",
        "gemini",
        "lm_studio",
        "ollama",
        "vllm",
        "custom_http",
        "openai_compatible",
      ],
    },
  });
  const routeTest = await requestJson(daemonEndpoint, `/api/v1/routes/${routeId}/test`, {
    method: "POST",
    token,
    body: { capability: "chat", model_policy: { privacy: "local_only" } },
  });

  return {
    modelId,
    endpointId,
    routeId,
    providerId,
    backendId,
    artifactPath,
    importedId: imported.id,
    mountedEndpointId: mounted.id,
    estimateStatus: estimate.status,
    loadInstanceId: loaded.id,
    loadStatus: loaded.status,
    loadedBackendId: loaded.backendId,
    routeProviderEligibility: route.provider_eligibility || route.providerEligibility,
    routeDeniedProviders: route.denied_providers || route.deniedProviders,
    routeTestEndpointId: routeTest.selection?.endpoint?.id,
    routeTestBackendId: routeTest.selection?.backend?.id,
  };
}
