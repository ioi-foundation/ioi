import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  configureNativeLlamaCppEnvDefaults,
  inferNativeModelId,
  nativeLlamaCppContextLength,
} from "./native-llama-cpp-discovery.mjs";

export const DEFAULT_RUNTIME_COGNITION_TIMEOUT_SECS = 140;
export const DEFAULT_RUNTIME_MODEL_ID = "stories260k";
export const DEFAULT_RUNTIME_ENDPOINT_ID = "endpoint.stories260k";
export const DEFAULT_RUNTIME_ROUTE_ID = "route.local-first";
export const DEFAULT_RUNTIME_PROVIDER_ID = "provider.autopilot.local";
export const DEFAULT_RUNTIME_BACKEND_ID = "backend.autopilot.native-local.fixture";

function truthyEnv(value) {
  return /^(1|true|yes|on)$/i.test(String(value || "").trim());
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
  const forceNativeFixture = truthyEnv(process.env.IOI_FORCE_NATIVE_FIXTURE_MODEL_ROUTE);
  if (!forceNativeFixture) {
    configureNativeLlamaCppEnvDefaults({ env: process.env });
  }
  const configuredLlamaCppModelPath = forceNativeFixture
    ? null
    : firstNonEmptyEnv(process.env, [
      "IOI_LLAMA_CPP_MODEL_PATH",
    ]);
  if (configuredLlamaCppModelPath) {
    if (!existsSync(configuredLlamaCppModelPath)) {
      throw new Error(`Configured llama.cpp model path does not exist: ${configuredLlamaCppModelPath}`);
    }
    const llamaModelId =
      firstNonEmptyEnv(process.env, [
        "IOI_LLAMA_CPP_MODEL_ID",
        "IOI_DAEMON_MODEL_ID",
        "IOI_RUNTIME_MODEL",
      ]) ?? inferNativeModelId(configuredLlamaCppModelPath, { env: process.env, fallback: modelId });
    const llamaEndpointId =
      firstNonEmptyEnv(process.env, ["IOI_LLAMA_CPP_ENDPOINT_ID"]) ?? "endpoint.electron.model-gui";
    const llamaRouteId =
      firstNonEmptyEnv(process.env, [
        "IOI_LLAMA_CPP_ROUTE_ID",
        "IOI_RUNTIME_MODEL_ROUTE_ID",
      ]) ?? routeId;
    const contextLength = nativeLlamaCppContextLength({ env: process.env });
    const parallel = Number(firstNonEmptyEnv(process.env, ["IOI_LLAMA_CPP_PARALLEL"]) ?? 1);
    const gpu = firstNonEmptyEnv(process.env, ["IOI_LLAMA_CPP_GPU"]) ?? "auto";

    const imported = await requestJson(daemonEndpoint, "/v1/model-mount/artifacts/import", {
      method: "POST",
      token,
      body: {
        model_id: llamaModelId,
        provider_id: "provider.llama-cpp",
        path: configuredLlamaCppModelPath,
        import_mode: "reference",
        context_window: contextLength,
        capabilities: ["chat", "responses", "structured_output", "code"],
      },
    });
    const mounted = await requestJson(daemonEndpoint, "/v1/model-mount/endpoints", {
      method: "POST",
      token,
      body: {
        id: llamaEndpointId,
        model_id: llamaModelId,
        provider_id: "provider.llama-cpp",
        backend_id: "backend.llama-cpp",
        load_policy: { mode: "on_demand", idle_ttl_seconds: 900, auto_evict: false },
      },
    });
    const loaded = await requestJson(daemonEndpoint, "/v1/model-mount/instances/load", {
      method: "POST",
      token,
      body: {
        endpoint_id: mounted.id,
        load_policy: { mode: "manual", auto_evict: false },
        load_options: {
          gpu,
          context_length: contextLength,
          parallel,
          ttl_seconds: 900,
          identifier: "autopilot-native-llama-cpp-validation",
          embeddings: process.env.IOI_LLAMA_CPP_ENABLE_EMBEDDINGS === "1",
        },
      },
    });
    const route = await requestJson(daemonEndpoint, "/v1/model-mount/routes", {
      method: "POST",
      token,
      body: {
        id: llamaRouteId,
        role: "agent",
        description: "Autopilot-native local route backed by configured llama.cpp runtime.",
        privacy: "local_only",
        quality: "local_native",
        max_cost_usd: 0,
        fallback: [mounted.id],
        provider_eligibility: ["llama_cpp"],
        denied_providers: [
          "lm_studio",
          "ollama",
          "openai",
          "anthropic",
          "gemini",
          "vllm",
          "custom_http",
          "openai_compatible",
          "ioi_fixture",
          "ioi_native_local",
        ],
      },
    });
    const routeTest = await requestJson(daemonEndpoint, `/v1/model-mount/routes/${llamaRouteId}/test`, {
      method: "POST",
      token,
      body: {
        capability: "chat",
        model: llamaModelId,
        model_policy: {
          privacy: "local_only",
          deny_fixture_models: true,
          denied_backends: ["fixture", "ioi_fixture"],
          denied_providers: ["provider.autopilot.local", "provider.local.folder"],
        },
      },
    });

    return {
      modelId: llamaModelId,
      endpointId: mounted.id,
      routeId: route.id,
      providerId: "provider.llama-cpp",
      backendId: "backend.llama-cpp",
      artifactPath: configuredLlamaCppModelPath,
      importedId: imported.id,
      mountedEndpointId: mounted.id,
      loadInstanceId: loaded.id,
      loadStatus: loaded.status,
      loadedBackendId: loaded.backendId,
      routeProviderEligibility: route.provider_eligibility || route.providerEligibility,
      routeDeniedProviders: route.denied_providers || route.deniedProviders,
      routeTestEndpointId: routeTest.selection?.endpoint?.id,
      routeTestBackendId: routeTest.selection?.backend?.id,
      runtimeEngine: "autopilot_native_llama_cpp",
      fixtureFree: true,
    };
  }

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

  const imported = await requestJson(daemonEndpoint, "/v1/model-mount/artifacts/import", {
    method: "POST",
    token,
    body: {
      model_id: modelId,
      provider_id: providerId,
      path: artifactPath,
      capabilities: ["chat", "responses", "embeddings", "structured_output", "code"],
    },
  });
  const mounted = await requestJson(daemonEndpoint, "/v1/model-mount/endpoints", {
    method: "POST",
    token,
    body: {
      id: endpointId,
      model_id: modelId,
      provider_id: providerId,
      backend_id: backendId,
    },
  });
  const estimate = await requestJson(daemonEndpoint, "/v1/model-mount/instances/load", {
    method: "POST",
    token,
    body: {
      endpoint_id: endpointId,
      estimate_only: true,
      load_policy: { mode: "on_demand", idle_ttl_seconds: 900, auto_evict: true },
      load_options: {
        estimate_only: true,
        gpu: "auto",
        context_length: 4096,
        parallel: 2,
        ttl_seconds: 900,
        identifier: modelId,
      },
    },
  });
  const loaded = await requestJson(daemonEndpoint, "/v1/model-mount/instances/load", {
    method: "POST",
    token,
    body: {
      endpoint_id: endpointId,
      load_policy: { mode: "on_demand", idle_ttl_seconds: 900, auto_evict: true },
      load_options: {
        gpu: "auto",
        context_length: 4096,
        parallel: 2,
        ttl_seconds: 900,
        identifier: modelId,
      },
    },
  });
  const route = await requestJson(daemonEndpoint, "/v1/model-mount/routes", {
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
  const routeTest = await requestJson(daemonEndpoint, `/v1/model-mount/routes/${routeId}/test`, {
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
