export function localFolderProviderRecord(checkedAt) {
  return {
    id: "provider.local.folder",
    kind: "local_folder",
    label: "Local model folder",
    apiFormat: "fixture",
    driver: "fixture",
    baseUrl: "local://models",
    status: "available",
    privacyClass: "local_private",
    capabilities: ["chat", "embeddings", "structured_output", "rerank"],
    discovery: {
      checkedAt,
      evidenceRefs: ["agentgres_model_registry_fixture"],
    },
  };
}

export function nativeLocalProviderRecord(checkedAt) {
  return {
    id: "provider.autopilot.local",
    kind: "ioi_native_local",
    label: "Autopilot native local",
    apiFormat: "ioi_native",
    driver: "native_local",
    baseUrl: "local://ioi-native/model-server",
    status: "available",
    privacyClass: "local_private",
    capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
    discovery: {
      checkedAt,
      evidenceRefs: ["autopilot_native_local_backend_registry", "deterministic_native_local_fixture"],
    },
  };
}

export function runtimeProviderRecords({
  checkedAt,
  llamaBinary,
  stableHash = (value) => String(value),
  vllmBinary,
  hostedProvider = (id, label, apiFormat, { secret_ref = `vault://${id}/api-key` } = {}) => ({
    id,
    label,
    apiFormat,
    status: "blocked",
    secret_ref,
  }),
} = {}) {
  return [
    {
      id: "provider.ollama",
      kind: "ollama",
      label: "Ollama",
      apiFormat: "ollama",
      driver: "ollama",
      baseUrl: process.env.OLLAMA_HOST ?? "http://127.0.0.1:11434",
      status: process.env.OLLAMA_HOST ? "configured" : "blocked",
      privacyClass: "local_private",
      capabilities: ["chat", "responses", "embeddings"],
      discovery: { checkedAt, evidenceRefs: ["OLLAMA_HOST"] },
    },
    {
      id: "provider.llama-cpp",
      kind: "llama_cpp",
      label: "llama.cpp",
      apiFormat: "openai_compatible",
      driver: "llama_cpp",
      baseUrl: process.env.IOI_LLAMA_CPP_BASE_URL ?? "http://127.0.0.1:8080/v1",
      status: process.env.IOI_LLAMA_CPP_BASE_URL || llamaBinary ? "configured" : "blocked",
      privacyClass: "local_private",
      capabilities: ["chat", "responses", "embeddings"],
      discovery: {
        checkedAt,
        evidenceRefs: [
          "IOI_LLAMA_CPP_BASE_URL",
          "IOI_LLAMA_CPP_SERVER_PATH",
          ...(llamaBinary ? ["autopilot_llama_cpp_runtime_engine_detected"] : []),
        ],
        binaryPathHash: llamaBinary ? stableHash(llamaBinary) : null,
      },
    },
    {
      id: "provider.vllm",
      kind: "vllm",
      label: "vLLM",
      apiFormat: "openai_compatible",
      driver: "vllm",
      baseUrl: process.env.VLLM_BASE_URL ?? "http://127.0.0.1:8000/v1",
      status: process.env.VLLM_BASE_URL || vllmBinary ? "configured" : "blocked",
      privacyClass: "workspace",
      capabilities: ["chat", "responses", "embeddings"],
      discovery: { checkedAt, evidenceRefs: ["VLLM_BASE_URL", vllmBinary ? "vllm_binary_detected" : "IOI_VLLM_BINARY"] },
    },
    {
      id: "provider.openai-compatible",
      kind: "openai_compatible",
      label: "OpenAI-compatible endpoint",
      apiFormat: "openai_compatible",
      driver: "openai_compatible",
      baseUrl: process.env.OPENAI_COMPATIBLE_BASE_URL ?? "http://127.0.0.1:1234/v1",
      status: process.env.OPENAI_COMPATIBLE_BASE_URL ? "configured" : "blocked",
      privacyClass: "workspace",
      capabilities: ["chat", "responses", "embeddings"],
      discovery: { checkedAt, evidenceRefs: ["OPENAI_COMPATIBLE_BASE_URL"] },
    },
    hostedProvider("provider.openai", "OpenAI", "openai", {
      secret_ref: "vault://provider.openai/api-key",
    }),
    hostedProvider("provider.anthropic", "Anthropic", "anthropic", {
      secret_ref: "vault://provider.anthropic/api-key",
    }),
    hostedProvider("provider.gemini", "Gemini", "gemini", {
      secret_ref: "vault://provider.gemini/api-key",
    }),
    {
      id: "provider.custom-http",
      kind: "custom_http",
      label: "Custom HTTP endpoint",
      apiFormat: "custom",
      driver: "openai_compatible",
      baseUrl: process.env.IOI_CUSTOM_MODEL_ENDPOINT ?? null,
      status: process.env.IOI_CUSTOM_MODEL_ENDPOINT ? "configured" : "blocked",
      privacyClass: "workspace",
      capabilities: ["chat"],
      discovery: { checkedAt, evidenceRefs: ["IOI_CUSTOM_MODEL_ENDPOINT"] },
    },
    {
      id: "provider.depin-tee",
      kind: "depin_tee",
      label: "DePIN / TEE runtime",
      apiFormat: "runtime_contract",
      driver: "fixture",
      baseUrl: null,
      status: "future",
      privacyClass: "remote_confidential",
      capabilities: ["chat", "code", "receipts"],
      discovery: { checkedAt, evidenceRefs: ["future_runtime_profile"] },
    },
  ];
}

export function localFixtureArtifactRecords(checkedAt) {
  return [
    {
      id: "local.auto",
      providerId: "provider.local.folder",
      modelId: "local:auto",
      displayName: "IOI local fixture model",
      family: "fixture",
      quantization: "fixture",
      sizeBytes: 0,
      contextWindow: 8192,
      capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
      privacyClass: "local_private",
      source: "deterministic_fixture",
      state: "installed",
      discoveredAt: checkedAt,
    },
    {
      id: "local.embedding.fixture",
      providerId: "provider.local.folder",
      modelId: "local:embedding-fixture",
      displayName: "IOI local embedding fixture",
      family: "fixture",
      quantization: "fixture",
      sizeBytes: 0,
      contextWindow: 2048,
      capabilities: ["embeddings"],
      privacyClass: "local_private",
      source: "deterministic_fixture",
      state: "installed",
      discoveredAt: checkedAt,
    },
  ];
}

export function localFixtureEndpointRecord(checkedAt) {
  return {
    id: "endpoint.local.auto",
    providerId: "provider.local.folder",
    modelId: "local:auto",
    apiFormat: "ioi_fixture",
    driver: "fixture",
    baseUrl: "local://ioi-daemon/model-fixture",
    capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
    privacyClass: "local_private",
    loadPolicy: {
      mode: "on_demand",
      idleTtlSeconds: 900,
      autoEvict: true,
    },
    status: "mounted",
    mountedAt: checkedAt,
  };
}

export function nativeFixtureEndpointRecord({ artifact, checkedAt } = {}) {
  return {
    id: "endpoint.autopilot.native-fixture",
    providerId: "provider.autopilot.local",
    modelId: artifact.modelId,
    apiFormat: "ioi_native",
    driver: "native_local",
    baseUrl: "local://ioi-native/model-server",
    capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
    privacyClass: "local_private",
    loadPolicy: {
      mode: "on_demand",
      idleTtlSeconds: 900,
      autoEvict: true,
    },
    status: "mounted",
    mountedAt: checkedAt,
  };
}

export function defaultRouteRecords() {
  return [
    {
      id: "route.local-first",
      role: "default",
      description: "Local/private first route with hosted fallback blocked unless policy allows it.",
      privacy: "local_or_enterprise",
      quality: "adaptive",
      maxCostUsd: 0.25,
      maxLatencyMs: 30000,
      providerEligibility: ["local_folder", "lm_studio", "ollama", "vllm", "openai_compatible"],
      fallback: [],
      deniedProviders: ["openai", "anthropic", "gemini"],
      status: "active",
      lastSelectedModel: null,
      lastReceiptId: null,
    },
    {
      id: "route.native-local",
      role: "default",
      description: "Autopilot-native local route that does not require LM Studio.",
      privacy: "local_only",
      quality: "native_local",
      maxCostUsd: 0,
      maxLatencyMs: 30000,
      providerEligibility: ["ioi_native_local"],
      fallback: [],
      deniedProviders: ["openai", "anthropic", "gemini", "lm_studio"],
      status: "active",
      lastSelectedModel: null,
      lastReceiptId: null,
    },
  ];
}
