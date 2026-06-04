import fs from "node:fs";
import path from "node:path";

export function ensureNativeLocalFixtureArtifact(state, checkedAt, deps = {}) {
  const { fileSha256, parseLocalModelMetadata } = deps;
  const fixtureDir = path.join(state.modelRoot, "native-fixture");
  const fixturePath = path.join(fixtureDir, "autopilot-native-fixture.Q4_K_M.gguf");
  fs.mkdirSync(fixtureDir, { recursive: true });
  if (!fs.existsSync(fixturePath)) {
    fs.writeFileSync(
      fixturePath,
      [
        "IOI deterministic native-local model fixture",
        "format=gguf",
        "family=autopilot-native",
        "quantization=Q4_K_M",
        "context=8192",
      ].join("\n"),
    );
  }
  const stats = fs.statSync(fixturePath);
  const metadata = parseLocalModelMetadata(fixturePath);
  return {
    id: "autopilot.native.fixture",
    providerId: "provider.autopilot.local",
    modelId: "autopilot:native-fixture",
    displayName: "Autopilot native local fixture",
    family: metadata.family ?? "autopilot-native",
    format: metadata.format ?? "gguf",
    quantization: metadata.quantization ?? "Q4_K_M",
    sizeBytes: stats.size,
    checksum: fileSha256(fixturePath),
    contextWindow: metadata.contextWindow ?? 8192,
    capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
    privacyClass: "local_private",
    source: "autopilot_native_local_fixture",
    state: "installed",
    artifactPath: fixturePath,
    backendRegistry: state.backendRegistry(),
    discoveredAt: checkedAt,
  };
}

export function discoverLmStudioProvider(state, checkedAt, deps = {}) {
  const {
    env = process.env,
    isExecutable,
    lmStudioPublicCliEnabled,
    runPublicCommand,
    truncate,
  } = deps;
  const publicCliEnabled = lmStudioPublicCliEnabled();
  if (!publicCliEnabled && !env.LM_STUDIO_BASE_URL && !env.LM_STUDIO_URL) {
    return {
      id: "provider.lmstudio",
      kind: "lm_studio",
      label: "LM Studio",
      apiFormat: "openai_compatible",
      driver: "lm_studio",
      baseUrl: "http://127.0.0.1:1234/v1",
      status: "absent",
      privacyClass: "local_private",
      capabilities: ["chat", "responses", "embeddings"],
      discovery: {
        checkedAt,
        evidenceRefs: ["lm_studio_public_cli_discovery_disabled"],
        publicCli: null,
        disabledByDefault: true,
      },
    };
  }
  const candidates = [
    env.IOI_LMS_PATH,
    path.join(state.homeDir, ".local/bin/lm-studio"),
    path.join(state.homeDir, ".local/bin/lm-studio.AppImage"),
    path.join(state.homeDir, ".lmstudio/bin/lms"),
  ].filter(Boolean);
  const executables = candidates.filter((candidate) => isExecutable(candidate));
  const lmsPath = candidates.find((candidate) => path.basename(candidate) === "lms" && isExecutable(candidate));
  const serverStatus = publicCliEnabled && lmsPath ? runPublicCommand(lmsPath, ["server", "status"]) : null;
  const serverStatusText = serverStatus?.stdout ?? serverStatus?.stderr ?? "";
  const baseUrl = env.LM_STUDIO_BASE_URL ?? env.LM_STUDIO_URL ?? "http://127.0.0.1:1234/v1";
  const status = serverStatusText.match(/\b(ON|RUNNING|STARTED)\b/i)
    ? "running"
    : env.LM_STUDIO_BASE_URL || env.LM_STUDIO_URL
      ? "configured"
      : executables.length > 0
      ? "stopped"
      : "absent";
  return {
    id: "provider.lmstudio",
    kind: "lm_studio",
    label: "LM Studio",
    apiFormat: "openai_compatible",
    driver: "lm_studio",
    baseUrl,
    status,
    privacyClass: "local_private",
    capabilities: ["chat", "responses", "embeddings"],
    discovery: {
      checkedAt,
      evidenceRefs: [
        publicCliEnabled ? "lm_studio_public_cli_or_server_probe" : "lm_studio_public_cli_discovery_disabled",
      ],
      executableCandidates: candidates,
      foundExecutables: publicCliEnabled ? executables : [],
      publicCli: publicCliEnabled && lmsPath
        ? {
            path: lmsPath,
            serverStatus: truncate(serverStatusText),
            exitCode: serverStatus?.status ?? null,
          }
        : null,
    },
  };
}

export function discoverLmStudioArtifacts(_state, provider, checkedAt, deps = {}) {
  const {
    lmStudioArtifact,
    lmStudioPublicCliEnabled,
    parseLmStudioList,
    runPublicCommand,
  } = deps;
  if (!lmStudioPublicCliEnabled()) return [];
  const lmsPath = provider.discovery?.publicCli?.path;
  if (!lmsPath) return [];
  const result = runPublicCommand(lmsPath, ["ls"]);
  if (!result || result.status !== 0) return [];
  return parseLmStudioList(result.stdout).map((model) => lmStudioArtifact(provider, model, checkedAt));
}

export function pruneLmStudioPublicProjectionRecords(state) {
  for (const [id, artifact] of state.artifacts.entries()) {
    if (
      artifact.providerId === "provider.lmstudio" ||
      String(id).startsWith("lmstudio.") ||
      String(artifact.source ?? "").startsWith("lm_studio_public")
    ) {
      state.artifacts.delete(id);
    }
  }
  const removedEndpointIds = new Set();
  for (const [id, endpoint] of state.endpoints.entries()) {
    if (endpoint.providerId === "provider.lmstudio" || String(id).includes("provider.lmstudio")) {
      removedEndpointIds.add(id);
      state.endpoints.delete(id);
    }
  }
  for (const [id, instance] of state.instances.entries()) {
    if (instance.providerId === "provider.lmstudio" || removedEndpointIds.has(instance.endpointId)) {
      state.instances.delete(id);
    }
  }
}

export function pruneInternalFixtureProjectionRecords(state, deps = {}) {
  const { isFixtureEndpointCandidate, isFixtureModelRecord } = deps;
  const removedEndpointIds = new Set();
  const removedModelIds = new Set();
  for (const [id, artifact] of state.artifacts.entries()) {
    if (isFixtureModelRecord(artifact) || String(id).includes("fixture") || String(artifact.modelId ?? "").includes("local:auto")) {
      removedModelIds.add(artifact.modelId);
      state.artifacts.delete(id);
    }
  }
  for (const [id, endpoint] of state.endpoints.entries()) {
    if (
      isFixtureEndpointCandidate(endpoint, state.providers.get(endpoint.providerId)) ||
      String(id).includes("fixture") ||
      String(endpoint.modelId ?? "").includes("local:auto")
    ) {
      removedEndpointIds.add(id);
      removedModelIds.add(endpoint.modelId);
      state.endpoints.delete(id);
    }
  }
  for (const [id, instance] of state.instances.entries()) {
    if (
      removedEndpointIds.has(instance.endpointId) ||
      removedModelIds.has(instance.modelId) ||
      isFixtureModelRecord(instance)
    ) {
      state.instances.delete(id);
    }
  }
}
