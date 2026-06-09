export function seedModelMountingDefaults(state, deps = {}) {
  const {
    defaultRouteRecords,
    discoverAutopilotLlamaServer,
    env = process.env,
    findExecutable,
    hostedProvider,
    internalFixtureModelsEnabled,
    localFixtureArtifactRecords,
    localFixtureEndpointRecord,
    localFolderProviderRecord,
    nativeFixtureEndpointRecord,
    nativeLocalProviderRecord,
    runtimeProviderRecords,
    stableHash,
  } = deps;

  const checkedAt = state.nowIso();
  const localProvider = localFolderProviderRecord(checkedAt);
  state.upsertDefault(state.providers, localProvider);

  const nativeLocalProvider = nativeLocalProviderRecord(checkedAt);
  state.upsertDefault(state.providers, nativeLocalProvider);

  state.pruneLmStudioPublicProjectionRecords();
  if (!internalFixtureModelsEnabled()) {
    state.pruneInternalFixtureProjectionRecords();
  }

  const llamaBinary =
    env.IOI_LLAMA_CPP_SERVER_PATH ??
    discoverAutopilotLlamaServer(state.homeDir) ??
    findExecutable("llama-server");
  const vllmBinary = env.IOI_VLLM_BINARY ?? findExecutable("vllm");
  for (const provider of runtimeProviderRecords({
    checkedAt,
    hostedProvider,
    llamaBinary,
    stableHash,
    vllmBinary,
  })) {
    state.upsertDefault(state.providers, provider);
  }

  state.seedBackends(checkedAt);

  let nativeFixtureArtifact = null;
  if (internalFixtureModelsEnabled()) {
    for (const artifact of localFixtureArtifactRecords(checkedAt)) {
      state.upsertDefault(state.artifacts, artifact);
    }
    nativeFixtureArtifact = state.ensureNativeLocalFixtureArtifact(checkedAt);
    state.upsertDefault(state.artifacts, nativeFixtureArtifact);
  }
  if (internalFixtureModelsEnabled()) {
    state.upsertDefault(state.endpoints, localFixtureEndpointRecord(checkedAt));
    state.upsertDefault(state.endpoints, nativeFixtureEndpointRecord({
      artifact: nativeFixtureArtifact,
      backendRegistry: state.backendRegistry(),
      checkedAt,
    }));
  }

  for (const route of defaultRouteRecords()) {
    state.upsertDefault(state.routes, route);
  }
}
