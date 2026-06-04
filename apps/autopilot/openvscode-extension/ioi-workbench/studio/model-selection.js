"use strict";

function createStudioModelSelection({
  daemonEndpoint,
  firstArray,
  getEnv,
  getStudioRuntimeProjection,
  isAutoStudioModelSelector,
  modelDisplayName,
  modelEndpointForArtifact,
  modelInstanceForEndpoint,
  modelSnapshotFromState,
  productModelUnavailable,
  stringValue,
  studioDefaultArtifactMaxOutputTokens,
  studioDefaultMaxOutputTokens,
  studioFixtureModelUsageAllowed,
  studioTextContainsProductFixtureMarker,
}) {
  function isFixtureStudioModelRecord(record = {}) {
    const haystack = [
      record.id,
      record.modelId,
      record.model_id,
      record.providerId,
      record.provider_id,
      record.backendId,
      record.backend_id,
      record.artifactId,
      record.artifact_id,
      record.name,
      record.label,
      record.displayName,
      record.display_name,
      record.description,
      record.family,
      record.source,
      record.quantization,
      record.driver,
      record.apiFormat,
      record.api_format,
      record.baseUrl,
      record.base_url,
      record.status,
      record.state,
    ].map((value) => String(value || "").toLowerCase()).join(" ");
    return (
      /\bfixture\b/.test(haystack) ||
      haystack.includes("local:auto") ||
      haystack.includes("autopilot:native-fixture") ||
      haystack.includes("endpoint.local.auto") ||
      haystack.includes("endpoint.autopilot.native-fixture") ||
      haystack.includes("lmstudio:detected") ||
      haystack.includes("lmstudio.detected") ||
      haystack.includes("detected model slot") ||
      haystack.includes("lm_studio_public_discovery") ||
      haystack.includes("provider_stopped")
    );
  }

  function studioExternalModelProviderUsageAllowed() {
    return /^(1|true|yes|on)$/i.test(String(getEnv("IOI_STUDIO_ALLOW_EXTERNAL_MODEL_PROVIDERS") || ""));
  }

  function isExternalStudioModelRecord(record = {}) {
    if (studioExternalModelProviderUsageAllowed()) {
      return false;
    }
    const haystack = [
      record.id,
      record.modelId,
      record.model_id,
      record.providerId,
      record.provider_id,
      record.backendId,
      record.backend_id,
      record.family,
      record.source,
      record.driver,
      record.apiFormat,
      record.api_format,
      record.baseUrl,
      record.base_url,
      record.description,
    ].map((value) => String(value || "").toLowerCase()).join(" ");
    return (
      haystack.includes("provider.lmstudio") ||
      haystack.includes("backend.lmstudio") ||
      haystack.includes("lm_studio") ||
      haystack.includes("lm-studio") ||
      haystack.includes("provider.ollama") ||
      haystack.includes("backend.ollama")
    );
  }

  function modelRecordSupportsChat(record = {}) {
    const capabilities = Array.isArray(record.capabilities) ? record.capabilities : [];
    return capabilities.length === 0 || capabilities.some((capability) => /chat|responses/i.test(String(capability || "")));
  }

  function modelRecordIsEmbeddingOnly(record = {}) {
    const capabilities = Array.isArray(record.capabilities) ? record.capabilities : [];
    return capabilities.length > 0 &&
      capabilities.some((capability) => /embed/i.test(String(capability || ""))) &&
      !capabilities.some((capability) => /chat|responses/i.test(String(capability || "")));
  }

  function studioSelectionSupportsChat({ artifact = {}, endpoint = {} } = {}) {
    if ([artifact, endpoint].some((record) => modelRecordIsEmbeddingOnly(record))) {
      return false;
    }
    return [artifact, endpoint].some((record) => modelRecordSupportsChat(record));
  }

  function studioSelectionModelId({ artifact = {}, endpoint = {}, route = {} } = {}) {
    return stringValue(
      artifact.modelId ||
        artifact.model_id ||
        artifact.id ||
        endpoint.modelId ||
        endpoint.model_id ||
        route.modelId ||
        route.model_id ||
        route.lastSelectedModel ||
        route.last_selected_model,
    );
  }

  function isProductStudioModelSelection({ artifact = {}, endpoint = {}, route = {} } = {}) {
    const selectedModel = studioSelectionModelId({ artifact, endpoint, route });
    if (!selectedModel || isAutoStudioModelSelector(selectedModel) || selectedModel === productModelUnavailable) {
      return false;
    }
    if (studioTextContainsProductFixtureMarker(selectedModel)) {
      return false;
    }
    if (!studioSelectionSupportsChat({ artifact, endpoint })) {
      return false;
    }
    return ![artifact, endpoint, route, { modelId: selectedModel }].some(
      (record) => isFixtureStudioModelRecord(record) || isExternalStudioModelRecord(record),
    );
  }

  function studioProductModelSelectionError(selectedRoute, selectedModelId) {
    if (studioFixtureModelUsageAllowed()) {
      return null;
    }
    const selectedModel = stringValue(selectedModelId);
    const routeOrModel = stringValue(selectedRoute);
    const haystack = `${selectedModel} ${routeOrModel}`.toLowerCase();
    if (
      !selectedModel ||
      selectedModel === productModelUnavailable ||
      haystack.includes("no product model") ||
      haystack.includes("product model mounted") ||
      haystack.includes("local:auto") ||
      haystack.includes("lmstudio:detected") ||
      haystack.includes("lmstudio.detected") ||
      haystack.includes("detected model slot") ||
      haystack.includes("autopilot:native-fixture") ||
      haystack.includes("stories260k") ||
      haystack.includes("provider.lmstudio") ||
      haystack.includes("backend.lmstudio") ||
      /\bfixture\b/.test(haystack)
    ) {
      const error = new Error(
        "No product model is mounted for this route. Open Manage models and load a real local model.",
      );
      error.code = "product_model_unavailable";
      return error;
    }
    return null;
  }

  function assertStudioProductModelSelector(selectedRoute, selectedModelId) {
    const error = studioProductModelSelectionError(selectedRoute, selectedModelId);
    if (error) {
      throw error;
    }
  }

  function normalizeStudioReasoningEffort(value, fallback = "none") {
    const normalized = String(value || "").trim().toLowerCase();
    if (!normalized || normalized === "provider_default" || normalized === "default" || normalized === "auto") {
      return fallback;
    }
    if (normalized === "off" || normalized === "disabled") {
      return "none";
    }
    return ["none", "low", "medium", "high", "xhigh"].includes(normalized) ? normalized : fallback;
  }

  function modelRecordReasoningSignals(...records) {
    return records
      .map((record) => {
        const capabilities = Array.isArray(record?.capabilities) ? record.capabilities : [];
        return [
          record?.id,
          record?.modelId,
          record?.model_id,
          record?.name,
          record?.label,
          record?.providerId,
          record?.provider_id,
          record?.driver,
          record?.apiFormat,
          record?.api_format,
          record?.architecture,
          record?.arch,
          record?.family,
          record?.reasoningEffort,
          record?.reasoning_effort,
          record?.thinking,
          ...capabilities,
        ]
          .filter(Boolean)
          .join(" ");
      })
      .join(" ")
      .toLowerCase();
  }

  function studioReasoningControlForSelection({ artifact = {}, endpoint = {}, route = {}, selectedModel = "", modelLabel = "" } = {}) {
    const projection = getStudioRuntimeProjection();
    const haystack = modelRecordReasoningSignals(
      artifact,
      endpoint,
      route,
      { modelId: selectedModel, label: modelLabel },
    );
    const supported =
      /\b(reasoning|thinking|think|qwen3|qwen\/qwen3|deepseek-r1|o1|o3|o4)\b/.test(haystack) ||
      haystack.includes("reasoning_effort") ||
      haystack.includes("reasoningeffort");
    return {
      supported,
      effort: normalizeStudioReasoningEffort(
        projection.reasoningEffort ||
          route.reasoningEffort ||
          route.reasoning_effort ||
          endpoint.reasoningEffort ||
          endpoint.reasoning_effort ||
          artifact.reasoningEffort ||
          artifact.reasoning_effort,
        "none",
      ),
    };
  }

  function studioReasoningEffortOptions(selected = "none") {
    const current = normalizeStudioReasoningEffort(selected, "none");
    return [
      ["none", "Reasoning off"],
      ["low", "Reasoning low"],
      ["medium", "Reasoning medium"],
      ["high", "Reasoning high"],
      ["xhigh", "Reasoning xhigh"],
    ]
      .map(([value, label]) => `<option value="${value}"${current === value ? " selected" : ""}>${label}</option>`)
      .join("");
  }

  function studioMaxOutputTokens() {
    const configured = Number(getEnv("IOI_STUDIO_MAX_OUTPUT_TOKENS") ?? "");
    if (Number.isFinite(configured) && configured >= 64) {
      return Math.min(8192, Math.floor(configured));
    }
    return studioDefaultMaxOutputTokens;
  }

  function studioArtifactMaxOutputTokens() {
    const configured = Number(getEnv("IOI_STUDIO_ARTIFACT_MAX_OUTPUT_TOKENS") ?? "");
    if (Number.isFinite(configured) && configured >= 512) {
      return Math.min(4096, Math.floor(configured));
    }
    return studioDefaultArtifactMaxOutputTokens;
  }

  function modelRecordStatusScore(...records) {
    const status = records.map((record) => String(record?.status || record?.state || "").toLowerCase()).join(" ");
    if (/loaded|running|active/.test(status)) return 50;
    if (/mounted|ready/.test(status)) return 40;
    if (/available/.test(status)) return 30;
    if (/installed/.test(status)) return 20;
    return 0;
  }

  function studioSameNonEmptyId(left, right) {
    return Boolean(left && right && String(left) === String(right));
  }

  function studioPreferredModelSelection(snapshot = {}) {
    const projection = getStudioRuntimeProjection();
    const activeRouteId = projection.modelRoute || "route.local-first";
    const activeRoute = snapshot.routes.find((candidate) =>
      candidate.id === activeRouteId || candidate.routeId === activeRouteId,
    );
    if (activeRoute) {
      const activeRouteFallback = firstArray(activeRoute.fallback || activeRoute.fallbackEndpoints || activeRoute.fallback_endpoints);
      const activeRouteModelId = stringValue(activeRoute.modelId || activeRoute.model_id || activeRoute.lastSelectedModel || activeRoute.last_selected_model);
      const activeEndpointId = activeRoute.endpointId || activeRoute.endpoint_id || activeRouteFallback[0] || "";
      const activeEndpoint =
        snapshot.endpoints.find((candidate) =>
          studioSameNonEmptyId(candidate.id, activeEndpointId) ||
          studioSameNonEmptyId(candidate.id, activeRoute.endpointId) ||
          activeRouteFallback.includes(candidate.id) ||
          studioSameNonEmptyId(candidate.routeId, activeRoute.routeId) ||
          studioSameNonEmptyId(candidate.routeId, activeRoute.id),
        ) ||
        snapshot.endpoints.find((candidate) =>
          studioSameNonEmptyId(candidate.modelId, activeRouteModelId) ||
          studioSameNonEmptyId(candidate.model_id, activeRouteModelId),
        ) ||
        {};
      const activeArtifact =
        snapshot.artifacts.find((candidate) =>
          studioSameNonEmptyId(candidate.id, activeEndpoint.artifactId) ||
          studioSameNonEmptyId(candidate.id, activeEndpoint.artifact_id) ||
          candidate.id === activeEndpoint.modelId ||
          candidate.modelId === activeEndpoint.modelId ||
          candidate.id === activeRoute.modelId ||
          candidate.modelId === activeRoute.modelId ||
          candidate.id === activeRouteModelId ||
          candidate.modelId === activeRouteModelId,
        ) ||
        {};
      if (modelRecordSupportsChat(activeArtifact) && isProductStudioModelSelection({
        artifact: activeArtifact,
        endpoint: activeEndpoint,
        route: activeRoute,
      })) {
        return {
          artifact: activeArtifact,
          endpoint: activeEndpoint,
          route: activeRoute,
          score: 1_000 + modelRecordStatusScore(activeEndpoint, activeRoute, activeArtifact),
        };
      }
    }

    const candidates = snapshot.artifacts
      .filter((artifact) => artifact && modelRecordSupportsChat(artifact) && !isFixtureStudioModelRecord(artifact))
      .map((artifact) => {
        const modelId = artifact.modelId || artifact.id || "";
        const endpoint = modelEndpointForArtifact(snapshot, artifact) || {};
        const route =
          snapshot.routes.find((candidate) =>
            studioSameNonEmptyId(candidate.endpointId, endpoint.id) ||
            firstArray(candidate.fallback || candidate.fallbackEndpoints || candidate.fallback_endpoints).includes(endpoint.id) ||
            studioSameNonEmptyId(candidate.modelId, modelId) ||
            studioSameNonEmptyId(candidate.id, endpoint.routeId) ||
            studioSameNonEmptyId(candidate.routeId, endpoint.routeId),
          ) ||
          {};
        const providerSignal = String(`${artifact.providerId || ""} ${endpoint.providerId || ""} ${artifact.source || ""} ${endpoint.driver || ""}`);
        const providerWeight = /llama-cpp|llama_cpp|provider\.llama/i.test(providerSignal)
          ? 130
          : /ollama|vllm|openai_compatible|local\.folder/i.test(providerSignal)
            ? 80
            : 10;
        const selection = {
          artifact,
          endpoint,
          route,
          score: providerWeight + modelRecordStatusScore(endpoint, route, artifact),
        };
        return isProductStudioModelSelection(selection) ? selection : null;
      })
      .filter(Boolean)
      .sort((left, right) => right.score - left.score);
    return candidates[0] || null;
  }

  function studioSnapshotFromState(state = {}) {
    const projection = getStudioRuntimeProjection();
    const snapshot = modelSnapshotFromState(state);
    const preferred = studioPreferredModelSelection(snapshot);
    const route = preferred?.route || snapshot.routes.find((candidate) =>
      candidate.id === projection.modelRoute || candidate.routeId === projection.modelRoute,
    ) || {};
    const endpoint = preferred?.endpoint || {};
    const artifact = preferred?.artifact || {};
    const staleSelectedModel = stringValue(projection.selectedModel);
    const staleProductSelectionAvailable = Boolean(
      !preferred &&
        staleSelectedModel &&
        !isAutoStudioModelSelector(staleSelectedModel) &&
        !studioProductModelSelectionError(projection.modelRoute || "route.local-first", staleSelectedModel),
    );
    const productModelAvailable = Boolean(preferred) || staleProductSelectionAvailable;
    const selectedModel = productModelAvailable
      ? (preferred ? studioSelectionModelId({ artifact, endpoint, route }) : staleSelectedModel)
      : productModelUnavailable;
    const modelLabel = productModelAvailable
      ? (preferred ? (
          artifact.name ||
          artifact.label ||
          artifact.displayName ||
          artifact.modelId ||
          artifact.id ||
          endpoint.modelId ||
          route.modelId ||
          selectedModel
        ) : staleSelectedModel)
      : "No product model mounted";
    const reasoningControl = studioReasoningControlForSelection({
      artifact,
      endpoint,
      route,
      selectedModel,
      modelLabel,
    });
    return {
      daemonStatus: state.modelMountingStatus?.status || "not_configured",
      daemonEndpoint: state.modelMountingStatus?.endpoint || daemonEndpoint() || null,
      routeId: route.routeId || route.id || projection.modelRoute || "route.local-first",
      endpointId: endpoint.id || route.endpointId || "",
      selectedModel,
      modelLabel,
      modelUnavailable: !productModelAvailable,
      reasoningControlSupported: reasoningControl.supported,
      reasoningEffort: reasoningControl.effort,
    };
  }

  function productStudioModelSelectionsFromSnapshot(snapshot = {}) {
    const seen = new Set();
    return (Array.isArray(snapshot.artifacts) ? snapshot.artifacts : [])
      .map((artifact) => {
        const modelId = studioSelectionModelId({ artifact });
        const endpoint = modelEndpointForArtifact(snapshot, artifact) || {};
        const route =
          (Array.isArray(snapshot.routes) ? snapshot.routes : []).find((candidate) =>
            studioSameNonEmptyId(candidate.endpointId, endpoint.id) ||
            firstArray(candidate.fallback || candidate.fallbackEndpoints || candidate.fallback_endpoints).includes(endpoint.id) ||
            studioSameNonEmptyId(candidate.modelId, modelId) ||
            studioSameNonEmptyId(candidate.id, endpoint.routeId) ||
            studioSameNonEmptyId(candidate.routeId, endpoint.routeId),
          ) ||
          {};
        const selection = { artifact, endpoint, route };
        if (!isProductStudioModelSelection(selection)) {
          return null;
        }
        const key = studioSelectionModelId(selection);
        if (!key || seen.has(key)) {
          return null;
        }
        seen.add(key);
        return selection;
      })
      .filter(Boolean);
  }

  function loadedProductStudioModelInstances(snapshot = {}, selections = []) {
    const endpointIds = new Set(selections.map((selection) => selection.endpoint?.id).filter(Boolean));
    const modelIds = new Set(selections.map((selection) => studioSelectionModelId(selection)).filter(Boolean));
    const seen = new Set();
    return (Array.isArray(snapshot.instances) ? snapshot.instances : [])
      .filter((instance) => {
        if (!/loaded|ready|running/i.test(String(instance.status || ""))) {
          return false;
        }
        return endpointIds.has(instance.endpointId) || modelIds.has(instance.modelId);
      })
      .filter((instance) => {
        const key = instance.id || `${instance.endpointId || ""}:${instance.modelId || ""}`;
        if (seen.has(key)) {
          return false;
        }
        seen.add(key);
        return true;
      });
  }

  function mountedModelQuickInputRowsFromState(state = {}) {
    const snapshot = modelSnapshotFromState(state);
    const mountedStatus = (value) => /loaded|ready|running|mounted|active/i.test(String(value || ""));
    const seen = new Set();
    return snapshot.artifacts
      .map((artifact) => {
        const endpoint = modelEndpointForArtifact(snapshot, artifact) || {};
        const modelId = artifact.modelId || artifact.id || endpoint.modelId || "";
        const instance =
          modelInstanceForEndpoint(snapshot, endpoint) ||
          snapshot.instances.find((candidate) =>
            (candidate.modelId === modelId || candidate.endpointId === endpoint.id) &&
            mountedStatus(candidate.status),
          ) ||
          {};
        const route =
          snapshot.routes.find((candidate) =>
            candidate.endpointId === endpoint.id ||
            firstArray(candidate.fallback || candidate.fallbackEndpoints || candidate.fallback_endpoints).includes(endpoint.id) ||
            candidate.modelId === modelId ||
            candidate.id === endpoint.routeId ||
            candidate.routeId === endpoint.routeId,
          ) ||
          {};
        const status = instance.status || endpoint.status || route.status || artifact.status || "";
        const selection = { artifact, endpoint, route };
        if (
          !modelId ||
          seen.has(modelId) ||
          !mountedStatus(status) ||
          !isProductStudioModelSelection(selection)
        ) {
          return null;
        }
        seen.add(modelId);
        return {
          id: route.routeId || route.id || endpoint.routeId || endpoint.id || modelId,
          label: modelDisplayName(artifact),
          detail: modelId,
          meta: status || "mounted",
          modelId,
          routeId: route.routeId || route.id || endpoint.routeId || endpoint.id || modelId,
          endpointId: endpoint.id || "",
          instanceId: instance.id || "",
        };
      })
      .filter(Boolean);
  }

  return {
    assertStudioProductModelSelector,
    isExternalStudioModelRecord,
    isFixtureStudioModelRecord,
    isProductStudioModelSelection,
    loadedProductStudioModelInstances,
    modelRecordIsEmbeddingOnly,
    modelRecordReasoningSignals,
    modelRecordStatusScore,
    modelRecordSupportsChat,
    mountedModelQuickInputRowsFromState,
    normalizeStudioReasoningEffort,
    productStudioModelSelectionsFromSnapshot,
    studioArtifactMaxOutputTokens,
    studioExternalModelProviderUsageAllowed,
    studioMaxOutputTokens,
    studioPreferredModelSelection,
    studioProductModelSelectionError,
    studioReasoningControlForSelection,
    studioReasoningEffortOptions,
    studioSameNonEmptyId,
    studioSelectionModelId,
    studioSelectionSupportsChat,
    studioSnapshotFromState,
  };
}

module.exports = {
  createStudioModelSelection,
};
