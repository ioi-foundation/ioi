"use strict";

function pickPayloadString(value, key) {
  if (typeof value === "string" && key === "value") {
    return value;
  }
  if (value && typeof value === "object" && typeof value[key] === "string") {
    return value[key];
  }
  if (value && typeof value === "object" && typeof value[key] === "number") {
    return String(value[key]);
  }
  return null;
}

function createModelDaemonActions({
  daemonEndpoint,
  daemonToken,
  requestJson,
}) {
  function requireEndpoint(message) {
    const endpoint = daemonEndpoint();
    if (!endpoint) {
      throw new Error(message);
    }
    return endpoint;
  }

  async function runDaemonModelWorkbenchAction(action, payload = {}) {
    const endpoint = requireEndpoint("IOI_DAEMON_ENDPOINT is required for model workbench actions.");
    const token = daemonToken();
    const targetEndpointId =
      pickPayloadString(payload, "endpointId") ||
      pickPayloadString(payload, "endpoint_id") ||
      "endpoint.electron.model-gui";
    const targetInstanceId =
      pickPayloadString(payload, "instanceId") || pickPayloadString(payload, "instance_id");
    let requestedGpu =
      pickPayloadString(payload, "gpu") || pickPayloadString(payload, "gpuOffload") || "0";
    if (requestedGpu === "auto") {
      requestedGpu = "0";
    }
    if (action === "estimate") {
      return requestJson(endpoint, "/api/v1/models/estimate-load", {
        method: "POST",
        token,
        payload: {
          endpoint_id: targetEndpointId,
          load_options: {
            estimateOnly: true,
            gpu: requestedGpu,
            contextLength: Number(pickPayloadString(payload, "contextLength") || 4096),
            parallel: Number(pickPayloadString(payload, "parallel") || 2),
            ttlSeconds: Number(pickPayloadString(payload, "ttlSeconds") || 900),
            identifier: pickPayloadString(payload, "identifier") || "electron-model-workbench",
          },
        },
      });
    }
    if (action === "load") {
      return requestJson(endpoint, `/api/v1/models/mounts/${encodeURIComponent(targetEndpointId)}/load`, {
        method: "POST",
        token,
        payload: {
          load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true },
          load_options: {
            gpu: requestedGpu,
            contextLength: Number(pickPayloadString(payload, "contextLength") || 4096),
            parallel: Number(pickPayloadString(payload, "parallel") || 2),
            ttlSeconds: Number(pickPayloadString(payload, "ttlSeconds") || 900),
            identifier: pickPayloadString(payload, "identifier") || "electron-model-workbench",
          },
        },
      });
    }
    if (action === "unload") {
      return requestJson(
        endpoint,
        targetInstanceId
          ? `/api/v1/models/instances/${encodeURIComponent(targetInstanceId)}/unload`
          : `/api/v1/models/mounts/${encodeURIComponent(targetEndpointId)}/unload`,
        {
          method: "POST",
          token,
          payload: {},
        },
      );
    }
    throw new Error(`Unknown model workbench action: ${action}`);
  }

  async function runDaemonModelCatalogSearch(payload = {}) {
    const endpoint = requireEndpoint("IOI_DAEMON_ENDPOINT is required for model catalog search.");
    const token = daemonToken();
    const params = new URLSearchParams();
    const query = pickPayloadString(payload, "query") || pickPayloadString(payload, "q") || "";
    if (query) {
      params.set("query", query);
    }
    const format = pickPayloadString(payload, "format");
    const quantization = pickPayloadString(payload, "quantization");
    if (format) params.set("format", format);
    if (quantization) params.set("quantization", quantization);
    params.set("limit", pickPayloadString(payload, "limit") || "20");
    return requestJson(endpoint, `/v1/models/catalog/search?${params.toString()}`, {
      method: "GET",
      token,
    });
  }

  async function runDaemonModelCatalogProviderConfig(payload = {}) {
    const endpoint = requireEndpoint("IOI_DAEMON_ENDPOINT is required for catalog source configuration.");
    const token = daemonToken();
    const providerId =
      pickPayloadString(payload, "providerId") ||
      pickPayloadString(payload, "provider_id") ||
      "catalog.huggingface";
    const body = {
      enabled: payload?.enabled === false ? false : true,
    };
    if (providerId === "catalog.local_manifest") {
      body.manifest_path = pickPayloadString(payload, "manifestPath") || pickPayloadString(payload, "path") || "";
    } else {
      body.base_url = pickPayloadString(payload, "baseUrl") || pickPayloadString(payload, "url") || "https://huggingface.co";
    }
    return requestJson(endpoint, `/api/v1/models/catalog/providers/${encodeURIComponent(providerId)}`, {
      method: "PATCH",
      token,
      payload: body,
    });
  }

  async function runDaemonModelCatalogDownload(payload = {}) {
    const endpoint = requireEndpoint("IOI_DAEMON_ENDPOINT is required for model catalog download.");
    const token = daemonToken();
    const sourceUrl = pickPayloadString(payload, "sourceUrl") || pickPayloadString(payload, "source_url");
    if (!sourceUrl) {
      throw new Error("A daemon catalog source URL is required for model download.");
    }
    return requestJson(endpoint, "/api/v1/models/download", {
      method: "POST",
      token,
      payload: {
        source_url: sourceUrl,
        model_id: pickPayloadString(payload, "modelId") || pickPayloadString(payload, "model_id"),
        catalog_entry_id: pickPayloadString(payload, "catalogEntryId") || pickPayloadString(payload, "catalog_entry_id"),
        download_policy: {
          approvalDecision: "required",
          externalNetwork: "daemon_gated",
        },
      },
    });
  }

  return {
    pickPayloadString,
    runDaemonModelCatalogDownload,
    runDaemonModelCatalogProviderConfig,
    runDaemonModelCatalogSearch,
    runDaemonModelWorkbenchAction,
  };
}

module.exports = {
  createModelDaemonActions,
  pickPayloadString,
};
