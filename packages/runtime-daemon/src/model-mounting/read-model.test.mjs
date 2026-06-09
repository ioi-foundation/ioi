import assert from "node:assert/strict";
import { test } from "node:test";

import {
  artifactList,
  downloadList,
  endpointList,
  instanceList,
  modelCapabilityList,
  openAiModelList,
  productArtifactList,
  providerList,
  routeList,
  runtimeModelCatalogList,
} from "./read-model.mjs";

function fakeState() {
  const state = {
    artifacts: new Map([
      ["artifact_b", { id: "artifact_b", modelId: "model_b", providerId: "provider.local.folder", privacyClass: "local_private", family: "local", capabilities: ["chat"], discoveredAt: "2026-06-03T00:00:02.000Z" }],
      ["artifact_a", { id: "artifact_a", modelId: "model_a", providerId: "provider.fixture", privacyClass: "hosted", family: "fixture", capabilities: ["chat"], discoveredAt: "2026-06-03T00:00:01.000Z" }],
    ]),
    downloads: new Map([
      ["download_b", { id: "download_b", createdAt: "2026-06-03T00:00:02.000Z" }],
      ["download_a", { id: "download_a", createdAt: "2026-06-03T00:00:01.000Z" }],
    ]),
    endpoints: new Map([
      ["endpoint_b", { id: "endpoint_b" }],
      ["endpoint_a", { id: "endpoint_a" }],
    ]),
    instances: new Map([
      ["instance_b", { id: "instance_b", loadedAt: "2026-06-03T00:00:02.000Z" }],
      ["instance_a", { id: "instance_a", loadedAt: "2026-06-03T00:00:01.000Z" }],
    ]),
    providers: new Map([
      ["provider_b", { id: "provider_b" }],
      ["provider_a", { id: "provider_a", secretRef: "vault://provider_a/api-key" }],
    ]),
    routes: new Map([
      ["route_b", { id: "route_b" }],
      ["route_a", { id: "route_a" }],
    ]),
    stateDir: "/state",
    vault: {
      vaultRefMetadata(secretRef) {
        return { secretRef, configured: true };
      },
    },
    coalesceLoadedInstances() {
      this.coalesced = true;
    },
    evictExpiredInstances() {
      this.evicted = true;
    },
    listArtifacts() {
      return artifactList(this);
    },
    listDownloads() {
      return downloadList(this);
    },
    listEndpoints() {
      return endpointList(this);
    },
    listInstances() {
      return instanceList(this);
    },
    listModelCapabilities() {
      return [{ modelId: "model_a" }];
    },
    listOAuthSessions() {
      return [];
    },
    listOAuthStates() {
      return [];
    },
    listProductArtifacts() {
      return productArtifactList(this, { isFixtureModelRecord: (artifact) => artifact.family === "fixture" });
    },
    listProviderHealth() {
      return [];
    },
    listProviders() {
      return providerList(this, {
        providerHasVaultRef: (provider) => Boolean(provider.secretRef),
        publicProvider: (provider, vaultMetadata) => ({ id: provider.id, vaultMetadata }),
      });
    },
    listRoutes() {
      return routeList(this);
    },
    nowIso() {
      return "2026-06-03T00:00:00.000Z";
    },
  };
  return state;
}

test("model mounting read model sorts primitive lists", () => {
  const state = fakeState();
  assert.deepEqual(artifactList(state).map((artifact) => artifact.id), ["artifact_a", "artifact_b"]);
  assert.deepEqual(endpointList(state).map((endpoint) => endpoint.id), ["endpoint_a", "endpoint_b"]);
  assert.deepEqual(instanceList(state).map((instance) => instance.id), ["instance_a", "instance_b"]);
  assert.equal(state.evicted, true);
  assert.equal(state.coalesced, true);
  assert.deepEqual(routeList(state).map((route) => route.id), ["route_a", "route_b"]);
  assert.deepEqual(downloadList(state).map((download) => download.id), ["download_a", "download_b"]);
});

test("model mounting read model builds product and protocol model lists", () => {
  const state = fakeState();
  assert.deepEqual(productArtifactList(state, { isFixtureModelRecord: (artifact) => artifact.family === "fixture" }).map((artifact) => artifact.id), ["artifact_b"]);
  assert.deepEqual(runtimeModelCatalogList(state).map((model) => model.id), ["model_b"]);
  assert.deepEqual(openAiModelList(state).data.map((model) => model.id), ["model_b"]);

  state.artifacts.set("artifact_native", {
    id: "artifact_native",
    modelId: "model_native",
    providerId: "provider.autopilot.local",
    privacyClass: "local_private",
    family: "native_local",
    capabilities: ["chat"],
    discoveredAt: "2026-06-03T00:00:03.000Z",
  });
  const nativeModel = runtimeModelCatalogList(state)
    .find((model) => model.id === "model_native");
  assert.equal(nativeModel.provider, "ioi-daemon-local");
});

test("model mounting read model applies provider vault metadata and capabilities", () => {
  const state = fakeState();
  assert.deepEqual(providerList(state, {
    providerHasVaultRef: (provider) => Boolean(provider.secretRef),
    publicProvider: (provider, vaultMetadata) => ({ id: provider.id, vaultMetadata }),
  }), [
    { id: "provider_a", vaultMetadata: { secretRef: "vault://provider_a/api-key", configured: true } },
    { id: "provider_b", vaultMetadata: null },
  ]);
  assert.deepEqual(modelCapabilityList(state, {
    buildModelCapabilities({ routes, endpoints, providers, artifacts, instances }) {
      return [{ routes: routes.length, endpoints: endpoints.length, providers: providers.length, artifacts: artifacts.length, instances: instances.length }];
    },
  }), [{ routes: 2, endpoints: 2, providers: 2, artifacts: 2, instances: 2 }]);
});
