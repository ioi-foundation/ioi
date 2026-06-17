import assert from "node:assert/strict";
import test from "node:test";

import * as defaultRecords from "./default-records.mjs";
import {
  defaultRouteRecords,
  localFixtureArtifactRecords,
  localFixtureEndpointRecord,
  localFolderProviderRecord,
  nativeFixtureEndpointRecord,
  nativeLocalProviderRecord,
  runtimeProviderRecords,
} from "./default-records.mjs";

const checkedAt = "2026-06-03T12:00:00.000Z";

function hostedProvider(id, label, apiFormat, options = {}) {
  return {
    id,
    label,
    apiFormat,
    status: "blocked",
    secret_ref: options.secret_ref,
  };
}

test("default model provider records preserve local and hosted boundaries", () => {
  const local = localFolderProviderRecord(checkedAt);
  const native = nativeLocalProviderRecord(checkedAt);
  const providers = runtimeProviderRecords({
    checkedAt,
    hostedProvider,
    llamaBinary: "/opt/llama-server",
    stableHash: (value) => `hash:${value}`,
    vllmBinary: null,
  });

  assert.equal(local.id, "provider.local.folder");
  assert.equal(local.privacyClass, "local_private");
  assert.deepEqual(local.discovery.evidenceRefs, ["agentgres_model_registry_fixture"]);
  assert.equal(native.id, "provider.hypervisor.local");
  assert.equal(native.driver, "native_local");

  const llama = providers.find((provider) => provider.id === "provider.llama-cpp");
  const vllm = providers.find((provider) => provider.id === "provider.vllm");
  const openai = providers.find((provider) => provider.id === "provider.openai");
  const depin = providers.find((provider) => provider.id === "provider.depin-tee");

  assert.equal(llama.status, "configured");
  assert.equal(llama.discovery.binaryPathHash, "hash:/opt/llama-server");
  assert.equal(vllm.status, "blocked");
  assert.equal(openai.status, "blocked");
  assert.equal(openai.secret_ref, "vault://provider.openai/api-key");
  assert.equal(Object.hasOwn(openai, "secretRef"), false);
  assert.equal(depin.status, "future");
  assert.equal(depin.privacyClass, "remote_confidential");
});

test("default artifact, endpoint, and route records preserve compatibility ids", () => {
  const [localArtifact, embeddingArtifact] = localFixtureArtifactRecords(checkedAt);
  const localEndpoint = localFixtureEndpointRecord(checkedAt);
  const nativeEndpoint = nativeFixtureEndpointRecord({
    artifact: { modelId: "hypervisor:native-fixture" },
    checkedAt,
  });
  const routes = defaultRouteRecords();

  assert.equal(localArtifact.id, "local.auto");
  assert.equal(localArtifact.modelId, "local:auto");
  assert.equal(embeddingArtifact.capabilities.includes("embeddings"), true);
  assert.equal(localEndpoint.id, "endpoint.local.auto");
  assert.equal(nativeEndpoint.id, "endpoint.hypervisor.native-fixture");
  assert.equal(nativeEndpoint.modelId, "hypervisor:native-fixture");
  assert.equal(Object.hasOwn(nativeEndpoint, "backendRegistry"), false);
  assert.equal(routes[0].id, "route.local-first");
  assert.equal(routes[1].id, "route.native-local");
  assert.deepEqual(routes[1].deniedProviders, ["openai", "anthropic", "gemini", "lm_studio"]);
});

test("default JS backend registry record factory stays retired", () => {
  assert.equal(Object.hasOwn(defaultRecords, "backendRegistryRecords"), false);
});
