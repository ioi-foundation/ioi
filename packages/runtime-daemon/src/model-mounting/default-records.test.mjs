import assert from "node:assert/strict";
import test from "node:test";

import {
  backendRegistryRecords,
  defaultRouteRecords,
  localFixtureArtifactRecords,
  localFixtureEndpointRecord,
  localFolderProviderRecord,
  nativeFixtureEndpointRecord,
  nativeLocalProviderRecord,
  runtimeProviderRecords,
} from "./default-records.mjs";

const checkedAt = "2026-06-03T12:00:00.000Z";

function hostedProvider(id, label, apiFormat, secret) {
  return {
    id,
    label,
    apiFormat,
    status: secret ? "configured" : "needs_secret",
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
  assert.equal(native.id, "provider.autopilot.local");
  assert.equal(native.driver, "native_local");

  const llama = providers.find((provider) => provider.id === "provider.llama-cpp");
  const vllm = providers.find((provider) => provider.id === "provider.vllm");
  const openai = providers.find((provider) => provider.id === "provider.openai");
  const depin = providers.find((provider) => provider.id === "provider.depin-tee");

  assert.equal(llama.status, "configured");
  assert.equal(llama.discovery.binaryPathHash, "hash:/opt/llama-server");
  assert.equal(vllm.status, "blocked");
  assert.equal(openai.status, "needs_secret");
  assert.equal(depin.status, "future");
  assert.equal(depin.privacyClass, "remote_confidential");
});

test("default artifact, endpoint, and route records preserve compatibility ids", () => {
  const [localArtifact, embeddingArtifact] = localFixtureArtifactRecords(checkedAt);
  const localEndpoint = localFixtureEndpointRecord(checkedAt);
  const nativeEndpoint = nativeFixtureEndpointRecord({
    artifact: { modelId: "autopilot:native-fixture" },
    backendRegistry: [{ id: "backend.autopilot.native-local.fixture" }],
    checkedAt,
  });
  const routes = defaultRouteRecords();

  assert.equal(localArtifact.id, "local.auto");
  assert.equal(localArtifact.modelId, "local:auto");
  assert.equal(embeddingArtifact.capabilities.includes("embeddings"), true);
  assert.equal(localEndpoint.id, "endpoint.local.auto");
  assert.equal(nativeEndpoint.id, "endpoint.autopilot.native-fixture");
  assert.equal(nativeEndpoint.modelId, "autopilot:native-fixture");
  assert.equal(routes[0].id, "route.local-first");
  assert.equal(routes[1].id, "route.native-local");
  assert.deepEqual(routes[1].deniedProviders, ["openai", "anthropic", "gemini", "lm_studio"]);
});

test("default backend registry records preserve process and provider-derived status", () => {
  const providers = new Map([
    ["provider.lmstudio", {
      id: "provider.lmstudio",
      status: "running",
      baseUrl: "http://127.0.0.1:1234/v1",
      discovery: { publicCli: { path: "/bin/lms" } },
    }],
    ["provider.openai-compatible", { id: "provider.openai-compatible", status: "configured", baseUrl: "http://127.0.0.1:9000/v1" }],
    ["provider.ollama", { id: "provider.ollama", status: "configured", baseUrl: "http://127.0.0.1:11434" }],
    ["provider.vllm", { id: "provider.vllm", status: "blocked", baseUrl: "http://127.0.0.1:8000/v1" }],
  ]);
  const backends = backendRegistryRecords({
    checkedAt,
    hardware: { gpu: "none" },
    llamaBinary: "/opt/llama-server",
    ollamaBinary: "/opt/ollama",
    providers,
    vllmBinary: null,
  });

  assert.equal(backends.find((backend) => backend.id === "backend.fixture").status, "available");
  assert.equal(backends.find((backend) => backend.id === "backend.llama-cpp").processStatus, "binary_configured");
  assert.equal(backends.find((backend) => backend.id === "backend.lmstudio").binaryPath, "/bin/lms");
  assert.equal(backends.find((backend) => backend.id === "backend.openai-compatible").baseUrl, "http://127.0.0.1:9000/v1");
  assert.equal(backends.find((backend) => backend.id === "backend.ollama").processStatus, "binary_configured");
  assert.equal(backends.find((backend) => backend.id === "backend.vllm").processStatus, "external_or_absent");
});
