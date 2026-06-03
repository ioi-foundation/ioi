import assert from "node:assert/strict";
import test from "node:test";

import { modelMountingRelationSchemas } from "./schema-relations.mjs";

test("model mounting relation schemas preserve canonical relation names and fields", () => {
  const schemas = modelMountingRelationSchemas();

  assert.deepEqual(Object.keys(schemas), [
    "modelArtifacts",
    "modelEndpoints",
    "modelInstances",
    "modelRoutes",
    "modelProviders",
    "modelBackends",
    "modelBackendProcesses",
    "providerHealth",
    "runtimeEngines",
    "runtimeEngineProfiles",
    "runtimePreferences",
    "modelCatalogEntries",
    "modelDownloads",
    "modelCatalogProviders",
    "oauthAuthorizationStates",
    "permissionTokens",
    "walletGrants",
    "mcpServers",
    "modelConversationStates",
    "workflowModelBindings",
    "modelMountingProjection",
  ]);
  assert.deepEqual(schemas.modelArtifacts, [
    "id",
    "providerId",
    "modelId",
    "capabilities",
    "privacyClass",
    "contextWindow",
  ]);
  assert.deepEqual(schemas.modelMountingProjection, [
    "artifacts",
    "backends",
    "endpoints",
    "instances",
    "routes",
    "providers",
    "receipts",
    "watermark",
  ]);
  assert.deepEqual(schemas.walletGrants, [
    "grantId",
    "revocationEpoch",
    "allowed",
    "denied",
    "expiry",
    "vaultRefs",
    "auditReceiptIds",
  ]);
});
