import test from "node:test";
import assert from "node:assert/strict";

import {
  catalogAuthFailureFields,
  catalogAuthFailureStatus,
  catalogEntryWithAuth,
  catalogProviderConfigHealthFields,
  publicCatalogAuthEvidence,
  publicCatalogProviderConfig,
} from "./catalog-projections.mjs";

test("catalog auth evidence projection redacts material and preserves public hashes", () => {
  const evidence = publicCatalogAuthEvidence({
    authVaultRefHash: "hash-auth",
    resolvedMaterial: true,
    catalogAuthScheme: "bearer",
    catalogAuthHeaderNameHash: "hash-header",
    material: "secret",
    evidenceRefs: ["VaultPort.resolveVaultRef"],
  });

  assert.deepEqual(evidence, {
    authVaultRefHash: "hash-auth",
    resolvedMaterial: true,
    catalogAuthScheme: "bearer",
    catalogAuthHeaderNameHash: "hash-header",
    evidenceRefs: ["VaultPort.resolveVaultRef"],
    oauthBoundary: null,
  });
});

test("catalog provider config exposes hashes and runtime material state only", () => {
  const projection = publicCatalogProviderConfig(
    "catalog.custom_http",
    { enabled: true, catalogAuthConfigured: true, authVaultRefHash: "hash-auth" },
    {
      baseUrl: "https://catalog.example.test",
      materialVaultRefHash: "hash-material",
      materialSource: "encrypted_keychain_vault_adapter",
    },
  );

  assert.equal(projection.id, "catalog.custom_http");
  assert.equal(projection.enabled, true);
  assert.equal(projection.authVaultRefHash, "hash-auth");
  assert.match(projection.baseUrlHash, /^[a-f0-9]{64}$/);
  assert.equal(projection.materialVaultRefHash, "hash-material");
  assert.equal(projection.runtimeMaterialStatus, "bound_runtime_session");
  assert.equal(projection.vaultMaterialSource, "encrypted_keychain_vault_adapter");
});

test("catalog health and failure helpers keep product-safe fields", () => {
  assert.equal(catalogAuthFailureStatus({ status: 403 }), "blocked");
  assert.equal(catalogAuthFailureStatus({ status: 500 }), "degraded");
  assert.deepEqual(catalogAuthFailureFields({
    details: {
      authVaultRefHash: "hash-auth",
      catalogAuthScheme: "bearer",
      catalogAuthHeaderNameHash: "hash-header",
      evidenceRefs: ["catalog_auth_fail_closed"],
    },
  }), {
    authVaultRefHash: "hash-auth",
    catalogAuthConfigured: true,
    catalogAuthResolved: false,
    catalogAuthScheme: "bearer",
    catalogAuthHeaderNameHash: "hash-header",
    catalogAuthEvidenceRefs: ["catalog_auth_fail_closed"],
    oauthSessionHash: null,
    oauthBoundary: null,
  });

  assert.deepEqual(catalogEntryWithAuth({ id: "entry" }, { resolvedMaterial: false }), {
    id: "entry",
    catalogAuth: {
      authVaultRefHash: null,
      resolvedMaterial: false,
      catalogAuthScheme: "bearer",
      catalogAuthHeaderNameHash: null,
      evidenceRefs: [],
      oauthBoundary: null,
    },
  });

  assert.equal(
    catalogProviderConfigHealthFields("catalog.custom_http", { enabled: false }).enabled,
    false,
  );
});
