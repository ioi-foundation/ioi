import { throwCatalogProviderControlRustCoreRequired } from "./catalog-provider-config.mjs";

export function startCatalogProviderOAuth(state, providerId, body = {}, deps = {}) {
  const {
    assertConfigurableCatalogProvider,
  } = deps;
  void state;
  assertConfigurableCatalogProvider(providerId);
  throwCatalogProviderControlRustCoreRequired(
    "model_mount.catalog_provider_oauth.start",
    { provider_id: providerId, request_field_count: Object.keys(body ?? {}).length },
    deps,
  );
}

export async function completeCatalogProviderOAuth(state, providerId, body = {}, deps = {}) {
  const {
    assertConfigurableCatalogProvider,
    requiredString,
  } = deps;
  void state;
  assertConfigurableCatalogProvider(providerId);
  requiredString(body.state, "state");
  throwCatalogProviderControlRustCoreRequired(
    "model_mount.catalog_provider_oauth.callback",
    { provider_id: providerId, state_present: true },
    deps,
  );
}

export async function exchangeCatalogProviderOAuth(state, providerId, body = {}, deps = {}) {
  const {
    assertConfigurableCatalogProvider,
  } = deps;
  void state;
  assertConfigurableCatalogProvider(providerId);
  throwCatalogProviderControlRustCoreRequired(
    "model_mount.catalog_provider_oauth.exchange",
    { provider_id: providerId, request_field_count: Object.keys(body ?? {}).length },
    deps,
  );
}

export async function refreshCatalogProviderOAuth(state, providerId, deps = {}) {
  const {
    assertConfigurableCatalogProvider,
  } = deps;
  void state;
  assertConfigurableCatalogProvider(providerId);
  throwCatalogProviderControlRustCoreRequired(
    "model_mount.catalog_provider_oauth.refresh",
    { provider_id: providerId },
    deps,
  );
}

export function revokeCatalogProviderOAuth(state, providerId, deps = {}) {
  const {
    assertConfigurableCatalogProvider,
  } = deps;
  void state;
  assertConfigurableCatalogProvider(providerId);
  throwCatalogProviderControlRustCoreRequired(
    "model_mount.catalog_provider_oauth.revoke",
    { provider_id: providerId },
    deps,
  );
}
