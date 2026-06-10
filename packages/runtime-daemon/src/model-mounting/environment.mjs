import { truthy } from "./io.mjs";

export function exposeInternalFixtureModels(env = process.env) {
  return truthy(env.IOI_EXPOSE_INTERNAL_FIXTURE_MODELS);
}

export function internalFixtureModelsEnabled(env = process.env) {
  return exposeInternalFixtureModels(env) || truthy(env.IOI_ENABLE_INTERNAL_FIXTURE_MODELS);
}

export function liveModelCatalogEnabled(env = process.env) {
  return env.IOI_LIVE_MODEL_CATALOG === "1";
}

export function liveModelDownloadEnabled(env = process.env) {
  return env.IOI_LIVE_MODEL_DOWNLOAD === "1";
}

export function modelCatalogTimeoutMs(env = process.env) {
  return Number(env.IOI_MODEL_CATALOG_TIMEOUT_MS ?? 5000) || 5000;
}

export function modelDownloadTimeoutMs(env = process.env) {
  return Number(env.IOI_MODEL_DOWNLOAD_TIMEOUT_MS ?? 30000) || 30000;
}
