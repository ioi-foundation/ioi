"use strict";

function formatBytes(value) {
  const bytes = Number(value ?? 0);
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "unknown";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let current = bytes;
  let index = 0;
  while (current >= 1024 && index < units.length - 1) {
    current /= 1024;
    index += 1;
  }
  return `${current >= 10 || index === 0 ? current.toFixed(0) : current.toFixed(1)} ${units[index]}`;
}

function modelSnapshotFromState(state) {
  const snapshot = state.modelMounting || {};
  return {
    artifacts: Array.isArray(snapshot.artifacts) ? snapshot.artifacts : [],
    endpoints: Array.isArray(snapshot.endpoints) ? snapshot.endpoints : [],
    instances: Array.isArray(snapshot.instances) ? snapshot.instances : [],
    routes: Array.isArray(snapshot.routes) ? snapshot.routes : [],
    backends: Array.isArray(snapshot.backends) ? snapshot.backends : [],
    runtimeEngines: Array.isArray(snapshot.runtimeEngines) ? snapshot.runtimeEngines : [],
    receipts: Array.isArray(snapshot.receipts) ? snapshot.receipts : [],
    downloads: Array.isArray(snapshot.downloads) ? snapshot.downloads : [],
    providers: Array.isArray(snapshot.providers) ? snapshot.providers : [],
    catalog: snapshot.catalog || {},
    catalogProviderConfigs: Array.isArray(snapshot.catalogProviderConfigs)
      ? snapshot.catalogProviderConfigs
      : [],
    server: snapshot.server || {},
    runtimePreference: snapshot.runtimePreference || {},
    generatedAt: snapshot.generatedAt || snapshot.server?.generatedAt || null,
  };
}

module.exports = {
  formatBytes,
  modelSnapshotFromState,
};
