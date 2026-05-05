import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const viewPath = path.join(
  root,
  "apps",
  "autopilot",
  "src",
  "surfaces",
  "MissionControl",
  "MissionControlMountsView.tsx",
);

test("Autopilot Mounts workbench is wired to daemon API without persisting capability tokens", () => {
  const source = fs.readFileSync(viewPath, "utf8");
  for (const route of [
    "/api/v1/models",
    "/api/v1/server/start",
    "/api/v1/server/stop",
    "/api/v1/server/restart",
    "/api/v1/server/logs",
    "/api/v1/server/events",
    "/api/v1/backends",
    "/api/v1/models/catalog/search",
    "/api/v1/models/catalog/import-url",
    "/api/v1/models/storage/cleanup",
    "/api/v1/models/:id",
    "/api/v1/runtime/engines",
    "/api/v1/runtime/engines/",
    "/api/v1/runtime/survey",
    "/api/v1/runtime/select",
    "/api/v1/backends/:id/health",
    "/api/v1/backends/:id/start",
    "/api/v1/backends/:id/stop",
    "/api/v1/backends/:id/logs",
    "/api/v1/tokens",
    "/api/v1/models/load",
    "/api/v1/models/unload",
    "/api/v1/models/download",
    "/api/v1/models/download/cancel",
    "/api/v1/providers/:id/models",
    "/api/v1/providers/:id/loaded",
    "/api/v1/providers/:id/health/latest",
    "/api/v1/providers",
    "/api/v1/vault/refs",
    "/api/v1/vault/status",
    "/api/v1/vault/health",
    "/api/v1/vault/health/latest",
    "/api/v1/chat",
    "/api/v1/responses",
    "/api/v1/embeddings",
    "/api/v1/mcp/import",
    "/api/v1/routes",
    "/api/v1/routes/route.local-first/test",
    "/api/v1/receipts",
    "/api/v1/receipts/:id/replay",
    "/api/v1/projections/model-mounting",
    "/api/v1/workflows/nodes/execute",
  ]) {
    assert.match(source, new RegExp(route.replaceAll("/", "\\/")));
  }

  assert.match(source, /ENDPOINT_STORAGE_KEY/);
  assert.match(source, /setSessionToken/);
  assert.match(source, /sessionTokenLabel/);
  assert.match(source, /provider\.autopilot\.local/);
  assert.match(source, /backend\.autopilot\.native-local\.fixture/);
  assert.match(source, /backend\.llama-cpp/);
  assert.match(source, /route\.native-local/);
  assert.match(source, /Probe native backend/);
  assert.match(source, /Start native/);
  assert.match(source, /Stop native/);
  assert.match(source, /Load native-local/);
  assert.match(source, /Download fixture/);
  assert.match(source, /Search catalog/);
  assert.match(source, /Import URL/);
  assert.match(source, /Scan cleanup/);
  assert.match(source, /Catalog gate/);
  assert.match(source, /Download gate/);
  assert.match(source, /IOI_LIVE_MODEL_CATALOG/);
  assert.match(source, /IOI_LIVE_MODEL_DOWNLOAD/);
  assert.match(source, /Hugging Face-compatible catalog/);
  assert.match(source, /Result limit/);
  assert.match(source, /Quantization/);
  assert.match(source, /searchCatalog/);
  assert.match(source, /importCatalogUrl/);
  assert.match(source, /cleanupStorage/);
  assert.match(source, /Save provider/);
  assert.match(source, /Bind vault secret/);
  assert.match(source, /Vault adapter/);
  assert.match(source, /Check adapter/);
  assert.match(source, /restart-durable encrypted keychain/);
  assert.match(source, /session-only runtime memory/);
  assert.match(source, /metadata configured, needs runtime bind/);
  assert.match(source, /material bound in runtime session/);
  assert.match(source, /vault\.write:\*/);
  assert.match(source, /vault\.read:\*/);
  assert.match(source, /Token scope editor/);
  assert.match(source, /Create session token/);
  assert.match(source, /Allowed scopes/);
  assert.match(source, /Denied scopes/);
  assert.match(source, /session-only raw token/);
  assert.match(source, /grant hash only/);
  assert.match(source, /createTokenFromDraft/);
  assert.match(source, /revokeTokenGrant/);
  assert.match(source, /\/api\/v1\/tokens\/\$\{encodeURIComponent\(tokenId\)\}/);
  assert.match(source, /tokenDraftPayload/);
  assert.match(source, /model-mounts-token-editor/);
  assert.match(source, /Revoke/);
  assert.match(source, /Test health/);
  assert.match(source, /Latest health/);
  assert.match(source, /Latest vault health/);
  assert.match(source, /latestProviderHealth/);
  assert.match(source, /latestVaultHealth/);
  assert.match(source, /Health receipt/);
  assert.match(source, /Provider health/);
  assert.match(source, /Vault adapter health/);
  assert.match(source, /Health summary/);
  assert.match(source, /Provider health receipts/);
  assert.match(source, /Vault health receipts/);
  assert.match(source, /Blocked\/degraded/);
  assert.match(source, /Latest health receipt/);
  assert.match(source, /healthSummaryFromReceipts/);
  assert.match(source, /model-mounts-health-strip/);
  assert.match(source, /Run health sweep/);
  assert.match(source, /Restart/);
  assert.match(source, /Tail logs/);
  assert.match(source, /startServer/);
  assert.match(source, /stopServer/);
  assert.match(source, /restartServer/);
  assert.match(source, /tailServerLogs/);
  assert.match(source, /server\.control:\*/);
  assert.match(source, /server\.logs:\*/);
  assert.match(source, /runHealthSweep/);
  assert.match(source, /Run runtime survey/);
  assert.match(source, /runRuntimeSurvey/);
  assert.match(source, /selectRuntimeEngine/);
  assert.match(source, /updateRuntimeEngine/);
  assert.match(source, /forgetRuntimeEngine/);
  assert.match(source, /Runtime engine profile editor/);
  assert.match(source, /Save engine profile/);
  assert.match(source, /Forget profile/);
  assert.match(source, /Supervisor/);
  assert.match(source, /PID hash/);
  assert.match(source, /processPidHash/);
  assert.match(source, /Load with options/);
  assert.match(source, /Estimate load/);
  assert.match(source, /Quick model picker/);
  assert.match(source, /ModelPickerStrip/);
  assert.match(source, /Load selection/);
  assert.match(source, /Unload instance/);
  assert.match(source, /Loaded instance/);
  assert.match(source, /Model selection inspector/);
  assert.match(source, /Selected model detail drawer/);
  assert.match(source, /ModelDetailDrawer/);
  assert.match(source, /Artifact metadata/);
  assert.match(source, /Runtime binding/);
  assert.match(source, /Lifecycle history/);
  assert.match(source, /Receipt trail/);
  assert.match(source, /Close details/);
  assert.match(source, /model-mounts-detail-drawer/);
  assert.match(source, /modelSelectionDetails/);
  assert.match(source, /loadPickerSelection/);
  assert.match(source, /unloadInstance/);
  assert.match(source, /model-mounts-picker/);
  assert.match(source, /loadModelWithOptions/);
  assert.match(source, /contextLength/);
  assert.match(source, /estimateOnly/);
  assert.match(source, /Runtime survey/);
  assert.match(source, /runtimeEngines/);
  assert.match(source, /runtimeSurvey/);
  assert.match(source, /healthSweepProviderTargets/);
  assert.match(source, /healthSweepBackendTargets/);
  assert.match(source, /health-sweep/);
  assert.match(source, /Streaming observability/);
  assert.match(source, /Filtered logs, receipts, and redacted payloads/);
  assert.match(source, /ObservabilityFilters/);
  assert.match(source, /ObservabilityEvent/);
  assert.match(source, /defaultObservabilityFilters/);
  assert.match(source, /receiptCategory/);
  assert.match(source, /receiptDirection/);
  assert.match(source, /receiptStatus/);
  assert.match(source, /filteredObservabilityEvents/);
  assert.match(source, /observabilitySummary/);
  assert.match(source, /ObservabilityEventRow/);
  assert.match(source, /Observability filters/);
  assert.match(source, /Filtered observability stream/);
  assert.match(source, /model-mounts-observability-filters/);
  assert.match(source, /model-mounts-observability-summary/);
  assert.match(source, /model-mounts-observability-stream/);
  assert.match(source, /Redacted payload preview/);
  assert.match(source, /Live tail/);
  assert.match(source, /Tail server logs/);
  assert.match(source, /providerLastHealth/);
  assert.match(source, /List models/);
  assert.match(source, /provider\.write:\*/);
  assert.match(source, /route\.write:\*/);
  assert.match(source, /providerDraftPayload/);
  assert.match(source, /auth_scheme/);
  assert.match(source, /auth_header_name/);
  assert.match(source, /Route policy editor/);
  assert.match(source, /Route editor/);
  assert.match(source, /Save route/);
  assert.match(source, /Save and test route/);
  assert.match(source, /Provider eligibility/);
  assert.match(source, /Denied providers/);
  assert.match(source, /Allow hosted fallback when testing/);
  assert.match(source, /saveRouteDraft/);
  assert.match(source, /testRouteDraft/);
  assert.match(source, /routeDraftPayload/);
  assert.match(source, /model-mounts-route-editor/);
  assert.match(source, /Ephemeral MCP probe/);
  assert.match(source, /Run workflow probe/);
  assert.doesNotMatch(source, /localStorage\.setItem\([^,\n]*token/i);
  assert.doesNotMatch(source, /sessionStorage\.setItem\([^,\n]*token/i);
  assert.doesNotMatch(source, /localStorage\.setItem\([^,\n]*(secret|vault|auth)/i);
  assert.doesNotMatch(source, /sessionStorage\.setItem\([^,\n]*(secret|vault|auth)/i);
  assert.match(source, /vault:\/\/mcp\.huggingface\/authorization/);
  assert.doesNotMatch(source, /vault:\/\/provider\.(openai|anthropic|gemini)\/api-key/);
  assert.match(source, /offline fixture projection/);
  assert.match(source, /VITE_AUTOPILOT_MOUNTS_DAEMON_ENDPOINT/);
  assert.match(source, /mountsEndpoint/);
  assert.match(source, /mountsTab/);
  assert.match(source, /Number\.parseInt\(event\.key/);
  assert.match(source, /\^F\[1-9\]\$/);
  assert.match(source, /Benchmarks and results/);
  assert.match(source, /Benchmark runner/);
  assert.match(source, /Run benchmark/);
  assert.match(source, /Benchmark results/);
  assert.match(source, /runBenchmark/);
  assert.match(source, /benchmarkSummary/);
  assert.match(source, /model-mounts-benchmark-editor/);
  assert.match(source, /model-mounts-benchmark-results/);
  assert.match(source, /Route quality telemetry/);
  assert.match(source, /ActionGuard/);
  assert.match(source, /Action readiness states/);
  assert.match(source, /GuardFact/);
  assert.match(source, /model-mounts-action-readiness/);
  assert.match(source, /model-mounts-action-guard/);
  assert.match(source, /data-guard-tone/);
  assert.match(source, /connectionActionGuard/);
  assert.match(source, /tokenScopeGuard/);
  assert.match(source, /providerGuard/);
  assert.match(source, /endpointGuard/);
  assert.match(source, /backendGuard/);
  assert.match(source, /routePolicyGuard/);
  assert.match(source, /selectedActionGuard/);
  assert.match(source, /providerDraftGuard/);
  assert.match(source, /vaultBindGuard/);
  assert.match(source, /daemon offline/);
  assert.match(source, /token on demand/);
  assert.match(source, /denied scope/);
  assert.match(source, /token expired/);
  assert.match(source, /scope missing/);
  assert.match(source, /provider blocked/);
  assert.match(source, /backend degraded/);
  assert.match(source, /vault ref missing/);
  assert.match(source, /unsupported/);
  assert.match(source, /privacy blocked/);
  assert.match(source, /policy blocked/);
});

test("Mounts GUI validation uses a dedicated desktop harness", () => {
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const runnerPath = path.join(root, "scripts", "run-model-mounts-gui-validation.mjs");
  const probePath = path.join(root, "apps", "autopilot", "scripts", "desktop_model_mounts_probe.py");
  const runner = fs.readFileSync(runnerPath, "utf8");
  const probe = fs.readFileSync(probePath, "utf8");
  assert.equal(
    packageJson.scripts["validate:model-mounts-gui:run"],
    "node scripts/run-model-mounts-gui-validation.mjs",
  );
  assert.match(runner, /desktop_model_mounts_probe\.py/);
  assert.match(probe, /view=mounts/);
  assert.match(probe, /VITE_AUTOPILOT_MOUNTS_DAEMON_ENDPOINT/);
  assert.match(probe, /MOUNT_TABS/);
  assert.match(probe, /MIN_DISTINCT_TAB_TRANSITIONS/);
  assert.match(probe, /capture_window_with_fallback/);
  assert.match(probe, /scan_for_plaintext_secrets/);
});

test("model mounting end-to-end validation is wired as the acceptance gate", () => {
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const e2ePath = path.join(root, "scripts", "validate-model-mounting-e2e.mjs");
  const source = fs.readFileSync(e2ePath, "utf8");
  assert.equal(
    packageJson.scripts["validate:model-mounting:e2e"],
    "node scripts/validate-model-mounting-e2e.mjs",
  );
  for (const token of [
    "startRuntimeDaemonService",
    "/api/v1/workflows/nodes/execute",
    "/api/v1/workflows/receipt-gate",
    "/v1/chat/completions",
    "/v1/embeddings",
    "runCli",
    "runGuiValidation",
    "scanFilesForSecrets",
    "receipt replay and projection continuity after daemon restart",
  ]) {
    assert.match(source, new RegExp(token.replaceAll("/", "\\/")));
  }
});

test("model mounting live-provider gates are explicit and opt-in", () => {
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const liveGatePath = path.join(root, "scripts", "live-model-mounting-gate.mjs");
  const source = fs.readFileSync(liveGatePath, "utf8");
  assert.equal(
    packageJson.scripts["test:lm-studio-live"],
    "node scripts/live-model-mounting-gate.mjs lm-studio",
  );
  assert.equal(
    packageJson.scripts["test:llama-cpp-live"],
    "node scripts/live-model-mounting-gate.mjs llama-cpp",
  );
  assert.equal(
    packageJson.scripts["test:model-backends:live"],
    "node scripts/live-model-mounting-gate.mjs model-backends",
  );
  assert.equal(
    packageJson.scripts["test:model-catalog-live"],
    "node scripts/live-model-mounting-gate.mjs model-catalog",
  );
  assert.equal(
    packageJson.scripts["test:wallet-live"],
    "node scripts/live-model-mounting-gate.mjs wallet",
  );
  assert.equal(
    packageJson.scripts["test:agentgres-live"],
    "node scripts/live-model-mounting-gate.mjs agentgres",
  );
  for (const token of [
    "IOI_LIVE_LM_STUDIO",
    "IOI_LIVE_LLAMA_CPP",
    "IOI_LLAMA_CPP_MODEL_PATH",
    "IOI_LLAMA_CPP_MODEL_ID",
    "IOI_LLAMA_CPP_LIVE_TIMEOUT_MS",
    "IOI_LIVE_MODEL_BACKENDS",
    "IOI_LIVE_MODEL_CATALOG",
    "IOI_LIVE_MODEL_DOWNLOAD",
    "IOI_MODEL_CATALOG_HF_BASE_URL",
    "IOI_MODEL_CATALOG_DOWNLOAD_SOURCE_URL",
    "IOI_MODEL_CATALOG_DOWNLOAD_FIRST_RESULT",
    "IOI_MODEL_CATALOG_DOWNLOAD_MAX_BYTES",
    "IOI_MODEL_DOWNLOAD_MAX_BYTES",
    "IOI_REMOTE_WALLET",
    "IOI_REMOTE_AGENTGRES",
    "docs/evidence/model-mounting-live",
    "lm_studio_server_stopped",
    "model_catalog_live_provider_unavailable",
    "remote_wallet_network_not_configured",
    "remote_agentgres_not_configured",
  ]) {
    assert.match(source, new RegExp(token.replaceAll("/", "\\/")));
  }
});

test("model mounting CLI exposes vault-backed provider configuration flags", () => {
  const source = fs.readFileSync(path.join(root, "crates", "cli", "src", "commands", "models.rs"), "utf8");
  const backendsSource = fs.readFileSync(path.join(root, "crates", "cli", "src", "commands", "backends.rs"), "utf8");
  const serverSource = fs.readFileSync(path.join(root, "crates", "cli", "src", "commands", "server.rs"), "utf8");
  const vaultSource = fs.readFileSync(path.join(root, "crates", "cli", "src", "commands", "vault.rs"), "utf8");
  const combinedSource = `${source}\n${backendsSource}\n${serverSource}\n${vaultSource}`;
  for (const token of [
    "ProviderSet",
    "VaultCommands",
    "/api/v1/providers",
    "/api/v1/models/catalog/search",
    "/api/v1/models/catalog/import-url",
    "/api/v1/models/storage/cleanup",
    "/api/v1/vault/refs",
    "/api/v1/vault/status",
    "/api/v1/vault/health",
    "/api/v1/vault/health/latest",
    "/health/latest",
    "secret_ref",
    "auth_scheme",
    "auth_header_name",
    "material_env",
    "ProviderHealth",
    "Health",
    "Survey",
    "Select",
    "Engines",
    "EngineGet",
    "EngineUpdate",
    "EngineRemove",
    "/api/v1/runtime/survey",
    "/api/v1/runtime/select",
    "/api/v1/runtime/engines",
    "/api/v1/server/restart",
    "/api/v1/server/logs",
    "/api/v1/server/events",
    "estimate_only",
    "context_length",
    "ttl_seconds",
    "identifier",
    "CatalogSearch",
    "CatalogImportUrl",
    "quantization",
    "format",
    "limit",
    "Delete",
    "Cleanup",
    "import_mode",
    "Restart",
    "Logs",
    "Events",
    "Raw keys are rejected by the daemon",
  ]) {
    assert.match(combinedSource, new RegExp(token.replaceAll("/", "\\/")));
  }
});

test("workflow canvas model mounting contract is represented in Agent IDE node schemas", () => {
  const graphTypes = fs.readFileSync(
    path.join(root, "packages", "agent-ide", "src", "types", "graph.ts"),
    "utf8",
  );
  const registry = fs.readFileSync(
    path.join(root, "packages", "agent-ide", "src", "runtime", "workflow-node-registry.ts"),
    "utf8",
  );
  for (const token of ["routeId", "modelPolicy", "capability", "receiptRequired", "selectedEndpointId", "requiredToolReceiptIds"]) {
    assert.match(graphTypes, new RegExp(token));
  }
  assert.match(registry, /route\.local-first/);
  assert.match(registry, /\/api\/v1\/workflows\/nodes\/execute/);
  assert.match(registry, /receiptRequired:\s*true/);
});
