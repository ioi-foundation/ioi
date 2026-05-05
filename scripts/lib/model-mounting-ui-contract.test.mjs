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
    "/api/v1/backends",
    "/api/v1/runtime/engines",
    "/api/v1/runtime/survey",
    "/api/v1/runtime/select",
    "/api/v1/backends/:id/health",
    "/api/v1/backends/:id/start",
    "/api/v1/backends/:id/stop",
    "/api/v1/backends/:id/logs",
    "/api/v1/tokens",
    "/api/v1/models/load",
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
    "/api/v1/mcp/import",
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
  assert.match(source, /Test health/);
  assert.match(source, /Latest health/);
  assert.match(source, /Latest vault health/);
  assert.match(source, /latestProviderHealth/);
  assert.match(source, /latestVaultHealth/);
  assert.match(source, /Health receipt/);
  assert.match(source, /Provider health/);
  assert.match(source, /Vault adapter health/);
  assert.match(source, /Replay latest provider health/);
  assert.match(source, /Replay latest vault health/);
  assert.match(source, /Health summary/);
  assert.match(source, /Provider health receipts/);
  assert.match(source, /Vault health receipts/);
  assert.match(source, /Blocked\/degraded/);
  assert.match(source, /Latest health receipt/);
  assert.match(source, /healthSummaryFromReceipts/);
  assert.match(source, /model-mounts-health-strip/);
  assert.match(source, /Run health sweep/);
  assert.match(source, /runHealthSweep/);
  assert.match(source, /Run runtime survey/);
  assert.match(source, /runRuntimeSurvey/);
  assert.match(source, /selectRuntimeEngine/);
  assert.match(source, /Load with options/);
  assert.match(source, /Estimate load/);
  assert.match(source, /loadModelWithOptions/);
  assert.match(source, /contextLength/);
  assert.match(source, /estimateOnly/);
  assert.match(source, /Runtime survey/);
  assert.match(source, /runtimeEngines/);
  assert.match(source, /runtimeSurvey/);
  assert.match(source, /healthSweepProviderTargets/);
  assert.match(source, /healthSweepBackendTargets/);
  assert.match(source, /health-sweep/);
  assert.match(source, /model-mounts-receipt-groups/);
  assert.match(source, /providerLastHealth/);
  assert.match(source, /List models/);
  assert.match(source, /provider\.write:\*/);
  assert.match(source, /providerDraftPayload/);
  assert.match(source, /auth_scheme/);
  assert.match(source, /auth_header_name/);
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
  assert.match(source, /\^F\[1-8\]\$/);
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
    packageJson.scripts["test:model-backends:live"],
    "node scripts/live-model-mounting-gate.mjs model-backends",
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
    "IOI_LIVE_MODEL_BACKENDS",
    "IOI_REMOTE_WALLET",
    "IOI_REMOTE_AGENTGRES",
    "docs/evidence/model-mounting-live",
    "lm_studio_server_stopped",
    "remote_wallet_network_not_configured",
    "remote_agentgres_not_configured",
  ]) {
    assert.match(source, new RegExp(token.replaceAll("/", "\\/")));
  }
});

test("model mounting CLI exposes vault-backed provider configuration flags", () => {
  const source = fs.readFileSync(path.join(root, "crates", "cli", "src", "commands", "models.rs"), "utf8");
  const backendsSource = fs.readFileSync(path.join(root, "crates", "cli", "src", "commands", "backends.rs"), "utf8");
  const vaultSource = fs.readFileSync(path.join(root, "crates", "cli", "src", "commands", "vault.rs"), "utf8");
  const combinedSource = `${source}\n${backendsSource}\n${vaultSource}`;
  for (const token of [
    "ProviderSet",
    "VaultCommands",
    "/api/v1/providers",
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
    "/api/v1/runtime/survey",
    "/api/v1/runtime/select",
    "estimate_only",
    "context_length",
    "ttl_seconds",
    "identifier",
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
