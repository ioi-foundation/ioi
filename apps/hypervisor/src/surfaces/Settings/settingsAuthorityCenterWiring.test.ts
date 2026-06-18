import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const settingsView = fs.readFileSync(
  new URL("./SettingsView.tsx", import.meta.url),
  "utf8",
);
const settingsViewBody = fs.readFileSync(
  new URL("./SettingsViewBody.tsx", import.meta.url),
  "utf8",
);
const authorityRuntime = fs.readFileSync(
  new URL("../Policy/authorityCenterRuntime.ts", import.meta.url),
  "utf8",
);
const authorityCenterPanel = fs.readFileSync(
  new URL("../Policy/AuthorityCenterPanel.tsx", import.meta.url),
  "utf8",
);
const authorityCenterModel = fs.readFileSync(
  new URL("../Policy/authorityCenter.ts", import.meta.url),
  "utf8",
);
const codeEditorAdapterPreferences = fs.readFileSync(
  new URL(
    "../../windows/HypervisorShellWindow/codeEditorAdapterPreferences.ts",
    import.meta.url,
  ),
  "utf8",
);
const authoritySettingsSurfaceView = fs.readFileSync(
  new URL("../Authority/AuthoritySettingsSurfaceView.tsx", import.meta.url),
  "utf8",
);
const retiredToolCatalogRoutePattern = new RegExp(
  ["\\/api", "\\/v1\\/tools"].join(""),
);
const retiredAuthorityFetchHelper = ["fetchAuthorityJson", "First"].join("");

test("policy authority surface is wired to the canonical authority projection", () => {
  assert.match(authorityRuntime, /loadAuthorityCenterRuntimeProjection/);
  assert.match(authorityRuntime, /buildAuthorityCenterProjection/);
  assert.match(authoritySettingsSurfaceView, /<PolicyView/);
  assert.match(authoritySettingsSurfaceView, /onOpenModelRoutes/);
  assert.match(authoritySettingsSurfaceView, /onOpenWorkflowPreflight/);
  assert.doesNotMatch(settingsViewBody, /SettingsAuthoritySection/);
  assert.doesNotMatch(settingsViewBody, /selectedSection === "authority"/);
});

test("authority center exposes canonical grant policy receipt posture", () => {
  assert.match(authorityCenterModel, /grantStatus/);
  assert.match(authorityCenterModel, /policyStatus/);
  assert.match(authorityCenterModel, /receiptStatus/);
  assert.match(authorityCenterModel, /lastRepairReceiptRefs/);
  assert.match(authorityCenterModel, /authorityEvidenceSnapshot/);
  assert.match(authorityCenterModel, /authorityEvidenceSummaryRows/);
  assert.match(authorityCenterModel, /authorityEvidenceReceiptRefsForCapability/);
  assert.match(authorityCenterModel, /safeReceiptRefs/);
  assert.doesNotMatch(authorityCenterModel, /runtimeThreadEvents|nodeRuns/);
  assert.doesNotMatch(
    authorityCenterModel,
    /field\(.*"(payload|output)"/,
  );
  assert.match(authorityCenterModel, /capabilityRuntimeReady/);
  assert.match(authorityCenterPanel, /data-capability-ref/);
  assert.match(authorityCenterPanel, /data-grant-status/);
  assert.match(authorityCenterPanel, /data-policy-status/);
  assert.match(authorityCenterPanel, /data-receipt-status/);
  assert.match(authorityCenterPanel, /data-repair-receipt-count/);
  assert.match(authorityCenterPanel, /shield-authority-repair-trail/);
  assert.match(authorityCenterPanel, /lastRepairSummary/);
  assert.match(authorityCenterPanel, /lastRepairReceiptRefs/);
  assert.match(authorityCenterPanel, /Runtime refs/);
  assert.match(authorityCenterPanel, /Run-ready/);
});

test("settings authority runtime uses stable Rust authority and tool catalog protocols", () => {
  assert.match(authorityRuntime, /MODEL_CAPABILITY_BINDING_ENDPOINT/);
  assert.match(authorityRuntime, /TOOL_CAPABILITY_BINDING_ENDPOINT/);
  assert.match(authorityRuntime, /MODEL_AUTHORITY_BINDING_ENDPOINT/);
  assert.match(
    authorityRuntime,
    /AUTHORITY_EVIDENCE_SUMMARIES_ENDPOINT/,
  );
  assert.match(
    authorityRuntime,
    /authorityEvidenceSnapshot[\s\S]*buildAuthorityCenterProjection/,
  );
  assert.match(
    authorityRuntime,
    /fetchAuthorityJson\(endpoint,\s*MODEL_CAPABILITY_BINDING_ENDPOINT\)/,
  );
  assert.match(
    authorityRuntime,
    /fetchAuthorityJson\(endpoint,\s*TOOL_CAPABILITY_BINDING_ENDPOINT\)/,
  );
  assert.match(
    authorityRuntime,
    new RegExp('"/v1/authority-evidence"'),
  );
  assert.doesNotMatch(authorityRuntime, new RegExp(retiredAuthorityFetchHelper));
  assert.doesNotMatch(authorityRuntime, retiredToolCatalogRoutePattern);
  assert.doesNotMatch(authorityRuntime, /\/api\/v1\/authority-evidence/);
  assert.doesNotMatch(authorityRuntime, /\/api\/v1\/workflow-capability-preflight/);
});

test("settings expose code editor adapter preference as a client default", () => {
  assert.match(settingsViewBody, /data-settings-reference-shell="ioi-settings"/);
  assert.match(settingsViewBody, /Account/);
  assert.match(settingsViewBody, /Secrets/);
  assert.match(settingsViewBody, /Git authentications/);
  assert.match(settingsViewBody, /Personal access tokens/);
  assert.match(settingsViewBody, /Integrations/);
  assert.match(settingsViewBody, /Account details/);
  assert.match(settingsViewBody, /Account ID/);
  assert.match(settingsViewBody, /Default code editor target/);
  assert.match(settingsViewBody, /SettingsEditorTargetList/);
  assert.match(settingsViewBody, /data-settings-editor-picker/);
  assert.match(settingsViewBody, /data-settings-editor-target/);
  assert.match(settingsViewBody, /Embedded code editor/);
  assert.doesNotMatch(
    settingsViewBody,
    /chat-settings-reference-advanced|<summary>Advanced<\/summary>/,
  );
  assert.match(
    settingsViewBody,
    /This will be your default code editor for workspace sessions/,
  );
  assert.doesNotMatch(settingsViewBody, /Default Workbench target/);
  assert.doesNotMatch(settingsViewBody, /Embedded Workbench/);
  assert.doesNotMatch(settingsViewBody, /Default Editor/);
  assert.doesNotMatch(settingsViewBody, /default selected editor/);
  assert.doesNotMatch(settingsViewBody, /Code tab/);
  assert.doesNotMatch(settingsViewBody, /Show the embedded VS Code editor/);
  assert.match(
    settingsViewBody,
    /Connect editor adapters, terminals, browsers, cloud accounts, model providers, and storage services/,
  );
  assert.match(settingsViewBody, /data-settings-reference-organization-link/);
  assert.doesNotMatch(settingsViewBody, /governed sessions/);
  assert.doesNotMatch(settingsViewBody, /plaintext custody domain/);
  assert.doesNotMatch(settingsViewBody, /adapter_preference_ref/);
  assert.match(codeEditorAdapterPreferences, /VS Code Insiders/);
  assert.match(codeEditorAdapterPreferences, /Cursor/);
  assert.match(codeEditorAdapterPreferences, /Windsurf/);
  assert.match(codeEditorAdapterPreferences, /IntelliJ IDEA Ultimate/);
  assert.match(codeEditorAdapterPreferences, /PyCharm Professional/);
  assert.match(codeEditorAdapterPreferences, /RubyMine/);
  assert.match(codeEditorAdapterPreferences, /WebStorm/);
  assert.match(codeEditorAdapterPreferences, /CLion/);
  assert.match(codeEditorAdapterPreferences, /RustRover/);
  assert.match(codeEditorAdapterPreferences, /Rider/);
  assert.match(codeEditorAdapterPreferences, /VS Code Browser/);
  assert.match(settingsView, /codeEditorAdapterPreferenceRef/);
  assert.match(settingsView, /chat-settings-view--reference/);
  assert.match(
    settingsView,
    /HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCE_STORAGE_KEY/,
  );
  assert.match(codeEditorAdapterPreferences, /executor_lane/);
  assert.match(codeEditorAdapterPreferences, /control_action/);
  assert.match(codeEditorAdapterPreferences, /control_channel_ref/);
  assert.match(codeEditorAdapterPreferences, /custody_posture/);
  assert.doesNotMatch(settingsViewBody, /buildCodeEditorAdapterLaunchPlan/);
  assert.doesNotMatch(settingsViewBody, /data-code-editor-adapter-executor-lane/);
  assert.doesNotMatch(settingsViewBody, /data-code-editor-adapter-control-action/);
});

test("authority repair actions route to canonical surfaces outside Settings", () => {
  assert.match(authoritySettingsSurfaceView, /onOpenModelRoutes/);
  assert.match(authoritySettingsSurfaceView, /onOpenWorkflowPreflight/);
  assert.doesNotMatch(settingsView, /onOpenModelRoutes/);
  assert.doesNotMatch(settingsView, /onOpenWorkflowPreflight/);
});

console.log("settingsAuthorityCenterWiring.test.ts: ok");
