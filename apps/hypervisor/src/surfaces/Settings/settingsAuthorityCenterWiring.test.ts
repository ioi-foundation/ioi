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
const settingsAuthoritySection = fs.readFileSync(
  new URL("./SettingsAuthoritySection.tsx", import.meta.url),
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
const environmentSection = fs.readFileSync(
  new URL("./SettingsEnvironmentSection.tsx", import.meta.url),
  "utf8",
);
const codeEditorAdapterSection = fs.readFileSync(
  new URL("./SettingsCodeEditorAdapterSection.tsx", import.meta.url),
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

test("settings authority section is wired to the canonical authority projection", () => {
  assert.match(settingsViewBody, /selectedSection === "authority"/);
  assert.match(settingsViewBody, /SettingsAuthoritySection/);
  assert.match(settingsView, /loadAuthorityCenterRuntimeProjection/);
  assert.match(settingsView, /authorityCenterProjection/);
  assert.match(settingsAuthoritySection, /settings-authority-center/);
  assert.match(settingsAuthoritySection, /settings-authority-fail-closed/);
  assert.match(settingsAuthoritySection, /settings-authority-capability-row/);
  assert.match(settingsAuthoritySection, /data-capability-ref/);
  assert.match(settingsAuthoritySection, /data-grant-status/);
  assert.match(settingsAuthoritySection, /data-policy-status/);
  assert.match(settingsAuthoritySection, /data-receipt-status/);
  assert.match(settingsAuthoritySection, /data-repair-receipt-count/);
  assert.match(settingsAuthoritySection, /chat-settings-repair-trail/);
  assert.match(settingsAuthoritySection, /lastRepairSummary/);
  assert.match(settingsAuthoritySection, /lastRepairReceiptRefs/);
  assert.match(settingsAuthoritySection, /Runtime refs/);
  assert.match(settingsAuthoritySection, /settings-authority-repair-actions/);
  assert.match(settingsAuthoritySection, /data-repair-action-kind/);
  assert.match(
    settingsAuthoritySection,
    /openWorkflowPreflight[\s\S]*panel: "readiness"[\s\S]*capabilityRef: action\.targetRef[\s\S]*source: "settings-authority"/,
  );
  assert.match(settingsAuthoritySection, /openModelRoute/);
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

test("environment settings are labeled as compatibility, not authority truth", () => {
  assert.match(environmentSection, /Compatibility bindings/);
  assert.match(environmentSection, /Source of truth/);
  assert.match(environmentSection, /Authority Center/);
});

test("settings expose code editor adapter preference as a client default", () => {
  assert.match(settingsViewBody, /selectedSection === "code_editor_adapter"/);
  assert.match(settingsViewBody, /SettingsCodeEditorAdapterSection/);
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
  assert.match(settingsViewBody, /className="chat-settings-reference-advanced"/);
  assert.match(settingsViewBody, /<summary>Advanced<\/summary>/);
  assert.doesNotMatch(
    settingsViewBody,
    /className="chat-settings-reference-advanced" hidden/,
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
  assert.match(codeEditorAdapterSection, /Default editor target/);
  assert.match(codeEditorAdapterSection, /HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES/);
  assert.match(codeEditorAdapterSection, /buildCodeEditorAdapterLaunchPlan/);
  assert.match(codeEditorAdapterSection, /data-code-editor-adapter-preference/);
  assert.match(codeEditorAdapterSection, /data-code-editor-adapter-executor-lane/);
  assert.match(codeEditorAdapterSection, /data-code-editor-adapter-control-action/);
  assert.match(codeEditorAdapterSection, /data-code-editor-adapter-control-channel-ref/);
  assert.match(codeEditorAdapterSection, /controlActionLabel/);
  assert.match(codeEditorAdapterSection, /Open embedded/);
  assert.match(codeEditorAdapterSection, /Open desktop/);
  assert.match(codeEditorAdapterSection, /Open browser editor/);
  assert.match(codeEditorAdapterSection, /Local workspace/);
  assert.match(codeEditorAdapterSection, /Session preference/);
  assert.match(codeEditorAdapterSection, /Sessions and Environments own terminal/);
  assert.doesNotMatch(codeEditorAdapterSection, /adapter_preference_ref/);
  assert.doesNotMatch(codeEditorAdapterSection, /preference\.launch_mode\} \/ /);
  assert.doesNotMatch(codeEditorAdapterSection, /custody_posture\.split/);
});

test("settings authority repair actions route to canonical surfaces", () => {
  assert.match(settingsView, /onOpenModelRoutes/);
  assert.match(settingsView, /onOpenWorkflowPreflight/);
  assert.match(authoritySettingsSurfaceView, /onOpenModelRoutes/);
  assert.match(authoritySettingsSurfaceView, /onOpenWorkflowPreflight/);
});

console.log("settingsAuthorityCenterWiring.test.ts: ok");
