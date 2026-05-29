import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const extensionSourcePath =
  "apps/autopilot/openvscode-extension/ioi-workbench/extension.js";
const studioPanelHtmlPath =
  "apps/autopilot/openvscode-extension/ioi-workbench/studio/studio-panel-html.js";
const studioModelCompletionPath =
  "apps/autopilot/openvscode-extension/ioi-workbench/studio/model-completion.js";
const studioOperationalSurfacePath =
  "apps/autopilot/openvscode-extension/ioi-workbench/studio/operational-surface.js";
const studioModelSurfacePath =
  "apps/autopilot/openvscode-extension/ioi-workbench/studio/model-surface.js";
const packageJsonPath =
  "apps/autopilot/openvscode-extension/ioi-workbench/package.json";
const codiconSourcePath =
  "packages/workspace-substrate/src/components/Codicon.tsx";
const desktopLauncherPath = "scripts/launch-autopilot-ide-fork.mjs";
const shellPatchPath = "scripts/lib/autopilot-workbench-shell-patch.mjs";

async function readExtensionCompositeSource() {
  const parts = await Promise.all([
    readFile(extensionSourcePath, "utf8"),
    readFile(studioPanelHtmlPath, "utf8"),
    readFile(studioModelCompletionPath, "utf8"),
    readFile(studioOperationalSurfacePath, "utf8"),
    readFile(studioModelSurfacePath, "utf8"),
  ]);
  return parts.join("\n");
}

function lineCount(source) {
  return source.split("\n").length;
}

test("native IOI chat view renders the canonical operator chat pane shell", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /data-operator-chat-pane="native-openvscode"/);
  assert.match(source, /data-inspection-target="native-ioi-chat-pane"/);
  assert.match(source, /data-inspection-target="native-ioi-chat-composer"/);
  assert.match(source, /Generate Agent Instructions/);
  assert.match(source, /Build Workspace/);
  assert.match(source, /function renderNativeChatConversation/);
  assert.match(source, /data-inspection-target="native-ioi-chat-thread"/);
  assert.match(source, /data-chat-turn-role/);
  assert.match(source, /state\.chat\?\.turns/);
  assert.match(
    source,
    /label: "Build Workspace",[\s\S]*requestType: "workflow\.codeGenerationRequest"/,
  );
  assert.match(source, /targetWorkspace/);
  assert.match(source, /Show Config/);
  assert.match(source, /requestType: "chat\.submit"/);
});

test("native IOI chat composer uses canonical Autopilot icons and layout tokens", async () => {
  const source = await readExtensionCompositeSource();
  const codiconSource = await readFile(codiconSourcePath, "utf8");
  const canonicalToolsPath = codiconSource.match(
    /<path d="([^"]*M5\.66901[^"]*)"/,
  )?.[1];

  assert.match(source, /function renderNativeChatIcon/);
  assert.ok(canonicalToolsPath);
  assert.match(source, /case "paperclip"/);
  assert.match(source, /case "device-desktop"/);
  assert.match(source, /case "cube"/);
  assert.match(source, /case "symbol-operator"/);
  assert.match(source, /case "tools"/);
  assert.match(source, /case "send"/);
  assert.match(source, /data-tauri-icon="paperclip"/);
  assert.match(source, /data-tauri-icon="cube"/);
  assert.match(source, /data-tauri-icon="stop"/);
  assert.match(source, /data-tauri-codicon="device-desktop"/);
  assert.match(source, /data-tauri-codicon="symbol-operator"/);
  assert.match(source, /data-tauri-codicon="chevron-down"/);
  assert.match(source, /data-tauri-codicon="send"/);
  assert.match(source, /data-tauri-codicon="tools"/);
  assert.match(source, /M13\.013 1\.013L2\.987 1\.013/);
  assert.match(source, /m21 16-9 5-9-5V8l9-5 9 5v8Z/);
  assert.match(source, /M6\.987 4\.480/);
  assert.match(source, /M1\.173 1\.120/);
  assert.ok(source.includes(canonicalToolsPath));
  assert.match(source, /class="operator-chat-icon-select"/);
  assert.match(source, /class="operator-chat-tool-toggle"/);
  assert.match(source, /data-bridge-request="commandCenter\.open"/);
  assert.match(source, /data-payload='\{"mode":"tools"\}'/);
  assert.match(source, /data-bridge-request="\$\{escapeHtml\(action\.requestType/);
  assert.doesNotMatch(source, /data-native-tool-picker-button/);
  assert.doesNotMatch(source, /class="operator-chat-tool-menu"/);
  assert.doesNotMatch(source, /data-native-tool-search/);
  assert.doesNotMatch(source, /data-native-tool-item/);
  assert.doesNotMatch(source, /function renderNativeChatToolMenu/);
  assert.doesNotMatch(source, /openNativeToolMenu/);
  assert.doesNotMatch(source, /closeNativeToolMenu/);
  assert.doesNotMatch(source, /data-bridge-request="chat\.toolControls"/);
  assert.match(source, /data-autopilot-theme="\$\{escapeHtml\(appearanceThemeId\)\}"/);
  assert.match(source, /--ioi-operator-chat-accent: #0098ff/);
  assert.match(source, /--operator-chat-accent: var\(\s*--ioi-operator-chat-accent/);
  assert.match(source, /--ioi-operator-chat-selected-border/);
  assert.match(source, /width: min\(100% - 24px, 360px\)/);
  assert.match(source, /enableForms: true/);
  assert.match(source, /this\.lastRenderedHtml = null/);
  assert.match(source, /if \(html === this\.lastRenderedHtml\)/);
  assert.match(source, /autocomplete="off"/);
  assert.match(source, /spellcheck="false"/);
  assert.match(source, /const focusComposerInput = \(\) =>/);
  assert.match(source, /composer\?\.addEventListener\("pointerdown"/);
  assert.match(source, /composerInput\?\.addEventListener\("pointerdown", focusComposerInput\)/);
  assert.match(source, /dataset\.chatMode/);
  assert.match(source, /dataset\.chatModel/);
  assert.doesNotMatch(source, /var\(--vscode-focusBorder\)/);
  assert.doesNotMatch(source, /data-testid="studio-add-context"[^>]*>⌕/);
  assert.doesNotMatch(source, /data-testid="studio-target-toggle"[^>]*>▣⌄/);
  assert.doesNotMatch(source, /data-testid="studio-model-toggle"[^>]*>◇⌄/);
  assert.doesNotMatch(source, /data-testid="studio-tools-toggle"[^>]*>⚒/);
  assert.doesNotMatch(source, /data-testid="studio-send-icon"[^>]*>▷/);
});

test("Agent Studio composer uses the Tauri chat source glyph vocabulary", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /data-testid="studio-add-context"[\s\S]*renderNativeChatIcon\("paperclip"\)/);
  assert.match(source, /data-testid="studio-composer-context-row"[\s\S]*data-testid="studio-add-context"[\s\S]*data-testid="studio-composer-input"[\s\S]*data-testid="studio-composer-toggle-row"/);
  assert.match(source, /\.studio-composer-context-row \.studio-context-btn \{[\s\S]*border-color: var\(--studio-border\)/);
  assert.match(source, /\.studio-composer-context-row \.studio-context-btn:hover \{[\s\S]*border-color: var\(--studio-border-strong\)/);
  assert.match(source, /data-testid="studio-target-toggle"[\s\S]*renderNativeChatIcon\("device-desktop"\)/);
  assert.match(source, /data-testid="studio-target-toggle"[\s\S]*renderNativeChatIcon\("chevron-down"\)/);
  assert.match(source, /data-testid="studio-model-toggle"[^>]*data-command="ioi\.quickInput\.modelRoute\.pick"/);
  assert.match(source, /data-testid="studio-model-toggle"[\s\S]*renderNativeChatIcon\("cube"\)/);
  assert.match(source, /mountedModelQuickInputRowsFromState\(state\)/);
  assert.match(source, /const activeRouteId = studioRuntimeProjection\.modelRoute \|\| "route\.local-first"/);
  assert.match(source, /score: 1_000 \+ modelRecordStatusScore\(activeEndpoint, activeRoute, activeArtifact\)/);
  assert.match(source, /function studioReasoningControlForSelection/);
  assert.match(source, /function studioReasoningEffortOptions/);
  assert.match(source, /const STUDIO_MODE_ASK = "ask"/);
  assert.match(source, /function normalizeStudioExecutionMode/);
  assert.match(source, /normalized === "ask"/);
  assert.match(source, /function studioExecutionModeLabel/);
  assert.match(source, /STUDIO_MODE_ASK \? "Ask" : "Agent"/);
  assert.match(source, /const STUDIO_PERMISSION_MODE_DEFAULT = "suggest"/);
  assert.match(source, /const STUDIO_PERMISSION_MODE_AUTO_REVIEW = "auto_local"/);
  assert.match(source, /const STUDIO_PERMISSION_MODE_FULL_ACCESS = "never_prompt"/);
  assert.match(source, /function normalizeStudioPermissionMode/);
  assert.match(source, /function studioPermissionDaemonMapping/);
  assert.match(source, /function applyStudioPermissionModeSelection/);
  assert.match(source, /function executionModeFromAgentModeResult/);
  assert.match(source, /function applyAgentModeResult/);
  assert.match(source, /function permissionModeFromResult/);
  assert.match(source, /function applyPermissionModeResult/);
  assert.match(source, /const selectedExecutionMode = result\.kind === "agentMode" \? applyAgentModeResult\(result\) : undefined/);
  assert.match(source, /const selectedPermissionMode = result\.kind === "permissionMode" \? applyPermissionModeResult\(result\) : undefined/);
  assert.match(source, /function studioModelIdForRouteInvocation/);
  assert.match(source, /const STUDIO_PRODUCT_MODEL_UNAVAILABLE = "__product_model_unavailable__"/);
  assert.match(source, /function isProductStudioModelSelection/);
  assert.match(source, /function isExternalStudioModelRecord/);
  assert.match(source, /IOI_STUDIO_ALLOW_EXTERNAL_MODEL_PROVIDERS/);
  assert.match(source, /function studioProductModelSelectionError/);
  assert.match(source, /function assertStudioProductModelSelector/);
  assert.match(source, /assertStudioProductModelSelector\(selectedRoute, explicitModelId\)/);
  assert.match(source, /Product model route unavailable/);
  assert.match(source, /No product model is mounted for this route/);
  assert.match(source, /record\.backendId/);
  assert.match(source, /record\.artifactId/);
  assert.match(source, /record\.displayName/);
  assert.match(source, /lmstudio:detected/);
  assert.match(source, /lmstudio\.detected/);
  assert.match(source, /detected model slot/);
  assert.match(source, /provider\.lmstudio/);
  assert.match(source, /backend\.lmstudio/);
  assert.match(source, /modelUnavailable: !productModelAvailable/);
  assert.match(source, /data-model-unavailable="\$\{snapshot\.modelUnavailable \? "true" : "false"\}"/);
  assert.match(source, /if \(!isAutoStudioModelSelector\(explicitModelId\)\) \{\s*return explicitModelId;\s*\}/);
  assert.match(source, /const requestedModel = studioModelIdForRouteInvocation\(selectedRoute, selectedModelId\)/);
  assert.match(source, /const STUDIO_MODEL_COMPLETION_TIMEOUT_MS = Number\.isFinite/);
  assert.match(source, /const STUDIO_DEFAULT_MAX_OUTPUT_TOKENS = 4096/);
  assert.match(source, /function studioMaxOutputTokens/);
  assert.match(source, /function studioAskMaxOutputTokens/);
  assert.match(source, /max_tokens: studioAskMaxOutputTokens\(selectedReasoningEffort, prompt\)/);
  assert.match(source, /function studioAskReasoningNeedsAnswerHandoff/);
  assert.match(source, /stoppedForReasoningHandoff/);
  assert.match(source, /function studioCleanProductErrorMessage/);
  assert.match(source, /Details are in Tracing/);
  assert.match(source, /const activeRouteFallback = firstArray\(activeRoute\.fallback \|\| activeRoute\.fallbackEndpoints \|\| activeRoute\.fallback_endpoints\)/);
  assert.match(source, /const activeRouteModelId = stringValue\(activeRoute\.modelId \|\| activeRoute\.model_id \|\| activeRoute\.lastSelectedModel \|\| activeRoute\.last_selected_model\)/);
  assert.match(source, /const activeEndpointId = activeRoute\.endpointId \|\| activeRoute\.endpoint_id \|\| activeRouteFallback\[0\]/);
  assert.match(source, /function studioSameNonEmptyId/);
  assert.match(source, /studioSameNonEmptyId\(candidate\.modelId, activeRouteModelId\)/);
  assert.match(source, /studioSameNonEmptyId\(candidate\.id, activeEndpointId\)/);
  assert.match(source, /modelRecordSupportsChat\(activeArtifact\) && isProductStudioModelSelection/);
  assert.match(source, /return isProductStudioModelSelection\(selection\) \? selection : null/);
  assert.doesNotMatch(source, /candidate\.routeId === activeRoute\.routeId/);
  assert.match(source, /firstArray\(candidate\.fallback \|\| candidate\.fallbackEndpoints \|\| candidate\.fallback_endpoints\)\.includes\(endpoint\.id\)/);
  assert.match(source, /const providerSignal = String\(`\$\{artifact\.providerId \|\| ""\} \$\{endpoint\.providerId \|\| ""\} \$\{artifact\.source \|\| ""\} \$\{endpoint\.driver \|\| ""\}`\)/);
  assert.match(source, /llama-cpp\|llama_cpp\|provider\\\.llama/);
  assert.doesNotMatch(source, /lmstudio\|lm_studio\/i\.test\(providerSignal\)[\s\S]*\? 100/);
  assert.match(source, /max_steps: 8/);
  assert.match(source, /function resolveStudioPromptIntentFrame/);
  assert.match(source, /\/v1\/studio\/intent-frame/);
  assert.match(source, /function studioIntentFrameProjectsArtifact/);
  assert.match(source, /function studioIntentFrameProjectsRuntimeCockpit/);
  assert.match(source, /function studioIntentFrameRequiresRetrieval/);
  assert.match(source, /function shouldProjectStudioRuntimeCockpit/);
  assert.match(source, /function projectStudioRuntimeCockpit/);
  assert.match(source, /function shouldProjectConversationArtifactCanvas/);
  assert.match(source, /function studioPromptRequestsGeneratedWebArtifact/);
  assert.match(source, /website\|web\\s\*site\|webpage\|web\\s\*page\|landing\\s\+page/);
  assert.match(source, /function projectStudioConversationArtifactCanvas/);
  assert.match(source, /studioIntentFrameProjectsArtifact\(intentFrame\)[\s\S]*projectStudioConversationArtifactCanvas\(prompt, output, intentFrame\)/);
  assert.match(source, /studioIntentFrameProjectsRuntimeCockpit\(intentFrame\)[\s\S]*await projectStudioRuntimeCockpit\(prompt, agentTurn, output\);/);
  assert.match(source, /function normalizeStudioAssistantReplyText/);
  assert.match(source, /function studioAssistantTextFromRuntimeToolEvents/);
  assert.match(source, /studioAssistantTextFromRuntimeToolEvents\(events\)/);
  assert.match(source, /String\(studioRuntimeEventToolName\(event\)\)\.toLowerCase\(\) !== "chat__reply"/);
  assert.match(source, /event\.data\?\.tool_name/);
  assert.match(source, /event\.data\?\.runtimeEventKind/);
  assert.match(source, /event\.payload_summary\?\.output/);
  assert.match(source, /function studioRuntimeEventsIncludeCompletedTool/);
  assert.match(source, /function studioAssistantReplyTextIsDeferred/);
  assert.match(source, /payload && payload\.event && typeof payload\.event === "object"/);
  assert.match(source, /studioAssistantReplyTextIsDeferred\(text\)/);
  assert.match(source, /function studioRetrievalFailClosedText/);
  assert.match(source, /did not emit a final chat__reply/);
  assert.match(source, /I will not choose or summarize from stale model memory/);
  assert.match(source, /function studioResultTextLooksRetrievalGrounded/);
  assert.match(source, /resultLooksRetrievalGrounded/);
  assert.match(source, /needsRetrieval && !\(hasCompletedSearch && hasCompletedRead\) && !resultLooksRetrievalGrounded/);
  assert.match(source, /function studioTextIndicatesApprovalPause/);
  assert.match(source, /function studioApprovalPauseError/);
  assert.match(source, /studioApprovalPause/);
  assert.match(source, /Daemon turn waiting for approval/);
  assert.match(source, /Agent turn waiting for approval/);
  assert.match(source, /const STUDIO_AGENT_TURN_POST_TIMEOUT_MS = 130000/);
  assert.match(source, /timeoutMs: STUDIO_AGENT_TURN_POST_TIMEOUT_MS/);
  assert.match(source, /function recoverStudioAgentTurnAfterSubmitTimeout/);
  assert.match(source, /fetchStudioThreadTurnEvents\(turn\.thread_id \|\| turn\.threadId \|\| threadId, output, \{\s*turnId: turn\.turn_id \|\| turn\.turnId,/);
  assert.match(source, /agentTurnStatus = agentTurn\.status === "blocked" \? "blocked" : "completed"/);
  assert.match(source, /label: "Blocked daemon thread released"/);
  assert.match(source, /resetStudioDaemonThreadProjection\(\);\s*studioRuntimeProjection\.timeline\.push\(\{\s*label: "Blocked daemon thread released"/);
  assert.match(source, /const explicitText = String\(payload\?\.text \|\| ""\)\.trim\(\)/);
  assert.match(source, /data-testid="studio-reasoning-effort-picker"/);
  assert.match(source, /reasoningEffort,\s*reasoning_effort: reasoningEffort/);
  assert.doesNotMatch(source, /data-testid="studio-model-toggle"[\s\S]{0,500}renderNativeChatIcon\("symbol-operator"\)/);
  assert.match(source, /data-testid="studio-tools-toggle"[\s\S]*renderNativeChatIcon\("tools"\)/);
  assert.match(source, /data-testid="studio-send-button"[\s\S]*renderNativeChatIcon\("send"\)/);
  assert.match(source, /data-testid="studio-stop-icon"[\s\S]*renderNativeChatIcon\("stop"\)/);
  assert.match(source, /data-tauri-icon="paperclip"/);
  assert.match(source, /data-tauri-icon="cube"/);
  assert.match(source, /data-tauri-icon="stop"/);
  assert.match(source, /data-tauri-codicon="device-desktop"/);
  assert.match(source, /data-tauri-codicon="symbol-operator"/);
  assert.match(source, /data-tauri-codicon="chevron-down"/);
  assert.match(source, /data-tauri-codicon="send"/);
  assert.match(source, /data-tauri-codicon="tools"/);
  assert.match(source, /class="studio-icon-toggle__chevron"/);
  assert.match(source, /class="studio-context-btn__icon"/);
  assert.match(source, /\.studio-composer-context-row/);
  assert.match(source, /\.studio-composer-context-row \.studio-context-btn \{[\s\S]*background: transparent/);
  assert.match(source, /\.studio-composer-context-row \.studio-context-btn:hover \{[\s\S]*background: transparent/);
  assert.match(source, /\.studio-composer-toolbar \.studio-icon-toggle,[\s\S]*border-color: transparent/);
  assert.match(source, /\.studio-composer-toolbar \.studio-icon-toggle:hover,[\s\S]*background: rgba\(255, 255, 255, 0\.08\)/);
  assert.match(source, /\.studio-composer \{\s*border-top: 0;\s*background: #191919;/);
  assert.match(source, /\.studio-composer \{\s*border-top: 0;\s*background: #050505;/);
  assert.doesNotMatch(source, /\.studio-composer \{\s*border-top: 1px/);
  assert.match(source, /let studioPanelLastHtml = null;/);
  assert.match(source, /let studioPanelNonce = null;/);
  assert.match(source, /function updateStudioPanelHtml\(state\)/);
  assert.match(source, /if \(html === studioPanelLastHtml\) \{\s*return;\s*\}/);
  assert.match(source, /const pageNonce = getPageNonce \? getPageNonce\(\) : \(studioPanelNonce \|\| \(studioPanelNonce = nonce\(\)\)\);/);
  assert.doesNotMatch(source, /if \(studioPanel\) \{\s*studioPanel\.webview\.html = studioPanelHtml\(state\);/);
  assert.match(source, /width: 28px;/);
  assert.match(source, /height: 22px;/);
  assert.match(source, /width: 28px;/);
});

test("Agent Studio renders browser and computer automation as managed live sessions", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /function studioManagedSessionFromRuntimeEvent/);
  assert.match(source, /function studioManagedSessionRows/);
  assert.match(source, /studioRuntimeProjection\.computerUseSessions/);
  assert.match(source, /data-testid="studio-managed-session-card"/);
  assert.match(source, /data-testid="studio-managed-session-compact-preview"/);
  assert.match(source, /data-testid="studio-managed-session-expanded-view"/);
  assert.match(source, /data-testid="studio-managed-session-mode-labels"/);
  assert.match(source, /Sandbox browser/);
  assert.match(source, /Local browser/);
  assert.match(source, /Desktop/);
  assert.match(source, /data-testid="studio-managed-session-observe"/);
  assert.match(source, /data-testid="studio-managed-session-take-over"/);
  assert.match(source, /data-testid="studio-managed-session-return"/);
  assert.match(source, /data-managed-live-viewport-observed/);
  assert.match(source, /data-managed-session-labels-observed/);
  assert.doesNotMatch(source, /studio-managed-session-card[\s\S]{0,1200}receiptRefs/);
});

test("Agent Studio product model selection is endpoint-first and fails closed when unavailable", async () => {
  const extensionSource = await readFile(extensionSourcePath, "utf8");
  const studioPanelSource = await readFile(studioPanelHtmlPath, "utf8");
  const modelSurfaceSource = await readFile(studioModelSurfacePath, "utf8");
  const shellPatchSource = await readFile(shellPatchPath, "utf8");
  const preferredModelBlock = extensionSource.slice(
    extensionSource.indexOf("function studioPreferredModelSelection"),
    extensionSource.indexOf("function studioSnapshotFromState"),
  );
  const quickInputRowsBlock = extensionSource.slice(
    extensionSource.indexOf("function mountedModelQuickInputRowsFromState"),
    extensionSource.indexOf("function studioIcon"),
  );
  const endpointFirstIndex = preferredModelBlock.indexOf("studioSameNonEmptyId(candidate.id, activeEndpointId)");
  const fallbackIndex = preferredModelBlock.indexOf("activeRouteFallback.includes(candidate.id)");
  const looseModelIndex = preferredModelBlock.indexOf("studioSameNonEmptyId(candidate.modelId, activeRouteModelId)");
  const artifactEndpointIndex = preferredModelBlock.indexOf("studioSameNonEmptyId(candidate.id, activeEndpoint.artifactId)");
  const modelSurfaceResolverBlock = modelSurfaceSource.slice(
    modelSurfaceSource.indexOf("function modelEndpointForArtifact"),
    modelSurfaceSource.indexOf("function modelInstanceForEndpoint"),
  );
  const artifactIdResolverIndex = modelSurfaceResolverBlock.indexOf("endpoint.artifactId === artifact.id");
  const looseModelResolverIndex = modelSurfaceResolverBlock.indexOf("endpoint.modelId === artifact.modelId");

  assert.ok(endpointFirstIndex >= 0, "active route selection should inspect the concrete endpoint id");
  assert.ok(fallbackIndex > endpointFirstIndex, "active route selection should honor fallback endpoints");
  assert.ok(looseModelIndex > endpointFirstIndex, "loose model-id matching must not beat route endpoint matching");
  assert.ok(artifactEndpointIndex > 0, "active artifact selection should bind through endpoint.artifactId");
  assert.ok(artifactIdResolverIndex >= 0, "model surface should prefer endpoint.artifactId");
  assert.ok(
    looseModelResolverIndex > artifactIdResolverIndex,
    "model surface loose model-id matching must not beat artifact endpoint matching",
  );
  assert.match(extensionSource, /haystack\.includes\("no product model"\)/);
  assert.match(extensionSource, /haystack\.includes\("product model mounted"\)/);
  assert.match(extensionSource, /function modelRecordIsEmbeddingOnly/);
  assert.match(extensionSource, /function studioSelectionSupportsChat/);
  assert.match(quickInputRowsBlock, /firstArray\(candidate\.fallback \|\| candidate\.fallbackEndpoints \|\| candidate\.fallback_endpoints\)\.includes\(endpoint\.id\)/);
  assert.match(quickInputRowsBlock, /!isProductStudioModelSelection\(selection\)/);
  assert.match(studioPanelSource, /routePicker\?\.dataset\?\.modelUnavailable === "true"/);
  assert.match(studioPanelSource, /"__product_model_unavailable__"/);
  assert.match(studioPanelSource, /result\.kind === "modelRoute" && result\.requestType === "models\.open"/);
  assert.match(shellPatchSource, /label: "Set up recommended models"/);
  assert.match(shellPatchSource, /requestType: "models\.open"/);
  assert.doesNotMatch(shellPatchSource, /label: "No mounted models"/);
  assert.match(shellPatchSource, /kind === "modelroute" \? "modelRoute"/);
  assert.match(modelSurfaceSource, /data-testid="model-recommended-setup"/);
  assert.match(modelSurfaceSource, /Qwen 3\.5/);
  assert.match(modelSurfaceSource, /Text embedding/);
});

test("Agent Studio tools icon opens the VS Code substrate Configure Tools picker", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /function studioToolPaletteSections/);
  assert.match(source, /function studioToolQuickPickItems/);
  assert.match(source, /data-testid="studio-tools-toggle"[^>]*data-command="ioi\.quickInput\.tools\.configure"/);
  assert.match(source, /vscode\.commands\.registerCommand\("ioi\.quickInput\.tools\.configure"/);
  assert.match(source, /recordForkQuickInputCommand\("ioi\.quickInput\.tools\.configure"/);
  assert.match(source, /extensionQuickInputFallbackEnabled\(\)/);
  assert.match(source, /window\.parent\?\.postMessage\(message, "\*"\)/);
  assert.match(source, /window\.top\.postMessage\(message, "\*"\)/);
  assert.match(source, /source: "ioi-workbench-agent-studio"/);
  assert.match(source, /type: "ioi\.quickInput\.open"/);
  assert.match(source, /message\.source !== "ioi-autopilot-fork-quickinput"/);
  assert.match(source, /nativeForkContributionUsed: true/);
  assert.match(source, /extensionQuickPickFallbackUsed: false/);
  assert.match(source, /buttonQuickInputPayload\(button\)/);
  assert.match(source, /anchorRect: \{/);
  assert.match(source, /vscode\.commands\.registerCommand\("ioi\.studio\.openToolPicker"/);
  assert.match(source, /vscode\.window\.createQuickPick\(\)/);
  assert.match(source, /picker\.title = "Configure Tools"/);
  assert.match(source, /picker\.placeholder = "Select tools that are available to chat\."/);
  assert.match(source, /picker\.canSelectMany = true/);
  assert.match(source, /picker\.selectedItems = items\.filter/);
  assert.match(source, /picker\.ignoreFocusOut = true/);
  assert.match(source, /picker\.buttons = \[toolButtons\.context, toolButtons\.manage, toolButtons\.settings\]/);
  assert.match(source, /new vscode\.ThemeIcon\("paperclip"\)/);
  assert.match(source, /new vscode\.ThemeIcon\("extensions"\)/);
  assert.match(source, /new vscode\.ThemeIcon\("settings-gear"\)/);
  assert.match(source, /vscode\.commands\.executeCommand\("ioi\.studio\.openContextPicker"\)/);
  assert.match(source, /writeBridgeRequest\("chat\.toolControls"/);
  assert.match(source, /action: "configureTools"/);
  assert.match(source, /selectedTools:/);
  assert.match(source, /selectedCount:/);
  assert.doesNotMatch(source, /function renderStudioToolPalette/);
  assert.doesNotMatch(source, /data-studio-tool-palette/);
  assert.doesNotMatch(source, /data-studio-tools-toggle/);
  assert.doesNotMatch(
    source,
    /data-testid="studio-tools-toggle"[^>]*data-bridge-request="commandCenter\.open"/,
  );
  assert.match(source, /title: "agent"/);
  assert.match(source, /title: "awaitTerminal"/);
  assert.match(source, /title: "createAndRunTask"/);
  assert.match(source, /title: "execute"/);
  assert.match(source, /title: "extensions"/);
  assert.match(source, /title: "getTerminalOutput"/);
  assert.match(source, /title: "killTerminal"/);
  assert.match(source, /title: "runInTerminal"/);
  assert.match(source, /title: "runSubagent"/);
  assert.match(source, /title: "terminalLastCommand"/);
  assert.match(source, /title: "terminalSelection"/);
  assert.match(source, /title: "todo"/);
  assert.match(source, /title: "vscode"/);
  assert.match(source, /title: "renderMermaidDiagram"/);
  assert.match(source, /Mermaid Chat Features/);
  assert.doesNotMatch(source, /title: "Go back"/);
  assert.match(source, /Live Tools/);
  assert.match(source, /Runtime Catalog/);
  assert.match(source, /studioNativeQuickInputToolPicker: true/);
});

test("Agent Studio renders Mermaid chat outputs as interactive renderer cards", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /function studioMermaidSourcesFromText/);
  assert.match(source, /function studioMermaidSummary/);
  assert.match(source, /function studioChatOutputRendererRows/);
  assert.match(source, /outputRenderers: \[\]/);
  assert.match(source, /turn\.outputRenderers \|\| turn\.output_renderers/);
  assert.match(source, /fencePattern = \/```\(\?:mermaid\|text\\\/vnd\\\.mermaid\)/);
  assert.match(source, /data-testid="studio-chat-mermaid-renderer"/);
  assert.match(source, /data-renderer-id="\$\{escapeHtml\(card\.rendererId\)\}"/);
  assert.match(source, /data-mime-type="\$\{escapeHtml\(card\.mimeType\)\}"/);
  assert.match(source, /data-testid="studio-chat-output-renderer-controls"/);
  assert.match(source, /data-testid="studio-chat-renderer-zoom-in"/);
  assert.match(source, /data-testid="studio-chat-renderer-zoom-out"/);
  assert.match(source, /data-testid="studio-chat-renderer-fit"/);
  assert.match(source, /data-testid="studio-mermaid-diagram-surface"/);
  assert.match(source, /data-testid="studio-mermaid-clickable-node"/);
  assert.match(source, /data-testid="studio-chat-output-renderer-source"/);
  assert.match(source, /studioChatOutputRendererRows\(turn, index\)/);
  assert.match(source, /turnCount: turns\.length/);
  assert.match(source, /studio-chat-output-renderer--mermaid/);
});

test("Agent Studio mounts imported trajectory audit panels in Trace", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /parentTrajectoryLinkagePanels: \[\]/);
  assert.match(source, /battleModePermissionImportPanels: \[\]/);
  assert.match(source, /importedStopHookGatePanels: \[\]/);
  assert.match(source, /importedBrowserActionEvidencePanels: \[\]/);
  assert.match(source, /importedExecutorConfigPanels: \[\]/);
  assert.match(source, /importedPolicyDraftPanels: \[\]/);
  assert.match(source, /importedGenerationMetadataPanels: \[\]/);
  assert.match(source, /importedErrorRenderInfoPanels: \[\]/);
  assert.match(source, /studio-imported-parent-trajectory-linkage/);
  assert.match(source, /studio-imported-battle-mode-permission/);
  assert.match(source, /studio-imported-stop-hook-gates/);
  assert.match(source, /studio-imported-browser-action-evidence/);
  assert.match(source, /studio-imported-executor-config/);
  assert.match(source, /studio-imported-policy-draft/);
  assert.match(source, /studio-imported-generation-metadata/);
  assert.match(source, /studio-imported-error-render-info/);
  assert.match(source, /imported\.parent_trajectory_linkage/);
  assert.match(source, /imported\.battle_mode_permission/);
  assert.match(source, /imported\.stop_hook_gates/);
  assert.match(source, /imported\.browser_action_evidence/);
  assert.match(source, /imported\.executor_config/);
  assert.match(source, /imported\.policy_draft/);
  assert.match(source, /imported\.generation_metadata/);
  assert.match(source, /imported\.error_render_info/);
});

test("Migration Assistant commands are visible and plan-only", async () => {
  const source = await readExtensionCompositeSource();
  const manifest = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const commandIds = new Set(manifest.contributes.commands.map((entry) => entry.command));
  const commandPaletteIds = new Set(
    manifest.contributes.menus.commandPalette.map((entry) => entry.command),
  );

  for (const commandId of [
    "ioi.migration.openAssistant",
    "ioi.migration.importVSCodeSettings",
    "ioi.migration.importCursorSettings",
    "ioi.migration.importWindsurfSettings",
    "ioi.migration.importVSCodeExtensions",
    "ioi.migration.importCursorExtensions",
    "ioi.migration.importWindsurfExtensions",
  ]) {
    assert.ok(commandIds.has(commandId), `${commandId} contributed`);
    assert.ok(commandPaletteIds.has(commandId), `${commandId} visible in command palette`);
    assert.match(source, new RegExp(`registerCommand\\("${commandId.replace(/\./g, "\\.")}"`));
  }

  assert.match(source, /const planMigrationImport = async/);
  assert.match(source, /writeBridgeRequest\("migration\.assistant\.open"/);
  assert.match(source, /writeBridgeRequest\("migration\.import\.plan"/);
  assert.match(source, /applyMode: "plan_only"/);
  assert.match(source, /policyReviewRequired: true/);
  assert.match(source, /sandboxBoundaryPreserved: true/);
  assert.match(source, /autoApply: false/);
  assert.match(source, /supportedSources: \["vscode", "cursor", "windsurf"\]/);
});

test("Agent Studio renders executable code blocks as sandbox plan cards", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /function studioExecutableCodeBlocksFromText/);
  assert.match(source, /function studioCodeExecutionPolicy/);
  assert.match(source, /function studioChatCodeExecutionRows/);
  assert.match(source, /data-testid="studio-chat-code-execution-card"/);
  assert.match(source, /data-network-policy="deny"/);
  assert.match(source, /data-apply-mode="plan_only"/);
  assert.match(source, /data-testid="studio-chat-code-execution-source"/);
  assert.match(source, /data-testid="studio-chat-code-execute-plan"/);
  assert.match(source, /data-bridge-request="chat\.executeCodeBlock\.plan"/);
  assert.match(source, /receiptRequired: true/);
  assert.match(source, /policy:code_execution\.sandbox\.network_deny/);
  assert.match(source, /policy:code_execution\.block\.network/);
  assert.match(source, /studioChatCodeExecutionRows\(turn, index\)/);
});

test("Agent Studio Add Context opens the native VS Code context picker", async () => {
  const source = await readExtensionCompositeSource();
  const shellPatchSource = await readFile(shellPatchPath, "utf8");

  assert.match(source, /function studioContextQuickPickItems/);
  assert.match(source, /data-testid="studio-add-context"[^>]*data-command="ioi\.quickInput\.context\.open"/);
  assert.match(source, /vscode\.commands\.registerCommand\("ioi\.quickInput\.context\.open"/);
  assert.match(source, /recordForkQuickInputCommand\("ioi\.quickInput\.context\.open"/);
  assert.match(source, /isForkQuickInputCommand\(button\.dataset\.command\)/);
  assert.match(source, /focusStudioComposer\(\)/);
  assert.match(source, /vscode\.commands\.registerCommand\("ioi\.studio\.openContextPicker"/);
  assert.match(source, /picker\.placeholder = "Search for files and context to add to your request"/);
  assert.match(source, /title: "Files & Folders\.\.\."/);
  assert.match(source, /title: "Instructions\.\.\."/);
  assert.match(source, /title: "Problems\.\.\."/);
  assert.match(source, /title: "Symbols\.\.\."/);
  assert.match(source, /title: "Tools\.\.\."/);
  assert.match(source, /new vscode\.ThemeIcon\(row\.icon\)/);
  assert.match(source, /requestType: "chat\.attachFilesAndFolders"/);
  assert.match(source, /requestType: "chat\.generateAgentInstructions"/);
  assert.match(source, /requestType: "chat\.attachProblems"/);
  assert.match(source, /requestType: "chat\.attachSymbols"/);
  assert.match(source, /command: "ioi\.quickInput\.tools\.configure"/);
  assert.match(source, /runtimeAuthority: "daemon-owned"/);
  assert.match(source, /type: "ioi\.quickInput\.dismiss"/);
  assert.match(shellPatchSource, /function focusForkQuickInputControl/);
  assert.match(shellPatchSource, /message\.type === "ioi\.quickInput\.dismiss"/);
  assert.match(shellPatchSource, /closeForkQuickInput\(\);/);
  assert.doesNotMatch(source, /data-testid="studio-add-context-menu"/);
  assert.doesNotMatch(source, /data-studio-context-toggle/);
  assert.doesNotMatch(source, /studio-context-menu/);
});

test("native IOI chat view routes user actions through bridge requests", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /message\?\.type === "bridgeRequest"/);
  assert.match(source, /writeBridgeRequest\(\s*message\.requestType/);
  assert.match(source, /buildWorkspaceActionContext\("ioi\.chat"\)/);
  assert.match(source, /vscode\.commands\.registerCommand\("ioi\.commandCenter\.open"/);
  assert.match(source, /writeBridgeRequest\("commandCenter\.open"/);
  assert.match(source, /initialQuery/);
  assert.match(source, /typeof options\.mode === "string"[\s\S]*\.\.\.\(mode \? \{ mode \} : \{\}\)/);
  assert.doesNotMatch(source, /createRuntime|new Runtime|reactShadowStore/i);
});

test("legacy IOI chat sidebar is not contributed to the primary Autopilot shell", async () => {
  const manifest = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const commands = new Set(
    (manifest.contributes?.commands || []).map((command) => command.command),
  );
  const secondaryContainers = manifest.contributes?.viewsContainers?.secondarySidebar || [];
  const activityContainers = manifest.contributes?.viewsContainers?.activitybar || [];

  assert.ok(!secondaryContainers.some((container) => container.id === "ioi-chat"));
  assert.equal(manifest.contributes?.views?.["ioi-chat"], undefined);
  assert.ok(!activityContainers.some((container) => container.id === "ioi"));
  assert.ok(
    activityContainers.some(
      (container) =>
        container.id === "ioi-overview" && container.icon === "$(home)",
    ),
  );
  assert.ok(
    activityContainers.some(
      (container) =>
        container.id === "ioi-studio" && container.icon === "$(sparkle)",
    ),
  );
  assert.ok(activityContainers.some((container) => container.id === "ioi-workflows"));
  assert.ok(activityContainers.some((container) => container.id === "ioi-models"));
  assert.ok(activityContainers.some((container) => container.id === "ioi-runs"));
  assert.ok(activityContainers.some((container) => container.id === "ioi-policy"));
  assert.ok(activityContainers.some((container) => container.id === "ioi-connectors"));
  assert.ok(activityContainers.some((container) => container.id === "ioi-code"));
  assert.ok(commands.has("ioi.commandCenter.open"));
  assert.ok(commands.has("ioi.code.open"));
  assert.ok(commands.has("ioi.autopilot.back"));
  assert.ok(commands.has("ioi.studio.open"));
  assert.ok(commands.has("ioi.studio.openContextPicker"));
  assert.ok(commands.has("ioi.studio.openToolPicker"));
  assert.ok(commands.has("ioi.studio.agentBuilder"));
  assert.ok(commands.has("ioi.chat.new"));
  assert.ok(commands.has("ioi.chat.newOptions"));
  assert.ok(commands.has("ioi.chat.openSettings"));
  assert.ok(commands.has("ioi.chat.focusComposer"));
  assert.ok(commands.has("ioi.chat.moreActions"));

  assert.ok(commands.has("ioi.chat.submit"));
  assert.ok(commands.has("ioi.chat.reviewFile"));
});

test("Agent Studio contributes an operational daemon-backed chat surface", async () => {
  const source = await readExtensionCompositeSource();
  const workSummarySource = await readFile(
    new URL("./studio-work-summary.js", import.meta.url),
    "utf8",
  );
  const manifest = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const studioViews = manifest.contributes?.views?.["ioi-studio"] || [];

  assert.ok(studioViews.some((view) => view.id === "ioi.studio"));
  assert.match(source, /function studioPanelHtml/);
  assert.match(source, /data-testid="agent-studio-operational-chat"/);
  assert.match(source, /data-testid="studio-transcript"/);
  assert.match(source, /data-testid="studio-composer"/);
  assert.match(source, /data-testid="studio-tool-timeline"/);
  assert.match(source, /data-testid="studio-approval-gate"/);
  assert.match(source, /data-testid="studio-receipts-replay"/);
  assert.match(source, /data-testid="studio-inline-diff-hunks"/);
  assert.match(source, /data-testid="studio-model-route-picker"/);
  assert.match(source, /data-testid="studio-reasoning-effort-picker"/);
  assert.match(source, /data-testid="studio-tauri-session-rail"/);
  assert.match(source, /Conversation history/);
  assert.match(source, /data-testid="studio-session-search"/);
  assert.match(source, /data-testid="studio-new-session"/);
  assert.doesNotMatch(source, /data-testid="studio-artifacts-row"/);
  assert.doesNotMatch(source, /data-testid="studio-workflow-handoff"/);
  assert.match(source, /data-testid="studio-current-session-row"/);
  assert.match(source, /data-testid="studio-chat-transcript"/);
  assert.match(source, /data-testid="studio-user-bubble"/);
  assert.match(source, /data-testid="studio-assistant-answer-card"/);
  assert.match(source, /data-testid="studio-run-status-bar"/);
  assert.match(source, /data-testid="studio-conversation-artifact-preview-frame"/);
  assert.match(source, /function studioArtifactPreviewSrcdoc/);
  assert.match(source, /studioArtifactPreviewSrcdoc\(text, studioPanelPageNonce \|\| ""\)/);
  assert.match(source, /getPageNonce: currentStudioPanelPageNonce/);
  assert.match(source, /function currentStudioPanelPageNonce/);
  assert.match(source, /sandbox="allow-scripts"/);
  assert.doesNotMatch(source, /studio-conversation-artifact-expanded[\s\S]{0,900}Open Tracing/);
  assert.match(source, /function studioArtifactOutputModality/);
  assert.match(source, /function studioArtifactIsWebsite/);
  assert.match(source, /return studioArtifactIsWebsite\(artifact\) \? "Website preview" : "HTML preview"/);
  assert.match(source, /outputModality: intentFrame\?\.artifact\?\.outputModality/);
  assert.match(source, /function studioWebsiteDraftRejectReason/);
  assert.match(source, /website HTML was truncated before the closing <\/html> tag/);
  assert.match(source, /roughly 70-110 lines, concise copy, at most five visible sections/);
  assert.match(source, /End the response immediately after the closing <\/html> tag/);
  assert.match(source, /represent the ambiguity in the page instead of silently substituting an adjacent topic/);
  assert.match(source, /model returned tool-call envelope/);
  assert.match(source, /model output came from a deterministic fixture route/);
  assert.match(source, /studioTextContainsProductFixtureMarker/);
  assert.match(source, /studioDenyFixtureModelPolicy/);
  assert.match(source, /data-testid="studio-response-metrics"/);
  assert.match(source, /function studioThinkingRows/);
  assert.match(source, /function ensureStreamingThinkingBlock/);
  assert.match(source, /message\.type === "assistantThinkingDelta"/);
  assert.match(source, /studioPostRuntimeMessage\("assistantThinkingDelta"/);
  assert.match(source, /function studioUsageFromProviderTimings/);
  assert.match(source, /payload\.timings[\s\S]*studioUsageFromProviderTimings/);
  assert.match(source, /Autopilot Ask mode presentation boundary/);
  assert.match(source, /function studioAskNeedsFreshRetrievalGuard/);
  assert.match(source, /fresh_retrieval_required/);
  assert.match(source, /Ask cannot safely choose or summarize from stale model memory/);
  assert.match(source, /fresh retrieval is required/);
  assert.match(source, /briefly acknowledge the likely meanings and make a clear, useful interpretation/);
  assert.match(source, /keep the thinking stream brief, then move into the final answer promptly/);
  assert.match(source, /Do not mention internal workspace paths, daemon routes, receipts, trace ids, runtime scaffolding, or selected-model plumbing/);
  assert.doesNotMatch(source, /ask_mode_boundary: provide direct answers/);
  assert.match(source, /I did not create a canned fallback page/);
  assert.match(source, /const studioWorkSummary = require\("\.\/studio-work-summary"\)/);
  assert.match(source, /function studioDocumentedWorkRecord\(cursor = \{\}\)/);
  assert.match(source, /studioWorkSummary\.studioDocumentedWorkRecord\(studioRuntimeProjection, cursor\)/);
  assert.match(workSummarySource, /if \(!lines\.length\) \{\s*return null;\s*\}/);
  assert.match(workSummarySource, /return Boolean\(record && firstArray\(record\.lines\)\.length\)/);
  assert.match(source, /data-testid="studio-tauri-composer"/);
  assert.match(source, /data-testid="studio-composer-context-row"/);
  assert.match(source, /data-testid="studio-composer-toggle-row"/);
  assert.match(source, /data-testid="studio-add-context"/);
  assert.match(source, /data-testid="studio-target-toggle"/);
  assert.match(source, /data-testid="studio-model-toggle"/);
  assert.match(source, /data-testid="studio-mode-toggle"/);
  assert.match(source, /data-testid="studio-permissions-toggle"/);
  assert.match(source, /Default permissions/);
  assert.match(source, /Auto-review/);
  assert.match(source, /Full access/);
  assert.match(source, /data-testid="studio-target-toggle"[^>]*data-command="ioi\.quickInput\.workflowTarget\.pick"/);
  assert.match(source, /data-testid="studio-mode-toggle"[^>]*data-command="ioi\.quickInput\.agentMode\.pick"/);
  assert.match(source, /data-testid="studio-permissions-toggle"[^>]*data-command="ioi\.quickInput\.permissionMode\.pick"/);
  assert.match(source, /vscode\.commands\.registerCommand\("ioi\.quickInput\.agentMode\.pick"/);
  assert.match(source, /vscode\.commands\.registerCommand\("ioi\.quickInput\.permissionMode\.pick"/);
  assert.match(source, /requestType: result\.requestType \|\| \(result\.kind === "agentMode" \? "chat\.agentMode\.select" : result\.kind === "permissionMode" \? "chat\.permissionMode\.select" : "chat\.target\.select"\)/);
  assert.match(source, /approvalMode,\s*approval_mode: approvalMode/);
  assert.match(source, /threadMode,\s*thread_mode: threadMode/);
  assert.doesNotMatch(source, /Daemon policy event projected/);
  assert.match(source, /data-testid="studio-tools-toggle"/);
  assert.match(source, /data-testid="studio-send-icon"/);
  assert.match(source, /data-testid="studio-stop-icon"/);
  assert.match(source, /data-testid="studio-utility-drawer"/);
  assert.match(source, /data-testid="studio-utility-toggle"/);
  assert.match(source, /data-testid="studio-approval-inline-card"/);
  assert.doesNotMatch(source, /data-testid="studio-receipt-chip"/);
  assert.doesNotMatch(source, /data-testid="studio-workflow-handoff"[\s\S]{0,200}data-command="ioi\.workflow\.openComposer"/);
  assert.match(source, /data-command="ioi\.models\.open"/);
  assert.match(source, /type: "studioSubmit"/);
  assert.match(source, /requestType: "chat\.submit"/);
  assert.match(source, /"chat\.stop"/);
  assert.match(source, /"chat\.hunkDecision"/);
  assert.match(source, /runtimeAuthority: "daemon-owned"/);
  assert.match(source, /projectionOwner: "ioi-workbench-agent-studio"/);
  assert.match(source, /normalizeStudioReasoningEffort\(payload\.reasoningEffort \?\? payload\.reasoning_effort, "none"\)/);
  assert.match(source, /reasoning_effort: selectedReasoningEffort/);
  assert.match(source, /targetStudioOperationalChatAchieved: true/);
  assert.match(source, /targetStudioTauriChatUxParityAchieved: true/);
  assert.doesNotMatch(source, /studio\.promptSubmit/);
  assert.match(source, /viewId: "ioi\.studio"[\s\S]*command: "ioi\.studio\.open"/);
  assert.match(source, /viewId: "ioi\.workflows"[\s\S]*command: "ioi\.workflow\.openComposer"/);
  assert.match(source, /viewId: "ioi\.models"[\s\S]*command: "ioi\.models\.open"/);
  assert.match(source, /function closePrimarySidebarAfterActivityLaunch/);
  assert.match(source, /ioi-studio\.svg/);
});

test("Agent Studio keeps heavyweight panel and model completion code outside the extension facade", async () => {
  const extensionSource = await readFile(extensionSourcePath, "utf8");
  const panelSource = await readFile(studioPanelHtmlPath, "utf8");
  const modelCompletionSource = await readFile(studioModelCompletionPath, "utf8");
  const operationalSurfaceSource = await readFile(studioOperationalSurfacePath, "utf8");
  const modelSurfaceSource = await readFile(studioModelSurfacePath, "utf8");

  assert.match(extensionSource, /createStudioPanelHtml/);
  assert.match(extensionSource, /createStudioModelCompletion/);
  assert.match(extensionSource, /createStudioOperationalSurface/);
  assert.match(extensionSource, /createModelSurfaceRenderer/);
  assert.ok(
    (extensionSource.match(/getStudioRuntimeProjection: \(\) => studioRuntimeProjection/g) || []).length >= 2,
    "extracted Studio helpers must read the live projection through a getter",
  );
  assert.doesNotMatch(extensionSource, /<title>Agent Studio<\/title>/);
  assert.doesNotMatch(extensionSource, /class="studio-operational-shell studio-tauri-chat-shell/);
  assert.doesNotMatch(extensionSource, /Autopilot Ask mode presentation boundary:[\s\S]*Return one complete HTML document only/);
  assert.match(panelSource, /function createStudioPanelHtml/);
  assert.match(panelSource, /return function studioPanelHtml/);
  assert.match(modelCompletionSource, /function createStudioModelCompletion/);
  assert.match(modelCompletionSource, /getStudioRuntimeProjection/);
  assert.doesNotMatch(modelCompletionSource, /^\s*studioRuntimeProjection,\s*$/m);
  assert.match(modelCompletionSource, /streamStudioModelCompletion/);
  assert.match(operationalSurfaceSource, /function createStudioOperationalSurface/);
  assert.match(operationalSurfaceSource, /getStudioRuntimeProjection/);
  assert.doesNotMatch(operationalSurfaceSource, /^\s*studioRuntimeProjection,\s*$/m);
  assert.match(operationalSurfaceSource, /function renderStudioOperationalSurface/);
  assert.match(modelSurfaceSource, /function createModelSurfaceRenderer/);
  assert.match(modelSurfaceSource, /function renderModelsPanelBody/);
  assert.doesNotMatch(extensionSource, /function renderModelsPanelBody/);
  assert.doesNotMatch(extensionSource, /function modelReceiptKind/);
  assert.ok(lineCount(extensionSource) < 14_000, "extension.js should stay below the post-extraction facade checkpoint");
});

test("Agent Studio de-noises runtime truth into the Runs/Tracing surface", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /runtimeUx:\s*\{/);
  assert.match(source, /denoised: true/);
  assert.match(source, /tracingSeparationAchieved: true/);
  assert.match(source, /modelProseNotAcceptedAsRuntimeTruth: true/);
  assert.match(source, /verifiedBadgesRequireReceiptRefs: true/);
  assert.match(source, /const STUDIO_RUNTIME_VISIBILITY = Object\.freeze/);
  assert.match(source, /function classifyStudioRuntimeEvent/);
  assert.match(source, /function studioTraceTarget/);
  assert.match(source, /function studioTraceLink/);
  assert.match(source, /function studioVerifiedBadge/);
  assert.match(source, /function studioHumanizeOperationalTranscriptText/);
  assert.match(source, /function studioDisplayTurnContent/);
  assert.match(source, /function humanizeProjectedTurnText/);
  assert.match(source, /function promptIsInternalHarnessProbe/);
  assert.match(source, /promptIsInternalHarnessProbe\(prompt\)/);
  assert.match(source, /STUDIO_TOOLCAT_MARKER_RE\.test\(text\)/);
  assert.match(source, /workspace_fixture_\|daemon_endpoint=\|computer_use_providers_url=/);
  assert.match(source, /studioDisplayTurnContent\(turn\)/);
  assert.match(source, /paragraph\.textContent = humanizeProjectedTurnText\(role, content\)/);
  assert.match(source, /prompt: prompt \|\| assistantTurn\?\.agentTurn\?\.prompt \|\| ""/);
  assert.match(source, /function projectedAssistantAnchor\(transcript, content, options = \{\}\)/);
  assert.match(source, /turn\.dataset\.studioPromptTool = projectedToolcatToolName\(content\)/);
  assert.match(source, /appendProjectedTurn\("assistant", text, \{ prompt: String\(payload\?\.prompt \|\| ""\) \}\)/);
  assert.match(source, /transcript\.insertBefore\(turn, anchor\.after\.nextSibling\)/);
  assert.match(source, /TOOLCAT_MARKER_RE/);
  assert.match(source, /Run live Rust tool catalogue verification for/);
  assert.match(source, /The live Rust tool catalogue probe failed for/);
  assert.match(source, /Permission is required before Agent can/);
  assert.match(source, /Permission needed/);
  assert.doesNotMatch(source, /Daemon policy event projected/);
  assert.match(source, /function studioTurnHasDocumentedWork/);
  assert.match(source, /function studioDocumentedWorkRecord/);
  assert.match(source, /studioRuntimeProjection\.turns\.map\(\(turn, index\) =>/);
  assert.match(source, /data-documented-work="\$\{hasDocumentedWork \? "true" : "false"\}"/);
  assert.match(source, /function studioCompactRuntimeStatusRows/);
  assert.match(source, /data-runtime-ux-denoised="\$\{studioRuntimeProjection\.runtimeUx\?\.denoised/);
  assert.match(source, /data-tracing-separation-achieved="\$\{studioRuntimeProjection\.runtimeUx\?\.tracingSeparationAchieved/);
  assert.match(source, /data-model-prose-runtime-truth="false"/);
  assert.match(source, /data-verified-badges-require-receipts="\$\{studioRuntimeProjection\.runtimeUx\?\.verifiedBadgesRequireReceiptRefs/);
  assert.match(source, /data-testid="studio-actionable-runtime-state"/);
  assert.doesNotMatch(source, /data-testid="studio-compact-runtime-status"/);
  assert.doesNotMatch(source, /data-testid="studio-tool-proposal-compact"/);
  assert.match(source, /data-testid="studio-policy-prompt-actionable"/);
  assert.doesNotMatch(source, /data-testid="studio-command-summary-not-log-wall"/);
  assert.doesNotMatch(source, /data-testid="studio-diagnostics-summary"/);
  assert.match(source, /data-testid="studio-native-hunk-review-inline"/);
  assert.match(source, /function studioParityPlusPanelRows/);
  assert.match(source, /engineReconnectBanners: \[\]/);
  assert.match(source, /chatResponsibilityContracts: \[\]/);
  assert.match(source, /securityScanPanels: \[\]/);
  assert.match(source, /workerContributionTraces: \[\]/);
  assert.match(source, /data-testid="studio-parity-plus-panels"/);
  assert.match(source, /data-testid="\$\{escapeHtml\(spec\.testId\)\}"/);
  assert.match(source, /studio-engine-reconnect-banner/);
  assert.match(source, /studio-chat-responsibility-contract/);
  assert.match(source, /studio-engine-guard-security-scan/);
  assert.match(source, /studio-worker-contribution-trace/);
  assert.match(source, /function applyStudioParityPlusEvent/);
  assert.match(source, /function studioRuntimeEventPayload/);
  assert.match(source, /studioRuntimeProjection\.engineReconnectBanners\.push/);
  assert.match(source, /studioRuntimeProjection\.chatResponsibilityContracts\.push/);
  assert.match(source, /studioRuntimeProjection\.securityScanPanels\.push/);
  assert.match(source, /studioRuntimeProjection\.workerContributionTraces\.push/);
  assert.match(source, /applyStudioParityPlusEvent\(event, \{ kind, status, summary, receiptRefs \}\)/);
  assert.match(source, /ioi\.studio\.injectParityPlusEvents/);
  assert.match(source, /IOI_AUTOPILOT_STUDIO_TEST_HOOKS/);
  assert.match(source, /studio\.parityPlusEvents\.injected/);
  assert.match(source, /for \(const item of firstArray\(studioRuntimeProjection\.engineReconnectBanners\)\)/);
  assert.match(source, /for \(const item of firstArray\(studioRuntimeProjection\.securityScanPanels\)\)/);
  assert.match(source, /data-testid="studio-view-trace-link"/);
  assert.match(source, /function studioDocumentedWorkSummary/);
  assert.doesNotMatch(source, /data-testid="studio-work-record"/);
  assert.match(source, /data-testid="studio-verified-badge"/);
  assert.match(source, /data-testid="studio-trace-handoff"/);
  assert.match(source, /data-command="ioi\.runs\.refresh"/);
  assert.match(source, /traceTarget: activeTraceTarget/);
  assert.match(source, /writeBridgeRequest\("runs\.open"/);
  assert.match(source, /data-testid="tracing-surface"/);
  assert.match(source, /data-focused-trace-step="\$\{escapeHtml\(target\.stepId/);
  assert.match(source, /data-tracing-separation-achieved="true"/);
  assert.match(source, /data-testid="tracing-focused-step"/);
  assert.match(source, /data-testid="tracing-timeline"/);
  assert.match(source, /data-testid="tracing-receipt-detail"/);
  assert.match(source, /data-testid="tracing-replay-step"/);
  assert.match(source, /data-testid="tracing-policy-detail"/);
  assert.match(source, /data-testid="tracing-command-log-detail"/);
  assert.match(source, /data-testid="tracing-proof-export"/);
  assert.match(source, /Model prose is never accepted as runtime proof/);
  assert.match(source, /Verified badges require daemon receipt refs/);
  assert.match(source, /runtimeAuthority: "daemon-owned"/);
  assert.match(source, /function ensurePendingProjection/);
  assert.match(source, /function hidePendingProjectionAfterMinimum/);
  assert.match(source, /Thinking about your request · /);
  assert.match(source, /data-testid="studio-pending-label"/);
  assert.match(source, /data-testid="studio-pending-worklog"/);
  assert.match(source, /pendingWorklog: \[\]/);
  assert.match(source, /function isAbstractStudioPendingWorkStep/);
  assert.match(source, /function studioPendingWorkStepIsConcrete/);
  assert.match(source, /function appendStudioPendingWorkStep/);
  assert.match(source, /if \(!studioPendingWorkStepIsConcrete\(payload\)\) \{\s*return null;\s*\}/);
  assert.match(source, /turn\\\.step\|agent\\\.step/);
  assert.match(source, /const appendedStep = appendStudioPendingWorkStep\(pendingStep\);/);
  assert.match(source, /if \(!concreteTool\) return;/);
  assert.match(source, /toolName === "chat__reply"/);
  assert.match(source, /if \(!normalizedPayload\) \{\s*return;\s*\}/);
  assert.match(source, /const abstractPendingText = \[label, detail\]\.join\(" "\)\.toLowerCase\(\);/);
  assert.match(source, /function studioPendingWorklogLastAtMs/);
  assert.match(source, /1200 - latestWorkStepElapsedMs/);
  assert.match(source, /data-pending-worklog-count/);
  assert.match(source, /data-pending-worklog="\$\{escapeHtml\(JSON\.stringify\(firstArray\(studioRuntimeProjection\.pendingWorklog\)\)\)\}"/);
  assert.doesNotMatch(source, /data-testid="studio-pending-progress"/);
  assert.doesNotMatch(source, /data-studio-pending-step/);
  assert.doesNotMatch(source, />Using tools</);
  assert.doesNotMatch(source, />Preparing response</);
  assert.doesNotMatch(source, /Preparing governed Agent run/);
  assert.doesNotMatch(source, /Starting the daemon session, model route, and policy context/);
  assert.doesNotMatch(source, /I'll run this through the governed Agent harness/);
  assert.doesNotMatch(source, /Tool calls, policy checks, receipts, and traces stay daemon-owned/);
  assert.doesNotMatch(source, /Preparing artifact run/);
  assert.doesNotMatch(source, /Gathering source context/);
  assert.doesNotMatch(source, /Gathered source context/);
  assert.doesNotMatch(source, /I'll draft a custom website with the selected model/);
  assert.doesNotMatch(source, /The preview will be created as a sandboxed artifact/);
  assert.doesNotMatch(source, /Drafted custom website content/);
  assert.doesNotMatch(source, /Drafting website artifact/);
  assert.doesNotMatch(source, /Model draft was rejected/);
  assert.doesNotMatch(source, /Creating sandboxed artifact preview/);
  assert.doesNotMatch(source, /Created artifact preview/);
  assert.doesNotMatch(source, /Used \$\{projectedToolNames\.length\} daemon tool/);
  assert.match(source, /message\.type === "assistantStreamStart"[\s\S]*showPendingProjection\(\);[\s\S]*return;/);
  assert.match(source, /message\.type === "assistantStreamDelta"[\s\S]*hidePendingProjectionAfterMinimum\(\);/);
  assert.match(source, /message\.type === "assistantThinkingDelta"[\s\S]*hidePendingProjectionAfterMinimum\(\);/);
  assert.doesNotMatch(source, /Daemon turn pending/);
  assert.doesNotMatch(source, /Studio prompt stayed in a mock launcher/);
  assert.doesNotMatch(source, /src-tauri|@tauri-apps|tauri:\/\/|tauri\./i);
});

test("Autopilot Overview is the IDE-native operator home surface", async () => {
  const source = await readExtensionCompositeSource();
  const manifest = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const commands = new Set(
    (manifest.contributes?.commands || []).map((command) => command.command),
  );
  const overviewViews = manifest.contributes?.views?.["ioi-overview"] || [];

  assert.ok(overviewViews.some((view) => view.id === "ioi.overviewActivity"));
  assert.ok(commands.has("ioi.overview.open"));
  assert.match(source, /function overviewPanelHtml/);
  assert.match(source, /function renderOverviewActivityView/);
  assert.match(source, /viewId: "ioi\.overviewActivity"[\s\S]*command: "ioi\.overview\.open"/);
  assert.match(source, /data-testid="autopilot-overview-home"/);
  assert.match(source, /Operator console for autonomous systems/);
  assert.match(source, /Build, run, govern, and verify/);
  assert.match(source, /data-runtime-authority="daemon-owned"/);
  assert.match(source, /function productStudioModelSelectionsFromSnapshot/);
  assert.match(source, /function loadedProductStudioModelInstances/);
  assert.match(source, /const productModelCount = productModelSelections\.length/);
  assert.match(source, /`\$\{loadedModels\.length\}\/\$\{productModelCount\} loaded`/);
  assert.match(source, /`\$\{productModelCount\} product model\$\{productModelCount === 1 \? "" : "s"\}`/);
  assert.doesNotMatch(source, /overviewPill\("Models", `\$\{loadedModels\.length\}\/\$\{snapshot\.artifacts\.length\} loaded`/);
  assert.match(source, /registerCommand\("ioi\.overview\.open"/);
  assert.match(source, /writeBridgeRequest\("overview\.open"/);
  assert.match(source, /AUTOPILOT_SKIP_OVERVIEW/);
  assert.match(source, /statusItem\.command = "ioi\.overview\.open"/);
  assert.match(source, /targetId: "ioi\.overview"/);
  assert.match(source, /targetId: "activity\.overview"/);
  assert.match(source, /commandId: "workbench\.view\.extension\.ioi-overview"/);
  assert.match(source, /commandId: "ioi\.overview\.open"/);
});

test("Autopilot Workbench contributes the transitional mode rail and Code command path", async () => {
  const source = await readExtensionCompositeSource();
  const manifest = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const containers = new Set(
    (manifest.contributes?.viewsContainers?.activitybar || []).map(
      (container) => container.id,
    ),
  );
  const commands = new Set(
    (manifest.contributes?.commands || []).map((command) => command.command),
  );

  for (const containerId of [
    "ioi-overview",
    "ioi-studio",
    "ioi-workflows",
    "ioi-models",
    "ioi-runs",
    "ioi-policy",
    "ioi-connectors",
    "ioi-code",
  ]) {
    assert.ok(
      containers.has(containerId),
      `${containerId} should be contributed for the transitional Autopilot rail`,
    );
  }

  assert.ok(commands.has("ioi.code.open"));
  assert.ok(commands.has("ioi.autopilot.back"));
  assert.ok(manifest.contributes?.views?.["ioi-runs"]?.some((view) => view.id === "ioi.runsActivity"));
  assert.ok(manifest.contributes?.views?.["ioi-policy"]?.some((view) => view.id === "ioi.policyActivity"));
  assert.ok(
    manifest.contributes?.views?.["ioi-connectors"]?.some(
      (view) => view.id === "ioi.connectorsActivity",
    ),
  );
  assert.ok(manifest.contributes?.views?.["ioi-code"]?.some((view) => view.id === "ioi.codeActivity"));
  assert.match(source, /const AUTOPILOT_MODES = \[/);
  assert.match(source, /const AUTOPILOT_MODE_BY_PANEL_VIEW_ID/);
  assert.match(source, /id: "code"[\s\S]*command: "ioi\.code\.open"/);
  assert.match(source, /function renderAutopilotShellHeader/);
  assert.match(source, /data-testid="autopilot-workbench-shell-header"/);
  assert.match(source, /window"\)\s*\n\s*\.update\("menuBarVisibility", menuBarVisibility, vscode\.ConfigurationTarget\.Global\)/);
  assert.match(source, /menuBarVisibility = modeId === "code" \? "classic" : "hidden"/);
  assert.match(source, /function openGenericModePanel/);
  assert.match(source, /const genericModePanels = new Map\(\)/);
  assert.match(source, /function codeModePanelHtml/);
  assert.match(source, /data-testid="autopilot-code-mode"/);
  assert.match(source, /data-testid="code-repository-surface"/);
  assert.match(source, /Code repositories/);
  assert.match(source, /data-testid="code-repositories-gate"/);
  assert.match(source, /Find pull requests\.\.\./);
  assert.match(source, /No pull requests created by you/);
  assert.match(source, /What's new\?/);
  assert.match(source, /function codeRepositoryGateProjection/);
  assert.match(source, /data-testid="code-mode-vscode-menu-tooling"/);
  assert.match(source, /testId: "back-to-autopilot-from-code"/);
  assert.match(source, /workbench\.view\.explorer/);
  assert.match(source, /workbench\.view\.search/);
  assert.match(source, /workbench\.view\.scm/);
  assert.match(source, /workbench\.view\.extensions/);
  assert.match(source, /viewId: "ioi\.runsActivity"[\s\S]*command: "ioi\.runs\.refresh"/);
  assert.match(source, /viewId: "ioi\.policyActivity"[\s\S]*command: "ioi\.policy\.open"/);
  assert.match(source, /viewId: "ioi\.connectorsActivity"[\s\S]*command: "ioi\.connections\.inspect"/);
  assert.doesNotMatch(source, /src-tauri|@tauri-apps|tauri:\/\/|tauri\./i);
});

test("Autopilot Models renders the LM Studio-inspired operator surface", async () => {
  const source = await readExtensionCompositeSource();
  const manifest = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const commands = new Set(
    (manifest.contributes?.commands || []).map((command) => command.command),
  );
  const modelViews = manifest.contributes?.views?.["ioi-models"] || [];

  assert.ok(modelViews.some((view) => view.id === "ioi.models"));
  assert.ok(commands.has("ioi.models.open"));
  assert.ok(commands.has("ioi.models.openLoader"));
  assert.ok(commands.has("ioi.models.selectForWorkflow"));
  assert.ok(commands.has("ioi.models.searchCatalog"));
  assert.ok(commands.has("ioi.models.configureCatalogProvider"));
  assert.ok(commands.has("ioi.models.downloadCatalog"));
  assert.match(source, /models-lmstudio__primary/);
  assert.match(source, /data-testid="model-library-table"/);
  assert.match(source, /data-testid="model-selected-inspector"/);
  assert.match(source, /data-testid="model-quick-loader-popover"/);
  assert.match(source, /data-testid="model-load-dialog"/);
  assert.match(source, /data-testid="model-discovery-surface"/);
  assert.match(source, /data-testid="model-discover-list"/);
  assert.match(source, /data-testid="model-discover-staff-picks"/);
  assert.match(source, /data-testid="model-discover-sort"/);
  assert.match(source, /data-testid="model-discover-search-button"/);
  assert.match(source, /data-testid="model-more-from-publisher"/);
  assert.match(source, /data-testid="model-discover-capabilities"/);
  assert.match(source, /data-testid="model-discover-stats"/);
  assert.match(source, /data-testid="model-discover-readme-title"/);
  assert.match(source, /Nemotron 3 Nano Omni/);
  assert.match(source, /Partial GPU offload possible/);
  assert.match(source, /data-testid="model-catalog-sources-surface"/);
  assert.match(source, /data-testid="model-local-autodiscovery-sources"/);
  assert.match(source, /data-testid="model-remote-registry-sources"/);
  assert.match(source, /function runDaemonModelCatalogProviderConfig/);
  assert.match(source, /function runDaemonModelCatalogSearch/);
  assert.match(source, /\/api\/v1\/models\/catalog\/providers/);
  assert.match(source, /\/api\/v1\/models\/catalog\/search/);
  assert.match(source, /data-testid="model-server-logs"/);
  assert.match(source, /data-testid="model-running-unload-button"/);
  assert.match(source, /data-testid="model-advanced-settings-panel"/);
  assert.match(source, /data-testid="model-estimate-button"/);
  assert.match(source, /data-testid="model-empty-state"/);
  assert.match(source, /data-testid="model-error-state"/);
  assert.match(source, /endpointId: endpoint\?\.id/);
  assert.match(source, /endpointId: selectedEndpoint\.id/);
  assert.match(source, /moveModelSelection/);
  assert.match(source, /data-model-inspector-tab="info"/);
  assert.match(source, /data-model-inspector-tab="load"/);
  assert.match(source, /function activateModelInspectorTab/);
  assert.match(source, /runtimeAuthority: "daemon-owned"/);
  assert.match(source, /webviewExecutesModel: false/);
  assert.doesNotMatch(source, /src-tauri|@tauri-apps|tauri:\/\/|tauri\./i);
});

test("Autopilot desktop launcher starts a daemon sidecar and discovers local models", async () => {
  const source = await readFile(desktopLauncherPath, "utf8");

  assert.match(source, /startRuntimeDaemonService/);
  assert.match(source, /IOI_DAEMON_ENDPOINT/);
  assert.match(source, /IOI_DAEMON_TOKEN/);
  assert.match(source, /AUTOPILOT_SKIP_DAEMON/);
  assert.match(source, /AUTOPILOT_SKIP_MODEL_AUTODISCOVERY/);
  assert.match(source, /AUTOPILOT_SKIP_EXTENSION_SYNC/);
  assert.match(source, /syncWorkbenchExtension/);
  assert.match(source, /syncWorkbenchExtensionTargets/);
  assert.match(source, /provider\.lmstudio/);
  assert.match(source, /\/api\/v1\/providers\/\$\{encodeURIComponent\(providerId\)\}\/models/);
  assert.match(source, /\/api\/v1\/models\/mount/);
  assert.match(source, /route\.native-local/);
  assert.match(source, /autopilot-ide-daemon-ready\.json/);
});

test("Workflow Composer reflects live daemon model route readiness", async () => {
  const composerSource = await readFile(
    "apps/autopilot/openvscode-extension/ioi-workbench/webview/workflow-composer/main.tsx",
    "utf8",
  );
  const runtimeSource = await readFile(
    "apps/autopilot/openvscode-extension/ioi-workbench/webview/workflow-composer/fixtureRuntime.ts",
    "utf8",
  );
  const daemonSource = await readFile("packages/runtime-daemon/src/model-mounting.mjs", "utf8");

  assert.match(composerSource, /daemonModelRouteReady/);
  assert.match(composerSource, /Daemon route blocked/);
  assert.match(composerSource, /data-route-ready/);
  assert.match(runtimeSource, /daemonModelId/);
  assert.match(runtimeSource, /max_tokens: 1/);
  assert.match(daemonSource, /max_tokens: body\.max_tokens/);
  assert.match(daemonSource, /temperature: body\.temperature/);
});

test("native workbench context snapshots are projected to IOI runtime bridge", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /function buildWorkbenchContextSnapshot/);
  assert.match(source, /schemaVersion: "ioi\.workbench-integration\.v1"/);
  assert.match(source, /runtimeTruthSource: "daemon-runtime"/);
  assert.match(source, /projectionOwner: "openvscode-workbench-adapter"/);
  assert.match(source, /ownsRuntimeState: false/);
  assert.match(source, /activeEditor/);
  assert.match(source, /diagnostics/);
  assert.match(source, /terminalState/);
  assert.match(source, /visibleView/);
  assert.match(source, /function buildWorkbenchScmState/);
  assert.match(source, /vscode\.extensions\.getExtension\("vscode\.git"\)/);
  assert.match(source, /workingTreeChanges/);
  assert.match(source, /indexChanges/);
  assert.match(source, /untrackedChanges/);
  assert.match(source, /function buildWorkbenchTaskState/);
  assert.match(source, /vscode\.tasks\.taskExecutions/);
  assert.match(source, /vscode\.tasks\.onDidStartTask/);
  assert.match(source, /vscode\.tasks\.onDidEndTaskProcess/);
  assert.match(source, /writeBridgeRequest\("workbench\.contextSnapshot"/);
  assert.match(source, /startWorkbenchContextSnapshotPublisher\(context, output\)/);
});

test("native inspection target index prefers workbench refs before fallback", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /function buildWorkbenchInspectionTargetIndex/);
  assert.match(source, /indexId: "workbench-target-index:latest"/);
  assert.match(source, /targetId: "ioi\.chat"/);
  assert.match(source, /targetId: "ioi\.chat\.composer"/);
  assert.match(source, /targetId: "ioi\.chat\.action\.build-workspace"/);
  assert.match(source, /targetId: "command-center\.autopilot-header"/);
  assert.match(source, /targetId: "command-center\.openvscode-disabled"/);
  assert.match(source, /targetId: "activity\.overview"/);
  assert.match(source, /targetId: "activity\.studio"/);
  assert.match(source, /targetId: "activity\.workflows"/);
  assert.match(source, /targetId: "activity\.models"/);
  assert.match(source, /targetId: "activity\.runs"/);
  assert.match(source, /targetId: "activity\.policy"/);
  assert.match(source, /targetId: "activity\.connectors"/);
  assert.match(source, /targetId: "activity\.code"/);
  assert.match(source, /targetId: "activity\.back-to-autopilot"/);
  assert.doesNotMatch(source, /targetId: "activity\.ioi"/);
  assert.match(source, /targetId: "activity\.explorer"/);
  assert.match(source, /targetId: "activity\.search"/);
  assert.match(source, /targetId: "activity\.scm"/);
  assert.match(source, /targetId: "explorer\.active-file"/);
  assert.match(source, /targetId: `editor\.tab\.\$\{groupIndex\}\.\$\{tabIndex\}`/);
  assert.match(source, /targetId: "workflow\.composer"/);
  assert.match(source, /targetId: "workflow\.generate-code"/);
  assert.match(source, /targetId: "run\.evidence\.rows"/);
  assert.match(source, /targetId: "checks\.tasks"/);
  assert.doesNotMatch(source, /commandId: "workbench\.view\.extension\.ioi-chat"/);
  assert.match(source, /commandId: "workbench\.view\.extension\.ioi-overview"/);
  assert.match(source, /commandId: "workbench\.view\.extension\.ioi-studio"/);
  assert.match(source, /commandId: "workbench\.view\.extension\.ioi-workflows"/);
  assert.match(source, /commandId: "workbench\.view\.extension\.ioi-models"/);
  assert.match(source, /commandId: "ioi\.workflow\.generateCode"/);
  assert.match(source, /commandId: "ioi\.runs\.refresh"/);
  assert.match(source, /commandId: "workbench\.action\.tasks\.runTask"/);
  assert.match(source, /targetId: "editor\.active"/);
  assert.match(source, /kind: "vscode-command"/);
  assert.match(source, /kind: "vscode-view"/);
  assert.match(source, /kind: "editor-range"/);
  assert.match(source, /writeBridgeRequest\("workbench\.inspectionTargetIndex"/);
});

test("workflow code generation requests are proposal-first runtime projections", async () => {
  const source = await readExtensionCompositeSource();
  const manifest = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const commands = new Set(
    (manifest.contributes?.commands || []).map((command) => command.command),
  );

  assert.ok(commands.has("ioi.workflow.generateCode"));
  assert.match(source, /vscode\.commands\.registerCommand\("ioi\.workflow\.generateCode"/);
  assert.match(source, /requestId: crypto\.randomUUID\(\)/);
  assert.match(source, /runtimeTruthSource: "daemon-runtime"/);
  assert.match(source, /projectionOwner: "openvscode-workbench-adapter"/);
  assert.match(source, /ownsRuntimeState: false/);
  assert.match(source, /boundModelCapabilityRef/);
  assert.match(source, /boundToolCapabilityRefs/);
  assert.match(source, /authorityScope: "workspace\.fs\.proposal"/);
  assert.match(source, /proposalOnly: true/);
  assert.match(source, /writeBridgeRequest\("workflow\.codeGenerationRequest"/);
});

test("native command routing emits IOI route receipts", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /function buildWorkbenchCommandRouteReceipt/);
  assert.match(source, /requestType: "workbench\.commandRouteReceipt"/);
  assert.match(source, /route: "ioi-runtime-action"/);
  assert.match(source, /"editor-local"/);
  assert.match(source, /route: "blocked"/);
  assert.match(source, /runtimeTruthSource: "daemon-runtime"/);
  assert.match(source, /projectionOwner: "openvscode-workbench-adapter"/);
  assert.match(source, /ownsRuntimeState: false/);
  assert.match(source, /isRuntimeActionRequestType\(requestType\)/);
  assert.match(source, /writeWorkbenchCommandRouteReceipt/);
});

test("Agent Studio streams website artifact drafting before rendering the final artifact", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /function generateStudioStaticWebsiteDraft/);
  assert.match(source, /presentation: "artifact_generation"/);
  assert.doesNotMatch(source, /label: "Drafting website artifact"/);
  assert.match(source, /const promptNeedsRetrieval = promptRequiresRetrieval\(prompt\);/);
  assert.match(source, /if \(!explicitSourceRequirement && !promptNeedsRetrieval\) \{\s*return "";\s*\}/);
  assert.match(source, /fileName: "index.html"/);
  assert.match(source, /requestSseJson\(endpoint, "\/v1\/chat\/completions"/);
  assert.match(source, /stream: true/);
  assert.match(source, /const STUDIO_DEFAULT_ARTIFACT_MAX_OUTPUT_TOKENS = 4096/);
  assert.match(source, /function studioArtifactMaxOutputTokens/);
  assert.match(source, /max_tokens: studioArtifactMaxOutputTokens\(\)/);
  assert.match(source, /assistantThinkingDelta/);
  assert.match(source, /assistantStreamDelta/);
  assert.match(source, /assistantStreamComplete/);
  assert.match(source, /htmlCloseMatch = streamResult\.text\.match\(\/<\\\/html>\/i\)/);
  assert.match(source, /return false;/);
  assert.match(source, /stoppedByClient: true/);
  assert.match(source, /function studioEstimatedTokenCount/);
  assert.match(source, /generatedText: text/);
  assert.match(source, /metrics\.estimatedTokens \? "~" : ""/);
  assert.match(source, /studioArtifactAnswerText\(\[artifact\]\)/);
  assert.doesNotMatch(source, /generateStudioStaticWebsiteDraft[\s\S]*stream: false[\s\S]*studioWebsiteDraftRejectReason/);
});

test("Agent Studio renders assistant chat answers as sanitized Markdown", async () => {
  const source = await readExtensionCompositeSource();

  assert.match(source, /function escapeMarkdownHtml/);
  assert.match(source, /function sanitizeMarkdownUrl/);
  assert.match(source, /function renderMarkdownBlocks/);
  assert.match(source, /function renderMarkdownInto/);
  assert.match(source, /function appendMarkdownDelta/);
  assert.match(source, /const STUDIO_MARKDOWN_FENCE = String\.fromCharCode\(96, 96, 96\)/);
  assert.match(source, /protocol === "http:" \|\| protocol === "https:" \|\| protocol === "mailto:"/);
  assert.match(source, /if \(!safeUrl\) return label;/);
  assert.match(source, /target="_blank" rel="noreferrer noopener"/);
  assert.match(source, /document\.createElement\(role === "assistant" \? "div" : "p"\)/);
  assert.match(source, /paragraph\.className = "studio-markdown"/);
  assert.match(source, /renderMarkdownInto\(paragraph, humanizeProjectedTurnText\(role, content\)\)/);
  assert.match(source, /appendMarkdownDelta\(target\.text, payload\.delta \|\| ""\)/);
  assert.match(source, /renderMarkdownInto\(target\.text, payload\.text\)/);
  assert.match(source, /\.studio-markdown pre code/);
  assert.match(source, /\.studio-markdown table/);
});

test("Agent Studio final refresh is bounded so artifact turns cannot remain visually pending forever", async () => {
  const source = await readExtensionCompositeSource();
  const extensionSource = await readFile(extensionSourcePath, "utf8");

  assert.match(source, /const STUDIO_REFRESH_STATE_TIMEOUT_MS = Number\.isFinite/);
  assert.match(source, /const STUDIO_MODEL_SNAPSHOT_TIMEOUT_MS = Number\.isFinite/);
  assert.match(source, /const STUDIO_ARTIFACT_REQUEST_TIMEOUT_MS = Number\.isFinite/);
  assert.match(source, /requestJson\(endpoint, "\/api\/v1\/models", \{[\s\S]*timeoutMs: STUDIO_MODEL_SNAPSHOT_TIMEOUT_MS/);
  assert.match(source, /function requestBridge\(method, bridgePath, payload, \{ timeoutMs \} = \{\}\)/);
  assert.match(source, /Bridge request timed out after \$\{boundedTimeoutMs\}ms/);
  assert.match(source, /requestBridge\("GET", "state", undefined, \{[\s\S]*timeoutMs: STUDIO_REFRESH_STATE_TIMEOUT_MS/);
  assert.match(source, /if \(data === "\[DONE\]"\) \{[\s\S]*finishResolve\(\{ statusCode, raw \}\);[\s\S]*request\.destroy\(\);/);
  assert.match(source, /timeoutMs: STUDIO_ARTIFACT_REQUEST_TIMEOUT_MS/);
  assert.match(source, /recoverStudioConversationArtifactAfterTimeout/);
  assert.match(source, /recovered conversation artifact after bounded request timeout/);
  assert.match(source, /const applyArtifactAction = async \(action, payload = \{\}\) =>/);
  assert.match(source, /if \(result\?\.artifact\) \{[\s\S]*artifact = result\.artifact/);
  assert.match(source, /if \(!generatedFiles\) \{[\s\S]*await applyArtifactAction\("rebuild"\)/);
  assert.match(source, /const staleProductSelectionAvailable = Boolean/);
  assert.doesNotMatch(source, /return requestJson\(daemonEndpoint\(\), `\/v1\/conversation-artifacts\/\$\{encodeURIComponent\(artifact\.id\)\}`/);
  assert.doesNotMatch(extensionSource, /studioPanelNonce/);
});
