import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import test from "node:test";

const require = createRequire(import.meta.url);

const paths = {
  extension: "apps/autopilot/openvscode-extension/ioi-workbench/extension.js",
  workbenchSurfaces:
    "apps/autopilot/openvscode-extension/ioi-workbench/workbench-surfaces.js",
  panel: "apps/autopilot/openvscode-extension/ioi-workbench/studio/studio-panel-html.js",
  styles: "apps/autopilot/openvscode-extension/ioi-workbench/studio/studio-panel-styles.js",
  modelSurface: "apps/autopilot/openvscode-extension/ioi-workbench/studio/model-surface.js",
  operationalSurface:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/operational-surface.js",
  modelCompletion:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/model-completion.js",
  answerStream:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/agent-answer-stream.js",
  finalHandoffStream:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/agent-final-handoff-stream.js",
  turnEvents:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/agent-turn-events.js",
  turnResultText:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/agent-turn-result-text.js",
  turnRecovery:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/agent-turn-recovery.js",
  runtimeEvents:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/runtime-event-utils.js",
  productErrors:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/product-error-message.js",
  artifactRouting:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/artifact-research-routing.js",
  packageJson: "apps/autopilot/openvscode-extension/ioi-workbench/package.json",
  launcher: "scripts/launch-autopilot-ide-fork.mjs",
  shellPatch: "scripts/lib/autopilot-workbench-shell-patch.mjs",
};

async function read(path) {
  return readFile(path, "utf8");
}

async function readStudioComposite() {
  const parts = await Promise.all(
    [
      paths.extension,
      paths.workbenchSurfaces,
      paths.panel,
      paths.styles,
      paths.modelSurface,
      paths.operationalSurface,
      paths.modelCompletion,
      paths.answerStream,
      paths.finalHandoffStream,
      paths.turnEvents,
      paths.turnResultText,
      paths.turnRecovery,
      paths.runtimeEvents,
      paths.productErrors,
      paths.artifactRouting,
    ].map(read),
  );
  return parts.join("\n");
}

function assertHas(source, patterns) {
  for (const pattern of patterns) {
    assert.match(source, pattern);
  }
}

function assertLacks(source, patterns) {
  for (const pattern of patterns) {
    assert.doesNotMatch(source, pattern);
  }
}

test("Agent Studio keeps the product chat shell, Markdown renderer, and clean transcript boundary", async () => {
  const source = await readStudioComposite();

  assertHas(source, [
    /data-operator-chat-pane="native-openvscode"/,
    /data-inspection-target="native-ioi-chat-pane"/,
    /data-inspection-target="native-ioi-chat-composer"/,
    /data-inspection-target="native-ioi-chat-thread"/,
    /function renderNativeChatConversation/,
    /data-chat-turn-role/,
    /renderMarkdownInto/,
    /humanizeProjectedTurnText/,
    /\.studio-markdown/,
    /composerTestId: "studio-composer-input"/,
    /data-testid="studio-pending-worklog"/,
  ]);
  assertLacks(source, [
    /Story 1:/,
    /Briefing for '/,
    /Run date \(UTC\):/,
    /Run timestamp \(UTC\):/,
    /Overall confidence:/,
  ]);
});

test("Agent Studio keeps Ask/Agent, permissions, and model route selection explicit", async () => {
  const source = await readStudioComposite();

  assertHas(source, [
    /const STUDIO_MODE_ASK = "ask"/,
    /function normalizeStudioExecutionMode/,
    /STUDIO_MODE_ASK \? "Ask" : "Agent"/,
    /const STUDIO_PERMISSION_MODE_DEFAULT = "suggest"/,
    /const STUDIO_PERMISSION_MODE_AUTO_REVIEW = "auto_local"/,
    /const STUDIO_PERMISSION_MODE_FULL_ACCESS = "never_prompt"/,
    /function studioPermissionDaemonMapping/,
    /function studioModelIdForRouteInvocation/,
    /const STUDIO_PRODUCT_MODEL_UNAVAILABLE = "__product_model_unavailable__"/,
    /function isProductStudioModelSelection/,
    /function assertStudioProductModelSelector/,
    /Product model route unavailable/,
    /No product model is mounted for this route/,
    /routePicker\?\.dataset\?\.modelUnavailable === "true"/,
  ]);
  assertLacks(source, [/candidate\.routeId === activeRoute\.routeId/]);
});

test("Agent Studio streams model text, tool work, final handoff, and artifact delivery through extracted modules", async () => {
  const source = await readStudioComposite();

  assertHas(source, [
    /function studioRuntimeEventIsRunningStepCompletion/,
    /studioAssistantTextFromRuntimeToolEvents/,
    /studioAgentTurnResultText/,
    /studioResultTextLooksRetrievalGrounded/,
    /function recoverStudioAgentTurnAfterSubmitTimeout/,
    /function recoverStudioAgentTurnFromLiveEventsAfterSubmitTimeout/,
    /function shouldProjectConversationArtifactCanvas/,
    /function projectStudioConversationArtifactCanvas/,
    /function studioPromptRequestsGeneratedWebArtifact/,
    /function normalizeStudioAssistantReplyText/,
    /function studioRetrievalFailClosedText/,
    /did not emit a clean final answer/,
    /const hasMaxStepsOverride = maxStepsOverride !== null/,
    /studioAgentMaxStepsForIntent\(intentFrame, prompt\)/,
  ]);
  assertLacks(source, [
    /function studioPromptRequestsSourceCandidates/,
    /function studioResultTextLooksSearchCandidateList/,
    /searchOnlySourceCandidateAnswer/,
    /const requestedMaxSteps = Number\.isFinite\(Number\(maxStepsOverride\)\)/,
  ]);
});

test("Agent Studio keeps the work lane glass-boxed without cluttering the collapsed summary", async () => {
  const source = await readStudioComposite();

  assertHas(source, [
    /function studioSourceRefsFromRuntimeEvent/,
    /function collectStudioSourceRefsFromPartialJsonText/,
    /studioUnescapeJsonStringFragment/,
    /function studioSourceChipRows/,
    /function sanitizeStudioSourceUrl/,
    /function studioSourceChipFaviconUrl/,
    /function studioProjectedSourceChipRows/,
    /function syncProjectedSourceRows/,
    /function studioWorkSummaryRows/,
    /source_url/,
    /source_observations/,
    /\.\.\.liveObservedEvents/,
    /studioSourceRefsFromRuntimeEvents\(generatedRuntimeEvents\)/,
    /artifactSourceRefs/,
    /artifactForTurn/,
    /sourceRefs: generatedSourceRefs/,
    /sourceRefs,\n    workRecord: studioPublicWorkRecordForWebview\(assistantTurn\?\.workRecord\),\n    prompt: prompt/,
    /sourceRefs: firstArray\(agentTurn\.sourceRefs\)/,
    /workRecord: studioPublicWorkRecordForWebview\(workRecord\)/,
    /syncProjectedSourceRows\(target\.turn, payload\.sourceRefs\)/,
    /function ensureProjectedWorkRunBar/,
    /ensureProjectedWorkRunBar\(target\.turn, payload\.workRecord, "completed"\)/,
    /ensureProjectedWorkRunBar\(turn, payload\?\.workRecord, status\)/,
    /rootStatus.*completed.*blocked/s,
    /removeAttribute\("data-agent-final-handoff-stream-complete"\)/,
    /removeAttribute\("data-artifact-handoff-stream-complete"\)/,
    /data-artifact-source-retained/,
    /!\["completed", "blocked"\]\.includes\(rootStatus\)/,
    /sourceChips/,
    /excerptPreview/,
    /\.studio-source-chip-list/,
    /\.studio-work-row/,
    /\.studio-pending-step__excerpt/,
  ]);
  assertLacks(source, [
    /<span>\$\{escapeHtml\(studioDocumentedWorkSummary\(workRecord\)\)\}<\/span>/,
    /<span>\$\{studioDocumentedWorkSummary\(workRecord\)\}<\/span>/,
  ]);
});

test("Agent Studio keeps managed browser and computer sessions as live artifacts", async () => {
  const source = await readStudioComposite();

  assertHas(source, [
    /function studioManagedSessionFromRuntimeEvent/,
    /function studioManagedSessionRows/,
    /studioRuntimeProjection\.computerUseSessions/,
    /data-testid="studio-managed-session-card"/,
    /data-testid="studio-managed-session-compact-preview"/,
    /data-testid="studio-managed-session-expanded-view"/,
    /Sandbox browser/,
    /Local browser/,
    /Desktop/,
    /data-testid="studio-managed-session-observe"/,
    /data-testid="studio-managed-session-take-over"/,
    /data-testid="studio-managed-session-return"/,
  ]);
});

test("Agent Studio normalizes daemon kernel tool events into product work rows", () => {
  const { studioRuntimeEventToolName, studioRuntimeToolEventDetail } = require(`./studio/runtime-event-utils.js`);
  const event = {
    event_kind: "tool.completed",
    payload: {
      kernel_event: JSON.stringify({
        AgentActionResult: {
          output: {
            preview: JSON.stringify({
              tool: "web__search",
              query: "photonic quantum computing",
              sources: [
                {
                  title: "Photonic quantum source",
                  url: "https://example.com/photonic",
                },
              ],
            }),
          },
        },
      }),
    },
  };

  assert.equal(studioRuntimeEventToolName(event), "web__search");
  assert.match(studioRuntimeToolEventDetail(event, studioRuntimeEventToolName(event)), /photonic quantum computing/);
});

test("Model setup remains native and product-scoped", async () => {
  const source = await readStudioComposite();
  const shellPatch = await read(paths.shellPatch);

  assertHas(source, [
    /data-testid="model-recommended-setup"/,
    /Qwen 3\.5/,
    /Text embedding/,
    /function modelRecordIsEmbeddingOnly/,
    /function studioSelectionSupportsChat/,
    /haystack\.includes\("no product model"\)/,
    /haystack\.includes\("product model mounted"\)/,
  ]);
  assertHas(shellPatch, [/label: "Set up recommended models"/, /requestType: "models\.open"/]);
  assertLacks(shellPatch, [/label: "No mounted models"/]);
});

test("Workbench contributions keep the operator surfaces reachable without restoring legacy sidebars", async () => {
  const source = await readStudioComposite();
  const manifest = JSON.parse(await read(paths.packageJson));
  const launcher = await read(paths.launcher);
  const commandIds = new Set(manifest.contributes.commands.map((entry) => entry.command));

  for (const commandId of [
    "ioi.overview.open",
    "ioi.studio.open",
    "ioi.models.open",
  ]) {
    assert.ok(commandIds.has(commandId), `${commandId} should stay contributed`);
  }
  assertHas(source, [
    /Agent Studio/,
    /Recents/,
    /function createStudioOperationalSurface/,
    /function renderModelsPanelBody/,
  ]);
  assertHas(launcher, [/startManagedDaemon/, /IOI_DAEMON_ENDPOINT/]);
  assertLacks(source, [/legacy IOI chat sidebar/i]);
});
