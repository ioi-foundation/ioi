import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import test from "node:test";

const require = createRequire(import.meta.url);

const paths = {
  extension: "apps/autopilot/openvscode-extension/ioi-workbench/extension.js",
  workbenchSurfaces:
    "apps/autopilot/openvscode-extension/ioi-workbench/workbench-surfaces.js",
  workbenchContextSnapshot:
    "apps/autopilot/openvscode-extension/ioi-workbench/workbench/context-snapshot.js",
  codeModePanel:
    "apps/autopilot/openvscode-extension/ioi-workbench/workbench/code-mode-panel.js",
  overviewPanel:
    "apps/autopilot/openvscode-extension/ioi-workbench/workbench/overview-panel.js",
  workflowComposerPanel:
    "apps/autopilot/openvscode-extension/ioi-workbench/workbench/workflow-composer-panel.js",
  panel: "apps/autopilot/openvscode-extension/ioi-workbench/studio/studio-panel-html.js",
  styles: "apps/autopilot/openvscode-extension/ioi-workbench/studio/studio-panel-styles.js",
  modelSurface: "apps/autopilot/openvscode-extension/ioi-workbench/studio/model-surface.js",
  operationalSurface:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/operational-surface.js",
  modelCompletion:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/model-completion.js",
  promptPolicy:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/prompt-policy.js",
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
  runtimeEventSelectors:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/runtime-event-selectors.js",
  pendingWork:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/pending-work.js",
  turnPolicy:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/turn-policy.js",
  policyLeaseLifecycle:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/policy-lease-lifecycle.js",
  workRecordProjection:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/work-record-projection.js",
  responseMetrics:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/response-metrics.js",
  sourceChipRenderer:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/source-chip-renderer.js",
  sourceRefs:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/source-refs.js",
  codeExecution:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/code-execution.js",
  chatOutputRenderers:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/chat-output-renderers.js",
  parityPlusPanels:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/parity-plus-panels.js",
  nativeChatView:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/native-chat-view.js",
  toolPalette:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/tool-palette.js",
  modelSelection:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/model-selection.js",
  overviewView:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/overview-view.js",
  traceView:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/trace-view.js",
  viewHelpers:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/view-helpers.js",
  chatCommands:
    "apps/autopilot/openvscode-extension/ioi-workbench/commands/chat.js",
  modelCommands:
    "apps/autopilot/openvscode-extension/ioi-workbench/commands/models.js",
  navigationCommands:
    "apps/autopilot/openvscode-extension/ioi-workbench/commands/navigation.js",
  runtimeSurfaceCommands:
    "apps/autopilot/openvscode-extension/ioi-workbench/commands/runtime-surfaces.js",
  productErrors:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/product-error-message.js",
  projectionState:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-state.js",
  projectionReplay:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-replay.js",
  publicTextSanitizer:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/public-text-sanitizer.js",
  managedSessions:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/projection-managed-sessions.js",
  artifactRouting:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/artifact-research-routing.js",
  artifactIntent:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/artifact-intent.js",
  artifactPreview:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/artifact-preview.js",
  managedSessionView:
    "apps/autopilot/openvscode-extension/ioi-workbench/studio/managed-session-view.js",
  studioModeControls:
    "apps/autopilot/openvscode-extension/ioi-workbench/commands/studio-mode-controls.js",
  studioQuickInput:
    "apps/autopilot/openvscode-extension/ioi-workbench/commands/studio-quick-input.js",
  studioTestHooks:
    "apps/autopilot/openvscode-extension/ioi-workbench/commands/studio-test-hooks.js",
  workflowCommands:
    "apps/autopilot/openvscode-extension/ioi-workbench/commands/workflow.js",
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
      paths.workbenchContextSnapshot,
      paths.codeModePanel,
      paths.overviewPanel,
      paths.workflowComposerPanel,
      paths.panel,
      paths.styles,
      paths.modelSurface,
      paths.operationalSurface,
      paths.modelCompletion,
      paths.promptPolicy,
      paths.answerStream,
      paths.finalHandoffStream,
      paths.turnEvents,
      paths.turnResultText,
      paths.turnRecovery,
      paths.runtimeEvents,
      paths.runtimeEventSelectors,
      paths.pendingWork,
      paths.turnPolicy,
      paths.policyLeaseLifecycle,
      paths.workRecordProjection,
      paths.responseMetrics,
      paths.sourceChipRenderer,
      paths.sourceRefs,
      paths.codeExecution,
      paths.chatOutputRenderers,
      paths.parityPlusPanels,
      paths.nativeChatView,
      paths.toolPalette,
      paths.modelSelection,
      paths.overviewView,
      paths.traceView,
      paths.viewHelpers,
      paths.chatCommands,
      paths.modelCommands,
      paths.navigationCommands,
      paths.runtimeSurfaceCommands,
      paths.productErrors,
      paths.projectionState,
      paths.projectionReplay,
      paths.publicTextSanitizer,
      paths.managedSessions,
      paths.artifactRouting,
      paths.artifactIntent,
      paths.artifactPreview,
      paths.managedSessionView,
      paths.studioModeControls,
      paths.studioQuickInput,
      paths.studioTestHooks,
      paths.workflowCommands,
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
    /function sanitizePublicAssistantText/,
    /sanitizePublicAssistantText\(payload\.text\)/,
    /function studioSanitizePublicAssistantText/,
    /Invalid transaction/,
    /Blocked by Policy/,
  ]);
  assertLacks(source, [
    /Story 1:/,
    /Briefing for '/,
    /Run date \(UTC\):/,
    /Run timestamp \(UTC\):/,
    /Overall confidence:/,
  ]);
});

test("Agent Studio product assistant text strips trace and tool plumbing without prompt help", () => {
  const { createStudioAgentTurnResultText } = require(`${process.cwd()}/${paths.turnResultText}`);
  const { sanitizeStudioProductAssistantText } = createStudioAgentTurnResultText({
    stringValue: (value) => String(value || ""),
    firstArray: (value) => (Array.isArray(value) ? value : []),
    studioRuntimeEventKind: () => "",
    studioRuntimeEventToolName: () => "",
    extractHtmlDocument: () => "",
  });

  const cleaned = sanitizeStudioProductAssistantText(
    "The governed file tool returned the following error: Blocked by policy: ERROR_CLASS=PolicyBlocked file__write refused /tmp/autopilot-agent-studio-demo/out.txt receipt_abc123456789.",
  );

  assert.equal(
    cleaned,
    "The policy reason was: policy block the governed file write refused the requested workspace path Tracing.",
  );

  const livePhrase = sanitizeStudioProductAssistantText(
    "The attempt to write foo to the requested workspace path was blocked by the governed file tool. The tool returned the error: `` Blocked by policy: filesystem path is outside workspace authority. `` This confirms enforcement.",
  );

  assert.equal(
    livePhrase,
    "The attempt to write foo to the requested workspace path was blocked. The policy reason was: filesystem path is outside workspace authority. This confirms enforcement.",
  );
});

test("Agent Studio keeps Ask/Agent, permissions, and model route selection explicit", async () => {
  const source = await readStudioComposite();

  assertHas(source, [
    /STUDIO_MODE_ASK,\s*\n\s*STUDIO_PERMISSION_MODE_DEFAULT,/,
    /normalizeStudioExecutionMode,\s*\n\s*normalizeStudioPermissionMode,/,
    /studioExecutionModeLabel,\s*\n\s*studioPermissionDaemonMapping,/,
    /require\("\.\/studio\/modes"\)/,
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

test("Agent Studio policy lease cockpit covers allow once, revoke, and expiry", async () => {
  const source = await readStudioComposite();

  assertHas(source, [
    /function exerciseStudioPolicyLeaseLifecycle/,
    /ioi\.studio\.exercisePolicyLeaseLifecycle/,
    /studio\.policyLeaseLifecycle\.exercised/,
    /data-policy-lease-allow-once-observed/,
    /data-policy-lease-revoke-observed/,
    /data-policy-lease-expiry-observed/,
    /data-lease-after-revoke-blocked/,
    /data-lease-after-expiry-blocked/,
    /studio-policy-lease-allow-once/,
    /studio-policy-lease-expired/,
    /Operator allowed one Studio policy lease dry-run execution/,
    /Operator revoked the Studio policy lease after one dry-run execution/,
  ]);
});

test("Agent Studio injected runtime events refresh replay rows", async () => {
  const source = await readStudioComposite();

  assertHas(source, [
    /function refreshStudioReplayStepsFromProjection/,
    /refreshStudioReplayStepsFromProjectionState\(studioRuntimeProjection\)/,
    /firstArray\(studioRuntimeProjection\.runtimeEvents\)\.slice\(-8\)\.map/,
    /firstArray\(studioRuntimeProjection\.receipts\)\.slice\(-8\)\.map/,
    /refreshStudioReplayStepsFromProjection\(\);\s*\n\s*studioRuntimeProjection\.status = payload\?\.status \|\| "completed"/,
    /data-testid="studio-replay-step-detail"/,
  ]);
});

test("Agent Studio projects run brain artifacts into replayable product rows", async () => {
  const source = await readStudioComposite();

  assertHas(source, [
    /sessionBrainPanels: \[\]/,
    /function exerciseStudioSessionBrainLifecycle/,
    /ioi\.studio\.exerciseSessionBrainLifecycle/,
    /studio\.sessionBrainLifecycle\.exercised/,
    /studio-session-brain-panel/,
    /studioSessionBrainArtifactRows/,
    /studio-session-brain-artifact-row/,
    /data-brain-implementation-plan-observed/,
    /data-brain-task-checklist-observed/,
    /data-brain-walkthrough-observed/,
    /data-brain-scratch-refs-observed/,
    /data-brain-artifact-refs-observed/,
    /data-brain-replay-cursor-observed/,
    /data-brain-outside-workspace/,
    /data-brain-read-only-audit-mode/,
    /session\[._-\]\?brain\|run\[._-\]\?brain\|active\[._-\]\?brain/,
  ]);
});

test("Agent Studio projects durable trajectory replay across GUI reconnect", async () => {
  const source = await readStudioComposite();

  assertHas(source, [
    /trajectoryReplayPanels: \[\]/,
    /function exerciseStudioTrajectoryReplayReconnect/,
    /ioi\.studio\.exerciseTrajectoryReplayReconnect/,
    /studio\.trajectoryReplayReconnect\.exercised/,
    /studio-trajectory-replay-panel/,
    /studioTrajectoryReplayRows/,
    /studio-trajectory-replay-step-row/,
    /data-trajectory-id-stable/,
    /data-trajectory-replay-cursor-observed/,
    /data-trajectory-gui-reconnected/,
    /data-trajectory-replay-ids-stable/,
    /data-trajectory-replay-from-cursor-empty/,
    /data-trajectory-side-effect-count/,
    /data-trajectory-duplicate-side-effect-count/,
    /STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY/,
    /sideEffectWriteAttempted/,
  ]);
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
    /const resolvedIntentFrame = await resolveStudioPromptIntentFrame\(prompt,/,
    /intentFrame: resolvedIntentFramePayload/,
    /runtimeAction: resolvedIntentFramePayload\.runtimeAction \|\| resolvedIntentFramePayload\.runtime_action \|\| null/,
    /const intentFramePayload = studioIntentFramePayload\(intentFrame\);/,
    /intentFrame: intentFramePayload/,
    /runtimeAction: intentFramePayload\.runtimeAction \|\| intentFramePayload\.runtime_action \|\| null/,
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
    /studioSourceRefsFromRuntimeEvent,\s*\n\s*studioSourceRefsFromRuntimeEvents,/,
    /collectStudioSourceRefsFromPartialJsonText,/,
    /studioUnescapeJsonStringFragment/,
    /require\("\.\/studio\/source-refs"\)/,
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
    /function studioPendingCommandOutputExcerpt/,
    /studioPendingCommandOutputExcerpt\(step, sourceChips\[0\]\?\.excerpt \|\| ""\)/,
    /studioPendingCommandOutputExcerpt\(payload, sourceChips\[0\]\?\.excerpt \|\| ""\)/,
    /\^\[a-z0-9_\.-\]\+\\s\+-e\\s\+<inline script>/,
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
    /\.studio-pending-step__command-output/,
    /data-testid="studio-pending-command-output"/,
    /Patched\|Edited\|Read/,
    /<tmp>\/g,\s*"workspace file"/,
    /recordSettled.*completed\|blocked\|failed\|cancelled\|canceled/s,
    /running\|started\|pending/,
  ]);
  assertLacks(source, [
    /<span>\$\{escapeHtml\(studioDocumentedWorkSummary\(workRecord\)\)\}<\/span>/,
    /<span>\$\{studioDocumentedWorkSummary\(workRecord\)\}<\/span>/,
    /duration recorded by daemon/,
    /no stdout projected/,
  ]);
});

test("Agent Studio work records carry sanitized command and hunk details", () => {
  const studioWorkSummary = require("./studio-work-summary");
  const record = studioWorkSummary.studioDocumentedWorkRecord({
    commandOutputs: [
      {
        id: "shell__start:abcdef1234567890",
        toolId: "shell__start",
        label: "npm test",
        stdout: "",
        excerptPreview: "ok receipt_abc1234567890 /tmp/autopilot-fixture/out.txt",
        stderr: "",
        exitCode: 0,
      },
    ],
    diffHunks: [
      {
        title: "Update total formatter",
        file: "/tmp/autopilot-fixture/src/format.mjs",
        status: "pending",
        before: "return value;",
        after: "return `$${value}`;",
        changeId: "change_123",
        hunkIndex: 0,
      },
    ],
  }, { startedAtMs: Date.now() - 1200 });

  assert.equal(record.commandOutputs.length, 1);
  assert.equal(record.diffHunks.length, 1);
  assert.match(record.commandOutputs[0].stdout, /<tmp>/);
  assert.doesNotMatch(record.commandOutputs[0].stdout, /receipt_/);
  assert.doesNotMatch(record.commandOutputs[0].stdout, /\/tmp\//);
  assert.equal(record.diffHunks[0].title, "Update total formatter");
  assert.equal(record.diffHunks[0].file, "/tmp/autopilot-fixture/src/format.mjs");
  assert.equal(record.diffHunks[0].before, "return value;");
  assert.equal(record.diffHunks[0].after, "return `$${value}`;");
});

test("Agent Studio work records preserve command stream chunks as public stdout", () => {
  const studioWorkSummary = require("./studio-work-summary");
  const record = studioWorkSummary.studioDocumentedWorkRecord({
    pendingWorklog: [
      {
        id: "shell.pending.1",
        toolName: "shell__run",
        label: "Ran command",
        detail: "node -e <inline script>",
        excerptPreview: "glassbox-tick-4",
      },
    ],
    commandOutputs: [
      {
        id: "shell.output.1",
        toolId: "shell__run",
        label: "shell__run",
        command: "node -e <inline script>",
        status: "completed",
        chunk: "compile-once complete\n",
      },
    ],
  }, { startedAtMs: Date.now() - 1200 });

  assert.equal(record.workRows.length, 0);
  assert.equal(record.commandOutputs.length, 1);
  assert.equal(record.commandOutputs[0].label, "Ran Node.js command");
  assert.equal(record.commandOutputs[0].stdout, "compile-once complete");
  assert.doesNotMatch(record.commandOutputs[0].stdout, /shell__start:|receipt_|trace_|command_id/);
});

test("Agent Studio keeps managed browser and computer sessions as live artifacts", async () => {
  const source = await readStudioComposite();

  assertHas(source, [
    /function studioManagedSessionFromRuntimeEvent/,
    /function applyStudioManagedSessionInspection/,
    /function applyStudioManagedSessionsToLatestTurn/,
    /function refreshStudioManagedSessionsFromDaemon/,
    /function exerciseStudioManagedSessionReconnect/,
    /ioi\.studio\.exerciseManagedSessionReconnect/,
    /studio\.managedSessionReconnect\.exercised/,
    /const daemonSessionCards = !projectsArtifact\s*\?\s*await refreshStudioManagedSessionsFromDaemon\(output\)\s*:\s*\[\];\s*const workRecord = studioWorkRecordWithSessionCards\(/s,
    /workRecord: studioWorkRecordWithSessionCards\(null, daemonSessionCards\)/,
    /function studioManagedSessionRows/,
    /studioRuntimeProjection\.computerUseSessions/,
    /controlState: compactStudioWhitespace/,
    /turn\.workRecord = \{/,
    /studioManagedSessionControl/,
    /managed-sessions\/control/,
    /applyStudioManagedSessionsToLatestTurn\(studioRuntimeProjection\.computerUseSessions\)/,
    /data-session-id=/,
    /data-control-state=/,
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
  assertLacks(source, [
    /artifact-session:/,
    /upsertStudioManagedSession\(\s*studioManagedSessionFromRuntimeEvent/,
  ]);
});

test("Agent Studio normalizes daemon kernel tool events into product work rows", () => {
  const {
    studioRuntimeEventToolName,
    studioRuntimeToolEventDetail,
    studioRuntimeToolEventExcerpt,
  } = require(`./studio/runtime-event-utils.js`);
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

  const shellEvent = {
    event_kind: "tool.completed",
    payload_summary: {
      tool_name: "shell__input",
      summary: JSON.stringify({
        command: "node",
        args: ["-e", "process.stdin.resume()"],
        command_id: "shell__start:349e4099529e0ffec0ebaac956284beace202a4cc1a887bdd49bbcd2fda65cd9",
        output_tail: "<ell__start:349e4099529e0ffec0ebaac956284beace202a4cc1a887bdd49bbcd2fda65cd9-1\nHELPER: ready\nioi_rc=0",
      }),
    },
  };
  assert.equal(studioRuntimeEventToolName(shellEvent), "shell__input");
  assert.equal(studioRuntimeToolEventDetail(shellEvent, "shell__input"), "node -e <inline script>");
  assert.equal(studioRuntimeToolEventExcerpt(shellEvent), "HELPER: ready");
  assert.doesNotMatch(studioRuntimeToolEventExcerpt(shellEvent), /shell__start:|ioi_rc=|command_id/);

  const foregroundChunkEvent = {
    event_kind: "tool.output",
    payload: {
      tool_name: "shell__run",
      stream: "stdout",
      chunk: "compile-once complete\n",
      seq: 1,
      is_final: false,
    },
  };
  assert.equal(studioRuntimeEventToolName(foregroundChunkEvent), "shell__run");
  assert.equal(studioRuntimeToolEventExcerpt(foregroundChunkEvent), "compile-once complete");
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
