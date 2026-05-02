import assert from "node:assert/strict";
import fs from "node:fs";

const answerCardSource = fs.readFileSync(
  new URL("./AnswerCard.tsx", import.meta.url),
  "utf8",
);
const timelineSource = fs.readFileSync(
  new URL("./ConversationTimeline.tsx", import.meta.url),
  "utf8",
);
const chatPanelsSource = fs.readFileSync(
  new URL("./ChatConversationPanels.tsx", import.meta.url),
  "utf8",
);
const chatApprovalCardSource = fs.readFileSync(
  new URL("./ChatApprovalCard.tsx", import.meta.url),
  "utf8",
);
const artifactHubTaskViewsSource = fs.readFileSync(
  new URL("./ArtifactHubTaskViews.tsx", import.meta.url),
  "utf8",
);
const sourcePillSource = fs.readFileSync(
  new URL("./SourcePill.tsx", import.meta.url),
  "utf8",
);
const sourceChipRowSource = fs.readFileSync(
  new URL("./SourceChipRow.tsx", import.meta.url),
  "utf8",
);
const modelSource = fs.readFileSync(
  new URL("../utils/assistantTurnProcessModel.ts", import.meta.url),
  "utf8",
);
const surfaceStateSource = fs.readFileSync(
  new URL("../hooks/useChatSurfaceState.ts", import.meta.url),
  "utf8",
);
const contentPipelineSummariesSource = fs.readFileSync(
  new URL("../viewmodels/contentPipeline.summaries.ts", import.meta.url),
  "utf8",
);
const runtimeStatusCopySource = fs.readFileSync(
  new URL("../viewmodels/runtimeStatusCopy.ts", import.meta.url),
  "utf8",
);
const artifactPanelCss = fs.readFileSync(
  new URL("../styles/ArtifactPanel.css", import.meta.url),
  "utf8",
);
const thoughtsViewSource = fs.readFileSync(
  new URL("./views/ThoughtsView.tsx", import.meta.url),
  "utf8",
);

assert.equal(
  fs.existsSync(new URL("./RuntimeFactsStrip.tsx", import.meta.url)),
  false,
  "the old RuntimeFactsStrip dashboard UI should not remain in the chat surface",
);

assert.equal(
  fs.existsSync(new URL("./RunStatusLine.tsx", import.meta.url)),
  false,
  "route/model/projection badge strips should not remain in the default chat transcript",
);

assert.equal(
  fs.existsSync(new URL("./ExecutionRouteCard.tsx", import.meta.url)),
  false,
  "the old route-dashboard card should not remain in chat/workbench UX",
);

assert.doesNotMatch(
  answerCardSource,
  /runtimeFacts/i,
  "default answer card must not accept or render a full Runtime Facts dashboard",
);

assert.doesNotMatch(
  answerCardSource,
  /answer-card-eyebrow|answer-card-title|<h3[^>]*>\s*Autopilot\s*<\/h3>/,
  "default final answers should not render a dashboard-style Results/Autopilot header",
);

assert.doesNotMatch(
  answerCardSource,
  /Export Trace|Open thoughts and evidence|onExportTraceBundle/,
  "default answer card must not expose trace export or thoughts controls",
);

assert.match(
  answerCardSource,
  /answer-card--plain/,
  "default final answers should render as inline transcript content, not a bordered dashboard panel",
);

assert.doesNotMatch(
  chatPanelsSource,
  /runtimeFacts/i,
  "pending chat status must not carry a hidden Runtime Facts dashboard prop",
);

assert.doesNotMatch(
  timelineSource,
  /RuntimeFactsStrip/,
  "default conversation timeline must not embed the full RuntimeFactsStrip",
);

assert.match(
  timelineSource,
  /<AssistantTurn[\s\S]*<AnswerCard/,
  "final answers should be wrapped by the sparse assistant turn transcript",
);

assert.doesNotMatch(
  timelineSource,
  /onOpenCapabilities=|RunStatusLine|compactBadges|ExecutionRouteCard/,
  "default chat transcript should not carry dashboard badge or route-card wiring",
);

assert.doesNotMatch(
  timelineSource,
  /Conversation Single Pass|Planner of record|Active Worker|GENERAL ROUTE/,
  "default chat transcript should not contain old dashboard route-card copy",
);

assert.match(
  timelineSource,
  /extractUserRequestFromContextualIntent\(turn\.prompt\.text\)/,
  "default user prompt bubbles should display the user request, not injected runtime context",
);

assert.match(
  timelineSource,
  /const showLiveActivityTurn =\s*showInlineStatusCard \|\| showInlineTranscript \|\| showAssistantPendingBubble;/,
  "active chat turns should converge on one assistant activity disclosure boundary",
);

assert.match(
  timelineSource,
  /showLiveActivityTurn \? assistantTurnShell\(liveActivityChildren\) : null/,
  "live status cards, terminal streams, and pending progress should render inside the unified assistant turn shell",
);

assert.doesNotMatch(
  timelineSource,
  /spot-message--pending|<ToolActivityGroup|ReasoningDisclosure/,
  "the chat timeline should not render separate pending, tool, or reasoning surfaces beside the assistant turn activity disclosure",
);

assert.doesNotMatch(
  timelineSource,
  /Worklog|steps captured|Open thinking artifacts/,
  "default conversation timeline must not surface retained worklog or trace controls",
);

assert.doesNotMatch(
  timelineSource,
  /Runtime timeline|required obligations|cleared obligations/,
  "default conversation timeline must not expose runtime ledger or completion-gate wording",
);

assert.doesNotMatch(
  artifactHubTaskViewsSource,
  /ExecutionRouteCard|Conversation Single Pass|Planner of record|Active Worker|GENERAL ROUTE/,
  "runtime drawer plan views should use transcript-style notes instead of the old route dashboard",
);

const chatShellSource = fs.readFileSync(
  new URL("../index.tsx", import.meta.url),
  "utf8",
);

assert.match(
  chatShellSource,
  /autoOpen:\s*Boolean\(activeArtifactChatSessionId\)\s*\|\|\s*studioArtifactExpected/,
  "direct chat should not auto-open the runtime workbench unless an artifact route expects it",
);

assert.doesNotMatch(
  chatShellSource,
  /const chatArtifactDrawerAvailable =[\s\S]*studioAvailableArtifacts\.length > 0;/,
  "historical artifacts must not make the drawer available for unrelated direct-chat runs",
);

assert.match(
  modelSource,
  /process\.status === "running"[\s\S]*process\.status === "thinking"[\s\S]*process\.status === "blocked"[\s\S]*process\.status === "failed"[\s\S]*"source_read"/,
  "completed process evidence should stay out of the default answer UI except collapsed local explored-file provenance",
);

assert.doesNotMatch(
  chatPanelsSource,
  /Tool transcript and observations attach when used|Policy and approval posture projected|spot-chat-status-workbench-row|spot-chat-status-timeline|spot-chat-status-skill-shell|Skill guidance|Active worker|Runtime stage/,
  "pending status cards should omit placeholder policy/tool/workbench/skill panels in the default chat lane",
);

assert.doesNotMatch(
  chatApprovalCardSource,
  /executionTranscript|gate-terminal/,
  "approval cards should stay decision-only; install terminal streaming belongs in the separate runtime status panel",
);

assert.match(
  surfaceStateSource,
  /hasOperatorDecisionPrompt && installTranscript[\s\S]*metrics:\s*null[\s\S]*processes:\s*\[\][\s\S]*livePreview: installPreview/,
  "install workflows should keep a separate terminal/status stream visible while an approval card is present without synthetic work-graph rows",
);

assert.doesNotMatch(
  contentPipelineSummariesSource,
  /active in the selected route|is working in \$\{selectedRoute\.toLowerCase\(\)\}/,
  "route progress copy should name the concrete route instead of framing it as an agent/worker placeholder",
);

assert.doesNotMatch(
  surfaceStateSource,
  /activeRole:\s*"Install workflow"|summary:\s*"Resolver, approval, command output, and verification/,
  "install status rows should use route-derived labels and receipt-backed summaries instead of generic workflow placeholders",
);

assert.match(
  surfaceStateSource,
  /metrics:\s*chrome\.metrics\?\.verification[\s\S]*processes:\s*\[\]/,
  "install terminal previews should not add synthetic progress rows on top of receipt-backed command output",
);

assert.match(
  surfaceStateSource,
  /if \(installTranscript\) \{[\s\S]*const installFailed =[\s\S]*detail: installBlockedDetail\(installTranscript\)[\s\S]*livePreview: installPreview/,
  "failed install workflows should keep install-blocker copy and terminal receipts instead of artifact failure fallback copy",
);

assert.match(
  chatPanelsSource,
  /livePreview\?\.kind === "command_stream" && livePreview\.status === "failed"[\s\S]*label: commandStreamFailed \? "Install blocked" : "Needs repair"/,
  "failed install terminal previews should label the terminal-backed blocker directly instead of asking for generic repair",
);

assert.doesNotMatch(
  runtimeStatusCopySource,
  /install\|set up\|setup|task\?\.intent[\s\S]*Software install workflow/,
  "runtime status copy must not classify install workflows by sniffing the prompt text",
);

assert.match(
  chatPanelsSource,
  /is-terminal-only[\s\S]*spot-agent-progress-previews[\s\S]*renderPreview\(livePreview\)/,
  "terminal-backed runtime status should render as terminal output without a second synthetic progress rail",
);

assert.doesNotMatch(
  surfaceStateSource,
  /Thinking through|Thinking through the artifact request|outcomeLabel \|\| "Thinking"/,
  "chat status copy should use the unified working/activity vocabulary rather than a separate thinking lane",
);

assert.match(
  sourcePillSource,
  /source\.faviconUrl/,
  "source pills should render provided favicon metadata",
);

assert.doesNotMatch(
  sourcePillSource,
  /google\.com\/s2|favicon\.ico/,
  "source pills must not fetch arbitrary favicons during render",
);

assert.doesNotMatch(
  sourceChipRowSource,
  /google\.com\/s2|favicon\.ico/,
  "legacy source chip rows must also avoid arbitrary favicon fetching during render",
);

assert.match(
  sourceChipRowSource,
  /aria-label="Search sources"[\s\S]*spot-source-chip__icon--fallback/,
  "source chip rows should be search-scoped and provide an icon fallback when favicon metadata is absent",
);

assert.doesNotMatch(
  artifactPanelCss,
  /thoughts-items-linked::before/,
  "thoughts surfaces should not render raw timeline rails for process evidence",
);

assert.match(
  thoughtsViewSource,
  /thoughts-items-compact/,
  "artifact thoughts should present research as compact grouped rows",
);

assert.match(
  thoughtsViewSource,
  /Searched web[\s\S]*Browsed source/,
  "artifact thoughts should label search and browse rows without exposing a raw event feed",
);

console.log("assistantTurnUx.guard.test.ts: ok");
