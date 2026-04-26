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
  /items\.length > 0 \|\| process\.status === "running"/,
  "empty process categories should be omitted unless the run is active, blocked, or failed",
);

assert.doesNotMatch(
  chatPanelsSource,
  /Tool transcript and observations attach when used|Policy and approval posture projected|spot-chat-status-workbench-row|spot-chat-status-timeline|spot-chat-status-skill-shell|Skill guidance/,
  "pending status cards should omit placeholder policy/tool/workbench/skill panels in the default chat lane",
);

assert.match(
  chatPanelsSource,
  /spot-agent-progress-row[\s\S]*spot-agent-progress-rail[\s\S]*spot-agent-progress-preview/,
  "pending status should render as a sparse thinking/tool transcript rail",
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
  /spot-source-chip__icon--fallback/,
  "source chip rows should provide an icon fallback when favicon metadata is absent",
);

console.log("assistantTurnUx.guard.test.ts: ok");
