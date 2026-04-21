import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(
  new URL("./index.tsx", import.meta.url),
  "utf8",
);

assert.match(
  source,
  /function isLikelyContextDependentSeedIntent\(intent: string\)/,
  "spotlight should classify seed prompts that depend on prior context",
);

assert.match(
  source,
  /function sessionLikelyAwaitingFollowUp\(session: SessionSummary\)/,
  "spotlight should identify retained sessions that are still waiting on follow-up context",
);

assert.match(
  source,
  /function looksLikeEllipticalFollowUpReply\(intent: string\)/,
  "spotlight should detect short clarification-style follow-up replies",
);

assert.match(
  source,
  /const requiresRetainedContext =[\s\S]*isLikelyContextDependentSeedIntent\(nextIntent\)/,
  "chat seed intent bootstrap should explicitly detect follow-up prompts before auto-submitting",
);

assert.match(
  source,
  /hasPendingFollowUpSession[\s\S]*looksEllipticalReply[\s\S]*shouldWaitForRetainedProjection/,
  "chat seed intent bootstrap should use pending gated sessions to classify terse follow-up replies",
);

assert.match(
  source,
  /chat_seed_intent_waiting_for_session_projection/,
  "seed intent bootstrap should wait for retained session projection when a follow-up prompt needs prior context",
);

assert.match(
  source,
  /Promise\.allSettled\(\[\s*refreshSessionHistory\(\),\s*refreshCurrentTask\(\),\s*\]\)/,
  "seed intent bootstrap should actively refresh retained session projection instead of waiting forever on empty session state",
);

assert.match(
  source,
  /handleLoadSession\(continuationSession\.session_id\)[\s\S]*return;/,
  "chat seed intent bootstrap should attach the retained session before submitting the follow-up prompt",
);

assert.match(
  source,
  /preferredClarificationOptionId\(task\)[\s\S]*handleSubmitClarification\(\s*clarificationOptionId,\s*nextIntent,\s*\)/,
  "chat seed intent bootstrap should route retained clarification follow-ups through the clarification submit path",
);

console.log("index.seedIntent.test.ts: ok");
