import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(
  new URL("./index.tsx", import.meta.url),
  "utf8",
);

assert.match(
  source,
  /function isLikelyContextDependentSeedIntent\(intent: string\)/,
  "chat shell should classify seed prompts that depend on prior context",
);

assert.match(
  source,
  /function sessionLikelyAwaitingFollowUp\(session: SessionSummary\)/,
  "chat shell should identify retained sessions that are still waiting on follow-up context",
);

assert.match(
  source,
  /function looksLikeEllipticalFollowUpReply\(intent: string\)/,
  "chat shell should detect short clarification-style follow-up replies",
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
  /SEED_INTENT_PROJECTION_WAIT_LIMIT[\s\S]*chat_seed_intent_projection_bind_failed[\s\S]*fallback: "fresh_chat_submission"/,
  "seed intent bootstrap should fail bounded retained-projection waits into a fresh chat submission instead of hanging indefinitely",
);

assert.match(
  source,
  /\^in\\s\+chat\\s\+only\\b[\s\S]*return false;/,
  "explicit chat-only seeded prompts should not be classified as terse retained-session follow-ups",
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
