import assert from "node:assert/strict";
import test from "node:test";

import {
  nativeFixtureConversationReply,
  nativeFixtureQueryNeedsCommand,
  nativeFixtureQueryNeedsWeb,
  nativeFixtureQueryTargetsWorkspace,
  nativeFixtureQueryWorkspaceConstrained,
} from "./native-fixture-intent.mjs";

test("native fixture classifies autopilot plan progress as workspace-constrained", () => {
  const prompt = "Review autopilot plan progress now that Stage75 is documented; what remains?";

  assert.equal(nativeFixtureQueryTargetsWorkspace(prompt), true);
  assert.equal(nativeFixtureQueryNeedsWeb(prompt), false);
  assert.equal(nativeFixtureQueryWorkspaceConstrained(prompt), true);
});

test("native fixture keeps current market prompts on the web path", () => {
  const prompt = "Which is a better investment, Akash or Filecoin?";

  assert.equal(nativeFixtureQueryNeedsWeb(prompt), true);
  assert.equal(nativeFixtureQueryWorkspaceConstrained(prompt), false);
});

test("native fixture detects command-directed prompts", () => {
  assert.equal(
    nativeFixtureQueryNeedsCommand(
      "Run `node --check scripts/lib/autopilot-agent-studio-chat-scenarios.mjs` and summarize the exit code.",
    ),
    true,
  );
});

test("native fixture keeps simple conversational replies direct", () => {
  assert.match(nativeFixtureConversationReply("hiya bot") ?? "", /Hiya/);
  assert.equal(nativeFixtureConversationReply("Review autopilot plan progress now"), null);
});
