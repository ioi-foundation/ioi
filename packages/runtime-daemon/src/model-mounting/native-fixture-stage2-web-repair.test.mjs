import assert from "node:assert/strict";
import test from "node:test";

import { nativeFixtureStage2WebRepairResponse } from "./native-fixture-stage2-web-repair.mjs";

const QUERY = "Who is the current Secretary-General of the UN? Use current web evidence and cite the source.";
const URL = "https://ask.un.org/faq/14625";

function parseToolCall(response) {
  assert.equal(typeof response, "string");
  return JSON.parse(response);
}

function withProofEnv(fn) {
  const previousEnabled = process.env.IOI_STAGE2_WEB_REPAIR_PROOF;
  const previousUrl = process.env.IOI_STAGE2_WEB_REPAIR_URL;
  process.env.IOI_STAGE2_WEB_REPAIR_PROOF = "1";
  process.env.IOI_STAGE2_WEB_REPAIR_URL = URL;
  try {
    return fn();
  } finally {
    if (previousEnabled === undefined) {
      delete process.env.IOI_STAGE2_WEB_REPAIR_PROOF;
    } else {
      process.env.IOI_STAGE2_WEB_REPAIR_PROOF = previousEnabled;
    }
    if (previousUrl === undefined) {
      delete process.env.IOI_STAGE2_WEB_REPAIR_URL;
    } else {
      process.env.IOI_STAGE2_WEB_REPAIR_URL = previousUrl;
    }
  }
}

function responseFor(inputText, calledTools = []) {
  return nativeFixtureStage2WebRepairResponse({
    queryText: QUERY,
    promptContextText: QUERY,
    inputText,
    expectsJsonToolCall: true,
    hasToolCalled: (toolName) => calledTools.includes(toolName),
  });
}

test("stage2 web repair fixture is disabled unless proof env is enabled", () => {
  const previousEnabled = process.env.IOI_STAGE2_WEB_REPAIR_PROOF;
  delete process.env.IOI_STAGE2_WEB_REPAIR_PROOF;
  try {
    assert.equal(responseFor(QUERY), null);
  } finally {
    if (previousEnabled !== undefined) {
      process.env.IOI_STAGE2_WEB_REPAIR_PROOF = previousEnabled;
    }
  }
});

test("stage2 web repair fixture walks search, read, rejection, and repaired chat reply", () => withProofEnv(() => {
  const directBeforeEvidence = nativeFixtureStage2WebRepairResponse({
    queryText: QUERY,
    promptContextText: QUERY,
    inputText: QUERY,
    expectsJsonToolCall: false,
  });
  assert.match(directBeforeEvidence, /Fresh retrieval is required/);

  const search = parseToolCall(responseFor(QUERY));
  assert.equal(search.name, "web__search");
  assert.match(search.arguments.query, /Secretary-General/);

  const read = parseToolCall(responseFor(`${QUERY}\nTool Output (web__search): ${URL}`, ["web__search"]));
  assert.equal(read.name, "web__read");
  assert.equal(read.arguments.url, URL);

  const weakReply = parseToolCall(responseFor(`${QUERY}\nTool Output (web__read): Antonio Guterres is current.`, ["web__search", "web__read"]));
  assert.equal(weakReply.name, "chat__reply");
  assert.doesNotMatch(weakReply.arguments.message, /Antonio Guterres/);
  assert.doesNotMatch(weakReply.arguments.message, /https?:\/\//);

  const weakDirectReply = nativeFixtureStage2WebRepairResponse({
    queryText: QUERY,
    promptContextText: QUERY,
    inputText: `${QUERY}\nPENDING WEB TOOL EVIDENCE:\nURL: ${URL}`,
    expectsJsonToolCall: false,
  });
  assert.match(weakDirectReply, /Antonio Guterres/);
  assert.doesNotMatch(weakDirectReply, /https?:\/\//);

  const repairedReply = parseToolCall(responseFor(
    [
      QUERY,
      "assistant: {\"name\":\"chat__reply\",\"arguments\":{\"message\":\"I found a current web source.\"}}",
      "tool.failed chat__reply ERROR_CLASS=NoEffectAfterAction Final web answer is not ready. Validator feedback: cite read-backed sources.",
    ].join("\n"),
    ["web__search", "web__read", "chat__reply"],
  ));
  assert.equal(repairedReply.name, "chat__reply");
  assert.match(repairedReply.arguments.message, /Antonio Guterres/);
  assert.match(repairedReply.arguments.message, /United Nations/);
  assert.match(repairedReply.arguments.message, new RegExp(URL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(repairedReply.arguments.message, /Validator feedback|ERROR_CLASS/);

  const done = parseToolCall(responseFor(
    `${QUERY}\nchat_reply_model_authored_web_pipeline_answer_accepted terminal_chat_reply_ready=true`,
    ["chat__reply"],
  ));
  assert.equal(done.name, "agent__complete");
}));
