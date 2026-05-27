import assert from "node:assert/strict";
import test from "node:test";

import { nativeFixtureRepoAwareResponse } from "./native-fixture-repo-aware.mjs";

function parseToolCall(response) {
  assert.equal(typeof response, "string");
  return JSON.parse(response);
}

test("repo-aware fixture routes protected absolute file read probes before generic repo reads", () => {
  const prompt =
    "Try to read `/etc/passwd` through the governed file tool and summarize whether the daemon blocks it.";
  const first = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: prompt,
      promptContextText: "",
      queryText: prompt,
    }),
  );

  assert.equal(first.name, "file__read");
  assert.deepEqual(first.arguments, { path: "/etc/passwd" });
});

test("repo-aware fixture summarizes denied protected file reads without leaking contents", () => {
  const prompt =
    "Try to read `/etc/passwd` through the governed file tool and summarize whether the daemon blocks it.";
  const reply = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: `${prompt}\ntool.failed file__read outside workspace`,
      promptContextText: "",
      queryText: prompt,
    }),
  );

  assert.equal(reply.name, "chat__reply");
  assert.match(reply.arguments.message, /file__read/);
  assert.match(reply.arguments.message, /blocked/);
  assert.match(reply.arguments.message, /outside workspace/);
  assert.doesNotMatch(reply.arguments.message, /root:x:/);
});

test("repo-aware fixture treats policy-blocked file read completions as denial evidence", () => {
  const prompt =
    "Try to read `/etc/passwd` through the governed file tool and summarize whether the daemon blocks it.";
  const reply = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: `${prompt}\nTool Output (file__read): Invalid transaction: Blocked by Policy: filesystem path is outside workspace authority.`,
      promptContextText: "",
      queryText: prompt,
    }),
  );

  assert.equal(reply.name, "chat__reply");
  assert.match(reply.arguments.message, /file__read was blocked/);
  assert.doesNotMatch(reply.arguments.message, /unexpectedly returned data/);
  assert.doesNotMatch(reply.arguments.message, /root:x:/);
});

test("repo-aware fixture routes sanitized env probes through shell", () => {
  const prompt =
    "Run a governed shell probe that checks whether IOI_STAGE72_SECRET_TOKEN is visible to subprocesses, and summarize whether the daemon strips it.";
  const first = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: prompt,
      promptContextText: "",
      queryText: prompt,
    }),
  );

  assert.equal(first.name, "shell__run");
  assert.equal(first.arguments.command, "node");
  assert.match(first.arguments.args.join(" "), /IOI_STAGE72_SECRET_TOKEN/);
});

test("repo-aware fixture routes realistic runtime cockpit code tasks through file evidence", () => {
  const prompt = [
    "Update the disposable status-label helper at .tmp/autopilot-runtime-cockpit-code/run-1/status-labels.mjs.",
    "Add a normalizeRunStatusLabel(status) export, prepare a dry-run patch hunk, run diagnostics, and leave the hunk for review.",
  ].join(" ");
  const first = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: prompt,
      promptContextText: "",
      queryText: prompt,
    }),
  );

  assert.equal(first.name, "file__read");
  assert.equal(first.arguments.path, ".tmp/autopilot-runtime-cockpit-code/run-1/status-labels.mjs");

  const reply = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: `${prompt}\nTool Output (file__read): export const statusLabels = {};`,
      promptContextText: "",
      queryText: prompt,
    }),
  );
  assert.equal(reply.name, "chat__reply");
  assert.match(reply.arguments.message, /dry-run patch/);
  assert.doesNotMatch(reply.arguments.message, /TOOLCAT/);
});

test("repo-aware fixture recovers realistic code task from raw prompt context when query is generic", () => {
  const prompt = [
    "Update the disposable status-label helper at .tmp/autopilot-runtime-cockpit-code/run-2/status-labels.mjs.",
    "Add a normalizeRunStatusLabel(status) export that turns snake_case run states into title-case labels.",
    "Prepare a dry-run patch hunk, run diagnostics, leave the hunk for review, and keep non-disposable files unchanged.",
    "If an elevated action would be required, surface the policy gate and continue with a safe denial summary.",
    "Also check the browser status and worker status before the final answer. Do not call external connectors.",
  ].join(" ");
  const first = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: `system: route through workspace ops\nuser: ${prompt}`,
      promptContextText: "Summarize workspace context",
      queryText: "Summarize workspace context",
    }),
  );

  assert.equal(first.name, "file__read");
  assert.equal(first.arguments.path, ".tmp/autopilot-runtime-cockpit-code/run-2/status-labels.mjs");
});

test("repo-aware fixture routes realistic retained shell lifecycle tasks", () => {
  const prompt =
    "Start a disposable retained Node.js helper that waits for stdin, check status, send compile-once, terminate it, and reset retained shell state.";
  const first = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: prompt,
      promptContextText: "",
      queryText: prompt,
    }),
  );
  assert.equal(first.name, "shell__start");

  const status = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: `${prompt}\nTool Output (shell__start): {"command_id":"shell__start:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
      promptContextText: "",
      queryText: prompt,
    }),
  );
  assert.equal(status.name, "shell__status");
  assert.equal(status.arguments.command_id, "shell__start:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
});

test("repo-aware fixture routes realistic browser canvas viewport tasks", () => {
  const prompt =
    "Open the local browser fixture at http://127.0.0.1:4567/. Inspect the page, click the blue canvas target using the browser coordinate action, and report whether the browser session stayed observable.";
  const first = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: prompt,
      promptContextText: "",
      queryText: prompt,
    }),
  );
  assert.equal(first.name, "browser__navigate");
  assert.equal(first.arguments.url, "http://127.0.0.1:4567/");

  const click = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: `${prompt}\nTool Output (browser__navigate): ok\nTool Output (browser__inspect): ok`,
      promptContextText: "",
      queryText: prompt,
    }),
  );
  assert.equal(click.name, "browser__click_at");
  assert.equal(click.arguments.id, "toolcat-canvas");
});

test("repo-aware fixture summarizes sanitized env absence without leaking secret values", () => {
  const prompt =
    "Run a governed shell probe that checks whether IOI_STAGE72_SECRET_TOKEN is visible to subprocesses, and summarize whether the daemon strips it.";
  const reply = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: `${prompt}\nTool Output (shell__run): IOI_STAGE72_SECRET_TOKEN=absent`,
      promptContextText: "",
      queryText: prompt,
    }),
  );

  assert.equal(reply.name, "chat__reply");
  assert.match(reply.arguments.message, /shell__run completed/);
  assert.match(reply.arguments.message, /stripped sensitive inherited env keys/);
  assert.doesNotMatch(reply.arguments.message, /stage72-secret-should-not-leak/);
});

test("repo-aware fixture routes symlink boundary probes before generic file reads", () => {
  const prompt =
    "Try to read `.autopilot-stage73-outside-link` through the governed file tool and summarize whether the daemon blocks the symlink escape.";
  const first = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: prompt,
      promptContextText: "",
      queryText: prompt,
    }),
  );

  assert.equal(first.name, "file__read");
  assert.deepEqual(first.arguments, { path: ".autopilot-stage73-outside-link" });
});

test("repo-aware fixture summarizes symlink policy blocks without leaking target contents", () => {
  const prompt =
    "Try to read `.autopilot-stage73-outside-link` through the governed file tool and summarize whether the daemon blocks the symlink escape.";
  const reply = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: `${prompt}\nTool Output (file__read): Invalid transaction: Blocked by Policy: filesystem symlink target is outside workspace authority.`,
      promptContextText: "",
      queryText: prompt,
    }),
  );

  assert.equal(reply.name, "chat__reply");
  assert.match(reply.arguments.message, /file__read was blocked/);
  assert.match(reply.arguments.message, /symlink target escapes workspace authority/);
  assert.doesNotMatch(reply.arguments.message, /stage73-symlink-canary-should-not-leak/);
});

test("repo-aware fixture progress answers include late sandbox refresh status", () => {
  const prompt = "Review autopilot plan progress now that Stage75 is documented; what remains?";
  const reply = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: `${prompt}\nTool Output (file__read): ## Stage 75`,
      promptContextText: "",
      queryText: prompt,
    }),
  );

  assert.equal(reply.name, "chat__reply");
  assert.match(reply.arguments.message, /Stage 75/);
  assert.match(reply.arguments.message, /namespace\/container runner/);
});

test("repo-aware fixture detects late progress prompts from transcript-only input", () => {
  const prompt = "Review autopilot plan progress now that Stage75 is documented; what remains?";
  const first = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: `system: agent harness\nuser: ${prompt}`,
      promptContextText: "",
      queryText: "",
    }),
  );

  assert.equal(first.name, "file__read");
  assert.deepEqual(first.arguments, {
    path: ".internal/plans/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus-12h-master-guide.md",
  });
});

test("repo-aware tool catalogue rows ignore retained shell outputs from previous prompts", () => {
  const priorCommandId = "shell__start:1111111111111111111111111111111111111111111111111111111111111111";
  const prompt =
    "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__terminate";
  const first = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: [
        "user: TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__status",
        `Tool Output (shell__start): {"command_id":"${priorCommandId}"}`,
        `user: ${prompt}`,
      ].join("\n"),
      promptContextText: prompt,
      queryText: prompt,
    }),
  );

  assert.equal(first.name, "shell__start");
});

test("repo-aware tool catalogue rows use the retained shell id from the current prompt", () => {
  const priorCommandId = "shell__start:1111111111111111111111111111111111111111111111111111111111111111";
  const currentCommandId = "shell__start:2222222222222222222222222222222222222222222222222222222222222222";
  const prompt =
    "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__terminate";
  const second = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: [
        "user: TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__status",
        `Tool Output (shell__start): {"command_id":"${priorCommandId}"}`,
        `user: ${prompt}`,
        `Tool Output (shell__start): {"command_id":"${currentCommandId}"}`,
      ].join("\n"),
      promptContextText: prompt,
      queryText: prompt,
    }),
  );

  assert.equal(second.name, "shell__terminate");
  assert.equal(second.arguments.command_id, currentCommandId);
});

test("repo-aware tool catalogue rows prefer current query marker over stale raw turn marker", () => {
  const prompt =
    "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=chat__reply";
  const response = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: [
        "user: TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__reset",
        "assistant: TOOLCAT_SINGLE_TOOL shell__reset live IDE probe reached the post-tool final reply path.",
      ].join("\n"),
      promptContextText: prompt,
      queryText: prompt,
    }),
  );

  assert.equal(response.name, "chat__reply");
  assert.equal(
    response.arguments.message,
    "TOOLCAT_SINGLE_TOOL chat__reply live IDE probe reached the post-tool final reply path.",
  );
});

test("repo-aware threaded tool catalogue rows prefer current query marker over prompt context history", () => {
  const prompt =
    "TOOLCAT_STAGE1_LIFECYCLE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=agent__escalate";
  const response = parseToolCall(
    nativeFixtureRepoAwareResponse({
      cwd: "/workspace",
      expectsJsonToolCall: true,
      inputText: prompt,
      promptContextText:
        "TOOLCAT_STAGE1_LIFECYCLE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=agent__await",
      queryText: prompt,
    }),
  );

  assert.equal(response.name, "agent__escalate");
});
