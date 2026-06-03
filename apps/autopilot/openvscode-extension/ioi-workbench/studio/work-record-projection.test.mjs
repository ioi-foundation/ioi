import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const {
  createStudioWorkRecordProjection,
  studioPublicOutputBlock,
} = require("./work-record-projection.js");

function createProjection(workspacePath = "/home/user/project") {
  return createStudioWorkRecordProjection({
    compactStudioWhitespace: (value = "") => String(value || "").replace(/\s+/g, " ").trim(),
    firstArray: (value) => (Array.isArray(value) ? value : []),
    workspacePath: () => workspacePath,
    studioPendingWorkLabelForTool: (toolName = "", detail = "", status = "") => {
      if (toolName === "shell__run") return /running/.test(status) ? "Running command" : "Ran command";
      if (toolName === "web__read") return detail ? `Read ${detail}` : "Read source";
      return "Used tool";
    },
    studioSourceRefFromRecord: (record = {}) => record?.url ? {
      title: record.title || record.url,
      url: record.url,
      domain: record.domain || "",
      excerpt: record.excerpt || "",
      state: record.state || "used",
    } : null,
  });
}

test("work record projection redacts command output and normalizes command labels", () => {
  const projection = createProjection();
  const command = projection.studioPublicCommandOutputForWebview({
    id: "shell__start:abcdef1234567890",
    toolId: "shell__run",
    label: "shell__run",
    command: "node -e <inline script>",
    status: "completed",
    stdout: "ok receipt_abc1234567890 /tmp/private/out.txt /home/user/project/src/app.js",
    stderr: "",
  });

  assert.equal(command.label, "Ran Node.js command");
  assert.equal(command.stdout, "ok <ref> <tmp> <path>");
  assert.doesNotMatch(command.stdout, /receipt_|\/tmp\/|\/home\//);
});

test("work record projection keeps workspace-relative hunks and bounds private paths", () => {
  const projection = createProjection("/home/user/project");

  const local = projection.studioPublicDiffHunkForWebview({
    file: "/home/user/project/src/app.js",
    before: "return old;",
    after: "return next;",
    changeId: "change_123",
  });
  const external = projection.studioPublicDiffHunkForWebview({
    file: "/tmp/private/file.js",
  });

  assert.equal(local.file, "src/app.js");
  assert.equal(local.before, "return old;");
  assert.equal(local.after, "return next;");
  assert.equal(external.file, "file.js");
});

test("work record projection removes generic command work rows when command output is richer", () => {
  const projection = createProjection();
  const record = projection.studioPublicWorkRecordForWebview({
    status: "completed",
    lines: ["Ran command"],
    workRows: [
      {
        id: "row-1",
        kind: "shell__run",
        headline: "Ran command",
        excerptPreview: "",
      },
      {
        id: "row-2",
        kind: "web__read",
        headline: "Read example.test",
        sourceChips: [{ title: "Example", url: "https://example.test" }],
      },
    ],
    commandOutputs: [
      {
        id: "cmd-1",
        toolId: "shell__run",
        label: "shell__run",
        command: "npm test",
        stdout: "tests passed",
      },
    ],
    diffHunks: [
      {
        file: "/home/user/project/src/app.js",
        before: "a",
        after: "b",
      },
    ],
    sessionCards: [
      {
        id: "session-1",
        kind: "sandbox_browser",
        waitingForUser: true,
      },
    ],
  });

  assert.equal(record.status, "completed");
  assert.deepEqual(record.workRows.map((row) => row.headline), ["Read example.test"]);
  assert.equal(record.commandOutputs[0].label, "Ran npm command");
  assert.equal(record.commandOutputs[0].stdout, "tests passed");
  assert.equal(record.diffHunks[0].file, "src/app.js");
  assert.equal(record.sessionCards[0].waitingForUser, true);
});

test("public output block redacts trace plumbing consistently", () => {
  const text = studioPublicOutputBlock(
    'shell__start:abcdef1234567890 "command_id":"secret" trace_abc123456789 /tmp/run /home/user/file',
  );

  assert.equal(text, '<command>  <ref> <tmp> <path>');
});
