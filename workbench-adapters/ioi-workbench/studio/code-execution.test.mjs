import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioCodeExecution } = require("./code-execution.js");

function createCodeExecution() {
  return createStudioCodeExecution({
    commandPayloadAttr: (payload) => ` data-payload='${JSON.stringify(payload)}'`,
    escapeHtml: (value = "") => String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;"),
  });
}

test("code execution extracts executable fenced blocks and normalizes aliases", () => {
  const codeExecution = createCodeExecution();
  const blocks = codeExecution.studioExecutableCodeBlocksFromText([
    "```js",
    "console.log('ok')",
    "```",
    "```md",
    "# ignored",
    "```",
    "```TS",
    "const value: number = 1;",
    "```",
  ].join("\n"));

  assert.deepEqual(blocks, [
    { language: "javascript", source: "console.log('ok')" },
    { language: "typescript", source: "const value: number = 1;" },
  ]);
});

test("code execution policy blocks network and host-write shaped commands", () => {
  const codeExecution = createCodeExecution();

  assert.deepEqual(codeExecution.studioCodeExecutionPolicy("echo ok"), {
    status: "ready",
    blockReason: null,
    policyRefs: ["policy:code_execution.plan_only", "policy:code_execution.sandbox.network_deny"],
  });
  assert.equal(codeExecution.studioCodeExecutionPolicy("curl https://example.com").status, "blocked");
  assert.match(codeExecution.studioCodeExecutionPolicy("curl https://example.com").blockReason, /Network-shaped/);
  assert.equal(codeExecution.studioCodeExecutionPolicy("sudo rm -rf /").status, "blocked");
  assert.match(codeExecution.studioCodeExecutionPolicy("sudo rm -rf /").blockReason, /Host-write/);
});

test("code execution rows render plan-only payloads and disabled blocked actions", () => {
  const codeExecution = createCodeExecution();
  const html = codeExecution.studioChatCodeExecutionRows({
    content: [
      "```bash",
      "echo ok",
      "```",
      "```python",
      "import urllib.request",
      "urllib.request.urlopen('https://example.com')",
      "```",
    ].join("\n"),
  }, 3);

  assert.equal((html.match(/data-testid="studio-chat-code-execution-card"/g) || []).length, 2);
  assert.match(html, /data-language="bash"/);
  assert.match(html, /data-execution-status="ready"/);
  assert.match(html, /data-execution-status="blocked"/);
  assert.match(html, /data-testid="studio-chat-code-execute-plan"/);
  assert.match(html, /data-bridge-request="chat.executeCodeBlock.plan"/);
  assert.match(html, /echo ok/);
  assert.match(html, /disabled/);
  assert.match(html, /"turnIndex":3/);
  assert.match(html, /"applyMode":"plan_only"/);
  assert.match(html, /"network":"deny"/);
});

test("code execution rows stay empty without executable code fences", () => {
  const codeExecution = createCodeExecution();

  assert.equal(codeExecution.studioChatCodeExecutionRows({ content: "plain text" }), "");
  assert.equal(codeExecution.studioChatCodeExecutionRows({ content: "```md\n# note\n```" }), "");
});
