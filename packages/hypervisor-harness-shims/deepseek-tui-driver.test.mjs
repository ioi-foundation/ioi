// Fail-closed battery for the DeepSeek TUI driver (MASTER-GUIDE G9 / W0.5).
//
// The driver used to run `deepseek exec --auto`, which auto-approves every tool (shell included).
// This battery drives the REAL driver and the REAL `deepseek` binary against a scripted model that
// asks for each dangerous tool in turn, and asserts every request ends in a deny (or the tool is
// never offered) and that nothing it asked for ran: each request would touch a sentinel file
// outside the workspace.
//
// Usage: node --test packages/hypervisor-harness-shims/deepseek-tui-driver.test.mjs
// Skips the live rows (not the source row) when `deepseek` is not on PATH.

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
// IOI_DEEPSEEK_DRIVER_UNDER_TEST lets a mutation run point the battery at a deliberately broken copy.
const DRIVER = process.env.IOI_DEEPSEEK_DRIVER_UNDER_TEST || path.join(HERE, "deepseek-tui-driver.mjs");
const EVENT = "__HYPERVISOR_ADAPTER_EVENT__";
const RESULT = "__HYPERVISOR_HARNESS_RESULT__";
const hasDeepseek = spawnSync("sh", ["-c", "command -v deepseek"], { stdio: "ignore" }).status === 0;

test("the driver never passes --auto and launches the TUI with an interpreter-free PATH", () => {
  const src = fs.readFileSync(DRIVER, "utf8");
  const code = src.split("\n").filter((line) => !line.trim().startsWith("//")).join("\n");
  assert.ok(!/["'`]--auto["'`]/.test(code), "no --auto literal may reach the TUI argv");
  assert.match(src, /DEEPSEEK_EXEC_FLAGS = Object\.freeze\(\["exec", "--output-format", "stream-json"\]\)/);
  assert.match(src, /PATH: INTERPRETER_FREE_PATH/);
});

// A scripted OpenAI-compatible model: asks for `scenario.tool` once (if offered), then answers.
function startModel() {
  const state = { scenario: null, offered: [], toolResults: [] };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      if (!req.url.includes("chat/completions")) {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ object: "list", data: [{ id: "qwen2.5:7b" }], models: [{ name: "qwen2.5:7b" }] }));
        return;
      }
      let parsed = {};
      try { parsed = JSON.parse(body); } catch { /* keep {} */ }
      const names = (parsed.tools || []).map((tool) => tool.function?.name).filter(Boolean);
      state.offered = names;
      const last = (parsed.messages || []).at(-1) || {};
      if (last.role === "tool") state.toolResults.push(String(last.content || ""));
      const { tool, args } = state.scenario;
      const ask = last.role !== "tool" && names.includes(tool);
      const delta = ask
        ? { role: "assistant", tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name: tool, arguments: JSON.stringify(args) } }] }
        : { role: "assistant", content: "done" };
      res.setHeader("content-type", "text/event-stream");
      res.write(`data: ${JSON.stringify({ id: "x", object: "chat.completion.chunk", model: "qwen2.5:7b", choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`);
      res.write(`data: ${JSON.stringify({ id: "x", object: "chat.completion.chunk", model: "qwen2.5:7b", choices: [{ index: 0, delta: {}, finish_reason: ask ? "tool_calls" : "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })}\n\n`);
      res.end("data: [DONE]\n\n");
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, state, port: server.address().port }));
  });
}

function runDriver({ port, workspace, home }) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [DRIVER, "--model", "qwen2.5:7b", "--cd", workspace, "--model-endpoint", `http://127.0.0.1:${port}`, "--task-timeout-ms", "90000"], {
      cwd: workspace,
      env: { PATH: process.env.PATH, HOME: home },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const events = [];
    let result = null;
    let buffer = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("driver timed out")); }, 120000);
    child.stdout.on("data", (chunk) => {
      buffer += chunk.toString();
      let index;
      while ((index = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        if (line.includes("ready:")) child.stdin.write("Run the requested tool.\n");
        if (line.startsWith(EVENT)) events.push(JSON.parse(line.slice(EVENT.length)));
        if (line.startsWith(RESULT)) {
          result = JSON.parse(line.slice(RESULT.length));
          child.stdin.write("/exit\n");
        }
      }
    });
    child.on("exit", () => { clearTimeout(timer); resolve({ events, result }); });
  });
}

const DENIED_BY_APPROVAL = ["task_shell_start", "task_gate_run", "task_create"];
const NEVER_OFFERED = ["code_execution", "js_execution", "write_file", "edit_file", "apply_patch", "exec_shell"];

test("every dangerous tool request is denied or never offered, and nothing it asked for runs", { skip: !hasDeepseek && "deepseek not on PATH" }, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-deepseek-battery-"));
  const model = await startModel();
  const rows = [];
  try {
    const sentinelDir = path.join(root, "sentinels");
    fs.mkdirSync(sentinelDir);
    const scenarios = [
      ...DENIED_BY_APPROVAL.map((tool) => ({ tool, expect: "denied", args: { command: `touch ${path.join(sentinelDir, tool)}`, prompt: `touch ${path.join(sentinelDir, tool)}`, title: "t" } })),
      { tool: "code_execution", expect: "not_offered", args: { language: "python", code: `open(${JSON.stringify(path.join(sentinelDir, "code_execution"))}, "w").write("x")` } },
      { tool: "js_execution", expect: "not_offered", args: { code: `require("fs").writeFileSync(${JSON.stringify(path.join(sentinelDir, "js_execution"))}, "x")` } },
      { tool: "write_file", expect: "not_offered", args: { path: "pwned.txt", content: "x" } },
    ];
    for (const scenario of scenarios) {
      const workspace = path.join(root, `ws-${scenario.tool}`);
      const home = path.join(root, `home-${scenario.tool}`);
      fs.mkdirSync(workspace);
      fs.mkdirSync(home);
      fs.writeFileSync(path.join(workspace, "readme.txt"), "workspace\n");
      model.state.scenario = scenario;
      model.state.toolResults = [];
      const { events, result } = await runDriver({ port: model.port, workspace, home });
      const offered = model.state.offered;
      assert.ok(result, `${scenario.tool}: the driver returned a result`);
      assert.deepEqual(result.files_written, [], `${scenario.tool}: nothing written to the workspace`);
      if (scenario.expect === "denied") {
        assert.ok(offered.includes(scenario.tool), `${scenario.tool} is offered (so the deny is exercised)`);
        const call = events.find((event) => event.kind === "tool_call" && event.payload?.status === "error");
        assert.ok(call, `${scenario.tool}: a failed tool_call event was emitted`);
        assert.match(String(call.payload.output || model.state.toolResults.join(" ")), /denied/i, `${scenario.tool}: denied`);
      } else {
        assert.ok(!offered.includes(scenario.tool), `${scenario.tool} must not be offered; offered=${offered.join(",")}`);
      }
      for (const tool of NEVER_OFFERED) {
        assert.ok(!offered.includes(tool), `${tool} must never be offered`);
      }
      rows.push({ tool: scenario.tool, verdict: scenario.expect });
    }
    assert.deepEqual(fs.readdirSync(sentinelDir), [], "no requested tool ran");
    assert.equal(rows.length, scenarios.length);
    console.log(`deepseek fail-closed battery: ${rows.length}/${scenarios.length} deny — ${rows.map((row) => `${row.tool}=${row.verdict}`).join(", ")}`);
  } finally {
    model.server.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
