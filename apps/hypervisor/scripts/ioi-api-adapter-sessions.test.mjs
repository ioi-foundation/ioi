// Sessions cut 1 (R-241): every Sessions write binds to daemon truth or is refused by name.
//
// Rename and Auto-stop used to answer 200 having done nothing; Tasks / Services / task runs answered
// empty lists where no plane exists ("No tasks defined"); Goal mode reached the harness; the Logs pane
// could not load because its token was refused. This drives `handle()` against a fake daemon that
// records every call (method, path, and the identity headers it was sent).
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

const calls = [];
const AT = "2026-09-27T10:00:00Z";
const routes = {
  "GET /v1/hypervisor/environments/env_1": () => ({ environment: { id: "env_1", spec: {}, status: { phase: "running" } } }),
  "POST /v1/hypervisor/environments/env_1/ops-lease": () => ({ accessToken: "lease_env1", lease_id: "lease_env1", environment_id: "env_1" }),
  "GET /v1/hypervisor/ops-lease/lease_env1": () => ({ active: true, environment_id: "env_1" }),
  "GET /v1/hypervisor/ops-lease/lease_env2": () => ({ active: true, environment_id: "env_2" }),
  "GET /v1/hypervisor/ops-lease/lease_expired": () => ({ active: false, environment_id: "env_1" }),
  "GET /v1/hypervisor/environments/env_1/logs?kind=session": () => ({
    ok: true,
    environment_id: "env_1",
    kind: "session",
    entries: [
      { at: AT, command: "ls -la", exit_code: 0, stdout_bytes: 120, stderr_bytes: 0 },
      { at: "2026-09-27T10:00:05Z", command: "false\nsecond line", exit_code: 1, stdout_bytes: 0, stderr_bytes: 3 },
    ],
  }),
  "GET /v1/hypervisor/auth/policy": () => ({ deployment_auth_posture: "local_development" }),
  "POST /v1/threads/thread_1/turns": () => ({ ok: true }),
};
const fake = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => { body += c; });
  req.on("end", () => {
    const key = `${req.method} ${req.url}`;
    calls.push({ key, body, headers: req.headers });
    const route = routes[key];
    res.writeHead(route ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify(route ? route() : { code: "not_found" }));
  });
});
await new Promise((r) => fake.listen(0, "127.0.0.1", r));
process.env.IOI_HYPERVISOR_DAEMON_URL = `http://127.0.0.1:${fake.address().port}`;
process.env.IOI_ENV_GATEWAY_ORIGIN = "http://127.0.0.1:47001";
const { handle } = await import("./ioi-api-adapter.mjs");

const JSON_CT = { "content-type": "application/json" };
const rpc = (method, payload, headers = JSON_CT) => handle(`/api/ioi.v1.${method}`, JSON.stringify(payload), headers);
const writes = () => calls.filter((c) => c.key.startsWith("POST ") || c.key.startsWith("PATCH ") || c.key.startsWith("DELETE "));
const codeOf = (out) => JSON.parse(out.body).code;
const messageOf = (out) => JSON.parse(out.body).message;

// ---- 1. Rename / Auto-stop: refused by name, nothing applied ----------------------------------------

test("rename (UpdateEnvironment metadata.name) is refused by name and writes nothing", async () => {
  calls.length = 0;
  const out = await rpc("EnvironmentService/UpdateEnvironment", { environmentId: "env_1", metadata: { name: "my session" } });
  assert.equal(out.status, 501);
  assert.equal(codeOf(out), "unimplemented");
  assert.match(messageOf(out), /^environment_rename_not_supported: /u);
  assert.deepEqual(calls.map((c) => c.key), [], "no daemon call at all — nothing read, nothing written");
});

test("clearing the name (an empty metadata) is the same rename refusal", async () => {
  const out = await rpc("EnvironmentService/UpdateEnvironment", { environmentId: "env_1", metadata: {} });
  assert.equal(out.status, 501);
  assert.match(messageOf(out), /^environment_rename_not_supported: /u);
});

test("auto-stop (UpdateEnvironment spec.timeout.disconnected) is refused by name and writes nothing", async () => {
  calls.length = 0;
  const out = await rpc("EnvironmentService/UpdateEnvironment", { environmentId: "env_1", spec: { timeout: { disconnected: "1800s" } } });
  assert.equal(out.status, 501);
  assert.equal(codeOf(out), "unimplemented");
  assert.match(messageOf(out), /^environment_auto_stop_not_supported: /u);
  assert.deepEqual(writes(), []);
});

test("a rename carried beside a port narrowing is refused whole — the port is not half-applied", async () => {
  calls.length = 0;
  const out = await rpc("EnvironmentService/UpdateEnvironment", {
    environmentId: "env_1",
    metadata: { name: "x" },
    spec: { ports: [{ port: 3000, admission: "ADMISSION_LEVEL_UNSPECIFIED" }] },
  });
  assert.equal(out.status, 501);
  assert.match(messageOf(out), /^environment_rename_not_supported: /u);
  assert.deepEqual(writes(), [], "no unexpose reached the daemon");
});

test("any other update member the daemon cannot store is named, not answered 200", async () => {
  const out = await rpc("EnvironmentService/UpdateEnvironment", { environmentId: "env_1", metadata: { lockdownAt: "1970-01-01T00:00:00Z" } });
  assert.equal(out.status, 501);
  assert.match(messageOf(out), /^environment_update_field_not_supported: .*metadata\.lockdownAt/u);
});

test("the port rule is intact: the page's own port sync (admission EVERYONE) is still refused by name", async () => {
  calls.length = 0;
  const out = await rpc("EnvironmentService/UpdateEnvironment", { environmentId: "env_1", spec: { ports: [{ port: 50432, admission: "ADMISSION_LEVEL_EVERYONE", name: "agent" }] } });
  assert.equal(out.status, 403);
  assert.match(out.body, /port_exposure_not_by_update/u);
  assert.deepEqual(writes(), []);
});

// ---- 2. Tasks / Services / task runs: the absent plane is named -------------------------------------

for (const [method, gap] of [
  ["ListServices", "environment_services_plane_absent"],
  ["ListTasks", "environment_tasks_plane_absent"],
  ["ListTaskExecutions", "environment_task_executions_plane_absent"],
]) {
  test(`EnvironmentAutomationService/${method} refuses naming the absent plane (terminal unimplemented, not an empty list)`, async () => {
    const out = await rpc(`EnvironmentAutomationService/${method}`, { filter: { environmentIds: ["env_1"] } });
    assert.equal(out.status, 501);
    assert.equal(codeOf(out), "unimplemented", "terminal: the bundle's query retry stops on unimplemented");
    assert.match(messageOf(out), new RegExp(`^${gap}: `, "u"));
    assert.equal(JSON.parse(out.body).services, undefined);
    assert.equal(JSON.parse(out.body).tasks, undefined);
  });
}

// ---- 3. Goal mode: refused by name; Plan and Agent still reach the daemon ---------------------------

test("Goal mode on CreateAgentSession (agent.turnOptions.modes AGENT_MODE_GOAL) is refused by name before any environment is created", async () => {
  calls.length = 0;
  const out = await rpc("AgentService/CreateAgentSession", {
    createEnvironment: { spec: { machine: { class: "local-workspace-v0" } } },
    agent: { agentId: "a", turnOptions: { modes: ["AGENT_MODE_GOAL"] } },
    initialInput: { inputs: [{ text: { content: "/ioi:goal ship the release" } }] },
  });
  assert.equal(out.status, 501);
  assert.equal(codeOf(out), "unimplemented");
  assert.match(messageOf(out), /^goal_mode_not_in_hypervisor: .*ioi\.ai composition/u);
  assert.deepEqual(calls.map((c) => c.key), [], "no daemon call: no environment, no run, no thread");
});

test("Goal mode on SendToAgentExecution (the /ioi:goal prompt prefix) is refused by name and no turn is sent", async () => {
  calls.length = 0;
  const out = await rpc("AgentService/SendToAgentExecution", {
    agentExecutionId: "thread_1",
    userInput: { id: "u1", inputs: [{ text: { content: "/ioi:goal keep the tests green" } }] },
  });
  assert.equal(out.status, 501);
  assert.match(messageOf(out), /^goal_mode_not_in_hypervisor: /u);
  assert.deepEqual(calls.map((c) => c.key), []);
});

test("Goal controls (controlInput.goal) and a typed /goal command are refused by name", async () => {
  const control = await rpc("AgentService/SendToAgentExecution", { agentExecutionId: "thread_1", controlInput: { goal: { set: { objective: "x" } } } });
  assert.equal(control.status, 501);
  assert.match(messageOf(control), /^goal_mode_not_in_hypervisor: Goal mode \(controlInput\.goal\)/u);
  const typed = await rpc("AgentService/SendToAgentExecution", { agentExecutionId: "thread_1", userInput: { inputs: [{ text: { content: "/goal ship it" } }] } });
  assert.equal(typed.status, 501);
  assert.match(messageOf(typed), /^goal_mode_not_in_hypervisor: /u);
});

test("the org Agent-policies Goal-mode save (an agentPolicy goal member) is refused by name", async () => {
  const out = await rpc("OrganizationService/UpdateOrganizationPolicies", { organizationId: "o", agentPolicy: { codexGoalModeEnabled: true } });
  assert.equal(out.status, 501);
  assert.match(messageOf(out), /^goal_mode_not_in_hypervisor: Goal mode \(agentPolicy\.codexGoalModeEnabled\)/u);
});

test("Plan mode (AGENT_MODE_SPEC, /ioi:spec) and Agent mode still reach the daemon as a turn", async () => {
  calls.length = 0;
  const plan = await rpc("AgentService/SendToAgentExecution", {
    agentExecutionId: "thread_1",
    turnOptions: { modes: ["AGENT_MODE_SPEC"] },
    userInput: { inputs: [{ text: { content: "/ioi:spec outline the migration" } }] },
  });
  assert.equal(plan.status ?? 200, 200);
  const agent = await rpc("AgentService/SendToAgentExecution", { agentExecutionId: "thread_1", userInput: { inputs: [{ text: { content: "fix the failing test" } }] } });
  assert.equal(agent.status ?? 200, 200);
  const turns = calls.filter((c) => c.key === "POST /v1/threads/thread_1/turns").map((c) => JSON.parse(c.body).text);
  assert.deepEqual(turns, ["/ioi:spec outline the migration", "fix the failing test"]);
});

// ---- 4. Logs: a real lease token, validated, then the daemon's session log as text/plain -------------

test("CreateEnvironmentLogsToken mints the env-scoped ops lease (no fabricated token)", async () => {
  calls.length = 0;
  const out = await rpc("EnvironmentService/CreateEnvironmentLogsToken", { environmentId: "env_1" });
  assert.equal(out.status ?? 200, 200);
  assert.deepEqual(JSON.parse(out.body), { accessToken: "lease_env1" });
  assert.deepEqual(calls.map((c) => c.key), ["POST /v1/hypervisor/environments/env_1/ops-lease"]);
});

test("environmentUrls.logs points at the adapter's logs route on the gateway origin, not local://", async () => {
  const out = await rpc("EnvironmentService/GetEnvironment", { environmentId: "env_1" });
  const logs = JSON.parse(out.body).environment.status.environmentUrls.logs;
  assert.equal(logs, "http://127.0.0.1:47001/api/ioi/environments/env_1/logs");
});

const LOGS_PATH = "/api/ioi/environments/env_1/logs";
const logsGet = (headers) => handle(LOGS_PATH, "", headers);

test("the logs GET with a valid token answers the daemon session log as text/plain, read as the caller without the bearer", async () => {
  calls.length = 0;
  const out = await logsGet({ authorization: "Bearer lease_env1", cookie: "ioi_session=abc" });
  assert.equal(out.status ?? 200, 200);
  assert.match(out.contentType, /^text\/plain/u);
  const read = calls.find((c) => c.key === "GET /v1/hypervisor/environments/env_1/logs?kind=session");
  assert.ok(read, "the daemon logs route was read");
  assert.equal(read.headers.cookie, "ioi_session=abc", "the caller's identity reached the daemon");
  assert.equal(read.headers.authorization, undefined, "the logs token is not presented to the daemon as identity");
  // The reference's log grammar (log-groups bundle): a section, then `[id:<section>] [<ts>] LEVEL msg`.
  const lines = out.body.trimEnd().split("\n");
  assert.equal(lines.length, 3);
  const create = JSON.parse(lines[0].replace("[section-create]", ""));
  assert.deepEqual(create, { id: "session", title: "Session commands", continuous: true });
  const SECTION_LINE = /^\[id:([^\]]+)\](.*)$/u;
  const TS_LEVEL = /^\[([^\]]+)\] ([A-Za-z]+)(.*)$/u;
  const parsed = lines.slice(1).map((l) => {
    const [, id, rest] = SECTION_LINE.exec(l);
    const [, ts, level, content] = TS_LEVEL.exec(rest.replace(/^ /u, ""));
    return { id, ts, level, content: content.replace(/^ /u, "") };
  });
  assert.deepEqual(parsed, [
    { id: "session", ts: AT, level: "INFO", content: "$ ls -la (exit 0; stdout 120 B, stderr 0 B)" },
    { id: "session", ts: "2026-09-27T10:00:05Z", level: "ERROR", content: "$ false ↵ second line (exit 1; stdout 0 B, stderr 3 B)" },
  ]);
});

test("the logs GET refuses a missing token (401) and reads nothing", async () => {
  calls.length = 0;
  const out = await logsGet({ cookie: "ioi_session=abc" });
  assert.equal(out.status, 401);
  assert.match(messageOf(out), /^environment_logs_token_required: /u);
  assert.deepEqual(calls, []);
});

test("the logs GET refuses a token bound to another environment (403) and never reads the logs", async () => {
  calls.length = 0;
  const out = await logsGet({ authorization: "Bearer lease_env2", cookie: "ioi_session=abc" });
  assert.equal(out.status, 403);
  assert.equal(codeOf(out), "permission_denied");
  assert.match(messageOf(out), /^environment_logs_token_invalid: .*different environment/u);
  assert.equal(calls.filter((c) => c.key.includes("/logs")).length, 0);
});

test("the logs GET refuses an expired or unknown token (403) and never reads the logs", async () => {
  for (const token of ["lease_expired", "lease_unknown"]) {
    calls.length = 0;
    const out = await logsGet({ authorization: `Bearer ${token}` });
    assert.equal(out.status, 403, token);
    assert.match(messageOf(out), /^environment_logs_token_invalid: .*not active/u, token);
    assert.equal(calls.filter((c) => c.key.includes("/logs")).length, 0, token);
  }
});

test.after(() => fake.close());
