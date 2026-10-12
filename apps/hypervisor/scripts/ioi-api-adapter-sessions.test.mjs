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
// A route answer may carry its HTTP status under this key (JSON.stringify drops symbol keys).
const STATUS = Symbol("status");
const routes = {
  "GET /v1/hypervisor/environments/env_1": () => ({ environment: { id: "env_1", spec: {}, status: { phase: "running", ports: [{ port: 50432, protocol: "tcp" }] } } }),
  // The access token and the lease (grant) id are distinct values, as the daemon mints them.
  "POST /v1/hypervisor/environments/env_1/ops-lease": () => ({ accessToken: "tok_env1", lease_id: "lease_env1", environment_id: "env_1" }),
  // A mint answer with a lease id and NO access token: the adapter must refuse, never hand on the lease id.
  "POST /v1/hypervisor/environments/env_untokened/ops-lease": () => ({ lease_id: "lease_untokened", environment_id: "env_untokened" }),
  // The daemon resolves an env-ops token presented in a header, never in the URL path, and answers
  // 401 with no environment for anything that is not an active env-ops token.
  "GET /v1/hypervisor/ops-lease": (req) => {
    const environment = { tok_env1: "env_1", tok_env2: "env_2" }[req.headers["x-ioi-env-ops-token"]];
    return environment ? { active: true, environment_id: environment } : { [STATUS]: 401, active: false, environment_id: null };
  },
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
  "GET /v1/hypervisor/editor-targets": () => ({ openable_targets: ["vscode-browser"], targets: [] }),
  "GET /v1/hypervisor/environments": () => ({ environments: [
    { id: "env_run", created_at: AT, updated_at: AT, spec: { desired_phase: "running", project_id: "project:acme", stop_policy: { idle_timeout_secs: 0 } }, status: { phase: "running" } },
    { id: "env_stop", created_at: AT, updated_at: AT, spec: {}, status: { phase: "stopped" } },
    { id: "env_arch", created_at: AT, updated_at: "2026-09-27T11:00:00Z", spec: {}, status: { phase: "archived" } },
    { id: "env_gone", created_at: AT, updated_at: AT, spec: {}, status: { phase: "deleted", deleted: true } },
  ] }),
};
const fake = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => { body += c; });
  req.on("end", () => {
    const key = `${req.method} ${req.url}`;
    calls.push({ key, body, headers: req.headers });
    const route = routes[key];
    const answer = route ? route(req) : { code: "not_found" };
    res.writeHead(route ? (answer[STATUS] ?? 200) : 404, { "content-type": "application/json" });
    res.end(JSON.stringify(answer));
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

test("an auto-delete period for archived environments is refused by name, as preference or organization policy — nothing deletes an archived environment but a person", async () => {
  calls.length = 0;
  const pref = await rpc("UserService/SetPreference", { preference: { key: "DELETE_ARCHIVED_ENVIRONMENTS_AFTER", value: "86400" } });
  assert.equal(pref.status, 501);
  assert.match(messageOf(pref), /^archived_environment_auto_delete_not_enforced: .*preference was not saved/u);
  const policy = await rpc("OrganizationService/UpdateOrganizationPolicies", { organizationId: "org_1", deleteArchivedEnvironmentsAfter: { seconds: "86400", nanos: 0 } });
  assert.equal(policy.status, 501);
  assert.match(messageOf(policy), /^archived_environment_auto_delete_not_enforced: .*organization policy was not saved/u);
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

test("Plan mode (AGENT_MODE_SPEC, /ioi:spec) is refused by name and sends nothing; Agent mode still reaches the daemon as a turn", async () => {
  // Ruled 2026-09-27 (R-240 Arm A): nothing downstream interprets a Plan turn, so it would run as an Agent turn with
  // the environment's full authority and could change files.
  calls.length = 0;
  const byMode = await rpc("AgentService/SendToAgentExecution", { agentExecutionId: "thread_1", turnOptions: { modes: ["AGENT_MODE_SPEC"] }, userInput: { inputs: [{ text: { content: "outline the migration" } }] } });
  assert.equal(byMode.status, 501);
  assert.match(messageOf(byMode), /^plan_mode_not_supported: Plan mode \(turnOptions\.modes AGENT_MODE_SPEC\)/u);
  const byPrefix = await rpc("AgentService/SendToAgentExecution", { agentExecutionId: "thread_1", userInput: { inputs: [{ text: { content: "/ioi:spec outline the migration" } }] } });
  assert.equal(byPrefix.status, 501);
  const onCreate = await rpc("AgentService/CreateAgentSession", { agent: { turnOptions: { modes: ["AGENT_MODE_SPEC"] } }, initialInput: { inputs: [{ text: { content: "plan it" } }] } });
  assert.equal(onCreate.status, 501, "no environment is created for a Plan session");
  const agent = await rpc("AgentService/SendToAgentExecution", { agentExecutionId: "thread_1", userInput: { inputs: [{ text: { content: "fix the failing test" } }] } });
  assert.equal(agent.status ?? 200, 200);
  const turns = calls.filter((c) => c.key === "POST /v1/threads/thread_1/turns").map((c) => JSON.parse(c.body).text);
  assert.deepEqual(turns, ["fix the failing test"]);
  assert.equal(calls.filter((c) => /environments$/u.test(c.key)).length, 0);
});

// ---- 4. Logs: a real lease token, validated, then the daemon's session log as text/plain -------------

test("CreateEnvironmentLogsToken mints the env-scoped ops lease (no fabricated token)", async () => {
  calls.length = 0;
  const out = await rpc("EnvironmentService/CreateEnvironmentLogsToken", { environmentId: "env_1" });
  assert.equal(out.status ?? 200, 200);
  assert.deepEqual(JSON.parse(out.body), { accessToken: "tok_env1" }, "the access token, never the lease id");
  assert.deepEqual(calls.map((c) => c.key), ["POST /v1/hypervisor/environments/env_1/ops-lease"]);
});

test("a mint answer without an access token is refused by name (503) and the lease id is never handed on as a token", async () => {
  for (const [method, gap] of [
    ["EnvironmentService/CreateEnvironmentLogsToken", "environment_logs_token_unissued"],
    ["EnvironmentService/CreateEnvironmentAccessToken", "environment_access_token_unissued"],
  ]) {
    calls.length = 0;
    const out = await rpc(method, { environmentId: "env_untokened" });
    assert.equal(out.status, 503, method);
    assert.match(messageOf(out), new RegExp(`^${gap}: `, "u"), method);
    assert.ok(!out.body.includes("lease_untokened"), `${method}: the lease id is not returned as a token`);
    assert.deepEqual(calls.map((c) => c.key), ["POST /v1/hypervisor/environments/env_untokened/ops-lease"], `${method}: nothing else reached the daemon`);
  }
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
  const out = await logsGet({ authorization: "Bearer tok_env1", cookie: "ioi_session=abc" });
  assert.equal(out.status ?? 200, 200);
  assert.match(out.contentType, /^text\/plain/u);
  const read = calls.find((c) => c.key === "GET /v1/hypervisor/environments/env_1/logs?kind=session");
  assert.ok(read, "the daemon logs route was read");
  assert.equal(read.headers.cookie, "ioi_session=abc", "the caller's identity reached the daemon");
  assert.equal(read.headers.authorization, undefined, "the logs token is not presented to the daemon as identity");
  const resolved = calls.find((c) => c.key === "GET /v1/hypervisor/ops-lease");
  assert.equal(resolved?.headers["x-ioi-env-ops-token"], "tok_env1", "the token is resolved from a header");
  assert.ok(calls.every((c) => !c.key.includes("tok_env1")), "the token never appears in a daemon URL");
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
  const out = await logsGet({ authorization: "Bearer tok_env2", cookie: "ioi_session=abc" });
  assert.equal(out.status, 403);
  assert.equal(codeOf(out), "permission_denied");
  assert.match(messageOf(out), /^environment_logs_token_invalid: .*different environment/u);
  assert.equal(calls.filter((c) => c.key.includes("/logs")).length, 0);
});

test("the logs GET refuses an expired or unknown token (403) and never reads the logs", async () => {
  for (const token of ["tok_expired", "tok_unknown", "lease_env1"]) {
    calls.length = 0;
    const out = await logsGet({ authorization: `Bearer ${token}` });
    assert.equal(out.status, 403, token);
    assert.match(messageOf(out), /^environment_logs_token_invalid: .*not active/u, token);
    assert.equal(calls.filter((c) => c.key.includes("/logs")).length, 0, token);
  }
});

test.after(() => fake.close());

// R-240 Arm A (Sessions): the Archived view's "Delete all" deletes every environment the ARCHIVED list answers. The list
// ignored the filter, so that button deleted running and stopped environments too.
test("the Archived view lists only archived environments (its Delete all deletes nothing else); the active view excludes them", async () => {
  const list = async (filter) => JSON.parse((await handle("/api/ioi.v1.EnvironmentService/ListEnvironments", JSON.stringify({ filter }), { "content-type": "application/json" })).body).environments;
  const archived = await list({ archivalStatus: "ARCHIVAL_STATUS_ARCHIVED" });
  assert.deepEqual(archived.map((e) => e.id), ["env_arch"]);
  assert.equal(archived[0].metadata.archivedAt, "2026-09-27T11:00:00Z", "the Archived view lists and sorts by it");
  assert.deepEqual((await list({ archivalStatus: "ARCHIVAL_STATUS_ACTIVE" })).map((e) => e.id), ["env_run", "env_stop"]);
  assert.deepEqual((await list({})).map((e) => e.id), ["env_run", "env_stop", "env_arch"], "unspecified keeps every live environment");
  assert.equal((await list({ archivalStatus: "ARCHIVAL_STATUS_ACTIVE" }))[0].metadata.archivedAt, undefined);
});

// R-240 Arm A (Sessions): every editor opener threw "No environment or organization ID provided" (the projection named
// no organization), the details card waited forever on a runner the projection never named, and ResolveEditorURL had
// no lane at all.
test("an environment names its organization and runner; an offered editor resolves to its open route, any other is refused by name", async () => {
  const envs = JSON.parse((await handle("/api/ioi.v1.EnvironmentService/ListEnvironments", JSON.stringify({}), { "content-type": "application/json" })).body).environments;
  assert.ok(envs.every((e) => e.metadata.organizationId && e.metadata.runnerId === "local-microvm"), JSON.stringify(envs.map((e) => e.metadata)));
  const resolve = async (editorId) => handle("/api/ioi.v1.EditorService/ResolveEditorURL", JSON.stringify({ environmentId: "env_run", organizationId: "o", editorId }), { "content-type": "application/json" });
  const ok = await resolve("vscode-browser");
  assert.equal(ok.status ?? 200, 200);
  assert.equal(JSON.parse(ok.body).url, "/__ioi/editor/open?environmentId=env_run");
  const probeFailed = await resolve("cursor");
  assert.equal(probeFailed.status, 412);
  assert.match(probeFailed.body, /editor_not_openable/u, "an editor whose probe did not pass opens nothing");
  const unknown = await resolve("emacs");
  assert.equal(unknown.status, 412);
  assert.match(unknown.body, /editor_not_offered/u);
});

test("the composer's chosen project is read from CreateAgentSession's createEnvironmentFromProject", async () => {
  const { extractProjectId } = await import("./ioi-agent-runs.mjs");
  assert.equal(extractProjectId({ createEnvironmentFromProject: { projectId: "project:acme", spec: {} } }), "project:acme");
  assert.equal(extractProjectId({ createEnvironment: { spec: {} } }), null, "a scratch session names no project");
});

// R-240 Arm A (Sessions): the sidebar grouped every session "From scratch" and "Go to project" stayed disabled (the
// projection named no project), and the auto-stop read "30m of inactivity" (the shell's default when none is sent)
// while the daemon's idle timeout is 0 — never.
test("an environment names its project (none for a scratch session) and its daemon auto-stop (0 = never)", async () => {
  const envs = JSON.parse((await handle("/api/ioi.v1.EnvironmentService/ListEnvironments", JSON.stringify({}), { "content-type": "application/json" })).body).environments;
  const run = envs.find((e) => e.id === "env_run");
  assert.equal(run.metadata.projectId, "project:acme");
  assert.deepEqual(run.spec.timeout, { disconnected: "0s" });
  const stop = envs.find((e) => e.id === "env_stop");
  assert.equal(stop.metadata.projectId, undefined);
  assert.equal(stop.spec.timeout, undefined, "no stop policy on the record, none claimed");
});

// R-240 Arm A (Sessions): the shell's AgentExecution.Phase is PHASE_PENDING / RUNNING / WAITING_FOR_INPUT / STOPPED; the
// AGENT_EXECUTION_PHASE_* spellings were dropped to UNSPECIFIED, so every run read "Starting…" forever — a failed one too.
test("a run projects a phase the shell knows: failed is STOPPED with its reason, done is STOPPED without, waiting on the operator is WAITING_FOR_INPUT", async () => {
  const { runToAgentExecution } = await import("./ioi-agent-runs.mjs");
  const at = (status, extra = {}) => runToAgentExecution({ id: "agent_1", name: "n", status, createdAt: AT, updatedAt: AT, statusVersion: 1, envId: "env_1", sessionRef: "s", ...extra });
  const failed = at("failed", { error: "No reachable model route" });
  assert.deepEqual([failed.status.phase, failed.status.failureMessage, failed.spec.desiredPhase], ["PHASE_STOPPED", "No reachable model route", "PHASE_RUNNING"]);
  const done = at("done");
  assert.deepEqual([done.status.phase, done.status.failureMessage], ["PHASE_STOPPED", undefined]);
  assert.equal(at("running").status.phase, "PHASE_RUNNING");
  assert.equal(at("waiting").status.phase, "PHASE_PENDING");
  assert.equal(at("awaiting_operator_approval").status.phase, "PHASE_WAITING_FOR_INPUT");
  assert.match(at("denied").status.failureMessage, /denied/u);
});
