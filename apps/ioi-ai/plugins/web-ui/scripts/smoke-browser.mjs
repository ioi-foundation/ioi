#!/usr/bin/env node
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../..");
const artifactRoot = path.join(root, ".artifacts", "implementation", "ioi-ai-browser-smoke");
const appPort = Number(process.env.IOI_AI_BROWSER_SMOKE_PORT ?? 45181);
const corePort = appPort + 1;
const daemonPort = appPort + 2;
const principal = "00000000-0000-4000-8000-000000000001";
const baseUrl = `http://127.0.0.1:${appPort}`;
const report = [];
const upstreamRequests = [];

fs.mkdirSync(artifactRoot, { recursive: true });

function sendJson(response, status, body) {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(payload),
    "content-type": "application/json; charset=utf-8",
  });
  response.end(payload);
}

function corePayload(url, method) {
  const pathname = url.pathname;
  if (method === "GET" && pathname === "/v1/surface-config") return { branding: { selfLabel: "ioi.ai" } };
  if (method === "POST" && pathname === "/v1/session-cap") return { token: "browser-smoke-capability" };
  if (pathname === "/v1/directory/meta") return { workspaceUrl: null };
  if (pathname === "/v1/sessions") return { sessions: [] };
  if (pathname === "/v1/contexts") return { contexts: [] };
  if (pathname === "/v1/files") return { owned: [], shared: [] };
  if (pathname === "/v1/crons") return { crons: [] };
  if (pathname === "/v1/connectors") return { providers: {} };
  if (pathname === "/v1/connectors/oauth/status") return { connected: [] };
  if (pathname === "/v1/keychain/overview") {
    return { accounts: [], credentials: [], grants: [], drops: [] };
  }
  if (pathname === "/v1/deployments") return { deployments: [] };
  if (pathname === "/v1/memory") return { content: "", revision: "empty" };
  if (pathname === "/v1/memory/history") return { revisions: [] };
  if (pathname === "/v1/skills") return { skills: [] };
  if (pathname === "/v1/runtime-config") {
    return {
      scopeId: `personal:${principal}`,
      approvedHarnesses: ["codex"],
      modelsByHarness: { codex: ["gpt-5"] },
      modelCatalog: { "gpt-5": { name: "GPT-5", provider: "openai" } },
      orgDefault: { harnessId: "codex", modelId: "gpt-5", revision: 1 },
      scopeOverride: null,
      effective: { harnessId: "codex", modelId: "gpt-5" },
      upgradeAvailable: false,
      fastModeModelIds: [],
      interactiveFastMode: false,
    };
  }
  if (pathname === "/v1/deliveries") return { deliveries: [] };
  if (method === "POST" && pathname === "/v1/turns") return {};
  return null;
}

function createCoreServer() {
  return http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", `http://127.0.0.1:${corePort}`);
    const method = request.method ?? "GET";
    upstreamRequests.push({ owner: "core", method, path: url.pathname });
    request.resume();
    const payload = corePayload(url, method);
    if (payload !== null) return sendJson(response, 200, payload);
    const known = corePayload(url, method === "GET" ? "POST" : "GET") !== null;
    sendJson(response, known ? 405 : 404, {
      error: { code: known ? "browser_smoke_method_not_allowed" : "browser_smoke_route_missing" },
    });
  });
}

async function jsonBody(request) {
  let raw = "";
  for await (const chunk of request) {
    raw += chunk;
    if (raw.length > 1_000_000) throw new Error("browser smoke request body exceeds 1 MB");
  }
  if (!raw) return {};
  const parsed = JSON.parse(raw);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("expected JSON object");
  return parsed;
}

function exactFields(body, fields) {
  const keys = Object.keys(body).sort();
  const allowed = [...fields].sort();
  return keys.every((key) => allowed.includes(key)) && allowed.every((key) => keys.includes(key));
}

function goalRun(id, goal, status = "draft") {
  return {
    schema_version: "ioi.goal-run.v1",
    goal_run_id: id,
    goal_ref: `goal://${id}`,
    owner_ref: `user://${principal}`,
    normalized_goal: goal,
    target_session_ref: "session:hyp-browser-smoke",
    receipt_refs: [`receipt://goal-run/${id}/admission`],
    work_result_refs: [],
    outcome_room_ref: null,
    status,
    created_at: "2026-08-06T12:00:00Z",
    updated_at: "2026-08-06T12:00:00Z",
  };
}

function outcomeRoom(id, goalRef, objective) {
  return {
    schema_version: "ioi.applications.ioi-ai.outcome-room.v2",
    outcome_room_id: `outcome-room://${id}`,
    system_id: `system://browser-smoke/${id}`,
    package_id: "package://ioi/outcome-room",
    owner_or_sponsor_ref: `user://${principal}`,
    objective_ref: goalRef,
    objective,
    room_mode: "private_goal",
    coordination_topology: "hosted_admission",
    member_goal_run_refs: [],
    latest_sequence: 1,
    latest_operation_ref: `agentgres://outcome-room/${id}/operations/1`,
    room_state_root: `sha256:${"1".repeat(64)}`,
    room_receipt_root: `sha256:${"2".repeat(64)}`,
    status: "open",
    created_at: "2026-08-06T12:00:00Z",
    updated_at: "2026-08-06T12:00:00Z",
  };
}

const fakeGoals = new Map([
  ["gr_seeded", goalRun("gr_seeded", "Seeded runnable outcome", "draft")],
]);
const fakeRooms = new Map([
  ["or_seeded", outcomeRoom("or_seeded", "goal://gr_seeded", "Seeded Outcome Room")],
]);

function goalEvents(id) {
  return {
    ok: true,
    goal_ref: `goal://${id}`,
    events: [],
    invocations: [],
    verifications: [],
  };
}

function roomProjection(id, kind) {
  const roomRef = `outcome-room://${id}`;
  if (kind === "collaborative-work-graph") {
    return {
      collaborative_work_graph: {
        schema_version: "ioi.applications.ioi-ai.collaborative-work-graph.v1",
        outcome_room_ref: roomRef,
        member_goal_run_refs: fakeRooms.get(id)?.member_goal_run_refs ?? [],
        participant_refs: [],
        frontier_item_refs: [],
        work_claim_refs: [],
        attempt_refs: [],
        finding_refs: [],
        verifier_challenge_refs: [],
        work_result_refs: [],
        outcome_delta_refs: [],
        source_admission_receipt_refs: [`receipt://agentgres/${id}/1`],
        information_flow_label_refs: [],
      },
    };
  }
  if (kind === "discussion-projection") {
    return {
      discussion_projection: {
        schema_version: "ioi.applications.ioi-ai.outcome-room-discussion-projection.v1",
        outcome_room_ref: roomRef,
        information_flow_label_refs: [],
        permitted_subject_refs: [],
        message_refs: [],
        redaction_summary_refs: [],
        source_admission_receipt_refs: [`receipt://agentgres/${id}/1`],
      },
    };
  }
  if (kind === "product-projection") {
    return {
      schema_version: "ioi.hypervisor.outcome-room-product-projection.v1",
      outcome_room: { outcome_room_ref: roomRef },
      member_goal_runs: [],
      work_result_refs: [],
      outcome_delta_refs: [],
      work_results: [],
      outcome_deltas: [],
      source_admission_receipt_refs: [`receipt://agentgres/${id}/1`],
    };
  }
  return {
    schema_version: "ioi.outcome-room-replay-projection.v2",
    outcome_room_ref: roomRef,
    operations: [],
  };
}

function methodRefusal(response, allowed) {
  response.setHeader("allow", allowed.join(", "));
  sendJson(response, 405, { error: { code: "browser_smoke_method_not_allowed", allowed } });
}

function createDaemonServer() {
  return http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", `http://127.0.0.1:${daemonPort}`);
    const method = request.method ?? "GET";
    upstreamRequests.push({ owner: "daemon", method, path: url.pathname });
    try {
    if (url.pathname === "/v1/hypervisor/auth/whoami") {
      if (method !== "GET") return methodRefusal(response, ["GET"]);
      request.resume();
      sendJson(response, 200, {
        authenticated: true,
        principal: { principal_id: principal },
      });
      return;
    }
    if (url.pathname === "/v1/goal-orchestration/goal-runs") {
      if (method === "GET") {
        request.resume();
        return sendJson(response, 200, { goal_runs: [...fakeGoals.values()], ok: true });
      }
      if (method !== "POST") return methodRefusal(response, ["GET", "POST"]);
      const body = await jsonBody(request);
      if (
        !["goal", "session_ref", "origin_surface", "model_route_ref"].every(
          (field) => field === "model_route_ref" || Object.hasOwn(body, field),
        ) ||
        Object.keys(body).some((field) => !["goal", "session_ref", "origin_surface", "model_route_ref"].includes(field)) ||
        typeof body.goal !== "string" ||
        !String(body.session_ref).startsWith("session:") ||
        body.origin_surface !== "api"
      )
        return sendJson(response, 422, { error: { code: "browser_smoke_goal_create_invalid" } });
      const run = goalRun("gr_interaction", body.goal, "draft");
      fakeGoals.set(run.goal_run_id, run);
      return sendJson(response, 201, { ok: true, goal_run: run });
    }
    const activation = url.pathname.match(/^\/v1\/goal-orchestration\/goal-run-activations\/(gra_[A-Za-z0-9_-]+)$/u);
    if (activation) {
      if (method !== "GET") return methodRefusal(response, ["GET"]);
      request.resume();
      if (activation[1] !== "gra_seeded") return sendJson(response, 404, { error: { code: "not_found" } });
      return sendJson(response, 200, {
        ok: true,
        activation: { activation_ref: "goal-run-activation://gra_seeded", status: "draft" },
        activation_hash: `sha256:${"a".repeat(64)}`,
        goal_draft: { goal_text: "Seeded activation awaiting exact review" },
        authority_decision: { decision: "review", required_scope: "scope:goal.run.create" },
        resolved_profile: { revision_ref: "profile://research/v1", content_hash: `sha256:${"b".repeat(64)}` },
        goal_run_execution_ceiling: { max_total_invocations: 0, max_parallel_invocations: 0 },
        goal_run: null,
      });
    }
    const goalPath = url.pathname.match(/^\/v1\/goal-orchestration\/goal-runs\/(gr_[A-Za-z0-9_-]+)(?:\/(events|start|reconcile))?$/u);
    if (goalPath) {
      const [, id, action] = goalPath;
      const run = fakeGoals.get(id);
      if (!run) {
        request.resume();
        return sendJson(response, 404, { error: { code: "goal_run_not_found" } });
      }
      if (!action) {
        if (method !== "GET") return methodRefusal(response, ["GET"]);
        request.resume();
        return sendJson(response, 200, { ok: true, goal_run: run });
      }
      if (action === "events") {
        if (method !== "GET") return methodRefusal(response, ["GET"]);
        request.resume();
        return sendJson(response, 200, goalEvents(id));
      }
      if (method !== "POST") return methodRefusal(response, ["POST"]);
      const body = await jsonBody(request);
      if (action === "start") {
        if (Object.keys(body).some((field) => field !== "wallet_approval_grant") || run.status !== "draft")
          return sendJson(response, 409, { error: { code: "browser_smoke_goal_start_invalid" } });
        run.status = "active";
        run.updated_at = "2026-08-06T12:01:00Z";
        run.receipt_refs.push(`receipt://goal-run/${id}/start`);
        return sendJson(response, 200, {
          ok: true,
          goal_run: run,
          invocations: [{ status: "completed", harness_invocation_id: `hi_${id}` }],
          partial_result: false,
          blockers: [],
        });
      }
      if (
        !exactFields(body, ["idempotency_key"]) ||
        typeof body.idempotency_key !== "string" ||
        body.idempotency_key.length < 8 ||
        run.status !== "active"
      )
        return sendJson(response, 409, { error: { code: "browser_smoke_goal_reconcile_invalid" } });
      run.status = "complete";
      run.updated_at = "2026-08-06T12:02:00Z";
      run.receipt_refs.push(`receipt://goal-run/${id}/reconcile`);
      run.work_result_refs.push(`work-result://goal-run/${id}/result/1`);
      return sendJson(response, 200, {
        ok: true,
        goal_run: run,
        reconciliation: { receipt_ref: `receipt://goal-run/${id}/reconciliation`, status: "committed" },
      });
    }
    if (url.pathname === "/v1/goal-orchestration/outcome-rooms") {
      if (method === "GET") {
        request.resume();
        return sendJson(response, 200, {
          schema_version: "ioi.applications.ioi-ai.outcome-room.v2",
          outcome_rooms: [...fakeRooms.values()],
          runtimeTruthSource: "daemon-runtime",
        });
      }
      if (method !== "POST") return methodRefusal(response, ["GET", "POST"]);
      const body = await jsonBody(request);
      if (
        body.schema_version !== "ioi.applications.ioi-ai.outcome-room.v2" ||
        typeof body.system_id !== "string" ||
        !body.system_id.startsWith("system://") ||
        body.owner_or_sponsor_ref !== `user://${principal}` ||
        body.coordination_topology !== "hosted_admission" ||
        body.host_domain_ref !== body.system_id ||
        typeof body.objective_ref !== "string" ||
        !body.objective_ref.startsWith("goal://gr_")
      )
        return sendJson(response, 422, { error: { code: "browser_smoke_room_create_invalid" } });
      const room = outcomeRoom("or_interaction", body.objective_ref, body.objective);
      room.system_id = body.system_id;
      room.room_mode = body.room_mode;
      fakeRooms.set("or_interaction", room);
      return sendJson(response, 201, {
        outcome_room: room,
        agentgres_admission: {
          receipt_ref: "receipt://agentgres/or_interaction/1",
          operation_ref: "agentgres://outcome-room/or_interaction/operations/1",
        },
        replayed: false,
      });
    }
    if (url.pathname === "/v1/goal-orchestration/outcome-rooms/overview") {
      if (method !== "GET") return methodRefusal(response, ["GET"]);
      request.resume();
      return sendJson(response, 200, {
        schema_version: "ioi.hypervisor.outcome-rooms-overview.v1",
        outcome_rooms: fakeRooms.size,
      });
    }
    const roomPath = url.pathname.match(
      /^\/v1\/goal-orchestration\/outcome-rooms\/(or_[A-Za-z0-9_-]+)(?:\/(replay|collaborative-work-graph|discussion-projection|product-projection|attach-goal-run|detach-goal-run))?$/u,
    );
    if (roomPath) {
      const [, id, action] = roomPath;
      const room = fakeRooms.get(id);
      if (!room) {
        request.resume();
        return sendJson(response, 404, { error: { code: "outcome_room_not_found" } });
      }
      if (!action) {
        if (method !== "GET") return methodRefusal(response, ["GET"]);
        request.resume();
        return sendJson(response, 200, { outcome_room: room });
      }
      if (["replay", "collaborative-work-graph", "discussion-projection", "product-projection"].includes(action)) {
        if (method !== "GET") return methodRefusal(response, ["GET"]);
        request.resume();
        return sendJson(response, 200, roomProjection(id, action));
      }
      if (method !== "POST") return methodRefusal(response, ["POST"]);
      const body = await jsonBody(request);
      const goalId = String(body.goal_run_ref ?? "").slice("goal://".length);
      const run = fakeGoals.get(goalId);
      if (
        !run ||
        body.goal_run_ref !== room.objective_ref ||
        body.expected_revision !== room.latest_sequence ||
        !/^sha256:[0-9a-f]{64}$/u.test(String(body.expected_goal_run_record_root ?? ""))
      )
        return sendJson(response, 409, { error: { code: "browser_smoke_room_membership_invalid" } });
      const attaching = action === "attach-goal-run";
      room.member_goal_run_refs = attaching ? [body.goal_run_ref] : [];
      room.latest_sequence += 1;
      run.outcome_room_ref = attaching ? room.outcome_room_id : null;
      return sendJson(response, 200, {
        outcome_room: room,
        goal_run: run,
        membership_transition: attaching ? "attach" : "detach",
        agentgres_admission: {
          receipt_ref: `receipt://agentgres/${id}/${room.latest_sequence}`,
          operation_ref: `agentgres://outcome-room/${id}/operations/${room.latest_sequence}`,
        },
      });
    }
    if (url.pathname === "/v1/hypervisor/auth/logout") {
      if (method !== "POST") return methodRefusal(response, ["POST"]);
      await jsonBody(request);
      return sendJson(response, 200, { ok: true });
    }
    request.resume();
    sendJson(response, 404, { error: { code: "browser_smoke_route_missing" } });
    } catch (error) {
      request.resume();
      sendJson(response, 400, {
        error: { code: "browser_smoke_invalid_request", message: error instanceof Error ? error.message : String(error) },
      });
    }
  });
}

function listen(server, port) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
}

function close(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

async function waitFor(url, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let last = "not ready";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
      last = `HTTP ${response.status}`;
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`${url} did not become ready: ${last}`);
}

const routes = [
  { path: "/goals", heading: "Intent becomes governed work." },
  { path: "/rooms/or_seeded", heading: "Seeded Outcome Room" },
  { path: "/goal-activations/gra_seeded", heading: "Review before activation" },
  { path: "/contexts", heading: "Projects" },
  { path: "/files", heading: "Files" },
  { path: "/crons", heading: "Crons" },
  { path: "/keychain", heading: "Keychain" },
  { path: "/deploys", heading: "Apps" },
  { path: "/memory", heading: "Memory" },
  { path: "/skills", heading: "Skills" },
  { path: "/", heading: "New chat composer", selector: 'textarea[placeholder="Ask anything"]' },
];

const modes = [
  { name: "light", colorScheme: "light", viewport: { width: 1440, height: 1000 } },
  { name: "dark", colorScheme: "dark", viewport: { width: 1440, height: 1000 } },
  { name: "narrow", colorScheme: "light", viewport: { width: 390, height: 844 } },
];

const core = createCoreServer();
const daemon = createDaemonServer();
let app;
let browser;

try {
  await Promise.all([listen(core, corePort), listen(daemon, daemonPort)]);
  Object.assign(process.env, {
    CORE_API_URL: `http://127.0.0.1:${corePort}`,
    IOI_AI_ALLOW_INSECURE_DAEMON_HTTP: "0",
    IOI_AI_ALLOW_LOOPBACK_DAEMON_TRUST: "1",
    IOI_HYPERVISOR_DAEMON_URL: `http://127.0.0.1:${daemonPort}`,
    NODE_ENV: "development",
    PORT: String(appPort),
    WEB_UI_PRINCIPALS: principal,
    WEB_UI_PUBLIC_URL: baseUrl,
  });
  const { handler } = await import("../server/index.ts");
  app = http.createServer((request, response) => {
    void handler(request, response).catch((error) => {
      if (!response.headersSent) sendJson(response, 502, { error: "browser_smoke_bff_failure" });
      else response.end();
      report.push({ kind: "bff-error", message: error instanceof Error ? error.stack : String(error) });
    });
  });
  await listen(app, appPort);
  await waitFor(`${baseUrl}/healthz`);
  const unknownDaemonRoute = await fetch(`http://127.0.0.1:${daemonPort}/v1/not-a-real-route`);
  if (unknownDaemonRoute.status !== 404)
    throw new Error(`fake daemon unknown route returned ${unknownDaemonRoute.status}, expected 404`);
  const wrongDaemonMethod = await fetch(`http://127.0.0.1:${daemonPort}/v1/goal-orchestration/goal-runs`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  if (wrongDaemonMethod.status !== 405)
    throw new Error(`fake daemon wrong method returned ${wrongDaemonMethod.status}, expected 405`);
  const malformedDaemonBody = await fetch(`http://127.0.0.1:${daemonPort}/v1/goal-orchestration/goal-runs`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "[]",
  });
  if (malformedDaemonBody.status !== 400)
    throw new Error(`fake daemon malformed body returned ${malformedDaemonBody.status}, expected 400`);
  report.push({
    kind: "fake-daemon-contract",
    unknown_route_status: unknownDaemonRoute.status,
    wrong_method_status: wrongDaemonMethod.status,
    malformed_body_status: malformedDaemonBody.status,
  });
  browser = await chromium.launch({ headless: true });

  for (const mode of modes) {
    const context = await browser.newContext({
      colorScheme: mode.colorScheme,
      reducedMotion: "reduce",
      viewport: mode.viewport,
    });
    const page = await context.newPage();
    const errors = [];
    let signedIn = false;
    page.on("console", (message) => {
      if (message.type() !== "error") return;
      if (!signedIn && /status of 401 \(Unauthorized\)/u.test(message.text())) return;
      errors.push(`console: ${message.text()}`);
    });
    page.on("pageerror", (error) => errors.push(`page: ${error.message}`));
    page.on("requestfailed", (request) => {
      const url = new URL(request.url());
      const reason = request.failure()?.errorText ?? "failed";
      if (url.pathname === "/api/deliveries/events" && reason === "net::ERR_ABORTED") return;
      errors.push(`request: ${request.method()} ${request.url()} ${reason}`);
    });
    page.on("response", (response) => {
      if (response.url().startsWith(baseUrl) && response.status() >= 400) {
        if (!signedIn && response.status() === 401 && new URL(response.url()).pathname === "/me") return;
        errors.push(`http: ${response.status()} ${response.request().method()} ${response.url()}`);
      }
    });

    await page.goto(`${baseUrl}/goals`, { waitUntil: "domcontentloaded" });
    await page.locator("#dev-principal").fill(principal);
    await page.getByRole("button", { name: "Continue" }).click();
    try {
      await page.getByRole("heading", { name: routes[0].heading, exact: true }).waitFor();
    } catch (error) {
      await page.screenshot({ path: path.join(artifactRoot, `${mode.name}-signin-failure.png`), fullPage: true });
      const text = (await page.locator("body").innerText()).slice(0, 4_000);
      throw new Error(
        `${mode.name} sign-in did not reach Goal Spaces: ${error instanceof Error ? error.message : String(error)}\n${text}\n${errors.join("\n")}`,
      );
    }
    signedIn = true;

    if (mode.name === "light") {
      await page.locator('[data-focus-key="goal-create-runnable"]').click();
      await page.locator('[name="goal"]').fill("Browser interaction GoalRun");
      await page.locator('[name="session_ref"]').fill("session:hyp-browser-smoke");
      await page.locator('[data-focus-key="goal-run-create"]').click();
      await page.getByRole("heading", { name: "Browser interaction GoalRun", exact: true }).waitFor();
      await page.locator('[data-focus-key="goal-start"]').click();
      await page.locator('[data-focus-key="goal-reconcile"]').waitFor();
      await page.locator('[data-focus-key="goal-reconcile"]').click();
      await page.locator(".goal-detail-head .goal-status-complete").waitFor();
      await page.screenshot({ path: path.join(artifactRoot, "interaction-goalrun-complete.png"), fullPage: true });
      report.push({
        kind: "interaction",
        journey: "goalrun-create-start-reconcile",
        final_status: "complete",
        screenshot: "interaction-goalrun-complete.png",
      });

      await page.goto(`${baseUrl}/goals`, { waitUntil: "domcontentloaded" });
      await page.getByRole("heading", { name: "Intent becomes governed work.", exact: true }).waitFor();
      await page.locator('[data-focus-key="room-materialize"]').click();
      await page.locator('[name="system_id"]').fill("system://browser-smoke/or_interaction");
      await page.locator('[name="goal_run_ref"]').fill("goal://gr_interaction");
      await page.locator('[name="objective"]').fill("Browser interaction OutcomeRoom");
      await page.locator('[name="governance"]').fill(
        JSON.stringify({
          stop_policy_ref: "policy://browser-smoke/stop",
          visibility_policy_ref: "policy://browser-smoke/visibility",
          participation_policy_ref: "policy://browser-smoke/participation",
          privacy_policy_ref: "policy://browser-smoke/privacy",
          contribution_policy_ref: "policy://browser-smoke/contribution",
          cooperation_surplus_policy_ref: "policy://browser-smoke/surplus",
          coordination_policy_ref: "policy://browser-smoke/coordination",
          ordering_and_merge_policy_ref: "policy://browser-smoke/ordering",
          conflict_and_failover_policy_ref: "policy://browser-smoke/failover",
        }),
      );
      await page.locator('[data-focus-key="outcome-room-create"]').click();
      await page.getByRole("heading", { name: "Browser interaction OutcomeRoom", exact: true }).waitFor();
      await page.locator('[data-focus-key="room-membership"]').click();
      await page.getByRole("button", { name: "Detach objective GoalRun", exact: true }).waitFor();
      await page.locator('[data-focus-key="room-membership"]').click();
      await page.getByRole("button", { name: "Attach objective GoalRun", exact: true }).waitFor();
      await page.screenshot({ path: path.join(artifactRoot, "interaction-outcome-room.png"), fullPage: true });
      report.push({
        kind: "interaction",
        journey: "outcome-room-materialize-attach-detach",
        final_membership: "detached",
        screenshot: "interaction-outcome-room.png",
      });
    }

    for (const route of routes) {
      await page.goto(`${baseUrl}${route.path}`, { waitUntil: "domcontentloaded" });
      if (route.selector) await page.locator(route.selector).waitFor({ timeout: 15_000 });
      else await page.getByRole("heading", { name: route.heading, exact: true }).waitFor({ timeout: 15_000 });
      await page.evaluate(async () => {
        await document.fonts.ready;
        await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      });
      const geometry = await page.evaluate(() => ({
        bodyClientWidth: document.body.clientWidth,
        bodyScrollWidth: document.body.scrollWidth,
        documentClientWidth: document.documentElement.clientWidth,
        documentScrollWidth: document.documentElement.scrollWidth,
      }));
      if (geometry.bodyScrollWidth > geometry.bodyClientWidth + 1) {
        errors.push(`overflow: body ${geometry.bodyScrollWidth}/${geometry.bodyClientWidth} at ${route.path}`);
      }
      if (geometry.documentScrollWidth > geometry.documentClientWidth + 1) {
        errors.push(`overflow: document ${geometry.documentScrollWidth}/${geometry.documentClientWidth} at ${route.path}`);
      }
      const file = `${mode.name}-${route.path === "/" ? "chats" : route.path.slice(1)}.png`;
      await page.screenshot({ path: path.join(artifactRoot, file), fullPage: true });
      report.push({
        mode: mode.name,
        route: route.path,
        heading: route.heading,
        viewport: mode.viewport,
        geometry,
        screenshot: file,
      });
    }

    await context.close();
    if (errors.length) throw new Error(`${mode.name} browser failures:\n${errors.join("\n")}`);
  }

  const daemonPaths = new Set(upstreamRequests.filter((item) => item.owner === "daemon").map((item) => item.path));
  for (const required of [
    "/v1/hypervisor/auth/whoami",
    "/v1/goal-orchestration/goal-runs",
    "/v1/goal-orchestration/goal-runs/gr_interaction/start",
    "/v1/goal-orchestration/goal-runs/gr_interaction/reconcile",
    "/v1/goal-orchestration/outcome-rooms",
    "/v1/goal-orchestration/outcome-rooms/or_interaction/attach-goal-run",
    "/v1/goal-orchestration/outcome-rooms/or_interaction/detach-goal-run",
    "/v1/goal-orchestration/goal-run-activations/gra_seeded",
  ]) {
    if (!daemonPaths.has(required)) throw new Error(`ioi.ai did not exercise daemon route ${required}`);
  }
  fs.writeFileSync(
    path.join(artifactRoot, "report.json"),
    `${JSON.stringify({ ok: true, routes: report, upstream_requests: upstreamRequests }, null, 2)}\n`,
  );
  process.stdout.write(`ioi.ai browser smoke: ${routes.length * modes.length} route renders passed\n`);
} catch (error) {
  fs.writeFileSync(
    path.join(artifactRoot, "report.json"),
    `${JSON.stringify(
      {
        ok: false,
        error: error instanceof Error ? error.stack : String(error),
        routes: report,
        upstream_requests: upstreamRequests,
      },
      null,
      2,
    )}\n`,
  );
  throw error;
} finally {
  if (browser) await browser.close();
  await Promise.all([app ? close(app) : Promise.resolve(), close(core), close(daemon)]);
}
