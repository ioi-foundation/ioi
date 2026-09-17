#!/usr/bin/env node
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  accessSync,
  constants,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  validateActivationResponse,
  validateGoalDetail,
  validateGoalEvents,
  validateGoalRunList,
  validateOrchestrationDelegations,
  validateOrchestrationDetail,
  validateOrchestrationGraph,
  validateOrchestrationList,
  validateOrchestrationReplay,
} from "../src/goal-space-response.ts";
import { goalRunId, orchestrationId } from "../src/goal-space-contract.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../..");
const artifactRoot = path.join(repoRoot, ".artifacts", "implementation", "ioi-ai-real-daemon-smoke");
const urlInput = process.env.IOI_AI_REAL_DAEMON_URL?.trim() ?? "";
const binaryInput = process.env.IOI_AI_REAL_DAEMON_BINARY?.trim() ?? "";
const expectedPrincipal = process.env.IOI_AI_REAL_DAEMON_PRINCIPAL?.trim() ?? "";
const bearerToken = process.env.IOI_AI_REAL_DAEMON_BEARER_TOKEN?.trim() ?? "";
const sessionToken = process.env.IOI_AI_REAL_DAEMON_SESSION?.trim() ?? "";
const allowLoopbackTrust = process.env.IOI_AI_REAL_ALLOW_LOOPBACK_TRUST === "1";
let effectiveBearerToken = bearerToken;
let effectiveSessionToken = sessionToken;

function usageError(message) {
  const error = new Error(
    `${message}\n` +
      "Set exactly one of IOI_AI_REAL_DAEMON_URL or IOI_AI_REAL_DAEMON_BINARY. " +
      "URL mode also requires IOI_AI_REAL_DAEMON_PRINCIPAL and an authenticated bearer/session " +
      "unless IOI_AI_REAL_ALLOW_LOOPBACK_TRUST=1 is deliberately set for a loopback daemon.",
  );
  error.exitCode = 2;
  return error;
}

function loopback(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}

function boundedCredential(value, label) {
  if (!value) return;
  if (value.length > 4096 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw usageError(`${label} is malformed.`);
  }
}

function boundedId(value, prefix, label) {
  if (!value) return null;
  if (value.length > 160 || !new RegExp(`^${prefix}[A-Za-z0-9_-]+$`, "u").test(value)) {
    throw usageError(`${label} must be a canonical ${prefix} identifier.`);
  }
  return value;
}

function authHeaders() {
  if (effectiveBearerToken) return { authorization: `Bearer ${effectiveBearerToken}` };
  if (effectiveSessionToken) return { cookie: `ioi_session=${effectiveSessionToken}` };
  return {};
}

function sanitizeLog(value) {
  return value
    .slice(-16_384)
    .replace(/\bioi_(?:bootstrap|sess|pat)_[A-Za-z0-9_-]+\b/gu, "[REDACTED]")
    .replace(/\b([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY)[A-Z0-9_]*=)[^\s]+/giu, "$1[REDACTED]")
    .replace(/\b(authorization\s*:\s*(?:bearer\s+)?)[^\s]+/giu, "$1[REDACTED]");
}

async function freePort() {
  const server = createNetServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("could not allocate an isolated daemon port");
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  return address.port;
}

async function waitForHealth(baseUrl, child) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) return false;
    try {
      const response = await fetch(`${baseUrl}/healthz`, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return true;
    } catch {
      // The real process has not bound yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return false;
}

async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGTERM");
  await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 2_000))]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await exited;
  }
}

async function startIsolatedBinary() {
  const binary = path.resolve(binaryInput);
  if (!existsSync(binary)) throw usageError(`IOI_AI_REAL_DAEMON_BINARY does not exist: ${binary}`);
  try {
    accessSync(binary, constants.X_OK);
  } catch {
    throw usageError(`IOI_AI_REAL_DAEMON_BINARY is not executable: ${binary}`);
  }

  const dataDir = mkdtempSync(path.join(tmpdir(), "ioi-ai-real-daemon-smoke-"));
  const port = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  let log = "";
  const child = spawn(binary, [], {
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_WALLET_SECRET_PASS: randomBytes(32).toString("hex"),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const retainTail = (chunk) => {
    log = (log + chunk.toString("utf8")).slice(-32_768);
  };
  child.stdout.on("data", retainTail);
  child.stderr.on("data", retainTail);

  if (!(await waitForHealth(baseUrl, child))) {
    await stopChild(child);
    rmSync(dataDir, { recursive: true, force: true });
    throw new Error(`the supplied daemon binary did not become healthy\n${sanitizeLog(log)}`);
  }
  const bootstrapToken = log.match(/\bioi_bootstrap_[0-9a-f]{64}\b/u)?.[0] ?? "";
  if (!bootstrapToken) {
    await stopChild(child);
    rmSync(dataDir, { recursive: true, force: true });
    throw new Error(
      `the supplied daemon binary did not emit its one-boot bootstrap token\n${sanitizeLog(log)}`,
    );
  }
  const bootstrapPassword = randomBytes(32).toString("hex");
  const bootstrapResponse = await fetch(`${baseUrl}/v1/hypervisor/auth/bootstrap`, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ token: bootstrapToken, password: bootstrapPassword }),
    redirect: "manual",
    signal: AbortSignal.timeout(15_000),
  });
  const bootstrapText = await bootstrapResponse.text();
  log = log.replaceAll(bootstrapToken, "[REDACTED]");
  let bootstrapBody;
  try {
    bootstrapBody = JSON.parse(bootstrapText);
  } catch {
    await stopChild(child);
    rmSync(dataDir, { recursive: true, force: true });
    throw new Error(`daemon bootstrap returned non-JSON (${bootstrapResponse.status})`);
  }
  const issuedSession = bootstrapBody?.session_token;
  const issuedPrincipal = bootstrapBody?.principal?.principal_id;
  if (
    bootstrapResponse.status !== 200 ||
    bootstrapBody?.ok !== true ||
    typeof issuedSession !== "string" ||
    !issuedSession ||
    issuedSession.length > 4096 ||
    /[\u0000-\u001f\u007f]/u.test(issuedSession) ||
    typeof issuedPrincipal !== "string" ||
    !issuedPrincipal
  ) {
    await stopChild(child);
    rmSync(dataDir, { recursive: true, force: true });
    const reason = bootstrapBody?.reason ?? bootstrapBody?.error?.code ?? "bootstrap_contract_invalid";
    throw new Error(`daemon bootstrap failed (${bootstrapResponse.status} ${String(reason)})`);
  }
  return {
    baseUrl,
    child,
    dataDir,
    mode: "binary-isolated",
    issuedSession,
    issuedPrincipal,
  };
}

function configuredUrl() {
  let parsed;
  try {
    parsed = new URL(urlInput);
  } catch {
    throw usageError("IOI_AI_REAL_DAEMON_URL must be an absolute HTTP(S) URL.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw usageError("IOI_AI_REAL_DAEMON_URL must use HTTP or HTTPS.");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || !["", "/"].includes(parsed.pathname)) {
    throw usageError("IOI_AI_REAL_DAEMON_URL must be an origin without credentials, query, fragment, or path.");
  }
  if (parsed.protocol === "http:" && !loopback(parsed.hostname)) {
    throw usageError("A non-loopback real daemon must use HTTPS.");
  }
  if (!expectedPrincipal) throw usageError("URL mode requires IOI_AI_REAL_DAEMON_PRINCIPAL.");
  return parsed.href.replace(/\/$/u, "");
}

async function daemonWhoami(baseUrl) {
  const response = await fetch(`${baseUrl}/v1/hypervisor/auth/whoami`, {
    headers: { accept: "application/json", ...authHeaders() },
    redirect: "manual",
    signal: AbortSignal.timeout(10_000),
  });
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`real daemon whoami returned non-JSON (${response.status})`);
  }
  if (response.status !== 200) {
    const code = body?.error?.code ?? body?.reason ?? "whoami_refused";
    throw new Error(`real daemon whoami refused the smoke (${response.status} ${code})`);
  }
  const principal = body?.principal?.principal_id;
  if (typeof principal !== "string" || !principal || principal.length > 256 || /[\u0000-\u001f\u007f]/u.test(principal)) {
    throw new Error("real daemon whoami did not return a bounded principal_id");
  }
  return { body, principal };
}

const REQUIRED_DAEMON_ROUTES = [
  ["/v1/goal-orchestration/goal-run-activations", ["POST"]],
  ["/v1/goal-orchestration/goal-run-activations/:id", ["GET"]],
  ["/v1/goal-orchestration/goal-run-activations/:id/submit", ["POST"]],
  ["/v1/goal-orchestration/goal-runs", ["GET", "POST"]],
  ["/v1/goal-orchestration/goal-runs/:id", ["GET"]],
  ["/v1/goal-orchestration/goal-runs/:id/start", ["POST"]],
  ["/v1/goal-orchestration/goal-runs/:id/reconcile", ["POST"]],
  ["/v1/goal-orchestration/goal-runs/:id/events", ["GET"]],
  ["/v1/threads", ["POST"]],
  ["/v1/threads/:id", ["GET"]],
  ["/v1/threads/:id/subagents", ["GET"]],
  ["/v1/hypervisor/autonomous-systems/projection", ["GET"]],
  ["/v1/hypervisor/autonomous-systems/:id/records", ["GET", "POST"]],
  ["/v1/hypervisor/autonomous-systems/:id/records/:contract/:object", ["GET"]],
];

async function daemonRouteInventory(baseUrl, trustedLocal) {
  const response = await fetch(`${baseUrl}/v1`, {
    headers: {
      accept: "application/json",
      ...authHeaders(),
      ...(!trustedLocal ? { "x-ioi-forwarded": "ioi-ai" } : {}),
    },
    redirect: "manual",
    signal: AbortSignal.timeout(15_000),
  });
  const text = await response.text();
  if (text.length > 4_000_000) throw new Error("real daemon route inventory exceeds the 4 MB smoke bound");
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`real daemon route inventory returned non-JSON (${response.status})`);
  }
  if (response.status !== 200) {
    const code = body?.error?.code ?? body?.reason ?? "route_inventory_refused";
    throw new Error(`real daemon route inventory failed (${response.status} ${code})`);
  }
  if (
    body?.schema_version !== "ioi.hypervisor.v1-index.v1" ||
    body?.runtimeTruthSource !== "daemon-runtime" ||
    body?.derivation?.kind !== "mechanical" ||
    !Number.isSafeInteger(body?.total_routes) ||
    body.total_routes < REQUIRED_DAEMON_ROUTES.length ||
    !Array.isArray(body?.families)
  ) {
    throw new Error("real daemon route inventory violates the mechanical v1-index contract");
  }
  const indexed = new Map();
  for (const family of body.families) {
    if (!family || !Array.isArray(family.paths)) continue;
    for (const route of family.paths) {
      if (typeof route?.path === "string" && Array.isArray(route.methods)) {
        indexed.set(route.path, route.methods.filter((method) => typeof method === "string"));
      }
    }
  }
  const required = REQUIRED_DAEMON_ROUTES.map(([route, methods]) => {
    const observed = indexed.get(route) ?? [];
    const missingMethods = methods.filter((method) => !observed.includes(method));
    if (missingMethods.length) {
      throw new Error(
        `real daemon route inventory is missing ${missingMethods.join(",")} ${route}`,
      );
    }
    return { route, methods };
  });
  return {
    schema_version: body.schema_version,
    total_routes: body.total_routes,
    derivation_kind: body.derivation.kind,
    runtime_truth_source: body.runtimeTruthSource,
    required_routes: required,
  };
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("could not bind the derivative BFF smoke server");
  return `http://127.0.0.1:${address.port}`;
}

async function closeServer(server) {
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
}

async function run() {
  if (Boolean(urlInput) === Boolean(binaryInput)) {
    throw usageError("The real-daemon smoke requires exactly one daemon source.");
  }
  if (bearerToken && sessionToken) {
    throw usageError("Set only one of IOI_AI_REAL_DAEMON_BEARER_TOKEN or IOI_AI_REAL_DAEMON_SESSION.");
  }
  boundedCredential(bearerToken, "IOI_AI_REAL_DAEMON_BEARER_TOKEN");
  boundedCredential(sessionToken, "IOI_AI_REAL_DAEMON_SESSION");
  if (binaryInput && (bearerToken || sessionToken)) {
    throw usageError(
      "Binary mode creates its own daemon-issued bootstrap session; do not supply an ambient bearer or session.",
    );
  }

  const runtime = binaryInput
    ? await startIsolatedBinary()
    : {
        baseUrl: configuredUrl(),
        child: null,
        dataDir: null,
        mode: "url",
        issuedSession: null,
        issuedPrincipal: null,
      };
  let bff = null;
  try {
    if (runtime.mode === "binary-isolated") {
      effectiveBearerToken = "";
      effectiveSessionToken = runtime.issuedSession;
    }
    const whoami = await daemonWhoami(runtime.baseUrl);
    const daemonUrl = new URL(runtime.baseUrl);
    const trustedLocal = runtime.mode === "url" && allowLoopbackTrust;
    if (runtime.mode === "binary-isolated" && whoami.principal !== runtime.issuedPrincipal) {
      throw new Error(
        `bootstrap session principal mismatch: issued ${runtime.issuedPrincipal}, received ${whoami.principal}`,
      );
    }
    if (runtime.mode === "url" && whoami.principal !== expectedPrincipal) {
      throw new Error(
        `real daemon principal mismatch: expected ${expectedPrincipal}, received ${whoami.principal}`,
      );
    }
    if (whoami.body.authenticated !== true && !(trustedLocal && loopback(daemonUrl.hostname))) {
      throw new Error(
        "real daemon identity is not authenticated; provide a bearer/session, or deliberately opt into loopback trust",
      );
    }
    const routeInventory = await daemonRouteInventory(runtime.baseUrl, trustedLocal);

    process.env.NODE_ENV = "test";
    process.env.ALLOW_UNSIGNED_TEST_IDENTITY = "1";
    process.env.WEB_UI_PRINCIPALS = whoami.principal;
    process.env.IOI_HYPERVISOR_DAEMON_URL = runtime.baseUrl;
    process.env.IOI_AI_ALLOW_INSECURE_DAEMON_HTTP = "0";
    process.env.IOI_AI_ALLOW_LOOPBACK_DAEMON_TRUST = trustedLocal ? "1" : "0";

    const serverModuleUrl = new URL("../server/index.ts", import.meta.url);
    serverModuleUrl.searchParams.set("real-daemon-smoke", String(Date.now()));
    const { handler } = await import(serverModuleUrl.href);
    bff = createHttpServer((request, response) => {
      void handler(request, response).catch((error) => {
        if (!response.headersSent) {
          response.writeHead(500, { "content-type": "application/json" });
          response.end(JSON.stringify({ error: "smoke_bff_failure" }));
        } else response.end();
        console.error(`[ioi.ai real-daemon smoke] BFF failure: ${error?.message ?? error}`);
      });
    });
    const bffUrl = await listen(bff);
    const inboundCookie = [
      `webuiuser=${encodeURIComponent(whoami.principal)}`,
      ...(effectiveSessionToken ? [`ioi_session=${effectiveSessionToken}`] : []),
    ].join("; ");
    const checks = [];
    checks.push({
      label: "daemon mechanical route inventory",
      route: "/v1",
      status: 200,
      contract: "valid",
      required_route_count: routeInventory.required_routes.length,
    });

    async function bffJson(route, validator, label) {
      const response = await fetch(`${bffUrl}${route}`, {
        headers: {
          accept: "application/json",
          cookie: inboundCookie,
          ...(effectiveBearerToken ? { authorization: `Bearer ${effectiveBearerToken}` } : {}),
        },
        redirect: "manual",
        signal: AbortSignal.timeout(15_000),
      });
      const text = await response.text();
      let body;
      try {
        body = JSON.parse(text);
      } catch {
        throw new Error(`${label} returned non-JSON (${response.status})`);
      }
      if (response.status !== 200) {
        const code = body?.error?.code ?? body?.error ?? body?.reason ?? "request_refused";
        throw new Error(`${label} failed (${response.status} ${String(code)})`);
      }
      if (response.headers.get("cache-control") !== "no-store" || response.headers.get("pragma") !== "no-cache") {
        throw new Error(`${label} was not protected by the derivative BFF no-store boundary`);
      }
      const value = validator(body);
      checks.push({ label, route, status: response.status, contract: "valid" });
      return { body, value };
    }

    const goals = await bffJson("/api/ioi/goals", validateGoalRunList, "GoalRun collection");
    const orchestrations = await bffJson("/api/ioi/orchestrations", validateOrchestrationList, "Orchestration collection");
    const explicitGoalId = boundedId(process.env.IOI_AI_REAL_GOAL_RUN_ID?.trim() ?? "", "gr_", "IOI_AI_REAL_GOAL_RUN_ID");
    const selectedGoalId = explicitGoalId ?? goalRunId(goals.value[0]);
    if (selectedGoalId) {
      await bffJson(
        `/api/ioi/goals/${encodeURIComponent(selectedGoalId)}`,
        (body) => validateGoalDetail(body, selectedGoalId),
        "GoalRun owner projection",
      );
      await bffJson(
        `/api/ioi/goals/${encodeURIComponent(selectedGoalId)}/events`,
        (body) => validateGoalEvents(body, selectedGoalId),
        "GoalRun event projection",
      );
    }

    const explicitOrchestrationId = boundedId(
      process.env.IOI_AI_REAL_ORCHESTRATION_ID?.trim() ?? "",
      "orc_",
      "IOI_AI_REAL_ORCHESTRATION_ID",
    );
    const explicitSystemId = process.env.IOI_AI_REAL_SYSTEM_ID?.trim() || null;
    if (explicitOrchestrationId && !explicitSystemId?.startsWith("system://")) {
      throw usageError("IOI_AI_REAL_ORCHESTRATION_ID requires IOI_AI_REAL_SYSTEM_ID, the canonical system:// ref it is recorded under.");
    }
    const firstOrchestration = orchestrations.value.orchestrations[0] ?? null;
    const selectedOrchestrationId = explicitOrchestrationId ?? (firstOrchestration ? orchestrationId(firstOrchestration.orchestration) : null);
    const selectedSystemId = explicitOrchestrationId ? explicitSystemId : (firstOrchestration?.system_id ?? null);
    if (selectedOrchestrationId && selectedSystemId) {
      const base = `/api/ioi/orchestrations/${encodeURIComponent(selectedOrchestrationId)}`;
      const query = `?system_id=${encodeURIComponent(selectedSystemId)}`;
      await bffJson(
        `${base}${query}`,
        (body) => validateOrchestrationDetail(body, selectedOrchestrationId),
        "Orchestration record at its current head",
      );
      await bffJson(
        `${base}/replay${query}`,
        (body) => validateOrchestrationReplay(body, selectedOrchestrationId),
        "Orchestration replay (the record's chain)",
      );
      await bffJson(
        `${base}/graph${query}`,
        (body) => validateOrchestrationGraph(body, selectedOrchestrationId),
        "Orchestration composed graph",
      );
      await bffJson(`${base}/delegations${query}`, validateOrchestrationDelegations, "Orchestration delegations");
    }

    const activationId = boundedId(
      process.env.IOI_AI_REAL_ACTIVATION_ID?.trim() ?? "",
      "gra_",
      "IOI_AI_REAL_ACTIVATION_ID",
    );
    if (activationId) {
      await bffJson(
        `/api/ioi/goal-activations/${encodeURIComponent(activationId)}`,
        (body) => validateActivationResponse(body, activationId),
        "GoalRun activation projection",
      );
    }

    const report = {
      schema_version: "ioi.ai.real-daemon-smoke.v2",
      ok: true,
      mode: runtime.mode,
      daemon_origin: new URL(runtime.baseUrl).origin,
      principal_id: whoami.principal,
      daemon_authenticated: whoami.body.authenticated === true,
      loopback_trust: trustedLocal && whoami.body.authenticated !== true,
      mutation_count: runtime.mode === "binary-isolated" ? 1 : 0,
      goal_orchestration_mutation_count: 0,
      isolated_auth_bootstrap_mutation_count: runtime.mode === "binary-isolated" ? 1 : 0,
      route_inventory: routeInventory,
      goal_run_count: goals.value.length,
      orchestration_count: orchestrations.value.orchestrations.length,
      orchestration_systems_unavailable: orchestrations.value.unavailable.map((entry) => entry.system_id),
      selected_goal_run_id: selectedGoalId ?? null,
      selected_orchestration_id: selectedOrchestrationId ?? null,
      selected_system_id: selectedSystemId ?? null,
      selected_activation_id: activationId,
      checks,
      generated_at: new Date().toISOString(),
    };
    mkdirSync(artifactRoot, { recursive: true });
    writeFileSync(path.join(artifactRoot, "report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
    console.log(
      `ioi.ai real-daemon smoke: ${checks.length} read contracts passed ` +
        `(GoalRuns=${goals.value.length}, orchestrations=${orchestrations.value.orchestrations.length}, ` +
        `goal-orchestration-mutations=0, auth-bootstrap=${runtime.mode === "binary-isolated" ? 1 : 0})`,
    );
  } finally {
    if (bff?.listening) await closeServer(bff);
    if (runtime.child) await stopChild(runtime.child);
    if (runtime.dataDir) rmSync(runtime.dataDir, { recursive: true, force: true });
  }
}

run().catch((error) => {
  console.error(`[ioi.ai real-daemon smoke] ${error?.message ?? error}`);
  process.exitCode = Number.isInteger(error?.exitCode) ? error.exitCode : 1;
});
