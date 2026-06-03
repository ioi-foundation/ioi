import { createServer } from "node:http";

import { waitForPredicate } from "./process.mjs";

export function sendJson(response, statusCode, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(statusCode, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
  });
  response.end(body);
}

export function readRequestBody(request) {
  return new Promise((resolveBody, rejectBody) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("error", rejectBody);
    request.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      try {
        resolveBody(raw ? JSON.parse(raw) : {});
      } catch (error) {
        rejectBody(error);
      }
    });
  });
}

export function queueCommand(commands, command, payload = {}) {
  const commandId = `${command}:${Date.now()}:${commands.length}`;
  commands.push({ commandId, command, args: [payload] });
  return commandId;
}

export async function requireNewRequest(requests, predicate, label, startIndex = requests.length, timeoutMs = 45_000) {
  const request = await waitForPredicate(
    () => requests.slice(startIndex).find((candidate) => predicate(candidate)),
    timeoutMs,
    300,
  );
  if (!request) throw new Error(`Timed out waiting for bridge request: ${label}`);
  return request;
}

export function createWorkbenchBridgeState({
  daemonEndpoint,
  repoRoot,
  modelMountingRoutes = [],
  summary = {},
  workflows = [],
  runs = [],
  policy = {},
  connections = [],
} = {}) {
  return {
    schemaVersion: "ioi.workbench-bridge-state.v1",
    generatedAtMs: Date.now(),
    workspace: {
      name: "ioi",
      path: repoRoot,
      rootPath: repoRoot,
    },
    summary: {
      activeRunCount: 0,
      policyIssueCount: 0,
      connectorCount: 0,
      ...summary,
    },
    modelMountingStatus: {
      status: "connected",
      endpoint: daemonEndpoint,
    },
    modelMounting: {
      routes: modelMountingRoutes,
      server: {
        status: "running",
        endpoint: daemonEndpoint,
      },
    },
    workflows,
    runs,
    policy: {
      activeIssueCount: 0,
      issues: [],
      ...policy,
    },
    connections,
  };
}

export function createWorkbenchBridgeServer({
  daemonEndpoint,
  repoRoot,
  requests,
  commands,
  deliveredCommands,
  modelMountingRoutes = [],
  state = null,
} = {}) {
  return createServer(async (request, response) => {
    try {
      if (request.method === "OPTIONS") {
        sendJson(response, 204, {});
        return;
      }
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (request.method === "GET" && url.pathname === "/state") {
        sendJson(
          response,
          200,
          state ??
            createWorkbenchBridgeState({
              daemonEndpoint,
              repoRoot,
              modelMountingRoutes,
            }),
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/commands") {
        const next = commands.splice(0);
        deliveredCommands.push(...next);
        sendJson(response, 200, next);
        return;
      }
      if (request.method === "POST" && url.pathname === "/requests") {
        const body = await readRequestBody(request);
        requests.push(body);
        sendJson(response, 200, { ok: true });
        return;
      }
      sendJson(response, 404, { error: "not_found" });
    } catch (error) {
      sendJson(response, 500, { error: String(error?.message ?? error) });
    }
  });
}
