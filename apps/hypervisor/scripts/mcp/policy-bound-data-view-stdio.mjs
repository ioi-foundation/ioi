#!/usr/bin/env node
// M05.8 — a BOUNDED local stdio MCP server for PolicyBoundDataView, and nothing more.
//
// WHAT IT IS. A newline-delimited JSON-RPC 2.0 server over stdin/stdout that exposes EXACTLY three
// tools — `policy_bound_data_view.admit`, `policy_bound_data_view.query`,
// `policy_bound_data_view.materialize` — each forwarding a bearer-authenticated call to the ONE
// native owner route and returning the daemon's JSON UNCHANGED in structured content. The daemon
// makes every admission and materialization decision; this shim resolves no policy, imports no owner
// implementation, and reinterprets no refusal code.
//
// WHAT IT IS NOT — THE M01.11 NONCLAIM, STATED IN THE BYTES. This is not the subject-scoped outward
// Hypervisor MCP gateway (M01.11). It normalizes no primitive to existing owners, exposes no master
// tool, resolves no ambient principal, and carries no tenant override. It forwards exactly three
// named tools over one route family, run locally by an operator who already holds the token. The
// bearer is read ONLY from `IOI_DAEMON_TOKEN` — never from tool arguments — so a tool call cannot
// smuggle a credential, name a principal, or select a tenant. Growing this into a general gateway is
// a different unit; the guards below refuse the moves that would start it.
//
// FRAMING. Newline-delimited JSON: one JSON-RPC object per line in, one per line out. This is the
// minimal deterministic transport a test can drive; it is deliberately not the full MCP capability
// negotiation, which a general gateway would own.
//
// Env: IOI_DAEMON_ENDPOINT (default http://127.0.0.1:8765) · IOI_DAEMON_TOKEN (the caller's own
// session or pat_* token; the token IS the principal binding).

import readline from "node:readline";

const ENDPOINT = (process.env.IOI_DAEMON_ENDPOINT || "http://127.0.0.1:8765").replace(/\/$/, "");
const VIEWS = "/v1/hypervisor/policy-bound-data-views";
const MATERIALIZATIONS = "/v1/hypervisor/policy-bound-data-view-materializations";

const SERVER_INFO = { name: "ioi-policy-bound-data-view", version: "0.1.0" };

// The three tools. Each input schema is exactly the owner route's own contract; this shim adds no
// field of its own, and `authorization`, `token`, principal and tenant are absent BY DESIGN — the
// token comes from the environment, not the arguments.
const TOOLS = [
  {
    name: "policy_bound_data_view.admit",
    description:
      "Admit one immutable PolicyBoundDataView revision. `body` is the exact admission request the native owner route validates; every binding is resolved server-side through its owner seam. Returns the daemon record or the typed refusal unchanged.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["body"],
      properties: {
        body: { type: "object", description: "The admission request, forwarded to the daemon unmodified." },
      },
    },
  },
  {
    name: "policy_bound_data_view.query",
    description:
      "Read the caller's own view inventory, one family, or one exact revision. Reachability only — no field of another principal's lineage is revealed.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        family: { type: "string", description: "A family token; omit to list the authorized inventory." },
        revision: { type: "integer", minimum: 1, description: "An exact revision ordinal within `family`." },
      },
    },
  },
  {
    name: "policy_bound_data_view.materialize",
    description:
      "Ask for a bounded projection. THE DAEMON decides whether a descriptor is granted; a refused decision is still admitted to the chain as evidence and returned unchanged. The grant, when made, is a descriptor and carries no payload bytes.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["body"],
      properties: {
        body: { type: "object", description: "The materialization request, forwarded to the daemon unmodified." },
      },
    },
  },
];

// Argument keys that would be an attempt to inject authority through the tool call rather than the
// environment. Refused by name so the nonclaim is enforced, not merely documented.
const FORBIDDEN_ARG_KEYS = ["authorization", "token", "bearer", "apiKey", "api_key", "__token", "endpoint"];

function daemonHeaders() {
  const headers = { accept: "application/json", "content-type": "application/json" };
  // The bearer is read ONLY here, from the environment. It is never taken from tool arguments.
  const token = process.env.IOI_DAEMON_TOKEN;
  if (token) headers.authorization = `Bearer ${token}`;
  return headers;
}

/** Forward one call and return `{ status, body }` with the daemon body UNCHANGED. */
async function forward(method, route, body) {
  let response;
  try {
    response = await fetch(`${ENDPOINT}${route}`, {
      method,
      headers: daemonHeaders(),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (error) {
    return { status: 0, body: { ok: false, error: { code: "mcp_daemon_unreachable", message: String(error) } } };
  }
  const text = await response.text();
  let parsed;
  try {
    parsed = text.length ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  return { status: response.status, body: parsed };
}

function guardArguments(args) {
  if (args === null || args === undefined) return {};
  if (typeof args !== "object" || Array.isArray(args)) {
    throw { code: -32602, message: "arguments must be an object" };
  }
  for (const key of FORBIDDEN_ARG_KEYS) {
    if (Object.prototype.hasOwnProperty.call(args, key)) {
      // The nonclaim, enforced: no credential, endpoint or principal override rides in the arguments.
      throw {
        code: -32602,
        message: `'${key}' is not a permitted tool argument — this shim reads its bearer only from IOI_DAEMON_TOKEN and grants no authority through tool arguments`,
      };
    }
  }
  return args;
}

async function callTool(name, rawArgs) {
  const args = guardArguments(rawArgs);
  let result;
  switch (name) {
    case "policy_bound_data_view.admit":
      result = await forward("POST", VIEWS, args.body);
      break;
    case "policy_bound_data_view.materialize":
      result = await forward("POST", MATERIALIZATIONS, args.body);
      break;
    case "policy_bound_data_view.query": {
      const params = new URLSearchParams();
      if (args.family !== undefined) params.set("family", String(args.family));
      if (args.revision !== undefined) params.set("revision", String(args.revision));
      const suffix = params.toString();
      result = await forward("GET", suffix ? `${VIEWS}?${suffix}` : VIEWS, undefined);
      break;
    }
    default:
      throw { code: -32601, message: `unknown tool: ${name}` };
  }
  // MCP tool result: the daemon body verbatim in BOTH the text block and structuredContent, and the
  // http status carried alongside so a caller sees a refusal without this shim reinterpreting it.
  return {
    content: [{ type: "text", text: JSON.stringify(result.body) }],
    structuredContent: { http_status: result.status, daemon_response: result.body },
    isError: !(result.status >= 200 && result.status < 300),
  };
}

function reply(id, resultOrError) {
  const message = { jsonrpc: "2.0", id };
  if (resultOrError && resultOrError.__isError) {
    message.error = { code: resultOrError.code, message: resultOrError.message };
  } else {
    message.result = resultOrError;
  }
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

async function handle(request) {
  const { id, method, params } = request;
  // Notifications (no id) get no response, per JSON-RPC.
  const isNotification = id === undefined || id === null;
  try {
    switch (method) {
      case "initialize":
        if (!isNotification) {
          reply(id, {
            protocolVersion: (params && params.protocolVersion) || "2024-11-05",
            capabilities: { tools: {} },
            serverInfo: SERVER_INFO,
            instructions:
              "Bounded local shim for PolicyBoundDataView over one daemon owner route. Not the M01.11 outward gateway.",
          });
        }
        return;
      case "tools/list":
        if (!isNotification) reply(id, { tools: TOOLS });
        return;
      case "tools/call": {
        const name = params && params.name;
        const result = await callTool(name, params && params.arguments);
        if (!isNotification) reply(id, result);
        return;
      }
      case "ping":
        if (!isNotification) reply(id, {});
        return;
      default:
        if (!isNotification) reply(id, { __isError: true, code: -32601, message: `method not found: ${method}` });
    }
  } catch (error) {
    const code = typeof error?.code === "number" ? error.code : -32603;
    const message = typeof error?.message === "string" ? error.message : String(error);
    if (!isNotification) reply(id, { __isError: true, code, message });
  }
}

function main() {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  // In-flight tool calls MUST drain before exit. `spawnSync` closes stdin the instant it finishes
  // writing, so a naive exit-on-close would kill the process mid-`fetch` and drop the response the
  // caller is waiting for. We track pending work and exit only when stdin has closed AND nothing is
  // still in flight.
  let stdinClosed = false;
  let pending = 0;
  const maybeExit = () => {
    if (stdinClosed && pending === 0) process.exit(0);
  };
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let request;
    try {
      request = JSON.parse(trimmed);
    } catch {
      process.stdout.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } })}\n`,
      );
      return;
    }
    // Each line is handled independently; a slow daemon call does not block reading the next line.
    pending += 1;
    handle(request).finally(() => {
      pending -= 1;
      maybeExit();
    });
  });
  rl.on("close", () => {
    stdinClosed = true;
    maybeExit();
  });
}

main();
