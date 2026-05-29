import crypto from "node:crypto";
import http from "node:http";

const mcpFixtureTools = [
  {
    name: "query",
    description: "Echo a query argument through a deterministic MCP remote tool.",
    inputSchema: {
      type: "object",
      properties: { q: { type: "string" } },
      required: ["q"],
    },
  },
  {
    name: "fetch",
    description: "Echo a fetch id through a deterministic MCP remote tool.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
    },
  },
];
const mcpFixtureResources = [
  {
    uri: "ioi://fixture/remote-context",
    name: "remote-context",
    description: "Deterministic read-only context exposed by the MCP remote fixture.",
    mimeType: "application/json",
  },
];
const mcpFixturePrompts = [
  {
    name: "remote-brief",
    description: "Build a concise brief for the deterministic MCP remote fixture.",
    arguments: [{ name: "topic", required: true }],
  },
];

export function largeMcpFixtureTools(count = 80) {
  return Array.from({ length: count }, (_, index) => {
    const suffix = String(index).padStart(3, "0");
    return {
      name: `large_tool_${suffix}`,
      description: `Large catalog fixture tool ${suffix}.`,
      inputSchema: {
        type: "object",
        properties: {
          value: { type: "string" },
          index: { type: "integer", const: index },
        },
      },
    };
  });
}

async function execFileWithInput(file, args, input, options = {}) {
  const mergedOptions = { maxBuffer: 10 * 1024 * 1024, ...options };
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, mergedOptions, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
    child.stdin.end(input);
  });
}

export async function startMcpRemoteFixtureServer(options = {}) {
  const requiredHeaders = options.requiredHeaders ?? {};
  const fixtureTools = Array.isArray(options.tools) ? options.tools : mcpFixtureTools;
  const observedHeaders = [];
  const sseClients = new Map();
  const recordHeaders = (request, pathLabel) => {
    observedHeaders.push({
      path: pathLabel,
      headers: Object.fromEntries(
        Object.entries(request.headers).map(([key, value]) => [
          key,
          Array.isArray(value) ? value.join(",") : String(value ?? ""),
        ]),
      ),
    });
  };
  const enforceRequiredHeaders = (request, response, pathLabel) => {
    recordHeaders(request, pathLabel);
    for (const [key, expectedValue] of Object.entries(requiredHeaders)) {
      if (String(request.headers[key.toLowerCase()] ?? "") !== String(expectedValue)) {
        response.writeHead(401, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: "missing_required_header", header: key }));
        return false;
      }
    }
    return true;
  };
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method === "GET" && ["/sse", "/secure-sse"].includes(url.pathname)) {
      if (url.pathname === "/secure-sse" && !enforceRequiredHeaders(request, response, url.pathname)) {
        return;
      }
      const sessionId = `session_${cryptoRandomSuffix()}`;
      response.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive",
      });
      const messagesPath = url.pathname === "/secure-sse" ? "/secure-messages" : "/messages";
      response.write(`event: endpoint\ndata: ${messagesPath}?sessionId=${sessionId}\n\n`);
      sseClients.set(sessionId, response);
      request.on("close", () => sseClients.delete(sessionId));
      return;
    }
    if (request.method === "POST" && ["/messages", "/secure-messages"].includes(url.pathname)) {
      if (url.pathname === "/secure-messages" && !enforceRequiredHeaders(request, response, url.pathname)) {
        return;
      }
      const sessionId = url.searchParams.get("sessionId") ?? "";
      const client = sseClients.get(sessionId);
      const message = JSON.parse(await readRequestBody(request));
      const rpc = mcpFixtureJsonRpcResponse(message, "ioi-fixture-mcp-sse", { tools: fixtureTools });
      response.writeHead(202).end();
      if (client && rpc) {
        client.write(`event: message\ndata: ${JSON.stringify(rpc)}\n\n`);
      }
      return;
    }
    if (request.method === "POST" && ["/mcp", "/secure-mcp"].includes(url.pathname)) {
      if (url.pathname === "/secure-mcp" && !enforceRequiredHeaders(request, response, url.pathname)) {
        return;
      }
      const message = JSON.parse(await readRequestBody(request));
      const rpc = mcpFixtureJsonRpcResponse(message, "ioi-fixture-mcp-http", { tools: fixtureTools });
      if (!rpc) {
        response.writeHead(202).end();
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(rpc));
      return;
    }
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "not_found" }));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  return {
    url: `http://${address.address}:${address.port}`,
    observedHeaders: () => observedHeaders.map((entry) => ({ ...entry, headers: { ...entry.headers } })),
    close: () =>
      new Promise((resolve, reject) => {
        for (const client of sseClients.values()) client.end();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

function mcpFixtureJsonRpcResponse(message, serverName, options = {}) {
  const tools = Array.isArray(options.tools) ? options.tools : mcpFixtureTools;
  if (message.method === "notifications/initialized") return null;
  if (message.method === "initialize") {
    return {
      jsonrpc: "2.0",
      id: message.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {}, resources: {}, prompts: {} },
        serverInfo: { name: serverName, version: "0.1.0" },
      },
    };
  }
  if (message.method === "tools/list") {
    return { jsonrpc: "2.0", id: message.id, result: { tools } };
  }
  if (message.method === "resources/list") {
    return { jsonrpc: "2.0", id: message.id, result: { resources: mcpFixtureResources } };
  }
  if (message.method === "prompts/list") {
    return { jsonrpc: "2.0", id: message.id, result: { prompts: mcpFixturePrompts } };
  }
  if (message.method === "tools/call") {
    const name = message.params?.name ?? "query";
    const args = message.params?.arguments ?? {};
    return {
      jsonrpc: "2.0",
      id: message.id,
      result: {
        content: [{ type: "text", text: `${name}:${args.q ?? args.id ?? args.value ?? ""}` }],
        structuredContent: {
          ok: true,
          server: serverName,
          tool: name,
          arguments: args,
        },
      },
    };
  }
  return {
    jsonrpc: "2.0",
    id: message.id,
    error: { code: -32601, message: `Unsupported method: ${message.method}` },
  };
}

export function cryptoRandomSuffix() {
  return Math.random().toString(36).slice(2, 10);
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}
