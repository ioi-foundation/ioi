#!/usr/bin/env node
const tools = [
  {
    name: "query",
    description: "Echo a query argument through a deterministic MCP stdio tool.",
    inputSchema: {
      type: "object",
      properties: { q: { type: "string" } },
      required: ["q"],
    },
  },
  {
    name: "fetch",
    description: "Echo a fetch id through a deterministic MCP stdio tool.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
    },
  },
];

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let newlineIndex = buffer.indexOf("\n");
  while (newlineIndex >= 0) {
    const line = buffer.slice(0, newlineIndex).trim();
    buffer = buffer.slice(newlineIndex + 1);
    if (line) handleLine(line);
    newlineIndex = buffer.indexOf("\n");
  }
});

function handleLine(line) {
  const request = JSON.parse(line);
  if (request.method === "notifications/initialized") return;
  if (request.method === "initialize") {
    respond(request.id, {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "ioi-fixture-mcp-stdio", version: "0.1.0" },
    });
    return;
  }
  if (request.method === "tools/list") {
    respond(request.id, { tools });
    return;
  }
  if (request.method === "tools/call") {
    const name = request.params?.name ?? "query";
    const args = request.params?.arguments ?? {};
    respond(request.id, {
      content: [
        {
          type: "text",
          text: `${name}:${args.q ?? args.id ?? args.value ?? ""}`,
        },
      ],
      structuredContent: {
        ok: true,
        server: "ioi-fixture-mcp-stdio",
        tool: name,
        arguments: args,
      },
    });
    return;
  }
  respond(request.id, {}, { code: -32601, message: `Unsupported method: ${request.method}` });
}

function respond(id, result, error = null) {
  const message = error
    ? { jsonrpc: "2.0", id, error }
    : { jsonrpc: "2.0", id, result };
  process.stdout.write(`${JSON.stringify(message)}\n`);
}
