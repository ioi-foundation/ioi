import assert from "node:assert/strict";
import test from "node:test";

import { validateMcpServerRecords } from "./mcp-manager.mjs";

test("MCP manager validation emits canonical output fields only", () => {
  const validation = validateMcpServerRecords([
    {
      id: "mcp.invalid",
      transport: "socket",
      allowed_tools: [],
    },
  ]);

  assert.equal(validation.schema_version, "ioi.runtime.mcp-manager-validation.v1");
  assert.equal(validation.ok, false);
  assert.equal(validation.issues[0].server_id, "mcp.invalid");
  assert.equal(validation.warnings[0].server_id, "mcp.invalid");
  assert.equal(Object.hasOwn(validation, "schemaVersion"), false);
  assert.equal(Object.hasOwn(validation.issues[0], "serverId"), false);
  assert.equal(Object.hasOwn(validation.warnings[0], "serverId"), false);
});
