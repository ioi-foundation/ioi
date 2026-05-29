import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repoRoot = process.cwd();

function read(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

test("live daemon contract keeps MCP remote fixtures outside the scenario file", () => {
  const contract = read("scripts/lib/live-runtime-daemon-contract.test.mjs");
  const fixtures = read("scripts/lib/live-runtime-daemon-contract/mcp-fixtures.mjs");

  assert.match(contract, /live-runtime-daemon-contract\/mcp-fixtures\.mjs/);
  assert.doesNotMatch(contract, /http\.createServer/);
  assert.doesNotMatch(contract, /function mcpFixtureJsonRpcResponse/);
  assert.match(fixtures, /export async function startMcpRemoteFixtureServer/);
  assert.match(fixtures, /export function largeMcpFixtureTools/);
  assert.match(fixtures, /function mcpFixtureJsonRpcResponse/);
});
