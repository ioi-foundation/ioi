import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repoRoot = process.cwd();

function read(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

test("model mounting daemon contract keeps provider fixtures outside the scenario file", () => {
  const contract = read("scripts/lib/model-mounting-daemon-contract.test.mjs");
  const fixtures = read("scripts/lib/model-mounting-daemon-contract/provider-fixtures.mjs");

  assert.match(contract, /from "\.\/model-mounting-daemon-contract\/provider-fixtures\.mjs"/);
  assert.doesNotMatch(contract, /http\.createServer/);
  assert.doesNotMatch(contract, /function runChildProcess/);
  assert.doesNotMatch(contract, /async function startFakeOpenAiCompatibleServer/);
  assert.match(fixtures, /async function startFakeOpenAiCompatibleServer/);
  assert.match(fixtures, /async function startFakeOllamaServer/);
  assert.match(fixtures, /async function startFakeVllmServer/);
  assert.match(fixtures, /async function startFakeLlamaCppServer/);
  assert.match(fixtures, /async function startFakeHuggingFaceCatalogServer/);
  assert.match(fixtures, /async function startFakeCustomCatalogServer/);
  assert.match(fixtures, /async function startFakeOAuthServer/);
  assert.match(fixtures, /function runChildProcess/);
});
