#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ARCHITECTURE_CONTRACT_FIXTURES,
  validateArchitectureContract,
} from "../packages/hypervisor-workbench/src/runtime/generated/architecture-contracts.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

for (const fixture of ARCHITECTURE_CONTRACT_FIXTURES) {
  const value = JSON.parse(fs.readFileSync(path.join(root, fixture.path), "utf8"));
  const result = validateArchitectureContract(fixture.contract_id, value);
  assert.equal(
    result.ok,
    fixture.expected === "accept",
    `${fixture.path}: ${result.errors.join(", ")}`,
  );
  if (fixture.expected_rule_id !== null) {
    assert.ok(
      result.errors.some((error) => error.includes(fixture.expected_rule_id)),
      `${fixture.path}: missing ${fixture.expected_rule_id}`,
    );
  }
}

console.log(
  JSON.stringify(
    {
      ok: true,
      runtime: "typescript",
      fixtures: ARCHITECTURE_CONTRACT_FIXTURES.length,
    },
    null,
    2,
  ),
);
