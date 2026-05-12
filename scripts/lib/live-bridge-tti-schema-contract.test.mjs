import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const rustTti = fs.readFileSync(
  path.join(root, "crates/types/src/app/runtime/thread_turn_item.rs"),
  "utf8",
);
const rustContracts = fs.readFileSync(
  path.join(root, "crates/types/src/app/runtime_contracts.rs"),
  "utf8",
);
const sdkMessages = fs.readFileSync(
  path.join(root, "packages/agent-sdk/src/messages.ts"),
  "utf8",
);
const sdkIndex = fs.readFileSync(path.join(root, "packages/agent-sdk/src/index.ts"), "utf8");

const schemaConstants = {
  RUNTIME_THREAD_SCHEMA_VERSION_V1: "ioi.runtime.thread.v1",
  RUNTIME_TURN_SCHEMA_VERSION_V1: "ioi.runtime.turn.v1",
  RUNTIME_ITEM_SCHEMA_VERSION_V1: "ioi.runtime.item.v1",
  RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION_V1: "ioi.runtime.event.v1",
};

const requiredFields = {
  RuntimeThreadRecord: [
    "schema_version",
    "thread_id",
    "session_id",
    "agent_id",
    "workspace_root",
    "title",
    "mode",
    "approval_mode",
    "trust_profile",
    "model_route",
    "status",
    "latest_turn_id",
    "latest_seq",
    "event_stream_id",
    "workflow_graph_id",
    "harness_binding_id",
    "agentgres_projection_ref",
    "created_at",
    "updated_at",
    "archived_at",
    "fixture_profile",
  ],
  RuntimeTurnRecord: [
    "schema_version",
    "turn_id",
    "thread_id",
    "parent_turn_id",
    "request_id",
    "status",
    "input_item_ids",
    "output_item_ids",
    "seq_start",
    "seq_end",
    "started_at",
    "completed_at",
    "mode",
    "approval_mode",
    "model_route_decision_id",
    "usage",
    "stop_reason",
    "error",
    "rollback_snapshot_id",
    "quality_ledger_ref",
    "workflow_execution_ref",
    "fixture_profile",
  ],
  RuntimeItemRecord: [
    "schema_version",
    "item_id",
    "thread_id",
    "turn_id",
    "kind",
    "status",
    "seq_start",
    "seq_end",
    "actor",
    "summary",
    "content_ref",
    "tool_name",
    "component_kind",
    "workflow_node_id",
    "receipt_refs",
    "artifact_refs",
    "approval_id",
    "policy_decision_id",
    "rollback_snapshot_id",
    "redaction_profile",
    "payload_schema_version",
  ],
  RuntimeEventEnvelope: [
    "schema_version",
    "event_id",
    "event_stream_id",
    "thread_id",
    "turn_id",
    "item_id",
    "seq",
    "parent_seq",
    "idempotency_key",
    "source",
    "source_event_kind",
    "event_kind",
    "status",
    "actor",
    "created_at",
    "workspace_root",
    "workflow_graph_id",
    "workflow_node_id",
    "component_kind",
    "tool_call_id",
    "approval_id",
    "artifact_refs",
    "receipt_refs",
    "policy_decision_refs",
    "rollback_refs",
    "payload_schema_version",
    "payload_ref",
    "payload",
    "redaction_profile",
    "fixture_profile",
  ],
};

function extractStringLiterals(body) {
  return Array.from(body.matchAll(/"([^"]+)"/g), (match) => match[1]);
}

function extractRustArray(name) {
  const match = rustTti.match(new RegExp(`pub const ${name}: &\\[&str\\] =\\s*&\\[([\\s\\S]*?)\\];`));
  assert.ok(match, `missing Rust ${name}`);
  return extractStringLiterals(match[1]);
}

function extractTsArray(name) {
  const match = sdkMessages.match(new RegExp(`export const ${name} = \\[([\\s\\S]*?)\\] as const;`));
  assert.ok(match, `missing TypeScript ${name}`);
  return extractStringLiterals(match[1]);
}

function extractRustConst(name) {
  const match = rustTti.match(new RegExp(`pub const ${name}: &str = "([^"]+)";`));
  assert.ok(match, `missing Rust ${name}`);
  return match[1];
}

function extractRustStructFields(name) {
  const match = rustTti.match(new RegExp(`pub struct ${name} \\{([\\s\\S]*?)\\n\\}`));
  assert.ok(match, `missing Rust struct ${name}`);
  return Array.from(match[1].matchAll(/^\s+pub ([a-zA-Z0-9_]+):/gm), (field) => field[1]);
}

function extractTsInterfaceFields(name) {
  const match = sdkMessages.match(new RegExp(`export interface ${name} \\{([\\s\\S]*?)\\n\\}`));
  assert.ok(match, `missing TypeScript interface ${name}`);
  return Array.from(match[1].matchAll(/^\s+([a-zA-Z0-9_]+)[?:]?:/gm), (field) => field[1]);
}

test("live bridge TTI schema literals match between Rust and TypeScript", () => {
  for (const [name, expected] of Object.entries(schemaConstants)) {
    assert.equal(extractRustConst(name), expected);
    assert.ok(sdkMessages.includes(`"${expected}"`), `TypeScript missing ${expected}`);
  }

  for (const name of [
    "RUNTIME_THREAD_MODES",
    "RUNTIME_APPROVAL_MODES",
    "RUNTIME_THREAD_STATUSES",
    "RUNTIME_TURN_STATUSES",
    "RUNTIME_ITEM_KINDS",
    "RUNTIME_ITEM_STATUSES",
    "RUNTIME_ITEM_ACTORS",
    "RUNTIME_EVENT_SOURCES",
  ]) {
    assert.deepEqual(extractTsArray(name), extractRustArray(name), `${name} drifted`);
  }
});

test("live bridge TTI record fields match between Rust and TypeScript", () => {
  for (const [record, fields] of Object.entries(requiredFields)) {
    assert.deepEqual(extractRustStructFields(record), fields, `${record} Rust field drift`);
    assert.deepEqual(extractTsInterfaceFields(record), fields, `${record} TypeScript field drift`);
  }
});

test("runtime_contracts compatibility surface exports live bridge TTI records", () => {
  for (const exported of [
    "RuntimeThreadRecord",
    "RuntimeTurnRecord",
    "RuntimeItemRecord",
    "RuntimeEventEnvelope",
    "RUNTIME_THREAD_SCHEMA_VERSION_V1",
    "RUNTIME_TURN_SCHEMA_VERSION_V1",
    "RUNTIME_ITEM_SCHEMA_VERSION_V1",
    "RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION_V1",
  ]) {
    assert.ok(rustContracts.includes(exported), `runtime_contracts missing ${exported}`);
  }
});

test("SDK root exports live bridge TTI constants and record types", () => {
  for (const exported of [
    "RUNTIME_TTI_SCHEMA_VERSIONS",
    "RUNTIME_THREAD_STATUSES",
    "RUNTIME_TURN_STATUSES",
    "RUNTIME_ITEM_KINDS",
    "RuntimeThreadRecord",
    "RuntimeTurnRecord",
    "RuntimeItemRecord",
    "RuntimeEventEnvelope",
  ]) {
    assert.ok(sdkIndex.includes(exported), `SDK root export missing ${exported}`);
  }
});
