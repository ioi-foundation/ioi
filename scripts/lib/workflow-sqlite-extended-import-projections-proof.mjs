#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-sqlite-extended-import-projections-proof.mjs <output-path>");
}

const { buildWorkflowImportedGenerationMetadataPanel } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-imported-generation-metadata.ts"
);
const { buildWorkflowImportedErrorRenderInfoPanel } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-imported-error-render-info.ts"
);

const outputDir = path.dirname(outputPath);
fs.mkdirSync(outputDir, { recursive: true });

const fixtureDbPath = path.join(outputDir, "antigravity-extended-import-fixture.db");
fs.rmSync(fixtureDbPath, { force: true });

const genPromptBlob = message([
  fieldBytes(1, stringBytes("kind=prompt_context")),
  fieldBytes(2, stringBytes("model=qwen/qwen3.5")),
  fieldBytes(3, stringBytes("route=route.local-first")),
  fieldBytes(4, stringBytes("Prompt contains PRIVATE_STAGE56_PROMPT and sk-stage56promptsecret.")),
  fieldVarint(5, 1600),
]);
const genGatewayBlob = message([
  fieldBytes(1, stringBytes("kind=gateway_request")),
  fieldBytes(2, stringBytes("url=http://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent")),
  fieldBytes(3, stringBytes("Authorization=Bearer ya29.stage56gatewaysecret")),
]);
const errorDetailsBlob = message([
  fieldBytes(1, stringBytes("code=TS2304")),
  fieldBytes(2, stringBytes("message=Cannot find imported symbol token=stage56-error-message")),
  fieldBytes(3, stringBytes("stack=STACK_STAGE56_CANARY\nAuthorization: Bearer ya29.stage56stacksecret")),
  fieldBytes(4, stringBytes("path=src/imported.ts")),
]);
const renderInfoBlob = message([
  fieldBytes(1, stringBytes("renderKind=markdown")),
  fieldBytes(2, stringBytes("artifact=artifact:render:stage56")),
  fieldBytes(3, stringBytes("target=https://example.invalid/render")),
]);
const taskDetailsBlob = message([
  fieldBytes(1, stringBytes("code=TASK_NOTE")),
  fieldBytes(2, stringBytes("message=missing receipt imported task detail")),
  fieldBytes(3, stringBytes("path=../outside.md")),
]);

const db = new DatabaseSync(fixtureDbPath);
try {
  db.exec(`
    CREATE TABLE gen_metadata (
      idx INTEGER PRIMARY KEY,
      data BLOB,
      size INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE steps (
      idx INTEGER PRIMARY KEY,
      step_type INTEGER,
      status INTEGER,
      error_details BLOB,
      render_info BLOB,
      task_details BLOB
    );
  `);
  db.prepare("INSERT INTO gen_metadata VALUES (?, ?, ?)").run(1, genPromptBlob, genPromptBlob.length);
  db.prepare("INSERT INTO gen_metadata VALUES (?, ?, ?)").run(2, genGatewayBlob, genGatewayBlob.length);
  db.prepare("INSERT INTO steps VALUES (?, ?, ?, ?, ?, ?)").run(
    1,
    3,
    3,
    errorDetailsBlob,
    renderInfoBlob,
    taskDetailsBlob,
  );

  const genRows = db.prepare("SELECT rowid AS __rowid__, * FROM gen_metadata ORDER BY idx").all()
    .map((row) => decodeGenMetadataRow(row));
  const errorRenderRows = blobRows(db, "steps", ["error_details", "render_info", "task_details"])
    .map((row) => decodeErrorRenderRow(row));

  const generationPanel = buildWorkflowImportedGenerationMetadataPanel({
    trajectoryId: "trajectory-stage56",
    rows: genRows,
  });
  const errorRenderPanel = buildWorkflowImportedErrorRenderInfoPanel({
    trajectoryId: "trajectory-stage56",
    workspaceRoot: "/workspace/project",
    rows: errorRenderRows,
  });

  assert.ok(fs.existsSync(fixtureDbPath));
  assert.equal(genRows.length, 2);
  assert.equal(errorRenderRows.length, 3);
  assert.equal(generationPanel.schemaVersion, "ioi.workflow.imported-generation-metadata.v1");
  assert.equal(generationPanel.status, "blocked");
  assert.equal(generationPanel.rawPromptRetention, "never");
  assert.equal(generationPanel.rows.find((row) => row.kind === "prompt_context")?.retention, "summary_only");
  assert.equal(generationPanel.rows.find((row) => row.kind === "gateway_request")?.status, "blocked");
  assert.equal(errorRenderPanel.schemaVersion, "ioi.workflow.imported-error-render-info.v1");
  assert.equal(errorRenderPanel.status, "blocked");
  assert.equal(errorRenderPanel.rawStackRetention, "never");
  assert.ok(errorRenderPanel.rows.some((row) => row.policyRefs.includes("policy:error_render.block.external_render_uri")));
  assert.ok(errorRenderPanel.rows.some((row) => row.policyRefs.includes("policy:error_render.block.workspace_path_escape")));

  const serializedPanels = JSON.stringify({ generationPanel, errorRenderPanel });
  for (const canary of [
    "PRIVATE_STAGE56_PROMPT",
    "sk-stage56promptsecret",
    "ya29.stage56gatewaysecret",
    "STACK_STAGE56_CANARY",
    "stage56-error-message",
    "ya29.stage56stacksecret",
  ]) {
    assert.ok(!serializedPanels.includes(canary), `panel leaked ${canary}`);
  }

  const proof = {
    schemaVersion: "ioi.autopilot.stage56.sqlite-extended-import-projections-proof.v1",
    passed: true,
    generatedAt: new Date().toISOString(),
    fixtureDbPath,
    checks: {
      realSqliteDatabaseCreated: fs.existsSync(fixtureDbPath),
      genMetadataRowsDecoded: genRows.length === 2,
      errorRenderRowsDecoded: errorRenderRows.length === 3,
      generationPanelRedactsPromptAndGateway: generationPanel.status === "blocked" &&
        generationPanel.rawPromptRetention === "never",
      errorRenderPanelBlocksUnsafeRows: errorRenderPanel.status === "blocked" &&
        errorRenderPanel.rawStackRetention === "never",
      canariesAbsent: true,
    },
    decodedRows: {
      genRows,
      errorRenderRows,
    },
    generationPanel,
    errorRenderPanel,
  };

  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  db.close();
}

function decodeGenMetadataRow(row) {
  const blob = Buffer.from(row.data);
  const scan = scanWire(blob);
  const field = (fieldNumber) => scan.find((entry) => entry.fieldNumber === fieldNumber)?.stringPreview ?? null;
  const kind = normalizeKind(valueAfter([field(1) ?? ""], "kind=")) || "prompt_context";
  const url = kind === "gateway_request" ? valueAfter([field(2) ?? ""], "url=") : null;
  const authorization = kind === "gateway_request" ? valueAfter([field(3) ?? ""], "Authorization=") : null;
  return {
    sourceRowId: row.__rowid__,
    kind,
    text: kind === "prompt_context" ? field(4) : null,
    modelId: kind === "prompt_context" ? valueAfter([field(2) ?? ""], "model=") : null,
    routeId: kind === "prompt_context" ? valueAfter([field(3) ?? ""], "route=") : null,
    provider: kind === "prompt_context" ? "local-native" : null,
    tokenCounts: { input: scan.find((entry) => entry.fieldNumber === 5)?.varintValue ?? null },
    gatewayUrl: url,
    headers: authorization ? { Authorization: authorization } : null,
    receiptRefs: [`receipt:sqlite:gen_metadata:${row.__rowid__}`],
  };
}

function normalizeKind(value) {
  const text = String(value || "");
  return [
    "prompt_context",
    "gateway_request",
    "thinking_trace",
    "assistant_output",
    "model_route",
    "token_usage",
  ].find((kind) => text.startsWith(kind)) ?? null;
}

function decodeErrorRenderRow(row) {
  const field = (fieldNumber) => row.fieldStrings[fieldNumber] ?? null;
  return {
    sourceRowId: row.rowid,
    stepIndex: row.stepIndex,
    column: row.column,
    code: valueAfter([field(1) ?? ""], "code="),
    message: valueAfter([field(2) ?? ""], "message="),
    stack: valueAfter([field(3) ?? ""], "stack="),
    diagnosticPath: valueAfter([field(row.column === "error_details" ? 4 : 3) ?? ""], "path="),
    renderKind: valueAfter([field(1) ?? ""], "renderKind="),
    artifactRef: valueAfter([field(2) ?? ""], "artifact="),
    targetUri: valueAfter([field(3) ?? ""], "target="),
    receiptRefs: row.column === "task_details" ? [] : [`receipt:sqlite:steps:${row.rowid}:${row.column}`],
  };
}

function blobRows(db, sourceTable, columns) {
  const rows = db.prepare(`SELECT rowid AS __rowid__, * FROM ${sourceTable} ORDER BY rowid`).all();
  return rows.flatMap((row) => columns.flatMap((column) => {
    const value = row[column];
    if (!value) return [];
    const blob = Buffer.from(value);
    if (blob.length === 0) return [];
    const scan = scanWire(blob);
    return [{
      sourceTable,
      column,
      rowid: row.__rowid__,
      stepIndex: row.idx,
      rawBlobRef: `sqlite://${sourceTable}/${row.__rowid__}/${column}`,
      byteLength: blob.length,
      topLevelFields: unique(scan.map((entry) => entry.fieldNumber)),
      fieldStrings: Object.fromEntries(scan
        .filter((entry) => entry.stringPreview)
        .map((entry) => [entry.fieldNumber, entry.stringPreview])),
      printableStrings: printableStrings(blob),
    }];
  }));
}

function valueAfter(strings, prefix) {
  const value = strings.find((entry) => entry.includes(prefix));
  if (!value) return null;
  return value.slice(value.indexOf(prefix) + prefix.length);
}

function scanWire(buffer) {
  const entries = [];
  let offset = 0;
  while (offset < buffer.length) {
    const key = readVarint(buffer, offset);
    if (!key) break;
    offset = key.nextOffset;
    const fieldNumber = Number(key.value >> 3n);
    const wireType = Number(key.value & 7n);
    if (fieldNumber <= 0 || wireType > 5) break;
    const entry = { fieldNumber, wireType, offset: key.offset };
    if (wireType === 0) {
      const value = readVarint(buffer, offset);
      if (!value) break;
      offset = value.nextOffset;
      entry.varintValue = Number(value.value);
    } else if (wireType === 2) {
      const length = readVarint(buffer, offset);
      if (!length) break;
      offset = length.nextOffset;
      const end = offset + Number(length.value);
      if (end > buffer.length) break;
      entry.length = end - offset;
      entry.stringPreview = buffer.subarray(offset, end).toString("utf8").replace(/[^\x20-\x7e]+/g, " ").trim();
      offset = end;
    } else if (wireType === 1) {
      offset += 8;
    } else if (wireType === 5) {
      offset += 4;
    } else {
      break;
    }
    entries.push(entry);
  }
  return entries;
}

function readVarint(buffer, offset) {
  let result = 0n;
  let shift = 0n;
  const start = offset;
  while (offset < buffer.length && shift < 70n) {
    const byte = BigInt(buffer[offset]);
    result |= (byte & 0x7fn) << shift;
    offset += 1;
    if ((byte & 0x80n) === 0n) return { value: result, offset: start, nextOffset: offset };
    shift += 7n;
  }
  return null;
}

function fieldBytes(fieldNumber, bytes) {
  return Buffer.concat([
    varint(BigInt((fieldNumber << 3) | 2)),
    varint(BigInt(bytes.length)),
    bytes,
  ]);
}

function fieldVarint(fieldNumber, value) {
  return Buffer.concat([varint(BigInt((fieldNumber << 3) | 0)), varint(BigInt(value))]);
}

function varint(value) {
  let remaining = BigInt(value);
  const bytes = [];
  while (remaining >= 0x80n) {
    bytes.push(Number((remaining & 0x7fn) | 0x80n));
    remaining >>= 7n;
  }
  bytes.push(Number(remaining));
  return Buffer.from(bytes);
}

function message(parts) {
  return Buffer.concat(parts);
}

function stringBytes(value) {
  return Buffer.from(value, "utf8");
}

function printableStrings(blob) {
  return unique([...blob.toString("utf8").matchAll(/[\x20-\x7e]{4,}/g)].map((match) => match[0]));
}

function unique(values) {
  return [...new Set(values)];
}
