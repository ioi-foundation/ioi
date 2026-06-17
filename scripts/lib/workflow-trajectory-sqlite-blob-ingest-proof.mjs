#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-trajectory-sqlite-blob-ingest-proof.mjs <output-path>");
}

const { buildWorkflowTrajectoryImportAudit } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-trajectory-import-audit.ts"
);

const outputDir = path.dirname(outputPath);
fs.mkdirSync(outputDir, { recursive: true });

const fixtureDbPath = path.join(outputDir, "antigravity-trajectory-fixture.db");
fs.rmSync(fixtureDbPath, { force: true });

const workspaceUri = `file://${process.cwd()}/packages/hypervisor-workbench/src/runtime/workflow-trajectory-import-audit.ts`;
const stepMetadataBlob = message([
  fieldVarint(3, 1),
  fieldBytes(12, stringBytes("cascade-stage43")),
  fieldBytes(20, message([
    fieldBytes(1, stringBytes("step-stage43-tool")),
    fieldBytes(4, stringBytes("trajectory-stage43")),
  ])),
]);
const stepPayloadBlob = message([
  fieldVarint(1, 3),
  fieldVarint(4, 3),
  fieldBytes(19, message([
    fieldBytes(2, stringBytes("Open traced workflow and inspect rows")),
    fieldBytes(4, message([
      fieldBytes(12, stringBytes(workspaceUri)),
      fieldBytes(13, stringBytes(workspaceUri)),
    ])),
  ])),
  fieldBytes(31, message([
    fieldBytes(1, stringBytes("replace_file_content")),
    fieldBytes(2, stringBytes("{\"target\":\"README.md\"}")),
    fieldVarint(4, 0),
  ])),
]);
const executorMetadataBlob = message([
  fieldVarint(1, 42),
  fieldVarint(2, 1),
  fieldVarint(3, 3),
  fieldBytes(9, stringBytes("cascade-stage43")),
  fieldBytes(10, message([
    fieldBytes(8, message([
      fieldBytes(3, message([
        fieldBytes(4, stringBytes("echo")),
        fieldBytes(4, stringBytes("date")),
      ])),
      fieldBytes(4, message([
        fieldBytes(4, stringBytes("curl")),
      ])),
    ])),
  ])),
]);
const trajectoryMetadataBlob = message([
  fieldBytes(1, message([
    fieldBytes(1, stringBytes(workspaceUri)),
    fieldBytes(4, stringBytes("master")),
  ])),
  fieldBytes(3, stringBytes("trajectory-stage43")),
  fieldBytes(7, stringBytes(workspaceUri)),
]);

const db = new DatabaseSync(fixtureDbPath);
try {
  db.exec(`
    CREATE TABLE trajectory_meta (
      trajectory_id TEXT PRIMARY KEY,
      trajectory_type INTEGER,
      source INTEGER
    );
    CREATE TABLE steps (
      idx INTEGER PRIMARY KEY,
      step_type INTEGER,
      status INTEGER,
      metadata BLOB,
      step_payload BLOB,
      error_details BLOB,
      permissions BLOB,
      task_details BLOB,
      render_info BLOB
    );
    CREATE TABLE executor_metadata (
      id INTEGER PRIMARY KEY,
      data BLOB
    );
    CREATE TABLE trajectory_metadata_blob (
      id INTEGER PRIMARY KEY,
      data BLOB
    );
    CREATE TABLE parent_references (
      id INTEGER PRIMARY KEY,
      data BLOB
    );
    CREATE TABLE battle_mode_infos (
      id INTEGER PRIMARY KEY,
      data BLOB
    );
  `);
  db.prepare("INSERT INTO trajectory_meta VALUES (?, ?, ?)").run("trajectory-stage43", 0, 1);
  db.prepare("INSERT INTO steps VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)")
    .run(1, 3, 3, stepMetadataBlob, stepPayloadBlob);
  db.prepare("INSERT INTO executor_metadata VALUES (?, ?)").run(1, executorMetadataBlob);
  db.prepare("INSERT INTO trajectory_metadata_blob VALUES (?, ?)").run(1, trajectoryMetadataBlob);

  const tableNames = db.prepare(`
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
    ORDER BY name
  `).all().map((row) => row.name);

  const blobInventory = [
    ...blobRows(db, "steps", ["metadata", "step_payload", "error_details", "permissions", "task_details", "render_info"]),
    ...blobRows(db, "executor_metadata", ["data"]),
    ...blobRows(db, "trajectory_metadata_blob", ["data"]),
    ...blobRows(db, "parent_references", ["data"]),
    ...blobRows(db, "battle_mode_infos", ["data"]),
  ];

  const stepPayload = blobInventory.find((row) => row.sourceTable === "steps" && row.column === "step_payload");
  const executorData = blobInventory.find((row) => row.sourceTable === "executor_metadata" && row.column === "data");
  const trajectoryData = blobInventory.find((row) => row.sourceTable === "trajectory_metadata_blob" && row.column === "data");

  const auditPanel = buildWorkflowTrajectoryImportAudit({
    currentWorkspaceRoot: process.cwd(),
    records: blobInventory.map((row, index) => ({
      sourceTable: row.sourceTable,
      fieldPath: `${row.sourceTable}.${row.column}`,
      sequence: index + 1,
      stepId: row.stepId,
      decodedType: decodedTypeForBlob(row),
      workspaceUri: row.workspaceUris[0] ?? null,
      payload: {
        rawBlobRef: row.rawBlobRef,
        byteLength: row.byteLength,
        wireTags: row.topLevelFields,
        workspaceUris: row.workspaceUris,
        printableStrings: row.printableStrings.slice(0, 8),
      },
    })),
  });

  assert.deepEqual(tableNames, [
    "battle_mode_infos",
    "executor_metadata",
    "parent_references",
    "steps",
    "trajectory_meta",
    "trajectory_metadata_blob",
  ]);
  assert.ok(stepPayload);
  assert.ok(executorData);
  assert.ok(trajectoryData);
  assert.deepEqual(stepPayload.topLevelFields, [1, 4, 19, 31]);
  assert.ok(stepPayload.nestedFields.some((entry) => entry.path === "31" && entry.fields.includes(1)));
  assert.ok(executorData.topLevelFields.includes(10));
  assert.ok(trajectoryData.topLevelFields.includes(1));
  assert.ok(trajectoryData.topLevelFields.includes(3));
  assert.ok(trajectoryData.topLevelFields.includes(7));
  assert.equal(auditPanel.schemaVersion, "ioi.workflow.trajectory-import-audit.v1");
  assert.equal(auditPanel.applyMode, "plan_only");
  assert.equal(auditPanel.status, "needs_review");
  assert.ok(auditPanel.missingReceiptCount >= 3);
  assert.ok(auditPanel.workspaceUriCount >= 1);

  const proof = {
    schemaVersion: "ioi.autopilot.stage43.trajectory-sqlite-blob-ingest-proof.v1",
    passed: true,
    generatedAt: new Date().toISOString(),
    fixtureDbPath,
    checks: {
      realSqliteDatabaseCreated: fs.existsSync(fixtureDbPath),
      requiredTablesPresent: tableNames.includes("steps") &&
        tableNames.includes("executor_metadata") &&
        tableNames.includes("trajectory_metadata_blob"),
      blobColumnsInventoried: blobInventory.length >= 4,
      stepPayloadWireTagsMapped: JSON.stringify(stepPayload.topLevelFields) === JSON.stringify([1, 4, 19, 31]),
      nestedToolCallFieldMapped: stepPayload.nestedFields.some((entry) => entry.path === "31" && entry.fields.includes(1)),
      executorConfigTagMapped: executorData.topLevelFields.includes(10),
      trajectoryWorkspaceTagsMapped: [1, 3, 7].every((tag) => trajectoryData.topLevelFields.includes(tag)),
      feedsAuditProjection: auditPanel.status === "needs_review" && auditPanel.missingReceiptCount >= 3,
    },
    tableNames,
    blobInventory,
    auditPanel,
  };

  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  db.close();
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
      stepId: sourceTable === "steps" ? `step-${row.idx}-${column}` : `${sourceTable}-${row.__rowid__}`,
      rawBlobRef: `sqlite://${sourceTable}/${row.__rowid__}/${column}`,
      byteLength: blob.length,
      topLevelFields: unique(scan.map((entry) => entry.fieldNumber)),
      nestedFields: nestedWireFields(scan),
      printableStrings: printableStrings(blob),
      workspaceUris: workspaceUrisFromScan(scan),
    }];
  }));
}

function decodedTypeForBlob(row) {
  if (row.sourceTable === "steps" && row.column === "metadata") return "StepMetadata";
  if (row.sourceTable === "steps" && row.column === "step_payload") {
    return row.topLevelFields.includes(31) ? "TrajectoryStepToolCall" : "TrajectoryStepMessage";
  }
  if (row.sourceTable === "executor_metadata") return "ExecutorMetadata";
  if (row.sourceTable === "trajectory_metadata_blob") return "TrajectoryMetadata";
  return "UnknownTrajectoryBlob";
}

function scanWire(buffer, depth = 0) {
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
    } else if (wireType === 1) {
      offset += 8;
    } else if (wireType === 2) {
      const length = readVarint(buffer, offset);
      if (!length) break;
      offset = length.nextOffset;
      const end = offset + Number(length.value);
      if (end > buffer.length) break;
      const bytes = buffer.subarray(offset, end);
      entry.length = bytes.length;
      entry.stringPreview = stringPreview(bytes);
      if (depth < 2) {
        const nested = scanWire(bytes, depth + 1);
        if (nested.length) entry.nested = nested;
      }
      offset = end;
    } else if (wireType === 5) {
      offset += 4;
    } else {
      break;
    }
    entries.push(entry);
  }
  return entries;
}

function nestedWireFields(entries, prefix = "") {
  const fields = [];
  for (const entry of entries) {
    if (!entry.nested?.length) continue;
    const path = prefix ? `${prefix}.${entry.fieldNumber}` : String(entry.fieldNumber);
    fields.push({ path, fields: unique(entry.nested.map((nested) => nested.fieldNumber)) });
    fields.push(...nestedWireFields(entry.nested, path));
  }
  return fields;
}

function stringPreviewsFromScan(entries) {
  const previews = [];
  for (const entry of entries) {
    if (entry.stringPreview && !entry.nested?.length) previews.push(entry.stringPreview);
    if (entry.nested?.length) previews.push(...stringPreviewsFromScan(entry.nested));
  }
  return previews;
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

function stringPreview(bytes) {
  const text = bytes.toString("utf8").replace(/[^\x20-\x7e]+/g, " ").trim();
  return text.length >= 4 ? text.slice(0, 120) : null;
}

function printableStrings(blob) {
  return unique([...blob.toString("utf8").matchAll(/[\x20-\x7e]{4,}/g)].map((match) => match[0]));
}

function workspaceUrisFromScan(entries) {
  return unique(stringPreviewsFromScan(entries).flatMap((preview) =>
    [...preview.matchAll(/file:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+/g)].map((match) => match[0])
  ));
}

function unique(values) {
  return [...new Set(values)];
}
