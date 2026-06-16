import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

import { assertModelMountingReceiptWriteBound } from "./receipt-write-guards.mjs";

const SECRET_REDACTION = "[REDACTED]";
const RUNTIME_MODEL_MOUNT_RECEIPT_STATE_COMMIT_SCHEMA_VERSION =
  "ioi.runtime_model_mount_receipt_state_commit.v1";
const RUNTIME_STATE_STORAGE_BACKEND_REF = "storage://runtime-agentgres/local-json";

function stableHash(value) {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

function stableStringify(value) {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(",")}}`;
}

function redact(value) {
  if (typeof value === "string" && value.startsWith("vault://")) return SECRET_REDACTION;
  if (!value || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(redact);
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      /tokenHash|tokenValue|secret|material|apiKey|authorization|header|privateKey|accessToken|refreshToken/i.test(key)
        ? SECRET_REDACTION
        : redact(item),
    ]),
  );
}

function emitRemoteBoundaryEvent(baseUrl, route, payload) {
  if (!baseUrl || typeof fetch !== "function") return;
  const url = `${String(baseUrl).replace(/\/+$/, "")}/${String(route).replace(/^\/+/, "")}`;
  const body = JSON.stringify(redact(payload));
  setTimeout(() => {
    fetch(url, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body,
    }).catch(() => {
      // Audit mirroring is best-effort so local runtime progress is not blocked.
    });
  }, 0);
}

function safeFileName(value) {
  return String(value).replace(/[^a-z0-9._-]+/gi, "_");
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function listJson(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => path.join(dir, file));
}

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function notFound(message, details) {
  return runtimeError({ status: 404, code: "not_found", message, details });
}

export class AgentgresModelMountingStore {
  constructor({ stateDir, commitRuntimeModelMountReceiptState = null }) {
    this.stateDir = path.resolve(stateDir);
    this.commitRuntimeModelMountReceiptState = commitRuntimeModelMountReceiptState;
  }

  ensureDirs() {
    for (const dir of [
      "model-artifacts",
      "model-endpoints",
      "model-instances",
      "model-routes",
      "model-providers",
      "model-downloads",
      "model-catalog-providers",
      "oauth-sessions",
      "oauth-states",
      "runtime-preferences",
      "runtime-engine-profiles",
      "provider-health",
      "models",
      "backend-logs",
      "server-logs",
      "projections",
      "lifecycle-events",
      "tokens",
      "vault-refs",
      "mcp-servers",
      "workflow-bindings",
      "receipts",
    ]) {
      fs.mkdirSync(path.join(this.stateDir, dir), { recursive: true });
    }
  }

  writeMap(dir, map) {
    throw runtimeError({
      status: 403,
      code: "model_mount_store_map_write_retired",
      message: "Model-mounting store map persistence is retired; use Rust Agentgres record-state commits per record.",
      details: {
        dir: dir ?? null,
        record_count: typeof map?.size === "number" ? map.size : null,
        canonical_persistence: "rust_agentgres_record_state_commit",
      },
    });
  }

  writeReceipt(receipt) {
    assertModelMountingReceiptWriteBound(receipt);
    const commit = this.commitModelMountReceiptState(receipt);
    emitRemoteBoundaryEvent(process.env.IOI_AGENTGRES_URL, "/operations", {
      port: "AgentgresModelMountingStorePort",
      kind: "receipt.write",
      objectId: receipt.id,
      receiptId: receipt.id,
      receiptKind: receipt.kind,
      redaction: receipt.redaction,
      evidenceRefs: receipt.evidenceRefs,
      commitHash: commit.commit_hash,
    });
    return commit;
  }

  listReceipts() {
    const receiptFiles = listJson(path.join(this.stateDir, "receipts"));
    return receiptFiles
      .map((filePath) => readJson(filePath))
      .sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? "")));
  }

  getReceipt(receiptId) {
    const receipt = this.listReceipts().find((item) => item.id === receiptId);
    if (!receipt) throw notFound(`Receipt not found: ${receiptId}`, { receipt_id: receiptId });
    return receipt;
  }

  writeProjection(name, projection, options = {}) {
    assertRustAuthoredModelMountProjection(name, projection, options?.rustProjection);
    writeJson(path.join(this.stateDir, "projections", `${safeFileName(name)}.json`), projection);
    emitRemoteBoundaryEvent(process.env.IOI_AGENTGRES_URL, "/operations", {
      port: "AgentgresModelMountingStorePort",
      kind: "projection.write",
      objectId: name,
      projection: name,
      watermark: projection?.watermark ?? null,
      source: projection?.source ?? null,
      rustSource: options?.rustProjection?.source ?? null,
      rustBackend: options?.rustProjection?.backend ?? null,
      evidenceRefs: options?.rustProjection?.evidence_refs ?? [],
    });
  }

  readProjection(name) {
    throw runtimeError({
      status: 403,
      code: "model_mount_projection_cache_read_retired",
      message: "Model-mounting projection cache reads are retired; use Rust daemon-core projection planning.",
      details: {
        projection: name ?? null,
        canonical_projection: "rust_daemon_core_model_mount_projection_plan",
      },
    });
  }

  adapterStatus() {
    return {
      port: "AgentgresModelMountingStorePort",
      implementation: "rust_plan_gated_receipt_projection_adapter",
      remoteAdapter: process.env.IOI_AGENTGRES_URL
        ? { configured: true, urlHash: stableHash(process.env.IOI_AGENTGRES_URL) }
        : { configured: false, failClosed: true },
      evidenceRefs: [
        "agentgres_receipt_projection_boundary",
        "typed_agentgres_projection_boundary",
        "model_mount_projection_cache_read_retired",
        "rust_daemon_core_model_mount_projection_required",
      ],
    };
  }

  commitModelMountReceiptState(receipt) {
    if (typeof this.commitRuntimeModelMountReceiptState !== "function") {
      const error = new Error("Model-mount receipt persistence requires Rust Agentgres receipt-state commit.");
      error.status = 500;
      error.code = "model_mount_receipt_state_commit_unconfigured";
      error.details = { receipt_id: receipt?.id ?? null };
      throw error;
    }
    return normalizeModelMountReceiptStateCommit(this.commitRuntimeModelMountReceiptState({
      schema_version: RUNTIME_MODEL_MOUNT_RECEIPT_STATE_COMMIT_SCHEMA_VERSION,
      receipt_id: receipt.id,
      operation_kind: "model_mount.receipt.write",
      storage_backend_ref: RUNTIME_STATE_STORAGE_BACKEND_REF,
      receipt,
      receipt_refs: [receipt.id],
    }));
  }
}

function assertRustAuthoredModelMountProjection(name, projection, rustProjection) {
  const missing = [];
  const mismatches = [];
  const evidenceRefs = Array.isArray(rustProjection?.evidence_refs) ? rustProjection.evidence_refs : [];

  if (name !== "model-mounting-canonical") mismatches.push("projection_name");
  if (!rustProjection || typeof rustProjection !== "object") missing.push("rust_projection_plan");
  if (rustProjection?.source !== "rust_daemon_core.model_mount.read_projection") {
    mismatches.push("rust_projection.source");
  }
  if (rustProjection?.projection_kind !== "projection") {
    mismatches.push("rust_projection.projection_kind");
  }
  if (rustProjection?.projection !== projection) {
    mismatches.push("rust_projection.projection_identity");
  }
  if (projection?.source !== "agentgres_model_mounting_projection") {
    mismatches.push("projection.source");
  }
  for (const evidenceRef of [
    "rust_daemon_core_model_mount_projection",
    "agentgres_model_mount_read_truth",
    "model_mount_js_read_projection_authoring_retired",
  ]) {
    if (!evidenceRefs.includes(evidenceRef)) missing.push(`evidence_refs.${evidenceRef}`);
  }

  if (missing.length > 0 || mismatches.length > 0) {
    throw runtimeError({
      status: 403,
      code: "model_mount_projection_direct_write_forbidden",
      message: "Model-mounting projection persistence requires a Rust daemon-core projection plan.",
      details: {
        projection: name ?? null,
        missing,
        mismatches,
        canonical_persistence: "rust_daemon_core_model_mount_projection_plan",
      },
    });
  }
}

function normalizeModelMountReceiptStateCommit(value = {}) {
  const commit = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const storageRecord = commit.storage_record && typeof commit.storage_record === "object"
    ? commit.storage_record
    : commit.record?.record ?? {};
  const required = {
    receipt_id: commit.receipt_id ?? commit.record?.receipt_id,
    object_ref: commit.object_ref ?? storageRecord.object_ref,
    content_hash: commit.content_hash ?? storageRecord.content_hash,
    admission_hash: commit.admission_hash ?? storageRecord.admission?.admission_hash,
    commit_hash: commit.commit_hash ?? commit.record?.commit_hash,
    written_record: commit.written_record,
  };
  for (const [field, value] of Object.entries(required)) {
    if (!value) {
      const error = new Error(`Rust model-mount receipt state commit returned without ${field}.`);
      error.status = 502;
      error.code = "model_mount_receipt_state_commit_invalid";
      error.details = { missing: field };
      throw error;
    }
  }
  return {
    ...commit,
    storage_record: storageRecord,
    receipt_id: required.receipt_id,
    object_ref: required.object_ref,
    content_hash: required.content_hash,
    admission_hash: required.admission_hash,
    commit_hash: required.commit_hash,
    written_record: required.written_record,
  };
}
