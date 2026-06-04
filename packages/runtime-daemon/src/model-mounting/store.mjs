import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

import {
  modelMountInstanceLifecycleBindingIssues,
  modelMountProviderKindRequiresRustInstanceLifecycle,
} from "./model-instance-lifecycle.mjs";

const SECRET_REDACTION = "[REDACTED]";

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
  constructor({ stateDir, appendOperation }) {
    this.stateDir = path.resolve(stateDir);
    this.appendOperation = appendOperation;
  }

  ensureDirs() {
    for (const dir of [
      "model-artifacts",
      "model-endpoints",
      "model-instances",
      "model-routes",
      "model-providers",
      "model-backends",
      "backend-processes",
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
    for (const record of map.values()) {
      writeJson(path.join(this.stateDir, dir, `${safeFileName(record.id)}.json`), record);
    }
  }

  writeReceipt(receipt) {
    assertAcceptedModelInvocationReceiptBound(receipt);
    assertModelInstanceLifecycleReceiptBound(receipt);
    writeJson(path.join(this.stateDir, "receipts", `${receipt.id}.json`), receipt);
    emitRemoteBoundaryEvent(process.env.IOI_AGENTGRES_URL, "/operations", {
      port: "AgentgresModelMountingStorePort",
      kind: "receipt.write",
      objectId: receipt.id,
      receiptId: receipt.id,
      receiptKind: receipt.kind,
      redaction: receipt.redaction,
      evidenceRefs: receipt.evidenceRefs,
    });
    this.appendOperation?.(receipt.kind, {
      objectId: receipt.id,
      receiptId: receipt.id,
      kind: receipt.kind,
      evidenceRefs: receipt.evidenceRefs,
      details: receipt.details,
    });
  }

  listReceipts() {
    const receiptFiles = listJson(path.join(this.stateDir, "receipts"));
    return receiptFiles
      .map((filePath) => readJson(filePath))
      .sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? "")));
  }

  getReceipt(receiptId) {
    const receipt = this.listReceipts().find((item) => item.id === receiptId);
    if (!receipt) throw notFound(`Receipt not found: ${receiptId}`, { receiptId });
    return receipt;
  }

  writeProjection(name, projection) {
    writeJson(path.join(this.stateDir, "projections", `${safeFileName(name)}.json`), projection);
    emitRemoteBoundaryEvent(process.env.IOI_AGENTGRES_URL, "/operations", {
      port: "AgentgresModelMountingStorePort",
      kind: "projection.write",
      objectId: name,
      projection: name,
      watermark: projection?.watermark ?? null,
      source: projection?.source ?? null,
    });
  }

  readProjection(name) {
    const filePath = path.join(this.stateDir, "projections", `${safeFileName(name)}.json`);
    if (!fs.existsSync(filePath)) {
      throw notFound(`Projection not found: ${name}`, { projection: name });
    }
    return readJson(filePath);
  }

  adapterStatus() {
    return {
      port: "AgentgresModelMountingStorePort",
      implementation: "local_operation_log",
      remoteAdapter: process.env.IOI_AGENTGRES_URL
        ? { configured: true, urlHash: stableHash(process.env.IOI_AGENTGRES_URL) }
        : { configured: false, failClosed: true },
      evidenceRefs: ["agentgres_canonical_operation_log", "typed_agentgres_projection_boundary"],
    };
  }
}

const ACCEPTED_MODEL_INVOCATION_RECEIPT_KINDS = new Set([
  "model_invocation",
  "model_invocation_coalesced",
  "model_invocation_stream_completed",
]);

const MODEL_INSTANCE_LIFECYCLE_RECEIPT_STATUSES = new Map([
  ["model_load", "loaded"],
  ["model_unload", "unloaded"],
  ["model_idle_evict", "evicted"],
  ["model_supersede", "superseded"],
]);

function assertAcceptedModelInvocationReceiptBound(receipt) {
  if (!ACCEPTED_MODEL_INVOCATION_RECEIPT_KINDS.has(receipt?.kind)) return;
  const details = receipt?.details && typeof receipt.details === "object" ? receipt.details : {};
  const operationRef = optionalNonEmptyString(details.modelMountAgentgresOperationRef);
  const missing = [];
  if (!optionalNonEmptyString(details.modelMountReceiptBindingRef)) missing.push("modelMountReceiptBindingRef");
  if (!optionalNonEmptyString(details.modelMountAcceptedReceiptAppendHash)) {
    missing.push("modelMountAcceptedReceiptAppendHash");
  }
  if (!operationRef) missing.push("modelMountAgentgresOperationRef");
  if (!optionalNonEmptyString(details.modelMountAgentgresAdmissionHash)) {
    missing.push("modelMountAgentgresAdmissionHash");
  }
  if (!optionalNonEmptyString(details.modelMountStepModuleInvocation?.input?.state_root_before)) {
    missing.push("modelMountStepModuleInvocation.input.state_root_before");
  }
  if (!Array.isArray(details.modelMountStepModuleResult?.agentgres_operation_refs)) {
    missing.push("modelMountStepModuleResult.agentgres_operation_refs");
  }
  if (!optionalNonEmptyString(details.modelMountStepModuleResult?.state_root_after)) {
    missing.push("modelMountStepModuleResult.state_root_after");
  }
  if (!optionalNonEmptyString(details.modelMountStepModuleResult?.resulting_head)) {
    missing.push("modelMountStepModuleResult.resulting_head");
  }

  const mismatches = [];
  if (
    operationRef &&
    !details.modelMountStepModuleResult?.agentgres_operation_refs?.includes(operationRef)
  ) {
    mismatches.push("modelMountAgentgresOperationRef");
  }
  if (
    operationRef &&
    optionalNonEmptyString(details.modelMountAgentgresAdmission?.operation_ref) !== operationRef
  ) {
    mismatches.push("modelMountAgentgresAdmission.operation_ref");
  }
  if (
    optionalNonEmptyString(details.modelMountAgentgresStateRootBefore) !==
    optionalNonEmptyString(details.modelMountStepModuleInvocation?.input?.state_root_before)
  ) {
    mismatches.push("modelMountAgentgresStateRootBefore");
  }
  if (
    optionalNonEmptyString(details.modelMountAgentgresStateRootAfter) !==
    optionalNonEmptyString(details.modelMountStepModuleResult?.state_root_after)
  ) {
    mismatches.push("modelMountAgentgresStateRootAfter");
  }
  if (
    optionalNonEmptyString(details.modelMountAgentgresResultingHead) !==
    optionalNonEmptyString(details.modelMountStepModuleResult?.resulting_head)
  ) {
    mismatches.push("modelMountAgentgresResultingHead");
  }

  if (missing.length > 0 || mismatches.length > 0) {
    throw runtimeError({
      status: 409,
      code: "model_mount_invocation_receipt_direct_append_forbidden",
      message: "Model invocation receipts require Rust receipt_binder and Agentgres admission before JS store persistence.",
      details: {
        receiptId: receipt?.id ?? null,
        receiptKind: receipt?.kind ?? null,
        missing,
        mismatches,
      },
    });
  }
}

function assertModelInstanceLifecycleReceiptBound(receipt) {
  if (receipt?.kind !== "model_lifecycle") return;
  const details = receipt?.details && typeof receipt.details === "object" ? receipt.details : {};
  const status = MODEL_INSTANCE_LIFECYCLE_RECEIPT_STATUSES.get(details.operation);
  if (!status) return;
  const providerKind = optionalNonEmptyString(details.providerKind ?? details.provider_kind);
  const missing = [];
  const mismatches = [];
  if (!providerKind && optionalNonEmptyString(details.providerId)) {
    missing.push("providerKind");
  }
  if (!providerKind || !modelMountProviderKindRequiresRustInstanceLifecycle(providerKind)) {
    if (missing.length > 0) {
      throw runtimeError({
        status: 409,
        code: "model_mount_instance_lifecycle_receipt_direct_append_forbidden",
        message: "Model instance lifecycle receipts require provider kind before JS store persistence.",
        details: {
          receiptId: receipt?.id ?? null,
          receiptKind: receipt?.kind ?? null,
          operation: details.operation ?? null,
          missing,
          mismatches,
        },
      });
    }
    return;
  }
  const issues = modelMountInstanceLifecycleBindingIssues(details, {
    prefix: details.instanceId ?? details.operation ?? "model_lifecycle",
    status,
  });
  missing.push(...issues.missing);
  mismatches.push(...issues.mismatches);
  if (missing.length > 0 || mismatches.length > 0) {
    throw runtimeError({
      status: 409,
      code: "model_mount_instance_lifecycle_receipt_direct_append_forbidden",
      message: "Model instance lifecycle receipts for migrated local providers require Rust model_mount lifecycle bindings before JS store persistence.",
      details: {
        receiptId: receipt?.id ?? null,
        receiptKind: receipt?.kind ?? null,
        operation: details.operation ?? null,
        providerKind,
        missing,
        mismatches,
      },
    });
  }
}

function optionalNonEmptyString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}
