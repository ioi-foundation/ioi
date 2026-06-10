import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const SECRET_REDACTION = "[REDACTED]";

export function safeId(value) {
  return (
    String(value)
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, ".")
      .replace(/^\.+|\.+$/g, "") || "item"
  );
}

export function safeFileName(value) {
  return String(value).replace(/[^a-z0-9._-]+/gi, "_");
}

export function isExecutable(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

export function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

export function listJson(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => path.join(dir, file));
}

export function notFound(message, details) {
  return runtimeError({ status: 404, code: "not_found", message, details });
}

export function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

export function stableHash(value) {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

export function stableStringify(value) {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(",")}}`;
}

export function shouldRedactKey(key) {
  if (
    [
      "tokenCount",
      "toolReceiptIds",
      "input_tokens",
      "output_tokens",
      "total_tokens",
      "providerAuthHeaderNames",
      "catalogAuth",
      "catalogAuthConfigured",
      "catalogAuthResolved",
      "catalogAuthScheme",
      "catalogAuthHeaderNameHash",
      "catalogAuthEvidenceRefs",
      "oauthBoundary",
      "resolvedMaterial",
      "runtimeBound",
      "materialBound",
      "materialSource",
      "materialConfigured",
      "materialPersistence",
      "materialVaultRefHash",
      "vaultMaterialSource",
      "runtimeMaterialStatus",
    ].includes(key)
  ) {
    return false;
  }
  return /tokenHash|tokenValue|secret|material|apiKey|authorization|header|privateKey|accessToken|refreshToken/i.test(key);
}

export function redact(value) {
  if (typeof value === "string" && value.startsWith("vault://")) return SECRET_REDACTION;
  if (!value || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(redact);
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      shouldRedactKey(key) ? SECRET_REDACTION : redact(item),
    ]),
  );
}

export function emitRemoteBoundaryEvent(baseUrl, route, payload) {
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
      // Remote wallet/Agentgres boundaries are fail-closed at authorization time;
      // audit mirroring is best-effort so local runtime progress is not blocked.
    });
  }, 0);
}

export function fileSha256(filePath) {
  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(filePath, "r");
  try {
    const buffer = Buffer.allocUnsafe(8 * 1024 * 1024);
    while (true) {
      const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
  } finally {
    fs.closeSync(fd);
  }
  return `sha256:${hash.digest("hex")}`;
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

export async function fetchWithTimeout(url, { timeoutMs, headers = {}, method = "GET", body = undefined } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs ?? 5000);
  try {
    return await fetch(url, { method, headers, body, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

export function fileSizeIfExists(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return 0;
  try {
    return fs.statSync(filePath).size;
  } catch {
    return 0;
  }
}

export function normalizeNonNegativeInteger(value, fallback = 0) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return Math.floor(parsed);
}

export function normalizeOptionalBytes(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.floor(parsed);
}

export function truthy(value) {
  return value === true || value === "true" || value === 1 || value === "1";
}

export function matchesAny(scope, patterns) {
  return patterns.some((pattern) => {
    if (pattern === scope) return true;
    if (pattern.endsWith("*")) return scope.startsWith(pattern.slice(0, -1));
    return false;
  });
}

export function hashToken(tokenValue) {
  return crypto.createHash("sha256").update(tokenValue).digest("hex");
}

export function publicVaultRefs(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value).map(([key, vaultRef]) => [
      key,
      typeof vaultRef === "string" && vaultRef.startsWith("vault://")
        ? { redacted: true, hash: stableHash(vaultRef) }
        : SECRET_REDACTION,
    ]),
  );
}

export function publicVaultRefMetadata(metadata) {
  return {
    vaultRef: { redacted: true, hash: metadata.vaultRefHash },
    vaultRefHash: metadata.vaultRefHash,
    label: metadata.label ?? null,
    purpose: metadata.purpose ?? "provider.auth",
    source: metadata.source ?? "agentgres_local_vault_metadata",
    materialSource: metadata.materialSource ?? (metadata.resolvedMaterial ? "runtime_memory" : "unbound"),
    configured: Boolean(metadata.configured),
    resolvedMaterial: Boolean(metadata.resolvedMaterial),
    runtimeBound: Boolean(metadata.runtimeBound ?? metadata.resolvedMaterial),
    materialBound: Boolean(metadata.materialBound ?? metadata.resolvedMaterial),
    requiresRebind: Boolean(metadata.requiresRebind ?? (metadata.configured && !metadata.resolvedMaterial)),
    createdAt: metadata.createdAt ?? null,
    updatedAt: metadata.updatedAt ?? null,
    removedAt: metadata.removedAt ?? null,
    lastResolvedAt: metadata.lastResolvedAt ?? null,
    evidenceRefs: normalizeScopes(metadata.evidenceRefs, ["VaultPort.localBinding"]),
  };
}

export function normalizeScopes(value, fallback) {
  if (!value) return [...fallback];
  if (Array.isArray(value)) return value.map(String);
  return [String(value)];
}

export function normalizeOAuthScopes(value, fallback = []) {
  if (!value) return [...fallback];
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  return String(value).split(/\s+/).map((scope) => scope.trim()).filter(Boolean);
}
