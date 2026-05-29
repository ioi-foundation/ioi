import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString("utf8");
  return text.trim() ? JSON.parse(text) : {};
}

export function writeSse(response, events) {
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.end(
    events
      .map((event) => `id: ${event.id ?? event.seq}\nevent: runtime.event\ndata: ${JSON.stringify(event)}\n\n`)
      .join(""),
  );
}

export function writeJsonResponse(response, value, status = 200) {
  response.statusCode = status;
  response.setHeader("content-type", "application/json");
  response.end(status === 204 ? "" : JSON.stringify(value));
}

export function writeMcpJsonRpcResponse(response, value) {
  if (value === null || (Array.isArray(value) && value.length === 0)) {
    writeJsonResponse(response, null, 204);
    return;
  }
  writeJsonResponse(response, value);
}

export function writeError(response, error) {
  if (response.destroyed || response.writableEnded) return;
  if (response.headersSent) {
    try {
      response.end();
    } catch {
      // Streaming clients may disconnect while the handler is unwinding.
    }
    return;
  }
  const status = error?.status ?? 500;
  response.statusCode = status;
  response.setHeader("content-type", "application/json");
  response.end(
    JSON.stringify({
      error: {
        code: error?.code ?? "runtime",
        message: error?.message ?? "Local daemon request failed.",
        retryable: status >= 500,
        requestId: response.getHeader("x-request-id"),
        details: redact(error?.details ?? {}),
      },
    }),
  );
}

export function notFound(message, details) {
  return runtimeError({ status: 404, code: "not_found", message, details });
}

export function policyError(message, details) {
  return runtimeError({ status: 403, code: "policy", message, details });
}

export function externalBlocker(message, details) {
  return runtimeError({ status: 424, code: "external_blocker", message, details });
}

export function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

export function redact(value) {
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      /token|secret|key|authorization/i.test(key) ? "[REDACTED]" : item,
    ]),
  );
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

export function readJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return fs
    .readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

export function listJsonl(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((file) => file.endsWith(".jsonl"))
    .map((file) => path.join(dir, file));
}

export function runtimeEventStreamFileName(eventStreamId) {
  return crypto.createHash("sha256").update(String(eventStreamId)).digest("hex");
}

export function relative(from, to) {
  return path.relative(from, to) || ".";
}
