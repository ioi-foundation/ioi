import crypto from "node:crypto";
import path from "node:path";

export function normalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

export function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

export function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).map((value) => String(value)).filter(Boolean))];
}

export function doctorCheck(id, status, required, summary, evidenceRefs = []) {
  return {
    id,
    status,
    required,
    summary,
    evidenceRefs: normalizeArray(evidenceRefs),
  };
}

export function doctorHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

export function relativePathForWorkspace(filePath, workspaceRoot) {
  const relative = path.relative(workspaceRoot, filePath);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative) ? relative : null;
}

export function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

export function booleanValue(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
  }
  return null;
}

export function operatorControlSource(value) {
  const source = optionalString(value);
  return ["cli_tui", "react_flow", "sdk_client", "runtime_auto", "mcp_serve"].includes(source) ? source : "sdk_client";
}

export function appendOperatorControl(controls, control) {
  const existing = normalizeArray(controls);
  if (existing.some((candidate) => candidate?.eventId === control.eventId)) return existing;
  return [...existing, control];
}

export function safeId(value) {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}
