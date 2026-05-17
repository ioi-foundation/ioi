import type { ConnectorSummary } from "@ioi/agent-ide";
import {
  MODEL_AUTHORITY_BINDING_ENDPOINT,
  MODEL_CAPABILITY_BINDING_ENDPOINT,
  TOOL_CAPABILITY_BINDING_ENDPOINT,
} from "@ioi/agent-ide";
import {
  buildAuthorityCenterProjection,
  type AuthorityCenterProjection,
} from "./authorityCenter";
import type { ShieldPolicyState } from "./policyCenter";

export const DEFAULT_AUTHORITY_DAEMON_ENDPOINT = "http://127.0.0.1:8765";
export const AUTHORITY_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.modelMounts.daemonEndpoint";
export const AUTHORITY_EVIDENCE_SUMMARIES_ENDPOINT =
  "/api/v1/authority-evidence";

export interface AuthorityCenterRuntimeProjectionResult {
  endpoint: string;
  projection: AuthorityCenterProjection;
  error: string | null;
  failures: string[];
}

export function readAuthorityDaemonEndpoint(): string {
  try {
    return (
      window.localStorage.getItem(AUTHORITY_DAEMON_ENDPOINT_STORAGE_KEY) ||
      DEFAULT_AUTHORITY_DAEMON_ENDPOINT
    );
  } catch {
    return DEFAULT_AUTHORITY_DAEMON_ENDPOINT;
  }
}

export async function fetchAuthorityJson(
  endpoint: string,
  path: string,
  options: { method?: string; body?: unknown } = {},
): Promise<unknown> {
  const response = await fetch(`${endpoint.replace(/\/+$/, "")}${path}`, {
    method: options.method ?? "GET",
    headers: {
      accept: "application/json",
      ...(options.body === undefined
        ? {}
        : { "content-type": "application/json" }),
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const message =
      value && typeof value === "object" && "error" in value
        ? JSON.stringify((value as { error: unknown }).error)
        : `${path} returned ${response.status}`;
    throw new Error(message);
  }
  return value;
}

export async function fetchAuthorityJsonFirst(
  endpoint: string,
  paths: readonly string[],
): Promise<unknown> {
  const failures: string[] = [];
  for (const path of paths) {
    try {
      return await fetchAuthorityJson(endpoint, path);
    } catch (error) {
      failures.push(
        error instanceof Error
          ? `${path}: ${error.message}`
          : `${path}: ${String(error)}`,
      );
    }
  }
  throw new Error(failures.join(" / "));
}

export async function loadAuthorityCenterRuntimeProjection({
  policyState,
  connectors = [],
  endpoint = readAuthorityDaemonEndpoint(),
}: {
  policyState: ShieldPolicyState;
  connectors?: ConnectorSummary[];
  endpoint?: string;
}): Promise<AuthorityCenterRuntimeProjectionResult> {
  const [
    modelCapabilitiesResult,
    modelSnapshotResult,
    toolCatalogResult,
    authorityResult,
    authorityEvidenceResult,
  ] = await Promise.allSettled([
    fetchAuthorityJsonFirst(endpoint, [
      MODEL_CAPABILITY_BINDING_ENDPOINT,
      "/v1/model-capabilities",
    ]),
    fetchAuthorityJson(endpoint, "/api/v1/models"),
    fetchAuthorityJsonFirst(endpoint, [
      TOOL_CAPABILITY_BINDING_ENDPOINT,
      "/v1/tools",
    ]),
    fetchAuthorityJson(endpoint, MODEL_AUTHORITY_BINDING_ENDPOINT),
    fetchAuthorityJsonFirst(endpoint, [
      AUTHORITY_EVIDENCE_SUMMARIES_ENDPOINT,
      "/api/v1/authority-evidence-summaries",
      "/api/v1/workflow-capability-preflight-evidence",
      "/api/v1/workflow-capability-preflight",
      "/v1/workflow-capability-preflights",
    ]),
  ]);
  const modelCapabilities =
    modelCapabilitiesResult.status === "fulfilled"
      ? modelCapabilitiesResult.value
      : undefined;
  const modelSnapshot =
    modelSnapshotResult.status === "fulfilled"
      ? mergeModelCapabilities(modelSnapshotResult.value, modelCapabilities)
      : mergeModelCapabilities(undefined, modelCapabilities);
  const toolCatalog =
    toolCatalogResult.status === "fulfilled" ? toolCatalogResult.value : [];
  const authoritySnapshot =
    authorityResult.status === "fulfilled" ? authorityResult.value : undefined;
  const authorityEvidenceSnapshot =
    authorityEvidenceResult.status === "fulfilled"
      ? authorityEvidenceResult.value
      : undefined;
  const failures = [
    modelCapabilitiesResult,
    modelSnapshotResult,
    toolCatalogResult,
    authorityResult,
  ]
    .filter(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    )
    .map((result) =>
      result.reason instanceof Error
        ? result.reason.message
        : String(result.reason),
    );
  const error = failures.length > 0 ? failures.join(" / ") : null;
  return {
    endpoint,
    error,
    failures,
    projection: buildAuthorityCenterProjection({
      authoritySnapshot,
      modelSnapshot,
      toolCatalog,
      authorityEvidenceSnapshot,
      connectors,
      policyState,
      error,
    }),
  };
}

function mergeModelCapabilities(
  modelSnapshot: unknown,
  modelCapabilities: unknown,
): Record<string, unknown> | unknown {
  const snapshot =
    modelSnapshot &&
    typeof modelSnapshot === "object" &&
    !Array.isArray(modelSnapshot)
      ? (modelSnapshot as Record<string, unknown>)
      : {};
  const capabilities = arrayPayload(modelCapabilities, [
    "modelCapabilities",
    "capabilities",
    "items",
  ]);
  if (capabilities.length === 0) {
    return modelSnapshot ?? snapshot;
  }
  return {
    ...snapshot,
    modelCapabilities: capabilities,
  };
}

function arrayPayload(value: unknown, keys: readonly string[]): unknown[] {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== "object") return [];
  const record = value as Record<string, unknown>;
  for (const key of keys) {
    const candidate = record[key];
    if (Array.isArray(candidate)) return candidate;
  }
  return [];
}
