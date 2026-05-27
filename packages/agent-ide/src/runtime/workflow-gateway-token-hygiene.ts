export const WORKFLOW_GATEWAY_TOKEN_HYGIENE_SCHEMA_VERSION =
  "ioi.workflow.gateway-token-hygiene.v1" as const;

export type WorkflowGatewayRequestKind = "generate_content" | "fetch_models" | "unknown";
export type WorkflowGatewayCheckStatus = "ready" | "needs_review" | "blocked";

export interface WorkflowGatewayTokenHygieneInput {
  localServer: {
    host: string;
    port: number;
    csrfToken?: string | null;
    env?: Record<string, unknown> | null;
  };
  remoteRequests: readonly {
    id: string;
    kind?: WorkflowGatewayRequestKind | null;
    url: string;
    method?: string | null;
    authToken?: string | null;
    headers?: Record<string, unknown> | null;
  }[];
}

export interface WorkflowGatewayTokenHygieneRequestRow {
  id: string;
  kind: WorkflowGatewayRequestKind;
  status: WorkflowGatewayCheckStatus;
  method: string;
  endpointHost: string | null;
  endpointPath: string | null;
  networkMode: "dry_run_plan";
  redactedHeaders: Record<string, unknown>;
  policyRefs: string[];
}

export interface WorkflowGatewayTokenHygienePanel {
  schemaVersion: typeof WORKFLOW_GATEWAY_TOKEN_HYGIENE_SCHEMA_VERSION;
  status: "ready" | "needs_review" | "blocked";
  applyMode: "plan_only";
  localServer: {
    host: string;
    port: number;
    localhostOnly: boolean;
    csrfTokenPresent: boolean;
    redactedEnv: Record<string, unknown>;
    policyRefs: string[];
  };
  requestCount: number;
  readyCount: number;
  needsReviewCount: number;
  blockedCount: number;
  rows: WorkflowGatewayTokenHygieneRequestRow[];
}

export function buildWorkflowGatewayTokenHygienePanel(
  input: WorkflowGatewayTokenHygieneInput,
): WorkflowGatewayTokenHygienePanel {
  const localServer = localServerPanel(input.localServer);
  const rows = normalizeRequests(input.remoteRequests).map(remoteRequestRow);
  const blockedCount = rows.filter((row) => row.status === "blocked").length +
    (localServer.localhostOnly && localServer.csrfTokenPresent ? 0 : 1);
  const needsReviewCount = rows.filter((row) => row.status === "needs_review").length;
  const readyCount = rows.filter((row) => row.status === "ready").length;

  return {
    schemaVersion: WORKFLOW_GATEWAY_TOKEN_HYGIENE_SCHEMA_VERSION,
    status: blockedCount > 0 ? "blocked" : needsReviewCount > 0 ? "needs_review" : "ready",
    applyMode: "plan_only",
    localServer,
    requestCount: rows.length,
    readyCount,
    needsReviewCount,
    blockedCount,
    rows,
  };
}

function localServerPanel(input: WorkflowGatewayTokenHygieneInput["localServer"]) {
  const localhostOnly = isLocalhost(input.host);
  const csrfTokenPresent = !!stringField(input.csrfToken) ||
    stringField(recordValue(input.env)?.ANTIGRAVITY_CSRF_TOKEN) !== null ||
    stringField(recordValue(input.env)?.IOI_CSRF_TOKEN) !== null;
  const policyRefs = ["policy:gateway.plan_only", "policy:gateway.tokens.redacted"];
  if (!localhostOnly) policyRefs.push("policy:gateway.block.non_local_bind");
  if (!csrfTokenPresent) policyRefs.push("policy:gateway.block.missing_csrf");
  return {
    host: input.host,
    port: input.port,
    localhostOnly,
    csrfTokenPresent,
    redactedEnv: redactObject(input.env ?? {}),
    policyRefs,
  };
}

function remoteRequestRow(
  request: WorkflowGatewayTokenHygieneInput["remoteRequests"][number],
): WorkflowGatewayTokenHygieneRequestRow {
  const parsed = parseUrl(request.url);
  const headers = {
    ...(recordValue(request.headers) ?? {}),
    ...(request.authToken ? { Authorization: `Bearer ${request.authToken}` } : {}),
  };
  const kind = request.kind ?? kindFromPath(parsed?.pathname ?? "");
  const policyRefs = [
    "policy:gateway.plan_only",
    "policy:gateway.network.dry_run",
    "policy:gateway.tokens.redacted",
  ];
  if (!request.authToken && !hasAuthHeader(headers)) {
    policyRefs.push("policy:gateway.review.missing_oauth");
  }
  if (!parsed || !isHttps(parsed)) {
    policyRefs.push("policy:gateway.block.non_https_remote");
  }
  const status = policyRefs.some((policyRef) => policyRef.includes(".block."))
    ? "blocked"
    : policyRefs.some((policyRef) => policyRef.includes(".review."))
      ? "needs_review"
      : "ready";

  return {
    id: safeId(request.id),
    kind,
    status,
    method: stringField(request.method)?.toUpperCase() ?? "POST",
    endpointHost: parsed?.host ?? null,
    endpointPath: parsed?.pathname ?? null,
    networkMode: "dry_run_plan",
    redactedHeaders: redactObject(headers),
    policyRefs,
  };
}

function kindFromPath(pathname: string): WorkflowGatewayRequestKind {
  if (/GenerateContent/i.test(pathname)) return "generate_content";
  if (/FetchAvailableModels/i.test(pathname)) return "fetch_models";
  return "unknown";
}

function hasAuthHeader(headers: Record<string, unknown>): boolean {
  return Object.keys(headers).some((key) => /authorization/i.test(key));
}

function parseUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function isHttps(url: URL): boolean {
  return url.protocol === "https:";
}

function isLocalhost(host: string): boolean {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}

function redactObject(value: Record<string, unknown>): Record<string, unknown> {
  const next: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    next[key] = isTokenKey(key) || isTokenValue(entry) ? "[REDACTED]" : entry;
  }
  return next;
}

function isTokenKey(value: string): boolean {
  return /(?:authorization|csrf|oauth|token|secret|password|credential)/i.test(value);
}

function isTokenValue(value: unknown): boolean {
  return typeof value === "string" && /\b(?:ya29\.[a-z0-9._-]+|sk-[a-z0-9_-]{8,}|bearer\s+\S+)\b/i.test(value);
}

function normalizeRequests(
  requests: readonly WorkflowGatewayTokenHygieneInput["remoteRequests"][number][] | undefined,
): WorkflowGatewayTokenHygieneInput["remoteRequests"][number][] {
  return Array.isArray(requests) ? requests.filter(Boolean) : [];
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringField(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function safeId(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._:-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "request"
  );
}
