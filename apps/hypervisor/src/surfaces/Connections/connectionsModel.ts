// Connections cockpit model — source-derived from the product-ui serve cockpit
// (renderConnectionsCockpit / connectionCategory / authDescriptor). The route anatomy and
// behavior are ported verbatim; only the data boundary changes: typed daemon clients instead
// of a server-rendered fetch. See docs/product-ui-api-integration.md.
import { daemon } from "../../data/daemon";

// Shapes mirrored from the daemon JSON (GET /v1/hypervisor/{connectors,scm-connectors,capability-leases}).
export type AuthProfile = {
  type?: string;
  discovered?: boolean;
  sealed_client_secret?: boolean | string;
  client_id?: string;
};
export type Connector = {
  connector_id: string;
  name?: string;
  service?: string;
  kind?: string;
  base_url?: string;
  auth_posture?: string;
  auth_profile?: AuthProfile | null;
  allowed_tools?: { name?: string }[];
  requires_credential?: boolean;
  org_policy?: { risk_posture?: string } | null;
};
export type ScmConnector = {
  name?: string;
  kind?: string;
  host?: string;
  remote_url?: string;
  auth_posture?: string;
  connected_login?: string;
};
export type CapabilityLease = {
  backing_provider?: string;
  resource_refs?: unknown;
};

export type ConnectionsData = {
  connectors: Connector[];
  scmConnectors: ScmConnector[];
  leases: CapabilityLease[];
};

export const CATEGORY_ORDER = [
  "MCP servers",
  "Communication channels",
  "Cloud roles",
  "Service accounts",
  "APIs & services",
  "Code / SCM",
] as const;

export function connectionCategory(c: Connector): string {
  if (c.kind === "mcp") return "MCP servers";
  if (["slack", "discord", "teams", "email"].includes(c.service || "")) return "Communication channels";
  if (c.kind === "aws-sigv4" || /aws|s3|sts/i.test(c.service || "")) return "Cloud roles";
  if (c.kind === "service-account") return "Service accounts";
  return "APIs & services";
}

export function authDescriptor(c: Connector): string {
  const ap = c.auth_profile || null;
  if (ap && ap.type)
    return ap.type === "oauth_authcode_pkce"
      ? ap.discovered
        ? "OAuth (auto-discovered + DCR)"
        : ap.sealed_client_secret
          ? "OAuth (confidential BYOA)"
          : "OAuth + PKCE"
      : ap.type;
  if (c.kind === "aws-sigv4") return "AWS SigV4";
  if (c.kind === "service-account") return "Service account";
  if (c.kind === "oidc-workload") return "OIDC workload";
  return c.requires_credential === false ? "open" : "bearer / token";
}

export function leaseCount(leases: CapabilityLease[], connectorId: string): number {
  return (leases || []).filter(
    (l) =>
      String(l.backing_provider || "").includes(connectorId) ||
      String(l.resource_refs || "").includes(connectorId),
  ).length;
}

export function isBound(c: Connector): boolean {
  return c.auth_posture === "token-lease:bound" || c.auth_posture === "open";
}

export function connectHref(c: Connector): string {
  const slackNoClient = c.service === "slack" && !(c.auth_profile && c.auth_profile.client_id);
  return slackNoClient
    ? "/__ioi/slack/setup"
    : `/__ioi/integrations/connect/${encodeURIComponent(c.connector_id)}`;
}

export function toolsLabel(c: Connector): string {
  return c.kind === "mcp"
    ? "tools discovered on connect"
    : (c.allowed_tools || []).map((t) => t.name).filter(Boolean).join(", ") || "—";
}

// ---- Add-connection create contracts (daemon-owned, native /v1/hypervisor/connectors) ----
// Follow the connector estate's register pipeline: POST /connectors registers the binding, then
// either /oauth/discover (MCP: auto-discover tools + Dynamic Client Registration on connect) or
// /credential (bearer: seal the token in the daemon — it never reaches a session). The created
// record is the daemon's own; we never fabricate it.
type ConnectorCreateResponse = { ok?: boolean; connector?: Connector; reason?: string };

async function registerConnector(body: Record<string, unknown>): Promise<Connector> {
  const r = await daemon.post<ConnectorCreateResponse>("/hypervisor/connectors", body);
  if (!r.ok || !r.connector?.connector_id) {
    throw new Error(r.reason || "Daemon did not return a registered connector");
  }
  return r.connector;
}

export type McpDraft = { name: string; url: string };

export async function addMcpConnector(draft: McpDraft): Promise<Connector> {
  const connector = await registerConnector({
    service: "mcp",
    kind: "mcp",
    name: draft.name.trim(),
    base_url: draft.url.trim(),
  });
  // Best-effort auto-discovery + DCR so the daemon self-configures (no vendor app needed). A
  // discovery failure does not unregister the connector — it just defers OAuth to Connect.
  await daemon
    .post(`/hypervisor/connectors/${encodeURIComponent(connector.connector_id)}/oauth/discover`, {})
    .catch(() => undefined);
  return connector;
}

export type BearerDraft = {
  name: string;
  baseUrl: string;
  tool: string;
  toolPath?: string;
  token: string;
};

export async function addBearerConnector(draft: BearerDraft): Promise<Connector> {
  const service = draft.name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-") || "service";
  const connector = await registerConnector({
    service,
    kind: "http",
    name: draft.name.trim(),
    base_url: draft.baseUrl.trim(),
    allowed_tools: [
      { name: draft.tool.trim(), method: "POST", path: (draft.toolPath || "").trim() || `/${draft.tool.trim()}` },
    ],
  });
  // Seal the bearer token in the daemon (binds the connector). Fail loudly: a sealed-token failure
  // leaves the connector unbound, so surface it rather than reporting a false success.
  const sealed = await daemon.post<{ ok?: boolean; reason?: string }>(
    `/hypervisor/connectors/${encodeURIComponent(connector.connector_id)}/credential`,
    { token: draft.token },
  );
  if (sealed && sealed.ok === false) {
    throw new Error(sealed.reason || "Daemon could not seal the credential");
  }
  return connector;
}

export async function fetchConnections(): Promise<ConnectionsData> {
  const [c, s, l] = await Promise.all([
    daemon.get<{ connectors?: Connector[] }>("/hypervisor/connectors").catch(() => null),
    daemon.get<{ connectors?: ScmConnector[] }>("/hypervisor/scm-connectors").catch(() => null),
    daemon.get<{ leases?: CapabilityLease[] }>("/hypervisor/capability-leases").catch(() => null),
  ]);
  return {
    connectors: c?.connectors || [],
    scmConnectors: s?.connectors || [],
    leases: l?.leases || [],
  };
}
