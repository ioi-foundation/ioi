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

export async function fetchConnections(): Promise<ConnectionsData> {
  const [c, s, l] = await Promise.all([
    daemon.get<{ connectors?: Connector[] }>("/connectors").catch(() => ({})),
    daemon.get<{ connectors?: ScmConnector[] }>("/scm-connectors").catch(() => ({})),
    daemon.get<{ leases?: CapabilityLease[] }>("/capability-leases").catch(() => ({})),
  ]);
  return {
    connectors: c.connectors || [],
    scmConnectors: s.connectors || [],
    leases: l.leases || [],
  };
}
