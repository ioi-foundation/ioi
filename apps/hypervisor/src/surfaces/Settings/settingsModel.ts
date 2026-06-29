// Settings surface models — source-owned, native daemon boundary (/v1/hypervisor/*).
// Source-derived from the product-ui Settings route tree (Organization + User settings with the
// members / runners+git-authentications / secrets / API-access-tokens / metering panes). The route
// anatomy (settings-nav → content pane with table/summary/empty states) is reproduced; the only
// change is the data boundary: typed daemon clients hitting the daemon's own REST contracts. Where
// the daemon owns no plane for a pane we render an honest "not yet ported" placeholder — never a
// fabricated row. Each pane fetcher swallows daemon-down into an empty result (graceful), surfacing
// the empty/placeholder state rather than crashing.
import { daemon } from "../../data/daemon";

// ---------------- Members (daemon principals plane) ----------------
// GET /v1/hypervisor/principals → { principals: [{ principal_id, name, email, role, status,
//   source, created_at }] }
export type PrincipalRecord = {
  principal_id?: string;
  name?: string;
  email?: string;
  role?: string;
  status?: string;
  source?: string;
  created_at?: string;
};
export type Member = {
  id: string;
  name: string;
  email: string;
  role: string;
  authenticatedWith: string;
  joinedAt?: string;
  active: boolean;
};
export function toMember(p: PrincipalRecord): Member {
  return {
    id: p.principal_id || "",
    name: p.name || p.email || p.principal_id || "Unknown",
    email: p.email || "",
    role: p.role === "admin" ? "Admin" : p.role ? cap(p.role) : "Member",
    authenticatedWith: prettySource(p.source),
    joinedAt: p.created_at,
    active: (p.status || "active") === "active",
  };
}
export async function listMembers(): Promise<Member[]> {
  const r = await daemon
    .get<{ principals?: PrincipalRecord[] }>("/hypervisor/principals")
    .catch(() => ({}) as { principals?: PrincipalRecord[] });
  return (r.principals || [])
    .filter((p) => (p.status || "active") === "active")
    .map(toMember)
    .filter((m) => m.id);
}

// ---------------- Runners (daemon provider registry) ----------------
// GET /v1/hypervisor/providers → { providers: [{ provider_ref, reason, status, capabilities:{
//   isolation, locality, remote, restore, monitors:[], note } }] }
export type ProviderRecord = {
  provider_ref?: string;
  reason?: string;
  status?: string;
  capabilities?: {
    isolation?: string;
    locality?: string;
    remote?: boolean;
    restore?: boolean;
    monitors?: string[];
    note?: string;
    authority_gated?: boolean;
    credentials_required?: boolean;
  } | null;
};
export type Runner = {
  id: string;
  reason: string;
  status: string;
  available: boolean;
  isolation: string;
  locality: string;
  remote: boolean;
  monitors: string[];
};
export function toRunner(p: ProviderRecord): Runner {
  const c = p.capabilities || {};
  return {
    id: p.provider_ref || "",
    reason: p.reason || "",
    status: p.status || "unknown",
    available: (p.status || "") === "available",
    isolation: c.isolation || "—",
    locality: c.locality || (c.remote ? "remote" : "local"),
    remote: !!c.remote,
    monitors: c.monitors || [],
  };
}
export async function listRunners(): Promise<Runner[]> {
  const r = await daemon
    .get<{ providers?: ProviderRecord[] }>("/hypervisor/providers")
    .catch(() => ({}) as { providers?: ProviderRecord[] });
  return (r.providers || []).map(toRunner).filter((x) => x.id);
}

// ---------------- Git authentications (daemon SCM connectors, host-level) ----------------
// GET /v1/hypervisor/scm-connectors → { connectors: [{ connector_id, kind, host, host_level,
//   auth_posture, connected_login, remote_url }] }
export type ScmRecord = {
  connector_id?: string;
  kind?: string;
  host?: string;
  host_level?: boolean;
  auth_posture?: string;
  connected_login?: string;
  remote_url?: string;
};
export type GitAuth = {
  id: string;
  host: string;
  kind: string;
  login?: string;
  bound: boolean;
};
export async function listGitAuths(): Promise<GitAuth[]> {
  const r = await daemon
    .get<{ connectors?: ScmRecord[] }>("/hypervisor/scm-connectors")
    .catch(() => ({}) as { connectors?: ScmRecord[] });
  return (r.connectors || [])
    .filter((c) => c.host_level && (c.kind === "github" || c.kind === "git"))
    .map((c) => ({
      id: c.connector_id || "",
      host: c.host || c.remote_url || "github.com",
      kind: c.kind || "git",
      login: c.connected_login,
      bound: c.auth_posture === "token-lease:bound",
    }))
    .filter((g) => g.id);
}

// ---------------- Secrets (daemon-sealed; metadata only) ----------------
// GET /v1/hypervisor/secrets → { secrets: [{ secret_id, name, scope, mount, created_at }] }.
// The value is sealed and never surfaces.
export type SecretRecord = {
  secret_id?: string;
  name?: string;
  scope?: Record<string, unknown> | null;
  mount?: { filePath?: string; environmentVariable?: unknown } | null;
  created_at?: string;
};
export type SecretRow = {
  id: string;
  name: string;
  mountType: string;
  createdAt?: string;
};
export function toSecret(s: SecretRecord): SecretRow {
  const m = s.mount || {};
  const mountType = m.filePath !== undefined
    ? "File path"
    : m.environmentVariable !== undefined
      ? "Environment variable"
      : "Sealed";
  return { id: s.secret_id || "", name: s.name || "(unnamed)", mountType, createdAt: s.created_at };
}
export async function listSecrets(): Promise<SecretRow[]> {
  const r = await daemon
    .get<{ secrets?: SecretRecord[] }>("/hypervisor/secrets")
    .catch(() => ({}) as { secrets?: SecretRecord[] });
  return (r.secrets || []).map(toSecret).filter((s) => s.id);
}

// ---------------- API access tokens (daemon; hash + metadata, value once on create) ----------------
// GET /v1/hypervisor/api-tokens → { tokens: [{ token_id, description, read_only, created_at,
//   expires_at, last_used_at }] }. The token value is never listed.
export type TokenRecord = {
  token_id?: string;
  description?: string;
  read_only?: boolean;
  created_at?: string;
  expires_at?: string;
  last_used_at?: string;
};
export type TokenRow = {
  id: string;
  description: string;
  readOnly: boolean;
  createdAt?: string;
  expiresAt?: string;
  lastUsedAt?: string;
};
export function toToken(t: TokenRecord): TokenRow {
  return {
    id: t.token_id || "",
    description: t.description || "(no description)",
    readOnly: !!t.read_only,
    createdAt: t.created_at,
    expiresAt: t.expires_at,
    lastUsedAt: t.last_used_at,
  };
}
export async function listTokens(): Promise<TokenRow[]> {
  const r = await daemon
    .get<{ tokens?: TokenRecord[] }>("/hypervisor/api-tokens")
    .catch(() => ({}) as { tokens?: TokenRecord[] });
  return (r.tokens || []).map(toToken).filter((t) => t.id);
}

// ---------------- Metering & Cost (daemon budget + usage consumption) ----------------
// GET /v1/hypervisor/budget → { budget: { budget_ocu, available_ocu, used_ocu, threshold_ocu,
//   target_ocu, auto_fund_enabled } }  (OCU = compute units derived from real receipts).
// GET /v1/hypervisor/usage/consumption → { metrics: [{ display_name, kind, series:[{ time, ocu }] }] }
export type BudgetRecord = {
  budget_ocu?: number;
  available_ocu?: number;
  used_ocu?: number;
  threshold_ocu?: number;
  target_ocu?: number;
  auto_fund_enabled?: boolean;
};
export type UsagePoint = { time?: string; ocu?: number };
export type UsageMetric = { display_name?: string; kind?: string; series?: UsagePoint[] };
export type Metering = {
  budgetOcu: number;
  availableOcu: number;
  usedOcu: number;
  thresholdOcu: number;
  targetOcu: number;
  autoFund: boolean;
  metrics: { name: string; kind: string; total: number; series: UsagePoint[] }[];
  hasBudget: boolean;
};
export async function fetchMetering(): Promise<Metering> {
  const [b, u] = await Promise.all([
    daemon.get<{ budget?: BudgetRecord }>("/hypervisor/budget").catch(() => ({}) as { budget?: BudgetRecord }),
    daemon
      .get<{ metrics?: UsageMetric[] }>("/hypervisor/usage/consumption")
      .catch(() => ({}) as { metrics?: UsageMetric[] }),
  ]);
  const budget = b.budget || {};
  const metrics = (u.metrics || []).map((m) => ({
    name: m.display_name || m.kind || "Usage",
    kind: m.kind || "",
    total: (m.series || []).reduce((acc, p) => acc + (p.ocu || 0), 0),
    series: m.series || [],
  }));
  return {
    budgetOcu: budget.budget_ocu ?? 0,
    availableOcu: budget.available_ocu ?? 0,
    usedOcu: budget.used_ocu ?? 0,
    thresholdOcu: budget.threshold_ocu ?? 0,
    targetOcu: budget.target_ocu ?? 0,
    autoFund: !!budget.auto_fund_enabled,
    metrics,
    hasBudget: b.budget !== undefined && b.budget !== null,
  };
}

// ---------------- helpers ----------------
function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function prettySource(src?: string): string {
  if (!src) return "Local";
  return src
    .split(/[-_]/)
    .map((w) => cap(w))
    .join("-");
}
export function fmtDate(iso?: string): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  return new Date(t).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
export function fmtOcu(n: number): string {
  if (!Number.isFinite(n)) return "0";
  return n.toLocaleString(undefined, { maximumFractionDigits: 2 });
}
