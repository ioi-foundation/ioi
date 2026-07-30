export type SurfaceState =
  | "loading" | "empty" | "missing_prerequisite" | "degraded" | "blocked"
  | "approval_pending" | "denied" | "failed" | "recovery" | "completed";

export type ProductSurfaceEntry = {
  identity_ref: string;
  display_name: string;
  canonical_route: string;
  resolved_launch_route: string | null;
  launchable: boolean;
  disabled_reason_codes: string[];
  surface_capability_depth?: "browse" | "inspect" | "propose" | "act" | "workflow_complete" | null;
  surface_operational_state?: "inactive" | "starting" | "ready" | "serving" | "degraded" | "blocked" | "stopped" | "unavailable" | null;
};

export type ProductSurfaceProjection = {
  schema_version: "ioi.hypervisor.product_surface_projection.v1";
  projection_id: string;
  request_context_hash: string;
  principal_ref: string;
  org_ref: string;
  workspace_entries: ProductSurfaceEntry[];
  application_entries: ProductSurfaceEntry[];
  policy_decision_refs: string[];
  read_model_only: true;
};

const CORE: ProductSurfaceEntry[] = [
  ["home", "Home"], ["systems", "Systems"], ["projects", "Projects"],
  ["applications", "Applications"], ["work", "Work"], ["settings", "Settings"],
].map(([key, name]) => ({
  identity_ref: `hypervisor-workspace://${key}`,
  display_name: name,
  canonical_route: `/${key}`,
  resolved_launch_route: `/${key}`,
  launchable: true,
  disabled_reason_codes: [],
}));

const APPLICATION_ROWS = [
  ["studio", "Studio"], ["automations", "Automations"], ["ontology", "Ontology"],
  ["data", "Data"], ["governance", "Governance"], ["provenance", "Provenance"],
  ["evaluations", "Evaluations"], ["improvement", "Improvement"], ["foundry", "Foundry"],
  ["packages", "Packages"], ["developer-workspace", "Developer Workspace"],
  ["developer-console", "Developer Console"], ["environments", "Environments"],
  ["operations", "Operations"],
] as const;

export const FALLBACK_PROJECTION: ProductSurfaceProjection = {
  schema_version: "ioi.hypervisor.product_surface_projection.v1",
  projection_id: "projection://hypervisor/product-surface/offline",
  request_context_hash: `sha256:${"0".repeat(64)}`,
  principal_ref: "user://local-operator",
  org_ref: "org://local",
  workspace_entries: CORE,
  application_entries: [
    ...APPLICATION_ROWS.map(([key, name]) => ({
      identity_ref: `surface://hypervisor/${key}`,
      display_name: name,
      canonical_route: `/${key}`,
      resolved_launch_route: null,
      launchable: false,
      disabled_reason_codes: ["product_surface_projection_unavailable"],
      surface_capability_depth: null,
      surface_operational_state: "degraded" as const,
    })),
    {
      identity_ref: "surface://hypervisor/embodied-systems",
      display_name: "Embodied Systems",
      canonical_route: "/embodied-systems",
      resolved_launch_route: null,
      launchable: false,
      disabled_reason_codes: ["planned"],
      surface_capability_depth: null,
      surface_operational_state: null,
    },
  ],
  policy_decision_refs: ["decision://hypervisor/product-surface/offline"],
  read_model_only: true,
};

async function jsonRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: "include", ...init, headers: { "content-type": "application/json", ...(init?.headers ?? {}) } });
  const value = await response.json();
  if (!response.ok) throw Object.assign(new Error(value.code ?? value.reason ?? `HTTP ${response.status}`), { status: response.status, value });
  return value as T;
}

export async function loadProductSurfaceProjection(): Promise<{ projection: ProductSurfaceProjection; source: "daemon" | "degraded_fallback" }> {
  try {
    const projection = await jsonRequest<ProductSurfaceProjection>("/v1/hypervisor/product-surface-projections", {
      method: "POST",
      body: JSON.stringify({ org_ref: "org://local", context: {}, requested_group_kinds: ["first_party_applications", "installed_applications", "recent", "favorites"], preference_projection_refs: [] }),
    });
    return { projection, source: "daemon" };
  } catch {
    return { projection: FALLBACK_PROJECTION, source: "degraded_fallback" };
  }
}

export type CollectionPage<T = Record<string, unknown>> = {
  schema_version: "ioi.hypervisor.collection_page.v1";
  query_ref: string;
  items: T[];
  next_cursor: string | null;
  serialized_bytes: number;
  total_policy_visible: number;
  policy_filtered_before_counts_and_cache: true;
};

export function queryCollection<T = Record<string, unknown>>(collection: string, search = "", cursor: string | null = null): Promise<CollectionPage<T>> {
  return jsonRequest("/v1/hypervisor/collections/query", { method: "POST", body: JSON.stringify({ org_ref: "org://local", collection, search, filters: [], sort: [], facets: [], cursor, page_size: 25 }) });
}

export async function listPreferences(): Promise<Array<Record<string, unknown>>> {
  const result = await jsonRequest<{ preferences: Array<Record<string, unknown>> }>("/v1/hypervisor/preferences?org_ref=org%3A%2F%2Flocal");
  return result.preferences;
}

export function putPreference(id: string, preference_kind: string, value: unknown, expected_revision: number) {
  return jsonRequest<{ preference: Record<string, unknown>; receipt: Record<string, unknown> }>(`/v1/hypervisor/preferences/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: JSON.stringify({ org_ref: "org://local", preference_kind, value, expected_revision }),
  });
}

export type SettingsOwnerProjection = {
  key: string;
  label: string;
  owner: string;
  endpoint: string;
  state: "ready" | "unavailable";
  summary: string;
};

const SETTINGS_OWNER_ENDPOINTS = [
  ["identity", "Identity & access", "identity and access", "/v1/hypervisor/auth/whoami"],
  ["connections", "Connected applications", "Developer Console connector registry", "/v1/hypervisor/connectors"],
  ["providers", "Providers & environments", "provider and environment domain", "/v1/hypervisor/providers"],
  ["governance", "Organization policy", "authority and policy", "/v1/hypervisor/authority/posture"],
  ["usage", "Usage & metering", "identity, access, and metering", "/v1/hypervisor/usage/consumption"],
  ["billing", "Billing & credits", "billing and settlement", "/v1/hypervisor/billing/projection"],
  ["memory", "Memory", "memory-space lifecycle", "/v1/hypervisor/memory-spaces"],
  ["skills", "Skills", "skill registry", "/v1/skills"],
  ["delivery", "Delivery", "events, receipts, and delivery", "/v1/hypervisor/delivery/projection"],
  ["learning", "Learning boundary", "institutional learning boundary", "/v1/hypervisor/learning-boundary/projection"],
] as const;

export async function loadSettingsOwnerProjections(): Promise<SettingsOwnerProjection[]> {
  return Promise.all(SETTINGS_OWNER_ENDPOINTS.map(async ([key, label, owner, endpoint]) => {
    try {
      const value = await jsonRequest<unknown>(endpoint);
      const count = Array.isArray(value)
        ? value.length
        : value && typeof value === "object"
          ? Object.values(value as Record<string, unknown>).find(Array.isArray)?.length
          : undefined;
      return { key, label, owner, endpoint, state: "ready" as const, summary: count === undefined ? "Owner projection available" : `${count} owner records visible` };
    } catch {
      return { key, label, owner, endpoint, state: "unavailable" as const, summary: "Owner projection unavailable; no local substitute" };
    }
  }));
}
