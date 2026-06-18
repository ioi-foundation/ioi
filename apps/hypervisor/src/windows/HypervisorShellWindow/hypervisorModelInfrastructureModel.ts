import {
  HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  type HypervisorModelMountInventorySnapshot,
} from "./harnessAdapterModel.ts";
import { HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE } from "./hypervisorPrivacyPostureModel.ts";
import { HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE } from "./hypervisorReceiptEvidenceModel.ts";
import { HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE } from "./hypervisorSessionOperationsModel.ts";

export type HypervisorModelInfrastructureSource =
  | "daemon-model-infrastructure-projection"
  | "fixture"
  | "unverified";

export interface HypervisorModelInfrastructureRoute {
  route_ref: string;
  role: string;
  status: "active" | "disabled" | "unknown";
  privacy_posture: string;
  provider_ref: string;
  endpoint_refs: string[];
  loaded_instance_refs: string[];
  model_weight_custody_lane: string;
  authority_scope_refs: string[];
  receipt_refs: string[];
}

export interface HypervisorModelInfrastructureProvider {
  provider_ref: string;
  label: string;
  provider_kind: "local" | "customer" | "hosted_api" | "tee" | "provider_trust";
  privacy_posture: string;
  credential_scope_refs: string[];
  receipt_ref: string;
}

export interface HypervisorModelInfrastructureSessionBinding {
  session_ref: string;
  selected_model_route_ref: string;
  selected_endpoint_ref: string;
  selected_instance_ref: string;
  custody_profile_ref: string;
  policy_ref: string;
  receipt_ref: string;
}

export interface HypervisorModelInfrastructureProjection {
  schema_version: "ioi.hypervisor.model_infrastructure_projection.v1";
  projection_id: string;
  source: HypervisorModelInfrastructureSource;
  selected_project_id: string;
  selected_session_ref: string;
  runtimeTruthSource: "daemon-runtime";
  infrastructure_boundary_invariant: string;
  inventory_source: HypervisorModelMountInventorySnapshot["source"];
  checked_at: string;
  model_route_refs: string[];
  endpoint_refs: string[];
  loaded_instance_refs: string[];
  provider_refs: string[];
  routes: HypervisorModelInfrastructureRoute[];
  providers: HypervisorModelInfrastructureProvider[];
  session_bindings: HypervisorModelInfrastructureSessionBinding[];
  model_weight_custody_policy_refs: string[];
  latest_receipt_refs: string[];
}

export const HYPERVISOR_MODEL_INFRASTRUCTURE_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_MODEL_INFRASTRUCTURE_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";
export const HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_PATH =
  "/v1/hypervisor/model-infrastructure";

type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string> },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface NormalizeModelInfrastructureProjectionOptions {
  source?: HypervisorModelInfrastructureSource;
}

interface LoadModelInfrastructureProjectionOptions
  extends NormalizeModelInfrastructureProjectionOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
  projectId?: string | null;
  sessionRef?: string | null;
}

const modelCustodyPolicies =
  HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.model_weight_policies.map(
    (policy) => `model-weight-custody:${policy.lane}`,
  );

function providerLabel(providerRef: string): string {
  if (providerRef.includes("local")) return "Local model mount";
  if (providerRef.includes("customer")) return "Customer model endpoint";
  if (providerRef.includes("tee")) return "TEE-backed model endpoint";
  if (providerRef.includes("hosted")) return "Hosted model API";
  return "Model provider";
}

function providerKind(
  providerRef: string,
): HypervisorModelInfrastructureProvider["provider_kind"] {
  if (providerRef.includes("local")) return "local";
  if (providerRef.includes("customer")) return "customer";
  if (providerRef.includes("tee")) return "tee";
  if (providerRef.includes("hosted")) return "hosted_api";
  return "provider_trust";
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim()))];
}

export function buildHypervisorModelInfrastructureProjectionFromInventory(
  inventory: HypervisorModelMountInventorySnapshot,
  options: {
    selectedProjectId?: string;
    selectedSessionRef?: string;
    source?: HypervisorModelInfrastructureSource;
  } = {},
): HypervisorModelInfrastructureProjection {
  const endpointRefs = uniqueStrings(inventory.endpoints.map((endpoint) => endpoint.id));
  const loadedInstanceRefs = uniqueStrings(
    inventory.loadedInstances.map((instance) => instance.id),
  );
  const providerRefs = uniqueStrings([
    ...inventory.endpoints.map(
      (endpoint) => endpoint.providerId ?? "provider:hypervisor-local",
    ),
    ...inventory.loadedInstances.map(
      (instance) => instance.providerId ?? "provider:hypervisor-local",
    ),
  ]);
  const firstEndpoint = inventory.endpoints[0];
  const firstInstance = inventory.loadedInstances[0];
  const selectedSessionRef =
    options.selectedSessionRef ??
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.selected_session_ref;

  return {
    schema_version: "ioi.hypervisor.model_infrastructure_projection.v1",
    projection_id: `model-infrastructure:${options.selectedProjectId ?? "hypervisor-core"}/default`,
    source: options.source ?? "fixture",
    selected_project_id: options.selectedProjectId ?? "hypervisor-core",
    selected_session_ref: selectedSessionRef,
    runtimeTruthSource: "daemon-runtime",
    infrastructure_boundary_invariant:
      "Models is an infrastructure projection over Core-owned model routes, provider endpoints, loaded instances, custody policy, authority scopes, and receipts. Model mounting UI may configure proposals; Hypervisor Core admits execution and Agentgres records model-route truth.",
    inventory_source: inventory.source,
    checked_at: inventory.checked_at ?? "unknown",
    model_route_refs: uniqueStrings(inventory.routes.map((route) => route.id)),
    endpoint_refs: endpointRefs,
    loaded_instance_refs: loadedInstanceRefs,
    provider_refs: providerRefs,
    routes: inventory.routes.map((route) => {
      const endpointMatches = inventory.endpoints.filter(
        (endpoint) =>
          endpoint.id === firstEndpoint?.id ||
          endpoint.providerId === firstEndpoint?.providerId,
      );
      const instanceMatches = inventory.loadedInstances.filter(
        (instance) =>
          endpointMatches.some((endpoint) => endpoint.id === instance.endpointId) ||
          instance.id === firstInstance?.id,
      );
      return {
        route_ref: route.id,
        role: route.role ?? "session-model-route",
        status: route.status,
        privacy_posture: route.privacy ?? firstEndpoint?.privacyClass ?? "unknown",
        provider_ref: firstEndpoint?.providerId ?? "provider:hypervisor-local",
        endpoint_refs: uniqueStrings(endpointMatches.map((endpoint) => endpoint.id)),
        loaded_instance_refs: uniqueStrings(
          instanceMatches.map((instance) => instance.id),
        ),
        model_weight_custody_lane:
          route.privacy === "local" || firstEndpoint?.privacyClass === "local"
            ? "local_or_open_weight"
            : "provider_trust_remote_mount",
        authority_scope_refs: ["scope:model.invoke", "scope:receipt.write"],
        receipt_refs:
          HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records
            .filter(
              (record) =>
                record.kind === "session_lifecycle" ||
                record.kind === "authority",
            )
            .map((record) => record.receipt_ref)
            .slice(0, 2),
      };
    }),
    providers: providerRefs.map((providerRef) => ({
      provider_ref: providerRef,
      label: providerLabel(providerRef),
      provider_kind: providerKind(providerRef),
      privacy_posture:
        firstEndpoint?.privacyClass ?? inventory.routes[0]?.privacy ?? "unknown",
      credential_scope_refs: ["scope:model.invoke", "scope:secret.use"],
      receipt_ref:
        HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records.find(
          (record) => record.kind === "authority",
        )?.receipt_ref ?? "receipt://model/infrastructure",
    })),
    session_bindings: [
      {
        session_ref: selectedSessionRef,
        selected_model_route_ref:
          inventory.routes[0]?.id ?? "model-route:hypervisor/default-local",
        selected_endpoint_ref: firstEndpoint?.id ?? "model-endpoint:unavailable",
        selected_instance_ref: firstInstance?.id ?? "model-instance:unavailable",
        custody_profile_ref:
          firstEndpoint?.privacyClass === "local" || inventory.routes[0]?.privacy === "local"
            ? "custody-profile:model/local"
            : "custody-profile:model/provider-trust",
        policy_ref: "policy:model-route/session-default",
        receipt_ref:
          HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records.find(
            (record) => record.kind === "authority",
          )?.receipt_ref ?? "receipt://model/session-binding",
      },
    ],
    model_weight_custody_policy_refs: modelCustodyPolicies,
    latest_receipt_refs:
      HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records
        .filter(
          (record) =>
            record.kind === "session_lifecycle" ||
            record.kind === "authority",
        )
        .map((record) => record.receipt_ref)
        .slice(0, 4),
  };
}

export const HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE =
  buildHypervisorModelInfrastructureProjectionFromInventory(
    HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
    { source: "fixture" },
  );

function objectRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function arrayOf(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.map(objectRecord) : [];
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function stringList(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) return fallback;
  const values = value
    .filter((item): item is string => typeof item === "string" && !!item.trim())
    .map((item) => item.trim());
  return values.length > 0 ? values : fallback;
}

function routeStatusValue(
  value: unknown,
  fallback: HypervisorModelInfrastructureRoute["status"],
): HypervisorModelInfrastructureRoute["status"] {
  return typeof value === "string" &&
    ["active", "disabled", "unknown"].includes(value)
    ? (value as HypervisorModelInfrastructureRoute["status"])
    : fallback;
}

function providerKindValue(
  value: unknown,
  fallback: HypervisorModelInfrastructureProvider["provider_kind"],
): HypervisorModelInfrastructureProvider["provider_kind"] {
  return typeof value === "string" &&
    ["local", "customer", "hosted_api", "tee", "provider_trust"].includes(value)
    ? (value as HypervisorModelInfrastructureProvider["provider_kind"])
    : fallback;
}

function normalizeRoute(
  item: Record<string, unknown>,
  index: number,
): HypervisorModelInfrastructureRoute {
  const fallback =
    HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.routes[index] ??
    HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.routes[0]!;
  return {
    route_ref: stringValue(item.route_ref, fallback.route_ref),
    role: stringValue(item.role, fallback.role),
    status: routeStatusValue(item.status, fallback.status),
    privacy_posture: stringValue(item.privacy_posture, fallback.privacy_posture),
    provider_ref: stringValue(item.provider_ref, fallback.provider_ref),
    endpoint_refs: stringList(item.endpoint_refs, fallback.endpoint_refs),
    loaded_instance_refs: stringList(
      item.loaded_instance_refs,
      fallback.loaded_instance_refs,
    ),
    model_weight_custody_lane: stringValue(
      item.model_weight_custody_lane,
      fallback.model_weight_custody_lane,
    ),
    authority_scope_refs: stringList(
      item.authority_scope_refs,
      fallback.authority_scope_refs,
    ),
    receipt_refs: stringList(item.receipt_refs, fallback.receipt_refs),
  };
}

function normalizeProvider(
  item: Record<string, unknown>,
  index: number,
): HypervisorModelInfrastructureProvider {
  const fallback =
    HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.providers[index] ??
    HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.providers[0]!;
  return {
    provider_ref: stringValue(item.provider_ref, fallback.provider_ref),
    label: stringValue(item.label, fallback.label),
    provider_kind: providerKindValue(item.provider_kind, fallback.provider_kind),
    privacy_posture: stringValue(item.privacy_posture, fallback.privacy_posture),
    credential_scope_refs: stringList(
      item.credential_scope_refs,
      fallback.credential_scope_refs,
    ),
    receipt_ref: stringValue(item.receipt_ref, fallback.receipt_ref),
  };
}

function normalizeSessionBinding(
  item: Record<string, unknown>,
  index: number,
): HypervisorModelInfrastructureSessionBinding {
  const fallback =
    HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.session_bindings[index] ??
    HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.session_bindings[0]!;
  return {
    session_ref: stringValue(item.session_ref, fallback.session_ref),
    selected_model_route_ref: stringValue(
      item.selected_model_route_ref,
      fallback.selected_model_route_ref,
    ),
    selected_endpoint_ref: stringValue(
      item.selected_endpoint_ref,
      fallback.selected_endpoint_ref,
    ),
    selected_instance_ref: stringValue(
      item.selected_instance_ref,
      fallback.selected_instance_ref,
    ),
    custody_profile_ref: stringValue(
      item.custody_profile_ref,
      fallback.custody_profile_ref,
    ),
    policy_ref: stringValue(item.policy_ref, fallback.policy_ref),
    receipt_ref: stringValue(item.receipt_ref, fallback.receipt_ref),
  };
}

export function readHypervisorModelInfrastructureDaemonEndpoint(): string {
  try {
    if (typeof window === "undefined") {
      return HYPERVISOR_MODEL_INFRASTRUCTURE_DEFAULT_DAEMON_ENDPOINT;
    }
    return (
      window.localStorage.getItem(
        HYPERVISOR_MODEL_INFRASTRUCTURE_DAEMON_ENDPOINT_STORAGE_KEY,
      ) || HYPERVISOR_MODEL_INFRASTRUCTURE_DEFAULT_DAEMON_ENDPOINT
    );
  } catch {
    return HYPERVISOR_MODEL_INFRASTRUCTURE_DEFAULT_DAEMON_ENDPOINT;
  }
}

export function normalizeHypervisorModelInfrastructureProjection(
  snapshot: unknown,
  options: NormalizeModelInfrastructureProjectionOptions = {},
): HypervisorModelInfrastructureProjection {
  const value = objectRecord(snapshot);
  const routes = arrayOf(value.routes).map(normalizeRoute);
  const providers = arrayOf(value.providers).map(normalizeProvider);
  const sessionBindings = arrayOf(value.session_bindings).map(
    normalizeSessionBinding,
  );
  return {
    schema_version: "ioi.hypervisor.model_infrastructure_projection.v1",
    projection_id: stringValue(
      value.projection_id,
      HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.projection_id,
    ),
    source: options.source ?? "daemon-model-infrastructure-projection",
    selected_project_id: stringValue(
      value.selected_project_id,
      HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.selected_project_id,
    ),
    selected_session_ref: stringValue(
      value.selected_session_ref,
      HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.selected_session_ref,
    ),
    runtimeTruthSource: "daemon-runtime",
    infrastructure_boundary_invariant: stringValue(
      value.infrastructure_boundary_invariant,
      HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.infrastructure_boundary_invariant,
    ),
    inventory_source: stringValue(
      value.inventory_source,
      HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.inventory_source,
    ) as HypervisorModelMountInventorySnapshot["source"],
    checked_at: stringValue(
      value.checked_at,
      HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.checked_at,
    ),
    model_route_refs: stringList(
      value.model_route_refs,
      HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.model_route_refs,
    ),
    endpoint_refs: stringList(
      value.endpoint_refs,
      HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.endpoint_refs,
    ),
    loaded_instance_refs: stringList(
      value.loaded_instance_refs,
      HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.loaded_instance_refs,
    ),
    provider_refs: stringList(
      value.provider_refs,
      HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.provider_refs,
    ),
    routes:
      routes.length > 0
        ? routes
        : HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.routes,
    providers:
      providers.length > 0
        ? providers
        : HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.providers,
    session_bindings:
      sessionBindings.length > 0
        ? sessionBindings
        : HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.session_bindings,
    model_weight_custody_policy_refs: stringList(
      value.model_weight_custody_policy_refs,
      HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.model_weight_custody_policy_refs,
    ),
    latest_receipt_refs: stringList(
      value.latest_receipt_refs,
      HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE.latest_receipt_refs,
    ),
  };
}

export async function loadHypervisorModelInfrastructureProjection(
  options: LoadModelInfrastructureProjectionOptions = {},
): Promise<HypervisorModelInfrastructureProjection> {
  const endpoint =
    options.endpoint ?? readHypervisorModelInfrastructureDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error(
      "fetch unavailable for Hypervisor model infrastructure projection",
    );
  }
  const url = new URL(
    `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_PATH}`,
  );
  if (options.projectId) url.searchParams.set("project_id", options.projectId);
  if (options.sessionRef) url.searchParams.set("session_ref", options.sessionRef);
  const response = await fetchImpl(url.toString(), {
    method: "GET",
    headers: { accept: "application/json" },
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(
      `Model infrastructure projection request failed with ${response.status}`,
    );
  }
  return normalizeHypervisorModelInfrastructureProjection(value, {
    source: options.source ?? "daemon-model-infrastructure-projection",
  });
}
