import type {
  HypervisorModelMountInventoryEndpoint,
  HypervisorModelMountInventoryInstance,
  HypervisorModelMountInventoryRoute,
  HypervisorModelMountInventorySnapshot,
  HypervisorModelMountInventorySource,
} from "./harnessAdapterModel";

export const HYPERVISOR_MODEL_MOUNT_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.modelMounts.daemonEndpoint";
const HYPERVISOR_CORE_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_MODEL_MOUNT_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";
export const HYPERVISOR_MODEL_MOUNT_SNAPSHOT_PATH =
  "/v1/model-mount/snapshot";

type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string> },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface NormalizeModelMountInventoryOptions {
  source?: HypervisorModelMountInventorySource;
  checkedAt?: string;
}

interface LoadModelMountInventoryOptions
  extends NormalizeModelMountInventoryOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
}

function objectRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function arrayOf(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.map(objectRecord) : [];
}

function stringValue(value: unknown, fallback?: string): string {
  return typeof value === "string" && value.trim()
    ? value.trim()
    : (fallback ?? "");
}

function normalizeRouteStatus(
  value: unknown,
): HypervisorModelMountInventoryRoute["status"] {
  const status = stringValue(value, "unknown").toLowerCase();
  if (["active", "available", "configured", "ready"].includes(status)) {
    return "active";
  }
  if (["disabled", "blocked", "unavailable", "stopped"].includes(status)) {
    return "disabled";
  }
  return "unknown";
}

function normalizeEndpointStatus(
  value: unknown,
): HypervisorModelMountInventoryEndpoint["status"] {
  const status = stringValue(value, "unknown").toLowerCase();
  if (status === "mounted" || status === "degraded") {
    return status;
  }
  if (["unmounted", "disabled", "blocked", "stopped"].includes(status)) {
    return "unmounted";
  }
  return "unknown";
}

function normalizeInstanceStatus(
  value: unknown,
): HypervisorModelMountInventoryInstance["status"] {
  const status = stringValue(value, "unknown").toLowerCase();
  if (["loaded", "unloaded", "evicted", "failed"].includes(status)) {
    return status as HypervisorModelMountInventoryInstance["status"];
  }
  return "unknown";
}

function routeFromSnapshotItem(
  item: Record<string, unknown>,
): HypervisorModelMountInventoryRoute {
  return {
    id: stringValue(item.id, "route.unknown"),
    role: stringValue(item.role, undefined),
    status: normalizeRouteStatus(item.status),
    privacy: stringValue(item.privacy ?? item.privacyClass, undefined),
  };
}

function endpointFromSnapshotItem(
  item: Record<string, unknown>,
): HypervisorModelMountInventoryEndpoint {
  return {
    id: stringValue(item.id, "endpoint.unknown"),
    providerId: stringValue(item.providerId ?? item.provider, undefined),
    modelId: stringValue(item.modelId, undefined),
    status: normalizeEndpointStatus(item.status),
    privacyClass: stringValue(item.privacyClass ?? item.privacy, undefined),
  };
}

function instanceFromSnapshotItem(
  item: Record<string, unknown>,
): HypervisorModelMountInventoryInstance {
  return {
    id: stringValue(item.id, "instance.unknown"),
    endpointId: stringValue(item.endpointId, undefined),
    providerId: stringValue(item.providerId ?? item.provider, undefined),
    modelId: stringValue(item.modelId, undefined),
    status: normalizeInstanceStatus(item.status),
  };
}

export function readHypervisorModelMountDaemonEndpoint(): string {
  try {
    if (typeof window === "undefined") {
      return HYPERVISOR_MODEL_MOUNT_DEFAULT_DAEMON_ENDPOINT;
    }
    const modelMountEndpoint = window.localStorage
      .getItem(HYPERVISOR_MODEL_MOUNT_DAEMON_ENDPOINT_STORAGE_KEY)
      ?.trim();
    if (modelMountEndpoint) {
      return modelMountEndpoint;
    }
    return (
      window.localStorage
        .getItem(HYPERVISOR_CORE_DAEMON_ENDPOINT_STORAGE_KEY)
        ?.trim() || HYPERVISOR_MODEL_MOUNT_DEFAULT_DAEMON_ENDPOINT
    );
  } catch {
    return HYPERVISOR_MODEL_MOUNT_DEFAULT_DAEMON_ENDPOINT;
  }
}

export function normalizeHypervisorModelMountInventorySnapshot(
  snapshot: unknown,
  options: NormalizeModelMountInventoryOptions = {},
): HypervisorModelMountInventorySnapshot {
  const value = objectRecord(snapshot);
  return {
    schema_version: "ioi.hypervisor.model_mount_inventory_snapshot.v1",
    source: options.source ?? "daemon-model-mount-inventory",
    checked_at: options.checkedAt ?? new Date().toISOString(),
    routes: arrayOf(value.routes).map(routeFromSnapshotItem),
    endpoints: arrayOf(value.endpoints).map(endpointFromSnapshotItem),
    loadedInstances: arrayOf(value.instances).map(instanceFromSnapshotItem),
  };
}

export async function loadHypervisorModelMountInventorySnapshot(
  options: LoadModelMountInventoryOptions = {},
): Promise<HypervisorModelMountInventorySnapshot> {
  const endpoint =
    options.endpoint ?? readHypervisorModelMountDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for Hypervisor model mount inventory");
  }
  const url = `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_MODEL_MOUNT_SNAPSHOT_PATH}`;
  const response = await fetchImpl(url, {
    method: "GET",
    headers: { accept: "application/json" },
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(
      `Model mount inventory request failed with ${response.status}`,
    );
  }
  return normalizeHypervisorModelMountInventorySnapshot(value, {
    source: options.source ?? "daemon-model-mount-inventory",
    checkedAt: options.checkedAt,
  });
}
