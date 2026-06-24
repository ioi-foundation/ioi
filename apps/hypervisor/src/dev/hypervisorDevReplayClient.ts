import { HYPERVISOR_CORE_DAEMON_ENDPOINT_STORAGE_KEY } from "../services/hypervisorDaemonEndpoint";
import { installHypervisorDevHostBridge } from "./hypervisorDevHostBridge";
import {
  HYPERVISOR_DEV_REPLAY_DEFAULT_ENDPOINT,
  HYPERVISOR_DEV_REPLAY_STATUS_PATH,
  type HypervisorDevReplayBootstrapResult,
  type HypervisorDevReplayStatus,
} from "./replayContracts";

const MODEL_MOUNT_DAEMON_ENDPOINT_STORAGE_KEY = "ioi.modelMounts.daemonEndpoint";
const DEV_REPLAY_BOOTSTRAP_TIMEOUT_MS = 450;

declare global {
  interface Window {
    __HYPERVISOR_DEV_REPLAY__?: HypervisorDevReplayBootstrapResult;
  }
}

function endpointUrl(endpoint: string, path: string): string {
  return `${endpoint.replace(/\/+$/, "")}${path}`;
}

function readStoredEndpoint(storageKey: string): string {
  try {
    return window.localStorage.getItem(storageKey)?.trim() ?? "";
  } catch {
    return "";
  }
}

function writeStoredEndpoint(endpoint: string): void {
  window.localStorage.setItem(
    HYPERVISOR_CORE_DAEMON_ENDPOINT_STORAGE_KEY,
    endpoint,
  );
  window.localStorage.setItem(MODEL_MOUNT_DAEMON_ENDPOINT_STORAGE_KEY, endpoint);
}

function candidateEndpoints(): string[] {
  const envEndpoint = (import.meta.env.VITE_HYPERVISOR_DEV_REPLAY_ENDPOINT ?? "")
    .toString()
    .trim();
  const storedCoreEndpoint = readStoredEndpoint(
    HYPERVISOR_CORE_DAEMON_ENDPOINT_STORAGE_KEY,
  );
  const storedModelEndpoint = readStoredEndpoint(
    MODEL_MOUNT_DAEMON_ENDPOINT_STORAGE_KEY,
  );
  const sameOriginEndpoint =
    typeof window !== "undefined" ? window.location.origin : "";
  return [
    envEndpoint,
    sameOriginEndpoint,
    storedCoreEndpoint,
    storedModelEndpoint,
    HYPERVISOR_DEV_REPLAY_DEFAULT_ENDPOINT,
  ].filter((endpoint, index, values): endpoint is string => {
    return Boolean(endpoint) && values.indexOf(endpoint) === index;
  });
}

async function probeDevReplayEndpoint(
  endpoint: string,
): Promise<HypervisorDevReplayStatus | null> {
  const controller = new AbortController();
  const timeout = window.setTimeout(
    () => controller.abort(),
    DEV_REPLAY_BOOTSTRAP_TIMEOUT_MS,
  );
  try {
    const response = await fetch(
      endpointUrl(endpoint, HYPERVISOR_DEV_REPLAY_STATUS_PATH),
      {
        headers: { accept: "application/json" },
        signal: controller.signal,
      },
    );
    if (!response.ok) {
      return null;
    }
    const value = (await response.json()) as Partial<HypervisorDevReplayStatus>;
    return value.status === "ready" ? (value as HypervisorDevReplayStatus) : null;
  } catch {
    return null;
  } finally {
    window.clearTimeout(timeout);
  }
}

export async function bootstrapHypervisorDevReplayClient(): Promise<HypervisorDevReplayBootstrapResult> {
  if (!import.meta.env.DEV || typeof window === "undefined") {
    return {
      enabled: false,
      endpoint: null,
      hostBridgeInstalled: false,
      reason: "dev replay bootstrap is only active in Vite development mode",
    };
  }

  for (const endpoint of candidateEndpoints()) {
    const status = await probeDevReplayEndpoint(endpoint);
    if (!status) {
      continue;
    }
    writeStoredEndpoint(endpoint);
    const hostBridgeInstalled = installHypervisorDevHostBridge({ endpoint });
    const result: HypervisorDevReplayBootstrapResult = {
      enabled: true,
      endpoint,
      hostBridgeInstalled,
      reason: status.boundary,
    };
    window.__HYPERVISOR_DEV_REPLAY__ = result;
    window.dispatchEvent(
      new CustomEvent("hypervisor-dev-replay-ready", { detail: result }),
    );
    return result;
  }

  const result: HypervisorDevReplayBootstrapResult = {
    enabled: false,
    endpoint: null,
    hostBridgeInstalled: false,
    reason: "no local Hypervisor dev replay endpoint responded",
  };
  window.__HYPERVISOR_DEV_REPLAY__ = result;
  return result;
}
