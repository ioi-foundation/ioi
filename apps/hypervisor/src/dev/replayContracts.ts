export const HYPERVISOR_DEV_REPLAY_DEFAULT_ENDPOINT =
  "http://127.0.0.1:8765";

export const HYPERVISOR_DEV_REPLAY_STATUS_PATH =
  "/v1/hypervisor/dev-replay/status";

export const HYPERVISOR_DEV_REPLAY_BRIDGE_INVOKE_PATH =
  "/v1/hypervisor/dev-host-bridge/invoke";

export interface HypervisorDevReplayStatus {
  schema_version: "ioi.hypervisor.dev_replay_status.v1";
  status: "ready";
  endpoint: string;
  generated_at: string;
  boundary: string;
  route_families: string[];
}

export interface HypervisorDevReplayBootstrapResult {
  enabled: boolean;
  endpoint: string | null;
  reason: string;
  hostBridgeInstalled: boolean;
}
