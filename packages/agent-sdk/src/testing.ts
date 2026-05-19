import {
  createRuntimeSubstrateClient,
  type RuntimeSubstrateClient,
  type RuntimeSubstrateClientOptions,
} from "./substrate-client.js";

/**
 * @deprecated Mock runtime substrate client has been deprecated and removed.
 * This stub delegates to the standard DaemonRuntimeSubstrateClient.
 */
export function createMockRuntimeSubstrateClient(
  options: RuntimeSubstrateClientOptions = {},
): RuntimeSubstrateClient {
  return createRuntimeSubstrateClient(options);
}

export type {
  RuntimeSubagentCancellationPropagationResult,
  RuntimeSubagentControlInput,
  RuntimeSubagentListInput,
  RuntimeSubagentListResult,
  RuntimeSubagentRecord,
  RuntimeSubagentResult,
  RuntimeThreadCompactInput,
  RuntimeTurnInterruptInput,
  RuntimeTurnSteerInput,
  RuntimeUsageListInput,
  RuntimeUsageListResult,
  RuntimeUsageTelemetry,
} from "./substrate-client.js";
export { RuntimeSubstrateClient, RuntimeSubstrateClientOptions };
