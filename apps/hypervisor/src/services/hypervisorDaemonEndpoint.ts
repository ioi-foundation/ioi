export const HYPERVISOR_CORE_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";

function readStoredEndpoint(storageKey: string): string {
  try {
    if (typeof window === "undefined" || !window.localStorage) {
      return "";
    }
    return window.localStorage.getItem(storageKey)?.trim() ?? "";
  } catch {
    return "";
  }
}

export function hasConfiguredHypervisorDaemonEndpoint(
  storageKeys: readonly string[] = [],
): boolean {
  return [HYPERVISOR_CORE_DAEMON_ENDPOINT_STORAGE_KEY, ...storageKeys].some(
    (storageKey) => readStoredEndpoint(storageKey).length > 0,
  );
}

export function shouldAttemptHypervisorDaemonProjectionFetch(
  ...storageKeys: string[]
): boolean {
  return hasConfiguredHypervisorDaemonEndpoint(storageKeys);
}
