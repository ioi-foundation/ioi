import { listen as listenHostEvent } from "./hypervisorHostBridge";

type HostUnlisten = () => void | Promise<void>;
type HostEventCallback<T> = (event: { payload: T }) => void;

export function isHypervisorClientRuntime(): boolean {
  return typeof window !== "undefined" && "__HYPERVISOR_HOST_BRIDGE__" in window;
}

export function listenIfHostBridge<T>(
  eventName: string,
  handler: HostEventCallback<T>,
): Promise<HostUnlisten> {
  if (!isHypervisorClientRuntime()) {
    return Promise.resolve(() => {});
  }

  return listenHostEvent<T>(eventName, handler);
}

function hostListenerCleanupErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return `${error.message}\n${error.stack ?? ""}`;
  }
  return String(error ?? "");
}

export function isBenignHostListenerCleanupError(error: unknown): boolean {
  const message = hostListenerCleanupErrorMessage(error).toLowerCase();
  return (
    message.includes("listeners[eventid].handlerid") ||
    (message.includes("unregisterlistener") &&
      message.includes("undefined is not an object"))
  );
}

export function safelyDisposeHostListener(
  unlistenPromise: Promise<HostUnlisten> | null | undefined,
): void {
  if (!unlistenPromise) {
    return;
  }

  void unlistenPromise
    .then((unlisten) => Promise.resolve().then(() => unlisten()))
    .catch((error) => {
      if (!isBenignHostListenerCleanupError(error)) {
        console.warn("[Autopilot] Failed to dispose host bridge listener", error);
      }
    });
}
