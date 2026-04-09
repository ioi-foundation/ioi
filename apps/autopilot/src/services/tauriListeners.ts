type TauriUnlisten = () => void | Promise<void>;

function tauriListenerCleanupErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return `${error.message}\n${error.stack ?? ""}`;
  }
  return String(error ?? "");
}

export function isBenignTauriListenerCleanupError(error: unknown): boolean {
  const message = tauriListenerCleanupErrorMessage(error).toLowerCase();
  return (
    message.includes("listeners[eventid].handlerid") ||
    (message.includes("unregisterlistener") &&
      message.includes("undefined is not an object"))
  );
}

export function safelyDisposeTauriListener(
  unlistenPromise: Promise<TauriUnlisten> | null | undefined,
): void {
  if (!unlistenPromise) {
    return;
  }

  void unlistenPromise
    .then((unlisten) => Promise.resolve().then(() => unlisten()))
    .catch((error) => {
      if (!isBenignTauriListenerCleanupError(error)) {
        console.warn("[Autopilot] Failed to dispose Tauri listener", error);
      }
    });
}
