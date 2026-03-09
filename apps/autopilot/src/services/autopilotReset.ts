import { listen } from "@tauri-apps/api/event";

async function clearIndexedDb(): Promise<void> {
  if (typeof window === "undefined" || !("indexedDB" in window)) return;

  const indexedDbWithDatabases = indexedDB as IDBFactory & {
    databases?: () => Promise<Array<{ name?: string }>>;
  };

  if (typeof indexedDbWithDatabases.databases !== "function") {
    return;
  }

  let databases: Array<{ name?: string }> = [];
  try {
    databases = await indexedDbWithDatabases.databases();
  } catch (_error) {
    return;
  }

  await Promise.all(
    databases
      .map((database) => database.name)
      .filter((name): name is string => Boolean(name))
      .map(
        (name) =>
          new Promise<void>((resolve) => {
            const request = indexedDB.deleteDatabase(name);
            request.onsuccess = () => resolve();
            request.onerror = () => resolve();
            request.onblocked = () => resolve();
          }),
      ),
  );
}

export async function clearAutopilotBrowserData(): Promise<void> {
  if (typeof window === "undefined") return;

  try {
    window.localStorage.clear();
  } catch (_error) {
    // Ignore best-effort browser storage reset failures.
  }

  try {
    window.sessionStorage.clear();
  } catch (_error) {
    // Ignore best-effort browser storage reset failures.
  }

  try {
    if ("caches" in window) {
      const keys = await window.caches.keys();
      await Promise.all(keys.map((key) => window.caches.delete(key)));
    }
  } catch (_error) {
    // Ignore best-effort browser cache reset failures.
  }

  await clearIndexedDb();
}

export async function resetAutopilotFrontendState(): Promise<void> {
  await clearAutopilotBrowserData();
  window.location.reload();
}

export function listenForAutopilotDataReset(): Promise<() => void> {
  return listen("autopilot-data-reset", () => {
    void resetAutopilotFrontendState();
  });
}
