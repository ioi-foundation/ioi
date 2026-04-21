export type SettingsSection =
  | "identity"
  | "knowledge"
  | "skill_sources"
  | "managed_settings"
  | "runtime"
  | "storage_api"
  | "sources"
  | "environment"
  | "local_data"
  | "repair_reset"
  | "diagnostics";

export const RESET_COPY = [
  "Local conversation history, events, and artifacts in `chat-memory.db`.",
  "Connector subscription registry and control policy state.",
  "Spotlight validation artifacts and browser-side local storage for the app origin.",
  "Kernel-backed runtime settings only reset when explicitly cleared or replaced.",
];

export function formatSettingsTime(timestampMs: number): string {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(timestampMs));
}

export function isEngineSection(section: SettingsSection): boolean {
  return (
    section === "runtime" ||
    section === "storage_api" ||
    section === "sources" ||
    section === "environment"
  );
}
