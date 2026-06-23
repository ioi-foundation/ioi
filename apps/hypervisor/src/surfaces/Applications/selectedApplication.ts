// Selected-application store — mirrors the reference harness's
// `hypervisor.selectedApplicationId` localStorage model (server.js). There is no
// pinned application by default; opening one from the launcher selects it, which
// pins it in the sidebar and renders its blank surface on /insights. Reactive via
// useSyncExternalStore so the sidebar pin updates immediately on selection.
import { useSyncExternalStore } from "react";

const STORAGE_KEY = "hypervisor.selectedApplicationId";
const listeners = new Set<() => void>();

export function getSelectedApplicationId(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setSelectedApplicationId(id: string | null): void {
  try {
    if (id == null) localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, id);
  } catch {
    /* ignore storage failures (private mode, etc.) */
  }
  for (const listener of listeners) listener();
}

function subscribe(callback: () => void): () => void {
  listeners.add(callback);
  return () => listeners.delete(callback);
}

export function useSelectedApplicationId(): string | null {
  return useSyncExternalStore(subscribe, getSelectedApplicationId, () => null);
}
