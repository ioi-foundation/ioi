import { invoke } from "@tauri-apps/api/core";
import type { ArtifactHubViewKey } from "../types";

const STORAGE_KEY = "autopilot.pending_chat_shell_launch.v1";

export type PendingChatShellLaunchRequest =
  | {
      kind: "view";
      view: ArtifactHubViewKey;
      turnId?: string | null;
    }
  | {
      kind: "artifact";
      artifactId: string;
    };

export type PendingChatShellLaunchEnvelope = {
  launchId: string;
  request: PendingChatShellLaunchRequest;
};

function canUseStorage() {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

function canUseTauri() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function createChatShellLaunchId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  return `chat-shell-launch-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

function normalizePendingChatShellLaunchEnvelope(
  value: unknown,
): PendingChatShellLaunchEnvelope | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const candidate = value as {
    launchId?: unknown;
    request?: unknown;
    kind?: unknown;
  };

  if (
    typeof candidate.launchId === "string" &&
    candidate.request &&
    typeof candidate.request === "object"
  ) {
    return {
      launchId: candidate.launchId,
      request: candidate.request as PendingChatShellLaunchRequest,
    };
  }

  if (typeof candidate.kind === "string") {
    return {
      launchId: createChatShellLaunchId(),
      request: candidate as PendingChatShellLaunchRequest,
    };
  }

  return null;
}

function readPendingChatShellLaunchEnvelope(): PendingChatShellLaunchEnvelope | null {
  if (!canUseStorage()) {
    return null;
  }

  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    return normalizePendingChatShellLaunchEnvelope(JSON.parse(raw));
  } catch (error) {
    console.warn("Failed to parse pending Chat shell launch request:", error);
    window.localStorage.removeItem(STORAGE_KEY);
    return null;
  }
}

export function setPendingChatShellLaunchRequest(
  request: PendingChatShellLaunchRequest | null,
) {
  if (!canUseStorage()) {
    return Promise.resolve();
  }

  if (!request) {
    window.localStorage.removeItem(STORAGE_KEY);
    return Promise.resolve();
  }

  const envelope: PendingChatShellLaunchEnvelope = {
    launchId: createChatShellLaunchId(),
    request,
  };
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
  return Promise.resolve();
}

export function showChatShellWithLaunchRequest(
  request: PendingChatShellLaunchRequest,
) {
  return setPendingChatShellLaunchRequest(request).then(async () => {
    if (canUseTauri()) {
      await invoke<void>("show_chat_session").catch(() => undefined);
    }
  });
}

export function peekPendingChatShellLaunchRequest() {
  return Promise.resolve(readPendingChatShellLaunchEnvelope());
}

export function ackPendingChatShellLaunchRequest(launchId: string) {
  const pendingLaunch = readPendingChatShellLaunchEnvelope();
  if (pendingLaunch?.launchId === launchId) {
    window.localStorage.removeItem(STORAGE_KEY);
    return Promise.resolve(true);
  }
  return Promise.resolve(false);
}
