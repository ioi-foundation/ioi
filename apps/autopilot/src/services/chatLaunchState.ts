import { invoke } from "@tauri-apps/api/core";
import type {
  AssistantWorkbenchSession,
  StudioCapabilityDetailSection,
  StudioViewTarget,
} from "@ioi/agent-ide";

const STORAGE_KEY = "autopilot.pending_studio_launch.v1";
const RECEIPTS_STORAGE_KEY = "autopilot.chat_launch_receipts.v1";
const MAX_RECEIPTS = 64;

export type PendingChatLaunchRequest =
  | {
      kind: "view";
      view: StudioViewTarget;
    }
  | {
      kind: "session-target";
      sessionId: string;
    }
  | {
      kind: "capability";
      connectorId?: string | null;
      detailSection?: StudioCapabilityDetailSection | null;
    }
  | {
      kind: "policy";
      connectorId?: string | null;
    }
  | {
      kind: "autopilot-intent";
      intent: string;
      sessionId?: string | null;
    }
  | {
      kind: "assistant-workbench";
      session: AssistantWorkbenchSession;
    };

export type PendingChatLaunchEnvelope = {
  launchId: string;
  request: PendingChatLaunchRequest;
};

export type ChatLaunchReceipt = {
  timestampMs: number;
  stage: string;
  detail: unknown;
};

function canUseStorage() {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

function canUseTauri() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function summarizeAssistantWorkbenchSession(
  session: AssistantWorkbenchSession,
) {
  const summary = {
    kind: session.kind,
    connectorId: session.connectorId,
    sourceNotificationId: session.sourceNotificationId ?? null,
  };

  switch (session.kind) {
    case "gmail_reply":
      return {
        ...summary,
        threadId: session.thread.threadId,
      };
    case "meeting_prep":
      return {
        ...summary,
        calendarId: session.event.calendarId,
        eventId: session.event.eventId,
      };
    default:
      return summary;
  }
}

export function summarizePendingChatLaunchRequest(
  request: PendingChatLaunchRequest,
) {
  switch (request.kind) {
    case "view":
      return {
        kind: request.kind,
        view: request.view,
      };
    case "session-target":
      return {
        kind: request.kind,
        sessionId: request.sessionId,
      };
    case "capability":
      return {
        kind: request.kind,
        connectorId: request.connectorId ?? null,
        detailSection: request.detailSection ?? null,
      };
    case "policy":
      return {
        kind: request.kind,
        connectorId: request.connectorId ?? null,
      };
    case "autopilot-intent":
      return {
        kind: request.kind,
        intent: request.intent,
        sessionId: request.sessionId ?? null,
      };
    case "assistant-workbench":
      return {
        kind: request.kind,
        session: summarizeAssistantWorkbenchSession(request.session),
      };
    default:
      return {
        kind: "unknown",
      };
  }
}

function createChatLaunchId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  return `studio-launch-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

function createPendingChatLaunchEnvelope(
  request: PendingChatLaunchRequest,
): PendingChatLaunchEnvelope {
  return {
    launchId: createChatLaunchId(),
    request,
  };
}

function normalizePendingChatLaunchEnvelope(
  value: unknown,
): PendingChatLaunchEnvelope | null {
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
      request: candidate.request as PendingChatLaunchRequest,
    };
  }

  if (typeof candidate.kind === "string") {
    return createPendingChatLaunchEnvelope(
      candidate as PendingChatLaunchRequest,
    );
  }

  return null;
}

function readPendingChatLaunchEnvelope(): PendingChatLaunchEnvelope | null {
  if (!canUseStorage()) {
    return null;
  }

  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    return normalizePendingChatLaunchEnvelope(JSON.parse(raw));
  } catch (error) {
    console.warn("Failed to parse pending Studio launch request:", error);
    window.localStorage.removeItem(STORAGE_KEY);
    return null;
  }
}

function readChatLaunchReceipts(): ChatLaunchReceipt[] {
  if (!canUseStorage()) {
    return [];
  }

  const raw = window.localStorage.getItem(RECEIPTS_STORAGE_KEY);
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ChatLaunchReceipt[]) : [];
  } catch (error) {
    console.warn("Failed to parse Studio launch receipts:", error);
    window.localStorage.removeItem(RECEIPTS_STORAGE_KEY);
    return [];
  }
}

function appendChatLaunchReceipt(stage: string, detail: unknown) {
  if (!canUseStorage()) {
    return;
  }

  const nextReceipts = [
    ...readChatLaunchReceipts(),
    {
      timestampMs: Date.now(),
      stage,
      detail,
    } satisfies ChatLaunchReceipt,
  ].slice(-MAX_RECEIPTS);
  window.localStorage.setItem(RECEIPTS_STORAGE_KEY, JSON.stringify(nextReceipts));
}

export function setPendingChatLaunchRequest(
  request: PendingChatLaunchRequest | null,
): Promise<void> {
  if (!canUseStorage()) {
    return Promise.resolve();
  }

  if (canUseTauri()) {
    if (!request) {
      return clearPendingChatLaunchRequest();
    }
    return invoke<void>("set_pending_chat_launch", { request }).catch(() => {
      const envelope = createPendingChatLaunchEnvelope(request);
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
    });
  }

  if (!request) {
    window.localStorage.removeItem(STORAGE_KEY);
    return Promise.resolve();
  }

  const envelope = createPendingChatLaunchEnvelope(request);
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
  return Promise.resolve();
}

export function showChatWithLaunchRequest(
  request: PendingChatLaunchRequest,
): Promise<void> {
  if (canUseTauri()) {
    return invoke<void>("show_chat_with_target", { request }).catch(async () => {
      await setPendingChatLaunchRequest(request);
      await invoke<void>("show_chat").catch(() => undefined);
    });
  }

  return setPendingChatLaunchRequest(request);
}

export function clearPendingChatLaunchRequest() {
  if (!canUseStorage()) {
    return Promise.resolve();
  }

  if (canUseTauri()) {
    return invoke<void>("clear_pending_chat_launch").catch(() => {
      window.localStorage.removeItem(STORAGE_KEY);
    });
  }

  window.localStorage.removeItem(STORAGE_KEY);
  return Promise.resolve();
}

export function peekPendingChatLaunchRequest(): Promise<PendingChatLaunchEnvelope | null> {
  if (!canUseStorage()) {
    return Promise.resolve(null);
  }

  if (canUseTauri()) {
    return invoke<PendingChatLaunchEnvelope | null>(
      "peek_pending_chat_launch",
    ).catch(() => readPendingChatLaunchEnvelope());
  }

  return Promise.resolve(readPendingChatLaunchEnvelope());
}

export function ackPendingChatLaunchRequest(launchId: string): Promise<boolean> {
  if (!canUseStorage()) {
    return Promise.resolve(false);
  }

  if (canUseTauri()) {
    return invoke<boolean>("ack_pending_chat_launch", { launchId }).catch(() => {
      const pendingLaunch = readPendingChatLaunchEnvelope();
      if (pendingLaunch?.launchId === launchId) {
        window.localStorage.removeItem(STORAGE_KEY);
        return true;
      }
      return false;
    });
  }

  const pendingLaunch = readPendingChatLaunchEnvelope();
  if (pendingLaunch?.launchId === launchId) {
    window.localStorage.removeItem(STORAGE_KEY);
    return Promise.resolve(true);
  }
  return Promise.resolve(false);
}

export function recordChatLaunchReceipt(stage: string, detail: unknown = {}) {
  if (!canUseStorage()) {
    return Promise.resolve();
  }

  if (canUseTauri()) {
    return invoke("record_chat_launch_receipt", {
      stage,
      detail,
    }).catch(() => {
      appendChatLaunchReceipt(stage, detail);
    });
  }

  appendChatLaunchReceipt(stage, detail);
  return Promise.resolve();
}

export function getChatLaunchReceipts(): Promise<ChatLaunchReceipt[]> {
  if (!canUseStorage()) {
    return Promise.resolve([]);
  }

  if (canUseTauri()) {
    return invoke<ChatLaunchReceipt[]>("get_chat_launch_receipts").catch(
      () => readChatLaunchReceipts(),
    );
  }

  return Promise.resolve(readChatLaunchReceipts());
}
