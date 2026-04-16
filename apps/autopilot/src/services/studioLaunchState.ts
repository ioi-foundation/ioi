import { invoke } from "@tauri-apps/api/core";
import type {
  AssistantWorkbenchSession,
  StudioCapabilityDetailSection,
  StudioViewTarget,
} from "@ioi/agent-ide";

const STORAGE_KEY = "autopilot.pending_studio_launch.v1";
const RECEIPTS_STORAGE_KEY = "autopilot.studio_launch_receipts.v1";
const MAX_RECEIPTS = 64;

export type PendingStudioLaunchRequest =
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

export type PendingStudioLaunchEnvelope = {
  launchId: string;
  request: PendingStudioLaunchRequest;
};

export type StudioLaunchReceipt = {
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

export function summarizePendingStudioLaunchRequest(
  request: PendingStudioLaunchRequest,
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

function createStudioLaunchId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  return `studio-launch-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

function createPendingStudioLaunchEnvelope(
  request: PendingStudioLaunchRequest,
): PendingStudioLaunchEnvelope {
  return {
    launchId: createStudioLaunchId(),
    request,
  };
}

function normalizePendingStudioLaunchEnvelope(
  value: unknown,
): PendingStudioLaunchEnvelope | null {
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
      request: candidate.request as PendingStudioLaunchRequest,
    };
  }

  if (typeof candidate.kind === "string") {
    return createPendingStudioLaunchEnvelope(
      candidate as PendingStudioLaunchRequest,
    );
  }

  return null;
}

function readPendingStudioLaunchEnvelope(): PendingStudioLaunchEnvelope | null {
  if (!canUseStorage()) {
    return null;
  }

  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    return normalizePendingStudioLaunchEnvelope(JSON.parse(raw));
  } catch (error) {
    console.warn("Failed to parse pending Studio launch request:", error);
    window.localStorage.removeItem(STORAGE_KEY);
    return null;
  }
}

function readStudioLaunchReceipts(): StudioLaunchReceipt[] {
  if (!canUseStorage()) {
    return [];
  }

  const raw = window.localStorage.getItem(RECEIPTS_STORAGE_KEY);
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as StudioLaunchReceipt[]) : [];
  } catch (error) {
    console.warn("Failed to parse Studio launch receipts:", error);
    window.localStorage.removeItem(RECEIPTS_STORAGE_KEY);
    return [];
  }
}

function appendStudioLaunchReceipt(stage: string, detail: unknown) {
  if (!canUseStorage()) {
    return;
  }

  const nextReceipts = [
    ...readStudioLaunchReceipts(),
    {
      timestampMs: Date.now(),
      stage,
      detail,
    } satisfies StudioLaunchReceipt,
  ].slice(-MAX_RECEIPTS);
  window.localStorage.setItem(RECEIPTS_STORAGE_KEY, JSON.stringify(nextReceipts));
}

export function setPendingStudioLaunchRequest(
  request: PendingStudioLaunchRequest | null,
): Promise<void> {
  if (!canUseStorage()) {
    return Promise.resolve();
  }

  if (canUseTauri()) {
    if (!request) {
      return clearPendingStudioLaunchRequest();
    }
    return invoke<void>("set_pending_studio_launch", { request }).catch(() => {
      const envelope = createPendingStudioLaunchEnvelope(request);
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
    });
  }

  if (!request) {
    window.localStorage.removeItem(STORAGE_KEY);
    return Promise.resolve();
  }

  const envelope = createPendingStudioLaunchEnvelope(request);
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
  return Promise.resolve();
}

export function showStudioWithLaunchRequest(
  request: PendingStudioLaunchRequest,
): Promise<void> {
  if (canUseTauri()) {
    return invoke<void>("show_studio_with_target", { request }).catch(async () => {
      await setPendingStudioLaunchRequest(request);
      await invoke<void>("show_studio").catch(() => undefined);
    });
  }

  return setPendingStudioLaunchRequest(request);
}

export function clearPendingStudioLaunchRequest() {
  if (!canUseStorage()) {
    return Promise.resolve();
  }

  if (canUseTauri()) {
    return invoke<void>("clear_pending_studio_launch").catch(() => {
      window.localStorage.removeItem(STORAGE_KEY);
    });
  }

  window.localStorage.removeItem(STORAGE_KEY);
  return Promise.resolve();
}

export function peekPendingStudioLaunchRequest(): Promise<PendingStudioLaunchEnvelope | null> {
  if (!canUseStorage()) {
    return Promise.resolve(null);
  }

  if (canUseTauri()) {
    return invoke<PendingStudioLaunchEnvelope | null>(
      "peek_pending_studio_launch",
    ).catch(() => readPendingStudioLaunchEnvelope());
  }

  return Promise.resolve(readPendingStudioLaunchEnvelope());
}

export function ackPendingStudioLaunchRequest(launchId: string): Promise<boolean> {
  if (!canUseStorage()) {
    return Promise.resolve(false);
  }

  if (canUseTauri()) {
    return invoke<boolean>("ack_pending_studio_launch", { launchId }).catch(() => {
      const pendingLaunch = readPendingStudioLaunchEnvelope();
      if (pendingLaunch?.launchId === launchId) {
        window.localStorage.removeItem(STORAGE_KEY);
        return true;
      }
      return false;
    });
  }

  const pendingLaunch = readPendingStudioLaunchEnvelope();
  if (pendingLaunch?.launchId === launchId) {
    window.localStorage.removeItem(STORAGE_KEY);
    return Promise.resolve(true);
  }
  return Promise.resolve(false);
}

export function recordStudioLaunchReceipt(stage: string, detail: unknown = {}) {
  if (!canUseStorage()) {
    return Promise.resolve();
  }

  if (canUseTauri()) {
    return invoke("record_studio_launch_receipt", {
      stage,
      detail,
    }).catch(() => {
      appendStudioLaunchReceipt(stage, detail);
    });
  }

  appendStudioLaunchReceipt(stage, detail);
  return Promise.resolve();
}

export function getStudioLaunchReceipts(): Promise<StudioLaunchReceipt[]> {
  if (!canUseStorage()) {
    return Promise.resolve([]);
  }

  if (canUseTauri()) {
    return invoke<StudioLaunchReceipt[]>("get_studio_launch_receipts").catch(
      () => readStudioLaunchReceipts(),
    );
  }

  return Promise.resolve(readStudioLaunchReceipts());
}
