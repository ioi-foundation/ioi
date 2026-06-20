import { invoke } from "./hypervisorHostBridge";
import type {
  AssistantWorkbenchSession,
  ChatViewTarget,
} from "@ioi/hypervisor-workbench";
import type { ChatCapabilityDetailSection } from "../types";

const STORAGE_KEY = "hypervisor.pending_hypervisor_launch.v1";
const RECEIPTS_STORAGE_KEY = "hypervisor.hypervisor_launch_receipts.v1";
const MAX_RECEIPTS = 64;

export type PendingHypervisorLaunchRequest =
  | {
      kind: "view";
      view: ChatViewTarget;
    }
  | {
      kind: "session-target";
      sessionId: string;
    }
  | {
      kind: "artifact";
      artifactId: string;
    }
  | {
      kind: "capability";
      connectorId?: string | null;
      detailSection?: ChatCapabilityDetailSection | null;
    }
  | {
      kind: "policy";
      connectorId?: string | null;
    }
  | {
      kind: "hypervisor-intent";
      intent: string;
      sessionId?: string | null;
    }
  | {
      kind: "assistant-workbench";
      session: AssistantWorkbenchSession;
    };

export type PendingHypervisorLaunchEnvelope = {
  launchId: string;
  request: PendingHypervisorLaunchRequest;
};

export type HypervisorLaunchReceipt = {
  timestampMs: number;
  stage: string;
  detail: unknown;
};

function canUseStorage() {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

function canUseHostBridge() {
  return typeof window !== "undefined" && "__HYPERVISOR_HOST_BRIDGE__" in window;
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

export function summarizePendingHypervisorLaunchRequest(
  request: PendingHypervisorLaunchRequest,
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
    case "artifact":
      return {
        kind: request.kind,
        artifactId: request.artifactId,
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
    case "hypervisor-intent":
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

function createHypervisorLaunchId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  return `hypervisor-launch-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

function createPendingHypervisorLaunchEnvelope(
  request: PendingHypervisorLaunchRequest,
): PendingHypervisorLaunchEnvelope {
  return {
    launchId: createHypervisorLaunchId(),
    request,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function isPendingHypervisorLaunchRequest(
  value: unknown,
): value is PendingHypervisorLaunchRequest {
  if (!isRecord(value) || typeof value.kind !== "string") {
    return false;
  }

  switch (value.kind) {
    case "view":
      return typeof value.view === "string";
    case "session-target":
      return typeof value.sessionId === "string";
    case "artifact":
      return typeof value.artifactId === "string";
    case "capability":
    case "policy":
      return true;
    case "hypervisor-intent":
      return typeof value.intent === "string";
    case "assistant-workbench":
      return isRecord(value.session);
    default:
      return false;
  }
}

function normalizePendingHypervisorLaunchEnvelope(
  value: unknown,
): PendingHypervisorLaunchEnvelope | null {
  if (!isRecord(value)) {
    return null;
  }

  if (
    typeof value.launchId === "string" &&
    isPendingHypervisorLaunchRequest(value.request)
  ) {
    return {
      launchId: value.launchId,
      request: value.request,
    };
  }

  if (isPendingHypervisorLaunchRequest(value)) {
    return createPendingHypervisorLaunchEnvelope(value);
  }

  return null;
}

function readPendingHypervisorLaunchEnvelope(): PendingHypervisorLaunchEnvelope | null {
  if (!canUseStorage()) {
    return null;
  }

  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    return normalizePendingHypervisorLaunchEnvelope(JSON.parse(raw));
  } catch (error) {
    console.warn("Failed to parse pending Hypervisor launch request:", error);
    window.localStorage.removeItem(STORAGE_KEY);
    return null;
  }
}

function readHypervisorLaunchReceipts(): HypervisorLaunchReceipt[] {
  if (!canUseStorage()) {
    return [];
  }

  const raw = window.localStorage.getItem(RECEIPTS_STORAGE_KEY);
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as HypervisorLaunchReceipt[]) : [];
  } catch (error) {
    console.warn("Failed to parse Hypervisor launch receipts:", error);
    window.localStorage.removeItem(RECEIPTS_STORAGE_KEY);
    return [];
  }
}

function appendHypervisorLaunchReceipt(stage: string, detail: unknown) {
  if (!canUseStorage()) {
    return;
  }

  const nextReceipts = [
    ...readHypervisorLaunchReceipts(),
    {
      timestampMs: Date.now(),
      stage,
      detail,
    } satisfies HypervisorLaunchReceipt,
  ].slice(-MAX_RECEIPTS);
  window.localStorage.setItem(RECEIPTS_STORAGE_KEY, JSON.stringify(nextReceipts));
}

export function setPendingHypervisorLaunchRequest(
  request: PendingHypervisorLaunchRequest | null,
): Promise<void> {
  if (!canUseStorage()) {
    return Promise.resolve();
  }

  if (canUseHostBridge()) {
    if (!request) {
      return clearPendingHypervisorLaunchRequest();
    }
    return invoke<void>("set_pending_hypervisor_launch", { request }).catch(() => {
      const envelope = createPendingHypervisorLaunchEnvelope(request);
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
    });
  }

  if (!request) {
    window.localStorage.removeItem(STORAGE_KEY);
    return Promise.resolve();
  }

  const envelope = createPendingHypervisorLaunchEnvelope(request);
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
  return Promise.resolve();
}

export function showHypervisorWithLaunchRequest(
  request: PendingHypervisorLaunchRequest,
): Promise<void> {
  if (canUseHostBridge()) {
    return invoke<void>("show_hypervisor_with_target", { request }).catch(async () => {
      await setPendingHypervisorLaunchRequest(request);
      await invoke<void>("show_hypervisor").catch(() => undefined);
    });
  }

  return setPendingHypervisorLaunchRequest(request);
}

export function clearPendingHypervisorLaunchRequest() {
  if (!canUseStorage()) {
    return Promise.resolve();
  }

  if (canUseHostBridge()) {
    return invoke<void>("clear_pending_hypervisor_launch").catch(() => {
      window.localStorage.removeItem(STORAGE_KEY);
    });
  }

  window.localStorage.removeItem(STORAGE_KEY);
  return Promise.resolve();
}

export function peekPendingHypervisorLaunchRequest(): Promise<PendingHypervisorLaunchEnvelope | null> {
  if (!canUseStorage()) {
    return Promise.resolve(null);
  }

  if (canUseHostBridge()) {
    return invoke<PendingHypervisorLaunchEnvelope | null>(
      "peek_pending_hypervisor_launch",
    ).catch(() => readPendingHypervisorLaunchEnvelope());
  }

  return Promise.resolve(readPendingHypervisorLaunchEnvelope());
}

export function ackPendingHypervisorLaunchRequest(launchId: string): Promise<boolean> {
  if (!canUseStorage()) {
    return Promise.resolve(false);
  }

  if (canUseHostBridge()) {
    return invoke<boolean>("ack_pending_hypervisor_launch", { launchId }).catch(() => {
      const pendingLaunch = readPendingHypervisorLaunchEnvelope();
      if (pendingLaunch?.launchId === launchId) {
        window.localStorage.removeItem(STORAGE_KEY);
        return true;
      }
      return false;
    });
  }

  const pendingLaunch = readPendingHypervisorLaunchEnvelope();
  if (pendingLaunch?.launchId === launchId) {
    window.localStorage.removeItem(STORAGE_KEY);
    return Promise.resolve(true);
  }
  return Promise.resolve(false);
}

export function recordHypervisorLaunchReceipt(stage: string, detail: unknown = {}) {
  if (!canUseStorage()) {
    return Promise.resolve();
  }

  if (canUseHostBridge()) {
    return invoke("record_hypervisor_launch_receipt", {
      stage,
      detail,
    }).catch(() => {
      appendHypervisorLaunchReceipt(stage, detail);
    });
  }

  appendHypervisorLaunchReceipt(stage, detail);
  return Promise.resolve();
}

export function getHypervisorLaunchReceipts(): Promise<HypervisorLaunchReceipt[]> {
  if (!canUseStorage()) {
    return Promise.resolve([]);
  }

  if (canUseHostBridge()) {
    return invoke<HypervisorLaunchReceipt[]>("get_hypervisor_launch_receipts").catch(
      () => readHypervisorLaunchReceipts(),
    );
  }

  return Promise.resolve(readHypervisorLaunchReceipts());
}
