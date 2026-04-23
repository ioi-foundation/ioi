import type { SessionServerSnapshot } from "../../../types";

export type ServerOverviewTone = "ready" | "setup" | "attention";

export interface ServerOverview {
  tone: ServerOverviewTone;
  statusLabel: string;
  statusDetail: string;
  continuityMeta: string[];
  historyMeta: string[];
  currentSessionLabel: string;
  currentSessionDetail: string;
}

export function buildServerOverview(
  snapshot: SessionServerSnapshot | null,
): ServerOverview {
  if (!snapshot) {
    return {
      tone: "setup",
      statusLabel: "Server posture loading",
      statusDetail:
        "Open a retained session to inspect the kernel RPC target, continuity posture, and remote history merge state.",
      continuityMeta: ["Awaiting kernel snapshot"],
      historyMeta: ["No retained continuity signal yet"],
      currentSessionLabel: "Awaiting continuity posture",
      currentSessionDetail:
        "The current-session remote posture will appear once the shared runtime publishes a server snapshot.",
    };
  }

  const tone: ServerOverviewTone = !snapshot.kernelReachable
    ? "attention"
    : snapshot.remoteHistoryAvailable || snapshot.remoteOnlySessionCount > 0
      ? "ready"
      : "setup";

  return {
    tone,
    statusLabel: snapshot.continuityStatusLabel,
    statusDetail: snapshot.continuityDetail,
    continuityMeta: [
      snapshot.continuityModeLabel,
      snapshot.rpcSourceLabel,
      snapshot.remoteKernelTarget ? "Remote target" : "Local target",
    ],
    historyMeta: [
      `${snapshot.localSessionCount} local`,
      `${snapshot.remoteSessionCount} remote`,
      `${snapshot.mergedSessionCount} merged`,
      `${snapshot.remoteAttachableSessionCount} remote attachable`,
      `${snapshot.remoteHistoryOnlySessionCount} remote history-only`,
    ],
    currentSessionLabel: snapshot.currentSessionContinuityLabel,
    currentSessionDetail: snapshot.currentSessionContinuityDetail,
  };
}
