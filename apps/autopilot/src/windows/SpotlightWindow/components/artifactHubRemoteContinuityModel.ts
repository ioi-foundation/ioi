import type { SessionServerSessionRecord } from "../../../types";

export type SpotlightRemoteContinuityLaunchMode = "attach" | "review";

export interface SpotlightRemoteContinuityLaunchRequest {
  sessionId: string;
  source: "mobile" | "server";
  mode: SpotlightRemoteContinuityLaunchMode;
  notice: string;
  queueSessionIds?: string[];
  queueLabel?: string | null;
}

export interface RemoteSessionContinuityActionState {
  attachable: boolean;
  spotlightLabel: string;
  studioLabel: string;
  detail: string;
  launchRequest: SpotlightRemoteContinuityLaunchRequest;
}

export interface MobileEvidenceContinuityActionState {
  available: boolean;
  attachable: boolean;
  spotlightLabel: string;
  studioLabel: string;
  detail: string;
  launchRequest: SpotlightRemoteContinuityLaunchRequest | null;
}

export function buildRemoteSessionContinuityAction(
  session: SessionServerSessionRecord,
): RemoteSessionContinuityActionState {
  const attachable = Boolean(session.workspaceRoot?.trim());
  const presenceState = session.presenceState || "remote_only_history_only";
  const detail =
    presenceState === "merged_attachable"
      ? "This retained remote session is already merged into local shell history and still carries a workspace root, so Spotlight can reopen the REPL lens and Studio can resume the same continuity target."
      : presenceState === "merged_history_only"
        ? "This retained remote session is already merged into local shell history, but only summary continuity remains right now; Spotlight and Studio can reopen the retained session, though PTY attach needs a workspace-backed run."
        : presenceState === "remote_only_attachable"
          ? "This retained remote session exists only in remote history, but it still carries a workspace root, so Spotlight can reopen the REPL lens and Studio can resume the same session target."
          : "This retained remote session can still reopen in Spotlight or Studio even though only history, not a workspace-backed REPL target, is currently available.";

  return {
    attachable,
    spotlightLabel: attachable
      ? "Attach in Spotlight REPL"
      : "Review in Spotlight REPL",
    studioLabel: "Open in Studio",
    detail,
    launchRequest: {
      sessionId: session.sessionId,
      source: "server",
      mode: attachable ? "attach" : "review",
      notice: attachable
        ? "Server continuity selected an attachable retained remote session. The shared REPL can pivot straight into that workspace-backed shell target."
        : "Server continuity selected a history-only retained remote session. The shared REPL will open in review mode until a workspace-backed run is retained again.",
    },
  };
}

export function buildMobileEvidenceContinuityAction(input: {
  evidenceThreadId?: string | null;
  hasActiveWorkbench: boolean;
  hasAttachableSessionTarget: boolean;
}): MobileEvidenceContinuityActionState {
  if (input.hasActiveWorkbench) {
    return {
      available: true,
      attachable: input.hasAttachableSessionTarget,
      spotlightLabel: input.hasAttachableSessionTarget
        ? "Attach in Spotlight REPL"
        : "Review in Spotlight REPL",
      studioLabel: "Resume in Studio",
      detail: input.hasAttachableSessionTarget
        ? "The active handoff already lives on the shared runtime and still carries an attachable retained session target, so Spotlight can reopen the REPL lens and Studio can resume the same continuity target."
        : "The active handoff already lives on the shared runtime, so Spotlight and Studio can reopen the same retained evidence thread without rebuilding shell-local state.",
      launchRequest: input.evidenceThreadId?.trim()
        ? {
            sessionId: input.evidenceThreadId,
            source: "mobile",
            mode: input.hasAttachableSessionTarget ? "attach" : "review",
            notice: input.hasAttachableSessionTarget
              ? "Mobile continuity selected the active retained handoff and requested an attachable REPL resume over the shared session target."
              : "Mobile continuity selected the active retained handoff for review-only continuity because no attachable workspace root is currently retained.",
          }
        : null,
    };
  }

  if (input.evidenceThreadId?.trim()) {
    return {
      available: true,
      attachable: input.hasAttachableSessionTarget,
      spotlightLabel: input.hasAttachableSessionTarget
        ? "Attach in Spotlight REPL"
        : "Review in Spotlight REPL",
      studioLabel: "Open in Studio",
      detail: input.hasAttachableSessionTarget
        ? "The retained handoff evidence thread still matches an attachable retained session target, so Spotlight and Studio can reopen the same continuity target even when the native handoff surface is no longer active."
        : "The retained handoff evidence thread can reopen directly in Spotlight or Studio even when the native handoff surface is no longer active.",
      launchRequest: {
        sessionId: input.evidenceThreadId,
        source: "mobile",
        mode: input.hasAttachableSessionTarget ? "attach" : "review",
        notice: input.hasAttachableSessionTarget
          ? "Mobile continuity selected a retained handoff with an attachable session target, so the shared REPL can reattach without rebuilding local shell state."
          : "Mobile continuity selected retained handoff evidence for review-only continuity because only the evidence thread, not an attachable workspace root, is still retained.",
      },
    };
  }

  return {
    available: false,
    attachable: false,
    spotlightLabel: "Review in Spotlight REPL",
    studioLabel: "Open in Studio",
    detail:
      "No retained evidence thread is available to reopen yet.",
    launchRequest: null,
  };
}
