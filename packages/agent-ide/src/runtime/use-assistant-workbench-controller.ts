import { useEffect, useMemo, useState } from "react";
import type {
  AssistantWorkbenchSession,
} from "./assistant-session-runtime-types";
import type { AgentWorkbenchRuntime } from "./agent-workbench-runtime-types";
import { createAssistantWorkbenchActivity } from "./assistant-workbench-activity";
import {
  buildMeetingBriefDraft,
  buildMeetingPrepAutopilotIntent,
  buildReplyAutopilotIntent,
  buildReplyBody,
  buildReplyReferences,
  collectCalendarLinks,
  ensureReplySubject,
  extractEmailAddress,
} from "./assistant-workbench-content";
import { reportAssistantWorkbenchActivity } from "./session-runtime";
import {
  buildConnectorApprovalMemoryRequest,
  parseShieldApprovalRequest,
  type ShieldApprovalRequest,
} from "./shield-approval";

export type AssistantWorkbenchBusyAction =
  | "draft"
  | "send"
  | "copy"
  | null;

export interface UseAssistantWorkbenchActionsOptions {
  session: AssistantWorkbenchSession | null;
  runtime: AgentWorkbenchRuntime;
}

async function emitWorkbenchActivity(
  session: AssistantWorkbenchSession | null,
  params: Parameters<typeof createAssistantWorkbenchActivity>[1],
) {
  if (!session) {
    return;
  }
  try {
    await reportAssistantWorkbenchActivity(
      createAssistantWorkbenchActivity(session, params),
    );
  } catch (error) {
    console.error("Failed to report assistant workbench activity:", error);
  }
}

export function useAssistantWorkbenchActions({
  session,
  runtime,
}: UseAssistantWorkbenchActionsOptions) {
  const [replyTo, setReplyTo] = useState("");
  const [replySubject, setReplySubject] = useState("");
  const [replyBody, setReplyBody] = useState("");
  const [meetingBrief, setMeetingBrief] = useState("");
  const [busyAction, setBusyAction] =
    useState<AssistantWorkbenchBusyAction>(null);
  const [actionResult, setActionResult] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [pendingShieldApproval, setPendingShieldApproval] =
    useState<{
      actionId: "gmail.draft_email" | "gmail.send_email";
      request: ShieldApprovalRequest;
    } | null>(null);

  const latestMessage = useMemo(() => {
    if (!session || session.kind !== "gmail_reply") {
      return null;
    }
    return session.thread.messages[session.thread.messages.length - 1] ?? null;
  }, [session]);

  const meetingLinks = useMemo(() => {
    if (!session || session.kind !== "meeting_prep") {
      return [];
    }
    return collectCalendarLinks(session.event);
  }, [session]);

  useEffect(() => {
    setActionResult(null);
    setActionError(null);
    setPendingShieldApproval(null);
    setBusyAction(null);

    if (!session) {
      setReplyTo("");
      setReplySubject("");
      setReplyBody("");
      setMeetingBrief("");
      return;
    }

    if (session.kind === "gmail_reply") {
      const latest = session.thread.messages[session.thread.messages.length - 1];
      setReplyTo(extractEmailAddress(latest?.from));
      setReplySubject(ensureReplySubject(latest?.subject));
      setReplyBody(buildReplyBody(session.thread));
      setMeetingBrief("");
      return;
    }

    setReplyTo("");
    setReplySubject("");
    setReplyBody("");
    setMeetingBrief(buildMeetingBriefDraft(session.event));
  }, [session]);

  const runReplyAction = async (
    actionId: "gmail.draft_email" | "gmail.send_email",
    options?: { shieldApproved?: boolean },
  ) => {
    if (!session || session.kind !== "gmail_reply") {
      return;
    }
    if (!runtime.runConnectorAction) {
      setActionError("Connector action runtime is unavailable in this shell.");
      return;
    }
    if (!replyTo.trim() || !replySubject.trim() || !replyBody.trim()) {
      setActionError("Recipient, subject, and body are required.");
      return;
    }

    setBusyAction(actionId === "gmail.draft_email" ? "draft" : "send");
    setActionError(null);
    setPendingShieldApproval(null);

    await emitWorkbenchActivity(session, {
      action: actionId === "gmail.draft_email" ? "draft" : "send",
      status: "started",
      message:
        actionId === "gmail.draft_email"
          ? "Saving Gmail draft from Gate/Chat workbench."
          : "Sending Gmail reply from Gate/Chat workbench.",
    });

    try {
      const latest = session.thread.messages[session.thread.messages.length - 1];
      const result = await runtime.runConnectorAction({
        connectorId: session.connectorId,
        actionId,
        input: {
          to: replyTo.trim(),
          subject: replySubject.trim(),
          body: replyBody,
          threadId: session.thread.threadId,
          inReplyTo: latest?.rfcMessageId ?? null,
          references:
            buildReplyReferences(latest?.references, latest?.rfcMessageId) ??
            null,
          ...(options?.shieldApproved ? { _shieldApproved: true } : {}),
        },
      });
      setActionResult(result.summary);
      await emitWorkbenchActivity(session, {
        action: actionId === "gmail.draft_email" ? "draft" : "send",
        status: "succeeded",
        message: result.summary,
      });
    } catch (nextError) {
      const approvalRequest = parseShieldApprovalRequest(nextError);
      if (approvalRequest && !options?.shieldApproved) {
        setActionResult(null);
        setActionError(null);
        setPendingShieldApproval({ actionId, request: approvalRequest });
        await emitWorkbenchActivity(session, {
          action: "shield_approval",
          status: "requested",
          message: approvalRequest.message,
        });
        return;
      }
      setActionError(String(nextError));
      await emitWorkbenchActivity(session, {
        action: actionId === "gmail.draft_email" ? "draft" : "send",
        status: "failed",
        message:
          actionId === "gmail.draft_email"
            ? "Gmail draft action failed."
            : "Gmail send action failed.",
        detail: String(nextError),
      });
    } finally {
      setBusyAction(null);
    }
  };

  const approvePendingShieldAction = async () => {
    if (!pendingShieldApproval) {
      return;
    }
    if (runtime.rememberConnectorApproval) {
      const input = buildConnectorApprovalMemoryRequest(
        pendingShieldApproval.request,
        "Assistant workbench",
      );
      if (input) {
        try {
          await runtime.rememberConnectorApproval(input);
        } catch (error) {
          console.warn("Failed to remember Shield approval:", error);
        }
      }
    }
    await runReplyAction(pendingShieldApproval.actionId, {
      shieldApproved: true,
    });
  };

  const copyMeetingBrief = async () => {
    if (!meetingBrief.trim()) {
      setActionError("Nothing to copy yet.");
      return;
    }

    setBusyAction("copy");
    setActionError(null);

    await emitWorkbenchActivity(session, {
      action: "copy",
      status: "started",
      message: "Copying meeting brief to clipboard.",
    });

    try {
      if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(meetingBrief);
        setActionResult("Copied meeting brief to clipboard.");
        await emitWorkbenchActivity(session, {
          action: "copy",
          status: "succeeded",
          message: "Copied meeting brief to clipboard.",
        });
      } else {
        throw new Error("Clipboard access is unavailable in this environment.");
      }
    } catch (nextError) {
      setActionError(String(nextError));
      await emitWorkbenchActivity(session, {
        action: "copy",
        status: "failed",
        message: "Meeting brief copy failed.",
        detail: String(nextError),
      });
    } finally {
      setBusyAction(null);
    }
  };

  const reportAutopilotHandoff = async (intent: string) => {
    if (!session) {
      return;
    }

    await emitWorkbenchActivity(session, {
      action: "autopilot_handoff",
      status: "started",
      message:
        session.kind === "gmail_reply"
          ? "Handing the reply draft to Autopilot."
          : "Handing the meeting prep brief to Autopilot.",
      detail: intent,
    });
  };

  return {
    replyTo,
    setReplyTo,
    replySubject,
    setReplySubject,
    replyBody,
    setReplyBody,
    meetingBrief,
    setMeetingBrief,
    busyAction,
    actionResult,
    actionError,
    pendingShieldApproval,
    latestMessage,
    meetingLinks,
    replyAutopilotIntent:
      session && session.kind === "gmail_reply"
        ? buildReplyAutopilotIntent(session.thread, replyTo, replySubject, replyBody)
        : null,
    meetingPrepAutopilotIntent:
      session && session.kind === "meeting_prep"
        ? buildMeetingPrepAutopilotIntent(session.event, meetingBrief)
        : null,
    runReplyAction,
    approvePendingShieldAction,
    dismissPendingShieldApproval: () => setPendingShieldApproval(null),
    copyMeetingBrief,
    reportAutopilotHandoff,
  };
}

export type UseAssistantWorkbenchControllerOptions =
  UseAssistantWorkbenchActionsOptions;

export const useAssistantWorkbenchController = useAssistantWorkbenchActions;
