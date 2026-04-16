import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";
import { getSessionId } from "./session-status";
import { submitAssistantSessionRuntimePassword } from "./session-runtime";

interface SessionClarificationOptionLike {
  id: string;
  label?: string | null;
  description?: string | null;
}

interface SessionClarificationRequestLike {
  kind?: string | null;
  question?: string | null;
  tool_name?: string | null;
  failure_class?: string | null;
  context_hint?: string | null;
  options?: SessionClarificationOptionLike[] | null;
}

interface SessionInterruptionTaskLike {
  id?: string | null;
  session_id?: string | null;
  clarification_request?: SessionClarificationRequestLike | null;
}

const intentResolutionCanonicalPrompts: Record<string, string> = {
  use_current_area: "near me",
  general_weather_guidance:
    "Give general weather guidance without checking a local forecast.",
  general_layering:
    "Give general weather guidance without checking a local forecast.",
  broad_city_recs: "Give broader city-level recommendations.",
  league_overview:
    "Give a league overview instead of a specific team or matchup.",
  recent_results_only: "Focus on recent results and headlines.",
  nba_default: "Use the NBA.",
  nfl_default: "Use the NFL.",
  coffee_shops: "Search for coffee shops.",
  restaurants: "Search for restaurants.",
  draft_email: "Draft it as an email.",
  draft_slack: "Draft it as a Slack message.",
  draft_text: "Draft it as a text message.",
  open_capabilities_to_connect:
    "Open capabilities so I can connect the required source.",
  wait_for_connector: "Wait for me to connect the source, then retry.",
  paste_the_source_data: "I will paste the source data here.",
  use_a_different_source: "Use a different available source.",
};

function resolveSessionId(
  task: SessionInterruptionTaskLike | null,
): string | null {
  return getSessionId(task);
}

function buildClarificationPrompt(
  request: SessionClarificationRequestLike | null | undefined,
  optionId: string,
  otherText: string,
): string {
  const selected = request?.options?.find((option) => option.id === optionId);
  const exactIdentifier = otherText.trim();
  const requestKind = request?.kind?.toLowerCase() ?? "";
  const isIntentResolution = requestKind === "intent_resolution";
  const intentStrategyFallback: Record<string, string> = {
    clarify_outcome: "Please continue with the current request outcome.",
    add_constraints: "Please continue with added constraints.",
    cancel_request: "Cancel this request.",
  };

  if (isIntentResolution) {
    return (
      exactIdentifier ||
      intentResolutionCanonicalPrompts[optionId] ||
      selected?.description ||
      intentStrategyFallback[optionId] ||
      "Continue."
    );
  }

  return [
    "Clarification response:",
    request?.question ? `question=${request.question}` : undefined,
    request?.tool_name ? `tool_name=${request.tool_name}` : undefined,
    request?.failure_class
      ? `failure_class=${request.failure_class}`
      : undefined,
    request?.context_hint ? `context_hint=${request.context_hint}` : undefined,
    `strategy=${optionId}`,
    selected ? `strategy_label=${selected.label}` : undefined,
    exactIdentifier ? `exact_identifier=${exactIdentifier}` : undefined,
    "Execution constraints:",
    exactIdentifier
      ? `- Treat '${exactIdentifier}' as the authoritative target identifier for the next retry.`
      : "- Use the selected strategy to resolve target identity.",
    "- Retry once on the same session.",
    "- If still unresolved, provide concrete discovered candidates and why each failed.",
    "- Do not ask the same clarification again without new evidence.",
  ]
    .filter(Boolean)
    .join("\n");
}

export interface UseSessionInterruptionActionsOptions<
  TTask extends SessionInterruptionTaskLike,
> {
  task: TTask | null;
  continueTask: (sessionId: string, userInput: string) => Promise<void>;
  setRuntimePasswordPending?: Dispatch<SetStateAction<boolean>>;
  setRuntimePasswordSessionId?: Dispatch<SetStateAction<string | null>>;
  onClarificationSubmit?: (input: {
    sessionId: string;
    optionId: string;
    exactIdentifier: string;
  }) => void;
  onClarificationCancel?: (input: { sessionId: string }) => void;
}

export function useSessionInterruptionActions<
  TTask extends SessionInterruptionTaskLike,
>({
  task,
  continueTask,
  setRuntimePasswordPending,
  setRuntimePasswordSessionId,
  onClarificationSubmit,
  onClarificationCancel,
}: UseSessionInterruptionActionsOptions<TTask>) {
  const handleSubmitRuntimePassword = useCallback(
    async (password: string) => {
      const sessionId = resolveSessionId(task);
      if (!sessionId) {
        throw new Error("No active session found");
      }

      setRuntimePasswordPending?.(true);
      setRuntimePasswordSessionId?.(sessionId);

      try {
        await submitAssistantSessionRuntimePassword(sessionId, password);
      } catch (error) {
        setRuntimePasswordPending?.(false);
        setRuntimePasswordSessionId?.(null);
        throw error;
      }
    },
    [setRuntimePasswordPending, setRuntimePasswordSessionId, task],
  );

  const handleCancelRuntimePassword = useCallback(() => {
    // Keep the session paused until the operator provides the credential or starts a new run.
  }, []);

  const handleSubmitClarification = useCallback(
    async (optionId: string, otherText: string) => {
      const sessionId = resolveSessionId(task);
      if (!sessionId) {
        throw new Error("No active session found");
      }

      const exactIdentifier = otherText.trim();
      onClarificationSubmit?.({
        sessionId,
        optionId,
        exactIdentifier,
      });

      await continueTask(
        sessionId,
        buildClarificationPrompt(
          task?.clarification_request,
          optionId,
          otherText,
        ),
      );
    },
    [continueTask, onClarificationSubmit, task],
  );

  const handleCancelClarification = useCallback(() => {
    const sessionId = resolveSessionId(task);
    if (!sessionId) {
      return;
    }

    onClarificationCancel?.({ sessionId });

    void continueTask(
      sessionId,
      "User canceled clarification. Stop retries for this task, summarize the blocker, and remain idle until a new user request.",
    ).catch(console.error);
  }, [continueTask, onClarificationCancel, task]);

  return {
    handleSubmitRuntimePassword,
    handleCancelRuntimePassword,
    handleSubmitClarification,
    handleCancelClarification,
  };
}

export function buildClarificationPromptForTests(
  request: SessionClarificationRequestLike | null | undefined,
  optionId: string,
  otherText: string,
): string {
  return buildClarificationPrompt(request, optionId, otherText);
}
