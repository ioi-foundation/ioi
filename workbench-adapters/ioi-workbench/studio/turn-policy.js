"use strict";

function createStudioTurnPolicy({
  firstArray,
  humanizeStudioToolName,
  stringValue,
  studioIntentFramePayload,
  studioIntentFrameRequiresRetrieval,
  studioRuntimeEventsIncludeCompletedTool,
  studioRuntimeEventToolName,
  uniqueStrings,
}) {
  function studioRetrievalFailClosedText({ events = [] } = {}) {
    const hasSearch = studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)search|search_web|web_search/);
    const hasRead = studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)read|read_web|web_read/);
    if (!(hasSearch || hasRead)) {
      return "";
    }
    return "I couldn't finish a clean answer from the sources I gathered. Details are in Tracing.";
  }

  function studioResultTextLooksRetrievalGrounded(text = "") {
    return /\b(web retrieval summary|current snapshot|citations?:|retrieved_utc|fresh evidence|retrieved current sources)\b/i.test(
      stringValue(text),
    );
  }

  function studioAgentMaxStepsForIntent(intentFrame = {}, prompt = "") {
    const intentText = `${stringValue(prompt)} ${JSON.stringify(studioIntentFramePayload(intentFrame))}`.toLowerCase();
    if (
      studioIntentFrameRequiresRetrieval(intentFrame, prompt) ||
      /\b(latest|current|today|now|price|investment|sources?|citations?|cite|web|search)\b/.test(intentText)
    ) {
      return 24;
    }
    if (/\b(repository|repo|codebase|workspace|files?|tests?|debug|fix|implement|refactor)\b/.test(intentText)) {
      return 16;
    }
    return 12;
  }

  function studioTextIndicatesApprovalPause(text = "") {
    return /\b(waiting for approval|awaiting .*approval|approval required|requires approval|pending approval|policy gate)\b/i.test(
      stringValue(text),
    );
  }

  function studioApprovalPauseErrorMessage({ resultText, events = [] } = {}) {
    const observedTools = uniqueStrings(firstArray(events).map((event) => studioRuntimeEventToolName(event)).filter(Boolean));
    const toolName = humanizeStudioToolName(observedTools.find(Boolean) || "");
    return [
      toolName
        ? `Permission is required before Agent can use ${toolName}.`
        : "Permission is required before Agent can continue.",
      "Details are in Tracing.",
      resultText && !/^waiting for approval\.?$/i.test(resultText) ? `Runtime status: ${resultText}.` : "",
    ].filter(Boolean).join(" ");
  }

  function studioPolicyBlockedRuntimeMessage({ prompt = "", resultText = "", events = [] } = {}) {
    const combined = [
      prompt,
      resultText,
      ...firstArray(events).map((event) =>
        [
          event?.summary,
          event?.payload?.output,
          event?.payload?.message,
          event?.payload_summary?.output,
          event?.payload_summary?.message,
          event?.payload_summary?.summary,
        ].filter(Boolean).join(" "),
      ),
    ].join(" ");
    if (!/\b(Blocked by Policy|PolicyBlocked|policy blocking|outside workspace authority|outside the workspace boundary|ignored workspace files?|symlink paths? must be resolved)\b/i.test(combined)) {
      return "";
    }
    const observedTools = uniqueStrings(firstArray(events).map((event) => studioRuntimeEventToolName(event)).filter(Boolean));
    const fileReadBlocked = observedTools.some((tool) => String(tool).toLowerCase() === "file__read") ||
      /\bfile__read\b/i.test(combined);
    if (!fileReadBlocked) {
      return "";
    }
    const path = (
      String(prompt || "").match(/`([^`]+)`/) ||
      String(resultText || "").match(/\bread\s+(\/\S+)/i) ||
      []
    )[1];
    const reason = /\bignored workspace files?\b/i.test(combined)
      ? "because ignored workspace files are protected"
      : /\bsymlink paths? must be resolved\b|\bsymlink\b/i.test(combined)
        ? "because symlink targets require an explicit governed workflow"
        : "because the target is outside the workspace boundary";
    return [
      `The daemon blocked the file read${path ? ` for \`${path}\`` : ""} ${reason}.`,
      "I did not expose the file contents. Details are in Tracing.",
    ].join(" ");
  }

  function studioApprovalPauseError({ resultText, events = [] } = {}) {
    const error = new Error(studioApprovalPauseErrorMessage({ resultText, events }));
    error.code = "studio_approval_pause";
    error.studioApprovalPause = true;
    return error;
  }

  return {
    studioAgentMaxStepsForIntent,
    studioApprovalPauseError,
    studioApprovalPauseErrorMessage,
    studioPolicyBlockedRuntimeMessage,
    studioResultTextLooksRetrievalGrounded,
    studioRetrievalFailClosedText,
    studioTextIndicatesApprovalPause,
  };
}

module.exports = {
  createStudioTurnPolicy,
};
