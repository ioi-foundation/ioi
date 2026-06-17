const CANNED_DAEMON_RESPONSE_PATTERNS = [
  /IOI daemon run completed/i,
  /Source=local_daemon_agentgres/i,
  /Agentgres canonical projection/i,
  /Daemon turn completed for:/i,
];

const NON_SEMANTIC_MODEL_RESPONSE_PATTERNS = [
  /IOI model router fixture response/i,
  /Hypervisor native local model response/i,
  /^Hello! I am a local assistant\.?$/i,
  /\binput_hash=[0-9a-f]{8,}\b/i,
];

export function assertNotCannedDaemonProjection(text, prompt) {
  const matched = CANNED_DAEMON_RESPONSE_PATTERNS.find((pattern) => pattern.test(text || ""));
  if (matched) {
    throw new Error(`Assistant response for "${prompt.slice(0, 40)}" used canned daemon projection: ${matched}`);
  }
}

export function assertSemanticModelResponse(text, prompt) {
  const matched = NON_SEMANTIC_MODEL_RESPONSE_PATTERNS.find((pattern) => pattern.test(text || ""));
  if (matched) {
    throw new Error(`Assistant response for "${prompt.slice(0, 40)}" used fixture/non-semantic model output: ${matched}`);
  }
}

export function isApprovalPauseText(text) {
  return /\b(waiting for approval|awaiting .*approval|approval required|requires approval|pending approval|policy gate|permission is required)\b/i.test(String(text || ""));
}

export function promptResultToolName(item) {
  return (
    String(item?.prompt || "").match(/\btoolcat_tool=([A-Za-z0-9_.:-]+)/)?.[1] ||
    String(item?.kind || "").match(/\b([A-Za-z]+__[A-Za-z0-9_:-]+|computer_use\.[A-Za-z0-9_:-]+)\b/)?.[1] ||
    ""
  );
}

export function approvalPauseSummary(promptResults = []) {
  return promptResults
    .filter((item) => isApprovalPauseText(item.assistantText) || /blocked|paused|approval/i.test(String(item.completionStatusObserved || "")))
    .map((item) => ({
      kind: item.kind,
      prompt: String(item.prompt || "").slice(0, 160),
      completionStatus: item.completionStatusObserved,
      assistantText: String(item.assistantText || "").slice(0, 240),
    }));
}

export function assertPromptSpecificResponse(text, promptCase) {
  const requiredAllTerms = Array.isArray(promptCase.mustMentionAll)
    ? promptCase.mustMentionAll.map((term) => String(term || "").trim()).filter(Boolean)
    : [];
  const requiredTerms = Array.isArray(promptCase.mustMentionAny)
    ? promptCase.mustMentionAny.map((term) => String(term || "").trim()).filter(Boolean)
    : [];
  if (requiredAllTerms.length === 0 && requiredTerms.length === 0) return;
  const lowerText = String(text || "").toLowerCase();
  const missing = requiredAllTerms.filter((term) => !lowerText.includes(term.toLowerCase()));
  if (missing.length > 0) {
    throw new Error(
      `Assistant response for "${String(promptCase.prompt || promptCase.kind).slice(0, 40)}" was not prompt-specific; missing required terms: ${missing.join(", ")}`,
    );
  }
  if (requiredTerms.length === 0) return;
  const matched = requiredTerms.some((term) => lowerText.includes(term.toLowerCase()));
  if (!matched) {
    throw new Error(
      `Assistant response for "${String(promptCase.prompt || promptCase.kind).slice(0, 40)}" was not prompt-specific; expected one of: ${requiredTerms.join(", ")}`,
    );
  }
}

export function assertPromptForbiddenTermsAbsent(text, promptCase) {
  const forbiddenTerms = Array.isArray(promptCase.mustNotMentionAny)
    ? promptCase.mustNotMentionAny.map((term) => String(term || "").trim()).filter(Boolean)
    : [];
  const forbiddenPatterns = Array.isArray(promptCase.mustNotMentionPatterns)
    ? promptCase.mustNotMentionPatterns.map((pattern) => String(pattern || "").trim()).filter(Boolean)
    : [];
  if (forbiddenTerms.length === 0 && forbiddenPatterns.length === 0) return;
  const responseText = String(text || "");
  const lowerText = responseText.toLowerCase();
  const matched = forbiddenTerms.find((term) => lowerText.includes(term.toLowerCase()));
  if (matched) {
    throw new Error(
      `Assistant response for "${String(promptCase.prompt || promptCase.kind).slice(0, 40)}" included forbidden direct-tool text: ${matched}`,
    );
  }
  const matchedPattern = forbiddenPatterns.find((pattern) => {
    try {
      return new RegExp(pattern, "i").test(responseText);
    } catch {
      return responseText.toLowerCase().includes(pattern.toLowerCase());
    }
  });
  if (matchedPattern) {
    throw new Error(
      `Assistant response for "${String(promptCase.prompt || promptCase.kind).slice(0, 40)}" matched forbidden product pattern: ${matchedPattern}`,
    );
  }
}
