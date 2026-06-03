const DEFAULT_STAGE2_WEB_REPAIR_URL = "https://ask.un.org/faq/14625";

function envTruthy(value) {
  return /^(1|true|yes|on)$/i.test(String(value || "").trim());
}

function safeProofUrl(value) {
  const candidate = String(value || "").trim();
  return /^https?:\/\//i.test(candidate) ? candidate : DEFAULT_STAGE2_WEB_REPAIR_URL;
}

function queryTargetsSecretaryGeneral(queryText, promptContextText) {
  const text = `${queryText || ""}\n${promptContextText || ""}`;
  return /\bSecretary-General\b/i.test(text) && /\b(UN|United Nations)\b/i.test(text);
}

function stage2WebRepairEnabled(queryText, promptContextText, inputText) {
  return (
    envTruthy(process.env.IOI_STAGE2_WEB_REPAIR_PROOF) &&
    queryTargetsSecretaryGeneral(queryText, `${promptContextText || ""}\n${inputText || ""}`)
  );
}

function stage2ChatReplyRejected(inputText) {
  const text = String(inputText || "");
  return (
    /\bERROR_CLASS=NoEffectAfterAction\b/i.test(text) ||
    /\bValidator feedback\b/i.test(text) ||
    /\bweb_model_chat_reply_contract_rejected_for_retry=true\b/i.test(text) ||
    /\bchat_reply_model_authored_web_pipeline_answer_rejected_for_retry\b/i.test(text) ||
    /\bFinal web answer is not ready\b/i.test(text)
  );
}

function stage2ChatReplyAccepted(inputText) {
  const text = String(inputText || "");
  return (
    /\bchat_reply_model_authored_web_pipeline_answer_accepted\b/i.test(text) ||
    /\bweb_final_answer_source=model_chat_reply\b/i.test(text) ||
    /\bterminal_chat_reply_ready=true\b/i.test(text)
  );
}

function stage2WebEvidenceAvailable(inputText, hasToolCalled) {
  const text = String(inputText || "");
  const called = typeof hasToolCalled === "function" ? hasToolCalled : () => false;
  return (
    called("web__read") ||
    /\bPENDING WEB TOOL EVIDENCE\b/i.test(text) ||
    /\bRetrieved source notes\b/i.test(text) ||
    /ask\.un\.org\/faq\/14625/i.test(text) ||
    /\bWho is and has been Secretary-General of the United Nations\b/i.test(text)
  );
}

function defaultJsonTool(name, args) {
  return JSON.stringify({ name, arguments: args });
}

export function nativeFixtureStage2WebRepairResponse({
  queryText,
  promptContextText,
  inputText,
  expectsJsonToolCall,
  hasToolCalled,
  jsonTool = defaultJsonTool,
} = {}) {
  if (!stage2WebRepairEnabled(queryText, promptContextText, inputText)) {
    return null;
  }

  const called = typeof hasToolCalled === "function" ? hasToolCalled : () => false;
  const proofUrl = safeProofUrl(process.env.IOI_STAGE2_WEB_REPAIR_URL);
  if (!expectsJsonToolCall) {
    if (stage2ChatReplyRejected(inputText)) {
      return [
        "Antonio Guterres is the current Secretary-General of the United Nations.",
        `I verified this against the United Nations Ask DAG source: ${proofUrl}`,
      ].join(" ");
    }
    if (stage2WebEvidenceAvailable(inputText, called)) {
      return "Antonio Guterres is the current Secretary-General of the United Nations, according to current United Nations source evidence.";
    }
    return "Fresh retrieval is required for current public facts; I should not guess from stale model memory.";
  }

  if (called("chat__reply") && stage2ChatReplyAccepted(inputText)) {
    return jsonTool("agent__complete", {
      result: "Stage 2 web answer repair completed through the terminal chat reply tool.",
    });
  }

  if (stage2ChatReplyRejected(inputText)) {
    return jsonTool("chat__reply", {
      message: [
        "Antonio Guterres is the current Secretary-General of the United Nations.",
        `I verified this against the United Nations Ask DAG source: ${proofUrl}`,
      ].join(" "),
    });
  }

  if (called("web__read")) {
    return jsonTool("chat__reply", {
      message: "I found a current web source for the United Nations Secretary-General and can answer now.",
    });
  }

  if (called("web__search")) {
    return jsonTool("web__read", {
      url: proofUrl,
      max_chars: 1600,
      allow_browser_fallback: true,
    });
  }

  return jsonTool("web__search", {
    query: "current Secretary-General of the United Nations site:ask.un.org",
    limit: 3,
  });
}
