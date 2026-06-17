function createStudioPublicTextSanitizer({
  compactStudioWhitespace,
  studioTextIndicatesApprovalPause,
}) {
  const STUDIO_TOOLCAT_MARKER_RE = /\bTOOLCAT_(?:SINGLE_TOOL|STAGE\d+_[A-Z0-9_]+)\b/i;
  const STUDIO_TOOLCAT_TOOL_RE = /\btoolcat_tool=([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i;
  const STUDIO_TOOLCAT_SINGLE_TOOL_RE = /\bTOOLCAT_SINGLE_TOOL\s+([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i;

  function humanizeStudioToolName(value = "") {
    const compact = compactStudioWhitespace(value);
    if (!compact) {
      return "";
    }
    return compact
      .replace(/\./g, " ")
      .replace(/__+/g, " ")
      .replace(/_+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();
  }

  function studioToolcatToolName(text = "") {
    const value = String(text || "");
    return humanizeStudioToolName(
      value.match(STUDIO_TOOLCAT_TOOL_RE)?.[1] ||
        value.match(STUDIO_TOOLCAT_SINGLE_TOOL_RE)?.[1] ||
        "",
    );
  }

  function studioApprovalToolName(text = "") {
    const value = String(text || "");
    const match = value.match(/\btools?:\s*([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i);
    return humanizeStudioToolName(match?.[1] || "");
  }

  function studioSanitizePublicAssistantText(value = "") {
    return String(value || "")
      .replace(/\bwas blocked by the governed file tool\.\s*The tool returned (?:the following )?(?:the )?error:\s*/gi, "was blocked. The policy reason was: ")
      .replace(/\bThe governed file (?:tool|write) returned (?:the following )?(?:the )?error:\s*Blocked by policy:\s*/gi, "The policy reason was: ")
      .replace(/\bThe tool returned (?:the following )?(?:the )?error:\s*`*\s*Blocked by policy:\s*/gi, "The policy reason was: ")
      .replace(/`+\s*Blocked by policy:\s*/gi, "Blocked by policy: ")
      .replace(/\bThe policy reason was:\s*Blocked by policy:\s*/gi, "The policy reason was: ")
      .replace(/\s*`+(?=\s|$)/g, "")
      .replace(/\bThe tool returned an? ["']?Invalid transaction["']? error with the specific policy reason:\s*/gi, "The policy reason was: ")
      .replace(/\ban? ["']?Invalid transaction["']? error\b/gi, "a policy block")
      .replace(/\ban policy block\b/gi, "a policy block")
      .replace(/\bInvalid transaction:\s*/gi, "")
      .replace(/\bBlocked by Policy:\s*/gi, "Blocked by policy: ")
      .replace(/\bERROR_CLASS=[a-z0-9_:-]+\b/gi, "policy block")
      .replace(/`?\bfile__write\b`?/gi, "the governed file write")
      .replace(/`?\bfile__read\b`?/gi, "the governed file read")
      .replace(/`?\bshell__run\b`?/gi, "the governed command runner")
      .replace(/`?\/tmp\/(?:autopilot-agent-studio-|autopilot-|ioi-)[^\s"'<>)\]}]+`?/gi, "the requested workspace path")
      .replace(/\bshell__start:[a-f0-9]{12,}\b/gi, "command")
      .replace(/"command_id"\s*:\s*"[^"]+"\s*,?/gi, "")
      .replace(/"commandId"\s*:\s*"[^"]+"\s*,?/gi, "")
      .replace(/\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/gi, "Tracing")
      .replace(/\b(?:receipt|trace):\/\/[^\s)\]}]+/gi, "Tracing")
      .replace(/\bworkspace_change:[^\s)\]}]+/gi, "workspace change")
      .replace(/[ \t]+\n/g, "\n")
      .trim();
  }

  function studioHumanizeOperationalTranscriptText(value, role = "assistant") {
    const raw = String(value || "").trim();
    const compact = compactStudioWhitespace(raw);
    if (!compact) {
      return "";
    }
    if (STUDIO_TOOLCAT_MARKER_RE.test(compact)) {
      const toolName = studioToolcatToolName(compact);
      if (role === "user") {
        return toolName
          ? `Run live Rust tool catalogue verification for ${toolName}.`
          : "Run live Rust tool catalogue verification.";
      }
      if (/\bfailed\b|\bfailure\b/i.test(compact)) {
        return toolName
          ? `The live Rust tool catalogue probe failed for ${toolName}. Details are in Tracing.`
          : "The live Rust tool catalogue verification step failed. Details are in Tracing.";
      }
      return toolName
        ? `The live Rust tool catalogue probe completed for ${toolName}.`
        : "The live Rust tool catalogue verification step completed.";
    }
    if (role === "assistant" && studioTextIndicatesApprovalPause(compact)) {
      const toolName = studioApprovalToolName(compact);
      return toolName
        ? `Permission is required before Agent can use ${toolName}.`
        : "Permission is required before Agent can continue.";
    }
    if (
      role === "assistant" &&
      /Daemon agent turn completed but did not emit a final chat__reply|did not emit a final chat__reply|final chat__reply/i.test(compact)
    ) {
      return "Agent reached the runtime but did not produce a chat reply. Details are in Tracing.";
    }
    return role === "assistant" ? studioSanitizePublicAssistantText(raw) : raw;
  }

  function studioDisplayTurnContent(turn = {}) {
    return studioHumanizeOperationalTranscriptText(turn.content || "", turn.role || "assistant");
  }

  return {
    humanizeStudioToolName,
    studioApprovalToolName,
    studioDisplayTurnContent,
    studioHumanizeOperationalTranscriptText,
    studioSanitizePublicAssistantText,
    studioToolcatToolName,
  };
}

module.exports = {
  createStudioPublicTextSanitizer,
};
