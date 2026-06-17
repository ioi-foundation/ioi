"use strict";

const STUDIO_TOOLCAT_MARKER_RE = /\bTOOLCAT_(?:SINGLE_TOOL|STAGE\d+_[A-Z0-9_]+)\b/i;
const STUDIO_TOOLCAT_TOOL_RE = /\btoolcat_tool=([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i;
const STUDIO_TOOLCAT_SINGLE_TOOL_RE = /\bTOOLCAT_SINGLE_TOOL\s+([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i;

function createStudioPromptPolicy({
  normalizeStudioExecutionMode,
  stringValue,
  studioModeAgent,
}) {
  function compactStudioWhitespace(value = "") {
    return String(value || "").replace(/\s+/g, " ").trim();
  }

  function isAutoStudioModelSelector(value) {
    const normalized = stringValue(value, "auto").toLowerCase();
    return normalized === "auto" || normalized === "local:auto" || normalized === "default";
  }

  function promptTargetsLocalWorkspace(prompt = "") {
    const text = stringValue(prompt).toLowerCase();
    return /\b(repository|repo|workspace|project|codebase|source tree|current workspace|local source|inspect\b.*workspace|files?)\b/.test(text) ||
      /(?:^|\s|["'`])(?:\.\/|\.\.\/|\/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?|workbench-adapters)\//.test(text) ||
      /workspace_fixture_|daemon_endpoint=|computer_use_providers_url=|current trace history/.test(text);
  }

  function promptIsInternalHarnessProbe(prompt = "") {
    const text = stringValue(prompt);
    return STUDIO_TOOLCAT_MARKER_RE.test(text) ||
      /workspace_fixture_|daemon_endpoint=|computer_use_providers_url=|live IDE Rust\/provider tool row/i.test(text);
  }

  function promptRequiresRetrieval(prompt = "") {
    if (promptIsInternalHarnessProbe(prompt)) {
      return false;
    }
    const text = stringValue(prompt).toLowerCase();
    const targetsLocalWorkspace = promptTargetsLocalWorkspace(text);
    const asksForExternalFact = /\b(today|right now|latest|recent|news|price|market|market cap|investment|invest|better|akt|akash|filecoin|fil|crypto|stock|exchange rate|weather)\b/.test(text);
    const asksForPublicSource = /\b(cite|citation|sources?|web|internet|online|public)\b/.test(text);
    const asksForCurrentExternalState =
      /\b(current|currently)\b/.test(text) &&
      /\b(price|market|news|investment|crypto|stock|exchange rate|weather|public|web|online)\b/.test(text);
    if (targetsLocalWorkspace && !asksForExternalFact && !asksForCurrentExternalState) {
      return false;
    }
    return asksForExternalFact || asksForPublicSource || asksForCurrentExternalState;
  }

  function promptRequiresWorkspaceContext(prompt = "", executionMode = studioModeAgent) {
    if (promptIsInternalHarnessProbe(prompt) || normalizeStudioExecutionMode(executionMode) !== studioModeAgent) {
      return false;
    }
    const text = stringValue(prompt).toLowerCase();
    if (!promptTargetsLocalWorkspace(text)) {
      return false;
    }
    return /\b(audit|check|decides?|explain|explore|find|how|inspect|list|locate|look like|progress|read|review|scan|search|summari[sz]e|where|which|what)\b/.test(text) ||
      /(?:^|\s|["'`])(?:\.\/|\.\.\/|\/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?|workbench-adapters)\//.test(text);
  }

  function workspaceTargetsForPrompt(prompt = "") {
    const raw = compactStudioWhitespace(prompt);
    const targets = [];
    const pathPattern = /(?:^|\s|["'`])((?:\.\/|\.\.\/|\/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?|workbench-adapters)\/[^\s"'`),;:]+)(?=$|\s|["'`),;:])/gi;
    for (const match of raw.matchAll(pathPattern)) {
      const path = compactStudioWhitespace(match?.[1] || "").replace(/[.!?]+$/g, "");
      if (path && !targets.some((target) => target.kind === "path" && target.path === path)) {
        targets.push({ kind: "path", path, reason: "explicit_workspace_path" });
      }
    }
    if (targets.length > 0) {
      return targets;
    }
    const stopWords = new Set([
      "about", "and", "are", "between", "codebase", "does", "explain", "find", "first",
      "from", "how", "inspect", "into", "look", "or", "per", "project", "read",
      "repo", "repository", "search", "should", "summarize", "the", "this", "what", "where", "which",
      "workspace",
    ]);
    const seenTerms = new Set();
    const terms = raw
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, " ")
      .split(/\s+/)
      .map((term) => term.replace(/^[-./_]+|[-./_]+$/g, ""))
      .filter((term) => term.length >= 3 && !stopWords.has(term))
      .filter((term) => {
        if (seenTerms.has(term)) return false;
        seenTerms.add(term);
        return true;
      })
      .slice(0, 8);
    const query = terms.length > 0 ? terms.join(" ") : raw.slice(0, 120);
    return query ? [{ kind: "search", query, reason: "workspace_context_query" }] : [];
  }

  return {
    compactStudioWhitespace,
    isAutoStudioModelSelector,
    promptIsInternalHarnessProbe,
    promptRequiresRetrieval,
    promptRequiresWorkspaceContext,
    promptTargetsLocalWorkspace,
    workspaceTargetsForPrompt,
  };
}

module.exports = {
  STUDIO_TOOLCAT_MARKER_RE,
  STUDIO_TOOLCAT_SINGLE_TOOL_RE,
  STUDIO_TOOLCAT_TOOL_RE,
  createStudioPromptPolicy,
};
