function stringValue(value, fallback = "") {
  if (typeof value !== "string") {
    return fallback;
  }
  const trimmed = value.trim();
  return trimmed || fallback;
}

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values = []) {
  return [...new Set(values.map((value) => stringValue(value)).filter(Boolean))];
}

function studioPromptExplicitlyRequiresSources(prompt = "") {
  return /\b(cite|citation|sources?|with sources?|using sources?|web|internet|online|references?)\b/i.test(
    stringValue(prompt),
  );
}

function studioArtifactPromptTargetsLocalWorkspace(prompt = "") {
  const text = stringValue(prompt).toLowerCase();
  return /\b(repository|repo|workspace|project|codebase|source tree|current workspace|local source|inspect\b.*workspace|files?)\b/.test(text) ||
    /(?:^|\s|["'`])(?:\.\/|\.\.\/|\/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?)\//.test(text) ||
    /workspace_fixture_|daemon_endpoint=|computer_use_providers_url=|current trace history/.test(text);
}

function studioArtifactShouldGatherResearch(prompt = "", artifactClass = "") {
  if (!["static_html_js", "markdown_html_report", "react_vite_app"].includes(stringValue(artifactClass))) {
    return false;
  }
  if (studioArtifactPromptTargetsLocalWorkspace(prompt)) {
    return false;
  }
  return /\b(explains?|guide|educational|overview|report|briefing|compare|versus|vs\.?|what is|how does|how do|history|timeline)\b/i.test(
    stringValue(prompt),
  );
}

function cleanResearchQuery(value = "") {
  return stringValue(value)
    .replace(/\band\s+(?:use|using|cite|include)\s+(?:sources?|citations?|references?)\b.*$/i, "")
    .replace(/\b(with|using)\s+(sources?|citations?|references?)\b.*$/i, "")
    .replace(/\b(as|like)\s+(an?\s+)?(?:artifact|website|web\s*page|html\s+file)\b.*$/i, "")
    .replace(/[“”"'`]/g, "")
    .replace(/[?.!,;:]+$/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function studioArtifactResearchQuery(prompt = "") {
  const text = stringValue(prompt);
  const patterns = [
    /\b(?:create|build|make|generate|draft|design|prototype|output)\b[\s\S]{0,120}\b(?:website|web\s*site|webpage|web\s*page|landing\s+page|microsite|static\s+site|html\s+(?:file|page|website))\b\s+(?:that\s+)?(?:explains?|about|on|for|covering|describing|comparing|compares?)\s+([\s\S]+)/i,
    /\b(?:explains?|guide|overview|report|briefing|compare|versus|vs\.?|what is|how does|how do|history|timeline)\b\s+([\s\S]+)/i,
  ];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    const candidate = cleanResearchQuery(match?.[1]);
    if (candidate) {
      return candidate.slice(0, 160);
    }
  }
  return cleanResearchQuery(text).slice(0, 160);
}

function studioResearchIntentFrameForArtifact(intentFrame = {}, researchQuery = "") {
  const retrieval = intentFrame?.retrieval && typeof intentFrame.retrieval === "object"
    ? intentFrame.retrieval
    : { required: true, requirements: ["source_grounding"] };
  const query = stringValue(researchQuery, stringValue(retrieval.query, stringValue(intentFrame.query)));
  return {
    ...intentFrame,
    target: query || intentFrame.target || null,
    query: query || intentFrame.query || null,
    intentId: "retrieval.answer",
    intent_id: "retrieval.answer",
    routeDirective: "agent",
    route_directive: "agent",
    artifact: {
      required: false,
      class: null,
      artifactClass: null,
      outputModality: null,
      title: null,
      summary: null,
    },
    retrieval: {
      ...retrieval,
      required: true,
      query: query || retrieval.query || null,
      requirements: uniqueStrings([
        ...firstArray(retrieval.requirements),
        ...firstArray(retrieval.requiredCapabilities),
        "source_grounding",
      ]),
    },
    effectContract: {
      applicabilityClass: "remote_retrieval",
      effectLevel: "read_only_external",
      sandbox: null,
      typedActionsOnly: false,
      receiptsRequired: ["retrieval_search", "retrieval_read", "chat_reply"],
    },
  };
}

module.exports = {
  studioPromptExplicitlyRequiresSources,
  studioArtifactShouldGatherResearch,
  studioArtifactResearchQuery,
  studioResearchIntentFrameForArtifact,
};
