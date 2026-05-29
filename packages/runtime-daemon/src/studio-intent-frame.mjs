import crypto from "node:crypto";

export const STUDIO_INTENT_FRAME_SCHEMA_VERSION = "ioi.studio.intent-frame.v1";

const ARTIFACT_CLASSES = new Set([
  "markdown_html_report",
  "static_html_js",
  "react_vite_app",
  "imported_document",
  "pdf_preview",
  "diff_patch",
  "dataset_chart",
  "browser_observation",
]);

const CREATION_VERB_RE = /\b(create|build|make|generate|draft|design|prototype|turn|convert|render|show|prepare)\b/i;
const WEB_DELIVERABLE_RE = /\b(website|web\s*site|webpage|web\s*page|landing\s+page|microsite|static\s+site|standalone\s+site)\b/i;
const RUNTIME_INSPECTION_RE = /\b(runtime cockpit|tool proposal|policy lease|sandbox(?:ed)? command|inline diff|hunk|diagnostics?|test gate|browser status|worker status|subagent|receipt timeline|replay)\b/i;
const INTERNAL_PROBE_RE = /\bTOOLCAT_(?:SINGLE_TOOL|STAGE\d+_[A-Z0-9_]+)\b|workspace_fixture_|daemon_endpoint=|computer_use_providers_url=|live IDE Rust\/provider tool row/i;

function compactText(value = "") {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function lowerText(value = "") {
  return compactText(value).toLowerCase();
}

function has(text, pattern) {
  return pattern.test(text);
}

function titleCaseFirst(value = "") {
  const cleaned = compactText(value);
  if (!cleaned) return "";
  return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
}

function promptTopicForWebArtifact(prompt = "") {
  const text = compactText(prompt);
  const match = text.match(/\b(?:explains?|about|for|on)\s+([^.!?\n]{3,90})/i);
  return compactText(match?.[1] || "")
    .replace(/\b(?:as|with|using|and)\b.*$/i, "")
    .replace(/^["'`]+|["'`]+$/g, "")
    .trim();
}

function artifactClassForPrompt(prompt = "") {
  const text = lowerText(prompt);
  const creationLike = has(text, CREATION_VERB_RE);
  if (/\b(odt|docx|document artifact|editable projection|word document|open document)\b/.test(text)) {
    return "imported_document";
  }
  if (/\b(pdf|read-only document|readonly document)\b/.test(text)) {
    return "pdf_preview";
  }
  if (/\b(react|vite|mini app|generated app|app preview)\b/.test(text)) {
    return "react_vite_app";
  }
  if (creationLike && has(text, WEB_DELIVERABLE_RE)) {
    return "static_html_js";
  }
  if (/\b(standalone html|html\/css\/js|static html|html css js)\b/.test(text)) {
    return "static_html_js";
  }
  if (/\b(diff|patch|reviewable patch)\b/.test(text)) {
    return "diff_patch";
  }
  if (/\b(csv|dataset|chart|table)\b/.test(text)) {
    return "dataset_chart";
  }
  if (/\b(browser session|computer session|capture this browser|observation artifact|browser capture)\b/.test(text)) {
    return "browser_observation";
  }
  if (/\b(report|markdown report|html report|memo)\b/.test(text)) {
    return "markdown_html_report";
  }
  if (/\bartifact|embedded document|document embed|canvas\b/.test(text)) {
    return "markdown_html_report";
  }
  return null;
}

function artifactTitleForPrompt(classId, prompt = "") {
  switch (classId) {
    case "imported_document":
      return "Document artifact";
    case "pdf_preview":
      return "Read-only PDF artifact";
    case "react_vite_app":
      return "Generated app artifact";
    case "static_html_js": {
      const topic = titleCaseFirst(promptTopicForWebArtifact(prompt));
      return topic ? `${topic} website` : "Generated website";
    }
    case "diff_patch":
      return "Reviewable patch";
    case "dataset_chart":
      return "Dataset artifact";
    case "browser_observation":
      return "Browser session capture";
    default:
      return "Generated report artifact";
  }
}

function promptTargetsLocalWorkspace(prompt = "") {
  const text = lowerText(prompt);
  return /\b(repository|repo|workspace|project|codebase|source tree|current workspace|local source|inspect\b.*workspace|files?)\b/.test(text) ||
    /(?:^|\s|["'`])(?:\.\/|\.\.\/|\/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?)\//.test(text) ||
    /workspace_fixture_|daemon_endpoint=|computer_use_providers_url=|current trace history/.test(text);
}

function workspaceTargetsForPrompt(prompt = "") {
  const raw = compactText(prompt);
  const targets = [];
  const pathPattern = /(?:^|\s|["'`])((?:\.\/|\.\.\/|\/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?)\/[^\s"'`),;:]+)(?=$|\s|["'`),;:])/gi;
  for (const match of raw.matchAll(pathPattern)) {
    const path = compactText(match?.[1] || "").replace(/[.!?]+$/g, "");
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

function workspaceRequirementsForPrompt(prompt = "", context = {}) {
  if (INTERNAL_PROBE_RE.test(String(prompt || ""))) {
    return [];
  }
  const executionMode = lowerText(context.executionMode || "agent");
  if (executionMode !== "agent") {
    return [];
  }
  const text = lowerText(prompt);
  if (!promptTargetsLocalWorkspace(text)) {
    return [];
  }
  const asksForWorkspaceContext =
    /\b(audit|check|decides?|explain|explore|find|how|inspect|list|locate|look like|progress|read|review|scan|search|summari[sz]e|where|which|what)\b/.test(text) ||
    /(?:^|\s|["'`])(?:\.\/|\.\.\/|\/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?)\//.test(text);
  return asksForWorkspaceContext ? ["workspace_context"] : [];
}

function retrievalRequirementsForPrompt(prompt = "", context = {}) {
  if (INTERNAL_PROBE_RE.test(String(prompt || ""))) {
    return [];
  }
  const text = lowerText(prompt);
  const targetsLocalWorkspace = promptTargetsLocalWorkspace(text);
  const artifactClass = context.artifactClass || artifactClassForPrompt(prompt);
  const executionMode = lowerText(context.executionMode || "agent");
  const asksForExternalFact = /\b(today|right now|latest|recent|news|price|market|market cap|investment|invest|better|akt|akash|filecoin|fil|crypto|stock|exchange rate|weather)\b/.test(text);
  const asksForPublicSource = /\b(cite|citation|sources?|web|internet|online|public)\b/.test(text);
  const asksForCurrentExternalState =
    /\b(current|currently)\b/.test(text) &&
    /\b(price|market|news|investment|crypto|stock|exchange rate|weather|public|web|online)\b/.test(text);
  const sourceGroundedArtifactClass = new Set(["static_html_js", "markdown_html_report", "react_vite_app"]).has(
    artifactClass,
  );
  const asksForFactualArtifact =
    executionMode === "agent" &&
    sourceGroundedArtifactClass &&
    !targetsLocalWorkspace &&
    /\b(explains?|guide|educational|overview|report|briefing|compare|versus|vs\.?|what is|how does|how do|history|timeline)\b/.test(text);
  if (targetsLocalWorkspace && !asksForExternalFact && !asksForCurrentExternalState) {
    return [];
  }
  const requirements = [];
  if (asksForExternalFact || asksForCurrentExternalState) requirements.push("current_external_state");
  if (asksForPublicSource || asksForFactualArtifact) requirements.push("source_grounding");
  return [...new Set(requirements)];
}

function effectContractFor({ artifactRequired, artifactClass, retrievalRequired, workspaceRequired, routeDirective }) {
  if (artifactRequired) {
    return {
      applicabilityClass: "deterministic_local",
      effectLevel: artifactClass === "diff_patch" ? "approval_gated_mutation" : "sandboxed_generation",
      sandbox: artifactClass === "diff_patch" ? null : "artifact_renderer",
      typedActionsOnly: true,
      receiptsRequired: [
        ...(retrievalRequired ? ["retrieval_search", "retrieval_read"] : []),
        "artifact_record",
        "artifact_revision",
        "artifact_policy",
      ],
    };
  }
  if (retrievalRequired) {
    return {
      applicabilityClass: "remote_retrieval",
      effectLevel: "read_only_external",
      sandbox: null,
      typedActionsOnly: false,
      receiptsRequired: ["retrieval_search", "retrieval_read", "chat_reply"],
    };
  }
  if (workspaceRequired) {
    return {
      applicabilityClass: "workspace_context",
      effectLevel: "read_only_workspace",
      sandbox: "workspace_readonly",
      typedActionsOnly: false,
      receiptsRequired: ["file_search", "file_read", "chat_reply"],
    };
  }
  if (routeDirective === "runtime_cockpit") {
    return {
      applicabilityClass: "runtime_inspection",
      effectLevel: "read_only_runtime",
      sandbox: null,
      typedActionsOnly: false,
      receiptsRequired: ["runtime_trace"],
    };
  }
  return {
    applicabilityClass: "conversation",
    effectLevel: "none",
    sandbox: null,
    typedActionsOnly: false,
    receiptsRequired: ["chat_reply"],
  };
}

export function resolveStudioIntentFrame(input = {}) {
  const prompt = compactText(input.prompt ?? input.input ?? input.query ?? "");
  const executionMode = lowerText(input.executionMode ?? input.execution_mode ?? "agent") === "ask"
    ? "ask"
    : "agent";
  const promptHash = crypto.createHash("sha256").update(prompt).digest("hex").slice(0, 16);
  const matchedFeatures = [];
  const artifactClass = artifactClassForPrompt(prompt);
  const artifactRequired = Boolean(artifactClass && ARTIFACT_CLASSES.has(artifactClass));
  const retrievalRequirements = retrievalRequirementsForPrompt(prompt, { artifactClass, executionMode });
  const retrievalRequired = retrievalRequirements.length > 0;
  const workspaceRequirements = workspaceRequirementsForPrompt(prompt, { executionMode });
  const workspaceRequired = workspaceRequirements.length > 0;
  const workspaceTargets = workspaceRequired ? workspaceTargetsForPrompt(prompt) : [];
  const runtimeInspect = !artifactRequired && RUNTIME_INSPECTION_RE.test(prompt);
  if (artifactRequired) matchedFeatures.push("artifact_deliverable");
  if (retrievalRequired) matchedFeatures.push("retrieval_required");
  if (workspaceRequired) matchedFeatures.push("workspace_context_required");
  if (runtimeInspect) matchedFeatures.push("runtime_inspection");
  if (INTERNAL_PROBE_RE.test(prompt)) matchedFeatures.push("internal_probe");

  const routeDirective = executionMode === "ask"
    ? "ask"
    : artifactRequired
      ? "artifact"
      : runtimeInspect
        ? "runtime_cockpit"
        : "agent";
  const intentId = artifactRequired
    ? "artifact.create"
    : runtimeInspect
      ? "runtime.inspect"
      : retrievalRequired
        ? "retrieval.answer"
        : workspaceRequired
          ? "workspace.context"
          : "conversation.reply";
  const confidence = artifactRequired || runtimeInspect || retrievalRequired || workspaceRequired ? 0.92 : 0.56;
  const artifact = artifactRequired
    ? {
        required: true,
        class: artifactClass,
        artifactClass,
        outputModality: artifactClass === "static_html_js" ? "website" : artifactClass.replace(/_/g, "-"),
        title: artifactTitleForPrompt(artifactClass, prompt),
        summary: artifactClass === "static_html_js"
          ? "Sandboxed website preview generated through the daemon-owned artifact lifecycle."
          : "Agent Studio conversation artifact created through the daemon-owned artifact lifecycle.",
      }
    : {
        required: false,
        class: null,
        artifactClass: null,
        outputModality: null,
        title: null,
        summary: null,
      };

  return {
    schemaVersion: STUDIO_INTENT_FRAME_SCHEMA_VERSION,
    schema_version: STUDIO_INTENT_FRAME_SCHEMA_VERSION,
    object: "ioi.studio_intent_frame",
    intentId,
    intent_id: intentId,
    routeDirective,
    route_directive: routeDirective,
    executionMode,
    execution_mode: executionMode,
    confidence,
    decision: prompt ? "selected" : "abstain",
    requiredCapabilities: [
      "prim:conversation.reply",
      ...(artifactRequired ? ["prim:artifact.write", "prim:artifact.render"] : []),
      ...(retrievalRequired ? ["prim:web.search", "prim:web.read"] : []),
      ...(workspaceRequired ? ["prim:file.search", "prim:file.read", "prim:workspace.read"] : []),
      ...(runtimeInspect ? ["prim:runtime.trace.read"] : []),
    ],
    required_capabilities: [
      "prim:conversation.reply",
      ...(artifactRequired ? ["prim:artifact.write", "prim:artifact.render"] : []),
      ...(retrievalRequired ? ["prim:web.search", "prim:web.read"] : []),
      ...(workspaceRequired ? ["prim:file.search", "prim:file.read", "prim:workspace.read"] : []),
      ...(runtimeInspect ? ["prim:runtime.trace.read"] : []),
    ],
    retrieval: {
      required: retrievalRequired,
      requirements: retrievalRequirements,
    },
    workspace: {
      required: workspaceRequired,
      requirements: workspaceRequirements,
      targets: workspaceTargets,
    },
    artifact,
    effectContract: effectContractFor({
      artifactRequired,
      artifactClass,
      retrievalRequired,
      workspaceRequired,
      routeDirective,
    }),
    effect_contract: effectContractFor({
      artifactRequired,
      artifactClass,
      retrievalRequired,
      workspaceRequired,
      routeDirective,
    }),
    decisionMaterial: {
      source: "deterministic_feature_resolver",
      matchedFeatures,
      promptHash,
      promptPreview: prompt.slice(0, 120),
    },
    decision_material: {
      source: "deterministic_feature_resolver",
      matched_features: matchedFeatures,
      prompt_hash: promptHash,
      prompt_preview: prompt.slice(0, 120),
    },
  };
}
