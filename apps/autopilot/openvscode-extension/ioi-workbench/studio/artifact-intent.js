"use strict";

function defaultStringValue(value, fallback = "") {
  if (value === undefined || value === null) {
    return fallback;
  }
  const normalized = String(value).trim();
  return normalized || fallback;
}

function defaultFirstArray(value) {
  return Array.isArray(value) ? value : [];
}

function createStudioArtifactIntent({
  stringValue = defaultStringValue,
  firstArray = defaultFirstArray,
  promptRequiresRetrieval = () => false,
  promptRequiresWorkspaceContext = () => false,
  workspaceTargetsForPrompt = () => [],
  normalizeStudioExecutionMode = (value) => stringValue(value, "agent"),
  studioArtifactShouldGatherResearch = () => false,
  modeAgent = "agent",
  modeAsk = "ask",
} = {}) {
  function shouldProjectStudioRuntimeCockpit(prompt) {
    const value = String(prompt || "");
    return /runtime cockpit|tool proposal|policy lease|sandbox(?:ed)? command|inline diff|hunk|diagnostics?|test gate|browser status|worker status|subagent|receipt timeline|replay/i.test(value);
  }

  function studioPromptRequestsGeneratedWebArtifact(prompt = "") {
    const value = String(prompt || "");
    return /\b(create|build|make|generate|draft|design|prototype|output)\b[\s\S]{0,120}\b(website|web\s*site|webpage|web\s*page|landing\s+page|microsite|static\s+site|html\s+(?:file|page|document|website))\b/i.test(value);
  }

  function studioPromptRequestsBrowserObservationArtifact(prompt = "") {
    const value = String(prompt || "");
    return (
      /\b(capture|save|export|promote|turn|convert|render)\b[\s\S]{0,100}\b(browser|computer)\b[\s\S]{0,100}\b(artifact|capture|observation|result)\b/i.test(value) ||
      /\b(browser|computer)\s+session\s+result\b[\s\S]{0,80}\bas\s+an?\s+artifact\b/i.test(value)
    );
  }

  function shouldProjectConversationArtifactCanvas(prompt) {
    return studioPromptRequestsGeneratedWebArtifact(prompt) ||
      studioPromptRequestsBrowserObservationArtifact(prompt) ||
      /\bartifact|embedded document|odt|docx|pdf|standalone html|html\/css\/js|react|vite|dashboard|csv|chart|dataset|patch artifact|diff artifact/i.test(String(prompt || ""));
  }

  function studioIntentFrameRouteDirective(intentFrame = {}) {
    return stringValue(intentFrame?.routeDirective || intentFrame?.route_directive);
  }

  function studioIntentFrameProjectsArtifact(intentFrame = {}) {
    return studioIntentFrameRouteDirective(intentFrame) === "artifact" || Boolean(intentFrame?.artifact?.required);
  }

  function studioIntentFrameProjectsRuntimeCockpit(intentFrame = {}) {
    return studioIntentFrameRouteDirective(intentFrame) === "runtime_cockpit" || stringValue(intentFrame?.intentId || intentFrame?.intent_id) === "runtime.inspect";
  }

  function studioIntentFrameRequiresRetrieval(intentFrame = {}, prompt = "") {
    if (intentFrame?.retrieval && typeof intentFrame.retrieval === "object") {
      return Boolean(intentFrame.retrieval.required);
    }
    return promptRequiresRetrieval(prompt);
  }

  function studioIntentFrameArtifactClass(intentFrame = {}, prompt = "") {
    return stringValue(
      intentFrame?.artifact?.class || intentFrame?.artifact?.artifactClass || intentFrame?.artifact?.artifact_class,
      studioArtifactClassFromPrompt(prompt),
    );
  }

  function studioIntentFrameArtifactTitle(intentFrame = {}, artifactClass, prompt = "") {
    return stringValue(intentFrame?.artifact?.title, studioArtifactTitleFromClass(artifactClass, prompt));
  }

  function studioIntentFrameArtifactSummary(intentFrame = {}, prompt = "") {
    return stringValue(
      intentFrame?.artifact?.summary,
      studioPromptRequestsGeneratedWebArtifact(prompt)
        ? "Sandboxed website preview generated through the daemon-owned artifact lifecycle."
        : "Agent Studio conversation artifact created through the daemon-owned artifact lifecycle.",
    );
  }

  function fallbackStudioPromptIntentFrame(prompt = "", { executionMode = modeAgent } = {}) {
    const normalizedExecutionMode = normalizeStudioExecutionMode(executionMode);
    const artifactClass = shouldProjectConversationArtifactCanvas(prompt)
      ? studioArtifactClassFromPrompt(prompt)
      : null;
    const projectsRuntime = !artifactClass && shouldProjectStudioRuntimeCockpit(prompt);
    const requiresRetrieval =
      promptRequiresRetrieval(prompt) ||
      studioArtifactShouldGatherResearch(prompt, artifactClass);
    const requiresWorkspaceContext = promptRequiresWorkspaceContext(prompt, normalizedExecutionMode);
    const routeDirective = normalizedExecutionMode === modeAsk
      ? "ask"
      : artifactClass
        ? "artifact"
        : projectsRuntime
          ? "runtime_cockpit"
          : "agent";
    const intentId = artifactClass
      ? "artifact.create"
      : projectsRuntime
        ? "runtime.inspect"
        : requiresRetrieval
          ? "retrieval.answer"
          : requiresWorkspaceContext
            ? "workspace.context"
            : "conversation.reply";
    const requiredCapabilities = [
      "prim:conversation.reply",
      ...(artifactClass ? ["prim:artifact.write", "prim:artifact.render"] : []),
      ...(requiresRetrieval ? ["prim:web.search", "prim:web.read"] : []),
      ...(requiresWorkspaceContext ? ["prim:file.search", "prim:file.read", "prim:workspace.read"] : []),
      ...(projectsRuntime ? ["prim:runtime.trace.read"] : []),
    ];
    const receiptsRequired = artifactClass
      ? ["artifact_record", "artifact_revision", "artifact_policy"]
      : requiresRetrieval
        ? ["retrieval_search", "retrieval_read", "chat_reply"]
        : requiresWorkspaceContext
          ? ["file_search", "file_read", "chat_reply"]
          : ["chat_reply"];
    return {
      schemaVersion: "ioi.studio.intent-frame.fallback.v1",
      object: "ioi.studio_intent_frame",
      target: prompt,
      query: requiresRetrieval ? prompt : null,
      intentId,
      routeDirective,
      executionMode: normalizedExecutionMode,
      decision: "selected",
      confidence: artifactClass || projectsRuntime || requiresRetrieval || requiresWorkspaceContext ? 0.76 : 0.42,
      requiredCapabilities,
      retrieval: {
        required: requiresRetrieval,
        requirements: requiresRetrieval ? ["source_grounding"] : [],
      },
      workspace: {
        required: requiresWorkspaceContext,
        requirements: requiresWorkspaceContext ? ["workspace_context"] : [],
        targets: requiresWorkspaceContext ? workspaceTargetsForPrompt(prompt) : [],
      },
      artifact: {
        required: Boolean(artifactClass),
        class: artifactClass,
        artifactClass,
        title: artifactClass ? studioArtifactTitleFromClass(artifactClass, prompt) : null,
        summary: artifactClass ? studioIntentFrameArtifactSummary({}, prompt) : null,
      },
      effectContract: {
        applicabilityClass: artifactClass ? "local_artifact_generation" : requiresRetrieval ? "remote_retrieval" : requiresWorkspaceContext ? "workspace_context" : "conversation",
        effectLevel: artifactClass ? "sandboxed_generation" : requiresRetrieval ? "read_only_external" : requiresWorkspaceContext ? "read_only_workspace" : "none",
        sandbox: artifactClass ? "artifact_renderer" : requiresWorkspaceContext ? "workspace_readonly" : null,
        typedActionsOnly: Boolean(artifactClass),
        receiptsRequired,
      },
      decisionMaterial: {
        source: "local_fallback_feature_resolver",
        matchedFeatures: [
          ...(artifactClass ? ["artifact_deliverable"] : []),
          ...(projectsRuntime ? ["runtime_inspection"] : []),
          ...(requiresRetrieval ? ["retrieval_required"] : []),
          ...(requiresWorkspaceContext ? ["workspace_context_required"] : []),
        ],
      },
    };
  }

  function studioIntentFramePayload(intentFrame = {}) {
    if (!intentFrame || typeof intentFrame !== "object") {
      return null;
    }
    return {
      schemaVersion: intentFrame.schemaVersion || intentFrame.schema_version || null,
      target: intentFrame.target || null,
      query: intentFrame.query || null,
      intentId: intentFrame.intentId || intentFrame.intent_id || null,
      routeDirective: intentFrame.routeDirective || intentFrame.route_directive || null,
      executionMode: intentFrame.executionMode || intentFrame.execution_mode || null,
      confidence: intentFrame.confidence ?? null,
      requiredCapabilities: firstArray(intentFrame.requiredCapabilities || intentFrame.required_capabilities),
      retrieval: intentFrame.retrieval || null,
      workspace: intentFrame.workspace || null,
      artifact: intentFrame.artifact || null,
      runtimeAction: intentFrame.runtimeAction || intentFrame.runtime_action || null,
      runtime_action: intentFrame.runtime_action || intentFrame.runtimeAction || null,
      effectContract: intentFrame.effectContract || intentFrame.effect_contract || null,
      decisionMaterial: intentFrame.decisionMaterial
        ? {
            source: intentFrame.decisionMaterial.source || null,
            matchedFeatures: firstArray(intentFrame.decisionMaterial.matchedFeatures),
            promptHash: intentFrame.decisionMaterial.promptHash || null,
            promptPreview: intentFrame.decisionMaterial.promptPreview || null,
          }
        : null,
    };
  }

  function studioArtifactClassFromPrompt(prompt = "") {
    const value = String(prompt || "").toLowerCase();
    if (/\b(odt|docx|document artifact|editable projection)\b/.test(value)) return "imported_document";
    if (/\b(pdf|read-only document|readonly document)\b/.test(value)) return "pdf_preview";
    if (/\b(react|vite|dashboard app|mini app)\b/.test(value)) return "react_vite_app";
    if (studioPromptRequestsGeneratedWebArtifact(prompt)) return "static_html_js";
    if (
      (/\b(markdown report|html report)\b/.test(value) ||
        (/\b(create|build|make|generate|draft|design|prototype|output|prepare)\b/.test(value) && /\breport\b/.test(value))) &&
      !/\b(standalone html\/css\/js|html\/css\/js|static html|html css js)\b/.test(value)
    ) return "markdown_html_report";
    if (/\b(standalone html|html\/css\/js|static html|html css js)\b/.test(value)) return "static_html_js";
    if (/\b(diff|patch|reviewable patch)\b/.test(value)) return "diff_patch";
    if (/\b(csv|dataset|chart|table)\b/.test(value)) return "dataset_chart";
    if (studioPromptRequestsBrowserObservationArtifact(prompt)) return "browser_observation";
    return "markdown_html_report";
  }

  function studioTopicFromGeneratedWebPrompt(prompt = "") {
    const text = String(prompt || "").replace(/\s+/g, " ").trim();
    const match = text.match(/\b(?:explains?|about|for|on)\s+([^.!?\n]{3,90})/i);
    const topic = (match?.[1] || "")
      .replace(/\b(?:as|with|using|and)\b.*$/i, "")
      .replace(/^["'`]+|["'`]+$/g, "")
      .trim();
    return topic || "";
  }

  function studioTitleCaseArtifactTopic(value = "") {
    const cleaned = String(value || "").replace(/\s+/g, " ").trim();
    if (!cleaned) return "";
    return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
  }

  function studioArtifactTitleFromClass(classId, prompt = "") {
    switch (classId) {
      case "imported_document":
        return "Launch memo document";
      case "pdf_preview":
        return "Read-only PDF artifact";
      case "react_vite_app":
        return "CSV dashboard app";
      case "static_html_js":
        if (studioPromptRequestsGeneratedWebArtifact(prompt)) {
          const topic = studioTitleCaseArtifactTopic(studioTopicFromGeneratedWebPrompt(prompt));
          return topic ? `${topic} website` : "Generated website";
        }
        return "Standalone HTML report";
      case "diff_patch":
        return "Reviewable patch";
      case "dataset_chart":
        return "Test results dataset";
      case "browser_observation":
        return "Browser session capture";
      default:
        return "Test results report";
    }
  }

  return {
    shouldProjectStudioRuntimeCockpit,
    studioPromptRequestsGeneratedWebArtifact,
    studioPromptRequestsBrowserObservationArtifact,
    shouldProjectConversationArtifactCanvas,
    studioIntentFrameRouteDirective,
    studioIntentFrameProjectsArtifact,
    studioIntentFrameProjectsRuntimeCockpit,
    studioIntentFrameRequiresRetrieval,
    studioIntentFrameArtifactClass,
    studioIntentFrameArtifactTitle,
    studioIntentFrameArtifactSummary,
    fallbackStudioPromptIntentFrame,
    studioIntentFramePayload,
    studioArtifactClassFromPrompt,
    studioTopicFromGeneratedWebPrompt,
    studioTitleCaseArtifactTopic,
    studioArtifactTitleFromClass,
  };
}

module.exports = {
  createStudioArtifactIntent,
};
