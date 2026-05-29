function createStudioModelCompletion(deps) {
  const {
    crypto,
    STUDIO_MODEL_COMPLETION_TIMEOUT_MS,
    requestSseJson,
    requestJson,
    daemonEndpoint,
    ensureStudioModelInvocationToken,
    getStudioRuntimeProjection,
    studioModelIdForRouteInvocation,
    normalizeStudioReasoningEffort,
    studioPostRuntimeMessage,
    firstArray,
    studioDenyFixtureModelPolicy,
    studioMaxOutputTokens,
    studioArtifactMaxOutputTokens,
    collectStudioStreamMetadata,
    studioReasoningDeltaFromSsePayload,
    studioDeltaFromSsePayload,
    studioSplitReasoningFromText,
    stringValue,
    studioResponseMetricsFromUsage,
    studioTextContainsProductFixtureMarker,
    studioFixtureModelUsageAllowed,
    appendStudioReceipts,
  } = deps;

  function studioReasoningEnabled(effort) {
    const normalized = stringValue(effort).trim().toLowerCase();
    return Boolean(normalized && !["none", "off", "false", "disabled"].includes(normalized));
  }

  function studioAskMaxOutputTokens(reasoningEffort = "none", prompt = "") {
    const configured = studioMaxOutputTokens();
    if (!studioReasoningEnabled(reasoningEffort)) {
      return configured;
    }
    const promptWordCount = stringValue(prompt).trim().split(/\s+/).filter(Boolean).length;
    const cap = promptWordCount <= 80 ? 1536 : 2048;
    return Math.max(512, Math.min(configured, cap));
  }

  function studioAskReasoningNeedsAnswerHandoff({ reasoningEffort = "none", thinkingText = "", answerText = "", startedAtMs = Date.now() } = {}) {
    if (!studioReasoningEnabled(reasoningEffort) || stringValue(answerText).trim()) {
      return false;
    }
    const thinking = stringValue(thinkingText);
    const configuredChars = Number(process.env.IOI_STUDIO_REASONING_HANDOFF_CHARS ?? "");
    const maxThinkingChars = Number.isFinite(configuredChars) && configuredChars >= 512 ? configuredChars : 3000;
    if (thinking.length >= maxThinkingChars) {
      return true;
    }
    const configuredMs = Number(process.env.IOI_STUDIO_REASONING_HANDOFF_MS ?? "");
    const maxThinkingMs = Number.isFinite(configuredMs) && configuredMs >= 5000 ? configuredMs : 45000;
    return thinking.trim().length >= 120 && Date.now() - startedAtMs >= maxThinkingMs;
  }

  function studioAskNeedsFreshRetrievalGuard(prompt = "") {
    const text = stringValue(prompt).toLowerCase();
    const asksForFreshness = /\b(right now|today|current(?:ly)?|latest|newest|this (?:week|month|year)|as of now|recent|live)\b/.test(text);
    const highStakesChoice = /\b(invest(?:ment|ing)?|price|market|stock|crypto|token|coin|better|best|buy|sell|hold|trade|forecast)\b/.test(text);
    return asksForFreshness && highStakesChoice;
  }

  function studioAskFreshRetrievalGuardText() {
    return "Ask cannot safely choose or summarize from stale model memory for a current or investment-sensitive question. Use Agent with fresh retrieval, or provide current sources; I should not guess.";
  }

  function streamStudioSyntheticAskText({ streamId, result, metadata, text, routeId, model, provider = "autopilot ask guard", startedAtMs, reasoningEffort = "none", requestedModel, prompt }) {
    metadata.firstTokenAtMs = metadata.firstTokenAtMs || Date.now();
    const chunks = String(text || "").match(/.{1,42}(?:\s+|$)/g) || [String(text || "")];
    for (const chunk of chunks) {
      result.text += chunk;
      result.chunkCount += 1;
      studioPostRuntimeMessage("assistantStreamDelta", {
        streamId,
        delta: chunk,
        chunkCount: result.chunkCount,
      });
    }
    result.receiptIds = [];
    result.routeId = routeId;
    result.model = model || requestedModel;
    result.provider = provider;
    result.providerStream = "synthetic_guard";
    result.stopReason = "fresh_retrieval_required";
    result.metrics = studioResponseMetricsFromUsage({
      usage: {},
      routeId: result.routeId,
      model: result.model,
      provider,
      reasoningEffort,
      elapsedMs: Date.now() - startedAtMs,
      timeToFirstTokenMs: metadata.firstTokenAtMs ? metadata.firstTokenAtMs - startedAtMs : null,
      stopReason: result.stopReason,
      requestedModel,
      promptText: prompt,
      generatedText: result.text,
    });
    studioPostRuntimeMessage("assistantStreamComplete", {
      streamId,
      text: result.text,
      thinkingText: result.thinkingText,
      chunkCount: result.chunkCount,
      receiptIds: result.receiptIds,
      routeId: result.routeId,
      model: result.model,
      providerStream: result.providerStream,
      metrics: result.metrics,
    });
    return result;
  }

  async function streamStudioModelCompletion({ prompt, selectedRoute, selectedModelId, reasoningEffort = "none", workspacePath }, output) {
  const studioRuntimeProjection = getStudioRuntimeProjection();
  const endpoint = daemonEndpoint();
  const token = await ensureStudioModelInvocationToken(output);
  const streamId = `studio-stream-${crypto.randomUUID()}`;
  const requestedModel = studioModelIdForRouteInvocation(selectedRoute, selectedModelId);
  const selectedReasoningEffort = normalizeStudioReasoningEffort(reasoningEffort, "none");
  const startedAtMs = Date.now();
  const metadata = {
    receiptIds: new Set(),
    routeId: selectedRoute,
    model: requestedModel,
    providerStream: null,
    provider: null,
    usage: null,
    stopReason: null,
    firstTokenAtMs: null,
  };
  const result = {
    streamId,
    text: "",
    thinkingText: "",
    chunkCount: 0,
    receiptIds: [],
    routeId: selectedRoute,
    model: requestedModel,
    providerStream: null,
    provider: null,
    usage: null,
    stopReason: null,
    metrics: null,
  };
  studioPostRuntimeMessage("assistantStreamStart", {
    streamId,
    routeId: selectedRoute,
    startedAt: new Date().toISOString(),
  });
  studioRuntimeProjection.timeline.push({
    label: "Model stream started",
    detail: `${selectedRoute} via /v1/chat/completions`,
    status: "streaming",
  });

  if (studioAskNeedsFreshRetrievalGuard(prompt)) {
    return streamStudioSyntheticAskText({
      streamId,
      result,
      metadata,
      text: studioAskFreshRetrievalGuardText(prompt),
      routeId: selectedRoute,
      model: requestedModel,
      startedAtMs,
      reasoningEffort: selectedReasoningEffort,
      requestedModel,
      prompt,
    });
  }

  try {
    const askModePresentationBoundary = [
      "Autopilot Ask mode presentation boundary:",
      "- Give the best direct model answer to the user's prompt.",
      "- When the user's wording is ambiguous, briefly acknowledge the likely meanings and make a clear, useful interpretation instead of silently collapsing it into a nearby domain.",
      "- When reasoning/thinking is enabled, keep the thinking stream brief, then move into the final answer promptly.",
      "- For short explanatory prompts, answer concisely unless the user asks for depth.",
      "- You may provide code, source snippets, explanations, plans, or analysis directly in chat.",
      "- Do not mention internal workspace paths, daemon routes, receipts, trace ids, runtime scaffolding, or selected-model plumbing unless the user explicitly asks for those implementation details.",
      "- Do not claim you edited files, ran tools, launched servers, hosted a site, or created artifacts. Agent mode handles governed execution and side effects.",
      "- If the user asks for a side effect, answer with the useful content you can provide and briefly note that Agent mode can perform the execution.",
      "- If the prompt asks for current, latest, today, or right-now high-stakes recommendations, do not choose from stale model memory. Say fresh retrieval is required, that Ask should not guess, and suggest Agent mode for web retrieval.",
    ].join("\n");
    let stoppedForReasoningHandoff = false;
    const handleAskPayload = (payload, { allowReasoningHandoff = false } = {}) => {
      collectStudioStreamMetadata(metadata, payload);
      const reasoningDelta = studioReasoningDeltaFromSsePayload(payload);
      if (reasoningDelta) {
        metadata.firstTokenAtMs = metadata.firstTokenAtMs || Date.now();
        result.thinkingText += reasoningDelta;
        studioPostRuntimeMessage("assistantThinkingDelta", {
          streamId,
          delta: reasoningDelta,
        });
        if (
          allowReasoningHandoff &&
          studioAskReasoningNeedsAnswerHandoff({
            reasoningEffort: selectedReasoningEffort,
            thinkingText: result.thinkingText,
            answerText: result.text,
            startedAtMs,
          })
        ) {
          stoppedForReasoningHandoff = true;
          return false;
        }
      }
      const delta = studioDeltaFromSsePayload(payload);
      if (!delta) {
        return undefined;
      }
      metadata.firstTokenAtMs = metadata.firstTokenAtMs || Date.now();
      result.text += delta;
      result.chunkCount += 1;
      studioPostRuntimeMessage("assistantStreamDelta", {
        streamId,
        delta,
        chunkCount: result.chunkCount,
      });
      return undefined;
    };
    await requestSseJson(endpoint, "/v1/chat/completions", {
      method: "POST",
      token,
      timeoutMs: STUDIO_MODEL_COMPLETION_TIMEOUT_MS,
      payload: {
        route_id: selectedRoute,
        model: requestedModel,
        stream: true,
        messages: [
          {
            role: "system",
            content:
              "You are Autopilot Agent Studio in Ask mode. Answer directly in chat with useful prose, code, or analysis from the selected model. Do not claim to edit files, run tools, or create artifacts; Agent mode handles governed execution.",
          },
          {
            role: "system",
            content: askModePresentationBoundary,
          },
          {
            role: "user",
            content: prompt,
          },
        ],
        metadata: {
          source: "agent-studio-operational-chat",
          workspaceRoot: workspacePath,
          runtimeAuthority: "daemon-owned",
          projectionOwner: "ioi-workbench-agent-studio",
        },
        model_policy: studioDenyFixtureModelPolicy(),
        modelPolicy: studioDenyFixtureModelPolicy(),
        max_tokens: studioAskMaxOutputTokens(selectedReasoningEffort, prompt),
        temperature: 1,
        top_p: 0.95,
        top_k: 20,
        presence_penalty: 1.5,
        reasoning_effort: selectedReasoningEffort,
        reasoningEffort: selectedReasoningEffort,
      },
      onPayload: (payload) => handleAskPayload(payload, { allowReasoningHandoff: true }),
    });
    if (stoppedForReasoningHandoff && !result.text.trim()) {
      await requestSseJson(endpoint, "/v1/chat/completions", {
        method: "POST",
        token,
        timeoutMs: STUDIO_MODEL_COMPLETION_TIMEOUT_MS,
        payload: {
          route_id: selectedRoute,
          model: requestedModel,
          stream: true,
          messages: [
            {
              role: "system",
              content:
                "You are Autopilot Agent Studio in Ask mode. Continue the same user turn by providing the final answer immediately. Do not include hidden reasoning or analysis.",
            },
            {
              role: "system",
              content: askModePresentationBoundary,
            },
            {
              role: "user",
              content: prompt,
            },
          ],
          metadata: {
            source: "agent-studio-operational-chat",
            workspaceRoot: workspacePath,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio",
            reasoningHandoff: true,
          },
          model_policy: studioDenyFixtureModelPolicy(),
          modelPolicy: studioDenyFixtureModelPolicy(),
          max_tokens: Math.min(studioMaxOutputTokens(), 2048),
          temperature: 1,
          top_p: 0.95,
          top_k: 20,
          presence_penalty: 1.5,
          reasoning_effort: "none",
          reasoningEffort: "none",
        },
        onPayload: (payload) => handleAskPayload(payload, { allowReasoningHandoff: false }),
      });
    }
  } catch (error) {
    studioPostRuntimeMessage("assistantStreamError", {
      streamId,
      error: error?.message || String(error),
    });
    throw error;
  }

  const split = studioSplitReasoningFromText(result.text);
  result.thinkingText = stringValue(result.thinkingText || split.thinkingText);
  result.text = split.answerText || result.text;
  result.receiptIds = [...metadata.receiptIds];
  result.routeId = metadata.routeId || selectedRoute;
  result.model = metadata.model;
  result.providerStream = metadata.providerStream;
  result.provider = metadata.provider;
  result.usage = metadata.usage;
  result.stopReason = metadata.stopReason;
  result.metrics = studioResponseMetricsFromUsage({
    usage: result.usage || {},
    routeId: result.routeId,
    model: result.model,
    provider: result.provider || (result.providerStream ? "provider native stream" : ""),
    reasoningEffort: selectedReasoningEffort,
    elapsedMs: Date.now() - startedAtMs,
    timeToFirstTokenMs: metadata.firstTokenAtMs ? metadata.firstTokenAtMs - startedAtMs : null,
    stopReason: result.stopReason,
    requestedModel,
    promptText: prompt,
    generatedText: result.text,
  });
  if (studioTextContainsProductFixtureMarker(`${result.model}\n${result.text}`) && !studioFixtureModelUsageAllowed()) {
    throw new Error("Selected model route produced fixture output instead of a product model response.");
  }
  if (!result.text.trim()) {
    throw new Error("Daemon model stream completed without assistant text.");
  }
  appendStudioReceipts(
    result.receiptIds.map((id) => ({
      id,
      kind: id.includes("stream") ? "model_invocation_stream_completed" : "model_invocation",
      summary: "Daemon model stream receipt projected into Studio.",
    })),
    "model_invocation",
  );
  studioPostRuntimeMessage("assistantStreamComplete", {
    streamId,
    text: result.text,
    thinkingText: result.thinkingText,
    chunkCount: result.chunkCount,
    receiptIds: result.receiptIds,
    routeId: result.routeId,
    model: result.model,
    providerStream: result.providerStream,
    metrics: result.metrics,
  });
  return result;
}

function studioChatCompletionText(response = {}) {
  const choice = response?.choices?.[0] || {};
  const direct = stringValue(
    choice.message?.content ||
      choice.delta?.content ||
      response.message?.content ||
      response.response?.output_text ||
      response.output_text ||
      response.text,
  );
  if (direct) return direct;
  const contentParts = firstArray(choice.message?.content || response.message?.content);
  return contentParts.map((part) => stringValue(part?.text || part?.content)).filter(Boolean).join("\n");
}

function parseStudioJsonObject(text = "") {
  const raw = stringValue(text);
  const candidates = [
    raw,
    raw.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, ""),
    raw.match(/```(?:json)?\s*([\s\S]*?)\s*```/i)?.[1] || "",
    raw.match(/\{[\s\S]*\}/)?.[0] || "",
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch {
      // Try the next candidate.
    }
  }
  return null;
}

function extractStudioHtmlDocument(text = "") {
  const raw = stringValue(text).trim();
  const candidates = [
    raw,
    raw.replace(/^```(?:html)?\s*/i, "").replace(/\s*```$/i, ""),
    raw.match(/```(?:html)?\s*([\s\S]*?)\s*```/i)?.[1] || "",
    raw.match(/<!doctype html[\s\S]*<\/html>/i)?.[0] || "",
    raw.match(/<html[\s\S]*<\/html>/i)?.[0] || "",
  ].filter(Boolean);
  for (const candidate of candidates) {
    const html = candidate.trim();
    if ((/<!doctype html/i.test(html) || /<html[\s>]/i.test(html)) && /<\/html>\s*$/i.test(html)) {
      return html;
    }
  }
  return "";
}

function studioWebsiteDraftRejectReason({ prompt = "", draft = {}, rawText = "", parsed = null } = {}) {
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const name = stringValue(parsed.name || parsed.tool || parsed.tool_name || parsed.toolName);
    const hasToolEnvelope = Boolean(name && (parsed.arguments || parsed.args || parsed.input));
    if (hasToolEnvelope) return `model returned tool-call envelope ${name}`;
  }
  const html = stringValue(draft.html);
  const css = stringValue(draft.css);
  const text = `${rawText}\n${draft.title || ""}\n${draft.summary || ""}\n${html}\n${css}`;
  if (!html || html.length < 80) return "missing usable HTML";
  if (!/<\/html>\s*$/i.test(html)) return "website HTML was truncated before the closing </html> tag";
  if (!studioFixtureModelUsageAllowed() && studioTextContainsProductFixtureMarker(text)) {
    return "model output came from a deterministic fixture route";
  }
  if (/\bchat__reply\b|\bagent__complete\b|\btool_call\b|\bTOOLCAT_/i.test(text)) {
    return "model output leaked harness/tool-call scaffolding";
  }
  if (/\/home\/[^<\s]+|Workspace root:|You are in \//i.test(text)) {
    return "model output leaked workspace/runtime scaffolding";
  }
  if (/<(?:script|link|img|iframe|source|audio|video)\b[^>]*(?:src|href)=["']?https?:\/\//i.test(text)) {
    return "model output referenced external network assets";
  }
  const topicWords = stringValue(prompt)
    .toLowerCase()
    .replace(/[^a-z0-9\s-]+/g, " ")
    .split(/\s+/)
    .filter((word) => word.length >= 5 && !new Set([
      "create",
      "build",
      "make",
      "generate",
      "website",
      "webpage",
      "landing",
      "explains",
      "about",
      "using",
      "with",
      "artifact",
    ]).has(word));
  if (topicWords.length > 0) {
    const haystack = text.toLowerCase();
    const matched = topicWords.filter((word) => haystack.includes(word));
    if (matched.length === 0) return "website draft did not reference the requested topic";
  }
  return "";
}

async function generateStudioStaticWebsiteDraft({ prompt, title, selectedRoute, selectedModelId, reasoningEffort = "none", workspacePath, researchContext = "" }, output) {
  const endpoint = daemonEndpoint();
  const token = await ensureStudioModelInvocationToken(output);
  const requestedModel = studioModelIdForRouteInvocation(selectedRoute, selectedModelId);
  const selectedReasoningEffort = normalizeStudioReasoningEffort(reasoningEffort, "none");
  const startedAtMs = Date.now();
  const denyFixturePolicy = studioDenyFixtureModelPolicy();
  const streamId = `studio-stream-${crypto.randomUUID()}`;
  const metadata = {
    receiptIds: new Set(),
    routeId: selectedRoute,
    model: requestedModel,
    providerStream: null,
    provider: null,
    usage: null,
    stopReason: null,
    firstTokenAtMs: null,
  };
  const streamResult = {
    streamId,
    text: "",
    thinkingText: "",
    chunkCount: 0,
  };
  studioPostRuntimeMessage("assistantStreamStart", {
    streamId,
    routeId: selectedRoute,
    startedAt: new Date().toISOString(),
    presentation: "artifact_generation",
    fileName: "index.html",
  });
  try {
    await requestSseJson(endpoint, "/v1/chat/completions", {
      method: "POST",
      token,
      timeoutMs: STUDIO_MODEL_COMPLETION_TIMEOUT_MS,
      payload: {
        route_id: selectedRoute,
        model: requestedModel,
        stream: true,
        messages: [
          {
            role: "system",
            content: [
              "You create polished, self-contained static website artifacts for Autopilot Agent Studio.",
              "Return one complete HTML document only: <!DOCTYPE html><html>...</html>.",
              "Keep the document compact enough to finish quickly in one response: roughly 70-110 lines, concise copy, at most five visible sections.",
              "End the response immediately after the closing </html> tag.",
              "The website must be specific to the user's request, not a reusable topic-swap template.",
              "When source context is provided, use it to improve the copy while avoiding footnote spam.",
              "If the topic wording is ambiguous, represent the ambiguity in the page instead of silently substituting an adjacent topic.",
              "Put all CSS in a <style> tag and any tiny optional JS in a <script> tag.",
              "No JSON wrapper, no markdown fences, no external network assets, no remote fonts, no scripts from CDNs, and no filesystem references.",
            ].join(" "),
          },
          {
            role: "user",
            content: [
              `Requested artifact title: ${title}`,
              "User request:",
              prompt,
              stringValue(researchContext) ? "\nUseful source/context notes:\n" + stringValue(researchContext).slice(0, 5000) : "",
            ].join("\n"),
          },
        ],
        metadata: {
          source: "agent-studio-conversation-artifact-generator",
          workspaceRoot: workspacePath,
          runtimeAuthority: "daemon-owned",
          projectionOwner: "ioi-workbench-agent-studio",
        },
        model_policy: denyFixturePolicy,
        modelPolicy: denyFixturePolicy,
        max_tokens: studioArtifactMaxOutputTokens(),
        temperature: 1,
        top_p: 0.95,
        top_k: 20,
        presence_penalty: 1.5,
        reasoning_effort: selectedReasoningEffort,
        reasoningEffort: selectedReasoningEffort,
      },
      onPayload: (payload) => {
        collectStudioStreamMetadata(metadata, payload);
        const reasoningDelta = studioReasoningDeltaFromSsePayload(payload);
        if (reasoningDelta) {
          metadata.firstTokenAtMs = metadata.firstTokenAtMs || Date.now();
          streamResult.thinkingText += reasoningDelta;
          studioPostRuntimeMessage("assistantThinkingDelta", {
            streamId,
            delta: reasoningDelta,
          });
        }
        const delta = studioDeltaFromSsePayload(payload);
        if (!delta) {
          return;
        }
        metadata.firstTokenAtMs = metadata.firstTokenAtMs || Date.now();
        streamResult.text += delta;
        streamResult.chunkCount += 1;
        studioPostRuntimeMessage("assistantStreamDelta", {
          streamId,
          delta,
          chunkCount: streamResult.chunkCount,
          fileName: "index.html",
        });
        const htmlCloseMatch = streamResult.text.match(/<\/html>/i);
        if (htmlCloseMatch?.index !== undefined) {
          streamResult.text = streamResult.text.slice(0, htmlCloseMatch.index + htmlCloseMatch[0].length);
          return false;
        }
      },
    });
  } catch (error) {
    studioPostRuntimeMessage("assistantStreamError", {
      streamId,
      error: error?.message || String(error),
    });
    throw error;
  }
  const split = studioSplitReasoningFromText(streamResult.text);
  streamResult.thinkingText = stringValue(streamResult.thinkingText || split.thinkingText);
  streamResult.text = split.answerText || streamResult.text;
  const streamedModel = metadata.model || requestedModel;
  const text = streamResult.text;
  const metrics = studioResponseMetricsFromUsage({
    usage: metadata.usage || {},
    routeId: metadata.routeId || selectedRoute,
    model: streamedModel,
    provider: metadata.provider || (metadata.providerStream ? "provider native stream" : ""),
    reasoningEffort: selectedReasoningEffort,
    elapsedMs: Date.now() - startedAtMs,
    timeToFirstTokenMs: metadata.firstTokenAtMs ? metadata.firstTokenAtMs - startedAtMs : null,
    stopReason: metadata.stopReason,
    requestedModel,
    promptText: prompt,
    generatedText: text,
  });
  studioPostRuntimeMessage("assistantStreamComplete", {
    streamId,
    text,
    thinkingText: streamResult.thinkingText,
    chunkCount: streamResult.chunkCount,
    receiptIds: [...metadata.receiptIds],
    routeId: metadata.routeId || selectedRoute,
    model: streamedModel,
    providerStream: metadata.providerStream,
    metrics,
    fileName: "index.html",
  });
  const parsed = parseStudioJsonObject(text);
  const parsedHtml = stringValue(parsed?.html);
  const extractedHtml = parsedHtml || extractStudioHtmlDocument(text);
  const draft = parsed && parsedHtml && parsedHtml.length >= 80
    ? {
        title: stringValue(parsed.title, title),
        summary: stringValue(parsed.summary, `Generated website for: ${prompt}`),
        html: parsedHtml,
        css: stringValue(parsed.css),
        js: stringValue(parsed.js),
      }
    : extractedHtml
      ? {
          title,
          summary: `Model-authored website artifact for: ${prompt}`,
          html: extractedHtml,
          css: "",
          js: "",
        }
      : { title, summary: "", html: "", css: "", js: "" };
  const rejectReason = studioWebsiteDraftRejectReason({ prompt, draft, rawText: text, parsed });
  if (rejectReason) {
    const error = new Error(`Selected model did not return usable website artifact content: ${rejectReason}.`);
    error.code = "invalid_website_artifact_draft";
    error.details = {
      rejectReason,
      structuredJson: Boolean(parsed && parsedHtml && parsedHtml.length >= 80),
      extractedHtml: Boolean(extractedHtml),
      rawTextHash: crypto.createHash("sha256").update(text).digest("hex").slice(0, 16),
    };
    throw error;
  }
  appendStudioReceipts(
    [...metadata.receiptIds].map((id) => ({
      id,
      kind: "model_invocation",
      summary: "Daemon model drafted website artifact content.",
    })),
    "model_invocation",
  );
  return {
    ...draft,
    generator: {
      routeId: selectedRoute,
      model: requestedModel,
      source: "daemon_model_completion",
      structuredJson: Boolean(parsed && parsedHtml && parsedHtml.length >= 80),
      htmlDocument: Boolean(extractedHtml && !(parsed && parsedHtml && parsedHtml.length >= 80)),
      metrics,
      receiptRefs: [...metadata.receiptIds],
      streamId,
    },
  };
}


  return {
    streamStudioModelCompletion,
    studioChatCompletionText,
    parseStudioJsonObject,
    extractStudioHtmlDocument,
    studioWebsiteDraftRejectReason,
    generateStudioStaticWebsiteDraft,
  };
}

module.exports = {
  createStudioModelCompletion,
};
