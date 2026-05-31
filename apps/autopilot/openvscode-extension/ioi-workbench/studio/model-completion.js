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

  function studioAskRequiresFreshRetrieval(prompt = "") {
    return /\b(today|right now|latest|recent|news|price|market|market cap|investment|invest|better|crypto|stock|exchange rate|weather|sources?|cite|citation)\b/i.test(
      stringValue(prompt),
    );
  }

  function studioAskFreshRetrievalBlockerText(prompt = "") {
    const text = stringValue(prompt).toLowerCase();
    if (/\b(invest|investment|price|market|crypto|stock|exchange rate)\b/.test(text)) {
      return "Fresh retrieval is required for this current market question; I should not guess. Switch to Agent mode so I can gather current sources and compare the evidence.";
    }
    return "Fresh retrieval is required for this current question; I should not guess. Switch to Agent mode so I can gather current sources first.";
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

  try {
    if (studioAskRequiresFreshRetrieval(prompt)) {
      const blockerText = studioAskFreshRetrievalBlockerText(prompt);
      metadata.firstTokenAtMs = Date.now();
      result.text = blockerText;
      result.chunkCount = 1;
      result.stopReason = "fresh_retrieval_required";
      studioPostRuntimeMessage("assistantStreamDelta", {
        streamId,
        delta: blockerText,
        chunkCount: result.chunkCount,
      });
      studioRuntimeProjection.timeline.push({
        label: "Ask fresh retrieval boundary",
        detail: "Current facts require Agent mode retrieval before an answer.",
        status: "blocked",
      });
    } else {
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
      "- If the prompt asks for current, latest, today, price, market, investment, or right-now high-stakes recommendations, your first sentence must include the exact phrase `fresh retrieval is required`, `current sources`, or `should not guess`; then suggest Agent mode for web retrieval.",
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
  result.stopReason = metadata.stopReason || result.stopReason;
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
    return "model output came from a test fixture route";
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
  const denyFixturePolicy = studioDenyFixtureModelPolicy();
  let lastError = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const startedAtMs = Date.now();
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
      attempt: attempt + 1,
    });
    try {
      const repairInstruction = lastError?.details?.rejectReason
        ? [
            "The previous model draft was rejected by the artifact boundary:",
            lastError.details.rejectReason,
            "Rewrite the artifact as one complete user-requested HTML document now.",
          ].join(" ")
        : "";
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
                repairInstruction,
              ].filter(Boolean).join(" "),
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
            artifactDraftAttempt: attempt + 1,
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
              presentation: "artifact_generation",
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
            presentation: "artifact_generation",
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
        presentation: "artifact_generation",
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
      presentation: "artifact_generation",
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
      lastError = new Error(`Artifact boundary rejected generated website draft: ${rejectReason}.`);
      lastError.code = "invalid_website_artifact_draft";
      lastError.details = {
        rejectReason,
        structuredJson: Boolean(parsed && parsedHtml && parsedHtml.length >= 80),
        extractedHtml: Boolean(extractedHtml),
        rawTextHash: crypto.createHash("sha256").update(text).digest("hex").slice(0, 16),
        attempt: attempt + 1,
      };
      continue;
    }
    if (attempt > 0) {
      appendStudioReceipts([{
        id: `artifact-draft-repaired-${streamId}`,
        kind: "model_invocation_repair",
        summary: "Daemon model repaired website artifact draft after validation feedback.",
      }], "model_invocation");
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
  throw lastError || new Error("Artifact boundary rejected generated website draft.");
}

function studioStaticWebsiteDraftFromRuntimeText({
  prompt = "",
  title = "Generated website",
  text = "",
  selectedRoute = "",
  selectedModelId = "",
  metrics = null,
  receiptRefs = [],
  streamId = "",
} = {}) {
  const split = studioSplitReasoningFromText(text);
  const answerText = stringValue(split.answerText || text);
  const parsed = parseStudioJsonObject(answerText);
  const parsedHtml = stringValue(parsed?.html);
  const extractedHtml = parsedHtml || extractStudioHtmlDocument(answerText);
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
  const rejectReason = studioWebsiteDraftRejectReason({ prompt, draft, rawText: answerText, parsed });
  if (rejectReason) {
    const error = new Error(`Artifact boundary rejected generated website draft: ${rejectReason}.`);
    error.code = "invalid_website_artifact_draft";
    error.details = {
      rejectReason,
      structuredJson: Boolean(parsed && parsedHtml && parsedHtml.length >= 80),
      extractedHtml: Boolean(extractedHtml),
      rawTextHash: crypto.createHash("sha256").update(answerText).digest("hex").slice(0, 16),
    };
    throw error;
  }
  appendStudioReceipts(
    firstArray(receiptRefs).map((id) => ({
      id,
      kind: "agent_artifact_draft",
      summary: "Daemon Agent loop produced website artifact content.",
    })),
    "agent_artifact_draft",
  );
  return {
    ...draft,
    generator: {
      routeId: selectedRoute,
      model: selectedModelId,
      source: "daemon_agent_loop",
      structuredJson: Boolean(parsed && parsedHtml && parsedHtml.length >= 80),
      htmlDocument: Boolean(extractedHtml && !(parsed && parsedHtml && parsedHtml.length >= 80)),
      metrics,
      receiptRefs: firstArray(receiptRefs),
      streamId,
    },
  };
}

async function streamStudioShortModelHandoff({
  prompt,
  selectedRoute,
  selectedModelId,
  reasoningEffort = "none",
  workspacePath,
  systemPrompt,
  handoffContext,
  presentation = "final_handoff",
  maxTokens = 512,
}, output) {
  const endpoint = daemonEndpoint();
  const token = await ensureStudioModelInvocationToken(output);
  const requestedModel = studioModelIdForRouteInvocation(selectedRoute, selectedModelId);
  const selectedReasoningEffort = normalizeStudioReasoningEffort(reasoningEffort, "none");
  const startedAtMs = Date.now();
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
  const result = {
    streamId,
    text: "",
    thinkingText: "",
    chunkCount: 0,
  };
  studioPostRuntimeMessage("assistantStreamStart", {
    streamId,
    routeId: selectedRoute,
    startedAt: new Date().toISOString(),
    presentation,
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
          { role: "system", content: systemPrompt },
          {
            role: "user",
            content: [
              "User request:",
              prompt,
              "",
              "Runtime result:",
              handoffContext,
            ].join("\n"),
          },
        ],
        metadata: {
          source: "agent-studio-model-authored-handoff",
          workspaceRoot: workspacePath,
          runtimeAuthority: "daemon-owned",
          projectionOwner: "ioi-workbench-agent-studio",
          presentation,
        },
        model_policy: studioDenyFixtureModelPolicy(),
        modelPolicy: studioDenyFixtureModelPolicy(),
        max_tokens: Math.max(128, Math.min(studioMaxOutputTokens(), maxTokens)),
        temperature: 0.8,
        top_p: 0.95,
        top_k: 20,
        presence_penalty: 1.1,
        reasoning_effort: selectedReasoningEffort,
        reasoningEffort: selectedReasoningEffort,
      },
      onPayload: (payload) => {
        collectStudioStreamMetadata(metadata, payload);
        const reasoningDelta = studioReasoningDeltaFromSsePayload(payload);
        if (reasoningDelta) {
          metadata.firstTokenAtMs = metadata.firstTokenAtMs || Date.now();
          result.thinkingText += reasoningDelta;
          studioPostRuntimeMessage("assistantThinkingDelta", {
            streamId,
            delta: reasoningDelta,
            presentation,
          });
        }
        const delta = studioDeltaFromSsePayload(payload);
        if (!delta) {
          return;
        }
        metadata.firstTokenAtMs = metadata.firstTokenAtMs || Date.now();
        result.text += delta;
        result.chunkCount += 1;
        studioPostRuntimeMessage("assistantStreamDelta", {
          streamId,
          delta,
          presentation,
          chunkCount: result.chunkCount,
        });
      },
    });
  } catch (error) {
    studioPostRuntimeMessage("assistantStreamError", {
      streamId,
      presentation,
      error: error?.message || String(error),
    });
    throw error;
  }

  const split = studioSplitReasoningFromText(result.text);
  const text = stringValue(split.answerText || result.text).trim();
  const thinkingText = stringValue(result.thinkingText || split.thinkingText);
  if (!text) {
    throw new Error("Selected model did not return a user-facing handoff.");
  }
  if (studioTextContainsProductFixtureMarker(`${metadata.model || requestedModel}\n${text}`) && !studioFixtureModelUsageAllowed()) {
    throw new Error("Selected model route produced fixture output instead of a product handoff.");
  }
  const metrics = studioResponseMetricsFromUsage({
    usage: metadata.usage || {},
    routeId: metadata.routeId || selectedRoute,
    model: metadata.model || requestedModel,
    provider: metadata.provider || (metadata.providerStream ? "provider native stream" : ""),
    reasoningEffort: selectedReasoningEffort,
    elapsedMs: Date.now() - startedAtMs,
    timeToFirstTokenMs: metadata.firstTokenAtMs ? metadata.firstTokenAtMs - startedAtMs : null,
    stopReason: metadata.stopReason,
    requestedModel,
    promptText: prompt,
    generatedText: text,
  });
  appendStudioReceipts(
    [...metadata.receiptIds].map((id) => ({
      id,
      kind: "model_invocation_handoff",
      summary: "Daemon model authored Studio handoff text.",
    })),
    "model_invocation",
  );
  studioPostRuntimeMessage("assistantStreamComplete", {
    streamId,
    text,
    thinkingText,
    chunkCount: result.chunkCount,
    receiptIds: [...metadata.receiptIds],
    routeId: metadata.routeId || selectedRoute,
    model: metadata.model || requestedModel,
    providerStream: metadata.providerStream,
    presentation,
    metrics,
  });
  return {
    text,
    streamId,
    receiptIds: [...metadata.receiptIds],
    metrics,
  };
}

async function streamStudioArtifactHandoffText(args, output) {
  return streamStudioShortModelHandoff({
    ...args,
    presentation: "artifact_handoff",
    maxTokens: 384,
    systemPrompt: [
      "You write the final user-facing handoff after Autopilot Agent Studio has created an artifact.",
      "Return only concise Markdown prose, one short paragraph or two bullets.",
      "Mention what the user can do next if useful.",
      "Do not expose traces, receipts, fixture paths, JSON payloads, daemon details, or policy plumbing.",
      "Do not claim hidden work beyond the runtime result supplied by the harness.",
    ].join(" "),
  }, output);
}

async function streamStudioArtifactBlockedHandoff(args, output) {
  return streamStudioShortModelHandoff({
    ...args,
    presentation: "artifact_blocked_handoff",
    maxTokens: 320,
    systemPrompt: [
      "You write the user-facing blocker after an Autopilot Agent Studio artifact boundary rejected a result.",
      "Return only concise Markdown prose.",
      "Explain the blocker in normal product language and give the next useful user action.",
      "Do not expose traces, receipts, fixture paths, JSON payloads, daemon details, policy plumbing, or validation internals.",
      "Do not pretend an artifact was created.",
    ].join(" "),
  }, output);
}


  return {
    streamStudioModelCompletion,
    studioChatCompletionText,
    parseStudioJsonObject,
    extractStudioHtmlDocument,
    studioWebsiteDraftRejectReason,
    generateStudioStaticWebsiteDraft,
    studioStaticWebsiteDraftFromRuntimeText,
    streamStudioArtifactHandoffText,
    streamStudioArtifactBlockedHandoff,
  };
}

module.exports = {
  createStudioModelCompletion,
};
