export function createSubmitPrompt(deps) {
  const {
    assertNotCannedDaemonProjection,
    assertSemanticModelResponse,
    assistantTextMatchesPrompt,
    latestAssistantText,
    markPromptPhase,
    normalizeScenarioExecutionMode,
    requireRequest,
    screenshot,
    setComposerValue,
    wait,
    waitForPredicate,
    withStudioFrame,
    writePromptTiming,
  } = deps;

  async function captureLatestMarkdownRenderProof(page) {
    return withStudioFrame(page, async (frame) => frame.evaluate(() => {
      const nodes = Array.from(document.querySelectorAll(
        '[data-testid="studio-assistant-answer-text"], [data-testid="studio-streaming-output"]',
      ));
      const node = nodes[nodes.length - 1] || null;
      if (!node) {
        return {
          observed: false,
          reason: "missing-assistant-answer-node",
        };
      }
      const turn = node.closest("[data-studio-turn-role='assistant']");
      const composer = document.querySelector("[data-testid='studio-composer']");
      const turnRect = turn?.getBoundingClientRect?.() || null;
      const composerRect = composer?.getBoundingClientRect?.() || null;
      const text = String(node.textContent || "");
      const proof = {
        observed: true,
        markdownHydrated: node.dataset.markdownHydrated === "true" || node.dataset.rawMarkdown !== undefined,
        headingCount: node.querySelectorAll("h1,h2,h3,h4").length,
        listCount: node.querySelectorAll("ul,ol").length,
        inlineCodeCount: Array.from(node.querySelectorAll("code")).filter((code) => !code.closest("pre")).length,
        fencedCodeBlockCount: node.querySelectorAll("pre code").length,
        tableCount: node.querySelectorAll("table").length,
        linkCount: node.querySelectorAll("a[href]").length,
        strongCount: node.querySelectorAll("strong").length,
        rawMarkdownSyntaxVisible:
          /(^|\n)\s{0,3}#{1,4}\s+\S/.test(text) ||
          /(^|\n)\s*[-*+]\s+\S/.test(text) ||
          /```/.test(text) ||
          /\*\*[^*\n]+\*\*/.test(text) ||
          /`[^`\n]+`/.test(text),
        answerTextSample: text.replace(/\s+/g, " ").trim().slice(0, 600),
        turnBottom: turnRect ? Math.round(turnRect.bottom) : null,
        composerTop: composerRect ? Math.round(composerRect.top) : null,
        overlappedByComposer: Boolean(turnRect && composerRect && turnRect.bottom > composerRect.top + 4),
      };
      return proof;
    }));
  }

  async function captureLatestSourceRowsProof(page) {
    return withStudioFrame(page, async (frame) => frame.evaluate(() => {
      const turns = Array.from(document.querySelectorAll("[data-studio-turn-role='assistant']"));
      const turn = turns[turns.length - 1] || null;
      const sourceRoot = turn?.querySelector?.("[data-testid='studio-answer-sources']") || null;
      const links = sourceRoot ? Array.from(sourceRoot.querySelectorAll("a[href]")) : [];
      return {
        observed: Boolean(sourceRoot),
        sourceCount: links.length,
        labels: links.map((link) => String(link.textContent || "").replace(/\s+/g, " ").trim()).filter(Boolean),
        hrefs: links.map((link) => link.getAttribute("href") || "").filter(Boolean),
      };
    }));
  }

  function markdownElementMissing(proof, elementName) {
    const normalized = String(elementName || "").trim().toLowerCase().replace(/[\s_-]+/g, "");
    if (!normalized) return false;
    if (["heading", "headings", "h1", "h2", "h3", "h4"].includes(normalized)) {
      return Number(proof?.headingCount || 0) === 0;
    }
    if (["list", "lists", "bullet", "bullets", "orderedlist", "unorderedlist"].includes(normalized)) {
      return Number(proof?.listCount || 0) === 0;
    }
    if (["inlinecode", "code"].includes(normalized)) {
      return Number(proof?.inlineCodeCount || 0) === 0;
    }
    if (["fencedcode", "codeblock", "pre", "precode"].includes(normalized)) {
      return Number(proof?.fencedCodeBlockCount || 0) === 0;
    }
    if (["table", "tables"].includes(normalized)) {
      return Number(proof?.tableCount || 0) === 0;
    }
    if (["link", "links"].includes(normalized)) {
      return Number(proof?.linkCount || 0) === 0;
    }
    if (["strong", "bold"].includes(normalized)) {
      return Number(proof?.strongCount || 0) === 0;
    }
    return false;
  }

  async function submitPrompt(page, requests, prompt, mode = "button", timingPath = null, options = {}) {
  const startedAtMs = Date.now();
  const timing = {
    prompt,
    mode,
    startedAt: new Date(startedAtMs).toISOString(),
    startedAtMs,
    timingPath,
    phases: [],
  };
  const startIndex = requests.length;
  let pendingProjectionProof = null;
  let artifactSourceStreamObserved = false;
  let phaseStartedAtMs = Date.now();
  const normalizeObservedAnswerText = (value) => String(value || "").replace(/\s+/g, " ").trim();
  const initialCounts = await withStudioFrame(page, async (frame) => {
    const initialAnswerTexts = await frame
      .locator('[data-testid="studio-assistant-answer-text"], [data-testid="studio-streaming-output"]')
      .allTextContents()
      .catch(() => []);
    return {
      assistantCount: await frame.locator('[data-testid="studio-assistant-answer-card"]').count(),
      documentedWorkCount: await frame.locator('[data-studio-turn-role="assistant"][data-documented-work="true"]').count(),
      streamOutputCount: await frame.locator('[data-testid="studio-streaming-output"]').count(),
      thinkingBlockCount: await frame.locator('[data-testid="studio-thinking-block"] p').count(),
      artifactSourceCount: await frame.locator('[data-testid="studio-artifact-source-output"]').count(),
      answerTextKeys: initialAnswerTexts.map(normalizeObservedAnswerText).filter(Boolean),
    };
  });
  const initialAssistantCount = initialCounts.assistantCount;
  const initialDocumentedWorkCount = initialCounts.documentedWorkCount;
  const initialStreamOutputCount = initialCounts.streamOutputCount;
  const initialThinkingBlockCount = initialCounts.thinkingBlockCount;
  const initialArtifactSourceCount = initialCounts.artifactSourceCount;
  const initialAnswerTextKeys = new Set(initialCounts.answerTextKeys || []);
  markPromptPhase(timing, "initial-assistant-count", phaseStartedAtMs, {
    initialAssistantCount,
    initialDocumentedWorkCount,
    initialStreamOutputCount,
    initialThinkingBlockCount,
  });
  phaseStartedAtMs = Date.now();
  await setComposerValue(page, prompt);
  markPromptPhase(timing, "set-composer-value", phaseStartedAtMs);

  const triggerSubmit = async () => {
    if (mode === "keyboard") {
      await withStudioFrame(page, async (frame) => {
        const input = frame.locator('[data-testid="studio-composer-input"]').first();
        await input.focus();
        await input.press(process.platform === "darwin" ? "Meta+Enter" : "Control+Enter");
      });
      return;
    }
    await withStudioFrame(page, async (frame) => {
      const sendButton = frame.locator('[data-testid="studio-send-button"]').first();
      await sendButton.click({ timeout: 5000 }).catch(async () => {
        await frame.evaluate(() => {
          const form = document.querySelector("[data-studio-prompt-form]");
          if (form?.requestSubmit) {
            form.requestSubmit();
            return;
          }
          form?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
        });
      });
    });
  };

  const triggerFormSubmit = async () => {
    await setComposerValue(page, prompt);
    await withStudioFrame(page, async (frame) => {
      await frame.evaluate(() => {
        const input = document.querySelector('[data-testid="studio-composer-input"]');
        if (input) {
          input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: "" }));
          input.dispatchEvent(new Event("change", { bubbles: true }));
        }
        const form = document.querySelector("[data-studio-prompt-form]");
        if (form?.requestSubmit) {
          form.requestSubmit();
          return;
        }
        form?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      });
    });
  };

  phaseStartedAtMs = Date.now();
  await triggerSubmit();
  markPromptPhase(timing, "submit-action", phaseStartedAtMs);
  const requestPromise = requireRequest(
    requests,
    (candidate) => candidate?.requestType === "chat.submit" && candidate?.payload?.prompt === prompt,
    `chat.submit:${prompt.slice(0, 40)}`,
    45_000,
    startIndex,
  ).catch((error) => ({ requestError: error }));
  let requestFromPendingPhase = null;
  phaseStartedAtMs = Date.now();
  const pending = await waitForPredicate(async () => {
    try {
      return await withStudioFrame(page, async (frame) => {
        const userTurns = await frame.locator('[data-testid="studio-user-turn-immediate"]').count();
        const pendingVisible = await frame.locator('[data-testid="studio-pending-state"]:not([hidden])').count();
        const answerCount = await frame.locator('[data-testid="studio-assistant-answer-card"]').count();
        const root = frame.locator('[data-testid="agent-studio-operational-chat"]').first();
        const immediateSubmitSeen = await root.getAttribute("data-immediate-submit-seen").catch(() => "false");
        const pendingStateSeen = await root.getAttribute("data-pending-state-seen").catch(() => "false");
        const bridgeRequestSeen = requests
          .slice(startIndex)
          .some((candidate) => candidate?.requestType === "chat.submit" && candidate?.payload?.prompt === prompt);
        return userTurns > 0 && (
          pendingVisible > 0 ||
          (immediateSubmitSeen === "true" && pendingStateSeen === "true") ||
          bridgeRequestSeen ||
          answerCount > initialAssistantCount
        );
      }, 3);
    } catch {
      return false;
    }
  }, 3000, 100);
  if (!pending) {
    const requestCandidate = await Promise.race([
      requestPromise,
      wait(2500).then(() => null),
    ]);
    if (requestCandidate && !requestCandidate.requestError) {
      requestFromPendingPhase = requestCandidate;
    } else {
      const retryStartedAtMs = Date.now();
      await triggerFormSubmit();
      markPromptPhase(timing, "submit-action-retry-after-missing-pending", retryStartedAtMs);
      const retryRequestCandidate = await Promise.race([
        requestPromise,
        wait(5000).then(() => null),
      ]);
      if (retryRequestCandidate && !retryRequestCandidate.requestError) {
        requestFromPendingPhase = retryRequestCandidate;
      } else {
        throw new Error(`Prompt did not produce immediate user turn or submit request: ${prompt.slice(0, 40)}`);
      }
    }
  }
  markPromptPhase(timing, "pending-observed", phaseStartedAtMs);
  const expectedExecutionMode = normalizeScenarioExecutionMode(options.expectedExecutionMode || "");
  if (options.capturePendingProjection && options.outputDir && options.screenshots) {
    await waitForPredicate(async () => {
      try {
        return await withStudioFrame(page, async (frame) => {
          const visible = await frame.locator('[data-testid="studio-pending-state"]:not([hidden])').count();
          const worklogCount = await frame.locator('[data-testid="studio-pending-worklog"] li').count();
          const streamOutputCount = await frame.locator('[data-testid="studio-streaming-output"]').count();
          const artifactSourceCount = await frame.locator('[data-testid="studio-artifact-source-output"]').count();
          const answerCount = await frame.locator('[data-testid="studio-assistant-answer-card"]').count();
          if (expectedExecutionMode === "ask") {
            return visible > 0 ||
              streamOutputCount > initialStreamOutputCount ||
              answerCount > initialAssistantCount;
          }
          return worklogCount > 0 || artifactSourceCount > initialArtifactSourceCount;
        }, 3);
      } catch {
        return false;
      }
    }, Number(options.pendingWorklogTimeoutMs || 12000), 100).catch(() => false);
    pendingProjectionProof = await withStudioFrame(page, async (frame) => {
      const pendingNode = frame.locator('[data-testid="studio-pending-state"]').first();
      const pendingText = await pendingNode.textContent({ timeout: 50 }).catch(() => "");
      const progressTagCount = await frame.locator('[data-testid="studio-pending-progress"], [data-studio-pending-step]').count();
      const worklogCount = await frame.locator('[data-testid="studio-pending-worklog"] li').count().catch(() => 0);
      const streamOutputCount = await frame.locator('[data-testid="studio-streaming-output"]').count().catch(() => 0);
      const artifactSourceCount = await frame.locator('[data-testid="studio-artifact-source-output"]').count().catch(() => 0);
      const answerCount = await frame.locator('[data-testid="studio-assistant-answer-card"]').count().catch(() => 0);
      const rootStatus = await frame.locator('[data-testid="agent-studio-operational-chat"]').first().getAttribute("data-studio-status").catch(() => "");
      const streamText = streamOutputCount > initialStreamOutputCount
        ? await frame.locator('[data-testid="studio-streaming-output"]').nth(streamOutputCount - 1).textContent({ timeout: 50 }).catch(() => "")
        : "";
      const artifactSourceText = artifactSourceCount > initialArtifactSourceCount
        ? await frame.locator('[data-testid="studio-artifact-source-output"]').nth(artifactSourceCount - 1).textContent({ timeout: 50 }).catch(() => "")
        : "";
      const pendingVisible = await pendingNode.isVisible({ timeout: 50 }).catch(() => false);
      const observed = pendingVisible ||
        worklogCount > 0 ||
        artifactSourceCount > initialArtifactSourceCount ||
        (
          expectedExecutionMode === "ask" && (
            streamOutputCount > initialStreamOutputCount ||
            answerCount > initialAssistantCount ||
            rootStatus === "streaming" ||
            rootStatus === "completed"
          )
        );
      return {
        observed,
        textSample: String(pendingText || "").replace(/\s+/g, " ").trim().slice(0, 500),
        progressTagCount,
        worklogCount,
        streamOutputCount,
        artifactSourceCount,
        answerCount,
        rootStatus,
        streamTextSample: String(streamText || "").replace(/\s+/g, " ").trim().slice(0, 500),
        artifactSourceSample: String(artifactSourceText || "").replace(/\s+/g, " ").trim().slice(0, 500),
        hasForbiddenTags: /\bUsing tools\b|\bPreparing response\b/.test(String(pendingText || "")) || progressTagCount > 0,
      };
    }).catch(() => null);
    await screenshot(page, options.outputDir, "pending-worklog-live.png", options.screenshots).catch(() => {});
    if (pendingProjectionProof?.hasForbiddenTags) {
      throw new Error(`Pending worklog still exposes scaffold tags: ${pendingProjectionProof.textSample}`);
    }
    if (options.requirePendingWorklog && expectedExecutionMode !== "ask" && !pendingProjectionProof?.worklogCount) {
      throw new Error("Pending worklog proof did not capture a concrete live tool row.");
    }
    if (!pendingProjectionProof?.observed && (options.requirePendingWorklog || expectedExecutionMode === "ask")) {
      throw new Error("Pending worklog proof did not capture the live pending state.");
    }
  }
  phaseStartedAtMs = Date.now();
  let request = requestFromPendingPhase;
  if (!request) {
    request = await Promise.race([
      requestPromise,
      wait(3500).then(() => null),
    ]);
    if (!request) {
      const retryStartedAtMs = Date.now();
      await triggerFormSubmit();
      markPromptPhase(timing, "submit-action-retry", retryStartedAtMs);
      request = await requestPromise;
    }
  }
  if (request?.requestError) {
    throw request.requestError;
  }
  markPromptPhase(timing, "bridge-request-observed", phaseStartedAtMs);
  const executionMode = String(request?.payload?.executionMode || "").toLowerCase();
  const agentFinalStreamRequired = executionMode === "agent" && Boolean(options.requireAgentFinalStream);
  const streamRequired = executionMode === "ask" || agentFinalStreamRequired;
  const assistantVisibleTimeoutMs = Number(options.assistantVisibleTimeoutMs) > 0
    ? Number(options.assistantVisibleTimeoutMs)
    : streamRequired ? 45_000 : 20_000;
  const streamProbeTimeoutMs = Number(options.streamProbeTimeoutMs) > 0
    ? Number(options.streamProbeTimeoutMs)
    : streamRequired ? 20_000 : 500;
  phaseStartedAtMs = Date.now();
  const streamProbe = await waitForPredicate(async () => {
    try {
      return await withStudioFrame(page, async (frame) => {
        const streamOutput = frame.locator('[data-testid="studio-streaming-output"]');
        const streamOutputCount = await streamOutput.count();
        const thinkingBlocks = frame.locator('[data-testid="studio-thinking-block"] p');
        const artifactSources = frame.locator('[data-testid="studio-artifact-source-output"]');
        const worklogItems = frame.locator('[data-testid="studio-pending-worklog"] li');
        const thinkingBlockCount = await thinkingBlocks.count();
        const artifactSourceCount = await artifactSources.count();
        const worklogCount = await worklogItems.count();
        const streamText = streamOutputCount > initialStreamOutputCount
          ? (await streamOutput.nth(streamOutputCount - 1).textContent({ timeout: 50 }).catch(() => "")).trim()
          : "";
        const thinkingText = thinkingBlockCount > initialThinkingBlockCount
          ? (await thinkingBlocks.nth(thinkingBlockCount - 1).textContent({ timeout: 50 }).catch(() => "")).trim()
          : "";
        const artifactSourceText = artifactSourceCount > initialArtifactSourceCount
          ? (await artifactSources.nth(artifactSourceCount - 1).textContent({ timeout: 50 }).catch(() => "")).trim()
          : "";
        const workText = worklogCount > 0
          ? (await worklogItems.nth(worklogCount - 1).textContent({ timeout: 50 }).catch(() => "")).trim()
          : "";
        const status = await frame.locator('[data-testid="agent-studio-operational-chat"]').first().getAttribute("data-studio-status");
        if (artifactSourceText && ["pending", "streaming", "completed"].includes(status || "")) {
          return { streamText: artifactSourceText, thinkingText, streamKind: "artifact_source", status };
        }
        if (streamText && ["pending", "streaming", "completed"].includes(status || "")) {
          return { streamText, thinkingText, streamKind: "answer", status };
        }
        if (thinkingText && ["pending", "streaming", "completed"].includes(status || "")) {
          return { streamText: "", thinkingText, streamKind: "thinking", status };
        }
        if (workText && ["pending", "streaming", "completed"].includes(status || "")) {
          return { streamText: "", thinkingText: "", workText, streamKind: "tool", status };
        }
        return null;
      }, 3);
    } catch {
      return null;
    }
  }, streamProbeTimeoutMs, 100);
  if (streamRequired && !streamProbe?.streamText && !streamProbe?.thinkingText && !streamProbe?.workText) {
    throw new Error(`Prompt did not expose streamed assistant deltas: ${prompt.slice(0, 40)}`);
  }
  let agentFinalStreamProbe = streamProbe?.streamKind === "answer" ? streamProbe : null;
  artifactSourceStreamObserved = streamProbe?.streamKind === "artifact_source" && Boolean(streamProbe?.streamText);
  if (streamProbe?.streamText) {
    assertNotCannedDaemonProjection(streamProbe.streamText, prompt);
    assertNoDeterministicSourceLeak(streamProbe.streamText, prompt);
  }
  if (
    options.capturePendingProjection &&
    options.outputDir &&
    options.screenshots &&
    streamProbe?.streamKind === "artifact_source" &&
    streamProbe.streamText
  ) {
    await screenshot(page, options.outputDir, "artifact-source-stream-live.png", options.screenshots).catch(() => {});
  }
  if (
    options.capturePendingProjection &&
    options.outputDir &&
    options.screenshots &&
    options.requireAgentFinalStream &&
    agentFinalStreamProbe?.streamText
  ) {
    await screenshot(page, options.outputDir, "agent-final-handoff-stream-live.png", options.screenshots).catch(() => {});
  }
  markPromptPhase(timing, "stream-probe", phaseStartedAtMs, {
    streamRequired,
    observed: Boolean(streamProbe?.streamText || streamProbe?.thinkingText || streamProbe?.workText),
    streamKind: streamProbe?.streamKind || null,
  });
  if (options.requireAgentArtifactSourceStream && !artifactSourceStreamObserved) {
    const artifactSourceProbe = await waitForPredicate(async () => {
      try {
        return await withStudioFrame(page, async (frame) => {
          const sources = frame.locator('[data-testid="studio-artifact-source-output"]');
          const count = await sources.count();
          const text = count > initialArtifactSourceCount
            ? (await sources.nth(count - 1).textContent({ timeout: 50 }).catch(() => "")).trim()
            : "";
          return text ? { streamText: text, streamKind: "artifact_source" } : null;
        }, 3);
      } catch {
        return null;
      }
    }, Number(options.artifactSourceStreamTimeoutMs || 180_000), 300);
    artifactSourceStreamObserved = Boolean(artifactSourceProbe?.streamText);
    if (artifactSourceProbe?.streamText) {
      assertNoDeterministicSourceLeak(artifactSourceProbe.streamText, prompt);
    }
  }
  if (agentFinalStreamRequired && !agentFinalStreamProbe?.streamText) {
    phaseStartedAtMs = Date.now();
    const finalStreamTimeoutMs = Number(options.agentFinalStreamTimeoutMs) > 0
      ? Number(options.agentFinalStreamTimeoutMs)
      : Math.max(assistantVisibleTimeoutMs, 180_000);
    agentFinalStreamProbe = await waitForPredicate(async () => {
      try {
            return await withStudioFrame(page, async (frame) => {
              const streamOutput = frame.locator('[data-testid="studio-streaming-output"]');
              const streamOutputCount = await streamOutput.count();
              const root = frame.locator('[data-testid="agent-studio-operational-chat"]').first();
              const status = await root.getAttribute("data-studio-status");
              const finalHandoffComplete = (await root.getAttribute("data-agent-final-handoff-stream-complete").catch(() => "false")) === "true";
              const streamText = streamOutputCount > initialStreamOutputCount
                ? (await streamOutput.nth(streamOutputCount - 1).textContent({ timeout: 50 }).catch(() => "")).trim()
                : "";
              if (streamText && ["pending", "streaming", "completed"].includes(status || "")) {
                return { streamText, thinkingText: "", streamKind: "answer", status };
              }
              const answerTexts = await frame
                .locator('[data-testid="studio-assistant-answer-text"], [data-testid="studio-streaming-output"]')
                .allTextContents()
                .catch(() => []);
              const latestText = String(answerTexts[answerTexts.length - 1] || "").trim();
              const normalizedLatestText = normalizeObservedAnswerText(latestText);
              if (
                latestText &&
                !initialAnswerTextKeys.has(normalizedLatestText) &&
                (status === "completed" || finalHandoffComplete)
              ) {
                return {
                  streamText: latestText,
                  thinkingText: "",
                  streamKind: finalHandoffComplete ? "answer_completed_handoff" : "answer_completed",
                  status,
                };
              }
              return null;
            }, 3);
      } catch {
        return null;
      }
    }, finalStreamTimeoutMs, 200);
    if (!agentFinalStreamProbe?.streamText) {
      throw new Error(`Agent final handoff did not stream as answer text: ${prompt.slice(0, 40)}`);
    }
    assertNotCannedDaemonProjection(agentFinalStreamProbe.streamText, prompt);
    assertNoDeterministicSourceLeak(agentFinalStreamProbe.streamText, prompt);
    if (options.capturePendingProjection && options.outputDir && options.screenshots) {
      await screenshot(page, options.outputDir, "agent-final-handoff-stream-live.png", options.screenshots).catch(() => {});
    }
    markPromptPhase(timing, "agent-final-stream-probe", phaseStartedAtMs, {
      observed: true,
      streamKind: agentFinalStreamProbe.streamKind,
    });
  }
  phaseStartedAtMs = Date.now();
  const completionTimeoutMs = !streamRequired && (streamProbe?.streamKind === "artifact_source" || options.requireConversationArtifactProof)
    ? Math.max(
      assistantVisibleTimeoutMs,
      Number(options.artifactCompletionTimeoutMs || options.agentArtifactCompletionTimeoutMs || 240_000),
    )
    : assistantVisibleTimeoutMs;
  const requiresCompletedStatus = streamRequired ||
    streamProbe?.streamKind === "artifact_source" ||
    Boolean(options.requireConversationArtifactProof) ||
    Boolean(options.requireCompletedStatus);
  const completed = await waitForPredicate(async () => {
    try {
      return await withStudioFrame(page, async (frame) => {
        const root = frame.locator('[data-testid="agent-studio-operational-chat"]').first();
        const status = await root.getAttribute("data-studio-status");
        const agentFinalHandoffComplete = (await root.getAttribute("data-agent-final-handoff-stream-complete")) === "true";
        const answerCount = await frame.locator('[data-testid="studio-assistant-answer-card"]').count();
        const documentedWorkCount = await frame.locator('[data-studio-turn-role="assistant"][data-documented-work="true"]').count();
        const finalizedAnswers = frame.locator('[data-testid="studio-assistant-answer-text"]');
        const finalizedAnswerCount = await finalizedAnswers.count();
        const streamingAnswers = frame.locator('[data-testid="studio-streaming-output"]');
        const streamingAnswerCount = await streamingAnswers.count();
        const finalizedTexts = finalizedAnswerCount > 0 ? await finalizedAnswers.allTextContents() : [];
        const streamingTexts = streamingAnswerCount > 0 ? await streamingAnswers.allTextContents() : [];
        const latestFinalizedAnswer = String(finalizedTexts[finalizedTexts.length - 1] || "").trim();
        const latestStreamingAnswer = String(streamingTexts[streamingTexts.length - 1] || "").trim();
        const expectedTermsAny = Array.isArray(options.mustMentionAny) ? options.mustMentionAny : [];
        const expectedTermsAll = Array.isArray(options.mustMentionAll) ? options.mustMentionAll : [];
        const matchesExpectedTerms = (value) => {
          const lower = String(value || "").toLowerCase();
          return expectedTermsAll.every((term) => lower.includes(String(term).toLowerCase())) &&
            (!expectedTermsAny.length || expectedTermsAny.some((term) => lower.includes(String(term).toLowerCase())));
        };
        const expectedAnswer = [...finalizedTexts, ...streamingTexts].map((text) => String(text || "").trim()).filter(Boolean).reverse().find(matchesExpectedTerms);
        const latestAnswer = expectedAnswer || latestFinalizedAnswer || latestStreamingAnswer;
        const answerMatchesPrompt = latestAnswer.length > 0 && assistantTextMatchesPrompt(prompt, latestAnswer);
        const latestAnswerKey = normalizeObservedAnswerText(latestAnswer);
        const answerTextIsNew = Boolean(latestAnswerKey) && !initialAnswerTextKeys.has(latestAnswerKey);
        const newAnswerVisible = answerMatchesPrompt && (answerCount > initialAssistantCount || answerTextIsNew);
        const streamCompletionObserved = Boolean(agentFinalStreamProbe?.streamText);
        const completionSatisfied = status === "completed" ||
          agentFinalHandoffComplete ||
          (!requiresCompletedStatus && streamCompletionObserved && newAnswerVisible);
        if (requiresCompletedStatus) {
          return completionSatisfied && (newAnswerVisible || answerMatchesPrompt)
            ? { status, answerCount, assistantText: latestAnswer, documentedWorkCount }
            : false;
        }
        return newAnswerVisible
          ? { status: status || "visible", answerCount, assistantText: latestAnswer, documentedWorkCount }
          : false;
      }, 3);
    } catch {
      return false;
    }
  }, completionTimeoutMs, 300);
  if (!completed) throw new Error(`Assistant response did not render for prompt: ${prompt.slice(0, 40)}`);
  markPromptPhase(timing, "assistant-visible", phaseStartedAtMs, { completionStatus: completed.status || "visible" });
  phaseStartedAtMs = Date.now();
  const assistantText = completed.assistantText || await latestAssistantText(page);
  markPromptPhase(timing, "assistant-text-read", phaseStartedAtMs, { assistantTextLength: assistantText.length });
  if (!assistantText) {
    throw new Error(`Assistant response text was empty for prompt: ${prompt.slice(0, 40)}`);
  }
  assertNotCannedDaemonProjection(assistantText, prompt);
  assertSemanticModelResponse(assistantText, prompt);
  assertNoDeterministicSourceLeak(assistantText, prompt);
  const markdownRenderProof = (options.requireMarkdownRenderProof || options.captureMarkdownRenderProof)
    ? await captureLatestMarkdownRenderProof(page)
    : null;
  if (options.requireMarkdownRenderProof) {
    const requiredMarkdownElements = Array.isArray(options.requiredMarkdownElements)
      ? options.requiredMarkdownElements
      : [];
    const missingMarkdownElements = requiredMarkdownElements.filter((element) =>
      markdownElementMissing(markdownRenderProof, element)
    );
    if (!markdownRenderProof?.observed || !markdownRenderProof?.markdownHydrated) {
      throw new Error(`Markdown proof did not observe hydrated assistant Markdown for prompt: ${prompt.slice(0, 40)}`);
    }
    if (markdownRenderProof.rawMarkdownSyntaxVisible) {
      throw new Error(`Markdown proof still sees raw Markdown syntax in product chat: ${markdownRenderProof.answerTextSample}`);
    }
    if (markdownRenderProof.overlappedByComposer) {
      throw new Error("Markdown answer is visually overlapped by the composer.");
    }
    if (missingMarkdownElements.length > 0) {
      throw new Error(`Markdown proof is missing rendered elements: ${missingMarkdownElements.join(", ")}`);
    }
  }
  const sourceRowsProof = (options.requireSourceRowsProof || options.captureSourceRowsProof)
    ? await captureLatestSourceRowsProof(page)
    : null;
  if (options.requireSourceRowsProof && (!sourceRowsProof?.observed || sourceRowsProof.sourceCount < 1)) {
    throw new Error(`Source proof did not observe product-facing source chips for prompt: ${prompt.slice(0, 40)}`);
  }
  timing.finishedAt = new Date().toISOString();
  timing.durationMs = Date.now() - startedAtMs;
  writePromptTiming(timingPath, timing);
  return {
    request,
    streamProbe,
    artifactSourceStreamObserved,
    assistantText,
    modelBackedStreamObserved: Boolean(
      streamProbe?.streamText ||
      streamProbe?.thinkingText ||
      agentFinalStreamProbe?.streamText
    ),
    agentFinalStreamObserved: agentFinalStreamRequired && Boolean(agentFinalStreamProbe?.streamText),
    executionMode,
    completionStatus: completed.status || "visible",
    newDocumentedWorkVisible: Number(completed.documentedWorkCount || 0) > initialDocumentedWorkCount,
    documentedWorkCount: Number(completed.documentedWorkCount || 0),
    durationMs: Date.now() - startedAtMs,
    pendingProjectionProof,
    markdownRenderProof,
    sourceRowsProof,
    timing,
  };
}

  return submitPrompt;
}

const DETERMINISTIC_SOURCE_LEAK_PATTERNS = [
  /https:\/\/example\.com\/crypto\/akt-price-today-2026/i,
  /https:\/\/example\.com\/crypto\/filecoin-price-today-2026/i,
  /https:\/\/example\.com\/akt-filecoin-comparison/i,
  /https:\/\/example\.com\/local-ai-runtime-issue/i,
  /https:\/\/www\.nist\.gov\/news-events\/news\/2026\/local-ai-model-runtime-issue/i,
  /\bedge:search:parity-fixture\b/i,
  /\bReliability Source \d+\b/i,
];

function assertNoDeterministicSourceLeak(text, prompt) {
  const matched = DETERMINISTIC_SOURCE_LEAK_PATTERNS.find((pattern) => pattern.test(text || ""));
  if (matched) {
    throw new Error(`Assistant response for "${prompt.slice(0, 40)}" leaked deterministic source evidence: ${matched}`);
  }
}
