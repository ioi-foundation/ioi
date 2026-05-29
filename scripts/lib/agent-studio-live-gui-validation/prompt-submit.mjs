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
  let phaseStartedAtMs = Date.now();
  const initialCounts = await withStudioFrame(page, async (frame) => ({
    assistantCount: await frame.locator('[data-testid="studio-assistant-answer-card"]').count(),
    documentedWorkCount: await frame.locator('[data-studio-turn-role="assistant"][data-documented-work="true"]').count(),
    streamOutputCount: await frame.locator('[data-testid="studio-streaming-output"]').count(),
    thinkingBlockCount: await frame.locator('[data-testid="studio-thinking-block"] p').count(),
    artifactSourceCount: await frame.locator('[data-testid="studio-artifact-source-output"]').count(),
  }));
  const initialAssistantCount = initialCounts.assistantCount;
  const initialDocumentedWorkCount = initialCounts.documentedWorkCount;
  const initialStreamOutputCount = initialCounts.streamOutputCount;
  const initialThinkingBlockCount = initialCounts.thinkingBlockCount;
  const initialArtifactSourceCount = initialCounts.artifactSourceCount;
  markPromptPhase(timing, "initial-assistant-count", phaseStartedAtMs, {
    initialAssistantCount,
    initialDocumentedWorkCount,
    initialStreamOutputCount,
    initialThinkingBlockCount,
  });
  phaseStartedAtMs = Date.now();
  await setComposerValue(page, prompt);
  markPromptPhase(timing, "set-composer-value", phaseStartedAtMs);
  phaseStartedAtMs = Date.now();
  if (mode === "keyboard") {
    await withStudioFrame(page, async (frame) => {
      const input = frame.locator('[data-testid="studio-composer-input"]').first();
      await input.focus();
      await input.press(process.platform === "darwin" ? "Meta+Enter" : "Control+Enter");
    });
  } else {
    await withStudioFrame(page, async (frame) => {
      await frame.locator('[data-testid="studio-send-button"]').click();
    });
  }
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
      throw new Error(`Prompt did not produce immediate user turn and pending state: ${prompt.slice(0, 40)}`);
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
  const request = requestFromPendingPhase || await requestPromise;
  if (request?.requestError) {
    throw request.requestError;
  }
  markPromptPhase(timing, "bridge-request-observed", phaseStartedAtMs);
  const executionMode = String(request?.payload?.executionMode || "").toLowerCase();
  const streamRequired = executionMode === "ask";
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
        const thinkingBlockCount = await thinkingBlocks.count();
        const artifactSourceCount = await artifactSources.count();
        const streamText = streamOutputCount > initialStreamOutputCount
          ? (await streamOutput.nth(streamOutputCount - 1).textContent({ timeout: 50 }).catch(() => "")).trim()
          : "";
        const thinkingText = thinkingBlockCount > initialThinkingBlockCount
          ? (await thinkingBlocks.nth(thinkingBlockCount - 1).textContent({ timeout: 50 }).catch(() => "")).trim()
          : "";
        const artifactSourceText = artifactSourceCount > initialArtifactSourceCount
          ? (await artifactSources.nth(artifactSourceCount - 1).textContent({ timeout: 50 }).catch(() => "")).trim()
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
        return null;
      }, 3);
    } catch {
      return null;
    }
  }, streamProbeTimeoutMs, 100);
  if (streamRequired && !streamProbe?.streamText && !streamProbe?.thinkingText) {
    throw new Error(`Prompt did not expose streamed assistant token deltas: ${prompt.slice(0, 40)}`);
  }
  if (streamProbe?.streamText) {
    assertNotCannedDaemonProjection(streamProbe.streamText, prompt);
    assertSemanticModelResponse(streamProbe.streamText, prompt);
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
  markPromptPhase(timing, "stream-probe", phaseStartedAtMs, {
    streamRequired,
    observed: Boolean(streamProbe?.streamText || streamProbe?.thinkingText),
    streamKind: streamProbe?.streamKind || null,
  });
  phaseStartedAtMs = Date.now();
  const completionTimeoutMs = !streamRequired && streamProbe?.streamKind === "artifact_source"
    ? Math.max(
      assistantVisibleTimeoutMs,
      Number(options.artifactCompletionTimeoutMs || options.agentArtifactCompletionTimeoutMs || 240_000),
    )
    : assistantVisibleTimeoutMs;
  const completed = await waitForPredicate(async () => {
    try {
      return await withStudioFrame(page, async (frame) => {
        const status = await frame.locator('[data-testid="agent-studio-operational-chat"]').first().getAttribute("data-studio-status");
        const answerCount = await frame.locator('[data-testid="studio-assistant-answer-card"]').count();
        const documentedWorkCount = await frame.locator('[data-studio-turn-role="assistant"][data-documented-work="true"]').count();
        const answerParagraphs = frame.locator('[data-testid="studio-assistant-answer-text"], [data-testid="studio-streaming-output"]');
        const answerParagraphCount = await answerParagraphs.count();
        const latestAnswer = answerParagraphCount > 0
          ? (await answerParagraphs.nth(answerParagraphCount - 1).textContent({ timeout: 50 }).catch(() => "")).trim()
          : "";
        const newAnswerVisible = answerCount > initialAssistantCount
          && latestAnswer.length > 0
          && assistantTextMatchesPrompt(prompt, latestAnswer);
        if (streamRequired) {
          return status === "completed" && newAnswerVisible
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
  timing.finishedAt = new Date().toISOString();
  timing.durationMs = Date.now() - startedAtMs;
  writePromptTiming(timingPath, timing);
  return {
    request,
    streamProbe,
    assistantText,
    modelBackedStreamObserved: Boolean(streamProbe?.streamText || streamProbe?.thinkingText),
    executionMode,
    completionStatus: completed.status || "visible",
    newDocumentedWorkVisible: Number(completed.documentedWorkCount || 0) > initialDocumentedWorkCount,
    documentedWorkCount: Number(completed.documentedWorkCount || 0),
    durationMs: Date.now() - startedAtMs,
    pendingProjectionProof,
    timing,
  };
}

  return submitPrompt;
}
