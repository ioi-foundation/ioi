import { readFileSync, writeFileSync } from "node:fs";

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
      const chips = sourceRoot ? Array.from(sourceRoot.querySelectorAll(".studio-source-chip")) : [];
      const links = sourceRoot ? Array.from(sourceRoot.querySelectorAll("a[href]")) : [];
      return {
        observed: Boolean(sourceRoot),
        sourceCount: chips.length,
        linkCount: links.length,
        labels: chips.map((chip) => String(chip.textContent || "").replace(/\s+/g, " ").trim()).filter(Boolean),
        hrefs: links.map((link) => link.getAttribute("href") || "").filter(Boolean),
      };
    }));
  }

  async function waitForLatestSourceRowsProof(page, timeoutMs = 5000) {
    return waitForPredicate(async () => {
      const proof = await captureLatestSourceRowsProof(page);
      return proof?.observed && Number(proof.sourceCount || 0) > 0 ? proof : false;
    }, timeoutMs, 250).catch(async () => captureLatestSourceRowsProof(page));
  }

  async function captureVisiblePendingProof(page) {
    return withStudioFrame(page, async (frame) => frame.evaluate(() => {
      const visiblePending = Array.from(document.querySelectorAll('[data-testid="studio-pending-state"]'))
        .reverse()
        .find((node) => {
          if (!node || node.hasAttribute("hidden")) return false;
          const style = window.getComputedStyle(node);
          if (style.display === "none" || style.visibility === "hidden") return false;
          const rect = node.getBoundingClientRect();
          return rect.width > 0 && rect.height > 0;
        }) || null;
      const root = document.querySelector('[data-testid="agent-studio-operational-chat"]');
      const text = String(visiblePending?.textContent || "");
      return {
        visible: Boolean(visiblePending),
        rootStatus: root?.getAttribute("data-studio-status") || "",
        textSample: text.replace(/\s+/g, " ").trim().slice(0, 500),
        worklogCount: visiblePending
          ? visiblePending.querySelectorAll('[data-testid="studio-pending-worklog"] li').length
          : 0,
      };
    }));
  }

  async function waitForNoVisiblePendingAfterCompletion(page, timeoutMs = 1800) {
    await waitForPredicate(async () => {
      const proof = await captureVisiblePendingProof(page);
      return !proof?.visible ? proof : false;
    }, timeoutMs, 100).catch(() => null);
    return captureVisiblePendingProof(page);
  }

  async function captureLatestWorkLaneProof(page, options = {}) {
    const preOpen = await withStudioFrame(page, async (frame) => frame.evaluate(() => {
      const bars = Array.from(document.querySelectorAll("[data-testid='studio-run-status-bar']"));
      const bar = bars[bars.length - 1] || null;
      const summary = bar?.querySelector?.("summary") || null;
      const summaryStrong = summary?.querySelector?.("strong") || null;
      const extraSummarySpanCount = summary
        ? Array.from(summary.querySelectorAll("span")).filter((node) => !node.classList.contains("studio-run-status-bar__check")).length
        : 0;
      return {
        observed: Boolean(bar),
        wasOpen: Boolean(bar?.hasAttribute?.("open")),
        collapsedHeadline: String(summaryStrong?.textContent || "").replace(/\s+/g, " ").trim(),
        extraSummarySpanCount,
      };
    }));
    if (!preOpen?.observed) {
      return { observed: false, reason: "missing-work-status-bar" };
    }
    await withStudioFrame(page, async (frame) => {
      const bars = frame.locator('[data-testid="studio-run-status-bar"]');
      const count = await bars.count();
      if (count < 1) return;
      const bar = bars.nth(count - 1);
      const open = await bar.evaluate((node) => node.hasAttribute("open")).catch(() => false);
      if (!open) {
        await bar.evaluate((node) => {
          const summary = node.querySelector(":scope > summary");
          summary?.click?.();
        });
      }
    });
    if (options.outputDir && options.screenshots) {
      const indexPart = Number.isFinite(Number(options.promptIndex))
        ? String(Number(options.promptIndex)).padStart(2, "0")
        : "latest";
      await screenshot(page, options.outputDir, `work-lane-expanded-${indexPart}.png`, options.screenshots).catch(() => {});
    }
    const expanded = await withStudioFrame(page, async (frame) => frame.evaluate(() => {
      const bars = Array.from(document.querySelectorAll("[data-testid='studio-run-status-bar']"));
      const bar = bars[bars.length - 1] || null;
      const rows = bar ? Array.from(bar.querySelectorAll(
        ".studio-work-row, .studio-command-work-row, .studio-diff-hunk, .studio-managed-session-card, .studio-conversation-artifact-card",
      )) : [];
      const chips = bar ? Array.from(bar.querySelectorAll(".studio-source-chip")) : [];
      const excerpts = bar ? Array.from(bar.querySelectorAll(
        ".studio-work-row__excerpt, .studio-pending-step__excerpt, [data-testid='studio-command-stdout'], [data-testid='studio-command-stderr']",
      )) : [];
      const text = String(bar?.textContent || "");
      const rawLeakPatterns = [
        /\breceipt_[a-z0-9_]+/i,
        /\breq_[a-z0-9-]+/i,
        /\{\\?"(?:payload|event|receipt|trace|tool_name)\\?"/i,
        /\/home\/[^<\s]+/i,
        /\bTOOLCAT_/i,
        /\binput_hash=/i,
        /\blocal:auto\b/i,
        /\bautopilot:native-fixture\b/i,
      ];
      return {
        rowCount: rows.length,
        sourceChipCount: chips.length,
        excerptCount: excerpts.length,
        rowLabels: rows.map((row) => String(row.querySelector("summary strong, header strong, strong")?.textContent || "").replace(/\s+/g, " ").trim()).filter(Boolean),
        sourceLabels: chips.map((chip) => String(chip.textContent || "").replace(/\s+/g, " ").trim()).filter(Boolean).slice(0, 8),
        excerptSamples: excerpts.map((node) => String(node.textContent || "").replace(/\s+/g, " ").trim()).filter(Boolean).slice(0, 4),
        rawLeaks: rawLeakPatterns.filter((pattern) => pattern.test(text)).map(String),
      };
    }));
    return {
      ...preOpen,
      ...expanded,
      collapsedMinimal: /^Worked for \S+/.test(preOpen.collapsedHeadline || "") && Number(preOpen.extraSummarySpanCount || 0) === 0,
      openedForProof: true,
    };
  }

  async function captureLatestHunkReviewProof(page, options = {}) {
    await withStudioFrame(page, async (frame) => frame.evaluate(() => {
      const bars = Array.from(document.querySelectorAll("[data-testid='studio-run-status-bar']"));
      for (const bar of bars) {
        bar.open = true;
        bar.setAttribute("open", "");
      }
      const drawer = document.querySelector("[data-testid='studio-utility-drawer']");
      if (drawer) {
        drawer.classList.add("is-expanded");
        drawer.setAttribute("aria-expanded", "true");
      }
    })).catch(() => {});
    const proof = await withStudioFrame(page, async (frame) => frame.evaluate(() => {
      const hunks = Array.from(document.querySelectorAll('[data-testid="studio-inline-diff-hunks"]'));
      const latest = hunks[hunks.length - 1] || null;
      const text = String(latest?.textContent || "");
      const buttons = latest ? Array.from(latest.querySelectorAll("[data-studio-hunk-decision]")) : [];
      const buttonStates = buttons.map((button) => ({
        action: button.getAttribute("data-studio-hunk-decision") || "",
        text: String(button.textContent || "").replace(/\s+/g, " ").trim(),
        disabled: Boolean(button.disabled || button.getAttribute("aria-disabled") === "true"),
        bound: button.getAttribute("data-studio-hunk-decision-bound") || "",
        approvalId: button.getAttribute("data-approval-id") || "",
        changeId: button.getAttribute("data-change-id") || "",
      })).filter((button) => button.action);
      const rawLeakPatterns = [
        /\breceipt_[a-z0-9_]+/i,
        /\breq_[a-z0-9-]+/i,
        /\{\\?"(?:payload|event|receipt|trace|tool_name|hunks)\\?"/i,
        /\/home\/[^<\s]+/i,
        /\bTOOLCAT_/i,
      ];
      return {
        observed: Boolean(latest),
        hunkCount: hunks.length,
        decisionObserved: document.body?.dataset?.studioHunkDecisionObserved === "true",
        decisionLast: document.body?.dataset?.studioHunkDecisionLast || "",
        decisionBoundCount: Number(document.body?.dataset?.studioHunkDecisionBoundCount || 0) || 0,
        status: String(latest?.querySelector("mark")?.textContent || "").replace(/\s+/g, " ").trim(),
        file: String(latest?.querySelector("code")?.textContent || "").replace(/\s+/g, " ").trim(),
        buttonActions: buttonStates.map((button) => button.action),
        buttonStates,
        approvalId: buttonStates.find((button) => button.approvalId)?.approvalId || "",
        changeId: buttonStates.find((button) => button.changeId)?.changeId || "",
        stale: /\bstale\b/i.test(text),
        acceptAvailable: buttonStates.some((button) => button.action === "approve" && !button.disabled),
        rejectAvailable: buttonStates.some((button) => button.action === "reject" && !button.disabled),
        rollbackAvailable: buttonStates.some((button) => button.action === "rollback" && !button.disabled),
        hasBeforeAfter: Boolean(latest?.querySelector(".studio-diff-remove")?.textContent || latest?.querySelector(".studio-diff-add")?.textContent),
        rawLeaks: rawLeakPatterns.filter((pattern) => pattern.test(text)).map(String),
        textSample: text.replace(/\s+/g, " ").trim().slice(0, 600),
      };
    }));
    const probePath = String(options.hunkStateProbePath || "").trim();
    if (probePath) {
      proof.probe = {
        path: probePath,
        exists: false,
        bytes: 0,
        sample: "",
        error: null,
      };
      try {
        const probeContent = readFileSync(probePath, "utf8");
        proof.probe.exists = true;
        proof.probe.bytes = Buffer.byteLength(probeContent);
        proof.probe.sample = probeContent.slice(0, 1000);
      } catch (error) {
        proof.probe.error = error?.message || String(error);
      }
    }
    if (options.outputDir && options.screenshots) {
      const indexPart = Number.isFinite(Number(options.promptIndex))
        ? String(Number(options.promptIndex)).padStart(2, "0")
        : "latest";
      await screenshot(page, options.outputDir, `hunk-review-${indexPart}.png`, options.screenshots).catch(() => {});
    }
    return proof;
  }

  function applyHunkStaleMutation(options = {}) {
    const mutation = options.hunkStaleMutation;
    const path = String(mutation?.path || "").trim();
    if (!path) return null;
    const original = readFileSync(path, "utf8");
    const replacement = mutation.replaceText !== undefined
      ? String(mutation.replaceText)
      : [
          "export function formatOrderTotal(cents) {",
          "  return `externally-changed-${Number(cents)}`;",
          "}",
          "",
        ].join("\n");
    let next = replacement;
    if (mutation.mode === "replaceBoundary") {
      const search = String(mutation.searchText || "return (Number(cents) / 100).toFixed(2);");
      next = original.includes(search)
        ? original.replace(search, String(mutation.replaceText || "return `externally-changed-${Number(cents)}`;"))
        : `${original}\n// externally changed by hunk stale proof\n`;
    } else if (mutation.mode === "append") {
      next = `${original}${String(mutation.appendText || "\n// externally changed by hunk stale proof\n")}`;
    }
    writeFileSync(path, next);
    return {
      path,
      mode: mutation.mode || "write",
      originalBytes: Buffer.byteLength(original),
      nextBytes: Buffer.byteLength(next),
      changed: original !== next,
    };
  }

  async function refreshLatestHunkReviewProjection(page, options = {}) {
    await withStudioFrame(page, async (frame) => {
      const nav = frame.locator("[data-studio-hunk-nav]").first();
      if (await nav.count()) {
        await nav.click({ timeout: 3000 }).catch(() => {});
      }
    }).catch(() => {});
    const desired = String(options.expectStatus || "").trim().toLowerCase();
    if (!desired) {
      await wait(500);
      return captureLatestHunkReviewProof(page, options);
    }
    return waitForPredicate(async () => {
      const proof = await captureLatestHunkReviewProof(page, options).catch(() => null);
      const status = String(proof?.status || "").toLowerCase();
      const text = String(proof?.textSample || "").toLowerCase();
      return proof?.observed && (status.includes(desired) || text.includes(desired)) ? proof : false;
    }, Number(options.hunkRefreshTimeoutMs || 12000), 250).catch(async () =>
      captureLatestHunkReviewProof(page, options)
    );
  }

  async function performLatestHunkDecision(page, action, options = {}) {
    const normalizedAction = String(action || "").trim().toLowerCase();
    if (!normalizedAction) return null;
    const before = await captureLatestHunkReviewProof(page, options);
    const clickResult = await withStudioFrame(page, async (frame) => {
      const buttons = frame.locator(`[data-testid="studio-inline-diff-hunks"] [data-studio-hunk-decision="${normalizedAction}"]`);
      const count = await buttons.count();
      if (count < 1) {
        return { clicked: false, reason: `missing-${normalizedAction}-button` };
      }
      await buttons.nth(count - 1).click({ timeout: 5000 });
      return { clicked: true };
    });
    let dispatchFallback = null;
    await wait(250);
    const observedAfterClick = await captureLatestHunkReviewProof(page, options).catch(() => null);
    if (clickResult?.clicked && !observedAfterClick?.decisionObserved) {
      dispatchFallback = await withStudioFrame(page, async (frame) => frame.evaluate((targetAction) => {
        const buttons = Array.from(document.querySelectorAll(
          `[data-testid="studio-inline-diff-hunks"] [data-studio-hunk-decision="${targetAction}"]`,
        ));
        const button = buttons[buttons.length - 1] || null;
        if (!button) {
          return { dispatched: false, reason: `missing-${targetAction}-button` };
        }
        button.dispatchEvent(new MouseEvent("click", {
          bubbles: true,
          cancelable: true,
          composed: true,
          view: window,
        }));
        return {
          dispatched: true,
          observed: document.body?.dataset?.studioHunkDecisionObserved === "true",
          last: document.body?.dataset?.studioHunkDecisionLast || "",
        };
      }, normalizedAction)).catch((error) => ({
        dispatched: false,
        reason: error?.message || String(error),
      }));
    }
    const afterMatch = await waitForPredicate(async () => {
      const proof = await captureLatestHunkReviewProof(page, options).catch(() => null);
      const status = String(proof?.status || "").toLowerCase();
      const text = String(proof?.textSample || "").toLowerCase();
      if (!proof?.observed) return false;
      if (
        normalizedAction === "approve" &&
        (
          status.includes("approved") ||
          status.includes("accepted") ||
          status.includes("applied") ||
          text.includes("approved") ||
          text.includes("accepted") ||
          text.includes("applied")
        )
      ) return proof;
      if (normalizedAction === "reject" && (status.includes("rejected") || text.includes("rejected"))) return proof;
      if (normalizedAction === "rollback" && (status.includes("rolled") || text.includes("rolled"))) return proof;
      return false;
    }, Number(options.hunkDecisionTimeoutMs || 12000), 250).catch(() => false);
    const after = afterMatch || await captureLatestHunkReviewProof(page, options).catch(() => false);
    if (options.outputDir && options.screenshots) {
      const indexPart = Number.isFinite(Number(options.promptIndex))
        ? String(Number(options.promptIndex)).padStart(2, "0")
        : "latest";
      await screenshot(page, options.outputDir, `hunk-decision-${normalizedAction}-${indexPart}.png`, options.screenshots).catch(() => {});
    }
    return {
      action: normalizedAction,
      ...clickResult,
      dispatchFallback,
      before,
      after,
    };
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
    const captureVisiblePendingProjectionProof = async () => withStudioFrame(page, async (frame) => frame.evaluate((args) => {
      const visiblePending = Array.from(document.querySelectorAll('[data-testid="studio-pending-state"]'))
        .reverse()
        .find((node) => {
          if (!node || node.hasAttribute("hidden")) return false;
          const style = window.getComputedStyle(node);
          if (style.display === "none" || style.visibility === "hidden") return false;
          const rect = node.getBoundingClientRect();
          return rect.width > 0 && rect.height > 0;
        }) || null;
      const root = document.querySelector('[data-testid="agent-studio-operational-chat"]');
      const streamOutputs = Array.from(document.querySelectorAll('[data-testid="studio-streaming-output"]'));
      const artifactSources = Array.from(document.querySelectorAll('[data-testid="studio-artifact-source-output"]'));
      const answerCards = Array.from(document.querySelectorAll('[data-testid="studio-assistant-answer-card"]'));
      const pendingText = String(visiblePending?.textContent || "");
      const worklogItems = visiblePending
        ? Array.from(visiblePending.querySelectorAll('[data-testid="studio-pending-worklog"] li'))
        : [];
      const progressTagCount = visiblePending
        ? visiblePending.querySelectorAll('[data-testid="studio-pending-progress"], [data-studio-pending-step]').length
        : 0;
      const streamOutputCount = streamOutputs.length;
      const artifactSourceCount = artifactSources.length;
      const answerCount = answerCards.length;
      const latestStream = streamOutputCount > args.initialStreamOutputCount
        ? streamOutputs[streamOutputCount - 1]
        : null;
      const latestArtifactSource = artifactSourceCount > args.initialArtifactSourceCount
        ? artifactSources[artifactSourceCount - 1]
        : null;
      const rootStatus = root?.getAttribute("data-studio-status") || "";
      const observed = Boolean(visiblePending) ||
        worklogItems.length > 0 ||
        artifactSourceCount > args.initialArtifactSourceCount ||
        (
          args.expectedExecutionMode === "ask" && (
            streamOutputCount > args.initialStreamOutputCount ||
            answerCount > args.initialAssistantCount ||
            rootStatus === "streaming" ||
            rootStatus === "completed"
          )
        );
      return {
        observed,
        visiblePendingObserved: Boolean(visiblePending),
        textSample: pendingText.replace(/\s+/g, " ").trim().slice(0, 500),
        progressTagCount,
        worklogCount: worklogItems.length,
        worklogTextSample: worklogItems.map((node) => String(node.textContent || "").replace(/\s+/g, " ").trim()).filter(Boolean).join(" | ").slice(0, 500),
        streamOutputCount,
        artifactSourceCount,
        answerCount,
        rootStatus,
        streamTextSample: String(latestStream?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 500),
        artifactSourceSample: String(latestArtifactSource?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 500),
        hasForbiddenTags: /\bUsing tools\b|\bPreparing response\b/.test(pendingText) || progressTagCount > 0,
      };
    }, {
      expectedExecutionMode,
      initialAssistantCount,
      initialStreamOutputCount,
      initialArtifactSourceCount,
    }));
    const requiredPendingWorklogTextAny = Array.isArray(options.requirePendingWorklogTextAny)
      ? options.requirePendingWorklogTextAny.map((value) => String(value || "").trim()).filter(Boolean)
      : [];
    const requiredPendingWorklogTextAll = Array.isArray(options.requirePendingWorklogTextAll)
      ? options.requirePendingWorklogTextAll.map((value) => String(value || "").trim()).filter(Boolean)
      : [];
    const pendingWorklogMatchesTextRequirement = (proof) => {
      if (!requiredPendingWorklogTextAny.length && !requiredPendingWorklogTextAll.length) return true;
      const haystack = `${proof?.textSample || ""}\n${proof?.worklogTextSample || ""}`.toLowerCase();
      const anyMatched = !requiredPendingWorklogTextAny.length ||
        requiredPendingWorklogTextAny.some((needle) => haystack.includes(needle.toLowerCase()));
      const allMatched = !requiredPendingWorklogTextAll.length ||
        requiredPendingWorklogTextAll.every((needle) => haystack.includes(needle.toLowerCase()));
      return anyMatched && allMatched;
    };
    await waitForPredicate(async () => {
      try {
        const proof = await captureVisiblePendingProjectionProof();
        if (expectedExecutionMode === "ask") {
          return proof?.visiblePendingObserved ||
            proof?.streamOutputCount > initialStreamOutputCount ||
            proof?.answerCount > initialAssistantCount;
        }
        const observedWork = proof?.worklogCount > 0 || proof?.artifactSourceCount > initialArtifactSourceCount;
        return observedWork && pendingWorklogMatchesTextRequirement(proof);
      } catch {
        return false;
      }
    }, Number(options.pendingWorklogTimeoutMs || 12000), 100).catch(() => false);
    pendingProjectionProof = await captureVisiblePendingProjectionProof().catch(() => null);
    await screenshot(page, options.outputDir, "pending-worklog-live.png", options.screenshots).catch(() => {});
    if (pendingProjectionProof?.hasForbiddenTags) {
      throw new Error(`Pending worklog still exposes scaffold tags: ${pendingProjectionProof.textSample}`);
    }
    if (options.requirePendingWorklog && expectedExecutionMode !== "ask" && !pendingProjectionProof?.worklogCount) {
      throw new Error("Pending worklog proof did not capture a concrete live tool row.");
    }
    if (options.requirePendingWorklog && expectedExecutionMode !== "ask" && !pendingWorklogMatchesTextRequirement(pendingProjectionProof)) {
      throw new Error(`Pending worklog proof did not include required live row text: ${[...requiredPendingWorklogTextAll, ...requiredPendingWorklogTextAny].join(" | ")}`);
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
                assistantTextMatchesPrompt(prompt, latestText) &&
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
          return completionSatisfied && newAnswerVisible
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
    ? await waitForLatestSourceRowsProof(page)
    : null;
  if (options.requireSourceRowsProof && (!sourceRowsProof?.observed || sourceRowsProof.sourceCount < 1)) {
    throw new Error(`Source proof did not observe product-facing source chips for prompt: ${prompt.slice(0, 40)}`);
  }
  const workLaneProof = (options.requireGlassBoxWorkLaneProof || options.captureGlassBoxWorkLaneProof)
    ? await captureLatestWorkLaneProof(page, options)
    : null;
  if (options.requireGlassBoxWorkLaneProof) {
    if (!workLaneProof?.observed) {
      throw new Error(`Work lane proof did not observe a completed work bar for prompt: ${prompt.slice(0, 40)}`);
    }
    if (!workLaneProof.collapsedMinimal) {
      throw new Error(`Work lane collapsed summary is not minimal: ${JSON.stringify(workLaneProof)}`);
    }
    if (Number(workLaneProof.rowCount || 0) < 1) {
      throw new Error(`Work lane proof did not observe expanded chronological rows for prompt: ${prompt.slice(0, 40)}`);
    }
    if (Array.isArray(workLaneProof.rawLeaks) && workLaneProof.rawLeaks.length > 0) {
      throw new Error(`Work lane leaked raw runtime details: ${workLaneProof.rawLeaks.join(", ")}`);
    }
    const arrayValue = (value) => Array.isArray(value) ? value : [];
    const excerptText = [
      ...arrayValue(workLaneProof.excerptSamples),
      ...arrayValue(workLaneProof.rowLabels),
    ].join("\n");
    for (const requiredText of arrayValue(options.requireWorkLaneExcerptTextAll)) {
      if (!excerptText.includes(requiredText)) {
        throw new Error(`Work lane proof did not include required excerpt ${JSON.stringify(requiredText)}: ${JSON.stringify(workLaneProof)}`);
      }
    }
  }
  const noPendingAfterCompletionProof = (options.requireNoPendingAfterCompletion || options.captureNoPendingAfterCompletion)
    ? await waitForNoVisiblePendingAfterCompletion(page, Number(options.noPendingAfterCompletionTimeoutMs || 1800))
    : null;
  if (options.requireNoPendingAfterCompletion && noPendingAfterCompletionProof?.visible) {
    throw new Error(`Completed answer still has a visible pending block: ${JSON.stringify(noPendingAfterCompletionProof)}`);
  }
  let hunkReviewProof = (options.requireHunkReviewProof || options.captureHunkReviewProof)
    ? await captureLatestHunkReviewProof(page, options)
    : null;
  if (options.requireHunkReviewProof) {
    if (!hunkReviewProof?.observed) {
      throw new Error(`Hunk review proof did not observe an inline diff hunk for prompt: ${prompt.slice(0, 40)}`);
    }
    if (!hunkReviewProof.hasBeforeAfter) {
      throw new Error(`Hunk review proof did not include before/after material: ${JSON.stringify(hunkReviewProof)}`);
    }
    if (!hunkReviewProof.buttonActions?.length) {
      throw new Error(`Hunk review proof did not expose any hunk action buttons: ${JSON.stringify(hunkReviewProof)}`);
    }
    if (Array.isArray(hunkReviewProof.rawLeaks) && hunkReviewProof.rawLeaks.length > 0) {
      throw new Error(`Hunk review leaked raw runtime details: ${hunkReviewProof.rawLeaks.join(", ")}`);
    }
  }
  const hunkStaleMutationProof = options.hunkStaleMutation
    ? applyHunkStaleMutation(options)
    : null;
  if (hunkStaleMutationProof) {
    hunkReviewProof = await refreshLatestHunkReviewProjection(page, {
      ...options,
      expectStatus: options.requireHunkStaleProof ? "stale" : "",
    });
    if (options.outputDir && options.screenshots) {
      const indexPart = Number.isFinite(Number(options.promptIndex))
        ? String(Number(options.promptIndex)).padStart(2, "0")
        : "latest";
      await screenshot(page, options.outputDir, `hunk-stale-refresh-${indexPart}.png`, options.screenshots).catch(() => {});
    }
    if (options.requireHunkStaleProof && !hunkReviewProof?.stale) {
      throw new Error(`Hunk stale proof did not render stale review state: ${JSON.stringify(hunkReviewProof)}`);
    }
  }
  const hunkDecisionProof = options.hunkDecisionAction
    ? await performLatestHunkDecision(page, options.hunkDecisionAction, options)
    : null;
  if (options.requireHunkDecisionProof) {
    if (!hunkDecisionProof?.clicked) {
      throw new Error(`Hunk decision proof did not click ${options.hunkDecisionAction}: ${JSON.stringify(hunkDecisionProof)}`);
    }
    const afterText = `${hunkDecisionProof?.after?.status || ""} ${hunkDecisionProof?.after?.textSample || ""}`.toLowerCase();
    const expected = String(options.hunkDecisionAction || "").toLowerCase();
    if (
      expected === "approve" &&
      !afterText.includes("approved") &&
      !afterText.includes("accepted") &&
      !afterText.includes("applied")
    ) {
      throw new Error(`Hunk approve proof did not render an accepted/applied state: ${JSON.stringify(hunkDecisionProof)}`);
    }
    if (expected === "reject" && !afterText.includes("rejected")) {
      throw new Error(`Hunk reject proof did not render rejected state: ${JSON.stringify(hunkDecisionProof)}`);
    }
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
    workLaneProof,
    noPendingAfterCompletionProof,
    hunkReviewProof,
    hunkDecisionProof,
    hunkStaleMutationProof,
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
