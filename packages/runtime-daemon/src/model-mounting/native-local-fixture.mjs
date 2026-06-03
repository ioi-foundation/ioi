import { nativeFixtureStaticWebsiteJson } from "./native-fixture-artifacts.mjs";
import {
  nativeFixtureConversationReply,
  nativeFixtureQueryNeedsCommand,
  nativeFixtureQueryNeedsUiInteraction,
  nativeFixtureQueryNeedsWeb,
  nativeFixtureQueryWorkspaceConstrained,
} from "./native-fixture-intent.mjs";
import { nativeFixtureRepoAwareResponse } from "./native-fixture-repo-aware.mjs";
import { nativeFixtureStage2WebRepairResponse } from "./native-fixture-stage2-web-repair.mjs";
import { nativeFixtureStage5StopHookRepairResponse } from "./native-fixture-stage5-stop-hook-repair.mjs";
import { stableHash } from "./io.mjs";

export function extractedUserQuery(inputStr) {
  const rawText = String(inputStr);
  const promptText = rawText.includes("\\n") || rawText.includes('\\"')
    ? rawText.replace(/\\n/g, "\n").replace(/\\"/g, '"')
    : rawText;

  const queryMatch = promptText.match(
    /(?:^|\n)(?:user:\s*)?Query:\n([\s\S]*?)(?:\n\n(?:Intents:|Return exactly one JSON object|Return JSON)|$)/i,
  );
  if (queryMatch?.[1]?.trim()) return queryMatch[1].trim();

  const requestMatch = promptText.match(
    /(?:^|\n)User request:\n([\s\S]*?)(?:\n\n(?:Resolved intent:|Required capabilities:|Provider selection state:|Return exactly one JSON object)|$)/i,
  );
  if (requestMatch?.[1]?.trim()) return requestMatch[1].trim();

  const latestRequestMatch = promptText.match(
    /(?:^|\n)Latest user request:\n([\s\S]*?)(?:\nFinal answer text:|$)/i,
  );
  if (latestRequestMatch?.[1]?.trim()) return latestRequestMatch[1].trim();

  const recentUserLines = [...promptText.matchAll(/(?:^|\n)user:\s*([^\n]+)/gi)]
    .map((match) => match[1].trim())
    .filter(Boolean);
  if (recentUserLines.length > 0) return recentUserLines.at(-1);

  const goalMatch = promptText.match(/(?:^|\n)- (?:Current Goal|Goal):\s*([^\n]+)/i);
  if (goalMatch?.[1]?.trim()) return goalMatch[1].trim();

  return rawText;
}

export function nativeFixtureCurrentTurnText(rawText, queryText) {
  const text = String(rawText || "");
  const query = String(queryText || "").trim();
  if (query) {
    const lowerText = text.toLowerCase();
    const lowerQuery = query.toLowerCase();
    const index = lowerText.lastIndexOf(lowerQuery);
    if (index >= 0) {
      return text.slice(index);
    }
  }
  const userMatches = [...text.matchAll(/(?:^|\n)\s*user:\s*/gi)];
  const latestUser = userMatches.at(-1);
  return latestUser ? text.slice(latestUser.index) : text;
}

export function nativeFixturePreReadSelection(inputStr) {
  if (
    !inputStr.includes("CEC State 3 (Typed Web Source Selection)") &&
    !inputStr.includes("Select URLs from the payload that best satisfy the typed retrieval contract")
  ) {
    return null;
  }

  const requiredUrlCount = Math.max(1, Number(inputStr.match(/"required_url_count"\s*:\s*(\d+)/)?.[1] ?? 1));
  const urls = [...inputStr.matchAll(/"url"\s*:\s*"([^"]+)"/g)]
    .map((match) => match[1])
    .filter((url, index, all) => /^https?:\/\//i.test(url) && all.indexOf(url) === index);
  const nonSearchHubUrls = urls.filter((url) => !/duckduckgo\.com|google\.com\/search/i.test(url));
  const selected = nonSearchHubUrls.slice(0, requiredUrlCount);

  return JSON.stringify({
    selection_mode: "direct_detail",
    urls: selected,
  });
}

export function nativeLocalOutput({ kind, input, modelId }) {
  const digest = stableHash(input).slice(0, 12);
  if (kind === "embeddings") return `native-local-embedding:${modelId}:${digest}`;

  const inputStr = String(input);
  const staticWebsiteJson = nativeFixtureStaticWebsiteJson(inputStr);
  if (staticWebsiteJson) return staticWebsiteJson;

  const queryText = extractedUserQuery(inputStr);
  const currentTurnText = nativeFixtureCurrentTurnText(inputStr, queryText);
  const promptContextText = `${queryText}\n${currentTurnText}`;
  const querySignalText = String(queryText || "").trim() || promptContextText;
  const expectsJsonToolCall =
    inputStr.includes("[AVAILABLE TOOLS]") ||
    inputStr.includes("Output EXACTLY ONE valid JSON tool call");
  const isSemanticScorePrompt =
    inputStr.includes("\"scores\"") &&
    inputStr.includes("\"intent_id\"") &&
    inputStr.includes("Score only semantic fit");
  const stage5StopHookToolPromptLikely =
    /\b(ARP_P0_007_PROOF_TOKEN|normalizeStatusLabel|status[-_\s]?labels?\.mjs)\b/i.test(inputStr) &&
    /\b(shell__run|chat__reply|file__edit|agent__complete|\[AVAILABLE TOOLS\]|available tools|tool calls?|next action|single tool)\b/i.test(inputStr);
  const hasToolCalled = (toolName) => {
    const lines = currentTurnText.split("\n");
    const escapedToolName = toolName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const structuredToolEvent = new RegExp(`\\btool\\.(?:started|completed|failed|result)\\b[\\s\\S]{0,500}\\b${escapedToolName}\\b`, "i");
    for (const line of lines) {
      const trimmedLine = line.trim();
      if (line.startsWith("assistant:") && line.includes(toolName)) {
        return true;
      }
      if (
        trimmedLine.startsWith("tool:") &&
        (
          trimmedLine.startsWith(`tool: ${toolName}`) ||
          trimmedLine.startsWith(`tool:${toolName}`) ||
          trimmedLine.includes(`name:${toolName}`) ||
          trimmedLine.includes(`"name":"${toolName}"`) ||
          trimmedLine.includes(`"name": "${toolName}"`) ||
          trimmedLine.includes(`Tool Output (${toolName})`)
        )
      ) {
        return true;
      }
    }
    return (
      structuredToolEvent.test(currentTurnText) ||
      new RegExp(`"tool"\\s*:\\s*"${escapedToolName}"`, "i").test(currentTurnText) ||
      new RegExp(`"tool_name"\\s*:\\s*"${escapedToolName}"`, "i").test(currentTurnText) ||
      new RegExp(`"toolName"\\s*:\\s*"${escapedToolName}"`, "i").test(currentTurnText)
    );
  };
  const jsonTool = (name, args) => JSON.stringify({ name, arguments: args });
  if (inputStr.includes("Classify the immediate next execution mode")) {
    const preferChat = /\b(humans|hello|hi|chat|conversation)\b/i.test(queryText);
    return JSON.stringify({
      mode: preferChat ? "Chat" : "Blind"
    });
  }

  const preReadSelection = nativeFixturePreReadSelection(inputStr);
  if (preReadSelection) {
    return preReadSelection;
  }

  if (
    inputStr.includes("remote_public_fact_required") &&
    inputStr.includes("host_local_clock_targeted") &&
    inputStr.includes("temporal_filesystem_filter")
  ) {
    const workspaceConstrained = nativeFixtureQueryWorkspaceConstrained(querySignalText);
    const commandDirected = nativeFixtureQueryNeedsCommand(querySignalText);
    const directUiInput = nativeFixtureQueryNeedsUiInteraction(querySignalText);
    const currentExternalFact = nativeFixtureQueryNeedsWeb(querySignalText) && !workspaceConstrained;
    return JSON.stringify({
      remote_public_fact_required: currentExternalFact,
      host_local_clock_targeted: false,
      command_directed: commandDirected,
      durable_automation_requested: false,
      model_registry_control_requested: false,
      app_launch_directed: false,
      direct_ui_input: directUiInput,
      desktop_screenshot_requested: false,
      temporal_filesystem_filter: false,
    });
  }

  if (!isSemanticScorePrompt || expectsJsonToolCall || stage5StopHookToolPromptLikely) {
    const stage5StopHookRepairResponse = nativeFixtureStage5StopHookRepairResponse({
      expectsJsonToolCall: expectsJsonToolCall || stage5StopHookToolPromptLikely,
      hasToolCalled,
      inputText: inputStr,
      jsonTool,
      promptContextText,
      queryText,
    });
    if (stage5StopHookRepairResponse) return stage5StopHookRepairResponse;
  }

  if (isSemanticScorePrompt) {
    const intentIds = [...new Set([...inputStr.matchAll(/"intent_id"\s*:\s*"([^"]+)"/g)].map((match) => match[1]))];
    const workspaceConstrained = nativeFixtureQueryWorkspaceConstrained(querySignalText);
    const preferCommand = nativeFixtureQueryNeedsCommand(querySignalText);
    const preferUi = nativeFixtureQueryNeedsUiInteraction(querySignalText) && !preferCommand;
    const preferWeb = nativeFixtureQueryNeedsWeb(querySignalText) && !workspaceConstrained;
    const preferWorkspace = workspaceConstrained && !preferWeb && !preferCommand && !preferUi;
    const preferConversation = /\b(humans|hello|hi|chat|conversation|thanks|thank you|how are you)\b/i.test(queryText) && !preferWeb && !preferWorkspace && !preferCommand && !preferUi;
    const isRustBridgeTest = /\b(Rust|RuntimeAgentService|bridge|KernelEvent|interrupt|validation|operator|cross-surface|react-flow)\b/i.test(querySignalText);
    const scores = intentIds.map((intentId) => {
      let score = isRustBridgeTest ? 0.0 : 0.05;
      if (preferCommand && intentId === "command.exec") score = 0.98;
      if (preferUi && intentId === "ui.interaction") score = 0.98;
      if (preferWeb && intentId === "web.research") score = 0.98;
      if (preferWorkspace && intentId === "workspace.ops") score = 0.94;
      if (preferConversation && intentId === "conversation.reply") score = 0.96;
      if (!preferWeb && !preferWorkspace && !preferConversation && !isRustBridgeTest && intentId === "conversation.reply") score = 0.7;
      return { intent_id: intentId, score };
    });
    return JSON.stringify({ scores });
  }

  const stage2WebRepairResponse = nativeFixtureStage2WebRepairResponse({
    expectsJsonToolCall,
    hasToolCalled,
    inputText: inputStr,
    jsonTool,
    promptContextText,
    queryText,
  });
  if (stage2WebRepairResponse) return stage2WebRepairResponse;

  const repoAwareResponse = nativeFixtureRepoAwareResponse({
    cwd: process.cwd(),
    expectsJsonToolCall:
      expectsJsonToolCall ||
      /\b(chat__reply|agent__complete|file__read|file__search)\b/i.test(inputStr),
    hasToolCalled,
    inputText: inputStr,
    promptContextText,
    queryText,
  });
  if (repoAwareResponse) return repoAwareResponse;

  if (nativeFixtureQueryNeedsWeb(promptContextText)) {
    if (!expectsJsonToolCall) {
      return "Fresh retrieval is required for current facts; I should not guess from stale model memory.";
    }
    if (hasToolCalled("chat__reply")) {
      return JSON.stringify({
        name: "agent__complete",
        arguments: {
          result: "Successfully completed currentness-gated retrieval."
        }
      });
    }
    if (hasToolCalled("web__read")) {
      return JSON.stringify({
        name: "chat__reply",
        arguments: {
          message: "Based on retrieved current sources, this answer is gated on fresh evidence about the local AI model runtime issue rather than stale model memory."
        }
      });
    }
    if (hasToolCalled("web__search")) {
      return JSON.stringify({
        name: "web__read",
        arguments: {
          url: "https://www.nist.gov/news-events/news/2026/local-ai-model-runtime-issue",
          max_chars: 1000,
          allow_browser_fallback: false
        }
      });
    }
    return JSON.stringify({
      name: "web__search",
      arguments: {
        query: queryText,
        limit: 5
      }
    });
  }

  if (queryText.includes("do you like humans?") || queryText.includes("humans")) {
    if (hasToolCalled("chat__reply")) {
      return JSON.stringify({
        name: "agent__complete",
        arguments: {
          result: "Done chatting about humans."
        }
      });
    }
    return JSON.stringify({
      name: "chat__reply",
      arguments: {
        message: "Yes, I like humans!"
      }
    });
  }

  if (!expectsJsonToolCall && modelId && String(modelId).startsWith("native:")) return "Autopilot native local model response";

  const conversationReply = nativeFixtureConversationReply(queryText);
  if (conversationReply) {
    if (!expectsJsonToolCall) {
      return conversationReply;
    }
    if (hasToolCalled("chat__reply")) {
      return JSON.stringify({
        name: "agent__complete",
        arguments: {
          result: "Conversational reply was delivered."
        }
      });
    }
    return JSON.stringify({
      name: "chat__reply",
      arguments: {
        message: conversationReply
      }
    });
  }

  const fallbackSurface = `${querySignalText}\n${inputStr}`;

  if (/\b(daemon|runtime authority|runtimeagentservice|bridge|electron workbench)\b/i.test(fallbackSurface)) {
    if (hasToolCalled("chat__reply")) {
      return JSON.stringify({
        name: "agent__complete",
        arguments: {
          result: "Runtime authority explanation was delivered."
        }
      });
    }
    return JSON.stringify({
      name: "chat__reply",
      arguments: {
        message: "The IOI daemon owns runtime authority so Electron stays a projection surface while governed sessions, policies, tool execution, and trace records remain in the daemon runtime."
      }
    });
  }

  if (/\b(repository|repo|workspace|project|codebase|source tree|inspect|file|files)\b/i.test(fallbackSurface)) {
    if (hasToolCalled("chat__reply")) {
      return JSON.stringify({
        name: "agent__complete",
        arguments: {
          result: "Workspace context was summarized."
        }
      });
    }
    return JSON.stringify({
      name: "chat__reply",
      arguments: {
        message: `You are in ${process.cwd()}. Studio should inspect the Agent Studio chat UX, runtime bridge wiring, and intent routing path first.`
      }
    });
  }

  // Fallback for any other prompt
  if (hasToolCalled("chat__reply")) {
    return JSON.stringify({
      name: "agent__complete",
      arguments: {
        result: "Task completed."
      }
    });
  }
  if (
    !expectsJsonToolCall &&
    (
      inputStr.toLowerCase().includes("native") ||
      inputStr.toLowerCase().includes("e2e")
    )
  ) {
    return "Autopilot native local model response";
  }
  return JSON.stringify({
    name: "chat__reply",
    arguments: {
      message: "Agent Studio is ready, daemon-routed, and waiting on the next governed instruction."
    }
  });
}

export function nativeLocalStreamRecords(outputText, tokenCount) {
  const text = String(outputText);
  const chunks = [];
  for (let offset = 0; offset < text.length; offset += 64) {
    chunks.push(text.slice(offset, offset + 64));
  }
  if (chunks.length === 0) chunks.push("");
  return [
    ...chunks.map((chunk) => ({ delta: chunk, done: false })),
    {
      delta: "",
      done: true,
      done_reason: "stop",
      prompt_eval_count: tokenCount.prompt_tokens,
      eval_count: tokenCount.completion_tokens,
    },
  ];
}

export function jsonLineReadableStream(records, { delayMs = 0, onAbort = null } = {}) {
  const encoder = new TextEncoder();
  const chunks = records.map((record) => encoder.encode(`${JSON.stringify(record)}\n`));
  let controllerRef = null;
  let timer = null;
  let closed = false;
  let abortRecorded = false;
  const clearTimer = () => {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  };
  const close = () => {
    if (closed) return;
    closed = true;
    clearTimer();
    try {
      controllerRef?.close();
    } catch {
      // The consumer may already have canceled the stream.
    }
  };
  const abort = (reason = "aborted") => {
    if (closed) return;
    if (!abortRecorded) {
      abortRecorded = true;
      onAbort?.(String(reason));
    }
    close();
  };
  const stream = new ReadableStream({
    start(controller) {
      controllerRef = controller;
      if (delayMs <= 0) {
        for (const chunk of chunks) {
          controller.enqueue(chunk);
        }
        close();
        return;
      }
      let index = 0;
      const pump = () => {
        if (closed) return;
        if (index >= chunks.length) {
          close();
          return;
        }
        try {
          controller.enqueue(chunks[index]);
        } catch {
          abort("enqueue_failed");
          return;
        }
        index += 1;
        if (index >= chunks.length) {
          close();
          return;
        }
        timer = setTimeout(pump, delayMs);
      };
      timer = setTimeout(pump, delayMs);
    },
    cancel(reason) {
      abort(reason ?? "consumer_cancel");
    },
  });
  return { stream, abort };
}

export function providerStreamFrameDelayMs() {
  const configured = Number(
    process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS ?? process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS ?? "",
  );
  if (Number.isFinite(configured) && configured >= 0) return Math.min(configured, 1000);
  return 0;
}
