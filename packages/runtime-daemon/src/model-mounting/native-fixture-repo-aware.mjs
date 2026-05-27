const DEFAULT_PROGRESS_GUIDE =
  ".internal/plans/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus-12h-master-guide.md";

import { nativeFixtureToolCatalogueResponse } from "./native-fixture-tool-catalogue.mjs";

const KNOWN_REPO_PROMPTS = [
  "What does progress look like per .internal/plans/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus-12h-master-guide.md?",
  "Where are local/native model providers registered in this repo?",
  "Explain how Agent Studio decides between Ask and Agent mode in this repo.",
  "Summarize risks in the Stage4 non-browser tool-history fix in this repo.",
  "Propose the smallest patch in this repo if file tool observations lose tool identity again.",
  "List the focused tests in this repo for the Stage4 tool-history fix.",
  "Run `node --check scripts/lib/autopilot-agent-studio-chat-scenarios.mjs` and summarize the exit code.",
  "Run `cargo test -q -p ioi-services --lib non_browser_tool_history_is_prefixed_for_next_model_turn` and summarize the exit code.",
  "Run `cargo test -q -p ioi-services --lib tool_history_prefix_is_not_duplicated` and summarize the exit code.",
  "Run `bash -lc 'touch /tmp/ioi-stage67-policy-denied'` and summarize whether the daemon allowed or blocked it.",
  "Run `node --version` after the blocked command and summarize the exit code.",
  "Try to read `/etc/passwd` through the governed file tool and summarize whether the daemon blocks it.",
  "Run a governed shell probe that checks whether IOI_STAGE72_SECRET_TOKEN is visible to subprocesses, and summarize whether the daemon strips it.",
  "Try to read `.autopilot-stage73-outside-link` through the governed file tool and summarize whether the daemon blocks the symlink escape.",
  "Review autopilot plan progress now that Stage75 is documented; what remains?",
];

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const KNOWN_REPO_PROMPT_PATTERN = new RegExp(KNOWN_REPO_PROMPTS.map(escapeRegExp).join("|"), "g");

function jsonTool(name, args) {
  return JSON.stringify({ name, arguments: args });
}

function extractedPlanPath(queryText) {
  const match = String(queryText || "").match(/\.internal\/plans\/[A-Za-z0-9._-]+\.md/);
  return match?.[0] ?? DEFAULT_PROGRESS_GUIDE;
}

function isProgressGuideQuery(queryText) {
  const text = String(queryText || "");
  return /\.internal\/plans\/[A-Za-z0-9._-]+\.md/.test(text) || /\b(plan progress|progress look|progress per|review autopilot plan progress)\b/i.test(text);
}

function isProviderRegistrationQuery(queryText) {
  return /\b(local|native)\b/i.test(queryText) && /\bproviders?\b/i.test(queryText) && /\b(registered|registration|where|how)\b/i.test(queryText);
}

function isAskAgentModeQuery(queryText) {
  return /\bAsk\b/i.test(queryText) && /\bAgent\b/i.test(queryText) && /\b(mode|decides|separation|executionMode)\b/i.test(queryText);
}

function isStage5ToolHistoryReviewQuery(queryText) {
  return /\b(review|summarize risks?|risk summary)\b/i.test(queryText) && /\bStage\s*4\b/i.test(queryText) && /\btool-history|tool history|non-browser\b/i.test(queryText);
}

function isStage5ToolHistoryPatchQuery(queryText) {
  return /\b(propose|smallest patch|patch)\b/i.test(queryText) && /\bfile tool observations?|tool identity|tool-history|tool history\b/i.test(queryText);
}

function isStage5ToolHistoryTestQuery(queryText) {
  return /\b(confirm|list|focused tests?|test)\b/i.test(queryText) && /\bStage\s*4\b/i.test(queryText) && /\btool-history|tool history\b/i.test(queryText);
}

function isStage8FileBoundaryReadQuery(queryText) {
  return /\/etc\/passwd\b/i.test(queryText) && /\b(file__read|file tool|governed file tool|read)\b/i.test(queryText);
}

function isStage9SanitizedEnvQuery(queryText) {
  return (
    /\bIOI_STAGE72_SECRET_TOKEN\b/i.test(queryText) &&
    /\b(env|environment|subprocess|shell|strips?|saniti[sz]e)\b/i.test(queryText)
  );
}

function isStage10SymlinkBoundaryReadQuery(queryText) {
  return (
    /\.autopilot-stage73-outside-link\b/i.test(queryText) &&
    /\b(file__read|file tool|governed file tool|read|symlink)\b/i.test(queryText)
  );
}

function stage6ShellTestCommandForQuery(queryText) {
  const text = String(queryText || "");
  if (/node\s+--check\s+scripts\/lib\/autopilot-agent-studio-chat-scenarios\.mjs/i.test(text)) {
    return {
      label: "node --check scripts/lib/autopilot-agent-studio-chat-scenarios.mjs",
      command: "node",
      args: ["--check", "scripts/lib/autopilot-agent-studio-chat-scenarios.mjs"],
      summary:
        "shell__run completed `node --check scripts/lib/autopilot-agent-studio-chat-scenarios.mjs` with exit code 0. The Stage 6 quick shell probe passed before moving to focused Rust tests.",
    };
  }
  if (/non_browser_tool_history_is_prefixed_for_next_model_turn/i.test(text)) {
    return {
      label: "cargo test -q -p ioi-services --lib non_browser_tool_history_is_prefixed_for_next_model_turn",
      command: "cargo",
      args: [
        "test",
        "-q",
        "-p",
        "ioi-services",
        "--lib",
        "non_browser_tool_history_is_prefixed_for_next_model_turn",
      ],
      summary:
        "shell__run completed `cargo test -q -p ioi-services --lib non_browser_tool_history_is_prefixed_for_next_model_turn` with exit code 0. The focused non-browser tool-history prefix test passed.",
    };
  }
  if (/tool_history_prefix_is_not_duplicated/i.test(text)) {
    return {
      label: "cargo test -q -p ioi-services --lib tool_history_prefix_is_not_duplicated",
      command: "cargo",
      args: [
        "test",
        "-q",
        "-p",
        "ioi-services",
        "--lib",
        "tool_history_prefix_is_not_duplicated",
      ],
      summary:
        "shell__run completed `cargo test -q -p ioi-services --lib tool_history_prefix_is_not_duplicated` with exit code 0. The browser-prefix duplicate guard test passed.",
    };
  }
  return null;
}

function stage9SanitizedEnvCommandForQuery(queryText) {
  if (!isStage9SanitizedEnvQuery(queryText)) return null;
  return {
    label: "node -e <IOI_STAGE72_SECRET_TOKEN visibility probe>",
    command: "node",
    args: [
      "-e",
      "const value = process.env.IOI_STAGE72_SECRET_TOKEN; console.log(value === undefined ? 'IOI_STAGE72_SECRET_TOKEN=absent' : 'IOI_STAGE72_SECRET_TOKEN=present:' + value);",
    ],
  };
}

function stage7ShellPolicyCommandForQuery(queryText) {
  const text = String(queryText || "");
  if (/bash\s+-lc\s+'touch\s+\/tmp\/ioi-stage67-policy-denied'/i.test(text)) {
    return {
      label: "bash -lc 'touch /tmp/ioi-stage67-policy-denied'",
      command: "bash",
      args: ["-lc", "touch /tmp/ioi-stage67-policy-denied"],
      summary:
        "shell__run unexpectedly completed `bash -lc 'touch /tmp/ioi-stage67-policy-denied'`. This should be treated as a policy regression because the command is mutation-like and not allowlisted.",
    };
  }
  if (/node\s+--version/i.test(text)) {
    return {
      label: "node --version",
      command: "node",
      args: ["--version"],
      summary:
        "shell__run completed `node --version` with exit code 0 after the blocked command. The harness recovered cleanly and returned the final result through chat__reply.",
    };
  }
  return null;
}

function latestRepoPromptContext(queryText, promptContextText, rawInput) {
  const raw = String(rawInput || "");
  const surface = `${queryText}\n${String(promptContextText || "")}`;
  const toolcatMatches = [...raw.matchAll(/\bTOOLCAT_STAGE\d+_[A-Z0-9_]*(?:[^\n\r]*)?/gi)];
  const latestToolcatPrompt = toolcatMatches.at(-1);
  if (latestToolcatPrompt) {
    return {
      surface,
      rawCurrentTurn: raw.slice(latestToolcatPrompt.index ?? 0),
    };
  }
  const knownPromptMatches = [...String(rawInput || "").matchAll(KNOWN_REPO_PROMPT_PATTERN)];
  const latestKnownPrompt = knownPromptMatches.at(-1);
  if (latestKnownPrompt) {
    return {
      surface: `${queryText}\n${latestKnownPrompt[0]}`,
      rawCurrentTurn: raw.slice(latestKnownPrompt.index ?? 0),
    };
  }
  return {
    surface,
    rawCurrentTurn: raw,
  };
}

export function nativeFixtureRepoAwareResponse({
  cwd,
  expectsJsonToolCall,
  hasToolCalled,
  inputText,
  promptContextText,
  queryText,
} = {}) {
  const query = String(queryText || "");
  const rawInput = String(inputText || "");
  const { surface, rawCurrentTurn } = latestRepoPromptContext(query, promptContextText, rawInput);
  if (!expectsJsonToolCall && !/\bTOOLCAT_STAGE\d+_/i.test(surface)) return null;
  const called = (toolName) => {
    const escaped = toolName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return (
      (typeof hasToolCalled === "function" && hasToolCalled(toolName)) ||
      new RegExp(`(?:^|\\n)\\s*assistant\\s*:[^\\n]{0,1200}\\b${escaped}\\b`, "i").test(rawCurrentTurn) ||
      new RegExp(`"role"\\s*:\\s*"assistant"[\\s\\S]{0,1200}\\b${escaped}\\b`, "i").test(rawCurrentTurn) ||
      new RegExp(`\\btool\\.(?:started|completed|result)\\b[\\s\\S]{0,800}\\b${escaped}\\b`, "i").test(rawCurrentTurn) ||
      new RegExp(`(?:^|\\n)\\s*tool:\\s*${escaped}\\b`, "i").test(rawCurrentTurn) ||
      new RegExp(`Tool Output \\(${escaped}\\)`, "i").test(rawCurrentTurn)
    );
  };
  const failed = (toolName) => {
    const escaped = toolName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return (
      new RegExp(`ERROR_CLASS=[^\\n]{0,200}\\b${escaped}\\b`, "i").test(rawCurrentTurn) ||
      new RegExp(`\\btool\\.failed\\b[\\s\\S]{0,800}\\b${escaped}\\b`, "i").test(rawCurrentTurn) ||
      new RegExp(`"runtimeEventKind"\\s*:\\s*"tool\\.failed"[\\s\\S]{0,800}\\b${escaped}\\b`, "i").test(rawCurrentTurn) ||
      new RegExp(`"runtime_event_kind"\\s*:\\s*"tool\\.failed"[\\s\\S]{0,800}\\b${escaped}\\b`, "i").test(rawCurrentTurn)
    );
  };

  const toolCatalogueResponse = nativeFixtureToolCatalogueResponse({
    surface,
    rawCurrentTurn,
    currentSurface: query,
    called,
    failed,
    jsonTool,
  });
  if (toolCatalogueResponse) return toolCatalogueResponse;

  if (isProgressGuideQuery(surface)) {
    const planPath = extractedPlanPath(surface);
    if (called("chat__reply")) {
      return jsonTool("agent__complete", {
        result: "Repo-aware plan progress answer was delivered.",
      });
    }
    if (called("file__read")) {
      return jsonTool("chat__reply", {
        message:
          `Per ${planPath}, early Stage 3/Stage 4 currentness and repo-aware read/search are complete, and the late live ladder now reaches Stage 75. ` +
          "Recent proof closes Stage 71 absolute protected-path denial, Stage 72 sanitized subprocess env, Stage 73 symlink boundary denial, and Stage 74 manifest coverage. " +
          "Stage 75 refreshes reverse-engineering sandbox deltas; the remaining item is future plus-gated Linux namespace/container runner wiring, only if arbitrary shell execution enters product scope.",
      });
    }
    return jsonTool("file__read", { path: planPath });
  }

  if (isProviderRegistrationQuery(surface)) {
    if (called("chat__reply")) {
      return jsonTool("agent__complete", {
        result: "Local/native provider registration answer was delivered.",
      });
    }
    if (called("file__read")) {
      return jsonTool("chat__reply", {
        message:
          "Local/native providers are registered in packages/runtime-daemon/src/model-mounting.mjs. " +
          "That file defines the native local provider/backend registry, including provider.autopilot.local, ioi_native_local handling, backend.autopilot.native-local.fixture, and defaultBackendForProvider mappings; LM Studio, Ollama, vLLM, and OpenAI-compatible provider drivers live in the same registry surface.",
      });
    }
    if (called("file__search")) {
      return jsonTool("file__read", { path: "packages/runtime-daemon/src/model-mounting.mjs" });
    }
    return jsonTool("file__search", {
      path: "packages/runtime-daemon/src",
      regex: "provider\\.autopilot\\.local|ioi_native_local|backend\\.autopilot\\.native-local\\.fixture|defaultBackendForProvider",
      file_pattern: "*.mjs",
    });
  }

  if (isAskAgentModeQuery(surface)) {
    if (called("chat__reply")) {
      return jsonTool("agent__complete", {
        result: "Ask and Agent mode explanation was delivered.",
      });
    }
    if (called("file__read")) {
      return jsonTool("chat__reply", {
        message:
          "Agent Studio mode selection is wired through apps/autopilot/openvscode-extension/ioi-workbench/extension.js. " +
          "The UI emits chat.agentMode.select with an executionMode payload; Ask stays a direct model-answer path, while Agent submits to the governed daemon RuntimeAgentService harness for tools, trace records, and final chat__reply projection.",
      });
    }
    if (called("file__search")) {
      return jsonTool("file__read", { path: "apps/autopilot/openvscode-extension/ioi-workbench/extension.js" });
    }
    return jsonTool("file__search", {
      path: "apps/autopilot/openvscode-extension/ioi-workbench",
      regex: "chat\\.agentMode\\.select|executionMode|studio-mode-toggle|submitStudioAgentTurn",
      file_pattern: "*.js",
    });
  }

  if (isStage5ToolHistoryReviewQuery(surface)) {
    if (called("chat__reply")) {
      return jsonTool("agent__complete", {
        result: "Stage 5 tool-history review answer was delivered.",
      });
    }
    if (called("file__read")) {
      return jsonTool("chat__reply", {
        message:
          "Findings: no blocking issue in the current Stage4 tool-history fix. Reviewed crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/success_path.rs:1042, where tool_history_message_content adds the Tool Output (<tool>) prefix without double-prefixing. Residual risk: future non-browser compactors must keep the prefix path centralized, or file__read/file__search could again become invisible to the next model turn.",
      });
    }
    if (called("file__search")) {
      return jsonTool("file__read", {
        path: "crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/success_path.rs",
      });
    }
    return jsonTool("file__search", {
      path: "crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase",
      regex: "tool_history_message_content|compact_tool_history_entry_for_chat|append_chat_to_scs",
      file_pattern: "*.rs",
    });
  }

  if (isStage5ToolHistoryPatchQuery(surface)) {
    if (called("chat__reply")) {
      return jsonTool("agent__complete", {
        result: "Stage 5 patch proposal answer was delivered.",
      });
    }
    if (called("file__read")) {
      return jsonTool("chat__reply", {
        message:
          "Smallest patch proposal: keep the mutation-free compaction in compact_tool_history_entry_for_chat, then always wrap the persisted chat-history payload with tool_history_message_content at crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/success_path.rs:2710. That makes non-browser outputs such as file__read and file__search visible to the next model turn as Tool Output (<tool>): ... without touching browser-specific pending-state logic.",
      });
    }
    return jsonTool("file__read", {
      path: "crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/success_path.rs",
    });
  }

  if (isStage5ToolHistoryTestQuery(surface)) {
    if (called("chat__reply")) {
      return jsonTool("agent__complete", {
        result: "Stage 5 focused test answer was delivered.",
      });
    }
    if (called("file__read")) {
      return jsonTool("chat__reply", {
        message:
          "Focused tests are in crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/success_path/tests.rs:137. non_browser_tool_history_is_prefixed_for_next_model_turn proves file__read history is stored as Tool Output (file__read): ..., and tool_history_prefix_is_not_duplicated keeps browser__inspect from double-prefixing. Run them as cargo test -q -p ioi-services --lib non_browser_tool_history_is_prefixed_for_next_model_turn and cargo test -q -p ioi-services --lib tool_history_prefix_is_not_duplicated.",
      });
    }
    return jsonTool("file__read", {
      path: "crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/success_path/tests.rs",
    });
  }

  const stage6ShellTestCommand = stage6ShellTestCommandForQuery(surface);
  if (stage6ShellTestCommand) {
    if (called("chat__reply")) {
      return jsonTool("agent__complete", {
        result: `Stage 6 shell/test answer was delivered for ${stage6ShellTestCommand.label}.`,
      });
    }
    if (failed("shell__run")) {
      return jsonTool("chat__reply", {
        message:
          `shell__run did not execute ${stage6ShellTestCommand.label}: the daemon reported a policy or scope failure. ` +
          "Do not claim an exit code until a successful shell__run completion is present in the trace.",
      });
    }
    if (called("shell__run")) {
      return jsonTool("chat__reply", {
        message: stage6ShellTestCommand.summary,
      });
    }
    return jsonTool("shell__run", {
      command: stage6ShellTestCommand.command,
      args: stage6ShellTestCommand.args,
      wait_ms_before_async: 30000,
      detach: false,
    });
  }

  const stage7ShellPolicyCommand = stage7ShellPolicyCommandForQuery(surface);
  if (stage7ShellPolicyCommand) {
    if (called("chat__reply")) {
      return jsonTool("agent__complete", {
        result: `Stage 7 shell policy answer was delivered for ${stage7ShellPolicyCommand.label}.`,
      });
    }
    if (failed("shell__run")) {
      return jsonTool("chat__reply", {
        message:
          `shell__run did not execute ${stage7ShellPolicyCommand.label}: the daemon reported a policy or scope failure. ` +
          "The harness failed closed, did not claim exit code 0, and is ready for the next allowed command.",
      });
    }
    if (called("shell__run")) {
      return jsonTool("chat__reply", {
        message: stage7ShellPolicyCommand.summary,
      });
    }
    return jsonTool("shell__run", {
      command: stage7ShellPolicyCommand.command,
      args: stage7ShellPolicyCommand.args,
      wait_ms_before_async: 30000,
      detach: false,
    });
  }

  if (isStage8FileBoundaryReadQuery(surface)) {
    const fileReadBlockedByPolicy =
      /\bfile__read\b/i.test(rawCurrentTurn) &&
      /\b(Blocked by Policy|outside workspace authority|workspace_filesystem_boundary|Invalid transaction)\b/i.test(
        rawCurrentTurn,
      );
    if (called("chat__reply")) {
      return jsonTool("agent__complete", {
        result: "Stage 8 file boundary denial answer was delivered.",
      });
    }
    if (failed("file__read") || fileReadBlockedByPolicy) {
      return jsonTool("chat__reply", {
        message:
          "file__read was blocked for `/etc/passwd` because the target is outside workspace authority. The daemon enforced the workspace boundary and did not expose protected host file contents.",
      });
    }
    if (called("file__read")) {
      return jsonTool("chat__reply", {
        message:
          "file__read unexpectedly returned data for `/etc/passwd`; treat this as a boundary regression because host file contents should stay outside workspace authority.",
      });
    }
    return jsonTool("file__read", { path: "/etc/passwd" });
  }

  const stage9SanitizedEnvCommand = stage9SanitizedEnvCommandForQuery(surface);
  if (stage9SanitizedEnvCommand) {
    const shellOutput = rawCurrentTurn.match(/Tool Output \(shell__run\):([\s\S]*)/i)?.[1] ?? rawCurrentTurn;
    const secretAbsent = /\bIOI_STAGE72_SECRET_TOKEN=absent\b/i.test(shellOutput);
    const secretPresent = /\bIOI_STAGE72_SECRET_TOKEN=present:/i.test(shellOutput);
    if (called("chat__reply")) {
      return jsonTool("agent__complete", {
        result: "Stage 9 sanitized env answer was delivered.",
      });
    }
    if (failed("shell__run")) {
      return jsonTool("chat__reply", {
        message:
          "shell__run did not execute the IOI_STAGE72_SECRET_TOKEN environment probe; the daemon reported a policy or scope failure, so the sanitized-env proof is inconclusive.",
      });
    }
    if (called("shell__run") && secretAbsent) {
      return jsonTool("chat__reply", {
        message:
          "shell__run completed the sanitized env probe: IOI_STAGE72_SECRET_TOKEN was absent from the subprocess environment, so the daemon stripped sensitive inherited env keys before command execution.",
      });
    }
    if (called("shell__run") && secretPresent) {
      return jsonTool("chat__reply", {
        message:
          "shell__run completed the sanitized env probe, but IOI_STAGE72_SECRET_TOKEN was present in the subprocess environment. Treat this as an env-scrubbing regression; the secret value is intentionally omitted from this reply.",
      });
    }
    if (called("shell__run")) {
      return jsonTool("chat__reply", {
        message:
          "shell__run completed the sanitized env probe, but the IOI_STAGE72_SECRET_TOKEN visibility marker was missing. Treat the result as inconclusive until the command output includes absent or present.",
      });
    }
    return jsonTool("shell__run", {
      command: stage9SanitizedEnvCommand.command,
      args: stage9SanitizedEnvCommand.args,
      wait_ms_before_async: 30000,
      detach: false,
    });
  }

  if (isStage10SymlinkBoundaryReadQuery(surface)) {
    const fileReadBlockedByPolicy =
      /\bfile__read\b/i.test(rawCurrentTurn) &&
      /\b(Blocked by Policy|outside workspace authority|symlink|Invalid transaction)\b/i.test(rawCurrentTurn);
    if (called("chat__reply")) {
      return jsonTool("agent__complete", {
        result: "Stage 10 symlink boundary denial answer was delivered.",
      });
    }
    if (failed("file__read") || fileReadBlockedByPolicy) {
      return jsonTool("chat__reply", {
        message:
          "file__read was blocked for `.autopilot-stage73-outside-link` because the symlink target escapes workspace authority. The daemon enforced the symlink boundary and did not expose outside-workspace file contents.",
      });
    }
    if (called("file__read")) {
      return jsonTool("chat__reply", {
        message:
          "file__read unexpectedly returned data for `.autopilot-stage73-outside-link`; treat this as a symlink boundary regression because outside-workspace target contents should stay protected.",
      });
    }
    return jsonTool("file__read", { path: ".autopilot-stage73-outside-link" });
  }

  if (/\b(repository|repo|workspace|project|codebase|source tree|inspect|file|files)\b/i.test(surface)) {
    if (called("chat__reply")) {
      return jsonTool("agent__complete", {
        result: "Workspace context was summarized.",
      });
    }
    if (called("file__read")) {
      return jsonTool("chat__reply", {
        message:
          `You are in ${cwd || process.cwd()}. Studio should inspect the Agent Studio chat UX, runtime bridge wiring, and intent routing path first, with file evidence attached to the answer.`,
      });
    }
    return jsonTool("file__read", { path: "package.json" });
  }

  return null;
}
