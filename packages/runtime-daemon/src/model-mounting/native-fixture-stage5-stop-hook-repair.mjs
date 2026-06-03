import fs from "node:fs";
import path from "node:path";

const DEFAULT_STAGE5_STATUS_LABEL_PATH = ".tmp/autopilot-stage5-stop-hook-repair/status-labels.mjs";

const BROKEN_HELPER = [
  "export function normalizeStatusLabel(status) {",
  "  return String(status || \"\").trim();",
  "}",
].join("\n");

const FIXED_HELPER = [
  "export function normalizeStatusLabel(status) {",
  "  const words = String(status || \"\")",
  "    .trim()",
  "    .split(/[_\\s-]+/)",
  "    .filter(Boolean)",
  "    .map((part) => part.toLowerCase());",
  "  if (!words.length) return \"\";",
  "  const [first, ...rest] = words;",
  "  return [`${first.slice(0, 1).toUpperCase()}${first.slice(1)}`, ...rest].join(\" \");",
  "}",
].join("\n");

const stage5ProofStateByHelperPath = new Map();

function envTruthy(value) {
  return /^(1|true|yes|on)$/i.test(String(value || "").trim());
}

function defaultJsonTool(name, args) {
  return JSON.stringify({ name, arguments: args });
}

function surfaceText({ queryText, promptContextText, inputText } = {}) {
  return [queryText, promptContextText, inputText].map((value) => String(value || "")).join("\n");
}

function stage5StopHookRepairEnabled(values = {}) {
  if (!envTruthy(process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF)) return false;
  return /\bARP_P0_007_PROOF_TOKEN\b|\bStage\s*5\b|\bstop[-_\s]?hook\b|\bnormalizeStatusLabel\b|\bstatus[-_\s]?label\b/i.test(
    surfaceText(values),
  );
}

function extractedStatusLabelPath(values = {}) {
  const text = surfaceText(values);
  return (
    text.match(/stage5-stop-hook-repair-workspace-fixtures\/[A-Za-z0-9_.-]+\/status-labels\.mjs/i)?.[0] ||
    text.match(/\.tmp\/autopilot-stage5-stop-hook-repair\/[A-Za-z0-9_.-]+\/status-labels\.mjs/i)?.[0] ||
    text.match(/\.tmp\/autopilot-stage5-stop-hook-repair\/status-labels\.mjs/i)?.[0] ||
    DEFAULT_STAGE5_STATUS_LABEL_PATH
  );
}

function testPathForStatusLabelPath(helperPath) {
  return String(helperPath || DEFAULT_STAGE5_STATUS_LABEL_PATH).replace(/status-labels\.mjs$/i, "status-labels.test.mjs");
}

function toolCompleted(inputText, toolName) {
  const text = String(inputText || "");
  const escaped = toolName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return (
    new RegExp(`\\btool\\.completed\\b[\\s\\S]{0,800}\\b${escaped}\\b`, "i").test(text) ||
    new RegExp(`"runtimeEventKind"\\s*:\\s*"tool\\.completed"[\\s\\S]{0,800}\\b${escaped}\\b`, "i").test(text) ||
    new RegExp(`"runtime_event_kind"\\s*:\\s*"tool\\.completed"[\\s\\S]{0,800}\\b${escaped}\\b`, "i").test(text) ||
    new RegExp(`Tool Output \\(${escaped}\\):`, "i").test(text)
  );
}

function stopHookBlocked(inputText) {
  return /\bERROR_CLASS=StopHookBlocked\b|\bstop_hook_completion_blocked=true\b|\bchat_reply_blocked_by_stop_hook\b/i.test(
    String(inputText || ""),
  );
}

function failingValidationObserved(inputText) {
  const text = String(inputText || "");
  return (
    /\bnot ok\b|\bAssertionError\b|\bERR_ASSERTION\b|\b#\s*fail\s+[1-9]\d*\b/i.test(text) ||
    /\bexit[_\s-]?code\b[^0-9-]{0,16}-?[1-9]\d*/i.test(text)
  );
}

function passingValidationObserved(inputText) {
  const text = String(inputText || "");
  return (
    /\b#\s*pass\s+[1-9]\d*\b/i.test(text) &&
    /\b#\s*fail\s+0\b/i.test(text)
  ) || /\bexit[_\s-]?code\b[^0-9-]{0,16}0\b/i.test(text);
}

function lastPatternIndex(text, pattern) {
  const source = pattern instanceof RegExp ? pattern.source : String(pattern || "");
  const originalFlags = pattern instanceof RegExp ? pattern.flags : "";
  const flags = originalFlags.includes("g") ? originalFlags : `${originalFlags}g`;
  const matcher = new RegExp(source, flags);
  let latest = -1;
  let match;
  while ((match = matcher.exec(text))) {
    latest = match.index;
    if (match[0].length === 0) matcher.lastIndex += 1;
  }
  return latest;
}

function completedValidationAfterEdit(inputText) {
  const text = String(inputText || "");
  const editIndex = Math.max(
    lastPatternIndex(text, /\btool\.completed\b[\s\S]{0,500}\bfile__edit\b/i),
    lastPatternIndex(text, /"runtimeEventKind"\s*:\s*"tool\.completed"[\s\S]{0,500}\bfile__edit\b/i),
    lastPatternIndex(text, /"runtime_event_kind"\s*:\s*"tool\.completed"[\s\S]{0,500}\bfile__edit\b/i),
    lastPatternIndex(text, /\bPatched\b[\s\S]{0,500}\bstatus-labels\.mjs\b/i),
  );
  const shellCompletedIndex = Math.max(
    lastPatternIndex(text, /\btool\.completed\b[\s\S]{0,500}\bshell__run\b/i),
    lastPatternIndex(text, /"runtimeEventKind"\s*:\s*"tool\.completed"[\s\S]{0,500}\bshell__run\b/i),
    lastPatternIndex(text, /"runtime_event_kind"\s*:\s*"tool\.completed"[\s\S]{0,500}\bshell__run\b/i),
    lastPatternIndex(text, /\bRan command\b(?!\s+failed)/i),
  );
  return editIndex >= 0 && shellCompletedIndex > editIndex;
}

function readObserved(inputText, helperPath, called) {
  const text = String(inputText || "");
  return (
    called("file__read") ||
    toolCompleted(inputText, "file__read") ||
    text.includes(BROKEN_HELPER) ||
    /\bSkipped immediate replay\b[\s\S]{0,240}\bidentical action already succeeded\b/i.test(text) ||
    new RegExp(`\\bworkspace_read_observed\\b[\\s\\S]{0,800}\\b${helperPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test(
      text,
    )
  );
}

function editNeedsReadObservation(inputText) {
  return /\bno matching read observation\b|\bUse `?file__read`?\b|\bUse `?file__view`?\b/i.test(String(inputText || ""));
}

function stage5ProofStateFile(helperPath) {
  const key = String(helperPath || DEFAULT_STAGE5_STATUS_LABEL_PATH);
  const root = process.env.IOI_STAGE5_STOP_HOOK_REPAIR_STATE_DIR ||
    path.join(process.cwd(), ".tmp", "autopilot-stage5-stop-hook-repair-state");
  const safeKey = Buffer.from(key).toString("base64url").slice(0, 160) || "default";
  return path.join(root, `${safeKey}.json`);
}

function readDurableStage(helperPath) {
  const key = String(helperPath || DEFAULT_STAGE5_STATUS_LABEL_PATH);
  const stateFile = stage5ProofStateFile(key);
  if (stage5ProofStateByHelperPath.has(stateFile)) {
    return stage5ProofStateByHelperPath.get(stateFile) || 0;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    const stage = Number(parsed?.stage);
    return Number.isFinite(stage) && stage >= 0 ? Math.floor(stage) : 0;
  } catch {
    return 0;
  }
}

function writeDurableStage(helperPath, stage) {
  const key = String(helperPath || DEFAULT_STAGE5_STATUS_LABEL_PATH);
  const stateFile = stage5ProofStateFile(key);
  stage5ProofStateByHelperPath.set(stateFile, stage);
  try {
    fs.mkdirSync(path.dirname(stateFile), { recursive: true });
    fs.writeFileSync(stateFile, `${JSON.stringify({ stage }, null, 2)}\n`, "utf8");
  } catch {
    // Proof-local state is a fallback for compact tool history; ignore write failures.
  }
}

function nextStageForHelperPath(helperPath) {
  const key = String(helperPath || DEFAULT_STAGE5_STATUS_LABEL_PATH);
  const stage = readDurableStage(key);
  writeDurableStage(key, stage + 1);
  return stage;
}

function stagedTool(helperPath, stage, jsonTool, name, args) {
  writeDurableStage(helperPath, stage);
  return jsonTool(name, args);
}

export function nativeFixtureStage5StopHookRepairResponse({
  queryText,
  promptContextText,
  inputText,
  expectsJsonToolCall,
  hasToolCalled,
  jsonTool = defaultJsonTool,
} = {}) {
  const values = { queryText, promptContextText, inputText };
  if (!stage5StopHookRepairEnabled(values)) return null;

  const called = typeof hasToolCalled === "function" ? hasToolCalled : () => false;
  const helperPath = extractedStatusLabelPath(values);
  const testPath = testPathForStatusLabelPath(helperPath);
  const durableStage = readDurableStage(helperPath);
  const editObserved = called("file__edit") || toolCompleted(inputText, "file__edit");
  const helperReadObserved = readObserved(inputText, helperPath, called);
  const validationPassed = passingValidationObserved(inputText) ||
    (editObserved && (completedValidationAfterEdit(inputText) || durableStage >= 5));
  const terminalReplyCompleted = validationPassed && toolCompleted(inputText, "chat__reply");

  if (!expectsJsonToolCall && !envTruthy(process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF)) {
    if (validationPassed) {
      return "I repaired the disposable status-label helper and the focused validation now passes.";
    }
    return "The failing validation needs a repair before I can give a completion answer.";
  }

  if (terminalReplyCompleted) {
    return "I repaired the disposable status-label helper and reran the focused validation. It now passes.";
  }

  if (!called("shell__run") && !failingValidationObserved(inputText) && !stopHookBlocked(inputText) && !editObserved && !validationPassed) {
    const stage = nextStageForHelperPath(helperPath);
    if (stage <= 0) {
      return jsonTool("shell__run", {
        command: "node",
        args: ["--test", testPath],
        wait_ms_before_async: 30000,
        detach: false,
      });
    }
    if (stage === 1) {
      return jsonTool("chat__reply", {
        message: "The disposable status-label helper repair is complete.",
      });
    }
    if (stage === 2) {
      return jsonTool("file__read", {
        path: helperPath,
      });
    }
    if (stage === 3) {
      return jsonTool("file__edit", {
        path: helperPath,
        search: BROKEN_HELPER,
        replace: FIXED_HELPER,
      });
    }
    if (stage === 4) {
      return jsonTool("shell__run", {
        command: "node",
        args: ["--test", testPath],
        wait_ms_before_async: 30000,
        detach: false,
      });
    }
    if (stage === 5) {
      return jsonTool("chat__reply", {
        message: "I repaired the disposable status-label helper and reran the focused validation. It now passes.",
      });
    }
    return "I repaired the disposable status-label helper and reran the focused validation. It now passes.";
  }

  if (validationPassed && editObserved) {
    return stagedTool(helperPath, 6, jsonTool, "chat__reply", {
      message: "I repaired the disposable status-label helper and reran the focused validation. It now passes.",
    });
  }

  if (editObserved) {
    return stagedTool(helperPath, 5, jsonTool, "shell__run", {
      command: "node",
      args: ["--test", testPath],
      wait_ms_before_async: 30000,
      detach: false,
    });
  }

  if (
    durableStage <= 1 &&
    (called("shell__run") || failingValidationObserved(inputText)) &&
    !stopHookBlocked(inputText) &&
    !helperReadObserved
  ) {
    return stagedTool(helperPath, 2, jsonTool, "chat__reply", {
      message: "The disposable status-label helper repair is complete.",
    });
  }

  if (editNeedsReadObservation(inputText)) {
    if (helperReadObserved) {
      return stagedTool(helperPath, 4, jsonTool, "file__edit", {
        path: helperPath,
        search: BROKEN_HELPER,
        replace: FIXED_HELPER,
      });
    }
    return stagedTool(helperPath, 3, jsonTool, "file__read", {
      path: helperPath,
    });
  }

  if (stopHookBlocked(inputText)) {
    if (!helperReadObserved) {
      return stagedTool(helperPath, 3, jsonTool, "file__read", {
        path: helperPath,
      });
    }
    return stagedTool(helperPath, 4, jsonTool, "file__edit", {
      path: helperPath,
      search: BROKEN_HELPER,
      replace: FIXED_HELPER,
    });
  }

  if (called("shell__run") || failingValidationObserved(inputText)) {
    return stagedTool(helperPath, 2, jsonTool, "chat__reply", {
      message: "The disposable status-label helper repair is complete.",
    });
  }

  return jsonTool("shell__run", {
    command: "node",
    args: ["--test", testPath],
    wait_ms_before_async: 30000,
    detach: false,
  });
}
