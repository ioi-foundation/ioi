import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import {
  captureLocalVisualGuiObservation,
} from "./visual-gui-local-capture.mjs";

const VISUAL_GUI_LOCAL_EXECUTOR_SCHEMA_VERSION =
  "ioi.runtime.visual-gui-local-executor.v1";
const DEFAULT_EXECUTION_TIMEOUT_MS = 5000;

export function visualGuiLocalExecutorRequested({ input = {}, actionKind, approvalRef } = {}) {
  if (!approvalRef || computerUseActionKindIsReadOnly(actionKind)) return false;
  const explicitRequest =
    booleanValue(input.local_gui_executor) ??
    booleanValue(input.execute_local_gui) ??
    booleanValue(input.visual_gui_local_executor);
  if (explicitRequest !== null) return explicitRequest;
  const executorMode = cleanString(
    input.visual_gui_executor ??
      input.executor_mode,
  );
  return (
    ["local", "local_gui", "fixture"].includes(executorMode ?? "") ||
    Boolean(cleanString(input.local_gui_executor_provider))
  );
}

export async function executeLocalVisualGuiAction({
  input = {},
  actionKind,
  approvalRef,
  targetRef,
  prompt = "",
  toolCallId = "visual_gui_action",
  captureDir,
  artifactResolver,
  maxBytes = 5 * 1024 * 1024,
} = {}) {
  const executorRef = `visual_gui_local_executor_${safeId(toolCallId)}`;
  const normalizedActionKind = normalizeActionKind(actionKind);
  if (!approvalRef) {
    return blockedExecution({
      executorRef,
      actionKind: normalizedActionKind,
      approvalRef,
      targetRef,
      errorClass: "policy",
      errorSummary: "Visual GUI local execution requires an approval reference.",
    });
  }
  if (!["click", "type_text", "key_press", "scroll"].includes(normalizedActionKind)) {
    return blockedExecution({
      executorRef,
      actionKind: normalizedActionKind,
      approvalRef,
      targetRef,
      errorClass: "unsupported_action",
      errorSummary: `Visual GUI local executor does not support ${normalizedActionKind}.`,
    });
  }

  const groundedTarget = resolveGroundedTarget(input, targetRef);
  if (!groundedTarget) {
    return blockedExecution({
      executorRef,
      actionKind: normalizedActionKind,
      approvalRef,
      targetRef,
      errorClass: "grounding",
      errorSummary: "Visual GUI local execution requires a targetRef with observation-bound target bounds.",
    });
  }
  if (
    groundedTarget.available_actions.length > 0 &&
    !groundedTarget.available_actions.includes(normalizedActionKind)
  ) {
    return blockedExecution({
      executorRef,
      actionKind: normalizedActionKind,
      approvalRef,
      targetRef: groundedTarget.target_ref,
      errorClass: "grounding",
      errorSummary: `Visual GUI local execution blocked because target ${groundedTarget.target_ref} does not advertise ${normalizedActionKind}.`,
    });
  }

  const screenshotRef = cleanString(
    input.screenshot_ref ??
      input.observation_bundle?.screenshot_ref,
  );
  const observedScreenshot = screenshotRef && artifactResolver
    ? artifactResolver(screenshotRef)
    : null;
  if (!observedScreenshot?.content) {
    return blockedExecution({
      executorRef,
      actionKind: normalizedActionKind,
      approvalRef,
      targetRef: groundedTarget.target_ref,
      errorClass: "verification",
      errorSummary: "Visual GUI local execution requires the original screenshot artifact for drift checking.",
    });
  }

  const preflightCapture = captureLocalVisualGuiObservation({
    input: {
      ...input,
      capture_screen: true,
      capture_provider:
        cleanString(input.local_gui_executor_provider) === "fixture"
          ? "fixture"
          : input.capture_provider,
      capture_fixture_png_base64:
        input.local_gui_executor_fixture_png_base64 ??
        input.capture_fixture_png_base64,
    },
    captureDir,
    toolCallId: `${toolCallId}_preflight`,
    maxBytes,
  });
  const cleanupPaths = preflightCapture?.cleanupPaths ?? [];
  try {
    if (preflightCapture?.status !== "captured") {
      return blockedExecution({
        executorRef,
        actionKind: normalizedActionKind,
        approvalRef,
        targetRef: groundedTarget.target_ref,
        errorClass: "environment",
        errorSummary: `Visual GUI local executor could not capture a pre-action drift check: ${preflightCapture?.receipt?.reason ?? "capture_unavailable"}.`,
        evidenceRefs: [screenshotRef],
        preflightReceipt: preflightCapture?.receipt ?? null,
      });
    }
    const currentScreenshotPath = preflightCapture.inputPatch?.screenshot_path;
    const currentScreenshotBase64 = currentScreenshotPath
      ? fs.readFileSync(currentScreenshotPath).toString("base64")
      : null;
    if (!currentScreenshotBase64 || currentScreenshotBase64 !== observedScreenshot.content) {
      return blockedExecution({
        executorRef,
        actionKind: normalizedActionKind,
        approvalRef,
        targetRef: groundedTarget.target_ref,
        errorClass: "visual_drift",
        errorSummary: "Visual GUI local executor blocked because the current screenshot no longer matches the grounded observation.",
        evidenceRefs: [screenshotRef],
        preflightReceipt: preflightCapture.receipt,
      });
    }

    const actionPayload = actionPayloadForKind({
      input,
      actionKind: normalizedActionKind,
      target: groundedTarget,
      prompt,
    });
    if (!actionPayload.ok) {
      return blockedExecution({
        executorRef,
        actionKind: normalizedActionKind,
        approvalRef,
        targetRef: groundedTarget.target_ref,
        errorClass: "invalid_action_payload",
        errorSummary: actionPayload.error,
        evidenceRefs: [screenshotRef],
        preflightReceipt: preflightCapture.receipt,
      });
    }

    const provider = localExecutorProvider(input);
    if (!provider) {
      return blockedExecution({
        executorRef,
        actionKind: normalizedActionKind,
        approvalRef,
        targetRef: groundedTarget.target_ref,
        errorClass: "environment",
        errorSummary: "No supported local GUI input provider is available for approved execution.",
        evidenceRefs: [screenshotRef],
        preflightReceipt: preflightCapture.receipt,
      });
    }

    const executionReceipt = provider.execute(actionPayload.value);
    return {
      schema_version: VISUAL_GUI_LOCAL_EXECUTOR_SCHEMA_VERSION,
      object: "ioi.runtime_visual_gui_local_execution_result",
      status: "completed",
      adapter_id: "ioi.visual_gui.local_executor",
      executor_ref: executorRef,
      action_kind: normalizedActionKind,
      approval_ref: approvalRef,
      target_ref: groundedTarget.target_ref,
      observation_ref: cleanString(input.observation_ref) ?? null,
      coordinate_space_id: groundedTarget.bounds.coordinate_space_id,
      payload_summary: localActionSummary(normalizedActionKind, groundedTarget, actionPayload.value),
      provider_id: provider.id,
      preflight_receipt: preflightCapture.receipt,
      execution_receipt: executionReceipt,
      evidence_refs: uniqueStrings([screenshotRef]),
      after: {
        status: "action_dispatched",
        requires_reobserve: true,
      },
    };
  } catch (error) {
    return blockedExecution({
      executorRef,
      actionKind: normalizedActionKind,
      approvalRef,
      targetRef: groundedTarget.target_ref,
      errorClass: "execution",
      errorSummary: error?.message ?? "Visual GUI local execution failed.",
      evidenceRefs: [screenshotRef],
      preflightReceipt: preflightCapture?.receipt ?? null,
    });
  } finally {
    for (const filePath of cleanupPaths) {
      removeQuiet(filePath);
    }
  }
}

function localExecutorProvider(input) {
  const requestedProvider = cleanString(input.local_gui_executor_provider);
  if (requestedProvider === "fixture") {
    return {
      id: "fixture",
      execute(payload) {
        return {
          status: "completed",
          provider_id: "fixture",
          action: payload.action,
          target_point: payload.target_point ?? null,
          source_path_included: false,
        };
      },
    };
  }
  if (process.platform === "linux") {
    const xdotool = findExecutable("xdotool");
    if (!xdotool) return null;
    return {
      id: "xdotool",
      execute(payload) {
        executeWithXdotool(xdotool, payload);
        return {
          status: "completed",
          provider_id: "xdotool",
          action: payload.action,
          target_point: payload.target_point ?? null,
          source_path_included: false,
        };
      },
    };
  }
  const cliclick = process.platform === "darwin" ? findExecutable("cliclick") : null;
  if (cliclick) {
    return {
      id: "cliclick",
      execute(payload) {
        executeWithCliclick(cliclick, payload);
        return {
          status: "completed",
          provider_id: "cliclick",
          action: payload.action,
          target_point: payload.target_point ?? null,
          source_path_included: false,
        };
      },
    };
  }
  return null;
}

function executeWithXdotool(xdotool, payload) {
  if (payload.target_point) {
    execFileSync(xdotool, ["mousemove", String(payload.target_point.x), String(payload.target_point.y)], execOptions());
  }
  if (payload.action === "click") {
    execFileSync(xdotool, ["click", "1"], execOptions());
  } else if (payload.action === "type_text") {
    execFileSync(xdotool, ["type", "--delay", "0", payload.text], execOptions());
  } else if (payload.action === "key_press") {
    execFileSync(xdotool, ["key", payload.key], execOptions());
  } else if (payload.action === "scroll") {
    const clicks = Math.min(12, Math.max(1, Math.ceil(Math.abs(payload.dy) / 120)));
    const button = payload.dy > 0 ? "5" : "4";
    for (let index = 0; index < clicks; index += 1) {
      execFileSync(xdotool, ["click", button], execOptions());
    }
  }
}

function executeWithCliclick(cliclick, payload) {
  if (payload.action === "click") {
    execFileSync(cliclick, [`c:${payload.target_point.x},${payload.target_point.y}`], execOptions());
  } else if (payload.action === "type_text") {
    if (payload.target_point) {
      execFileSync(cliclick, [`c:${payload.target_point.x},${payload.target_point.y}`], execOptions());
    }
    execFileSync(cliclick, [`t:${payload.text}`], execOptions());
  } else if (payload.action === "key_press") {
    execFileSync(cliclick, [`kp:${payload.key}`], execOptions());
  } else if (payload.action === "scroll") {
    throw new Error("cliclick scroll execution is not supported by the local GUI executor.");
  }
}

function actionPayloadForKind({ input, actionKind, target, prompt }) {
  const target_point = targetCenter(target);
  if (!target_point) return { ok: false, error: "Target bounds do not include a usable center point." };
  if (actionKind === "click") {
    return { ok: true, value: { action: "click", target_point } };
  }
  if (actionKind === "type_text") {
    const text = cleanString(input.input_text) ?? textFromPrompt(prompt);
    if (!text) return { ok: false, error: "Approved type_text action requires input_text or a quoted type prompt." };
    return { ok: true, value: { action: "type_text", target_point, text } };
  }
  if (actionKind === "key_press") {
    const key = cleanString(input.key_text) ?? keyFromPrompt(prompt);
    if (!key) return { ok: false, error: "Approved key_press action requires key_text or a key prompt." };
    return { ok: true, value: { action: "key_press", target_point, key } };
  }
  if (actionKind === "scroll") {
    const dy = finiteNumber(input.scroll_y) ?? 0;
    const dx = finiteNumber(input.scroll_x) ?? 0;
    if (dx === 0 && dy === 0) return { ok: false, error: "Approved scroll action requires scroll_x or scroll_y." };
    return { ok: true, value: { action: "scroll", target_point, dx, dy } };
  }
  return { ok: false, error: `Unsupported visual GUI action ${actionKind}.` };
}

function resolveGroundedTarget(input, targetRef) {
  const normalizedTargetRef = cleanString(targetRef ?? input.target_ref);
  if (!normalizedTargetRef) return null;
  const targets = [
    ...arrayValue(input.visual_targets),
    ...arrayValue(input.computer_use_target_index?.targets),
    ...arrayValue(input.target_index?.targets),
  ]
    .map((target) => normalizeTarget(target))
    .filter(Boolean);
  return targets.find((target) => target.target_ref === normalizedTargetRef) ?? null;
}

function normalizeTarget(target) {
  if (!target || typeof target !== "object" || Array.isArray(target)) return null;
  const bounds = normalizeBounds(target.bounds);
  if (!bounds) return null;
  return {
    target_ref: cleanString(target.target_ref),
    label: cleanString(target.label ?? target.name) ?? "Visual target",
    role: cleanString(target.role) ?? "region",
    bounds,
    available_actions: uniqueStrings(
      arrayValue(target.available_actions)
        .map((value) => normalizeActionKind(value))
        .filter(Boolean),
    ),
  };
}

function normalizeBounds(bounds) {
  if (!bounds || typeof bounds !== "object" || Array.isArray(bounds)) return null;
  const x = finiteNumber(bounds.x);
  const y = finiteNumber(bounds.y);
  const width = finiteNumber(bounds.width);
  const height = finiteNumber(bounds.height);
  const coordinateSpaceId = cleanString(bounds.coordinate_space_id);
  if (x === null || y === null || !width || !height || !coordinateSpaceId) return null;
  return {
    coordinate_space_id: coordinateSpaceId,
    x,
    y,
    width,
    height,
  };
}

function targetCenter(target) {
  const bounds = target?.bounds;
  if (!bounds) return null;
  return {
    x: Math.round(bounds.x + bounds.width / 2),
    y: Math.round(bounds.y + bounds.height / 2),
  };
}

function blockedExecution({
  executorRef,
  actionKind,
  approvalRef,
  targetRef,
  errorClass,
  errorSummary,
  evidenceRefs = [],
  preflightReceipt = null,
}) {
  return {
    schema_version: VISUAL_GUI_LOCAL_EXECUTOR_SCHEMA_VERSION,
    object: "ioi.runtime_visual_gui_local_execution_result",
    status: "blocked",
    adapter_id: "ioi.visual_gui.local_executor",
    executor_ref: executorRef,
    action_kind: actionKind,
    approval_ref: approvalRef ?? null,
    target_ref: targetRef ?? null,
    error_class: errorClass,
    error_summary: errorSummary,
    evidence_refs: uniqueStrings(evidenceRefs),
    preflight_receipt: preflightReceipt,
  };
}

function localActionSummary(actionKind, target, payload) {
  if (actionKind === "type_text") return `type_text into ${target.label}`;
  if (actionKind === "key_press") return `key_press ${payload.key} at ${target.label}`;
  if (actionKind === "scroll") return `scroll ${target.label}`;
  return `click ${target.label}`;
}

function normalizeActionKind(value) {
  const normalized = cleanString(value)?.toLowerCase().replace(/[\s-]+/g, "_");
  if (normalized === "type" || normalized === "input_text") return "type_text";
  if (normalized === "keypress") return "key_press";
  return normalized ?? "inspect";
}

function computerUseActionKindIsReadOnly(actionKind) {
  return ["inspect", "observe", "screenshot", "read"].includes(normalizeActionKind(actionKind));
}

function textFromPrompt(prompt) {
  const match = String(prompt ?? "").match(/\btype\s+["']([^"']+)["']/i);
  return match?.[1] ?? null;
}

function keyFromPrompt(prompt) {
  const match = String(prompt ?? "").match(/\b(?:press|key)\s+([A-Za-z0-9_+-]+)/i);
  return match?.[1] ?? null;
}

function execOptions() {
  return {
    timeout: DEFAULT_EXECUTION_TIMEOUT_MS,
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 1024 * 1024,
  };
}

function findExecutable(name) {
  if (!name) return null;
  const extensions = process.platform === "win32" ? ["", ".exe", ".cmd", ".bat"] : [""];
  for (const dir of String(process.env.PATH ?? "").split(path.delimiter)) {
    if (!dir) continue;
    for (const extension of extensions) {
      const candidate = path.join(dir, `${name}${extension}`);
      try {
        fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      } catch {
        // Keep scanning PATH.
      }
    }
  }
  return null;
}

function booleanValue(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
  }
  return null;
}

function finiteNumber(value) {
  const numeric = typeof value === "number" ? value : Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function cleanString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value)));
}

function safeId(value) {
  return String(value ?? "item")
    .replace(/[^a-zA-Z0-9_-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 96) || "item";
}

function removeQuiet(filePath) {
  try {
    fs.rmSync(filePath, { force: true });
  } catch {
    // Best-effort cleanup only; execution receipts never expose raw paths.
  }
}
