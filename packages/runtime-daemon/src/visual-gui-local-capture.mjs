import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const VISUAL_GUI_LOCAL_CAPTURE_SCHEMA_VERSION =
  "ioi.runtime.visual-gui-local-capture.v1";
const DEFAULT_CAPTURE_TIMEOUT_MS = 5000;

export function visualGuiLocalCaptureRequested(input = {}) {
  return Boolean(
    booleanValue(input.captureScreen ?? input.capture_screen) ??
      booleanValue(input.localCapture ?? input.local_capture) ??
      booleanValue(input.captureVisualGui ?? input.capture_visual_gui) ??
      cleanString(input.captureProvider ?? input.capture_provider ?? input.localCaptureProvider ?? input.local_capture_provider),
  );
}

export function captureLocalVisualGuiObservation({
  input = {},
  captureDir,
  toolCallId = "visual_gui_observe",
  maxBytes = 5 * 1024 * 1024,
} = {}) {
  if (!visualGuiLocalCaptureRequested(input)) return null;
  const captureRef = `visual_gui_local_capture_${safeId(toolCallId)}`;
  const captureRoot = captureDir ?? path.join(os.tmpdir(), "ioi-visual-gui-captures");
  fs.mkdirSync(captureRoot, { recursive: true });
  const screenshotPath = path.join(captureRoot, `${captureRef}.png`);
  const axPath = path.join(captureRoot, `${captureRef}.ax.json`);
  const requestedProvider = cleanString(
    input.captureProvider ??
      input.capture_provider ??
      input.localCaptureProvider ??
      input.local_capture_provider,
  );
  const captureAxTree = Boolean(
    booleanValue(input.captureAxTree ?? input.capture_ax_tree ?? input.captureAccessibilityTree ?? input.capture_accessibility_tree),
  );
  const warnings = [];
  const cleanupPaths = [];
  let providerId = null;
  let screenshotBuffer = null;

  if (requestedProvider === "fixture") {
    if (process.env.IOI_RUNTIME_ENABLE_VISUAL_CAPTURE_FIXTURE !== "1") {
      return unavailableCapture({
        captureRef,
        reason: "fixture_provider_disabled",
        warnings: ["Fixture visual capture provider requires IOI_RUNTIME_ENABLE_VISUAL_CAPTURE_FIXTURE=1."],
      });
    }
    const fixtureBase64 = cleanString(input.captureFixturePngBase64 ?? input.capture_fixture_png_base64);
    if (!fixtureBase64) {
      return unavailableCapture({
        captureRef,
        reason: "fixture_png_missing",
        warnings: ["Fixture visual capture provider requires captureFixturePngBase64."],
      });
    }
    try {
      screenshotBuffer = Buffer.from(fixtureBase64, "base64");
      fs.writeFileSync(screenshotPath, screenshotBuffer);
      cleanupPaths.push(screenshotPath);
      providerId = "fixture";
    } catch (error) {
      return unavailableCapture({
        captureRef,
        reason: "fixture_write_failed",
        warnings: [`Fixture screenshot could not be written: ${error?.code ?? error?.message ?? "write_failed"}.`],
      });
    }
  } else {
    const attempts = [];
    for (const provider of screenshotProvidersForPlatform()) {
      try {
        provider.run(screenshotPath);
        screenshotBuffer = fs.readFileSync(screenshotPath);
        cleanupPaths.push(screenshotPath);
        providerId = provider.id;
        break;
      } catch (error) {
        attempts.push({
          provider: provider.id,
          reason: error?.code ?? error?.message ?? "capture_failed",
        });
        removeQuiet(screenshotPath);
      }
    }
    if (!screenshotBuffer) {
      return unavailableCapture({
        captureRef,
        reason: "no_local_capture_provider_available",
        warnings: attempts.length
          ? attempts.map((attempt) => `${attempt.provider}: ${attempt.reason}`)
          : ["No supported read-only local screenshot provider was found on PATH."],
      });
    }
  }

  if (screenshotBuffer.byteLength > maxBytes) {
    removeQuiet(screenshotPath);
    return unavailableCapture({
      captureRef,
      reason: "captured_screenshot_too_large",
      warnings: [`Captured screenshot exceeds ${maxBytes} bytes.`],
    });
  }

  let axWritten = false;
  if (captureAxTree) {
    const fixtureAxTree = input.captureFixtureAxTree ?? input.capture_fixture_ax_tree;
    const fixtureAxJson = cleanString(input.captureFixtureAxJson ?? input.capture_fixture_ax_json);
    if (requestedProvider === "fixture" && (fixtureAxTree || fixtureAxJson)) {
      const axContent =
        fixtureAxJson ??
        JSON.stringify(fixtureAxTree, null, 2);
      fs.writeFileSync(axPath, axContent);
      cleanupPaths.push(axPath);
      axWritten = true;
    } else {
      warnings.push("Accessibility-tree capture is not mounted for the local daemon adapter; screenshot capture continued read-only.");
    }
  }

  const dimensions = pngDimensions(screenshotBuffer);
  const coordinateSpaceId =
    cleanString(
      input.captureCoordinateSpaceId ??
        input.capture_coordinate_space_id ??
        input.coordinateSpaceId ??
        input.coordinate_space_id,
    ) ?? `screen_${safeId(toolCallId)}_local_capture`;
  const appName =
    cleanString(input.captureAppName ?? input.capture_app_name) ??
    cleanString(input.appName ?? input.app_name);
  const windowTitle =
    cleanString(input.captureWindowTitle ?? input.capture_window_title) ??
    cleanString(input.windowTitle ?? input.window_title);
  const viewportWidth =
    positiveNumber(input.viewportWidth ?? input.viewport_width) ?? dimensions?.width ?? null;
  const viewportHeight =
    positiveNumber(input.viewportHeight ?? input.viewport_height) ?? dimensions?.height ?? null;
  const contentHash = sha256(screenshotBuffer);
  const axHash = axWritten ? sha256(fs.readFileSync(axPath)) : null;
  const receipt = {
    schema_version: VISUAL_GUI_LOCAL_CAPTURE_SCHEMA_VERSION,
    object: "ioi.runtime_visual_gui_local_capture_receipt",
    capture_ref: captureRef,
    status: "captured",
    lane: "visual_gui",
    authority_scope: "computer_use.visual_gui.read",
    provider_id: providerId,
    platform: process.platform,
    display_server: displayServer(),
    screenshot_content_hash: contentHash,
    screenshot_content_bytes: screenshotBuffer.byteLength,
    ax_content_hash: axHash,
    coordinate_space_id: coordinateSpaceId,
    viewport_width: viewportWidth,
    viewport_height: viewportHeight,
    warnings,
    source_path_included: false,
  };
  const detectedPatterns = uniqueStrings([
    ...arrayValue(input.detectedPatterns ?? input.detected_patterns)
      .map((value) => cleanString(value))
      .filter(Boolean),
    "local_gui_capture",
    "screenshot",
    axWritten ? "accessibility_tree" : null,
  ]);
  const inputPatch = {
    screenshotPath,
    screenshot_path: screenshotPath,
    coordinateSpaceId,
    coordinate_space_id: coordinateSpaceId,
    detectedPatterns,
    detected_patterns: detectedPatterns,
    computerUseVisualCaptureReceipt: receipt,
    computer_use_visual_capture_receipt: receipt,
    ...(axWritten ? { axPath, ax_path: axPath } : {}),
    ...(appName ? { appName, app_name: appName } : {}),
    ...(windowTitle ? { windowTitle, window_title: windowTitle } : {}),
    ...(viewportWidth ? { viewportWidth, viewport_width: viewportWidth } : {}),
    ...(viewportHeight ? { viewportHeight, viewport_height: viewportHeight } : {}),
  };
  if (!hasVisualTargets(input) && viewportWidth && viewportHeight) {
    const visualTargets = [
      {
        targetRef: `target_${safeId(toolCallId)}_captured_surface`,
        target_ref: `target_${safeId(toolCallId)}_captured_surface`,
        label: windowTitle ?? appName ?? "Captured visual surface",
        role: appName || windowTitle ? "application" : "screen",
        confidence: 0.65,
        availableActions: ["inspect"],
        available_actions: ["inspect"],
        bounds: {
          coordinateSpaceId,
          coordinate_space_id: coordinateSpaceId,
          x: 0,
          y: 0,
          width: viewportWidth,
          height: viewportHeight,
        },
      },
    ];
    inputPatch.visualTargets = visualTargets;
    inputPatch.visual_targets = visualTargets;
  }
  return {
    status: "captured",
    receipt,
    inputPatch,
    cleanupPaths,
  };
}

export function visualGuiLocalCaptureUnavailablePatch(input = {}) {
  if (hasSuppliedObservationSource(input)) return {};
  return {
    screenshotRef: undefined,
    screenshot_ref: undefined,
    screenshotPath: undefined,
    screenshot_path: undefined,
    somRef: undefined,
    som_ref: undefined,
    somPath: undefined,
    som_path: undefined,
    axRef: undefined,
    ax_ref: undefined,
    axPath: undefined,
    ax_path: undefined,
    appName: undefined,
    app_name: undefined,
    windowTitle: undefined,
    window_title: undefined,
    visualTargets: undefined,
    visual_targets: undefined,
    detectedPatterns: undefined,
    detected_patterns: undefined,
  };
}

function unavailableCapture({ captureRef, reason, warnings = [] }) {
  return {
    status: "unavailable",
    receipt: {
      schema_version: VISUAL_GUI_LOCAL_CAPTURE_SCHEMA_VERSION,
      object: "ioi.runtime_visual_gui_local_capture_receipt",
      capture_ref: captureRef,
      status: "unavailable",
      lane: "visual_gui",
      authority_scope: "computer_use.visual_gui.read",
      provider_id: null,
      platform: process.platform,
      display_server: displayServer(),
      reason,
      warnings,
      source_path_included: false,
    },
    inputPatch: {},
    cleanupPaths: [],
  };
}

function screenshotProvidersForPlatform() {
  if (process.platform === "darwin") {
    return executableCandidates([
      {
        id: "screencapture",
        commandNames: ["/usr/sbin/screencapture", "screencapture"],
        args: (outputPath) => ["-x", outputPath],
      },
    ]);
  }
  if (process.platform === "win32") {
    return executableCandidates([
      {
        id: "powershell-screenshot",
        commandNames: ["powershell.exe", "powershell"],
        args: (outputPath) => [
          "-NoProfile",
          "-NonInteractive",
          "-ExecutionPolicy",
          "Bypass",
          "-Command",
          [
            "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;",
            "$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds;",
            "$bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height;",
            "$graphics = [System.Drawing.Graphics]::FromImage($bitmap);",
            "$graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size);",
            `$bitmap.Save(${JSON.stringify(outputPath)}, [System.Drawing.Imaging.ImageFormat]::Png);`,
            "$graphics.Dispose();",
            "$bitmap.Dispose();",
          ].join(" "),
        ],
      },
    ]);
  }
  return executableCandidates([
    ...(process.env.WAYLAND_DISPLAY
      ? [
          {
            id: "grim",
            commandNames: ["grim"],
            args: (outputPath) => [outputPath],
          },
        ]
      : []),
    {
      id: "gnome-screenshot",
      commandNames: ["gnome-screenshot"],
      args: (outputPath) => ["-f", outputPath],
    },
    {
      id: "import-root",
      commandNames: ["import"],
      args: (outputPath) => ["-window", "root", outputPath],
    },
    {
      id: "scrot",
      commandNames: ["scrot"],
      args: (outputPath) => [outputPath],
    },
    {
      id: "maim",
      commandNames: ["maim"],
      args: (outputPath) => [outputPath],
    },
  ]);
}

function executableCandidates(specs) {
  return specs
    .map((spec) => {
      const commandPath = spec.commandNames.map(findExecutable).find(Boolean);
      if (!commandPath) return null;
      return {
        id: spec.id,
        run(outputPath) {
          execFileSync(commandPath, spec.args(outputPath), {
            timeout: DEFAULT_CAPTURE_TIMEOUT_MS,
            stdio: ["ignore", "pipe", "pipe"],
            maxBuffer: 1024 * 1024,
          });
          const stat = fs.statSync(outputPath);
          if (!stat.isFile() || stat.size <= 0) {
            throw new Error("capture_output_empty");
          }
        },
      };
    })
    .filter(Boolean);
}

function findExecutable(name) {
  if (!name) return null;
  if (path.isAbsolute(name)) return canExecute(name) ? name : null;
  const extensions =
    process.platform === "win32"
      ? ["", ".exe", ".cmd", ".bat", ".ps1"]
      : [""];
  for (const dir of String(process.env.PATH ?? "").split(path.delimiter)) {
    if (!dir) continue;
    for (const extension of extensions) {
      const candidate = path.join(dir, `${name}${extension}`);
      if (canExecute(candidate)) return candidate;
    }
  }
  return null;
}

function canExecute(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function displayServer() {
  if (process.env.WAYLAND_DISPLAY) return "wayland";
  if (process.env.DISPLAY) return "x11";
  if (process.platform === "darwin") return "quartz";
  if (process.platform === "win32") return "win32";
  return "unknown";
}

function hasSuppliedObservationSource(input) {
  return Boolean(
    cleanString(input.screenshotRef ?? input.screenshot_ref) ||
      cleanString(input.screenshotPath ?? input.screenshot_path) ||
      cleanString(input.somRef ?? input.som_ref) ||
      cleanString(input.somPath ?? input.som_path) ||
      cleanString(input.axRef ?? input.ax_ref) ||
      cleanString(input.axPath ?? input.ax_path) ||
      cleanString(input.appName ?? input.app_name) ||
      cleanString(input.windowTitle ?? input.window_title) ||
      hasVisualTargets(input),
  );
}

function hasVisualTargets(input) {
  return arrayValue(input.visualTargets ?? input.visual_targets).length > 0;
}

function pngDimensions(buffer) {
  if (
    !Buffer.isBuffer(buffer) ||
    buffer.length < 24 ||
    buffer[0] !== 0x89 ||
    buffer[1] !== 0x50 ||
    buffer[2] !== 0x4e ||
    buffer[3] !== 0x47
  ) {
    return null;
  }
  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
  };
}

function booleanValue(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
  }
  return null;
}

function positiveNumber(value) {
  const numeric = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return null;
  return numeric;
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

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function removeQuiet(filePath) {
  try {
    fs.rmSync(filePath, { force: true });
  } catch {
    // Best-effort cleanup only; the capture receipt never exposes raw paths.
  }
}
