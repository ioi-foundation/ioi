import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const NATIVE_BROWSER_CONTROLLED_RELAUNCH_SCHEMA_VERSION =
  "ioi.runtime.native-browser-controlled-relaunch.v1";

export async function launchControlledNativeBrowser({
  input = {},
  runId = "run_native_browser",
  approvalRef = null,
  timeoutMs = 8_000,
  cwd = process.cwd(),
} = {}) {
  const launchRef = `controlled_relaunch_${stableHash(JSON.stringify({
    runId,
    approvalRef,
    startUrl: controlledRelaunchStartUrl(input),
  })).slice(0, 16)}`;
  const brokerRef = controlledRelaunchBrokerRef(input, launchRef);
  const launchApprovalRef = stringValue(approvalRef) ?? controlledRelaunchApprovalRef(input);
  if (!launchApprovalRef) {
    return unavailableLaunch({
      runId,
      launchRef,
      brokerRef,
      errorClass: "ControlledRelaunchApprovalRequired",
      errorSummary:
        "Controlled browser relaunch requires an explicit launch approval ref before the daemon starts a browser process.",
    });
  }

  const executablePath = controlledRelaunchExecutablePath(input);
  if (!executablePath) {
    return unavailableLaunch({
      runId,
      launchRef,
      brokerRef,
      approvalRef: launchApprovalRef,
      errorClass: "ControlledRelaunchExecutableUnavailable",
      errorSummary:
        "No Chromium/Chrome executable was configured or found for controlled browser relaunch.",
    });
  }

  const profileDir = await fs.promises.mkdtemp(
    path.join(os.tmpdir(), `ioi-controlled-browser-${safeId(runId)}-`),
  );
  const profileDirRef = `profile:controlled_relaunch:${stableHash(profileDir).slice(0, 16)}`;
  const port = controlledRelaunchPort(input);
  const startUrl = controlledRelaunchStartUrl(input);
  const headless = controlledRelaunchHeadless(input);
  const userVisible = !headless;
  const executableArgs = controlledRelaunchExecutableArgs(input);
  const launchArgs = [
    ...executableArgs,
    `--user-data-dir=${profileDir}`,
    `--remote-debugging-port=${port ?? 0}`,
    "--remote-debugging-address=127.0.0.1",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-default-apps",
    "--disable-extensions",
    ...(headless ? ["--headless=new", "--disable-gpu"] : []),
    ...controlledRelaunchExtraArgs(input),
    ...(startUrl ? [startUrl] : []),
  ];

  let child = null;
  try {
    child = spawn(executablePath, launchArgs, {
      cwd,
      env: process.env,
      stdio: "ignore",
      detached: false,
    });
    const endpoint = await waitForDevToolsEndpoint({
      child,
      profileDir,
      port,
      timeoutMs,
    });
    const processRef = `process:native_browser:${stableHash(`${child.pid}:${profileDir}`).slice(0, 16)}`;
    const launchReceipt = {
      schema_version: NATIVE_BROWSER_CONTROLLED_RELAUNCH_SCHEMA_VERSION,
      object: "ioi.runtime_native_browser_controlled_relaunch",
      launch_ref: launchRef,
      broker_ref: brokerRef,
      adapter_id: "ioi.native_browser.controlled_relaunch_broker",
      status: "launched",
      approval_ref: launchApprovalRef,
      authority_scope: "computer_use.native_browser.controlled_relaunch",
      process_ref: processRef,
      profile_dir_ref: profileDirRef,
      profile_provenance: "temporary_ioi_controlled_relaunch_profile",
      executable_ref: `executable:${stableHash(executablePath).slice(0, 16)}`,
      command_ref: `command:${stableHash(JSON.stringify(launchArgs)).slice(0, 16)}`,
      endpoint_ref: endpoint.endpointRef,
      session_ref: endpoint.sessionRef,
      endpoint_source: endpoint.source,
      browser: endpoint.browser,
      protocol_version: endpoint.protocolVersion,
      start_url: startUrl,
      user_visible: userVisible,
      headless,
      cleanup_required: true,
      evidence_refs: compactValues([
        brokerRef,
        launchApprovalRef,
        processRef,
        profileDirRef,
        endpoint.endpointRef,
        endpoint.sessionRef,
      ]),
    };
    return {
      status: "launched",
      endpointUrl: endpoint.endpointUrl,
      launchReceipt,
      async cleanup({ leaseId = null, retainedArtifactRefs = ["computer-use-trace.json"] } = {}) {
        const cleanup = await cleanupLaunchedBrowser({
          child,
          profileDir,
          processRef,
          profileDirRef,
        });
        return {
          cleanup_ref: `cleanup_${safeId(runId)}_controlled_relaunch_launch`,
          lease_id: leaseId,
          status: cleanup.status,
          closed_process_refs: cleanup.closedProcessRefs,
          deleted_profile_refs: cleanup.deletedProfileRefs,
          retained_artifact_refs: retainedArtifactRefs,
          warnings: cleanup.warnings,
        };
      },
    };
  } catch (error) {
    const cleanup = await cleanupLaunchedBrowser({
      child,
      profileDir,
      processRef: child?.pid
        ? `process:native_browser:${stableHash(`${child.pid}:${profileDir}`).slice(0, 16)}`
        : null,
      profileDirRef,
    });
    return unavailableLaunch({
      runId,
      launchRef,
      brokerRef,
      approvalRef: launchApprovalRef,
      profileDirRef,
      errorClass: error?.name ?? "ControlledRelaunchLaunchError",
      errorSummary: String(error?.message ?? error).slice(0, 300),
      cleanup,
    });
  }
}

function unavailableLaunch({
  runId,
  launchRef,
  brokerRef,
  approvalRef = null,
  profileDirRef = null,
  errorClass,
  errorSummary,
  cleanup = null,
}) {
  return {
    status: "unavailable",
    endpointUrl: null,
    launchReceipt: {
      schema_version: NATIVE_BROWSER_CONTROLLED_RELAUNCH_SCHEMA_VERSION,
      object: "ioi.runtime_native_browser_controlled_relaunch",
      launch_ref: launchRef,
      broker_ref: brokerRef,
      adapter_id: "ioi.native_browser.controlled_relaunch_broker",
      status: "unavailable",
      approval_ref: approvalRef,
      authority_scope: "computer_use.native_browser.controlled_relaunch",
      process_ref: null,
      profile_dir_ref: profileDirRef,
      profile_provenance: profileDirRef ? "temporary_ioi_controlled_relaunch_profile" : "none",
      endpoint_ref: null,
      session_ref: null,
      endpoint_source: null,
      start_url: null,
      user_visible: null,
      cleanup_required: false,
      error_class: errorClass,
      error_summary: errorSummary,
      cleanup_status: cleanup?.status ?? null,
      evidence_refs: compactValues([brokerRef, approvalRef, profileDirRef]),
    },
    async cleanup({ leaseId = null, retainedArtifactRefs = ["computer-use-trace.json"] } = {}) {
      return {
        cleanup_ref: `cleanup_${safeId(runId)}_controlled_relaunch_launch`,
        lease_id: leaseId,
        status: cleanup?.status ?? "not_required",
        closed_process_refs: cleanup?.closedProcessRefs ?? [],
        deleted_profile_refs: cleanup?.deletedProfileRefs ?? [],
        retained_artifact_refs: retainedArtifactRefs,
        warnings: cleanup?.warnings ?? [errorSummary],
      };
    },
  };
}

async function waitForDevToolsEndpoint({ child, profileDir, port, timeoutMs }) {
  const deadline = Date.now() + timeoutMs;
  let latestError = null;
  while (Date.now() < deadline) {
    if (child?.exitCode !== null) {
      throw new Error(`Controlled browser process exited before exposing CDP (exit ${child.exitCode}).`);
    }
    const endpointUrl = await devToolsEndpointUrl({ profileDir, port });
    if (endpointUrl) {
      try {
        const version = await fetchJsonWithTimeout(`${endpointUrl}/json/version`, 1_000);
        const webSocketDebuggerUrl = stringValue(version?.webSocketDebuggerUrl);
        if (webSocketDebuggerUrl) {
          return {
            endpointUrl,
            endpointRef: `cdp_endpoint_${stableHash(endpointUrl).slice(0, 16)}`,
            sessionRef: `cdp_session_${stableHash(webSocketDebuggerUrl).slice(0, 16)}`,
            source: "controlled_relaunch_http_endpoint",
            browser: stringValue(version?.Browser),
            protocolVersion: stringValue(version?.["Protocol-Version"]),
          };
        }
      } catch (error) {
        latestError = error;
      }
    }
    await delay(100);
  }
  throw new Error(
    `Controlled browser relaunch did not expose CDP before timeout.${latestError ? ` Last error: ${latestError.message}` : ""}`,
  );
}

async function devToolsEndpointUrl({ profileDir, port }) {
  if (port) return `http://127.0.0.1:${port}`;
  const activePortPath = path.join(profileDir, "DevToolsActivePort");
  try {
    const content = await fs.promises.readFile(activePortPath, "utf8");
    const discoveredPort = Number(content.split(/\r?\n/)[0]);
    if (Number.isFinite(discoveredPort) && discoveredPort > 0) {
      return `http://127.0.0.1:${Math.round(discoveredPort)}`;
    }
  } catch {
    return null;
  }
  return null;
}

async function cleanupLaunchedBrowser({ child, profileDir, processRef, profileDirRef }) {
  const warnings = [];
  const closedProcessRefs = [];
  const deletedProfileRefs = [];
  if (child && child.exitCode === null) {
    try {
      child.kill("SIGTERM");
      await Promise.race([
        new Promise((resolve) => child.once("exit", resolve)),
        delay(1_000).then(() => {
          if (child.exitCode === null) child.kill("SIGKILL");
        }),
      ]);
      if (processRef) closedProcessRefs.push(processRef);
    } catch (error) {
      warnings.push(`process_cleanup_failed:${String(error?.message ?? error).slice(0, 120)}`);
    }
  }
  if (profileDir) {
    try {
      await fs.promises.rm(profileDir, { recursive: true, force: true });
      if (profileDirRef) deletedProfileRefs.push(profileDirRef);
    } catch (error) {
      warnings.push(`profile_cleanup_failed:${String(error?.message ?? error).slice(0, 120)}`);
    }
  }
  return {
    status: warnings.length > 0 ? "completed_with_warnings" : "completed",
    closedProcessRefs,
    deletedProfileRefs,
    warnings,
  };
}

async function fetchJsonWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

function controlledRelaunchApprovalRef(input) {
  return stringValue(
    input.controlled_relaunch_approval_ref ??
      input.host_browser_launch_approval_ref ??
      input.browser_launch_approval_ref,
  );
}

function controlledRelaunchBrokerRef(input, fallback) {
  return stringValue(
    input.controlled_relaunch_broker_ref ??
      input.computer_use_controlled_relaunch_broker?.broker_ref ??
      input.controlled_relaunch_broker?.broker_ref,
  ) ?? `broker_${fallback}`;
}

function controlledRelaunchExecutablePath(input) {
  const explicit = stringValue(
    input.controlled_relaunch_executable_path ??
      input.browser_executable_path,
  );
  if (explicit) return explicit;
  for (const envName of [
    "IOI_NATIVE_BROWSER_EXECUTABLE",
    "CHROME_PATH",
    "CHROMIUM_PATH",
    "BROWSER_PATH",
  ]) {
    const value = stringValue(process.env[envName]);
    if (value) return value;
  }
  return knownBrowserExecutablePaths().find((candidate) => fs.existsSync(candidate)) ?? null;
}

function knownBrowserExecutablePaths() {
  if (process.platform === "darwin") {
    return [
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ];
  }
  if (process.platform === "win32") {
    return [
      path.join(process.env.PROGRAMFILES ?? "C:\\Program Files", "Google\\Chrome\\Application\\chrome.exe"),
      path.join(process.env["PROGRAMFILES(X86)"] ?? "C:\\Program Files (x86)", "Google\\Chrome\\Application\\chrome.exe"),
    ];
  }
  return [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
  ];
}

function controlledRelaunchExecutableArgs(input) {
  return stringArray(
    input.controlled_relaunch_executable_args ??
      input.browser_executable_args,
  );
}

function controlledRelaunchExtraArgs(input) {
  return stringArray(
    input.controlled_relaunch_extra_args ??
      input.browser_launch_args,
  );
}

function controlledRelaunchPort(input) {
  const value = Number(
    input.controlled_relaunch_cdp_port ??
      input.browser_launch_cdp_port,
  );
  if (Number.isFinite(value) && value > 0 && value < 65536) return Math.round(value);
  return null;
}

function controlledRelaunchStartUrl(input) {
  const value = stringValue(
    input.controlled_relaunch_start_url ??
      input.url ??
      input.target_url,
  );
  return /^https?:\/\//i.test(value ?? "") ? value : null;
}

function controlledRelaunchHeadless(input) {
  const value =
    booleanValue(input.controlled_relaunch_headless) ??
    booleanValue(input.browser_launch_headless);
  return value ?? false;
}

function stringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => stringValue(item)).filter(Boolean);
}

function stringValue(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function booleanValue(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
  }
  return null;
}

function compactValues(values) {
  return values.filter(Boolean);
}

function safeId(value) {
  return String(value ?? "id")
    .replace(/[^a-zA-Z0-9_.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80) || "id";
}

function stableHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
