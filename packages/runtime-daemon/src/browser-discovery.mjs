import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import os from "node:os";

export const COMPUTER_USE_BROWSER_DISCOVERY_SCHEMA_VERSION =
  "ioi.computer-use.browser-discovery.v1";

const BROWSER_FAMILIES = [
  {
    family: "chrome",
    patterns: ["google-chrome", "google chrome", "chrome", "chrome.exe"],
  },
  {
    family: "chromium",
    patterns: ["chromium", "chromium-browser", "chromium.exe"],
  },
  {
    family: "brave",
    patterns: ["brave", "brave-browser", "brave.exe"],
  },
  {
    family: "edge",
    patterns: ["microsoft-edge", "msedge", "edge.exe"],
  },
  {
    family: "vivaldi",
    patterns: ["vivaldi", "vivaldi-bin", "vivaldi.exe"],
  },
];

export async function discoverComputerUseBrowsers(options = {}) {
  const rows = options.processRows ?? listBrowserProcessRows();
  const report = browserDiscoveryReportFromProcessRows(rows, options);
  if (options.includeCdpProbe === false) return report;
  const cdpEndpoints = [];
  for (const endpoint of report.cdp_endpoints) {
    cdpEndpoints.push(await probeCdpEndpoint(endpoint, options));
  }
  return finalizeBrowserDiscoveryReport({
    ...report,
    cdp_endpoints: cdpEndpoints,
    cdp_endpoint_count: cdpEndpoints.length,
    safety: {
      ...report.safety,
      cdp_probe_enabled: true,
    },
  });
}

export function discoverComputerUseBrowsersSync(options = {}) {
  const rows = options.processRows ?? listBrowserProcessRows();
  return browserDiscoveryReportFromProcessRows(rows, {
    ...options,
    includeCdpProbe: false,
  });
}

export function browserDiscoveryReportFromProcessRows(rows, options = {}) {
  const platform = options.platform ?? os.platform();
  const discoveredAt = options.discoveredAt ?? new Date().toISOString();
  const processes = rows
    .map((row) => parseBrowserProcessRow(row, { platform }))
    .filter((process) => process && !process.is_browser_child_process);
  const cdpEndpoints = cdpEndpointsForBrowserProcesses(processes);
  return finalizeBrowserDiscoveryReport({
    schema_version: COMPUTER_USE_BROWSER_DISCOVERY_SCHEMA_VERSION,
    object: "ioi.computer_use.browser_discovery_report",
    receipt_ref: discoveryReceiptRef({
      discoveredAt,
      platform,
      processes,
      cdpEndpoints,
    }),
    discovered_at: discoveredAt,
    platform,
    process_count: rows.length,
    browser_process_count: processes.length,
    browser_processes: processes,
    cdp_endpoint_count: cdpEndpoints.length,
    cdp_endpoints: cdpEndpoints,
    default_profile_remote_debugging_blockers:
      defaultProfileRemoteDebuggingBlockers(processes),
    safety: {
      read_only: true,
      mutated_browser_state: false,
      copied_profiles: false,
      copied_credentials: false,
      raw_profile_paths_redacted: true,
      raw_command_lines_redacted: true,
      cdp_probe_enabled: false,
      cdp_probe_scope: "declared_remote_debugging_ports_only",
    },
    recommended_next_steps: recommendedBrowserDiscoveryNextSteps(processes, cdpEndpoints),
  });
}

export function parseBrowserProcessRow(row, options = {}) {
  const text = String(row ?? "").trim();
  if (!text) return null;
  const platform = options.platform ?? os.platform();
  const parsed = platform === "win32"
    ? parseWindowsProcessRow(text)
    : parsePosixProcessRow(text);
  if (!parsed) return null;
  const family = browserFamilyForProcess(parsed.command, parsed.args);
  if (!family) return null;
  const flags = browserFlagSummary(parsed.args);
  const remoteDebuggingPort = browserFlagValue(
    parsed.args,
    "--remote-debugging-port",
  );
  const remoteDebuggingAddress =
    browserFlagValue(parsed.args, "--remote-debugging-address") ?? "127.0.0.1";
  const userDataDir = browserFlagValue(parsed.args, "--user-data-dir");
  const profileDirectory = browserFlagValue(parsed.args, "--profile-directory");
  const isChild = /\s--type=/.test(` ${parsed.args}`);
  const profilePathHash = userDataDir ? stableHash(userDataDir) : null;
  return {
    process_ref: `browser_process_${stableHash(`${parsed.pid}:${parsed.command}:${parsed.args}`).slice(0, 16)}`,
    pid: parsed.pid,
    ppid: parsed.ppid,
    command: parsed.command,
    browser_family: family,
    is_browser_child_process: isChild,
    has_remote_debugging_port: Boolean(remoteDebuggingPort),
    remote_debugging_port: safePositiveInteger(remoteDebuggingPort),
    remote_debugging_address: remoteDebuggingPort ? remoteDebuggingAddress : null,
    user_data_dir_present: Boolean(userDataDir),
    user_data_dir_hash: profilePathHash,
    profile_directory_present: Boolean(profileDirectory),
    profile_directory_hash: profileDirectory ? stableHash(profileDirectory) : null,
    profile_provenance: userDataDir
      ? "explicit_user_data_dir_redacted"
      : "implicit_default_profile_or_unknown",
    default_profile_cdp_refusal_risk:
      !userDataDir && Boolean(remoteDebuggingPort),
    cdp_status: remoteDebuggingPort
      ? "declared_not_probed"
      : "not_exposed",
    redacted_flags: flags,
  };
}

function listBrowserProcessRows() {
  const platform = os.platform();
  try {
    if (platform === "win32") {
      const output = execFileSync(
        "wmic",
        ["process", "get", "ProcessId,ParentProcessId,Name,CommandLine", "/FORMAT:CSV"],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
      );
      return output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    }
    const output = execFileSync(
      "ps",
      ["-eo", "pid=,ppid=,comm=,args="],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    );
    return output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function parsePosixProcessRow(text) {
  const match = text.match(/^(\d+)\s+(\d+)\s+(\S+)\s*(.*)$/);
  if (!match) return null;
  return {
    pid: Number(match[1]),
    ppid: Number(match[2]),
    command: match[3],
    args: match[4] ?? "",
  };
}

function parseWindowsProcessRow(text) {
  const parts = text.split(",");
  if (parts.length < 5 || parts[0] === "Node") return null;
  const pid = Number(parts[4]);
  const ppid = Number(parts[3]);
  return {
    pid,
    ppid,
    command: parts[2] || "",
    args: parts.slice(1, -3).join(",") || parts[2] || "",
  };
}

function browserFamilyForProcess(command, args) {
  const firstArg = String(args ?? "").trim().split(/\s+/)[0] ?? "";
  const haystack = `${command} ${firstArg}`.toLowerCase();
  for (const family of BROWSER_FAMILIES) {
    if (family.patterns.some((pattern) => haystack.includes(pattern))) {
      return family.family;
    }
  }
  return null;
}

function browserFlagValue(args, flag) {
  const escaped = flag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = String(args ?? "").match(
    new RegExp(`${escaped}(?:=|\\s+)(?:"([^"]+)"|'([^']+)'|(\\S+))`),
  );
  return match ? match[1] ?? match[2] ?? match[3] ?? null : null;
}

function browserFlagSummary(args) {
  const flags = [];
  for (const flag of [
    "--remote-debugging-port",
    "--remote-debugging-address",
    "--user-data-dir",
    "--profile-directory",
    "--app",
    "--headless",
  ]) {
    const value = browserFlagValue(args, flag);
    if (value === null) continue;
    const redactedValue =
      flag === "--user-data-dir" || flag === "--profile-directory" || flag === "--app"
        ? `sha256:${stableHash(value).slice(0, 16)}`
        : value;
    flags.push({ flag, value: redactedValue });
  }
  return flags;
}

function cdpEndpointsForBrowserProcesses(processes) {
  return processes
    .filter((process) => process.has_remote_debugging_port && process.remote_debugging_port)
    .map((process) => {
      const host = endpointHostForAddress(process.remote_debugging_address);
      const port = process.remote_debugging_port;
      return {
        endpoint_ref: `cdp_endpoint_${stableHash(`${process.process_ref}:${host}:${port}`).slice(0, 16)}`,
        process_ref: process.process_ref,
        pid: process.pid,
        browser_family: process.browser_family,
        host,
        port,
        endpoint_url: `http://${host}:${port}`,
        source: "remote_debugging_process_flag",
        status: "declared_not_probed",
        browser: null,
        protocol_version: null,
        tab_count: null,
        tabs: [],
      };
    });
}

async function probeCdpEndpoint(endpoint, options = {}) {
  const timeoutMs = safePositiveInteger(options.probeTimeoutMs) ?? 500;
  try {
    const version = await fetchJsonWithTimeout(
      `${endpoint.endpoint_url}/json/version`,
      timeoutMs,
    );
    const tabs = options.includeTabMetadata
      ? sanitizeCdpTabs(
          await fetchJsonWithTimeout(`${endpoint.endpoint_url}/json/list`, timeoutMs),
          { revealTitles: options.revealTabTitles === true },
        )
      : [];
    return {
      ...endpoint,
      status: "available",
      browser: stringOrNull(version?.Browser),
      protocol_version: stringOrNull(version?.["Protocol-Version"]),
      tab_count: tabs.length,
      tabs,
    };
  } catch (error) {
    return {
      ...endpoint,
      status: "unreachable",
      error_class: error?.name ?? "CdpProbeError",
      error_summary: String(error?.message ?? error).slice(0, 180),
    };
  }
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

function sanitizeCdpTabs(value, options = {}) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 20).map((tab) => {
    const url = stringOrNull(tab?.url);
    return {
      tab_ref: `cdp_tab_${stableHash(`${tab?.id ?? ""}:${url ?? ""}`).slice(0, 16)}`,
      type: stringOrNull(tab?.type),
      title: options.revealTitles ? stringOrNull(tab?.title) : null,
      title_hash: tab?.title ? stableHash(String(tab.title)) : null,
      url_origin: urlOrigin(url),
      url_hash: url ? stableHash(url) : null,
      attached: Boolean(tab?.webSocketDebuggerUrl),
    };
  });
}

function defaultProfileRemoteDebuggingBlockers(processes) {
  return processes
    .filter((process) => process.default_profile_cdp_refusal_risk)
    .map((process) => ({
      process_ref: process.process_ref,
      pid: process.pid,
      browser_family: process.browser_family,
      reason:
        "remote_debugging_port_declared_without_explicit_user_data_dir",
      recommended_branch:
        "request_consent_for_attach_or_controlled_relaunch_with_non_default_profile",
    }));
}

function recommendedBrowserDiscoveryNextSteps(processes, cdpEndpoints) {
  if (cdpEndpoints.length > 0) {
    return [
      "Request explicit consent before attaching to any exposed CDP endpoint.",
      "Use the endpoint only through the computer-use lease and receipt spine.",
    ];
  }
  if (processes.length > 0) {
    return [
      "No declared CDP endpoint was discovered.",
      "Offer owned browser or consented controlled relaunch instead of mutating the user browser.",
    ];
  }
  return [
    "No browser process was discovered.",
    "Use owned hermetic browser mode or ask the user to open a browser if attachment is required.",
  ];
}

function finalizeBrowserDiscoveryReport(report) {
  return {
    ...report,
    cdp_endpoint_count: report.cdp_endpoints.length,
    browser_process_count: report.browser_processes.length,
  };
}

function endpointHostForAddress(address) {
  if (!address || address === "0.0.0.0" || address === "::") return "127.0.0.1";
  return address;
}

function urlOrigin(url) {
  try {
    return url ? new URL(url).origin : null;
  } catch {
    return null;
  }
}

function stringOrNull(value) {
  return typeof value === "string" && value.trim() ? value : null;
}

function safePositiveInteger(value) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : null;
}

function discoveryReceiptRef({ discoveredAt, platform, processes, cdpEndpoints }) {
  return `receipt_computer_use_browser_discovery_${stableHash(
    JSON.stringify({
      discoveredAt,
      platform,
      processes: processes.map((process) => process.process_ref),
      cdpEndpoints: cdpEndpoints.map((endpoint) => endpoint.endpoint_ref),
    }),
  ).slice(0, 16)}`;
}

function stableHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}
