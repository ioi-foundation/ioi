import assert from "node:assert/strict";
import {
  buildInstallExecutionTranscript,
  testOnlyInstallExecutionTranscript,
} from "./installExecutionTranscript.ts";

const receiptSummary =
  "RoutingReceipt(step=0, tier=host, tool=software_install__execute_plan, decision=require_approval, stop=false, policy_hash=abc, verify=[software_install.stage=resolved, software_install.display_name=Example App, software_install.platform=linux, software_install.architecture=x86_64, software_install.source_kind=manual_installer, software_install.manager=apt-get, software_install.package_id=example-app, software_install.requires_elevation=true, software_install.verification=example-app --version, software_install.command=not_available])";

const parsed =
  testOnlyInstallExecutionTranscript.parseInstallResolutionFromText(receiptSummary);
assert.equal(parsed.display_name, "Example App");
assert.equal(parsed.platform, "linux");
assert.equal(parsed.requires_elevation, "true");

const terminalReceipt =
  "Task failed: ERROR_CLASS=InstallerResolutionRequired Resolved 'Example App' for linux x86_64 as an official manual installer source (https://example.test), but no verified unattended installer candidate passed policy for manager 'apt-get'. SOFTWARE_INSTALL display_name='Example App' canonical_id='example-app' target_kind='desktop_app' source_kind='manual_installer' source_discovery_url='https://example.test' verification='example-app --version' SOFTWARE_INSTALL stage='unsupported' display_name='Example App' manager='apt-get' source_kind='manual_installer'";
const parsedTerminal =
  testOnlyInstallExecutionTranscript.parseInstallResolutionFromText(terminalReceipt);
assert.equal(parsedTerminal.display_name, "Example App");
assert.equal(parsedTerminal.stage, "unsupported");
assert.equal(parsedTerminal.source_discovery_url, "https://example.test");

const gatedTranscript = buildInstallExecutionTranscript({
  id: "task-install",
  intent: "install example app",
  phase: "Gate",
  current_step: "Awaiting install approval: Example App",
  history: [
    {
      role: "system",
      text: receiptSummary,
      timestamp: 1,
    },
  ],
  events: [],
  gate_info: {
    title: "Approve software install",
    description:
      "Resolved Example App for linux x86_64 as manual_installer via apt-get.",
    risk: "high",
    approve_label: "Approve install",
    deny_label: "Deny",
    surface_label: "Host system",
    scope_label: "Software install",
    operation_label: "Install",
    target_label: "Example App",
    operator_note: "Approval permits the resolved installer command to run.",
  },
} as any);

assert.ok(gatedTranscript);
assert.equal(gatedTranscript?.status, "blocked");
assert.match(gatedTranscript?.content ?? "", /# install example app: awaiting approval/);
assert.match(gatedTranscript?.content ?? "", /target: Example App/);
assert.match(gatedTranscript?.content ?? "", /command: not_available/);
assert.match(gatedTranscript?.content ?? "", /verify: example-app --version/);
assert.doesNotMatch(
  gatedTranscript?.content ?? "",
  /state:/,
  "install terminal transcript should not echo task.current_step as command output",
);

const appImageApprovalTranscript = buildInstallExecutionTranscript({
  id: "task-install-appimage",
  intent: "install example app",
  phase: "Gate",
  current_step: "Awaiting install approval: Example App via appimage (appimage)",
  history: [
    {
      role: "system",
      text:
        "RoutingReceipt(step=0, tier=host, tool=software_install__execute_plan, decision=require_approval, stop=false, policy_hash=abc, verify=[software_install.stage=resolved, software_install.display_name=Example App, software_install.platform=linux, software_install.architecture=x86_64, software_install.source_kind=appimage, software_install.manager=appimage, software_install.package_id=example-app.AppImage, software_install.requires_elevation=false, software_install.verification=sh -lc test -x \"$HOME/.local/bin/example-app.AppImage\", software_install.source_discovery_url=https://example.test, software_install.command=bash -lc /tmp/install-example-app.sh])",
      timestamp: 1,
    },
  ],
  events: [],
  gate_info: {
    title: "Approve software install",
    description:
      "Resolved Example App for linux x86_64 as appimage via appimage.",
    risk: "high",
    target_label: "Example App",
  },
} as any);

assert.ok(appImageApprovalTranscript);
assert.equal(appImageApprovalTranscript?.status, "blocked");
assert.match(appImageApprovalTranscript?.content ?? "", /source: appimage via appimage/);
assert.match(
  appImageApprovalTranscript?.content ?? "",
  /discover: https:\/\/example\.test/,
);
assert.doesNotMatch(
  appImageApprovalTranscript?.content ?? "",
  /download\/latest\/linux\/x64/,
);

const seededRouteTranscript = buildInstallExecutionTranscript({
  id: "task-install-seeded",
  intent: "install lmstudio",
  phase: "Running",
  current_step: "Scheduling first step...",
  history: [],
  events: [],
  chat_outcome: {
    decisionEvidence: [
      "local_install_requested",
      "desktop_app_install_requested",
      "software_install_capability_required",
      "software_install_target_text:example app",
    ],
  },
} as any);

assert.equal(
  seededRouteTranscript,
  null,
  "seeded route evidence and infrastructure current_step alone must not fabricate an install terminal transcript",
);

const failedTerminalTranscript = buildInstallExecutionTranscript({
  id: "task-install-terminal",
  intent: "install example app",
  phase: "Failed",
  current_step: terminalReceipt,
  history: [{ role: "system", text: terminalReceipt, timestamp: 1 }],
  events: [],
  chat_outcome: {
    decisionEvidence: [
      "local_install_requested",
      "desktop_app_install_requested",
      "software_install_capability_required",
      "software_install_target_text:example app",
    ],
  },
} as any);

assert.ok(failedTerminalTranscript);
assert.equal(failedTerminalTranscript?.status, "failed");
assert.match(failedTerminalTranscript?.content ?? "", /# install example app: failed/);
assert.match(failedTerminalTranscript?.content ?? "", /source: manual_installer via apt-get/);
assert.match(failedTerminalTranscript?.content ?? "", /discover: https:\/\/example.test/);
assert.match(failedTerminalTranscript?.content ?? "", /error_class: InstallerResolutionRequired/);

const alreadyInstalledTranscript = buildInstallExecutionTranscript({
  id: "task-install-already",
  intent: "install example app",
  phase: "Complete",
  current_step:
    "Already installed: 'Example App' is present before host mutation; verification passed. SOFTWARE_INSTALL stage='already_installed' display_name='Example App' canonical_id='example-app' target_kind='desktop_app' source_kind='manual_installer' manager='apt-get' package_id='example-app' verification='example-app --version' command='skipped_already_installed'",
  history: [
    {
      role: "system",
      text: receiptSummary,
      timestamp: 1,
    },
    {
      role: "tool",
      text:
        "Tool Output (software_install__execute_plan): Already installed: 'Example App' is present before host mutation; verification passed. SOFTWARE_INSTALL stage='already_installed' display_name='Example App' canonical_id='example-app' target_kind='desktop_app' source_kind='manual_installer' manager='apt-get' package_id='example-app' verification='example-app --version' command='skipped_already_installed'",
      timestamp: 2,
    },
  ],
  events: [],
  chat_outcome: {
    decisionEvidence: [
      "local_install_requested",
      "desktop_app_install_requested",
      "software_install_capability_required",
      "software_install_target_text:example app",
    ],
  },
} as any);

assert.ok(alreadyInstalledTranscript);
assert.equal(alreadyInstalledTranscript?.status, "complete");
assert.match(alreadyInstalledTranscript?.content ?? "", /# install example app: complete/);
assert.match(alreadyInstalledTranscript?.content ?? "", /command: skipped_already_installed/);
assert.doesNotMatch(
  alreadyInstalledTranscript?.content ?? "",
  /blocker:/,
  "already installed verifier receipts should not retain stale resolver blockers",
);

const runningTranscript = buildInstallExecutionTranscript({
  id: "task-install-running",
  intent: "install media tool",
  phase: "Running",
  current_step: "Streaming software_install__execute_plan (stdout) . unpacking media tool",
  history: [
    {
      role: "system",
      text: receiptSummary.split("Example App").join("Media Tool"),
      timestamp: 1,
    },
  ],
  events: [
    {
      event_id: "evt-stream",
      timestamp: "now",
      thread_id: "task-install-running",
      step_index: 1,
      event_type: "COMMAND_STREAM",
      title: "Streaming software_install__execute_plan (stdout)",
      digest: {
        tool_name: "software_install__execute_plan",
        channel: "stdout",
        stream_id: "software_install__execute_plan",
      },
      details: {
        chunk: "Reading package lists...\nUnpacking media tool...\n",
      },
      artifact_refs: [],
      receipt_ref: null,
      input_refs: [],
      status: "PARTIAL",
      duration_ms: null,
    },
  ],
} as any);

assert.ok(runningTranscript);
assert.equal(runningTranscript?.status, "running");
assert.match(runningTranscript?.content ?? "", /\$ software_install__execute_plan/);
assert.match(runningTranscript?.content ?? "", /\[stdout\] Reading package lists/);
assert.match(runningTranscript?.content ?? "", /\[stdout\] Unpacking media tool/);
assert.doesNotMatch(runningTranscript?.content ?? "", /state:/);

const gateCopyOnlyTranscript = buildInstallExecutionTranscript({
  id: "task-copy-only",
  intent: "what is this notification?",
  phase: "Gate",
  current_step: "Approval required",
  history: [],
  events: [],
  gate_info: {
    title: "Approve software install",
    description: "Approval is required.",
    risk: "high",
  },
} as any);

assert.equal(gateCopyOnlyTranscript, null);

const directAnswerTranscript = buildInstallExecutionTranscript({
  id: "task-direct",
  intent: "what is 2+2",
  phase: "Complete",
  current_step: "Ready for input",
  history: [{ role: "agent", text: "4", timestamp: 1 }],
  events: [],
} as any);

assert.equal(directAnswerTranscript, null);
