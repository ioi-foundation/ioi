import assert from "node:assert/strict";
import {
  buildInstallExecutionTranscript,
  testOnlyInstallExecutionTranscript,
} from "./installExecutionTranscript.ts";

const installResolution = {
  stage: "resolved",
  display_name: "Example App",
  canonical_id: "example-app",
  target_kind: "desktop_app",
  host: {
    platform: "linux",
    architecture: "x86_64",
  },
  source: {
    source_kind: "appimage",
    manager: "appimage",
    package_id: "example-app.AppImage",
    source_discovery_url: "https://example.test",
  },
  requires_elevation: false,
  command: "bash -lc /tmp/install-example-app.sh",
  verification: "test -x $HOME/.local/bin/example-app.AppImage",
  plan_ref: "software-install-plan:v2:test",
};

const flattened =
  testOnlyInstallExecutionTranscript.flattenInstallPayload(installResolution);
assert.equal(flattened.display_name, "Example App");
assert.equal(flattened.platform, "linux");
assert.equal(flattened.source_kind, "appimage");
assert.equal(flattened.requires_elevation, "false");

function event(overrides: Record<string, unknown> = {}) {
  return {
    event_id: "evt",
    timestamp: "now",
    thread_id: "task",
    step_index: 0,
    event_type: "COMMAND_RUN",
    title: "Install event",
    digest: {
      tool_name: "software_install__resolve",
    },
    details: {
      install_event: installResolution,
    },
    artifact_refs: [],
    receipt_ref: null,
    input_refs: [],
    status: "SUCCESS",
    duration_ms: null,
    ...overrides,
  };
}

const gatedTranscript = buildInstallExecutionTranscript({
  id: "task-install",
  intent: "install example app",
  phase: "Gate",
  current_step: "Awaiting install approval: Example App",
  history: [],
  events: [event()],
  gate_info: {
    title: "Approve software install",
    description:
      "Resolved Example App for linux x86_64 as appimage via appimage.",
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
assert.match(gatedTranscript?.content ?? "", /source: appimage via appimage/);
assert.match(gatedTranscript?.content ?? "", /command: bash -lc/);
assert.match(gatedTranscript?.content ?? "", /verify: test -x/);
assert.match(gatedTranscript?.content ?? "", /discover: https:\/\/example\.test/);
assert.doesNotMatch(gatedTranscript?.content ?? "", /state:/);

const seededRouteTranscript = buildInstallExecutionTranscript({
  id: "task-install-seeded",
  intent: "install lmstudio",
  phase: "Running",
  current_step: "Scheduling first step...",
  history: [],
  events: [],
  chat_outcome: {
    decisionEvidence: [
      "legacy installer route evidence",
      "software_install_capability_required",
    ],
  },
} as any);

assert.equal(
  seededRouteTranscript,
  null,
  "route evidence and current_step alone must not fabricate an install terminal transcript",
);

const legacyStringOnlyTranscript = buildInstallExecutionTranscript({
  id: "task-install-terminal",
  intent: "install example app",
  phase: "Failed",
  current_step: "Task failed: legacy installer stage marker",
  history: [
    {
      role: "system",
      text: "legacy installer display marker",
      timestamp: 1,
    },
  ],
  events: [],
} as any);

assert.equal(
  legacyStringOnlyTranscript,
  null,
  "legacy string receipts must not drive install process UI",
);

const alreadyInstalledTranscript = buildInstallExecutionTranscript({
  id: "task-install-already",
  intent: "install example app",
  phase: "Complete",
  current_step: "Task completed",
  history: [
    {
      role: "tool",
      text: `Tool Output (software_install__execute_plan): ${JSON.stringify({
        kind: "install_final_receipt",
        summary: "Example App is already installed.",
        install_final_receipt: {
          status: "already_installed_verified",
          display_name: "Example App",
          plan_ref: "software-install-plan:v2:test",
          verification: {
            summary: "example-app --version completed successfully",
          },
        },
      })}`,
      timestamp: 2,
    },
  ],
  events: [
    event({
      details: {
        install_final_receipt: {
          status: "already_installed_verified",
          display_name: "Example App",
          plan_ref: "software-install-plan:v2:test",
          verification: {
            summary: "example-app --version completed successfully",
          },
        },
      },
    }),
  ],
} as any);

assert.ok(alreadyInstalledTranscript);
assert.equal(alreadyInstalledTranscript?.status, "complete");
assert.match(alreadyInstalledTranscript?.content ?? "", /# install example app: complete/);
assert.match(
  alreadyInstalledTranscript?.content ?? "",
  /verify: example-app --version completed successfully/,
);
assert.doesNotMatch(alreadyInstalledTranscript?.content ?? "", /blocker:/);

const runningTranscript = buildInstallExecutionTranscript({
  id: "task-install-running",
  intent: "install media tool",
  phase: "Running",
  current_step: "Streaming command",
  history: [],
  events: [
    event({
      details: {
        install_event: {
          ...installResolution,
          display_name: "Media Tool",
        },
      },
    }),
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

const resolverReceiptTranscript = buildInstallExecutionTranscript({
  id: "task-install-resolver-receipt",
  intent: "install snorflepaint",
  phase: "Failed",
  current_step: "Install blocked: No verified install candidate",
  history: [],
  events: [
    event({
      status: "FAILED",
      details: {
        output: `ERROR_CLASS=InstallerResolutionRequired ${JSON.stringify({
          summary: "No verified install candidate passed resolver policy.",
          install_event: {
            stage: "unresolved",
            display_name: "snorflepaint",
            blocker: "No verified install candidate passed resolver policy.",
          },
        })}`,
        install_event: {
          stage: "unresolved",
          display_name: "snorflepaint",
          blocker: "No verified install candidate passed resolver policy.",
        },
      },
    }),
  ],
} as any);

assert.ok(resolverReceiptTranscript);
assert.match(resolverReceiptTranscript?.content ?? "", /blocker: No verified install candidate/);
assert.doesNotMatch(resolverReceiptTranscript?.content ?? "", /ERROR_CLASS=/);
assert.doesNotMatch(resolverReceiptTranscript?.content ?? "", /"install_event"/);

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
