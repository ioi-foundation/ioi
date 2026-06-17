#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-computer-use-replay-timeline-proof.mjs <output-path>");
}

const { buildWorkflowComputerUseReplayTimeline } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-computer-use-replay-timeline.ts"
);

const workflowGraphId = "workflow.react-flow.computer-use-replay-timeline";
const threadId = "thread-computer-use-replay-timeline";
const RAW_SCREENSHOT_CANARY = "RAW_SCREENSHOT_BYTES_MUST_NOT_ENTER_REPLAY_TIMELINE";

function computerUseEvent({ id, seq, lane, eventKind, step, payload = {} }) {
  return {
    event_id: id,
    seq,
    thread_id: threadId,
    threadId,
    workflow_graph_id: workflowGraphId,
    workflowGraphId,
    workflow_node_id: `runtime.${lane}.${step}`,
    workflowNodeId: `runtime.${lane}.${step}`,
    event_kind: eventKind,
    eventKind,
    status: "completed",
    component_kind: "computer_use_harness",
    componentKind: "computer_use_harness",
    receipt_refs: [`receipt_${id}`],
    receiptRefs: [`receipt_${id}`],
    artifact_refs: [],
    artifactRefs: [],
    policy_decision_refs: payload.computer_use_policy_decision_ref
      ? [payload.computer_use_policy_decision_ref]
      : [],
    policyDecisionRefs: payload.computer_use_policy_decision_ref
      ? [payload.computer_use_policy_decision_ref]
      : [],
    payload_summary: {
      event_kind: eventKind,
      computer_use_lane: lane,
      computer_use_step: step,
      redaction: "computer_use_trace_safe",
      ...payload,
    },
  };
}

function laneEvents({ lane, seqStart, actionKind, approvalRef = null }) {
  const label = lane.replace(/_/g, "-");
  const screenshotRef = `artifact:${label}:screenshot-redacted`;
  const somRef = `artifact:${label}:som-overlay`;
  const axRef = `artifact:${label}:ax-tree`;
  const targetIndexRef = `target-index-${label}`;
  const affordanceGraphRef = `affordance-${label}`;
  const proposalRef = `proposal-${label}-${actionKind}`;
  const actionRef = `action-${label}-${actionKind}`;
  const verificationRef = `verification-${label}`;
  const cleanupRef = `cleanup-${label}`;
  return [
    computerUseEvent({
      id: `event-${label}-observe`,
      seq: seqStart,
      lane,
      eventKind: "computer_use.observation",
      step: "observe",
      payload: {
        computer_use_observation_ref: `observation-${label}`,
        computer_use_target_index_ref: targetIndexRef,
        observation_bundle: {
          lane,
          observation_ref: `observation-${label}`,
          screenshot_ref: screenshotRef,
          som_ref: somRef,
          ax_ref: axRef,
          target_index_ref: targetIndexRef,
          screenshot_base64: RAW_SCREENSHOT_CANARY,
          targets: [
            { target_ref: `target-${label}-primary`, label: "Primary target" },
            { target_ref: `target-${label}-secondary`, label: "Secondary target" },
          ],
        },
        target_index: {
          target_index_ref: targetIndexRef,
          targets: [
            { target_ref: `target-${label}-primary`, label: "Primary target" },
            { target_ref: `target-${label}-secondary`, label: "Secondary target" },
          ],
        },
      },
    }),
    computerUseEvent({
      id: `event-${label}-affordance`,
      seq: seqStart + 1,
      lane,
      eventKind: "computer_use.affordance_graph",
      step: "build_affordance_graph",
      payload: {
        computer_use_affordance_graph_ref: affordanceGraphRef,
        affordance_graph: {
          graph_ref: affordanceGraphRef,
          affordances: [
            {
              affordance_ref: `affordance-${label}-inspect`,
              target_ref: `target-${label}-primary`,
              possible_action: "inspect",
            },
            {
              affordance_ref: `affordance-${label}-${actionKind}`,
              target_ref: `target-${label}-secondary`,
              possible_action: actionKind,
            },
          ],
        },
      },
    }),
    computerUseEvent({
      id: `event-${label}-proposal`,
      seq: seqStart + 2,
      lane,
      eventKind: "computer_use.action_proposed",
      step: "propose_action",
      payload: {
        computer_use_proposal_ref: proposalRef,
        computer_use_action_ref: actionRef,
        computer_use_target_ref: `target-${label}-secondary`,
        computer_use_policy_decision_ref: approvalRef ?? `policy-${label}-read-only`,
      },
    }),
    computerUseEvent({
      id: `event-${label}-verification`,
      seq: seqStart + 3,
      lane,
      eventKind: "computer_use.verification",
      step: "verify_postcondition",
      payload: {
        computer_use_action_ref: actionRef,
        computer_use_verification_ref: verificationRef,
      },
    }),
    computerUseEvent({
      id: `event-${label}-cleanup`,
      seq: seqStart + 4,
      lane,
      eventKind: "computer_use.cleanup",
      step: "cleanup",
      payload: {
        computer_use_cleanup_ref: cleanupRef,
      },
    }),
  ];
}

const events = [
  ...laneEvents({ lane: "native_browser", seqStart: 1, actionKind: "inspect" }),
  ...laneEvents({
    lane: "visual_gui",
    seqStart: 6,
    actionKind: "click",
    approvalRef: "approval-visual-gui-run-button",
  }),
];

const timeline = buildWorkflowComputerUseReplayTimeline(events, { workflowGraphId });
const nativeTimeline = buildWorkflowComputerUseReplayTimeline(events, {
  workflowGraphId,
  lane: "native_browser",
});
const visualTimeline = buildWorkflowComputerUseReplayTimeline(events, {
  workflowGraphId,
  lane: "visual_gui",
});
const legacyAliasTimeline = buildWorkflowComputerUseReplayTimeline(
  [
    {
      id: "legacy-only-computer-use-event",
      seq: 11,
      thread_id: threadId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: "runtime.native_browser.cleanup",
      event_kind: "computer_use.cleanup",
      payload_summary: {
        event_kind: "computer_use.cleanup",
        computer_use_lane: "native_browser",
        computer_use_step: "cleanup",
      },
    },
  ],
  { workflowGraphId },
);
const retiredEvidenceAliasTimeline = buildWorkflowComputerUseReplayTimeline(
  [
    {
      event_id: "event-retired-evidence-aliases",
      seq: 12,
      thread_id: threadId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: "runtime.native_browser.proposal",
      event_kind: "computer_use.action_proposed",
      receiptRefs: ["receipt-retired-event-alias"],
      policyDecisionRefs: ["policy-retired-event-alias"],
      artifactRefs: ["artifact-retired-event-alias"],
      payload_summary: {
        event_kind: "computer_use.action_proposed",
        computer_use_lane: "native_browser",
        computer_use_step: "propose_action",
        receiptRefs: ["receipt-retired-payload-alias"],
        policyDecisionRefs: ["policy-retired-payload-alias"],
        computerUsePolicyDecisionRef: "policy-retired-scalar-alias",
      },
    },
  ],
  { workflowGraphId },
);
const retiredIdentityKindAliasTimeline = buildWorkflowComputerUseReplayTimeline(
  [
    {
      event_id: "event-retired-kind-alias",
      seq: 13,
      threadId: "thread-retired-kind-alias",
      workflowGraphId: workflowGraphId,
      workflowNodeId: "runtime.native_browser.retired-kind",
      eventKind: "computer_use.cleanup",
      payload_summary: {
        eventKind: "computer_use.cleanup",
        computer_use_lane: "native_browser",
        computer_use_step: "cleanup",
        workflowGraphId: workflowGraphId,
      },
    },
  ],
  { workflowGraphId },
);
const retiredIdentityFieldAliasTimeline = buildWorkflowComputerUseReplayTimeline(
  [
    {
      event_id: "event-retired-identity-field-aliases",
      seq: 14,
      threadId: "thread-retired-identity",
      workflowGraphId: workflowGraphId,
      workflowNodeId: "runtime.native_browser.retired-identity",
      event_kind: "computer_use.cleanup",
      payload_summary: {
        event_kind: "computer_use.cleanup",
        computer_use_lane: "native_browser",
        computer_use_step: "cleanup",
        workflowGraphId: workflowGraphId,
      },
    },
  ],
  { workflowGraphId },
);
const retiredArtifactRefAliasTimeline = buildWorkflowComputerUseReplayTimeline(
  [
    {
      event_id: "event-retired-artifact-ref-aliases",
      seq: 15,
      thread_id: threadId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: "runtime.native_browser.retired-artifacts",
      event_kind: "computer_use.observation",
      payload_summary: {
        event_kind: "computer_use.observation",
        computer_use_lane: "native_browser",
        computer_use_step: "observe",
        computerUseObservationRef: "observation-retired-payload-alias",
        computerUseScreenRef: "artifact:retired:screen",
        computerUseSomRef: "artifact:retired:som",
        computerUseAxRef: "artifact:retired:ax",
        computerUseTargetIndexRef: "target-index-retired-payload-alias",
        computerUseAffordanceGraphRef: "affordance-retired-payload-alias",
        observationBundle: {
          observationRef: "observation-retired-bundle-alias",
          screenshotRef: "artifact:retired:bundle-screen",
          somRef: "artifact:retired:bundle-som",
          axRef: "artifact:retired:bundle-ax",
          targetIndexRef: "target-index-retired-bundle-alias",
          targets: [{ targetRef: "target-retired-alias" }],
        },
        targetIndex: {
          targetIndexRef: "target-index-retired-object-alias",
          targets: [{ targetRef: "target-retired-object-alias" }],
        },
        affordanceGraph: {
          graphRef: "affordance-retired-object-alias",
          affordances: [{ affordanceRef: "affordance-retired-alias" }],
        },
      },
    },
  ],
  { workflowGraphId },
);
const retiredControlAliasTimeline = buildWorkflowComputerUseReplayTimeline(
  [
    {
      event_id: "event-retired-control-aliases",
      seq: 16,
      thread_id: threadId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: "runtime.native_browser.retired-control",
      event_kind: "computer_use.action_proposed",
      payload_summary: {
        event_kind: "computer_use.action_proposed",
        computerUseLane: "retired_lane",
        computerUseStep: "retired_step",
        computerUseProposalRef: "proposal-retired",
        computerUseActionRef: "action-retired",
        computerUseVerificationRef: "verification-retired",
        computerUseCommitGateRef: "commit-gate-retired",
        computerUseTrajectoryRef: "trajectory-retired",
        computerUseCleanupRef: "cleanup-retired",
      },
    },
  ],
  { workflowGraphId },
);

assert.equal(timeline.status, "ready");
assert.equal(timeline.frameCount, 10);
assert.deepEqual(timeline.lanes, ["native_browser", "visual_gui"]);
assert.equal(timeline.replayRange.firstSeq, 1);
assert.equal(timeline.replayRange.lastSeq, 10);
assert.equal(timeline.scrubber.scrubbable, true);
assert.equal(timeline.scrubber.rawScreenshotBytesIncluded, false);
assert.equal(nativeTimeline.frameCount, 5);
assert.equal(visualTimeline.frameCount, 5);
assert.ok(timeline.screenshotRefs.includes("artifact:native-browser:screenshot-redacted"));
assert.ok(timeline.screenshotRefs.includes("artifact:visual-gui:screenshot-redacted"));
assert.ok(timeline.targetIndexRefs.includes("target-index-native-browser"));
assert.ok(timeline.affordanceGraphRefs.includes("affordance-visual-gui"));
assert.equal(timeline.frames.filter((frame) => frame.step === "observe").length, 2);
assert.ok(timeline.frames.filter((frame) => frame.step === "observe").every((frame) => frame.displayMode === "artifact_ref_only"));
assert.ok(timeline.frames.filter((frame) => frame.step === "observe").every((frame) => frame.sourceHadRawScreenshot));
assert.ok(timeline.frames.some((frame) => frame.policyDecisionRef === "approval-visual-gui-run-button"));
assert.ok(timeline.frames.every((frame) => frame.redaction === "computer_use_trace_safe"));
assert.ok(!JSON.stringify(timeline).includes(RAW_SCREENSHOT_CANARY));
assert.equal(legacyAliasTimeline.frames[0]?.eventId, null);
assert.equal(retiredEvidenceAliasTimeline.frames[0]?.policyDecisionRef, null);
assert.deepEqual(retiredEvidenceAliasTimeline.frames[0]?.receiptRefs, []);
assert.deepEqual(retiredEvidenceAliasTimeline.frames[0]?.policyDecisionRefs, []);
assert.deepEqual(retiredEvidenceAliasTimeline.frames[0]?.artifactRefs, []);
assert.equal(retiredIdentityKindAliasTimeline.frameCount, 0);
assert.equal(retiredIdentityFieldAliasTimeline.frames[0]?.threadId, null);
assert.equal(retiredIdentityFieldAliasTimeline.frames[0]?.workflowGraphId, null);
assert.equal(retiredIdentityFieldAliasTimeline.frames[0]?.workflowNodeId, null);
assert.equal(retiredArtifactRefAliasTimeline.frames[0]?.observationRef, null);
assert.equal(retiredArtifactRefAliasTimeline.frames[0]?.screenshotRef, null);
assert.equal(retiredArtifactRefAliasTimeline.frames[0]?.somRef, null);
assert.equal(retiredArtifactRefAliasTimeline.frames[0]?.axRef, null);
assert.equal(retiredArtifactRefAliasTimeline.frames[0]?.targetIndexRef, null);
assert.equal(retiredArtifactRefAliasTimeline.frames[0]?.affordanceGraphRef, null);
assert.equal(retiredArtifactRefAliasTimeline.frames[0]?.targetCount, 0);
assert.equal(retiredArtifactRefAliasTimeline.frames[0]?.affordanceCount, 0);
assert.deepEqual(retiredArtifactRefAliasTimeline.frames[0]?.artifactRefs, []);
assert.equal(retiredControlAliasTimeline.frameCount, 1);
assert.equal(retiredControlAliasTimeline.frames[0]?.lane, null);
assert.equal(retiredControlAliasTimeline.frames[0]?.step, "action_proposed");
assert.equal(retiredControlAliasTimeline.frames[0]?.proposalRef, null);
assert.equal(retiredControlAliasTimeline.frames[0]?.actionRef, null);
assert.equal(retiredControlAliasTimeline.frames[0]?.verificationRef, null);
assert.equal(retiredControlAliasTimeline.frames[0]?.commitGateRef, null);
assert.equal(retiredControlAliasTimeline.frames[0]?.trajectoryRef, null);
assert.equal(retiredControlAliasTimeline.frames[0]?.cleanupRef, null);

const proof = {
  schemaVersion: "ioi.autopilot.stage18.computer-use-replay-timeline-proof.v1",
  passed: true,
  workflowGraphId,
  threadId,
  checks: {
    timelineReady: timeline.status === "ready",
    nativeAndVisualLanesPresent: timeline.lanes.includes("native_browser") && timeline.lanes.includes("visual_gui"),
    replayRangeOrdered: timeline.replayRange.firstSeq === 1 && timeline.replayRange.lastSeq === 10,
    screenshotRefsOnly: timeline.scrubber.rawScreenshotBytesIncluded === false,
    rawScreenshotCanaryScrubbed: !JSON.stringify(timeline).includes(RAW_SCREENSHOT_CANARY),
    observationFramesAreArtifactRefs: timeline.frames
      .filter((frame) => frame.step === "observe")
      .every((frame) => frame.displayMode === "artifact_ref_only" && Boolean(frame.screenshotRef)),
    targetAndAffordanceRefsPresent:
      timeline.targetIndexRefs.length === 2 && timeline.affordanceGraphRefs.length === 2,
    visualApprovalVisible: timeline.frames.some((frame) => frame.policyDecisionRef === "approval-visual-gui-run-button"),
    legacyEventIdAliasIgnored: legacyAliasTimeline.frames[0]?.eventId === null,
    retiredEvidenceAliasesIgnored:
      retiredEvidenceAliasTimeline.frames[0]?.policyDecisionRef === null &&
      retiredEvidenceAliasTimeline.frames[0]?.receiptRefs.length === 0 &&
      retiredEvidenceAliasTimeline.frames[0]?.policyDecisionRefs.length === 0 &&
      retiredEvidenceAliasTimeline.frames[0]?.artifactRefs.length === 0,
    retiredIdentityAliasesIgnored:
      retiredIdentityKindAliasTimeline.frameCount === 0 &&
      retiredIdentityFieldAliasTimeline.frames[0]?.threadId === null &&
      retiredIdentityFieldAliasTimeline.frames[0]?.workflowGraphId === null &&
      retiredIdentityFieldAliasTimeline.frames[0]?.workflowNodeId === null,
    retiredArtifactRefAliasesIgnored:
      retiredArtifactRefAliasTimeline.frames[0]?.observationRef === null &&
      retiredArtifactRefAliasTimeline.frames[0]?.screenshotRef === null &&
      retiredArtifactRefAliasTimeline.frames[0]?.somRef === null &&
      retiredArtifactRefAliasTimeline.frames[0]?.axRef === null &&
      retiredArtifactRefAliasTimeline.frames[0]?.targetIndexRef === null &&
      retiredArtifactRefAliasTimeline.frames[0]?.affordanceGraphRef === null &&
      retiredArtifactRefAliasTimeline.frames[0]?.targetCount === 0 &&
      retiredArtifactRefAliasTimeline.frames[0]?.affordanceCount === 0 &&
      retiredArtifactRefAliasTimeline.frames[0]?.artifactRefs.length === 0,
    retiredControlAliasesIgnored:
      retiredControlAliasTimeline.frameCount === 1 &&
      retiredControlAliasTimeline.frames[0]?.lane === null &&
      retiredControlAliasTimeline.frames[0]?.step === "action_proposed" &&
      retiredControlAliasTimeline.frames[0]?.proposalRef === null &&
      retiredControlAliasTimeline.frames[0]?.actionRef === null &&
      retiredControlAliasTimeline.frames[0]?.verificationRef === null &&
      retiredControlAliasTimeline.frames[0]?.commitGateRef === null &&
      retiredControlAliasTimeline.frames[0]?.trajectoryRef === null &&
      retiredControlAliasTimeline.frames[0]?.cleanupRef === null,
  },
  summary: {
    frameCount: timeline.frameCount,
    lanes: timeline.lanes,
    screenshotRefs: timeline.screenshotRefs,
    targetIndexRefs: timeline.targetIndexRefs,
    affordanceGraphRefs: timeline.affordanceGraphRefs,
    replayRange: timeline.replayRange,
  },
  timeline,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
