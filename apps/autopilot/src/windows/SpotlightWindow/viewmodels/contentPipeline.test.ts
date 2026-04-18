import assert from "node:assert/strict";
import type {
  ActivityEventRef,
  AgentEvent,
  Artifact,
  ChatMessage,
  PlanSelectedSkill,
} from "../../../types";
import {
  buildRunPresentation,
  classifyActivityEvent,
  normalizeOutputForHash,
} from "./contentPipeline";
import { buildExecutionMoments } from "./contentPipeline.summaries";
import { parseChatContractEnvelope } from "./chatContract";

const BASE_TIMESTAMP = "2026-02-19T03:00:00Z";

const baseEvent: AgentEvent = {
  event_id: "evt-1",
  timestamp: BASE_TIMESTAMP,
  thread_id: "thread-a",
  step_index: 1,
  event_type: "COMMAND_RUN",
  title: "Ran chat__reply",
  digest: { tool_name: "chat__reply" },
  details: {
    output:
      "Top 3 stories\nCompletion reason: Completed after meeting the source floor.\nRun timestamp (UTC): 2026-02-19T02:59:18Z\nOverall confidence: medium\nhttps://example.com/a\nhttps://example.com/b",
  },
  artifact_refs: [],
  receipt_ref: null,
  input_refs: [],
  status: "SUCCESS",
  duration_ms: null,
};

function activityRefsFromEvents(events: AgentEvent[]): ActivityEventRef[] {
  return events.map((event) => ({
    key: event.event_id,
    kind:
      event.event_type === "RECEIPT"
        ? "receipt_event"
        : event.event_type === "INFO_NOTE"
          ? "reasoning_event"
          : "workload_event",
    event,
    toolName: String(event.digest?.tool_name || ""),
  }));
}

function expectedSelectedSkills(...ids: string[]): PlanSelectedSkill[] {
  return ids.map((id) => ({
    id,
    entryId: `skill:${id}`,
    label: id.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase()),
  }));
}

function classifyEventTest(): void {
  const receipt: AgentEvent = {
    ...baseEvent,
    event_id: "evt-r",
    event_type: "RECEIPT",
    title: "Receipt",
  };
  const reasoning: AgentEvent = {
    ...baseEvent,
    event_id: "evt-reasoning",
    event_type: "INFO_NOTE",
    title: "Captured reasoning step",
    digest: {},
  };

  assert.equal(classifyActivityEvent(receipt), "receipt_event");
  assert.equal(classifyActivityEvent(baseEvent), "primary_answer_event");
  assert.equal(classifyActivityEvent(reasoning), "reasoning_event");
}

function normalizeOutputTest(): void {
  const normalized = normalizeOutputForHash(
    "a  b   c | 2026-02-19T02:59:18Z | value",
  );
  assert.equal(normalized, "a b c |TIMESTAMP| value");
}

function dedupAndAnswerTest(): void {
  const duplicateAnswerDifferentStep: AgentEvent = {
    ...baseEvent,
    event_id: "evt-2",
    step_index: 2,
  };

  const history: ChatMessage[] = [
    { role: "user", text: "question", timestamp: Date.now() - 10_000 },
    {
      role: "agent",
      text: "final answer\nRun timestamp (UTC): 2026-02-19T03:00:00Z",
      timestamp: Date.now() - 1_000,
    },
  ];

  const presentation = buildRunPresentation(
    history,
    [baseEvent, duplicateAnswerDifferentStep],
    [],
  );
  assert.equal(presentation.prompt?.text, "question");
  assert.equal(
    presentation.finalAnswer?.message.text.includes("Top 3 stories"),
    true,
  );
  assert.equal(presentation.activityGroups.length, 1);
  assert.equal(presentation.activityGroups[0]?.events.length, 1);
}

function activitySummaryTest(): void {
  const searchEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-search",
    step_index: 2,
    event_type: "COMMAND_RUN",
    digest: { tool_name: "web__search" },
    details: { output: "ok" },
  };

  const readEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-read",
    step_index: 3,
    event_type: "COMMAND_RUN",
    digest: { tool_name: "web__read" },
    details: { output: "ok" },
  };

  const receiptEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-receipt",
    step_index: 4,
    event_type: "RECEIPT",
    title: "Receipt",
    digest: { tool_name: "web__read" },
  };

  const reasoningEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-reasoning",
    step_index: 5,
    event_type: "INFO_NOTE",
    title: "Captured reasoning step",
    digest: {},
    details: { output: "reasoning" },
  };

  const artifacts: Artifact[] = [
    {
      artifact_id: "art-1",
      created_at: BASE_TIMESTAMP,
      thread_id: "thread-a",
      artifact_type: "LOG",
      title: "Log",
      description: "",
      content_ref: "ioi-memory://artifact/art-1",
      metadata: {},
      version: 1,
      parent_artifact_id: null,
    },
  ];

  const presentation = buildRunPresentation(
    [],
    [searchEvent, readEvent, receiptEvent, reasoningEvent],
    artifacts,
  );

  assert.equal(presentation.activitySummary.searchCount, 1);
  assert.equal(presentation.activitySummary.readCount, 1);
  assert.equal(presentation.activitySummary.receiptCount, 1);
  assert.equal(presentation.activitySummary.reasoningCount, 1);
  assert.equal(presentation.activitySummary.artifactCount, 1);
  assert.equal(presentation.artifactRefs.length, 1);
}

function sourceSummaryTest(): void {
  const searchBundle = {
    schema_version: 1,
    retrieved_at_ms: 1771600000000,
    tool: "web__search",
    backend: "edge:ddg",
    query: "current weather Anderson South Carolina",
    sources: [
      {
        source_id: "s1",
        rank: 1,
        url: "https://weather.com/weather/today/l/Anderson+SC",
        title: "weather.com",
        domain: "weather.com",
      },
      {
        source_id: "s2",
        rank: 2,
        url: "https://www.accuweather.com/en/us/anderson/29624/current-weather/330677",
        title: "accuweather",
        domain: "accuweather.com",
      },
    ],
    documents: [],
  };

  const readBundle = {
    schema_version: 1,
    retrieved_at_ms: 1771600001000,
    tool: "web__read",
    backend: "edge:read",
    url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC",
    sources: [
      {
        source_id: "s3",
        rank: 1,
        url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC",
        title: "NWS Anderson",
        domain: "forecast.weather.gov",
      },
    ],
    documents: [
      {
        source_id: "s3",
        url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC",
        title: "NWS Anderson, SC",
        content_text: "ok",
        content_hash: "abc",
        quote_spans: [],
      },
    ],
  };

  const searchEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-web-search",
    step_index: 10,
    digest: { tool_name: "web__search" },
    details: {
      output: JSON.stringify(searchBundle, null, 2),
    },
  };

  const readEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-web-read",
    step_index: 11,
    digest: { tool_name: "web__read" },
    details: {
      output: JSON.stringify(readBundle, null, 2),
    },
  };

  const presentation = buildRunPresentation([], [searchEvent, readEvent], []);
  assert.ok(presentation.sourceSummary);
  assert.equal(presentation.sourceSummary?.totalSources, 3);
  assert.equal(presentation.sourceSummary?.searches.length, 1);
  assert.equal(presentation.sourceSummary?.browses.length, 1);
  assert.equal(
    presentation.sourceSummary?.searches[0]?.query,
    "current weather Anderson South Carolina",
  );
}

function sourceSummaryReceiptOnlyTest(): void {
  const searchBundle = {
    schema_version: 1,
    retrieved_at_ms: 1771600000000,
    tool: "web__search",
    backend: "edge:ddg",
    query: "weather right now near me",
    sources: [
      {
        source_id: "s1",
        rank: 1,
        url: "https://weather.com/weather/today/l/Anderson+SC",
        title: "weather.com",
        domain: "weather.com",
      },
    ],
    documents: [],
  };

  const readBundle = {
    schema_version: 1,
    retrieved_at_ms: 1771600001000,
    tool: "web__read",
    backend: "edge:read",
    url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC",
    sources: [
      {
        source_id: "s2",
        rank: 1,
        url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC",
        title: "NWS Anderson",
        domain: "forecast.weather.gov",
      },
    ],
    documents: [],
  };

  const searchReceipt: AgentEvent = {
    ...baseEvent,
    event_id: "evt-receipt-search",
    step_index: 12,
    event_type: "RECEIPT",
    title: "Receipt: web__search",
    digest: { tool_name: "web__search" },
    details: {
      output: JSON.stringify(searchBundle, null, 2),
    },
  };

  const readReceipt: AgentEvent = {
    ...baseEvent,
    event_id: "evt-receipt-read",
    step_index: 13,
    event_type: "RECEIPT",
    title: "Receipt: web__read",
    digest: { tool_name: "web__read" },
    details: {
      output: JSON.stringify(readBundle, null, 2),
    },
  };

  const presentation = buildRunPresentation(
    [],
    [searchReceipt, readReceipt],
    [],
  );
  assert.ok(presentation.sourceSummary);
  assert.equal(presentation.sourceSummary?.totalSources, 2);
  assert.equal(presentation.sourceSummary?.searches.length, 1);
  assert.equal(presentation.sourceSummary?.browses.length, 1);
}

function thoughtSummaryTest(): void {
  const workerReceipt: AgentEvent = {
    ...baseEvent,
    event_id: "evt-think-receipt",
    step_index: 20,
    event_type: "RECEIPT",
    title: "Research worker spawned",
    digest: {
      kind: "worker",
      role: "Research Worker",
      template_id: "researcher",
      workflow_id: "live_research_brief",
    },
    details: {
      step_label: "Gather sources",
    },
  };

  const reasoningEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-think-1",
    step_index: 20,
    event_type: "INFO_NOTE",
    title: "Captured reasoning step",
    digest: {},
    details: { output: "Compare source agreement and provide concise answer." },
  };

  const systemEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-think-2",
    step_index: 21,
    event_type: "INFO_NOTE",
    title: "System update: IntentResolver",
    digest: {
      kind: "worker",
      template_id: "verifier",
      workflow_id: "citation_audit",
    },
    details: { output: "Need direct answer with UTC timestamp and citations." },
  };

  const presentation = buildRunPresentation(
    [],
    [workerReceipt, reasoningEvent, systemEvent],
    [],
  );
  assert.ok(presentation.thoughtSummary);
  assert.equal(presentation.thoughtSummary?.agents.length, 2);
  assert.equal(
    presentation.thoughtSummary?.agents[0]?.agentLabel,
    "Research Worker",
  );
  assert.equal(
    presentation.thoughtSummary?.agents[0]?.agentRole,
    "Gather Sources",
  );
  assert.equal(presentation.thoughtSummary?.agents[0]?.agentKind, "worker");
  assert.equal(
    presentation.thoughtSummary?.agents[0]?.notes[0],
    "Compare source agreement and provide concise answer.",
  );
  assert.equal(presentation.thoughtSummary?.agents[1]?.agentLabel, "Verifier");
  assert.equal(
    presentation.thoughtSummary?.agents[1]?.agentRole,
    "Citation Audit",
  );
  assert.equal(presentation.thoughtSummary?.agents[1]?.agentKind, "verifier");
  assert.equal(presentation.finalAnswer, null);
}

function clarificationReasoningFallbackTest(): void {
  const history: ChatMessage[] = [
    { role: "user", text: "Summarize this repo briefly.", timestamp: Date.now() - 5_000 },
  ];

  const reasoningClarification: AgentEvent = {
    ...baseEvent,
    event_id: "evt-clarification-reasoning",
    step_index: 22,
    event_type: "INFO_NOTE",
    title: "Captured reasoning step",
    digest: {},
    details: {
      content:
        "To provide the correct function call, I need more details about the current goal and the history of actions taken so far. Could you please specify the goal and any relevant context or previous steps that have been executed?",
    },
  };

  const presentation = buildRunPresentation(history, [reasoningClarification], []);
  assert.ok(presentation.finalAnswer);
  assert.equal(
    presentation.finalAnswer?.displayText.includes("Could you please specify the goal"),
    true,
  );
}

function ordinaryReasoningDoesNotBecomeAnswerTest(): void {
  const history: ChatMessage[] = [
    { role: "user", text: "Summarize this repo briefly.", timestamp: Date.now() - 5_000 },
  ];

  const reasoningEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-plain-reasoning",
    step_index: 23,
    event_type: "INFO_NOTE",
    title: "Captured reasoning step",
    digest: {},
    details: {
      content: "Compare source agreement and provide concise answer.",
    },
  };

  const presentation = buildRunPresentation(history, [reasoningEvent], []);
  assert.equal(presentation.finalAnswer, null);
}

function planSummaryCapturesTypedHierarchyTest(): void {
  const parentPlaybookStarted: AgentEvent = {
    ...baseEvent,
    event_id: "evt-playbook-started",
    step_index: 40,
    event_type: "RECEIPT",
    title: "Parent playbook started",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__delegate",
      phase: "started",
      playbook_id: "evidence_audited_patch",
      playbook_label: "Evidence-Audited Patch",
      route_family: "coding",
      topology: "planner_specialist_verifier",
      planner_authority: "kernel",
      verifier_state: "queued",
      verifier_role: "test_verifier",
      status: "running",
      success: true,
    },
    details: {
      parent_session_id: "session-parent",
      verifier_outcome: "warning",
      summary: "Started parent playbook.",
    },
  };

  const codingWorkerSpawned: AgentEvent = {
    ...baseEvent,
    event_id: "evt-worker-coder",
    step_index: 41,
    event_type: "RECEIPT",
    title: "Coding worker spawned",
    digest: {
      kind: "worker",
      tool_name: "agent__delegate",
      phase: "spawned",
      role: "Coding Worker",
      template_id: "coder",
      workflow_id: "patch_build_verify",
      status: "running",
      success: true,
    },
    details: {
      child_session_id: "child-coder",
      parent_session_id: "session-parent",
      summary: "Patch worker is active.",
    },
  };

  const verifierMerged: AgentEvent = {
    ...baseEvent,
    event_id: "evt-worker-verifier",
    step_index: 42,
    event_type: "RECEIPT",
    title: "Verification worker merged",
    digest: {
      kind: "worker",
      tool_name: "agent__await",
      phase: "merged",
      role: "Verification Worker",
      template_id: "verifier",
      workflow_id: "postcondition_audit",
      status: "completed",
      success: true,
    },
    details: {
      child_session_id: "child-verifier",
      parent_session_id: "session-parent",
      summary: "Audit merged into the parent.",
    },
  };

  const approvalGate: AgentEvent = {
    ...baseEvent,
    event_id: "evt-approval",
    step_index: 43,
    event_type: "RECEIPT",
    title: "Routing receipt",
    digest: {
      tool_name: "file__write",
      policy_decision: "require_approval",
      status: "gate",
    },
    details: {
      status: "gate",
      output: "Waiting for approval",
    },
  };

  const parentPlaybookCompleted: AgentEvent = {
    ...baseEvent,
    event_id: "evt-playbook-complete",
    step_index: 44,
    event_type: "RECEIPT",
    title: "Parent playbook completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "completed",
      playbook_id: "evidence_audited_patch",
      playbook_label: "Evidence-Audited Patch",
      route_family: "coding",
      topology: "planner_specialist_verifier",
      planner_authority: "kernel",
      verifier_state: "passed",
      verifier_role: "test_verifier",
      verifier_outcome: "pass",
      status: "completed",
      success: true,
    },
    details: {
      parent_session_id: "session-parent",
      summary: "Completed parent playbook.",
    },
  };

  const presentation = buildRunPresentation(
    [],
    [
      parentPlaybookStarted,
      codingWorkerSpawned,
      verifierMerged,
      approvalGate,
      parentPlaybookCompleted,
    ],
    [],
  );

  assert.ok(presentation.planSummary);
  assert.equal(presentation.planSummary?.routeFamily, "coding");
  assert.equal(
    presentation.planSummary?.topology,
    "planner_specialist_verifier",
  );
  assert.equal(presentation.planSummary?.plannerAuthority, "kernel");
  assert.equal(presentation.planSummary?.workerCount, 2);
  assert.equal(presentation.planSummary?.branchCount, 2);
  assert.equal(presentation.planSummary?.activeWorkerLabel, "Coding Worker");
  assert.equal(presentation.planSummary?.verifierState, "passed");
  assert.equal(presentation.planSummary?.verifierRole, "test_verifier");
  assert.equal(presentation.planSummary?.verifierOutcome, "pass");
  assert.equal(presentation.planSummary?.approvalState, "pending");
  assert.equal(
    presentation.planSummary?.selectedRoute.includes("Evidence"),
    true,
  );
}

function streamedParentPlaybookRouteContractTest(): void {
  const streamedParentPlaybook: AgentEvent = {
    ...baseEvent,
    event_id: "evt-streamed-parent-playbook",
    step_index: 132,
    event_type: "RECEIPT",
    title: "Parent playbook completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "completed",
      playbook_id: "citation_grounded_brief",
      playbook_label: "Citation Grounded Brief",
      route_family: "research",
      topology: "planner_specialist_verifier",
      planner_authority: "kernel",
      verifier_state: "passed",
      verifier_role: "citation_verifier",
      verifier_outcome: "pass",
      status: "completed",
      success: true,
    },
    details: {
      parent_session_id: "session-research",
      planner_authority: "kernel",
      verifier_role: "citation_verifier",
      verifier_outcome: "pass",
      summary: "Completed citation-grounded brief.",
    },
  };

  const presentation = buildRunPresentation([], [streamedParentPlaybook], []);

  assert.equal(presentation.planSummary?.routeFamily, "research");
  assert.equal(presentation.planSummary?.plannerAuthority, "kernel");
  assert.equal(
    presentation.planSummary?.verifierRole,
    "citation_verifier",
  );
  assert.equal(presentation.planSummary?.verifierOutcome, "pass");
}

function routeDecisionReceiptProjectionTest(): void {
  const routingReceipt: AgentEvent = {
    ...baseEvent,
    event_id: "evt-route-decision",
    step_index: 211,
    event_type: "RECEIPT",
    title: "Receipt: google_gmail__draft_email (allowed)",
    digest: {
      tool_name: "google_gmail__draft_email",
      route_family: "communication",
      output_intent: "tool_execution",
      direct_answer_allowed: false,
      currentness_override: true,
      selected_provider_family: "mail.google.gmail",
      selected_provider_route_label: "google_gmail",
      connector_first_preference: true,
      narrow_tool_preference: true,
      projected_tools: [
        "google_gmail__draft_email",
        "chat__reply",
        "memory__search",
      ],
      primary_tools: ["google_gmail__draft_email"],
      broad_fallback_tools: ["chat__reply", "memory__search"],
      direct_answer_blockers: [
        "currentness_override",
        "connector_preferred",
      ],
    },
    details: {
      route_decision: {
        route_family: "communication",
        direct_answer_allowed: false,
        direct_answer_blockers: [
          "currentness_override",
          "connector_preferred",
        ],
        currentness_override: true,
        connector_candidate_count: 1,
        selected_provider_family: "mail.google.gmail",
        selected_provider_route_label: "google_gmail",
        connector_first_preference: true,
        narrow_tool_preference: true,
        file_output_intent: false,
        artifact_output_intent: false,
        inline_visual_intent: false,
        skill_prep_required: false,
        output_intent: "tool_execution",
        effective_tool_surface: {
          projected_tools: [
            "google_gmail__draft_email",
            "chat__reply",
            "memory__search",
          ],
          primary_tools: ["google_gmail__draft_email"],
          broad_fallback_tools: ["chat__reply", "memory__search"],
          diagnostic_tools: ["web__search"],
        },
      },
      lane_frame: {
        primaryLane: "communication",
        secondaryLanes: ["integrations"],
        primaryGoal: "Draft and ground the requested email reply.",
        toolWidgetFamily: null,
        currentnessPressure: true,
        workspaceGroundingRequired: false,
        persistentDeliverableRequested: false,
        activeArtifactFollowUp: false,
        laneConfidence: 0.94,
      },
      request_frame: {
        kind: "message_compose",
        channel: "email",
        recipientContext: "Finance team",
        purpose: "draft",
        missingSlots: [],
        clarificationRequiredSlots: [],
      },
      source_selection: {
        candidateSources: [
          "connector",
          "conversation_context",
          "direct_answer",
        ],
        selectedSource: "connector",
        explicitUserSource: false,
        fallbackReason: null,
      },
      retained_lane_state: {
        activeLane: "communication",
        selectedProviderFamily: "mail.google.gmail",
        selectedProviderRouteLabel: "google_gmail",
        selectedSourceFamily: "connector",
      },
      lane_transitions: [
        {
          transitionKind: "planned",
          fromLane: null,
          toLane: "communication",
          reason: "The prompt is best treated as a communication/composition task.",
          evidence: ["request_frame:message_compose"],
        },
        {
          transitionKind: "planned",
          fromLane: "communication",
          toLane: "integrations",
          reason: "The message lane will lean on a connected provider when one is available.",
          evidence: ["connector_intent_detected"],
        },
      ],
      orchestration_state: {
        objective: {
          objectiveId: "objective-mail-1",
          title: "Draft the requested email reply",
          status: "in_progress",
          successCriteria: [
            "Use the connected mailbox if available",
            "Preserve the requested communication intent",
          ],
        },
        tasks: [
          {
            taskId: "task-mail-1",
            label: "Resolve the message lane",
            status: "complete",
            laneFamily: "communication",
            dependsOn: [],
            summary: "The message compose frame was derived from the prompt.",
          },
          {
            taskId: "task-mail-2",
            label: "Use the connector-backed provider",
            status: "in_progress",
            laneFamily: "integrations",
            dependsOn: ["task-mail-1"],
            summary: "Gmail stayed selected as the primary provider route.",
          },
        ],
        checkpoints: [
          {
            checkpointId: "checkpoint-mail-1",
            label: "Provider selected",
            status: "complete",
            summary: "The connected Gmail route is retained for execution.",
          },
        ],
        completionInvariant: {
          summary: "The reply must remain grounded in the selected connected mailbox.",
          satisfied: false,
          outstandingRequirements: ["Complete the draft generation step"],
        },
      },
      domain_policy_bundle: {
        clarification_policy: {
          mode: "clarify_on_missing_slots",
          assumedBindings: [],
          blockingSlots: [],
          rationale: "Clarify only when the message lane still lacks required fields.",
        },
        fallback_policy: {
          mode: "allow_ranked_fallbacks",
          primaryLane: "communication",
          fallbackLanes: ["integrations"],
          triggerSignals: ["connector_intent_detected"],
          rationale: "Connector-backed messaging stays primary, with ranked integration assists.",
        },
        presentation_policy: {
          primarySurface: "communication_surface",
          widgetFamily: "message",
          renderer: "html_iframe",
          tabPriority: ["render", "evidence"],
          rationale: "Communication stays on a route-shaped parity surface.",
        },
        transformation_policy: {
          outputShape: "message_draft",
          orderedSteps: ["resolve_channel", "compose_draft"],
          rationale: "Transform the prompt into a channel-specific draft.",
        },
        risk_profile: {
          sensitivity: "medium",
          reasons: ["connector-backed communication can affect external systems"],
          approvalRequired: false,
          userVisibleGuardrails: ["Show the provider and verification gate before completion."],
        },
        verification_contract: {
          strategy: "message_shape_and_audience",
          requiredChecks: ["message_channel_resolved", "communication_surface_rendered"],
          completionGate: "surface_and_route_verified",
        },
        policy_contract: {
          bindings: ["lane_frame", "request_frame", "domain_policy_bundle"],
          hiddenInstructionDependency: false,
          rationale: "Policies are retained in typed bindings.",
        },
        source_ranking: [
          {
            source: "connector",
            rank: 1,
            rationale: "Selected as the active source for this turn.",
          },
        ],
        retained_widget_state: {
          widgetFamily: "message",
          bindings: [
            { key: "message.channel", value: "email", source: "request_frame" },
          ],
          lastUpdatedAt: null,
        },
      },
    },
  };

  const presentation = buildRunPresentation([], [routingReceipt], []);

  assert.equal(presentation.planSummary?.routeFamily, "communication");
  assert.equal(
    presentation.planSummary?.routeDecision?.selectedProviderFamily,
    "mail.google.gmail",
  );
  assert.equal(
    presentation.planSummary?.routeDecision?.connectorFirstPreference,
    true,
  );
  assert.deepEqual(
    presentation.planSummary?.routeDecision?.effectiveToolSurface.primaryTools,
    ["google_gmail__draft_email"],
  );
  assert.equal(
    presentation.planSummary?.routeDecision?.laneFrame?.primaryLane,
    "communication",
  );
  assert.equal(
    presentation.planSummary?.routeDecision?.requestFrame?.kind,
    "message_compose",
  );
  assert.equal(
    presentation.planSummary?.routeDecision?.sourceSelection?.selectedSource,
    "connector",
  );
  assert.equal(
    presentation.planSummary?.routeDecision?.laneTransitions[1]?.toLane,
    "integrations",
  );
  assert.equal(
    presentation.planSummary?.routeDecision?.orchestrationState?.tasks.length,
    2,
  );
  assert.equal(
    presentation.planSummary?.routeDecision?.domainPolicyBundle?.presentationPolicy
      ?.primarySurface,
    "communication_surface",
  );
  assert.equal(
    presentation.planSummary?.routeDecision?.domainPolicyBundle?.policyContract
      ?.hiddenInstructionDependency,
    false,
  );
}

function planSummaryFallsBackToSingleAgentResearchRoute(): void {
  const searchEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-route-search",
    step_index: 30,
    event_type: "COMMAND_RUN",
    title: "Search the web",
    digest: { tool_name: "web__search" },
    details: { output: "Searching current sources." },
  };

  const readEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-route-read",
    step_index: 31,
    event_type: "COMMAND_RUN",
    title: "Read source",
    digest: { tool_name: "web__read" },
    details: { output: "Reading selected source." },
  };

  const presentation = buildRunPresentation([], [searchEvent, readEvent], []);

  assert.ok(presentation.planSummary);
  assert.equal(presentation.planSummary?.routeFamily, "research");
  assert.equal(presentation.planSummary?.topology, "single_agent");
  assert.equal(presentation.planSummary?.plannerAuthority, "primary_agent");
  assert.equal(presentation.planSummary?.verifierRole, null);
  assert.equal(presentation.planSummary?.selectedRoute, "Research route");
  assert.equal(presentation.planSummary?.activeWorkerLabel, "Primary agent");
  assert.equal(presentation.planSummary?.approvalState, "clear");
}

function planSummaryUsesExplicitComputerUseRouteContract(): void {
  const parentPlaybookStarted: AgentEvent = {
    ...baseEvent,
    event_id: "evt-browser-playbook",
    step_index: 50,
    event_type: "RECEIPT",
    title: "Parent playbook started",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__delegate",
      phase: "started",
      playbook_id: "browser_postcondition_gate",
      playbook_label: "Browser Postcondition Gate",
      route_family: "computer_use",
      topology: "planner_specialist_verifier",
      verifier_state: "queued",
      status: "running",
      success: true,
    },
    details: {
      parent_session_id: "session-browser",
      summary: "Started browser route.",
    },
  };

  const browserWorker: AgentEvent = {
    ...baseEvent,
    event_id: "evt-browser-worker",
    step_index: 51,
    event_type: "RECEIPT",
    title: "Browser worker spawned",
    digest: {
      kind: "worker",
      tool_name: "agent__delegate",
      phase: "spawned",
      role: "Browser Operator",
      template_id: "browser_operator",
      workflow_id: "browser_postcondition_pass",
      status: "running",
      success: true,
    },
    details: {
      child_session_id: "child-browser",
      parent_session_id: "session-browser",
      summary: "Browser worker is active.",
    },
  };

  const presentation = buildRunPresentation(
    [],
    [parentPlaybookStarted, browserWorker],
    [],
  );

  assert.ok(presentation.planSummary);
  assert.equal(presentation.planSummary?.routeFamily, "computer_use");
  assert.equal(
    presentation.planSummary?.topology,
    "planner_specialist_verifier",
  );
  assert.equal(presentation.planSummary?.plannerAuthority, "kernel");
  assert.equal(
    presentation.planSummary?.verifierRole,
    "postcondition_verifier",
  );
  assert.equal(presentation.planSummary?.verifierOutcome, null);
  assert.equal(
    presentation.planSummary?.selectedRoute.includes("Browser"),
    true,
  );
  assert.equal(presentation.planSummary?.activeWorkerLabel, "Browser Operator");
  assert.equal(presentation.planSummary?.verifierState, "queued");
}

function planSummaryCarriesComputerUsePerceptionVerificationAndRecovery(): void {
  const browserPerception: AgentEvent = {
    ...baseEvent,
    event_id: "evt-browser-perception",
    step_index: 52,
    event_type: "RECEIPT",
    title: "Browser perception completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "step_completed",
      playbook_id: "browser_postcondition_gate",
      playbook_label: "Browser Postcondition Gate",
      route_family: "computer_use",
      topology: "planner_specialist_verifier",
      verifier_state: "queued",
      status: "running",
      success: true,
      computer_use_perception: {
        surface_status: "clear",
        ui_state: "Checkout form is visible with the submit button enabled.",
        target: "Submit order button",
        approval_risk: "possible",
        next_action: "Click submit order",
        notes: "A payment confirmation dialog may appear after submit.",
      },
    },
    details: {
      parent_session_id: "session-browser",
      step_id: "perceive",
      step_label: "Capture UI state",
      template_id: "perception_worker",
      workflow_id: "ui_state_brief",
      computer_use_perception: {
        surface_status: "clear",
        ui_state: "Checkout form is visible with the submit button enabled.",
        target: "Submit order button",
        approval_risk: "possible",
        next_action: "Click submit order",
        notes: "A payment confirmation dialog may appear after submit.",
      },
      summary: "UI-state brief completed.",
    },
  };

  const browserVerification: AgentEvent = {
    ...baseEvent,
    event_id: "evt-browser-verification",
    step_index: 53,
    event_type: "RECEIPT",
    title: "Browser verification completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "step_completed",
      playbook_id: "browser_postcondition_gate",
      playbook_label: "Browser Postcondition Gate",
      route_family: "computer_use",
      topology: "planner_specialist_verifier",
      verifier_state: "passed",
      status: "completed",
      success: true,
      computer_use_verification: {
        verdict: "passed",
        postcondition_status: "met",
        approval_state: "approved",
        recovery_status: "not_needed",
        observed_postcondition:
          "Confirmation banner is visible and the URL changed to /receipt.",
        notes:
          "Confirmation banner and receipt URL match the requested postcondition.",
      },
      computer_use_recovery: {
        status: "not_needed",
        reason: "Verifier confirmed the browser postcondition.",
        next_step: "Return completion to the parent planner.",
      },
    },
    details: {
      parent_session_id: "session-browser",
      step_id: "verify",
      step_label: "Verify postcondition",
      template_id: "verifier",
      workflow_id: "browser_postcondition_audit",
      computer_use_verification: {
        verdict: "passed",
        postcondition_status: "met",
        approval_state: "approved",
        recovery_status: "not_needed",
        observed_postcondition:
          "Confirmation banner is visible and the URL changed to /receipt.",
        notes:
          "Confirmation banner and receipt URL match the requested postcondition.",
      },
      computer_use_recovery: {
        status: "not_needed",
        reason: "Verifier confirmed the browser postcondition.",
        next_step: "Return completion to the parent planner.",
      },
      summary: "Browser verification completed.",
    },
  };

  const presentation = buildRunPresentation(
    [],
    [browserPerception, browserVerification],
    [],
  );

  assert.ok(presentation.planSummary);
  assert.equal(presentation.planSummary?.routeFamily, "computer_use");
  assert.equal(presentation.planSummary?.approvalState, "approved");
  assert.equal(
    presentation.planSummary?.computerUsePerception?.surfaceStatus,
    "clear",
  );
  assert.equal(
    presentation.planSummary?.computerUsePerception?.target,
    "Submit order button",
  );
  assert.equal(
    presentation.planSummary?.computerUseVerification?.verdict,
    "passed",
  );
  assert.equal(presentation.planSummary?.verifierOutcome, "pass");
  assert.equal(
    presentation.planSummary?.computerUseVerification?.postconditionStatus,
    "met",
  );
  assert.equal(
    presentation.planSummary?.computerUseRecovery?.status,
    "not_needed",
  );
}

function planSummaryCarriesResearchPrepContext(): void {
  const researchRoute: AgentEvent = {
    ...baseEvent,
    event_id: "evt-research-prep",
    step_index: 60,
    event_type: "RECEIPT",
    title: "Research route spawned",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__delegate",
      phase: "step_spawned",
      playbook_id: "citation_grounded_brief",
      playbook_label: "Citation-Grounded Brief",
      route_family: "research",
      topology: "planner_specialist_verifier",
      planner_authority: "kernel",
      verifier_state: "queued",
      verifier_role: "citation_verifier",
      selected_skills: [
        "research__benchmark_scorecard",
        "research__citation_audit",
      ],
      prep_summary:
        "Prior note: planner-specialist-verifier routing improved citation coverage on the last pass.",
      status: "running",
      success: true,
    },
    details: {
      parent_session_id: "session-research",
      step_label: "Research the topic",
      template_id: "researcher",
      workflow_id: "live_research_brief",
      planner_authority: "kernel",
      verifier_role: "citation_verifier",
      selected_skills: [
        "research__benchmark_scorecard",
        "research__citation_audit",
      ],
      prep_summary:
        "Prior note: planner-specialist-verifier routing improved citation coverage on the last pass.",
      summary: "Spawned research step with explicit prep context.",
    },
  };

  const presentation = buildRunPresentation([], [researchRoute], []);

  assert.ok(presentation.planSummary);
  assert.equal(presentation.planSummary?.routeFamily, "research");
  assert.equal(presentation.planSummary?.plannerAuthority, "kernel");
  assert.equal(presentation.planSummary?.verifierRole, "citation_verifier");
  assert.equal(presentation.planSummary?.verifierOutcome, null);
  assert.deepEqual(
    presentation.planSummary?.selectedSkills,
    expectedSelectedSkills(
      "research__benchmark_scorecard",
      "research__citation_audit",
    ),
  );
  assert.equal(
    presentation.planSummary?.prepSummary,
    "Prior note: planner-specialist-verifier routing improved citation coverage on the last pass.",
  );
}

function planSummaryUsesBuiltinPlaybookContractWhenRouteFieldsAreMissing(): void {
  const artifactRoute: AgentEvent = {
    ...baseEvent,
    event_id: "evt-artifact-implied-contract",
    step_index: 60,
    event_type: "RECEIPT",
    title: "Route step spawned",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__delegate",
      phase: "step_spawned",
      playbook_id: "artifact_generation_gate",
      status: "running",
      success: true,
    },
    details: {
      parent_session_id: "session-artifact-implied",
      step_label: "Generate candidate",
      template_id: "artifact_generator",
      workflow_id: "artifact_candidate_generation",
      summary: "Spawned next step.",
    },
  };

  const presentation = buildRunPresentation([], [artifactRoute], []);

  assert.ok(presentation.planSummary);
  assert.equal(presentation.planSummary?.routeFamily, "artifacts");
  assert.equal(
    presentation.planSummary?.topology,
    "planner_specialist_verifier",
  );
  assert.equal(presentation.planSummary?.plannerAuthority, "kernel");
  assert.equal(
    presentation.planSummary?.verifierRole,
    "artifact_validation_verifier",
  );
  assert.equal(presentation.planSummary?.verifierState, "queued");
}

function planSummaryUsesBuiltinWorkflowContractWhenPlaybookFieldsAreMissing(): void {
  const researchVerifier: AgentEvent = {
    ...baseEvent,
    event_id: "evt-research-workflow-implied-contract",
    step_index: 60,
    event_type: "RECEIPT",
    title: "Verifier completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "step_completed",
      status: "running",
      success: true,
      research_scorecard: {
        verdict: "passed",
        source_count: 2,
        distinct_domain_count: 2,
        source_count_floor_met: true,
        source_independence_floor_met: true,
        freshness_status: "passed",
        quote_grounding_status: "passed",
        notes: "Known workflow should still hydrate the research route.",
      },
    },
    details: {
      parent_session_id: "session-research-implied",
      step_label: "Verify grounding",
      template_id: "verifier",
      workflow_id: "citation_audit",
      summary: "Verifier completed with a bounded scorecard.",
      research_scorecard: {
        verdict: "passed",
        source_count: 2,
        distinct_domain_count: 2,
        source_count_floor_met: true,
        source_independence_floor_met: true,
        freshness_status: "passed",
        quote_grounding_status: "passed",
        notes: "Known workflow should still hydrate the research route.",
      },
    },
  };

  const presentation = buildRunPresentation([], [researchVerifier], []);

  assert.ok(presentation.planSummary);
  assert.equal(presentation.planSummary?.routeFamily, "research");
  assert.equal(
    presentation.planSummary?.topology,
    "planner_specialist_verifier",
  );
  assert.equal(presentation.planSummary?.plannerAuthority, "kernel");
  assert.equal(presentation.planSummary?.verifierRole, "citation_verifier");
  assert.equal(presentation.planSummary?.verifierOutcome, "pass");
}

function planSummaryCarriesPrepContextFromCompletionOnlyReceipt(): void {
  const artifactCompletion: AgentEvent = {
    ...baseEvent,
    event_id: "evt-artifact-completion-prep",
    step_index: 61,
    event_type: "RECEIPT",
    title: "Artifact route completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "completed",
      playbook_id: "artifact_generation_gate",
      selected_skills: ["artifact__frontend_validation_spine"],
      prep_summary:
        "Prior note: keep the hero contrast crisp and the mobile CTA stack stable.",
      artifact_quality: {
        verdict: "needs_attention",
        fidelity_status: "faithful",
        presentation_status: "needs_repair",
        repair_status: "required",
        notes: "Completion receipt still preserves prep context for Spotlight.",
      },
      status: "completed",
      success: true,
    },
    details: {
      parent_session_id: "session-artifact-completion-prep",
      selected_skills: ["artifact__frontend_validation_spine"],
      prep_summary:
        "Prior note: keep the hero contrast crisp and the mobile CTA stack stable.",
      summary: "Artifact route completed with retained prep context.",
      artifact_quality: {
        verdict: "needs_attention",
        fidelity_status: "faithful",
        presentation_status: "needs_repair",
        repair_status: "required",
        notes: "Completion receipt still preserves prep context for Spotlight.",
      },
    },
  };

  const presentation = buildRunPresentation([], [artifactCompletion], []);

  assert.ok(presentation.planSummary);
  assert.deepEqual(
    presentation.planSummary?.selectedSkills,
    expectedSelectedSkills("artifact__frontend_validation_spine"),
  );
  assert.equal(
    presentation.planSummary?.prepSummary,
    "Prior note: keep the hero contrast crisp and the mobile CTA stack stable.",
  );
}

function planSummaryMergesPrepContextAcrossSplitReceipts(): void {
  const spawnedRoute: AgentEvent = {
    ...baseEvent,
    event_id: "evt-research-split-prep-start",
    step_index: 61,
    event_type: "RECEIPT",
    title: "Research route spawned",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__delegate",
      phase: "step_spawned",
      playbook_id: "citation_grounded_brief",
      route_family: "research",
      topology: "planner_specialist_verifier",
      verifier_state: "queued",
      selected_skills: ["research__benchmark_scorecard"],
      status: "running",
      success: true,
    },
    details: {
      parent_session_id: "session-research-split-prep",
      step_label: "Research the topic",
      workflow_id: "live_research_brief",
      selected_skills: ["research__benchmark_scorecard"],
      summary: "Spawned research step with skill selection only.",
    },
  };

  const blockedRoute: AgentEvent = {
    ...baseEvent,
    event_id: "evt-research-split-prep-blocked",
    step_index: 62,
    event_type: "RECEIPT",
    title: "Research route paused",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "blocked",
      playbook_id: "citation_grounded_brief",
      route_family: "research",
      topology: "planner_specialist_verifier",
      verifier_state: "queued",
      prep_summary:
        "Planner chose the benchmark scorecard skill before verifier handoff.",
      status: "blocked",
      success: false,
    },
    details: {
      parent_session_id: "session-research-split-prep",
      step_label: "Research the topic",
      workflow_id: "live_research_brief",
      prep_summary:
        "Planner chose the benchmark scorecard skill before verifier handoff.",
      summary: "Blocked receipt carried the remaining prep context.",
    },
  };

  const presentation = buildRunPresentation([], [spawnedRoute, blockedRoute], []);

  assert.ok(presentation.planSummary);
  assert.deepEqual(
    presentation.planSummary?.selectedSkills,
    expectedSelectedSkills("research__benchmark_scorecard"),
  );
  assert.equal(
    presentation.planSummary?.prepSummary,
    "Planner chose the benchmark scorecard skill before verifier handoff.",
  );
}

function planSummaryKeepsUnknownNarrativeRouteGeneral(): void {
  const unknownRoute: AgentEvent = {
    ...baseEvent,
    event_id: "evt-unknown-route-narrative",
    step_index: 63,
    event_type: "RECEIPT",
    title: "Route step spawned",
    digest: {
      kind: "worker",
      tool_name: "agent__delegate",
      phase: "step_spawned",
      status: "running",
      success: true,
    },
    details: {
      parent_session_id: "session-unknown-route",
      step_label: "Do work",
      summary: "Collect source notes before a later validation call.",
    },
  };

  const presentation = buildRunPresentation([], [unknownRoute], []);

  assert.ok(presentation.planSummary);
  assert.equal(presentation.planSummary?.routeFamily, "general");
  assert.equal(presentation.planSummary?.verifierState, "not_engaged");
}

function planSummaryCarriesResearchVerificationScorecard(): void {
  const researchVerification: AgentEvent = {
    ...baseEvent,
    event_id: "evt-research-verifier",
    step_index: 61,
    event_type: "RECEIPT",
    title: "Research verifier completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "step_completed",
      playbook_id: "citation_grounded_brief",
      playbook_label: "Citation-Grounded Brief",
      route_family: "research",
      topology: "planner_specialist_verifier",
      verifier_state: "passed",
      research_scorecard: {
        verdict: "passed",
        source_count: 3,
        distinct_domain_count: 3,
        source_count_floor_met: true,
        source_independence_floor_met: true,
        freshness_status: "passed",
        quote_grounding_status: "needs_attention",
        notes:
          "Two quotes were grounded cleanly; one metric still needs a read-backed quote check.",
      },
      status: "running",
      success: true,
    },
    details: {
      parent_session_id: "session-research",
      step_label: "Verify grounding",
      template_id: "verifier",
      workflow_id: "citation_audit",
      research_scorecard: {
        verdict: "passed",
        source_count: 3,
        distinct_domain_count: 3,
        source_count_floor_met: true,
        source_independence_floor_met: true,
        freshness_status: "passed",
        quote_grounding_status: "needs_attention",
        notes:
          "Two quotes were grounded cleanly; one metric still needs a read-backed quote check.",
      },
      summary: "Research verifier finished with a compact scorecard.",
    },
  };

  const presentation = buildRunPresentation([], [researchVerification], []);

  assert.ok(presentation.planSummary);
  assert.equal(presentation.planSummary?.routeFamily, "research");
  assert.equal(
    presentation.planSummary?.researchVerification?.verdict,
    "passed",
  );
  assert.equal(presentation.planSummary?.researchVerification?.sourceCount, 3);
  assert.equal(
    presentation.planSummary?.researchVerification?.distinctDomainCount,
    3,
  );
  assert.equal(
    presentation.planSummary?.researchVerification?.quoteGroundingStatus,
    "needs_attention",
  );
  assert.equal(presentation.planSummary?.verifierOutcome, "pass");
}

function planSummaryCarriesCodingVerificationAndPatchSynthesis(): void {
  const codingVerification: AgentEvent = {
    ...baseEvent,
    event_id: "evt-coding-verifier",
    step_index: 62,
    event_type: "RECEIPT",
    title: "Coding verifier completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "step_completed",
      playbook_id: "evidence_audited_patch",
      playbook_label: "Evidence-Audited Patch",
      route_family: "coding",
      topology: "planner_specialist_verifier",
      verifier_state: "passed",
      coding_scorecard: {
        verdict: "passed",
        targeted_command_count: 2,
        targeted_pass_count: 2,
        widening_status: "not_needed",
        regression_status: "clear",
        notes:
          "Focused cargo test and cargo check both passed without widening.",
      },
      status: "running",
      success: true,
    },
    details: {
      parent_session_id: "session-coding",
      step_label: "Verify targeted tests",
      template_id: "verifier",
      workflow_id: "targeted_test_audit",
      coding_scorecard: {
        verdict: "passed",
        targeted_command_count: 2,
        targeted_pass_count: 2,
        widening_status: "not_needed",
        regression_status: "clear",
        notes:
          "Focused cargo test and cargo check both passed without widening.",
      },
      summary: "Coding verifier completed with a bounded scorecard.",
    },
  };

  const patchSynthesis: AgentEvent = {
    ...baseEvent,
    event_id: "evt-patch-synth",
    step_index: 63,
    event_type: "RECEIPT",
    title: "Patch synthesis completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "completed",
      playbook_id: "evidence_audited_patch",
      playbook_label: "Evidence-Audited Patch",
      route_family: "coding",
      topology: "planner_specialist_verifier",
      verifier_state: "passed",
      patch_synthesis: {
        status: "ready",
        touched_file_count: 3,
        verification_ready: true,
        notes:
          "Synthesized final handoff aligns the diff with the verifier result.",
      },
      status: "completed",
      success: true,
    },
    details: {
      parent_session_id: "session-coding",
      step_label: "Synthesize final patch",
      template_id: "patch_synthesizer",
      workflow_id: "patch_synthesis_handoff",
      patch_synthesis: {
        status: "ready",
        touched_file_count: 3,
        verification_ready: true,
        notes:
          "Synthesized final handoff aligns the diff with the verifier result.",
      },
      summary: "Patch synthesis completed with final handoff state.",
    },
  };

  const presentation = buildRunPresentation(
    [],
    [codingVerification, patchSynthesis],
    [],
  );

  assert.ok(presentation.planSummary);
  assert.equal(presentation.planSummary?.routeFamily, "coding");
  assert.equal(presentation.planSummary?.codingVerification?.verdict, "passed");
  assert.equal(
    presentation.planSummary?.codingVerification?.targetedCommandCount,
    2,
  );
  assert.equal(
    presentation.planSummary?.codingVerification?.wideningStatus,
    "not_needed",
  );
  assert.equal(presentation.planSummary?.verifierOutcome, "pass");
  assert.equal(presentation.planSummary?.patchSynthesis?.status, "ready");
  assert.equal(presentation.planSummary?.patchSynthesis?.touchedFileCount, 3);
  assert.equal(
    presentation.planSummary?.patchSynthesis?.verificationReady,
    true,
  );
}

function planSummaryCarriesArtifactGenerationQualityAndRepair(): void {
  const artifactContext: AgentEvent = {
    ...baseEvent,
    event_id: "evt-artifact-context",
    step_index: 64,
    event_type: "RECEIPT",
    title: "Artifact context spawned",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__delegate",
      phase: "step_spawned",
      playbook_id: "artifact_generation_gate",
      playbook_label: "Artifact Generation Gate",
      route_family: "artifacts",
      topology: "planner_specialist_verifier",
      verifier_state: "queued",
      selected_skills: ["artifact__frontend_validation_spine"],
      prep_summary:
        "Prior note: strong artifact runs keep the hero contrast crisp and the mobile CTA stack stable.",
      status: "running",
      success: true,
    },
    details: {
      parent_session_id: "session-artifact",
      step_id: "context",
      step_label: "Capture artifact context",
      template_id: "context_worker",
      workflow_id: "artifact_context_brief",
      selected_skills: ["artifact__frontend_validation_spine"],
      prep_summary:
        "Prior note: strong artifact runs keep the hero contrast crisp and the mobile CTA stack stable.",
      summary: "Spawned artifact context step with explicit prep context.",
    },
  };

  const artifactBuild: AgentEvent = {
    ...baseEvent,
    event_id: "evt-artifact-build",
    step_index: 65,
    event_type: "RECEIPT",
    title: "Artifact build completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "step_completed",
      playbook_id: "artifact_generation_gate",
      playbook_label: "Artifact Generation Gate",
      route_family: "artifacts",
      topology: "planner_specialist_verifier",
      verifier_state: "active",
      artifact_generation: {
        status: "generated",
        produced_file_count: 2,
        verification_signal_status: "retained",
        presentation_status: "needs_repair",
        notes: "Mobile hero copy overlaps the CTA at the narrow breakpoint.",
      },
      artifact_repair: {
        status: "required",
        reason: "Mobile hero copy overlaps the CTA at the narrow breakpoint.",
        next_step: "Fix the mobile hero stacking before presentation.",
      },
      status: "running",
      success: true,
    },
    details: {
      parent_session_id: "session-artifact",
      step_id: "build",
      step_label: "Generate artifact",
      template_id: "artifact_builder",
      workflow_id: "artifact_generate_repair",
      artifact_generation: {
        status: "generated",
        produced_file_count: 2,
        verification_signal_status: "retained",
        presentation_status: "needs_repair",
        notes: "Mobile hero copy overlaps the CTA at the narrow breakpoint.",
      },
      artifact_repair: {
        status: "required",
        reason: "Mobile hero copy overlaps the CTA at the narrow breakpoint.",
        next_step: "Fix the mobile hero stacking before presentation.",
      },
      summary:
        "Artifact generation completed with retained verification signals.",
    },
  };

  const artifactValidation: AgentEvent = {
    ...baseEvent,
    event_id: "evt-artifact-validation",
    step_index: 66,
    event_type: "RECEIPT",
    title: "Artifact validation completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "completed",
      playbook_id: "artifact_generation_gate",
      playbook_label: "Artifact Generation Gate",
      route_family: "artifacts",
      topology: "planner_specialist_verifier",
      verifier_state: "passed",
      artifact_quality: {
        verdict: "needs_attention",
        fidelity_status: "faithful",
        presentation_status: "needs_repair",
        repair_status: "required",
        notes:
          "Layout intent is strong, but mobile CTA overlap blocks presentation readiness.",
      },
      artifact_repair: {
        status: "required",
        reason:
          "Layout intent is strong, but mobile CTA overlap blocks presentation readiness.",
        next_step: "Fix the mobile hero stacking before presentation.",
      },
      status: "completed",
      success: true,
    },
    details: {
      parent_session_id: "session-artifact",
      step_id: "validation",
      step_label: "Validate artifact quality",
      template_id: "verifier",
      workflow_id: "artifact_validation_audit",
      artifact_quality: {
        verdict: "needs_attention",
        fidelity_status: "faithful",
        presentation_status: "needs_repair",
        repair_status: "required",
        notes:
          "Layout intent is strong, but mobile CTA overlap blocks presentation readiness.",
      },
      artifact_repair: {
        status: "required",
        reason:
          "Layout intent is strong, but mobile CTA overlap blocks presentation readiness.",
        next_step: "Fix the mobile hero stacking before presentation.",
      },
      summary: "Artifact validation finished with a repair-required verdict.",
    },
  };

  const presentation = buildRunPresentation(
    [],
    [artifactContext, artifactBuild, artifactValidation],
    [],
  );

  assert.ok(presentation.planSummary);
  assert.equal(presentation.planSummary?.routeFamily, "artifacts");
  assert.deepEqual(
    presentation.planSummary?.selectedSkills,
    expectedSelectedSkills("artifact__frontend_validation_spine"),
  );
  assert.equal(
    presentation.planSummary?.artifactGeneration?.status,
    "generated",
  );
  assert.equal(
    presentation.planSummary?.artifactGeneration?.producedFileCount,
    2,
  );
  assert.equal(
    presentation.planSummary?.artifactQuality?.presentationStatus,
    "needs_repair",
  );
  assert.equal(presentation.planSummary?.verifierOutcome, "warning");
  assert.equal(presentation.planSummary?.artifactRepair?.status, "required");
  assert.equal(
    presentation.planSummary?.currentStage,
    "Validate Artifact Quality",
  );
  assert.equal(
    presentation.planSummary?.progressSummary,
    "Artifact validation finished with a repair-required verdict.",
  );
}

function planSummaryCarriesStageProgressAndPause(): void {
  const artifactContext: AgentEvent = {
    ...baseEvent,
    event_id: "evt-artifact-stage",
    step_index: 67,
    event_type: "RECEIPT",
    title: "Artifact context spawned",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__delegate",
      phase: "step_spawned",
      playbook_id: "artifact_generation_gate",
      playbook_label: "Artifact Generation Gate",
      route_family: "artifacts",
      topology: "planner_specialist_verifier",
      verifier_state: "queued",
      status: "running",
      success: true,
    },
    details: {
      parent_session_id: "session-artifact",
      step_id: "context",
      step_label: "Capture artifact context",
      template_id: "context_worker",
      workflow_id: "artifact_context_brief",
      summary:
        "Preparing reference cues and output expectations for the generator.",
    },
  };

  const approvalGate: AgentEvent = {
    ...baseEvent,
    event_id: "evt-artifact-approval",
    step_index: 68,
    event_type: "RECEIPT",
    title: "Routing receipt",
    digest: {
      tool_name: "browser__open",
      policy_decision: "require_approval",
      status: "gate",
    },
    details: {
      status: "gate",
      output:
        "Waiting for approval before opening external inspiration references.",
    },
  };

  const presentation = buildRunPresentation(
    [],
    [artifactContext, approvalGate],
    [],
  );

  assert.ok(presentation.planSummary);
  assert.equal(
    presentation.planSummary?.currentStage,
    "Capture Artifact Context",
  );
  assert.equal(
    presentation.planSummary?.progressSummary,
    "Preparing reference cues and output expectations for the generator.",
  );
  assert.equal(
    presentation.planSummary?.pauseSummary,
    "Waiting for approval before opening external inspiration references.",
  );
}

function executionMomentsCaptureBranchApprovalAndVerification(): void {
  const codingWorkerSpawned: AgentEvent = {
    ...baseEvent,
    event_id: "evt-worker-coder-moment",
    step_index: 70,
    event_type: "RECEIPT",
    title: "Coding worker spawned",
    digest: {
      kind: "worker",
      tool_name: "agent__delegate",
      phase: "spawned",
      role: "Coding Worker",
      template_id: "coder",
      workflow_id: "patch_build_verify",
      status: "running",
      success: true,
    },
    details: {
      child_session_id: "child-coder",
      parent_session_id: "session-coding",
      summary: "Patch worker is active.",
    },
  };

  const verifierWorkerSpawned: AgentEvent = {
    ...baseEvent,
    event_id: "evt-worker-verifier-moment",
    step_index: 71,
    event_type: "RECEIPT",
    title: "Verification worker spawned",
    digest: {
      kind: "worker",
      tool_name: "agent__delegate",
      phase: "spawned",
      role: "Verifier",
      template_id: "verifier",
      workflow_id: "targeted_test_audit",
      status: "running",
      success: true,
    },
    details: {
      child_session_id: "child-verifier",
      parent_session_id: "session-coding",
      summary: "Verifier is queued.",
    },
  };

  const approvalGate: AgentEvent = {
    ...baseEvent,
    event_id: "evt-approval-moment",
    step_index: 72,
    event_type: "RECEIPT",
    title: "Routing receipt",
    digest: {
      tool_name: "file__write",
      policy_decision: "require_approval",
      status: "gate",
    },
    details: {
      status: "gate",
      output: "Waiting for approval before writing the patched files.",
    },
  };

  const codingVerification: AgentEvent = {
    ...baseEvent,
    event_id: "evt-coding-verifier-moment",
    step_index: 73,
    event_type: "RECEIPT",
    title: "Coding verifier completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "step_completed",
      playbook_id: "evidence_audited_patch",
      playbook_label: "Evidence-Audited Patch",
      route_family: "coding",
      topology: "planner_specialist_verifier",
      verifier_state: "passed",
      coding_scorecard: {
        verdict: "passed",
        targeted_command_count: 2,
        targeted_pass_count: 2,
        widening_status: "not_needed",
        regression_status: "clear",
        notes: "Focused cargo test and cargo check both passed.",
      },
      status: "completed",
      success: true,
    },
    details: {
      parent_session_id: "session-coding",
      step_label: "Verify targeted tests",
      template_id: "verifier",
      workflow_id: "targeted_test_audit",
      coding_scorecard: {
        verdict: "passed",
        targeted_command_count: 2,
        targeted_pass_count: 2,
        widening_status: "not_needed",
        regression_status: "clear",
        notes: "Focused cargo test and cargo check both passed.",
      },
      summary: "Coding verifier completed with a bounded scorecard.",
    },
  };

  const events = [
    codingWorkerSpawned,
    verifierWorkerSpawned,
    approvalGate,
    codingVerification,
  ];
  const presentation = buildRunPresentation([], events, []);
  const moments = buildExecutionMoments(
    activityRefsFromEvents(events),
    presentation.planSummary,
  );

  assert.deepEqual(
    moments.map((moment) => moment.kind),
    ["branch", "approval", "verification"],
  );
  assert.equal(moments[0]?.title, "Opened 2 worker branches");
  assert.equal(moments[1]?.title, "Approval required");
  assert.equal(
    moments[1]?.summary,
    "Waiting for approval before writing the patched files.",
  );
  assert.equal(moments[2]?.title, "Test verifier Passed");
  assert.equal(
    moments[2]?.summary,
    "Focused cargo test and cargo check both passed.",
  );
}

function executionMomentsShowArtifactVerifierWarning(): void {
  const artifactValidation: AgentEvent = {
    ...baseEvent,
    event_id: "evt-artifact-warning",
    step_index: 74,
    event_type: "RECEIPT",
    title: "Artifact validation completed",
    digest: {
      kind: "parent_playbook",
      tool_name: "agent__await",
      phase: "completed",
      playbook_id: "artifact_generation_gate",
      playbook_label: "Artifact Generation Gate",
      route_family: "artifacts",
      topology: "planner_specialist_verifier",
      verifier_state: "passed",
      verifier_role: "artifact_validation_verifier",
      artifact_quality: {
        verdict: "needs_attention",
        fidelity_status: "faithful",
        presentation_status: "needs_repair",
        repair_status: "required",
        notes: "Mobile CTA overlap still needs repair before presentation.",
      },
      status: "completed",
      success: true,
    },
    details: {
      parent_session_id: "session-artifact",
      step_label: "Validate artifact quality",
      template_id: "verifier",
      workflow_id: "artifact_validation_audit",
      verifier_role: "artifact_validation_verifier",
      artifact_quality: {
        verdict: "needs_attention",
        fidelity_status: "faithful",
        presentation_status: "needs_repair",
        repair_status: "required",
        notes: "Mobile CTA overlap still needs repair before presentation.",
      },
      summary: "Artifact validation finished with a repair-required verdict.",
    },
  };

  const presentation = buildRunPresentation([], [artifactValidation], []);
  const moments = buildExecutionMoments(
    activityRefsFromEvents([artifactValidation]),
    presentation.planSummary,
  );

  assert.equal(presentation.planSummary?.verifierOutcome, "warning");
  assert.equal(moments[0]?.status, "warning");
  assert.equal(moments[0]?.title, "Artifact quality verifier Needs Attention");
}

function chatContractParsingTest(): void {
  const validPayload = {
    schema_version: "chat_contract_v1",
    intent_id: "search.list_files",
    outcome: { status: "success", count: 2, summary: "Found matching files." },
    interpretation: {
      timezone: "America/New_York",
      sort: "modified_desc",
    },
    result_columns: [
      { key: "name", label: "File" },
      { key: "modified", label: "Modified" },
    ],
    result_rows: [
      { name: "a.pdf", modified: "2026-02-27T19:48:48Z" },
      { name: "b.pdf", modified: "2026-02-26T19:48:48Z" },
    ],
    actions: [{ id: "open_all", label: "Open all" }],
  };

  const parsedValid = parseChatContractEnvelope(JSON.stringify(validPayload));
  assert.ok(parsedValid.envelope);
  assert.equal(parsedValid.issues.length, 0);

  const invalidPayload = {
    ...validPayload,
    answer_markdown: "Completed. Final response emitted via chat_reply.",
  };
  const parsedInvalid = parseChatContractEnvelope(
    JSON.stringify(invalidPayload),
  );
  assert.equal(parsedInvalid.envelope, null);
  assert.equal(
    parsedInvalid.issues.some(
      (issue) => issue.code === "forbidden_internal_label",
    ),
    true,
  );
}

function invalidContractFallbackTest(): void {
  const invalidPayload = {
    schema_version: "chat_contract_v1",
    intent_id: "search.list_files",
    outcome: { status: "success", count: 1 },
    interpretation: { timezone: "UTC" },
    result_rows: [{ name: "a.pdf" }],
    answer_markdown: "Completed. Final response emitted via chat_reply.",
  };

  const history: ChatMessage[] = [
    { role: "user", text: "find files", timestamp: Date.now() - 5_000 },
    {
      role: "agent",
      text: JSON.stringify(invalidPayload),
      timestamp: Date.now() - 2_000,
    },
  ];

  const presentation = buildRunPresentation(history, [], []);
  assert.equal(
    presentation.finalAnswer?.displayText,
    "Structured response unavailable due to contract validation failure.",
  );
  assert.equal(
    presentation.finalAnswer?.displayText.includes(
      "final response emitted via chat_reply",
    ),
    false,
  );
}

classifyEventTest();
normalizeOutputTest();
dedupAndAnswerTest();
activitySummaryTest();
sourceSummaryTest();
sourceSummaryReceiptOnlyTest();
thoughtSummaryTest();
clarificationReasoningFallbackTest();
ordinaryReasoningDoesNotBecomeAnswerTest();
planSummaryCapturesTypedHierarchyTest();
streamedParentPlaybookRouteContractTest();
routeDecisionReceiptProjectionTest();
planSummaryFallsBackToSingleAgentResearchRoute();
planSummaryUsesExplicitComputerUseRouteContract();
planSummaryCarriesComputerUsePerceptionVerificationAndRecovery();
planSummaryCarriesResearchPrepContext();
planSummaryUsesBuiltinPlaybookContractWhenRouteFieldsAreMissing();
planSummaryUsesBuiltinWorkflowContractWhenPlaybookFieldsAreMissing();
planSummaryCarriesPrepContextFromCompletionOnlyReceipt();
planSummaryMergesPrepContextAcrossSplitReceipts();
planSummaryCarriesResearchVerificationScorecard();
planSummaryCarriesCodingVerificationAndPatchSynthesis();
planSummaryCarriesArtifactGenerationQualityAndRepair();
planSummaryCarriesStageProgressAndPause();
executionMomentsCaptureBranchApprovalAndVerification();
executionMomentsShowArtifactVerifierWarning();
planSummaryKeepsUnknownNarrativeRouteGeneral();
chatContractParsingTest();
invalidContractFallbackTest();
