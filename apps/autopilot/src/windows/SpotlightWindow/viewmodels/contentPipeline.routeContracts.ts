import type {
  ActivityEventRef,
  PlanCheckpointStateSummary,
  PlanDomainPolicyBundleSummary,
  PlanFallbackMode,
  PlanCompletionInvariantSummary,
  PlanClarificationMode,
  PlanLaneFamily,
  PlanLaneFrameSummary,
  PlanLaneTransitionKind,
  PlanLaneTransitionSummary,
  PlanNormalizedRequestFrameSummary,
  PlanObjectiveStateSummary,
  PlanOrchestrationStateSummary,
  PlanOutputIntent,
  PlanRouteDecisionSummary,
  PlanRiskSensitivity,
  PlanSourceFamily,
  PlanSourceSelectionSummary,
  PlanSummary,
  PlanRetainedLaneStateSummary,
  PlanTaskUnitStateSummary,
  PlanWorkStatus,
} from "../../../types";

type StringFromRecord = (
  record: Record<string, unknown>,
  ...keys: string[]
) => string | undefined;

type RecordAccessor = (entry: ActivityEventRef) => Record<string, unknown>;

export type ExplicitRouteContract = {
  routeFamily: PlanSummary["routeFamily"] | null;
  topology: PlanSummary["topology"] | null;
  plannerAuthority: PlanSummary["plannerAuthority"] | null;
  verifierState: PlanSummary["verifierState"] | null;
  verifierRole: PlanSummary["verifierRole"] | null;
  verifierOutcome: PlanSummary["verifierOutcome"] | null;
};

function recordFromRecord(
  record: Record<string, unknown>,
  ...keys: string[]
): Record<string, unknown> | null {
  for (const key of keys) {
    const value = record[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  }
  return null;
}

function booleanFromRecord(
  record: Record<string, unknown>,
  ...keys: string[]
): boolean | null {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "boolean") {
      return value;
    }
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (normalized === "true") return true;
      if (normalized === "false") return false;
    }
  }
  return null;
}

function arrayFromRecord(
  record: Record<string, unknown>,
  ...keys: string[]
): string[] {
  for (const key of keys) {
    const value = record[key];
    if (!Array.isArray(value)) continue;
    return value
      .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
      .filter((entry) => entry.length > 0);
  }
  return [];
}

function numberFromRecord(
  record: Record<string, unknown>,
  ...keys: string[]
): number | null {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
    if (typeof value === "string") {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }
  }
  return null;
}

function parseLaneFamily(value?: string): PlanLaneFamily | null {
  switch ((value || "").trim().toLowerCase()) {
    case "general":
    case "research":
    case "coding":
    case "integrations":
    case "conversation":
    case "tool_widget":
    case "visualizer":
    case "artifact":
    case "communication":
    case "user_input":
      return value!.trim().toLowerCase() as PlanLaneFamily;
    default:
      return null;
  }
}

function parseSourceFamily(value?: string): PlanSourceFamily | null {
  switch ((value || "").trim().toLowerCase()) {
    case "user_directed":
    case "conversation_context":
    case "memory":
    case "conversation_retrieval":
    case "connector":
    case "specialized_tool":
    case "web_search":
    case "direct_answer":
    case "workspace":
    case "artifact_context":
      return value!.trim().toLowerCase() as PlanSourceFamily;
    default:
      return null;
  }
}

function parseWorkStatus(value?: string): PlanWorkStatus | null {
  switch ((value || "").trim().toLowerCase()) {
    case "pending":
    case "in_progress":
    case "complete":
    case "blocked":
      return value!.trim().toLowerCase() as PlanWorkStatus;
    default:
      return null;
  }
}

function parseLaneTransitionKind(
  value?: string,
): PlanLaneTransitionKind | null {
  switch ((value || "").trim().toLowerCase()) {
    case "planned":
    case "reactive":
      return value!.trim().toLowerCase() as PlanLaneTransitionKind;
    default:
      return null;
  }
}

function parseClarificationMode(
  value?: string,
): PlanClarificationMode | null {
  switch ((value || "").trim().toLowerCase()) {
    case "assume_from_retained_state":
    case "clarify_on_missing_slots":
    case "block_until_clarified":
      return value!.trim().toLowerCase() as PlanClarificationMode;
    default:
      return null;
  }
}

function parseFallbackMode(value?: string): PlanFallbackMode | null {
  switch ((value || "").trim().toLowerCase()) {
    case "stay_in_specialized_lane":
    case "allow_ranked_fallbacks":
    case "block_until_clarified":
      return value!.trim().toLowerCase() as PlanFallbackMode;
    default:
      return null;
  }
}

function parseRiskSensitivity(value?: string): PlanRiskSensitivity | null {
  switch ((value || "").trim().toLowerCase()) {
    case "low":
    case "medium":
    case "high":
      return value!.trim().toLowerCase() as PlanRiskSensitivity;
    default:
      return null;
  }
}

function laneFamiliesFromRecord(
  record: Record<string, unknown>,
  ...keys: string[]
): PlanLaneFamily[] {
  for (const key of keys) {
    const value = record[key];
    if (!Array.isArray(value)) continue;
    const parsed = value
      .map((entry) =>
        typeof entry === "string" ? parseLaneFamily(entry) : null,
      )
      .filter((entry): entry is PlanLaneFamily => Boolean(entry));
    if (parsed.length > 0) {
      return parsed;
    }
  }
  return [];
}

function sourceFamiliesFromRecord(
  record: Record<string, unknown>,
  ...keys: string[]
): PlanSourceFamily[] {
  for (const key of keys) {
    const value = record[key];
    if (!Array.isArray(value)) continue;
    const parsed = value
      .map((entry) =>
        typeof entry === "string" ? parseSourceFamily(entry) : null,
      )
      .filter((entry): entry is PlanSourceFamily => Boolean(entry));
    if (parsed.length > 0) {
      return parsed;
    }
  }
  return [];
}

function laneFrameFromRecord(
  record: Record<string, unknown> | null,
  stringFromRecord: StringFromRecord,
): PlanLaneFrameSummary | null {
  if (!record) return null;
  const primaryLane = parseLaneFamily(
    stringFromRecord(record, "primaryLane", "primary_lane"),
  );
  if (!primaryLane) return null;
  return {
    primaryLane,
    secondaryLanes: laneFamiliesFromRecord(
      record,
      "secondaryLanes",
      "secondary_lanes",
    ),
    primaryGoal:
      stringFromRecord(record, "primaryGoal", "primary_goal") || "Runtime-selected lane",
    toolWidgetFamily:
      stringFromRecord(record, "toolWidgetFamily", "tool_widget_family") || null,
    currentnessPressure:
      booleanFromRecord(record, "currentnessPressure", "currentness_pressure") ===
      true,
    workspaceGroundingRequired:
      booleanFromRecord(
        record,
        "workspaceGroundingRequired",
        "workspace_grounding_required",
      ) === true,
    persistentDeliverableRequested:
      booleanFromRecord(
        record,
        "persistentDeliverableRequested",
        "persistent_deliverable_requested",
      ) === true,
    activeArtifactFollowUp:
      booleanFromRecord(record, "activeArtifactFollowUp", "active_artifact_follow_up") ===
      true,
    laneConfidence:
      numberFromRecord(record, "laneConfidence", "lane_confidence") ?? 0,
  };
}

function sourceSelectionFromRecord(
  record: Record<string, unknown> | null,
  stringFromRecord: StringFromRecord,
): PlanSourceSelectionSummary | null {
  if (!record) return null;
  const selectedSource = parseSourceFamily(
    stringFromRecord(record, "selectedSource", "selected_source"),
  );
  if (!selectedSource) return null;
  return {
    candidateSources: sourceFamiliesFromRecord(
      record,
      "candidateSources",
      "candidate_sources",
    ),
    selectedSource,
    explicitUserSource:
      booleanFromRecord(record, "explicitUserSource", "explicit_user_source") ===
      true,
    fallbackReason:
      stringFromRecord(record, "fallbackReason", "fallback_reason") || null,
  };
}

function domainPolicyBundleFromRecord(
  record: Record<string, unknown> | null,
  stringFromRecord: StringFromRecord,
): PlanDomainPolicyBundleSummary | null {
  if (!record) return null;
  const clarificationPolicyRecord = recordFromRecord(
    record,
    "clarificationPolicy",
    "clarification_policy",
  );
  const fallbackPolicyRecord = recordFromRecord(
    record,
    "fallbackPolicy",
    "fallback_policy",
  );
  const presentationPolicyRecord = recordFromRecord(
    record,
    "presentationPolicy",
    "presentation_policy",
  );
  const transformationPolicyRecord = recordFromRecord(
    record,
    "transformationPolicy",
    "transformation_policy",
  );
  const riskProfileRecord = recordFromRecord(record, "riskProfile", "risk_profile");
  const verificationContractRecord = recordFromRecord(
    record,
    "verificationContract",
    "verification_contract",
  );
  const policyContractRecord = recordFromRecord(
    record,
    "policyContract",
    "policy_contract",
  );
  const retainedWidgetStateRecord = recordFromRecord(
    record,
    "retainedWidgetState",
    "retained_widget_state",
  );
  const sourceRankingValues = record.sourceRanking || record.source_ranking;
  const sourceRanking = Array.isArray(sourceRankingValues)
    ? sourceRankingValues
        .map((entry) => {
          if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
            return null;
          }
          const ranking = entry as Record<string, unknown>;
          const source = parseSourceFamily(
            stringFromRecord(ranking, "source"),
          );
          const rank = numberFromRecord(ranking, "rank");
          if (!source || rank === null) return null;
          return {
            source,
            rank,
            rationale:
              stringFromRecord(ranking, "rationale") || "Ranked source",
          };
        })
        .filter(
          (
            entry,
          ): entry is PlanDomainPolicyBundleSummary["sourceRanking"][number] =>
            Boolean(entry),
        )
    : [];
  const bundle: PlanDomainPolicyBundleSummary = {
    clarificationPolicy: clarificationPolicyRecord
      ? {
          mode:
            parseClarificationMode(
              stringFromRecord(
                clarificationPolicyRecord,
                "mode",
              ),
            ) || "clarify_on_missing_slots",
          assumedBindings: arrayFromRecord(
            clarificationPolicyRecord,
            "assumedBindings",
            "assumed_bindings",
          ),
          blockingSlots: arrayFromRecord(
            clarificationPolicyRecord,
            "blockingSlots",
            "blocking_slots",
          ),
          rationale:
            stringFromRecord(clarificationPolicyRecord, "rationale") ||
            "Clarification policy retained",
        }
      : null,
    fallbackPolicy:
      fallbackPolicyRecord &&
      parseLaneFamily(
        stringFromRecord(fallbackPolicyRecord, "primaryLane", "primary_lane"),
      )
        ? {
            mode:
              parseFallbackMode(
                stringFromRecord(fallbackPolicyRecord, "mode"),
              ) || "allow_ranked_fallbacks",
            primaryLane:
              parseLaneFamily(
                stringFromRecord(
                  fallbackPolicyRecord,
                  "primaryLane",
                  "primary_lane",
                ),
              ) || "general",
            fallbackLanes: laneFamiliesFromRecord(
              fallbackPolicyRecord,
              "fallbackLanes",
              "fallback_lanes",
            ),
            triggerSignals: arrayFromRecord(
              fallbackPolicyRecord,
              "triggerSignals",
              "trigger_signals",
            ),
            rationale:
              stringFromRecord(fallbackPolicyRecord, "rationale") ||
              "Fallback policy retained",
          }
        : null,
    presentationPolicy: presentationPolicyRecord
      ? {
          primarySurface:
            stringFromRecord(
              presentationPolicyRecord,
              "primarySurface",
              "primary_surface",
            ) || "surface",
          widgetFamily:
            stringFromRecord(
              presentationPolicyRecord,
              "widgetFamily",
              "widget_family",
            ) || null,
          renderer: (stringFromRecord(presentationPolicyRecord, "renderer") ||
            null) as any,
          tabPriority: arrayFromRecord(
            presentationPolicyRecord,
            "tabPriority",
            "tab_priority",
          ),
          rationale:
            stringFromRecord(presentationPolicyRecord, "rationale") ||
            "Presentation policy retained",
        }
      : null,
    transformationPolicy: transformationPolicyRecord
      ? {
          outputShape:
            stringFromRecord(
              transformationPolicyRecord,
              "outputShape",
              "output_shape",
            ) || "output",
          orderedSteps: arrayFromRecord(
            transformationPolicyRecord,
            "orderedSteps",
            "ordered_steps",
          ),
          rationale:
            stringFromRecord(transformationPolicyRecord, "rationale") ||
            "Transformation policy retained",
        }
      : null,
    riskProfile:
      riskProfileRecord &&
      parseRiskSensitivity(stringFromRecord(riskProfileRecord, "sensitivity"))
        ? {
            sensitivity:
              parseRiskSensitivity(
                stringFromRecord(riskProfileRecord, "sensitivity"),
              ) || "low",
            reasons: arrayFromRecord(riskProfileRecord, "reasons"),
            approvalRequired:
              booleanFromRecord(
                riskProfileRecord,
                "approvalRequired",
                "approval_required",
              ) === true,
            userVisibleGuardrails: arrayFromRecord(
              riskProfileRecord,
              "userVisibleGuardrails",
              "user_visible_guardrails",
            ),
          }
        : null,
    verificationContract: verificationContractRecord
      ? {
          strategy:
            stringFromRecord(verificationContractRecord, "strategy") ||
            "verification",
          requiredChecks: arrayFromRecord(
            verificationContractRecord,
            "requiredChecks",
            "required_checks",
          ),
          completionGate:
            stringFromRecord(
              verificationContractRecord,
              "completionGate",
              "completion_gate",
            ) || "completion",
        }
      : null,
    policyContract: policyContractRecord
      ? {
          bindings: arrayFromRecord(
            policyContractRecord,
            "bindings",
          ),
          hiddenInstructionDependency:
            booleanFromRecord(
              policyContractRecord,
              "hiddenInstructionDependency",
              "hidden_instruction_dependency",
            ) === true,
          rationale:
            stringFromRecord(policyContractRecord, "rationale") ||
            "Policy contract retained",
        }
      : null,
    sourceRanking,
    retainedWidgetState: retainedWidgetStateRecord
      ? {
          widgetFamily:
            stringFromRecord(
              retainedWidgetStateRecord,
              "widgetFamily",
              "widget_family",
            ) || null,
          bindings: Array.isArray(retainedWidgetStateRecord.bindings)
            ? retainedWidgetStateRecord.bindings
                .map((entry) => {
                  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
                    return null;
                  }
                  const binding = entry as Record<string, unknown>;
                  const key = stringFromRecord(binding, "key");
                  const value = stringFromRecord(binding, "value");
                  const source = stringFromRecord(binding, "source");
                  if (!key || !value || !source) {
                    return null;
                  }
                  return { key, value, source };
                })
                .filter(
                  (entry): entry is { key: string; value: string; source: string } =>
                    Boolean(entry),
                )
            : [],
          lastUpdatedAt:
            stringFromRecord(
              retainedWidgetStateRecord,
              "lastUpdatedAt",
              "last_updated_at",
            ) || null,
        }
      : null,
  };
  const hasBundle =
    bundle.clarificationPolicy ||
    bundle.fallbackPolicy ||
    bundle.presentationPolicy ||
    bundle.transformationPolicy ||
    bundle.riskProfile ||
    bundle.verificationContract ||
    bundle.policyContract ||
    bundle.sourceRanking.length > 0 ||
    bundle.retainedWidgetState;
  return hasBundle ? bundle : null;
}

function requestFrameFromRecord(
  record: Record<string, unknown> | null,
  stringFromRecord: StringFromRecord,
): PlanNormalizedRequestFrameSummary | null {
  if (!record) return null;
  const kind = (stringFromRecord(record, "kind") || "").trim().toLowerCase();
  switch (kind) {
    case "weather":
      return {
        kind: "weather",
        inferredLocations: arrayFromRecord(
          record,
          "inferredLocations",
          "inferred_locations",
        ),
        assumedLocation:
          stringFromRecord(record, "assumedLocation", "assumed_location") || null,
        temporalScope:
          stringFromRecord(record, "temporalScope", "temporal_scope") || null,
        missingSlots: arrayFromRecord(record, "missingSlots", "missing_slots"),
        clarificationRequiredSlots: arrayFromRecord(
          record,
          "clarificationRequiredSlots",
          "clarification_required_slots",
        ),
      };
    case "sports":
      return {
        kind: "sports",
        league: stringFromRecord(record, "league") || null,
        teamOrTarget:
          stringFromRecord(record, "teamOrTarget", "team_or_target") || null,
        dataScope: stringFromRecord(record, "dataScope", "data_scope") || null,
        missingSlots: arrayFromRecord(record, "missingSlots", "missing_slots"),
        clarificationRequiredSlots: arrayFromRecord(
          record,
          "clarificationRequiredSlots",
          "clarification_required_slots",
        ),
      };
    case "places":
      return {
        kind: "places",
        searchAnchor:
          stringFromRecord(record, "searchAnchor", "search_anchor") || null,
        category: stringFromRecord(record, "category") || null,
        locationScope:
          stringFromRecord(record, "locationScope", "location_scope") || null,
        missingSlots: arrayFromRecord(record, "missingSlots", "missing_slots"),
        clarificationRequiredSlots: arrayFromRecord(
          record,
          "clarificationRequiredSlots",
          "clarification_required_slots",
        ),
      };
    case "recipe":
      return {
        kind: "recipe",
        dish: stringFromRecord(record, "dish") || null,
        servings: stringFromRecord(record, "servings") || null,
        missingSlots: arrayFromRecord(record, "missingSlots", "missing_slots"),
        clarificationRequiredSlots: arrayFromRecord(
          record,
          "clarificationRequiredSlots",
          "clarification_required_slots",
        ),
      };
    case "message_compose":
      return {
        kind: "message_compose",
        channel: stringFromRecord(record, "channel") || null,
        recipientContext:
          stringFromRecord(record, "recipientContext", "recipient_context") || null,
        purpose: stringFromRecord(record, "purpose") || null,
        missingSlots: arrayFromRecord(record, "missingSlots", "missing_slots"),
        clarificationRequiredSlots: arrayFromRecord(
          record,
          "clarificationRequiredSlots",
          "clarification_required_slots",
        ),
      };
    case "user_input":
      return {
        kind: "user_input",
        interactionKind:
          stringFromRecord(record, "interactionKind", "interaction_kind") || null,
        explicitOptionsPresent:
          booleanFromRecord(
            record,
            "explicitOptionsPresent",
            "explicit_options_present",
          ) === true,
        missingSlots: arrayFromRecord(record, "missingSlots", "missing_slots"),
        clarificationRequiredSlots: arrayFromRecord(
          record,
          "clarificationRequiredSlots",
          "clarification_required_slots",
        ),
      };
    default:
      return null;
  }
}

function retainedLaneStateFromRecord(
  record: Record<string, unknown> | null,
  stringFromRecord: StringFromRecord,
): PlanRetainedLaneStateSummary | null {
  if (!record) return null;
  const activeLane = parseLaneFamily(
    stringFromRecord(record, "activeLane", "active_lane"),
  );
  if (!activeLane) return null;
  return {
    activeLane,
    activeToolWidgetFamily:
      stringFromRecord(record, "activeToolWidgetFamily", "active_tool_widget_family") ||
      null,
    activeArtifactId:
      stringFromRecord(record, "activeArtifactId", "active_artifact_id") || null,
    unresolvedClarificationQuestion:
      stringFromRecord(
        record,
        "unresolvedClarificationQuestion",
        "unresolved_clarification_question",
      ) || null,
    selectedProviderFamily:
      stringFromRecord(record, "selectedProviderFamily", "selected_provider_family") ||
      null,
    selectedProviderRouteLabel:
      stringFromRecord(
        record,
        "selectedProviderRouteLabel",
        "selected_provider_route_label",
      ) || null,
    selectedSourceFamily:
      parseSourceFamily(
        stringFromRecord(record, "selectedSourceFamily", "selected_source_family"),
      ) || null,
  };
}

function laneTransitionsFromRecord(
  record: Record<string, unknown> | null,
  stringFromRecord: StringFromRecord,
): PlanLaneTransitionSummary[] {
  if (!record) return [];
  const values = record.laneTransitions || record.lane_transitions;
  if (!Array.isArray(values)) return [];
  return values
    .map((entry) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        return null;
      }
      const transition = entry as Record<string, unknown>;
      const transitionKind = parseLaneTransitionKind(
        stringFromRecord(transition, "transitionKind", "transition_kind"),
      );
      const toLane = parseLaneFamily(
        stringFromRecord(transition, "toLane", "to_lane"),
      );
      if (!transitionKind || !toLane) return null;
      return {
        transitionKind,
        fromLane:
          parseLaneFamily(stringFromRecord(transition, "fromLane", "from_lane")) ||
          null,
        toLane,
        reason: stringFromRecord(transition, "reason") || "Lane transition retained",
        evidence: arrayFromRecord(transition, "evidence"),
      };
    })
    .filter((entry): entry is PlanLaneTransitionSummary => Boolean(entry));
}

function objectiveStateFromRecord(
  record: Record<string, unknown> | null,
  stringFromRecord: StringFromRecord,
): PlanObjectiveStateSummary | null {
  if (!record) return null;
  const status = parseWorkStatus(stringFromRecord(record, "status"));
  if (!status) return null;
  return {
    objectiveId:
      stringFromRecord(record, "objectiveId", "objective_id") || "objective",
    title: stringFromRecord(record, "title") || "Objective",
    status,
    successCriteria: arrayFromRecord(record, "successCriteria", "success_criteria"),
  };
}

function taskUnitStatesFromRecord(
  record: Record<string, unknown> | null,
  stringFromRecord: StringFromRecord,
): PlanTaskUnitStateSummary[] {
  if (!record) return [];
  const values = record.tasks;
  if (!Array.isArray(values)) return [];
  return values
    .map((entry) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        return null;
      }
      const task = entry as Record<string, unknown>;
      const status = parseWorkStatus(stringFromRecord(task, "status"));
      const laneFamily = parseLaneFamily(
        stringFromRecord(task, "laneFamily", "lane_family"),
      );
      if (!status || !laneFamily) return null;
      return {
        taskId: stringFromRecord(task, "taskId", "task_id") || "task",
        label: stringFromRecord(task, "label") || "Task",
        status,
        laneFamily,
        dependsOn: arrayFromRecord(task, "dependsOn", "depends_on"),
        summary: stringFromRecord(task, "summary") || null,
      };
    })
    .filter((entry): entry is PlanTaskUnitStateSummary => Boolean(entry));
}

function checkpointStatesFromRecord(
  record: Record<string, unknown> | null,
  stringFromRecord: StringFromRecord,
): PlanCheckpointStateSummary[] {
  if (!record) return [];
  const values = record.checkpoints;
  if (!Array.isArray(values)) return [];
  return values
    .map((entry) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        return null;
      }
      const checkpoint = entry as Record<string, unknown>;
      const status = parseWorkStatus(stringFromRecord(checkpoint, "status"));
      if (!status) return null;
      return {
        checkpointId:
          stringFromRecord(checkpoint, "checkpointId", "checkpoint_id") ||
          "checkpoint",
        label: stringFromRecord(checkpoint, "label") || "Checkpoint",
        status,
        summary: stringFromRecord(checkpoint, "summary") || "",
      };
    })
    .filter((entry): entry is PlanCheckpointStateSummary => Boolean(entry));
}

function completionInvariantFromRecord(
  record: Record<string, unknown> | null,
  stringFromRecord: StringFromRecord,
): PlanCompletionInvariantSummary | null {
  if (!record) return null;
  const summary = stringFromRecord(record, "summary");
  if (!summary) return null;
  return {
    summary,
    satisfied: booleanFromRecord(record, "satisfied") === true,
    outstandingRequirements: arrayFromRecord(
      record,
      "outstandingRequirements",
      "outstanding_requirements",
    ),
  };
}

function orchestrationStateFromRecord(
  record: Record<string, unknown> | null,
  stringFromRecord: StringFromRecord,
): PlanOrchestrationStateSummary | null {
  if (!record) return null;
  const objective = objectiveStateFromRecord(
    recordFromRecord(record, "objective"),
    stringFromRecord,
  );
  const tasks = taskUnitStatesFromRecord(record, stringFromRecord);
  const checkpoints = checkpointStatesFromRecord(record, stringFromRecord);
  const completionInvariant = completionInvariantFromRecord(
    recordFromRecord(record, "completionInvariant", "completion_invariant"),
    stringFromRecord,
  );
  if (!objective && tasks.length === 0 && checkpoints.length === 0 && !completionInvariant) {
    return null;
  }
  return {
    objective,
    tasks,
    checkpoints,
    completionInvariant,
  };
}

export type KnownPlaybookRouteContract = {
  routeFamily: PlanSummary["routeFamily"];
  topology: PlanSummary["topology"];
  plannerAuthority: PlanSummary["plannerAuthority"];
  verifierRole: PlanSummary["verifierRole"] | null;
  requiresVerifier: boolean;
};

const BUILTIN_PLAYBOOK_ROUTE_CONTRACTS: Record<
  string,
  KnownPlaybookRouteContract
> = {
  evidence_audited_patch: {
    routeFamily: "coding",
    topology: "planner_specialist_verifier",
    plannerAuthority: "kernel",
    verifierRole: "test_verifier",
    requiresVerifier: true,
  },
  citation_grounded_brief: {
    routeFamily: "research",
    topology: "planner_specialist_verifier",
    plannerAuthority: "kernel",
    verifierRole: "citation_verifier",
    requiresVerifier: true,
  },
  browser_postcondition_gate: {
    routeFamily: "computer_use",
    topology: "planner_specialist_verifier",
    plannerAuthority: "kernel",
    verifierRole: "postcondition_verifier",
    requiresVerifier: true,
  },
  artifact_generation_gate: {
    routeFamily: "artifacts",
    topology: "planner_specialist_verifier",
    plannerAuthority: "kernel",
    verifierRole: "artifact_validation_verifier",
    requiresVerifier: true,
  },
};

const BUILTIN_ROUTE_CONTRACT_ALIASES: Record<string, string> = {
  repo_context_brief: "evidence_audited_patch",
  patch_build_verify: "evidence_audited_patch",
  targeted_test_audit: "evidence_audited_patch",
  patch_synthesis_handoff: "evidence_audited_patch",
  live_research_brief: "citation_grounded_brief",
  citation_audit: "citation_grounded_brief",
  ui_state_brief: "browser_postcondition_gate",
  browser_postcondition_pass: "browser_postcondition_gate",
  browser_postcondition_audit: "browser_postcondition_gate",
  postcondition_audit: "browser_postcondition_gate",
  artifact_context_brief: "artifact_generation_gate",
  artifact_generate_repair: "artifact_generation_gate",
  artifact_validation_audit: "artifact_generation_gate",
  artifact_candidate_generation: "artifact_generation_gate",
};

function normalizePlaybookLookupKey(value?: string): string | null {
  const normalized = (value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return normalized || null;
}

function builtinPlaybookRouteContractForValue(
  value?: string,
): KnownPlaybookRouteContract | null {
  const key = normalizePlaybookLookupKey(value);
  if (!key) {
    return null;
  }
  const playbookKey = BUILTIN_ROUTE_CONTRACT_ALIASES[key] || key;
  return BUILTIN_PLAYBOOK_ROUTE_CONTRACTS[playbookKey] || null;
}

export function parseRouteFamily(
  value?: string,
): PlanSummary["routeFamily"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "research":
    case "coding":
    case "integrations":
    case "communication":
    case "user_input":
    case "tool_widget":
    case "computer_use":
    case "artifacts":
    case "general":
      return value!.trim().toLowerCase() as PlanSummary["routeFamily"];
    default:
      return null;
  }
}

export function parseTopology(
  value?: string,
): PlanSummary["topology"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "single_agent":
    case "planner_specialist":
    case "planner_specialist_verifier":
      return value!.trim().toLowerCase() as PlanSummary["topology"];
    default:
      return null;
  }
}

export function parsePlannerAuthority(
  value?: string,
): PlanSummary["plannerAuthority"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "kernel":
    case "primary_agent":
      return value!.trim().toLowerCase() as PlanSummary["plannerAuthority"];
    default:
      return null;
  }
}

export function parseVerifierState(
  value?: string,
): PlanSummary["verifierState"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "not_engaged":
    case "queued":
    case "active":
    case "passed":
    case "blocked":
      return value!.trim().toLowerCase() as PlanSummary["verifierState"];
    default:
      return null;
  }
}

export function parseVerifierRole(
  value?: string,
): PlanSummary["verifierRole"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "verifier":
    case "citation_verifier":
    case "test_verifier":
    case "postcondition_verifier":
    case "artifact_validation_verifier":
      return value!.trim().toLowerCase() as PlanSummary["verifierRole"];
    default:
      return null;
  }
}

export function parseVerifierOutcome(
  value?: string,
): PlanSummary["verifierOutcome"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "pass":
    case "warning":
    case "blocked":
      return value!.trim().toLowerCase() as PlanSummary["verifierOutcome"];
    default:
      return null;
  }
}

export function parseApprovalState(
  value?: string,
): PlanSummary["approvalState"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "pending":
    case "require_approval":
    case "approval_required":
      return "pending";
    case "approved":
      return "approved";
    case "denied":
      return "denied";
    case "clear":
    case "cleared":
    case "none":
    case "allowed":
    case "not_needed":
      return "clear";
    default:
      return null;
  }
}

export function parseOutputIntent(
  value?: string,
): PlanOutputIntent | null {
  switch ((value || "").trim().toLowerCase()) {
    case "direct_inline":
    case "file":
    case "artifact":
    case "inline_visual":
    case "delegated":
    case "tool_execution":
      return value!.trim().toLowerCase() as PlanOutputIntent;
    default:
      return null;
  }
}

export function explicitRouteDecision(
  events: ActivityEventRef[],
  digestRecord: RecordAccessor,
  detailsRecord: RecordAccessor,
  stringFromRecord: StringFromRecord,
): PlanRouteDecisionSummary | null {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const routeDecision =
      recordFromRecord(details, "route_decision") ||
      recordFromRecord(digest, "route_decision");
    const routeDecisionRecord = routeDecision || {};
    const effectiveToolSurface =
      (routeDecision && recordFromRecord(routeDecision, "effective_tool_surface")) ||
      recordFromRecord(details, "effective_tool_surface") ||
      recordFromRecord(digest, "effective_tool_surface");
    const laneFrame =
      recordFromRecord(details, "lane_frame", "laneFrame") ||
      recordFromRecord(digest, "lane_frame", "laneFrame") ||
      recordFromRecord(routeDecisionRecord, "lane_frame", "laneFrame");
    const requestFrame =
      recordFromRecord(details, "request_frame", "requestFrame") ||
      recordFromRecord(digest, "request_frame", "requestFrame") ||
      recordFromRecord(routeDecisionRecord, "request_frame", "requestFrame");
    const sourceSelection =
      recordFromRecord(details, "source_selection", "sourceSelection") ||
      recordFromRecord(digest, "source_selection", "sourceSelection") ||
      recordFromRecord(routeDecisionRecord, "source_selection", "sourceSelection");
    const retainedLaneState =
      recordFromRecord(details, "retained_lane_state", "retainedLaneState") ||
      recordFromRecord(digest, "retained_lane_state", "retainedLaneState") ||
      recordFromRecord(routeDecisionRecord, "retained_lane_state", "retainedLaneState");
    const orchestrationState =
      recordFromRecord(details, "orchestration_state", "orchestrationState") ||
      recordFromRecord(digest, "orchestration_state", "orchestrationState") ||
      recordFromRecord(routeDecisionRecord, "orchestration_state", "orchestrationState");
    const domainPolicyBundle =
      recordFromRecord(details, "domain_policy_bundle", "domainPolicyBundle") ||
      recordFromRecord(digest, "domain_policy_bundle", "domainPolicyBundle") ||
      recordFromRecord(routeDecisionRecord, "domain_policy_bundle", "domainPolicyBundle");
    const laneTransitions = laneTransitionsFromRecord(
      {
        lane_transitions:
          details.lane_transitions ??
          details.laneTransitions ??
          digest.lane_transitions ??
          digest.laneTransitions ??
          routeDecisionRecord.lane_transitions ??
          routeDecisionRecord.laneTransitions,
      },
      stringFromRecord,
    );
    const routeFamily = parseRouteFamily(
      stringFromRecord(routeDecisionRecord, "route_family") ||
        stringFromRecord(digest, "route_family") ||
        stringFromRecord(details, "route_family"),
    );
    const outputIntent = parseOutputIntent(
      stringFromRecord(routeDecisionRecord, "output_intent") ||
        stringFromRecord(digest, "output_intent") ||
        stringFromRecord(details, "output_intent"),
    );
    const directAnswerAllowed = booleanFromRecord(
      routeDecisionRecord,
      "direct_answer_allowed",
    ) ??
      booleanFromRecord(digest, "direct_answer_allowed") ??
      booleanFromRecord(details, "direct_answer_allowed");

    if (
      !routeFamily &&
      !outputIntent &&
      directAnswerAllowed === null &&
      !laneFrame &&
      !requestFrame &&
      !sourceSelection &&
      !retainedLaneState &&
      laneTransitions.length === 0 &&
      !orchestrationState &&
      !domainPolicyBundle
    ) {
      continue;
    }

    return {
      routeFamily: routeFamily || "general",
      directAnswerAllowed: directAnswerAllowed === true,
      directAnswerBlockers: arrayFromRecord(
        routeDecisionRecord,
        "direct_answer_blockers",
      ).concat(
        arrayFromRecord(digest, "direct_answer_blockers"),
        arrayFromRecord(details, "direct_answer_blockers"),
      ),
      currentnessOverride:
        (booleanFromRecord(routeDecisionRecord, "currentness_override") ??
          booleanFromRecord(digest, "currentness_override") ??
          booleanFromRecord(details, "currentness_override")) === true,
      connectorCandidateCount: Number(
        routeDecisionRecord.connector_candidate_count ||
          digest.connector_candidate_count ||
          details.connector_candidate_count ||
          0,
      ),
      selectedProviderFamily:
        stringFromRecord(routeDecisionRecord, "selected_provider_family") ||
        stringFromRecord(digest, "selected_provider_family") ||
        stringFromRecord(details, "selected_provider_family") ||
        null,
      selectedProviderRouteLabel:
        stringFromRecord(routeDecisionRecord, "selected_provider_route_label") ||
        stringFromRecord(digest, "selected_provider_route_label") ||
        stringFromRecord(details, "selected_provider_route_label") ||
        null,
      connectorFirstPreference:
        (booleanFromRecord(routeDecisionRecord, "connector_first_preference") ??
          booleanFromRecord(digest, "connector_first_preference") ??
          booleanFromRecord(details, "connector_first_preference")) === true,
      narrowToolPreference:
        (booleanFromRecord(routeDecisionRecord, "narrow_tool_preference") ??
          booleanFromRecord(digest, "narrow_tool_preference") ??
          booleanFromRecord(details, "narrow_tool_preference")) === true,
      fileOutputIntent:
        (booleanFromRecord(routeDecisionRecord, "file_output_intent") ??
          booleanFromRecord(digest, "file_output_intent") ??
          booleanFromRecord(details, "file_output_intent")) === true,
      artifactOutputIntent:
        (booleanFromRecord(routeDecisionRecord, "artifact_output_intent") ??
          booleanFromRecord(digest, "artifact_output_intent") ??
          booleanFromRecord(details, "artifact_output_intent")) === true,
      inlineVisualIntent:
        (booleanFromRecord(routeDecisionRecord, "inline_visual_intent") ??
          booleanFromRecord(digest, "inline_visual_intent") ??
          booleanFromRecord(details, "inline_visual_intent")) === true,
      skillPrepRequired:
        (booleanFromRecord(routeDecisionRecord, "skill_prep_required") ??
          booleanFromRecord(digest, "skill_prep_required") ??
          booleanFromRecord(details, "skill_prep_required")) === true,
      outputIntent: outputIntent || "tool_execution",
      effectiveToolSurface: {
        projectedTools: arrayFromRecord(
          effectiveToolSurface || digest,
          "projected_tools",
        ),
        primaryTools: arrayFromRecord(
          effectiveToolSurface || digest,
          "primary_tools",
        ),
        broadFallbackTools: arrayFromRecord(
          effectiveToolSurface || digest,
          "broad_fallback_tools",
        ),
        diagnosticTools: arrayFromRecord(
          effectiveToolSurface || digest,
          "diagnostic_tools",
        ),
      },
      laneFrame: laneFrameFromRecord(laneFrame, stringFromRecord),
      requestFrame: requestFrameFromRecord(requestFrame, stringFromRecord),
      sourceSelection: sourceSelectionFromRecord(sourceSelection, stringFromRecord),
      retainedLaneState: retainedLaneStateFromRecord(
        retainedLaneState,
        stringFromRecord,
      ),
      laneTransitions,
      orchestrationState: orchestrationStateFromRecord(
        orchestrationState,
        stringFromRecord,
      ),
      domainPolicyBundle: domainPolicyBundleFromRecord(
        domainPolicyBundle,
        stringFromRecord,
      ),
    };
  }

  return null;
}

export function explicitRouteContract(
  events: ActivityEventRef[],
  digestRecord: RecordAccessor,
  detailsRecord: RecordAccessor,
  stringFromRecord: StringFromRecord,
): ExplicitRouteContract {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const routeDecision =
      recordFromRecord(details, "route_decision") ||
      recordFromRecord(digest, "route_decision");
    const routeFamily = parseRouteFamily(
      stringFromRecord(routeDecision || {}, "route_family") ||
      stringFromRecord(digest, "route_family") ||
        stringFromRecord(details, "route_family"),
    );
    const topology = parseTopology(
      stringFromRecord(digest, "topology") ||
        stringFromRecord(details, "topology"),
    );
    const plannerAuthority = parsePlannerAuthority(
      stringFromRecord(digest, "planner_authority") ||
        stringFromRecord(details, "planner_authority"),
    );
    const verifierState = parseVerifierState(
      stringFromRecord(digest, "verifier_state") ||
        stringFromRecord(details, "verifier_state"),
    );
    const verifierRole = parseVerifierRole(
      stringFromRecord(digest, "verifier_role") ||
        stringFromRecord(details, "verifier_role"),
    );
    const verifierOutcome = parseVerifierOutcome(
      stringFromRecord(digest, "verifier_outcome") ||
        stringFromRecord(details, "verifier_outcome"),
    );
    if (
      routeFamily ||
      topology ||
      plannerAuthority ||
      verifierState ||
      verifierRole ||
      verifierOutcome
    ) {
      return {
        routeFamily,
        topology,
        plannerAuthority,
        verifierState,
        verifierRole,
        verifierOutcome,
      };
    }
  }

  return {
    routeFamily: null,
    topology: null,
    plannerAuthority: null,
    verifierState: null,
    verifierRole: null,
    verifierOutcome: null,
  };
}

export function impliedRouteContractFromPlaybook(
  events: ActivityEventRef[],
  digestRecord: RecordAccessor,
  detailsRecord: RecordAccessor,
  stringFromRecord: StringFromRecord,
): KnownPlaybookRouteContract | null {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const contractCandidates = [
      stringFromRecord(digest, "playbook_id"),
      stringFromRecord(details, "playbook_id"),
      stringFromRecord(digest, "playbook_label"),
      stringFromRecord(details, "playbook_label"),
      stringFromRecord(digest, "workflow_id"),
      stringFromRecord(details, "workflow_id"),
      stringFromRecord(digest, "selected_route"),
      stringFromRecord(details, "selected_route"),
      stringFromRecord(digest, "route"),
      stringFromRecord(details, "route"),
    ];
    for (const candidate of contractCandidates) {
      const contract = builtinPlaybookRouteContractForValue(candidate);
      if (contract) {
        return contract;
      }
    }
  }

  return null;
}

export function defaultVerifierRole(
  routeFamily: PlanSummary["routeFamily"],
  topology: PlanSummary["topology"],
): PlanSummary["verifierRole"] | null {
  if (topology !== "planner_specialist_verifier") {
    return null;
  }
  switch (routeFamily) {
    case "research":
      return "citation_verifier";
    case "coding":
      return "test_verifier";
    case "computer_use":
      return "postcondition_verifier";
    case "artifacts":
      return "artifact_validation_verifier";
    default:
      return "verifier";
  }
}

function verifierOutcomeFromVerdict(
  verdict?: string | null,
): PlanSummary["verifierOutcome"] | null {
  switch ((verdict || "").trim().toLowerCase()) {
    case "passed":
      return "pass";
    case "blocked":
      return "blocked";
    case "needs_attention":
    case "unknown":
      return "warning";
    default:
      return null;
  }
}

export function defaultVerifierOutcome(
  verifierState: PlanSummary["verifierState"],
  researchVerification: PlanSummary["researchVerification"],
  codingVerification: PlanSummary["codingVerification"],
  computerUseVerification: PlanSummary["computerUseVerification"],
  artifactQuality: PlanSummary["artifactQuality"],
): PlanSummary["verifierOutcome"] | null {
  return (
    verifierOutcomeFromVerdict(researchVerification?.verdict) ||
    verifierOutcomeFromVerdict(codingVerification?.verdict) ||
    verifierOutcomeFromVerdict(computerUseVerification?.verdict) ||
    verifierOutcomeFromVerdict(artifactQuality?.verdict) ||
    (verifierState === "blocked" ? "blocked" : null)
  );
}

export function verifierRoleTitle(
  role: PlanSummary["verifierRole"] | null,
): string {
  switch (role) {
    case "citation_verifier":
      return "Citation verifier";
    case "test_verifier":
      return "Test verifier";
    case "postcondition_verifier":
      return "Postcondition verifier";
    case "artifact_validation_verifier":
      return "Artifact quality verifier";
    default:
      return "Verifier";
  }
}
