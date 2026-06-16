import { commitRuntimeArtifactRecord } from "./runtime-artifact-state-commit.mjs";

const conversationArtifactControlEvidenceRefs = [
  "runtime_conversation_artifact_control_rust_owned",
  "runtime_conversation_artifact_state_commit_rust_owned",
  "runtime_conversation_artifact_control_js_facade_retired",
  "conversation_artifact_create_js_facade_retired",
  "conversation_artifact_action_js_facade_retired",
  "conversation_artifact_export_js_facade_retired",
  "conversation_artifact_promote_js_facade_retired",
  "agentgres_conversation_artifact_truth_required",
];

const conversationArtifactReadProjectionEvidenceRefs = [
  "runtime_conversation_artifact_read_projection_rust_owned",
  "conversation_artifact_read_projection_js_facade_retired",
  "conversation_artifact_list_js_facade_retired",
  "conversation_artifact_get_js_facade_retired",
  "conversation_artifact_revision_list_js_facade_retired",
  "agentgres_conversation_artifact_projection_truth_required",
];

function optionalString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function validProjectedConversationArtifactRead(projectionKind, projection) {
  if (projectionKind === "list" || projectionKind === "revisions") return Array.isArray(projection);
  if (projectionKind === "get") return projection === null || (projection && typeof projection === "object" && !Array.isArray(projection));
  return false;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

export function createRuntimeConversationArtifactSurface({
  contextPolicyCore = null,
  runtimeError = ({ status = 500, code = "runtime_conversation_artifact_error", message, details }) =>
    Object.assign(new Error(message), { status, code, details }),
} = {}) {
  function throwConversationArtifactControlRequired({
    operation,
    operationKind,
    threadId = null,
    artifactId = null,
    code = "runtime_conversation_artifact_control_rust_core_required",
    source = "runtime.conversation_artifact_surface.control",
  }) {
    throw runtimeError({
      status: 501,
      code,
      message:
        "Runtime conversation artifact control requires direct Rust daemon-core planning and Agentgres artifact-state admission.",
      details: {
        rust_core_boundary: "runtime.conversation_artifact_control",
        operation,
        operation_kind: operationKind,
        ...(threadId ? { thread_id: threadId } : {}),
        ...(artifactId ? { artifact_id: artifactId } : {}),
        source,
        evidence_refs: [
          ...conversationArtifactControlEvidenceRefs,
          `${operation}_rust_owned`,
        ],
      },
    });
  }

  function requireConversationArtifactControlCore(request = {}) {
    if (contextPolicyCore?.planRuntimeConversationArtifactControl) return contextPolicyCore;
    throwConversationArtifactControlRequired({
      operation: request.operation ?? "conversation_artifact_control",
      operationKind: request.operation_kind ?? "artifact.conversation.control",
      threadId: request.thread_id ?? null,
      artifactId: request.artifact_id ?? null,
    });
  }

  function assertConversationArtifactCommitAvailable(store, request = {}) {
    if (typeof store?.commitRuntimeArtifactState === "function") return;
    throwConversationArtifactControlRequired({
      operation: request.operation ?? "conversation_artifact_control",
      operationKind: request.operation_kind ?? "artifact.conversation.control",
      threadId: request.thread_id ?? null,
      artifactId: request.artifact_id ?? null,
      code: "runtime_conversation_artifact_agentgres_commit_required",
      source: "runtime.conversation_artifact_surface.agentgres_commit",
    });
  }

  function requireConversationArtifactProjectionCore(request = {}) {
    if (contextPolicyCore?.projectRuntimeConversationArtifactProjection) return contextPolicyCore;
    throw runtimeError({
      status: 501,
      code: "runtime_conversation_artifact_read_projection_rust_projection_missing",
      message:
        "Runtime conversation artifact read projections require Rust daemon-core projection over Agentgres artifact truth.",
      details: {
        rust_core_boundary: "runtime.conversation_artifact_projection",
        operation: request.route_operation ?? null,
        operation_kind: request.operation_kind ?? null,
        projection_kind: request.projection_kind ?? null,
        thread_id: request.thread_id ?? null,
        artifact_id: request.artifact_id ?? null,
        source: "runtime.conversation_artifact_surface.read_projection",
        evidence_refs: conversationArtifactReadProjectionEvidenceRefs,
      },
    });
  }

  function requireConversationArtifactDaemonStateDir(store, request = {}) {
    const stateDir = optionalString(store?.stateDir);
    if (stateDir) return stateDir;
    throw runtimeError({
      status: 501,
      code: "runtime_conversation_artifact_daemon_state_dir_required",
      message:
        "Runtime conversation artifact projection and control require the daemon Agentgres state_dir; ConversationArtifactStore state_dir fallbacks are retired.",
      details: {
        rust_core_boundary: request.rust_core_boundary ?? "runtime.conversation_artifact_projection",
        operation: request.operation ?? null,
        operation_kind: request.operation_kind ?? null,
        projection_kind: request.projection_kind ?? null,
        thread_id: request.thread_id ?? null,
        artifact_id: request.artifact_id ?? null,
        source: request.source ?? "runtime.conversation_artifact_surface",
        evidence_refs: [
          ...conversationArtifactControlEvidenceRefs,
          ...conversationArtifactReadProjectionEvidenceRefs,
          "runtime_conversation_artifact_store_state_dir_fallback_retired",
        ],
      },
    });
  }

  function conversationArtifactControlRequestPayload(input = {}) {
    const source = objectRecord(input) ?? {};
    const request = {};
    for (const key of [
      "title",
      "body",
      "content",
      "artifact_class",
      "output_modality",
      "state_label",
      "source_refs",
      "original_refs",
      "projection_refs",
      "preview_refs",
      "trace_refs",
      "policy_refs",
      "receipt_refs",
      "log_refs",
      "rollback_refs",
      "idempotency_key",
      "created_at",
      "updated_at",
      "action_kind",
      "export_format",
      "promotion_target",
      "requested_by",
      "reason",
    ]) {
      if (source[key] !== undefined) request[key] = source[key];
    }
    return request;
  }

  function planConversationArtifactControl(store, {
    operation,
    operationKind,
    threadId = null,
    artifactId = null,
    input = {},
  }) {
    const requestContext = {
      operation,
      operation_kind: operationKind,
      thread_id: threadId,
      artifact_id: artifactId,
    };
    const core = requireConversationArtifactControlCore(requestContext);
    assertConversationArtifactCommitAvailable(store, requestContext);
    const request = {
      operation,
      operation_kind: operationKind,
      thread_id: threadId,
      artifact_id: artifactId,
      state_dir: requireConversationArtifactDaemonStateDir(store, {
        rust_core_boundary: "runtime.conversation_artifact_control",
        operation,
        operation_kind: operationKind,
        thread_id: threadId,
        artifact_id: artifactId,
        source: "runtime.conversation_artifact_surface.control",
      }),
      request: conversationArtifactControlRequestPayload(input),
      evidence_refs: [
        ...conversationArtifactControlEvidenceRefs,
        `${operation}_rust_owned`,
      ],
    };
    const plan = core.planRuntimeConversationArtifactControl(request);
    return assertConversationArtifactControlPlan(plan, {
      operation,
      operationKind,
      threadId,
      artifactId,
    });
  }

  function assertConversationArtifactControlPlan(plan, {
    operation,
    operationKind,
    threadId = null,
    artifactId = null,
  }) {
    const artifact = objectRecord(plan?.artifact);
    const result = objectRecord(plan?.result);
    const plannedArtifactId = optionalString(plan?.artifact_id ?? artifact?.id ?? artifact?.artifact_id);
    if (
      plan?.operation_kind !== operationKind ||
      !artifact ||
      !result ||
      !plannedArtifactId ||
      (artifactId && plannedArtifactId !== artifactId)
    ) {
      throw runtimeError({
        status: 502,
        code: "runtime_conversation_artifact_control_plan_invalid",
        message:
          "Rust conversation artifact control returned an invalid control plan.",
        details: {
          rust_core_boundary: "runtime.conversation_artifact_control",
          operation,
          operation_kind: operationKind,
          ...(threadId ? { thread_id: threadId } : {}),
          ...(artifactId ? { artifact_id: artifactId } : {}),
          planned_operation_kind: plan?.operation_kind ?? null,
          planned_artifact_id: plannedArtifactId,
          source: "runtime.conversation_artifact_surface.control",
        },
      });
    }
    return {
      ...plan,
      artifact_id: plannedArtifactId,
      artifact,
      result,
    };
  }

  function commitConversationArtifactControl(store, plan) {
    try {
      const commit = commitRuntimeArtifactRecord(store, plan.artifact, plan.operation_kind);
      if (typeof store?.conversationArtifacts?.load === "function") {
        store.conversationArtifacts.load();
      }
      return {
        ...plan.result,
        artifact_id: plan.artifact_id,
        operation_kind: plan.operation_kind,
        artifact: plan.artifact,
        receipt_refs: plan.receipt_refs ?? [],
        policy_decision_refs: plan.policy_decision_refs ?? [],
        evidence_refs: plan.evidence_refs ?? [],
        commit,
      };
    } catch (error) {
      throw runtimeError({
        status: 502,
        code: "runtime_conversation_artifact_agentgres_commit_failed",
        message:
          "Rust Agentgres artifact-state admission rejected the conversation artifact control record.",
        details: {
          rust_core_boundary: "runtime.conversation_artifact_control",
          operation_kind: plan?.operation_kind ?? null,
          artifact_id: plan?.artifact_id ?? null,
          cause: error?.message ?? String(error),
          source: "runtime.conversation_artifact_surface.agentgres_commit",
          evidence_refs: conversationArtifactControlEvidenceRefs,
        },
      });
    }
  }

  function projectConversationArtifactRead(store, projectionKind, {
    routeOperation,
    threadId = null,
    artifactId = null,
  } = {}) {
    const operationKind = `runtime.conversation_artifact_projection.${projectionKind}`;
    const requestContext = {
      route_operation: routeOperation,
      operation_kind: operationKind,
      projection_kind: projectionKind,
      thread_id: threadId,
      artifact_id: artifactId,
    };
    const core = requireConversationArtifactProjectionCore(requestContext);
    const request = {
      operation: "runtime_conversation_artifact_projection",
      operation_kind: operationKind,
      projection_kind: projectionKind,
      thread_id: threadId,
      artifact_id: artifactId,
      state_dir: requireConversationArtifactDaemonStateDir(store, {
        rust_core_boundary: "runtime.conversation_artifact_projection",
        operation: "runtime_conversation_artifact_projection",
        operation_kind: operationKind,
        projection_kind: projectionKind,
        thread_id: threadId,
        artifact_id: artifactId,
        source: "runtime.conversation_artifact_surface.read_projection",
      }),
      source: "runtime.conversation_artifact_surface.read_projection",
      evidence_refs: conversationArtifactReadProjectionEvidenceRefs,
    };
    const result = core.projectRuntimeConversationArtifactProjection(request);
    if (
      result?.projection_kind !== projectionKind ||
      !validProjectedConversationArtifactRead(projectionKind, result?.projection)
    ) {
      throw runtimeError({
        status: 502,
        code: "runtime_conversation_artifact_read_projection_rust_projection_invalid",
        message:
          "Rust conversation artifact projection returned an invalid route projection.",
        details: {
          rust_core_boundary: "runtime.conversation_artifact_projection",
          expected_projection_kind: projectionKind,
          actual_projection_kind: result?.projection_kind ?? null,
          operation: request.operation,
          operation_kind: request.operation_kind,
          source: "runtime.conversation_artifact_surface.read_projection",
        },
      });
    }
    return result.projection;
  }

  return {
    createConversationArtifact(store, threadId, input = {}) {
      const plan = planConversationArtifactControl(store, {
        operation: "conversation_artifact_create",
        operationKind: "artifact.conversation.create",
        threadId,
        input,
      });
      return commitConversationArtifactControl(store, plan);
    },
    listConversationArtifacts(store, query = {}) {
      return projectConversationArtifactRead(store, "list", {
        routeOperation: "conversation_artifact_list",
        threadId: optionalString(query.thread_id),
      });
    },
    getConversationArtifact(store, artifactId) {
      return projectConversationArtifactRead(store, "get", {
        routeOperation: "conversation_artifact_get",
        artifactId: optionalString(artifactId),
      });
    },
    listConversationArtifactRevisions(store, artifactId) {
      return projectConversationArtifactRead(store, "revisions", {
        routeOperation: "conversation_artifact_revision_list",
        artifactId: optionalString(artifactId),
      });
    },
    performConversationArtifactAction(store, artifactId, input = {}) {
      const plan = planConversationArtifactControl(store, {
        operation: "conversation_artifact_action",
        operationKind: "artifact.conversation.action",
        artifactId,
        input,
      });
      return commitConversationArtifactControl(store, plan);
    },
    exportConversationArtifact(store, artifactId, input = {}) {
      const plan = planConversationArtifactControl(store, {
        operation: "conversation_artifact_export",
        operationKind: "artifact.conversation.export",
        artifactId,
        input,
      });
      return commitConversationArtifactControl(store, plan);
    },
    promoteConversationArtifact(store, artifactId, input = {}) {
      const plan = planConversationArtifactControl(store, {
        operation: "conversation_artifact_promote",
        operationKind: "artifact.conversation.promote",
        artifactId,
        input,
      });
      return commitConversationArtifactControl(store, plan);
    },
  };
}
