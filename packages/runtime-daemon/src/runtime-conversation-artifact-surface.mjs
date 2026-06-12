const conversationArtifactMutationFacadeRetirementEvidenceRefs = [
  "runtime_conversation_artifact_control_js_facade_retired",
  "conversation_artifact_create_js_facade_retired",
  "conversation_artifact_action_js_facade_retired",
  "conversation_artifact_export_js_facade_retired",
  "conversation_artifact_promote_js_facade_retired",
  "rust_daemon_core_conversation_artifact_control_required",
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

export function createRuntimeConversationArtifactSurface({
  contextPolicyRunner = null,
  runtimeError = ({ status = 500, code = "runtime_conversation_artifact_error", message, details }) =>
    Object.assign(new Error(message), { status, code, details }),
} = {}) {
  function throwConversationArtifactRustCoreRequired({
    operation,
    operationKind,
    threadId = null,
    artifactId = null,
  }) {
    throw runtimeError({
      status: 501,
      code: "runtime_conversation_artifact_control_rust_core_required",
      message:
        "Runtime conversation artifact lifecycle and projection facades require direct Rust daemon-core admission, persistence, and projection.",
      details: {
        rust_core_boundary: "runtime.conversation_artifact_control",
        operation,
        operation_kind: operationKind,
        ...(threadId ? { thread_id: threadId } : {}),
        ...(artifactId ? { artifact_id: artifactId } : {}),
        evidence_refs: [
          ...conversationArtifactMutationFacadeRetirementEvidenceRefs,
          `${operation}_js_facade_retired`,
        ],
      },
    });
  }

  function conversationArtifactProjectionRunner(store, request = {}) {
    const runner = store?.contextPolicyRunner ?? contextPolicyRunner;
    if (runner?.projectRuntimeConversationArtifactProjection) return runner;
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

  function candidateConversationArtifacts(store) {
    const list = store?.conversationArtifacts?.list;
    if (typeof list !== "function") {
      throw runtimeError({
        status: 500,
        code: "runtime_conversation_artifact_read_projection_candidates_missing",
        message:
          "Runtime conversation artifact read projection candidates are unavailable.",
        details: {
          rust_core_boundary: "runtime.conversation_artifact_projection",
          source: "runtime.conversation_artifact_surface.read_projection",
        },
      });
    }
    return list.call(store.conversationArtifacts, {});
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
    const runner = conversationArtifactProjectionRunner(store, requestContext);
    const artifacts = candidateConversationArtifacts(store);
    const request = {
      operation: "runtime_conversation_artifact_projection",
      operation_kind: operationKind,
      projection_kind: projectionKind,
      thread_id: threadId,
      artifact_id: artifactId,
      source: "runtime.conversation_artifact_surface.read_projection",
      projection: { artifacts },
      evidence_refs: conversationArtifactReadProjectionEvidenceRefs,
    };
    const result = runner.projectRuntimeConversationArtifactProjection(request);
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
      void store;
      void input;
      throwConversationArtifactRustCoreRequired({
        operation: "conversation_artifact_create",
        operationKind: "artifact.conversation.create",
        threadId,
      });
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
      void store;
      void input;
      throwConversationArtifactRustCoreRequired({
        operation: "conversation_artifact_action",
        operationKind: "artifact.conversation.action",
        artifactId,
      });
    },
    exportConversationArtifact(store, artifactId, input = {}) {
      void store;
      void input;
      throwConversationArtifactRustCoreRequired({
        operation: "conversation_artifact_export",
        operationKind: "artifact.conversation.export",
        artifactId,
      });
    },
    promoteConversationArtifact(store, artifactId, input = {}) {
      void store;
      void input;
      throwConversationArtifactRustCoreRequired({
        operation: "conversation_artifact_promote",
        operationKind: "artifact.conversation.promote",
        artifactId,
      });
    },
  };
}
