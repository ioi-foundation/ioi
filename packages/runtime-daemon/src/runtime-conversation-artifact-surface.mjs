const conversationArtifactControlFacadeRetirementEvidenceRefs = [
  "runtime_conversation_artifact_control_js_facade_retired",
  "conversation_artifact_list_js_facade_retired",
  "conversation_artifact_get_js_facade_retired",
  "conversation_artifact_revision_list_js_facade_retired",
  "conversation_artifact_create_js_facade_retired",
  "conversation_artifact_action_js_facade_retired",
  "conversation_artifact_export_js_facade_retired",
  "conversation_artifact_promote_js_facade_retired",
  "rust_daemon_core_conversation_artifact_control_required",
  "agentgres_conversation_artifact_truth_required",
];

export function createRuntimeConversationArtifactSurface({
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
          ...conversationArtifactControlFacadeRetirementEvidenceRefs,
          `${operation}_js_facade_retired`,
        ],
      },
    });
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
      void store;
      void query;
      throwConversationArtifactRustCoreRequired({
        operation: "conversation_artifact_list",
        operationKind: "artifact.conversation.list",
      });
    },
    getConversationArtifact(store, artifactId) {
      void store;
      throwConversationArtifactRustCoreRequired({
        operation: "conversation_artifact_get",
        operationKind: "artifact.conversation.get",
        artifactId,
      });
    },
    listConversationArtifactRevisions(store, artifactId) {
      void store;
      throwConversationArtifactRustCoreRequired({
        operation: "conversation_artifact_revision_list",
        operationKind: "artifact.conversation.revision.list",
        artifactId,
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
