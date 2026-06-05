import {
  capabilityForInvocationKind,
  modelMountInvocationAdmissionRequestForReceipt,
  modelMountInvocationAgentgresTransitionForReceipt,
  modelMountInvocationReceiptBindingRequestForReceipt,
  withModelMountInvocationAdmission,
  withModelMountInvocationReceiptBinding,
} from "./model-invocation-operations.mjs";

export function nextResponseId(state, requested, deps = {}) {
  const {
    optionalString,
    randomUUID,
    runtimeError,
  } = deps;
  const responseId = optionalString(requested) ?? `resp_${randomUUID()}`;
  if (state.conversations.has(responseId)) {
    throw runtimeError({
      status: 409,
      code: "continuation",
      message: "response_id already exists.",
      details: { response_id: responseId },
    });
  }
  return responseId;
}

export function conversationState(state, responseId, deps = {}) {
  const { runtimeError } = deps;
  const record = state.conversations.get(responseId);
  if (!record) {
    throw runtimeError({
      status: 404,
      code: "continuation",
      message: "previous_response_id was not found.",
      details: { previous_response_id: responseId },
    });
  }
  return record;
}

export function recordConversationState(state, {
  responseId,
  previousState,
  kind,
  input,
  outputText,
  selection,
  instance,
  receipt,
  routeReceipt,
  tokenCount,
  streamReceiptId = null,
  status = "completed",
  continuationSafety = null,
}, deps = {}) {
  const { stableHash } = deps;
  const now = state.nowIso();
  const record = {
    id: responseId,
    object: "ioi.model_response_state",
    status,
    redaction: "redacted",
    createdAt: now,
    previous_response_id: previousState?.id ?? null,
    root_response_id: previousState?.root_response_id ?? previousState?.id ?? responseId,
    kind,
    routeId: selection.route.id,
    endpointId: selection.endpoint.id,
    selectedModel: selection.endpoint.modelId,
    providerId: selection.endpoint.providerId,
    backendId: instance?.backendId ?? selection.endpoint.backendId ?? null,
    instanceId: instance?.id ?? null,
    receiptId: receipt.id,
    routeReceiptId: routeReceipt?.id ?? null,
    streamReceiptId,
    inputHash: stableHash(input),
    outputHash: stableHash(outputText),
    tokenCount,
    messageCount: Number(previousState?.messageCount ?? 0) + 2,
    continuation: continuationSafety,
    replay: {
      source: "redacted_conversation_state",
      plaintextPersisted: false,
      previous_response_id: previousState?.id ?? null,
    },
  };
  state.conversations.set(record.id, record);
  state.writeMap("model-conversations", state.conversations);
  return record;
}

export function recordModelStreamCompleted(state, {
  invocation,
  streamKind,
  outputText = "",
  providerUsage = null,
  chunksForwarded = 0,
  finishReason = null,
  providerResult = {},
  providerStreamShapeSummary = null,
}, deps = {}) {
  const {
    estimateTokens,
    normalizeUsage,
    stableHash,
  } = deps;
  const tokenCount = normalizeUsage(providerUsage, estimateTokens(invocation.input ?? "", outputText));
  const receiptKind = "model_invocation_stream_completed";
  const receiptId = nextStreamCompletionReceiptId(state, receiptKind);
  const receiptDetails = {
    streamKind,
    streamSource: "provider_native",
    invocationReceiptId: invocation.receipt.id,
    routeId: invocation.route.id,
    selectedModel: invocation.model,
    endpointId: invocation.endpoint.id,
    providerId: invocation.endpoint.providerId,
    instanceId: invocation.instance.id,
    backendId: invocation.instance.backendId ?? invocation.receipt.details?.backendId ?? null,
    selectedBackend: invocation.receipt.details?.selectedBackend ?? null,
    providerResponseKind: providerResult.providerResponseKind ?? invocation.providerResponseKind ?? null,
    providerAuthEvidenceRefs: providerResult.providerAuthEvidenceRefs ?? invocation.receipt.details?.providerAuthEvidenceRefs ?? [],
    backendEvidenceRefs: providerResult.backendEvidenceRefs ?? [],
    toolReceiptIds: invocation.toolReceiptIds ?? [],
    tokenCount,
    policyHash: invocation.receipt.details?.policyHash ?? stableHash({}),
    inputHash: invocation.receipt.details?.inputHash ?? stableHash(invocation.input ?? ""),
    outputHash: stableHash(outputText),
    chunksForwarded,
    finishReason,
    providerStreamShapeSummary,
    responseId: invocation.responseId ?? null,
    previous_response_id: invocation.previousResponseId ?? null,
  };
  const admissionRequest = modelMountInvocationAdmissionRequestForReceipt({
    body: {},
    capability: capabilityForInvocationKind(invocation.kind),
    kind: invocation.kind,
    receiptDetails,
    receiptId,
    receiptKind,
    routeReceipt: invocation.routeReceipt,
    selection: {
      route: invocation.route,
      endpoint: invocation.endpoint,
      provider: null,
    },
    streamStatus: "completed",
  });
  const admission = admitModelMountInvocation(state, admissionRequest);
  const agentgresTransition = modelMountInvocationAgentgresTransitionForReceipt(state, {
    admission,
    admissionRequest,
    receiptDetails,
    receiptId,
    receiptKind,
  });
  const binding = bindModelMountInvocationReceipt(
    state,
    modelMountInvocationReceiptBindingRequestForReceipt({
      admission,
      admissionRequest,
      agentgresTransition,
      receiptDetails,
      receiptId,
    }),
  );
  const receipt = state.receipt("model_invocation_stream_completed", {
    id: receiptId,
    summary: `${streamKind} stream completed for ${invocation.model}.`,
    redaction: "redacted",
    evidenceRefs: [
      "model_stream",
      streamKind,
      invocation.receipt.id,
      invocation.route.id,
      invocation.endpoint.id,
      "rust_model_mount_core",
      admission.invocation_admission_ref,
      ...(admission.evidence_refs ?? []),
      "rust_receipt_binder_core",
      binding.receipt_binding?.binding_hash,
      binding.accepted_receipt_append?.append_hash,
      binding.agentgres_admission?.admission_hash,
      ...(binding.evidence_refs ?? []),
    ],
    details: withModelMountInvocationReceiptBinding(
      withModelMountInvocationAdmission(receiptDetails, admission),
      binding,
    ),
  });
  if (invocation.responseId) {
    invocation.conversationState = state.recordConversationState({
      responseId: invocation.responseId,
      previousState: invocation.previousConversationState ?? null,
      kind: invocation.kind,
      input: invocation.input ?? "",
      outputText,
      selection: {
        route: invocation.route,
        endpoint: invocation.endpoint,
        provider: null,
      },
      instance: invocation.instance,
      receipt: invocation.receipt,
      routeReceipt: invocation.routeReceipt,
      tokenCount,
      streamReceiptId: receipt.id,
      status: "completed",
      continuationSafety: invocation.continuationSafety ?? null,
    });
  }
  return receipt;
}

function nextStreamCompletionReceiptId(state, kind) {
  if (typeof state.nextReceiptId !== "function") {
    const error = new Error("Model stream completion admission requires a precomputed receipt id before Rust admission.");
    error.status = 500;
    error.code = "model_mount_stream_completion_receipt_id_required";
    throw error;
  }
  return state.nextReceiptId(kind);
}

function admitModelMountInvocation(state, request) {
  if (typeof state.admitModelMountInvocation !== "function") {
    const error = new Error("Model stream completion requires Rust model_mount invocation admission.");
    error.status = 500;
    error.code = "model_mount_stream_completion_admission_required";
    throw error;
  }
  return state.admitModelMountInvocation(request);
}

function bindModelMountInvocationReceipt(state, request) {
  if (typeof state.bindModelMountInvocationReceipt !== "function") {
    const error = new Error("Model stream completion requires Rust receipt_binder binding.");
    error.status = 500;
    error.code = "model_mount_stream_completion_receipt_binding_required";
    throw error;
  }
  return state.bindModelMountInvocationReceipt(request);
}

export function listConversations(state) {
  return [...state.conversations.values()].sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? "")));
}
