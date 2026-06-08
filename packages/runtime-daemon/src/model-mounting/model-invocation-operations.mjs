import * as routeDecision from "./route-decision.mjs";
import {
  estimateTokens,
  inputText,
} from "./provider-protocol.mjs";
import {
  driverNameForProvider,
  modelInvocationCoalesceKey,
  supportsResponseState,
} from "./provider-driver-helpers.mjs";
import { optionalString } from "./provider-registry.mjs";
import { stableHash } from "./io.mjs";
import {
  createModelMountStepModuleProjection,
} from "../step-module-abi.mjs";
import { modelConversationRustCoreRequiredError } from "./conversation-operations.mjs";

const RETIRED_MODEL_INVOCATION_REQUEST_ALIASES = [
  "routeId",
  "modelPolicy",
  "responseId",
  "previousResponseId",
  "sendOptions",
  "authorityGrantRefs",
  "authorityReceiptRefs",
  "custodyRef",
  "privacyProfile",
  "nodePlaintextAllowed",
];

const MODEL_INVOCATION_RUST_CORE_REQUIRED_EVIDENCE_REFS = [
  "model_mount_invocation_js_facade_retired",
  "rust_daemon_core_model_invocation_required",
  "agentgres_model_invocation_truth_required",
];

export async function invokeModel(state, { authorization, requiredScope, kind, body = {} }, deps = {}) {
  const {
    estimateTokens: estimateTokenCounts = estimateTokens,
    inputText: textFromInput = inputText,
    modelInvocationCoalesceKey: coalesceKeyForInvocation = modelInvocationCoalesceKey,
    optionalString: optional = optionalString,
    providerRequestBodyForRoute = routeDecision.providerRequestBodyForRoute,
    stableHash: hash = stableHash,
    supportsResponseState: responseStateSupported = supportsResponseState,
  } = deps;
  assertCanonicalModelInvocationRequestBody(body);
  throwModelInvocationRustCoreRequired("model_mount.invocation.invoke", {
    kind,
    model_id: body.model ?? body.model_id ?? null,
    route_id: body.route_id ?? null,
    required_scope: requiredScope ?? null,
    stream: false,
  });
  const token = state.authorize(authorization, requiredScope);
  const started = state.now().getTime();
  const input = textFromInput(body);
  const statefulInvocation = responseStateSupported(kind);
  const previousResponseId = statefulInvocation ? optional(body.previous_response_id) : null;
  const previousState = previousResponseId ? state.conversationState(previousResponseId) : null;
  const responseId = statefulInvocation ? state.nextResponseId(body.response_id) : null;
  const capability = capabilityForInvocationKind(kind);
  const selection = state.selectRoute({
    modelId: body.model,
    routeId: body.route_id,
    capability,
    policy: body.model_policy ?? {},
  });
  const continuationSafety = state.validateContinuationSafety({ previousState, selection, body });
  const routeReceipt = state.routeSelectionReceipt(selection, { body, capability, responseId, previousResponseId });
  const providerBody = providerRequestBodyForRoute(body, selection.endpoint);
  const coalesceKey = coalesceKeyForInvocation({
    kind,
    body,
    providerBody,
    input,
    token,
    selection,
    previousResponseId,
  });
  let providerExecution = coalesceKey ? state.inflightModelInvocations.get(coalesceKey) : null;
  const coalesced = Boolean(providerExecution);
  if (!providerExecution) {
    providerExecution = (async () => {
      const instance = await state.ensureLoaded(selection.endpoint);
      const ephemeralMcp = state.compileEphemeralMcpIntegrations({ authorization, body, input });
      const modelMountProviderExecutionAdmission = admitModelMountProviderExecution(
        state,
        modelMountProviderExecutionRequestForInvocation({
          body,
          capability,
          ephemeralMcp,
          hash,
          input,
          instance,
          kind,
          previousResponseId,
          providerBody,
          responseId,
          routeReceipt,
          selection,
          streamStatus: null,
          token,
        }),
      );
      const providerResult = await executeModelProviderInvocation({
        input,
        instance,
        kind,
        modelMountProviderExecutionAdmission,
        providerBody,
        selection,
        state,
        token,
      });
      return { instance, ephemeralMcp, modelMountProviderExecutionAdmission, providerResult };
    })();
    if (coalesceKey) {
      state.inflightModelInvocations.set(coalesceKey, providerExecution);
    }
  }
  let execution;
  try {
    execution = await providerExecution;
  } finally {
    if (coalesceKey && !coalesced) {
      state.inflightModelInvocations.delete(coalesceKey);
    }
  }
  const { instance, ephemeralMcp, modelMountProviderExecutionAdmission, providerResult } = execution;
  const outputText = providerResult.outputText;
  const latencyMs = Math.max(1, state.now().getTime() - started);
  const tokenCount = providerResult.tokenCount ?? estimateTokenCounts(input, outputText);
  const receiptKind = coalesced ? "model_invocation_coalesced" : "model_invocation";
  const receiptId = nextInvocationReceiptId(state, receiptKind);
  const receiptDetails = withModelMountProviderExecutionAdmission(
    invocationReceiptDetails({
      body,
      coalesced,
      coalesceKey,
      continuationSafety,
      hash,
      input,
      instance,
      latencyMs,
      outputText,
      previousResponseId,
      providerResult,
      responseId,
      routeReceipt,
      selection,
      token,
      tokenCount,
      ephemeralMcp,
      includeInvocationFields: true,
    }),
    modelMountProviderExecutionAdmission,
  );
  const modelMountInvocationAdmissionRequest = modelMountInvocationAdmissionRequestForReceipt({
    body,
    capability,
    kind,
    receiptDetails,
    receiptId,
    receiptKind,
    routeReceipt,
    selection,
  });
  const modelMountInvocationAdmission = state.admitModelMountInvocation(modelMountInvocationAdmissionRequest);
  const agentgresTransition = modelMountInvocationAgentgresTransitionForReceipt(state, {
    admission: modelMountInvocationAdmission,
    admissionRequest: modelMountInvocationAdmissionRequest,
    receiptDetails,
    receiptId,
    receiptKind,
  });
  const modelMountInvocationReceiptBinding = bindModelMountInvocationReceipt(
    state,
    modelMountInvocationReceiptBindingRequestForReceipt({
      admission: modelMountInvocationAdmission,
      admissionRequest: modelMountInvocationAdmissionRequest,
      agentgresTransition,
      receiptDetails,
      receiptId,
    }),
  );
  const receipt = state.receipt(receiptKind, {
    id: receiptId,
    summary: coalesced
      ? `${kind} invocation reused an identical in-flight request for ${selection.endpoint.modelId}.`
      : `${kind} invocation routed through ${selection.route.id} to ${selection.endpoint.modelId}.`,
    redaction: "redacted",
    evidenceRefs: uniqueRefs([
      "model_router",
      ...(coalesced ? ["model_invocation_inflight_coalesced"] : []),
      routeReceipt.id,
      selection.route.id,
      selection.endpoint.id,
      instance.id,
      token.grantId,
      ...ephemeralMcp.evidenceRefs,
      ...(providerResult.providerAuthEvidenceRefs ?? []),
      providerResult.model_mount_provider_result_admission_ref,
      ...(providerResult.model_mount_provider_result_admission_evidence_refs ?? []),
      "rust_model_mount_core",
      modelMountProviderExecutionAdmission.provider_execution_ref,
      ...(modelMountProviderExecutionAdmission.evidence_refs ?? []),
      modelMountInvocationAdmission.invocation_admission_ref,
      ...(modelMountInvocationAdmission.evidence_refs ?? []),
      "rust_receipt_binder_core",
      modelMountInvocationReceiptBinding.receipt_binding?.binding_hash,
      modelMountInvocationReceiptBinding.accepted_receipt_append?.append_hash,
      ...(modelMountInvocationReceiptBinding.evidence_refs ?? []),
    ]),
    details: withModelMountInvocationReceiptBinding(
      withModelMountInvocationAdmission(receiptDetails, modelMountInvocationAdmission),
      modelMountInvocationReceiptBinding,
    ),
  });
  const conversationState = statefulInvocation
    ? skippedModelConversationProjection({
        responseId,
        previousState,
        kind,
        receipt,
        routeReceipt,
      })
    : null;
  const route = persistRouteSelection(state, selection.route, selection.endpoint.modelId, receipt.id);
  return {
    kind,
    outputText,
    model: selection.endpoint.modelId,
    route,
    endpoint: selection.endpoint,
    instance,
    receipt,
    routeReceipt,
    tokenCount,
    providerResponse: providerResult.providerResponse ?? null,
    providerResponseKind: providerResult.providerResponseKind ?? null,
    toolReceiptIds: ephemeralMcp.toolReceiptIds,
    responseId,
    previousResponseId,
    conversationState,
  };
}

function skippedModelConversationProjection({ responseId, previousState, kind, receipt, routeReceipt }) {
  if (previousState) {
    throw modelConversationRustCoreRequiredError({
      operation: "model_conversation_continuation",
      response_id: responseId ?? null,
      previous_response_id: previousState.id ?? null,
      receipt_id: receipt?.id ?? null,
      route_receipt_id: routeReceipt?.id ?? null,
      kind,
    });
  }
  return null;
}

export async function startModelStream(state, { authorization, requiredScope, kind, body = {} }, deps = {}) {
  const {
    estimateTokens: estimateTokenCounts = estimateTokens,
    inputText: textFromInput = inputText,
    optionalString: optional = optionalString,
    providerRequestBodyForRoute = routeDecision.providerRequestBodyForRoute,
    stableHash: hash = stableHash,
    supportsResponseState: responseStateSupported = supportsResponseState,
  } = deps;
  assertCanonicalModelInvocationRequestBody(body);
  throwModelInvocationRustCoreRequired("model_mount.invocation.stream_start", {
    kind,
    model_id: body.model ?? body.model_id ?? null,
    route_id: body.route_id ?? null,
    required_scope: requiredScope ?? null,
    stream: true,
  });
  const token = state.authorize(authorization, requiredScope);
  const started = state.now().getTime();
  const input = textFromInput(body);
  const statefulInvocation = responseStateSupported(kind);
  const previousResponseId = statefulInvocation ? optional(body.previous_response_id) : null;
  const previousState = previousResponseId ? state.conversationState(previousResponseId) : null;
  const responseId = statefulInvocation ? state.nextResponseId(body.response_id) : null;
  const capability = capabilityForInvocationKind(kind);
  const selection = state.selectRoute({
    modelId: body.model,
    routeId: body.route_id,
    capability,
    policy: body.model_policy ?? {},
  });
  const continuationSafety = state.validateContinuationSafety({ previousState, selection, body });
  const rustProviderStream = modelMountProviderStreamInvocationRequiresRust(selection);
  if (!rustProviderStream && modelMountProviderInvocationRequiresRust(selection, { stream: true })) {
    const error = new Error("Native model stream requires a Rust model_mount stream backend for the selected provider.");
    error.status = 501;
    error.code = "model_mount_native_stream_backend_required";
    throw error;
  }
  if (!rustProviderStream) {
    rejectUnmigratedProviderInvocationExecution(selection, { stream: true });
  }
  const routeReceipt = state.routeSelectionReceipt(selection, { body, capability, responseId, previousResponseId });
  const instance = await state.ensureLoaded(selection.endpoint);
  const ephemeralMcp = state.compileEphemeralMcpIntegrations({ authorization, body, input });
  const providerBody = providerRequestBodyForRoute(body, selection.endpoint);
  const modelMountProviderExecutionAdmission = admitModelMountProviderExecution(
    state,
    modelMountProviderExecutionRequestForInvocation({
      body,
      capability,
      ephemeralMcp,
      hash,
      input,
      instance,
      kind,
      previousResponseId,
      providerBody,
      responseId,
      routeReceipt,
      selection,
      streamStatus: "started",
      token,
    }),
  );
  requireModelMountProviderResultAdmission(state);
  let providerResult = rustProviderStream
    ? executeModelMountProviderStreamInvocation(
        state,
        modelMountProviderStreamInvocationRequestForExecution({
          input,
          instance,
          kind,
          modelMountProviderExecutionAdmission,
          selection,
        }),
      )
    : null;
  if (rustProviderStream) {
    providerResult = withTextChunksReadableStream(providerResult);
  }
  rejectProviderCompatTranslation(providerResult);
  if (!providerResult?.stream) {
    const error = new Error("Native provider stream invocation did not return a stream after Rust stream-start admission.");
    error.status = 502;
    error.code = "model_mount_native_stream_result_required";
    throw error;
  }
  const modelMountProviderResultAdmission = admitModelMountProviderResult(
    state,
    modelMountProviderResultAdmissionRequestForExecution({
      input,
      instance,
      kind,
      modelMountProviderExecutionAdmission,
      providerResult,
      selection,
    }),
  );
  providerResult = withModelMountProviderResultAdmission(providerResult, modelMountProviderResultAdmission);
  const outputText = "";
  const latencyMs = Math.max(1, state.now().getTime() - started);
  const tokenCount = providerResult.tokenCount ?? estimateTokenCounts(input, outputText);
  const receiptId = nextInvocationReceiptId(state, "model_invocation");
  const receiptDetails = withModelMountProviderExecutionAdmission({
    ...invocationReceiptDetails({
      body,
      coalesced: false,
      coalesceKey: null,
      continuationSafety,
      hash,
      input,
      instance,
      latencyMs,
      outputText,
      previousResponseId,
      providerResult,
      responseId,
      routeReceipt,
      selection,
      token,
      tokenCount,
      ephemeralMcp,
      includeInvocationFields: false,
    }),
    stream_status: "started",
    stream_source: "provider_native",
  }, modelMountProviderExecutionAdmission);
  const modelMountInvocationAdmissionRequest = modelMountInvocationAdmissionRequestForReceipt({
    body,
    capability,
    kind,
    receiptDetails,
    receiptId,
    receiptKind: "model_invocation",
    routeReceipt,
    selection,
    streamStatus: "started",
  });
  const modelMountInvocationAdmission = state.admitModelMountInvocation(modelMountInvocationAdmissionRequest);
  const agentgresTransition = modelMountInvocationAgentgresTransitionForReceipt(state, {
    admission: modelMountInvocationAdmission,
    admissionRequest: modelMountInvocationAdmissionRequest,
    receiptDetails,
    receiptId,
    receiptKind: "model_invocation",
  });
  const modelMountInvocationReceiptBinding = bindModelMountInvocationReceipt(
    state,
    modelMountInvocationReceiptBindingRequestForReceipt({
      admission: modelMountInvocationAdmission,
      admissionRequest: modelMountInvocationAdmissionRequest,
      agentgresTransition,
      receiptDetails,
      receiptId,
    }),
  );
  const receipt = state.receipt("model_invocation", {
    id: receiptId,
    summary: `${kind} invocation stream started through ${selection.route.id} to ${selection.endpoint.modelId}.`,
    redaction: "redacted",
    evidenceRefs: uniqueRefs([
      "model_router",
      "provider_native_stream",
      routeReceipt.id,
      selection.route.id,
      selection.endpoint.id,
      instance.id,
      token.grantId,
      ...ephemeralMcp.evidenceRefs,
      ...(providerResult.providerAuthEvidenceRefs ?? []),
      providerResult.model_mount_provider_result_admission_ref,
      ...(providerResult.model_mount_provider_result_admission_evidence_refs ?? []),
      "rust_model_mount_core",
      modelMountProviderExecutionAdmission.provider_execution_ref,
      ...(modelMountProviderExecutionAdmission.evidence_refs ?? []),
      modelMountInvocationAdmission.invocation_admission_ref,
      ...(modelMountInvocationAdmission.evidence_refs ?? []),
      "rust_receipt_binder_core",
      modelMountInvocationReceiptBinding.receipt_binding?.binding_hash,
      modelMountInvocationReceiptBinding.accepted_receipt_append?.append_hash,
      ...(modelMountInvocationReceiptBinding.evidence_refs ?? []),
    ]),
    details: withModelMountInvocationReceiptBinding(
      withModelMountInvocationAdmission(receiptDetails, modelMountInvocationAdmission),
      modelMountInvocationReceiptBinding,
    ),
  });
  const route = persistRouteSelection(state, selection.route, selection.endpoint.modelId, receipt.id);
  const invocation = {
    kind,
    input,
    outputText,
    model: selection.endpoint.modelId,
    route,
    endpoint: selection.endpoint,
    instance,
    receipt,
    routeReceipt,
    tokenCount,
    providerResponse: null,
    providerResponseKind: providerResult.providerResponseKind ?? null,
    toolReceiptIds: ephemeralMcp.toolReceiptIds,
    responseId,
    previousResponseId,
    previousConversationState: previousState,
    continuationSafety,
  };
  return {
    native: true,
    invocation,
    providerStream: providerResult.stream,
    abort: providerResult.abort,
    providerResult,
  };
}

export function modelMountInvocationAdmissionRequestForReceipt({
  body = {},
  capability = "chat",
  kind,
  receiptDetails = {},
  receiptId,
  receiptKind,
  routeReceipt,
  selection,
  streamStatus = null,
} = {}) {
  assertCanonicalModelInvocationRequestBody(body);
  const routeReceiptRef = receiptRef(requiredStringRef("routeReceipt.id", routeReceipt?.id));
  const invocationReceiptRef = receiptRef(requiredStringRef("receiptId", receiptId));
  const routeDecisionRef = requiredStringRef(
    "routeReceipt.details.model_mount_route_decision_ref",
    routeReceipt?.details?.model_mount_route_decision_ref,
  );
  const policy = body.model_policy ?? {};
  return {
    schema_version: "ioi.model_mount.invocation_admission.v1",
    invocation_ref: `model-invocation://${requiredStringRef("receiptId", receiptId)}`,
    route_decision_ref: routeDecisionRef,
    route_receipt_ref: routeReceiptRef,
    invocation_receipt_ref: invocationReceiptRef,
    route_ref: requiredStringRef("route.id", selection?.route?.id ?? receiptDetails.route_id),
    provider_ref: requiredStringRef("provider.id", selection?.provider?.id ?? receiptDetails.provider_id),
    endpoint_ref: requiredStringRef("endpoint.id", selection?.endpoint?.id ?? receiptDetails.endpoint_id),
    model_ref: requiredStringRef("endpoint.modelId", selection?.endpoint?.modelId ?? receiptDetails.selected_model),
    capability: requiredStringRef("capability", capability),
    invocation_kind: requiredStringRef("kind", kind),
    policy_hash: policyHashRef(receiptDetails.policy_hash),
    input_hash: hashRef(receiptDetails.input_hash, "input_hash"),
    output_hash: hashRef(receiptDetails.output_hash, "output_hash"),
    idempotency_key: `${receiptKind}:${receiptId}`,
    receipt_refs: uniqueRefs([
      routeReceiptRef,
      invocationReceiptRef,
      ...(Array.isArray(receiptDetails.tool_receipt_ids) ? receiptDetails.tool_receipt_ids.map(receiptRef) : []),
    ]),
    authority_grant_refs: uniqueRefs([
      optionalRef(receiptDetails.grant_id),
      ...(Array.isArray(body.authority_grant_refs) ? body.authority_grant_refs : []),
    ]),
    authority_receipt_refs: uniqueRefs([
      ...(Array.isArray(body.authority_receipt_refs) ? body.authority_receipt_refs : []),
    ]),
    provider_auth_evidence_refs: uniqueRefs(receiptDetails.provider_auth_evidence_refs ?? []),
    backend_evidence_refs: uniqueRefs(receiptDetails.backend_evidence_refs ?? []),
    tool_receipt_refs: uniqueRefs(receiptDetails.tool_receipt_ids ?? []),
    custody_ref: optionalRef(
      body.custody_ref ??
        selection?.endpoint?.custodyRef ??
        selection?.endpoint?.custody_ref ??
        selection?.provider?.custodyRef ??
        selection?.provider?.custody_ref,
    ),
    privacy_profile: optionalRef(
      body.privacy_profile ??
        policy.privacy_profile ??
        policy.privacy ??
        selection?.route?.privacy ??
        selection?.provider?.privacyClass,
    ),
    node_plaintext_allowed: Boolean(
      body.node_plaintext_allowed ??
        selection?.endpoint?.nodePlaintextAllowed ??
        selection?.provider?.nodePlaintextAllowed ??
        false,
    ),
    workflow_graph_ref: optionalRef(routeReceipt?.details?.workflow_graph_id),
    workflow_node_ref: optionalRef(routeReceipt?.details?.workflow_node_id),
    response_ref: optionalRef(receiptDetails.response_id),
    previous_response_ref: optionalRef(receiptDetails.previous_response_id),
    stream_status: optionalRef(streamStatus ?? receiptDetails.stream_status),
  };
}

export function modelMountProviderExecutionRequestForInvocation({
  body = {},
  capability = "chat",
  ephemeralMcp = {},
  hash = stableHash,
  input,
  instance = {},
  kind,
  previousResponseId = null,
  providerBody = {},
  responseId = null,
  routeReceipt,
  selection,
  streamStatus = null,
  token = {},
} = {}) {
  assertCanonicalModelInvocationRequestBody(body);
  const routeReceiptRef = receiptRef(requiredStringRef("routeReceipt.id", routeReceipt?.id));
  const routeDecisionRef = requiredStringRef(
    "routeReceipt.details.model_mount_route_decision_ref",
    routeReceipt?.details?.model_mount_route_decision_ref,
  );
  const requestHash = hashRef(
    hash({
      endpointId: selection?.endpoint?.id ?? null,
      invocationKind: kind,
      providerBody,
      streamStatus,
    }),
    "request_hash",
  );
  const policy = body.model_policy ?? {};
  return {
    schema_version: "ioi.model_mount.provider_execution.v1",
    invocation_ref: `model-provider-execution://${requestHash.replace(/^sha256:/, "sha256/")}`,
    route_decision_ref: routeDecisionRef,
    route_receipt_ref: routeReceiptRef,
    route_ref: requiredStringRef("route.id", selection?.route?.id),
    provider_ref: requiredStringRef("provider.id", selection?.provider?.id),
    endpoint_ref: requiredStringRef("endpoint.id", selection?.endpoint?.id),
    model_ref: requiredStringRef("endpoint.modelId", selection?.endpoint?.modelId),
    capability: requiredStringRef("capability", capability),
    invocation_kind: requiredStringRef("kind", kind),
    policy_hash: policyHashRef(hash(policy)),
    input_hash: hashRef(hash(input ?? ""), "input_hash"),
    request_hash: requestHash,
    idempotency_key: `model_provider_execution:${routeReceiptRef}:${requestHash}`,
    receipt_refs: uniqueRefs([
      routeReceiptRef,
      ...(Array.isArray(ephemeralMcp.toolReceiptIds) ? ephemeralMcp.toolReceiptIds.map(receiptRef) : []),
    ]),
    authority_grant_refs: uniqueRefs([
      optionalRef(token.grantId),
      ...(Array.isArray(body.authority_grant_refs) ? body.authority_grant_refs : []),
    ]),
    authority_receipt_refs: uniqueRefs([
      ...(Array.isArray(body.authority_receipt_refs) ? body.authority_receipt_refs : []),
    ]),
    provider_auth_evidence_refs: [],
    backend_evidence_refs: uniqueRefs([
      instance.backendId,
      selection?.endpoint?.backendId,
    ]),
    tool_receipt_refs: uniqueRefs(ephemeralMcp.toolReceiptIds ?? []),
    custody_ref: optionalRef(
      body.custody_ref ??
        selection?.endpoint?.custodyRef ??
        selection?.endpoint?.custody_ref ??
        selection?.provider?.custodyRef ??
        selection?.provider?.custody_ref,
    ),
    privacy_profile: optionalRef(
      body.privacy_profile ??
        policy.privacy_profile ??
        policy.privacy ??
        selection?.route?.privacy ??
        selection?.provider?.privacyClass,
    ),
    node_plaintext_allowed: Boolean(
      body.node_plaintext_allowed ??
        selection?.endpoint?.nodePlaintextAllowed ??
        selection?.provider?.nodePlaintextAllowed ??
        false,
    ),
    workflow_graph_ref: optionalRef(routeReceipt?.details?.workflow_graph_id),
    workflow_node_ref: optionalRef(routeReceipt?.details?.workflow_node_id),
    response_ref: optionalRef(responseId),
    previous_response_ref: optionalRef(previousResponseId),
    stream_status: optionalRef(streamStatus),
  };
}

export function modelMountProviderInvocationRequestForExecution({
  input,
  instance = {},
  kind,
  modelMountProviderExecutionAdmission = {},
  selection,
} = {}) {
  const record = modelMountProviderExecutionAdmission.record ?? {};
  const provider = selection?.provider ?? {};
  const endpoint = selection?.endpoint ?? {};
  return {
    schema_version: "ioi.model_mount.provider_invocation.v1",
    provider_execution_ref: requiredStringRef(
      "modelMountProviderExecutionAdmission.provider_execution_ref",
      modelMountProviderExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
    ),
    provider_execution_hash: requiredStringRef(
      "modelMountProviderExecutionAdmission.provider_execution_hash",
      modelMountProviderExecutionAdmission.provider_execution_hash ?? record.provider_execution_hash,
    ),
    route_decision_ref: requiredStringRef("providerExecution.route_decision_ref", record.route_decision_ref),
    route_receipt_ref: requiredStringRef("providerExecution.route_receipt_ref", record.route_receipt_ref),
    route_ref: requiredStringRef("providerExecution.route_ref", record.route_ref),
    provider_ref: requiredStringRef("providerExecution.provider_ref", record.provider_ref),
    provider_kind: requiredStringRef("provider.kind", provider.kind),
    endpoint_ref: requiredStringRef("providerExecution.endpoint_ref", record.endpoint_ref),
    model_ref: requiredStringRef("providerExecution.model_ref", record.model_ref),
    capability: requiredStringRef("providerExecution.capability", record.capability),
    invocation_kind: requiredStringRef("providerExecution.invocation_kind", record.invocation_kind ?? kind),
    input: String(input ?? ""),
    request_hash: requiredStringRef("providerExecution.request_hash", record.request_hash),
    execution_backend: modelMountProviderInvocationExecutionBackend(selection),
    api_format: optionalRef(endpoint.apiFormat ?? provider.apiFormat),
    driver: optionalRef(endpoint.driver ?? provider.driver ?? driverNameForProvider(provider)),
    backend_ref: optionalRef(instance.backendId ?? endpoint.backendId),
    stream_status: optionalRef(record.stream_status),
    receipt_refs: modelMountProviderExecutionAdmission.receipt_refs ?? record.receipt_refs ?? [],
    evidence_refs: uniqueRefs([
      modelMountProviderExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
      ...(modelMountProviderExecutionAdmission.evidence_refs ?? []),
    ]),
    admitted_provider_execution: record,
  };
}

export function modelMountProviderStreamInvocationRequestForExecution({
  input,
  instance = {},
  kind,
  modelMountProviderExecutionAdmission = {},
  selection,
} = {}) {
  const record = modelMountProviderExecutionAdmission.record ?? {};
  const provider = selection?.provider ?? {};
  const endpoint = selection?.endpoint ?? {};
  return {
    schema_version: "ioi.model_mount.provider_invocation.v1",
    provider_execution_ref: requiredStringRef(
      "modelMountProviderExecutionAdmission.provider_execution_ref",
      modelMountProviderExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
    ),
    provider_execution_hash: requiredStringRef(
      "modelMountProviderExecutionAdmission.provider_execution_hash",
      modelMountProviderExecutionAdmission.provider_execution_hash ?? record.provider_execution_hash,
    ),
    route_decision_ref: requiredStringRef("providerExecution.route_decision_ref", record.route_decision_ref),
    route_receipt_ref: requiredStringRef("providerExecution.route_receipt_ref", record.route_receipt_ref),
    route_ref: requiredStringRef("providerExecution.route_ref", record.route_ref),
    provider_ref: requiredStringRef("providerExecution.provider_ref", record.provider_ref),
    provider_kind: requiredStringRef("provider.kind", provider.kind),
    endpoint_ref: requiredStringRef("providerExecution.endpoint_ref", record.endpoint_ref),
    model_ref: requiredStringRef("providerExecution.model_ref", record.model_ref),
    capability: requiredStringRef("providerExecution.capability", record.capability),
    invocation_kind: requiredStringRef("providerExecution.invocation_kind", record.invocation_kind ?? kind),
    input: String(input ?? ""),
    request_hash: requiredStringRef("providerExecution.request_hash", record.request_hash),
    execution_backend: "rust_model_mount_native_local_stream",
    api_format: optionalRef(endpoint.apiFormat ?? provider.apiFormat),
    driver: optionalRef(endpoint.driver ?? provider.driver ?? driverNameForProvider(provider)),
    backend_ref: optionalRef(instance.backendId ?? endpoint.backendId),
    stream_status: optionalRef(record.stream_status) ?? "started",
    receipt_refs: modelMountProviderExecutionAdmission.receipt_refs ?? record.receipt_refs ?? [],
    evidence_refs: uniqueRefs([
      modelMountProviderExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
      ...(modelMountProviderExecutionAdmission.evidence_refs ?? []),
    ]),
    admitted_provider_execution: record,
  };
}

export function modelMountProviderResultAdmissionRequestForExecution({
  input,
  instance = {},
  kind,
  modelMountProviderExecutionAdmission = {},
  providerResult = {},
  selection,
} = {}) {
  const record = modelMountProviderExecutionAdmission.record ?? {};
  const provider = selection?.provider ?? {};
  const endpoint = selection?.endpoint ?? {};
  const outputText = String(providerResult.outputText ?? "");
  const tokenCount = providerResult.tokenCount ?? estimateTokens(input, outputText);
  return {
    schema_version: "ioi.model_mount.provider_result.v1",
    provider_execution_ref: requiredStringRef(
      "modelMountProviderExecutionAdmission.provider_execution_ref",
      modelMountProviderExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
    ),
    provider_execution_hash: requiredStringRef(
      "modelMountProviderExecutionAdmission.provider_execution_hash",
      modelMountProviderExecutionAdmission.provider_execution_hash ?? record.provider_execution_hash,
    ),
    route_decision_ref: requiredStringRef("providerExecution.route_decision_ref", record.route_decision_ref),
    route_receipt_ref: requiredStringRef("providerExecution.route_receipt_ref", record.route_receipt_ref),
    route_ref: requiredStringRef("providerExecution.route_ref", record.route_ref),
    provider_ref: requiredStringRef("providerExecution.provider_ref", record.provider_ref),
    provider_kind: requiredStringRef("provider.kind", provider.kind),
    endpoint_ref: requiredStringRef("providerExecution.endpoint_ref", record.endpoint_ref),
    model_ref: requiredStringRef("providerExecution.model_ref", record.model_ref),
    capability: requiredStringRef("providerExecution.capability", record.capability),
    invocation_kind: requiredStringRef("providerExecution.invocation_kind", record.invocation_kind ?? kind),
    request_hash: requiredStringRef("providerExecution.request_hash", record.request_hash),
    output_text: outputText,
    output_hash: hashRef(stableHash(outputText), "output_hash"),
    token_count: tokenCount,
    provider_response_kind: optionalRef(providerResult.providerResponseKind),
    execution_backend: requiredStringRef(
      "providerResult.execution_backend",
      providerResult.execution_backend ?? providerResult.executionBackend,
    ),
    backend_ref: optionalRef(providerResult.backendId ?? instance.backendId ?? endpoint.backendId),
    stream_status: optionalRef(record.stream_status),
    receipt_refs: modelMountProviderExecutionAdmission.receipt_refs ?? record.receipt_refs ?? [],
    provider_auth_evidence_refs: uniqueRefs(providerResult.providerAuthEvidenceRefs ?? []),
    backend_evidence_refs: uniqueRefs(providerResult.backendEvidenceRefs ?? []),
    evidence_refs: uniqueRefs([
      modelMountProviderExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
      ...(modelMountProviderExecutionAdmission.evidence_refs ?? []),
    ]),
    admitted_provider_execution: record,
  };
}

export function modelMountInvocationReceiptBindingRequestForReceipt({
  admission,
  admissionRequest,
  agentgresTransition = null,
  receiptDetails = {},
  receiptId,
} = {}) {
  const receiptRefValue = receiptRef(requiredStringRef("receiptId", receiptId));
  const { invocation, result } = createModelMountStepModuleProjection({
    invocation_ref: requiredStringRef("admissionRequest.invocation_ref", admissionRequest?.invocation_ref),
    route_ref: requiredStringRef("admissionRequest.route_ref", admissionRequest?.route_ref),
    provider_ref: requiredStringRef("admissionRequest.provider_ref", admissionRequest?.provider_ref),
    endpoint_ref: requiredStringRef("admissionRequest.endpoint_ref", admissionRequest?.endpoint_ref),
    model_ref: requiredStringRef("admissionRequest.model_ref", admissionRequest?.model_ref),
    capability: requiredStringRef("admissionRequest.capability", admissionRequest?.capability),
    invocation_kind: requiredStringRef("admissionRequest.invocation_kind", admissionRequest?.invocation_kind),
    input_hash: hashRef(admissionRequest?.input_hash, "admissionRequest.input_hash"),
    output_hash: hashRef(admissionRequest?.output_hash, "admissionRequest.output_hash"),
    policy_hash: policyHashRef(admissionRequest?.policy_hash),
    route_decision_ref: requiredStringRef("admissionRequest.route_decision_ref", admissionRequest?.route_decision_ref),
    route_receipt_ref: requiredStringRef("admissionRequest.route_receipt_ref", admissionRequest?.route_receipt_ref),
    receipt_ref: receiptRefValue,
    authority_grant_refs: admissionRequest?.authority_grant_refs ?? [],
    workflow_graph_id: optionalRef(admissionRequest?.workflow_graph_ref) ?? "workflow:model-mount",
    workflow_node_id:
      optionalRef(admissionRequest?.workflow_node_ref) ?? `node:model-mount:${requiredStringRef("receiptId", receiptId)}`,
    privacy_profile: admissionRequest?.privacy_profile ?? "internal",
    node_plaintext_allowed: Boolean(admissionRequest?.node_plaintext_allowed),
    custody_proof_ref: admissionRequest?.custody_ref ?? null,
    idempotency_key: admissionRequest?.idempotency_key ?? `model_invocation:${receiptId}`,
    state_root_before: requiredStringRef("agentgresTransition.state_root_before", agentgresTransition?.state_root_before),
    projection_watermark: requiredStringRef("agentgresTransition.projection_watermark", agentgresTransition?.projection_watermark),
    agentgres_operation_refs: [
      requiredStringRef("agentgresTransition.operation_ref", agentgresTransition?.operation_ref),
    ],
    state_root_after: requiredStringRef("agentgresTransition.state_root_after", agentgresTransition?.state_root_after),
    resulting_head: requiredStringRef("agentgresTransition.resulting_head", agentgresTransition?.resulting_head),
    evidence_refs: uniqueRefs([
      "rust_model_mount_core",
      admission?.invocation_admission_ref,
      ...(admission?.evidence_refs ?? []),
      ...(receiptDetails.provider_auth_evidence_refs ?? []),
      ...(receiptDetails.backend_evidence_refs ?? []),
    ]),
  });
  return {
    invocation,
    result,
    acceptedReceiptTransition: objectRecord(agentgresTransition?.acceptedReceiptTransition),
    receiptRef: receiptRefValue,
  };
}

export function modelMountInvocationAgentgresTransitionForReceipt(
  state,
  {
    admission,
    admissionRequest,
    receiptDetails = {},
    receiptId,
    receiptKind,
  } = {},
) {
  if (typeof state.planModelMountAcceptedReceiptTransition !== "function") {
    const error = new Error("Model invocation Agentgres admission requires Rust model-mount accepted receipt transition planning.");
    error.status = 500;
    error.code = "model_mount_accepted_receipt_transition_planner_required";
    throw error;
  }
  if (typeof state.agentgresModelMountingHead !== "function") {
    const error = new Error("Model invocation Agentgres admission requires a current model-mounting operation head.");
    error.status = 500;
    error.code = "model_mount_agentgres_head_required";
    throw error;
  }
  const currentHead = normalizeAgentgresHead(state.agentgresModelMountingHead());
  const transition = state.planModelMountAcceptedReceiptTransition({
    schema_version: "ioi.model_mount.accepted_receipt_transition.v1",
    current_sequence: currentHead.sequence,
    current_head_ref: currentHead.head_ref,
    current_state_root: currentHead.state_root,
    receipt_id: requiredStringRef("receiptId", receiptId),
    receipt_kind: requiredStringRef("receiptKind", receiptKind),
    route_decision_ref: admissionRequest?.route_decision_ref ?? null,
    invocation_admission_ref: admission?.invocation_admission_ref ?? null,
    invocation_admission_hash: admission?.invocation_admission_hash ?? null,
    input_hash: admissionRequest?.input_hash ?? receiptDetails.input_hash ?? null,
    output_hash: admissionRequest?.output_hash ?? receiptDetails.output_hash ?? null,
  });
  return {
    operation_id: requiredStringRef("transition.operation_id", transition?.operation_id),
    operation_ref: requiredStringRef("transition.operation_ref", transition?.operation_ref),
    expected_heads: uniqueRefs(transition?.expected_heads ?? []),
    state_root_before: requiredStringRef("transition.state_root_before", transition?.state_root_before),
    state_root_after: requiredStringRef("transition.state_root_after", transition?.state_root_after),
    resulting_head: requiredStringRef("transition.resulting_head", transition?.resulting_head),
    projection_watermark: requiredStringRef("transition.projection_watermark", transition?.projection_watermark),
    transition_hash: requiredStringRef("transition.transition_hash", transition?.transition_hash),
    evidence_refs: uniqueRefs(transition?.evidence_refs ?? []),
    acceptedReceiptTransition: objectRecord(transition?.transition),
  };
}

export function withModelMountInvocationAdmission(details, admission) {
  return {
    ...details,
    model_mount_invocation_admission_schema_version: "ioi.model_mount.invocation_admission.v1",
    model_mount_invocation_admission_ref: admission.invocation_admission_ref,
    model_mount_invocation_admission_hash: admission.invocation_admission_hash,
    model_mount_invocation_admission_source: admission.source,
    model_mount_invocation_admission_backend: admission.backend,
    model_mount_invocation_admission_receipt_refs: admission.receipt_refs ?? [],
    model_mount_invocation_admission: admission.record,
  };
}

export function withModelMountProviderExecutionAdmission(details, admission) {
  return {
    ...details,
    model_mount_provider_execution_schema_version: "ioi.model_mount.provider_execution.v1",
    model_mount_provider_execution_ref: admission.provider_execution_ref,
    model_mount_provider_execution_hash: admission.provider_execution_hash,
    model_mount_provider_execution_source: admission.source,
    model_mount_provider_execution_backend: admission.backend,
    model_mount_provider_execution_receipt_refs: admission.receipt_refs ?? [],
    model_mount_provider_execution: admission.record,
  };
}

export function withModelMountInvocationReceiptBinding(details, binding) {
  return {
    ...details,
    model_mount_receipt_binding_source: binding.source,
    model_mount_receipt_binding_backend: binding.backend,
    model_mount_receipt_binding_ref: binding.receipt_binding?.binding_hash ?? null,
    model_mount_receipt_binding: binding.receipt_binding ?? null,
    model_mount_accepted_receipt_append_hash: binding.accepted_receipt_append?.append_hash ?? null,
    model_mount_accepted_receipt_append: binding.accepted_receipt_append ?? null,
    model_mount_step_module_invocation: binding.invocation ?? null,
    model_mount_step_module_result: binding.result ?? null,
    model_mount_router_admission: binding.router_admission ?? null,
    model_mount_agentgres_admission: binding.agentgres_admission ?? null,
    model_mount_agentgres_admission_hash: binding.agentgres_admission?.admission_hash ?? null,
    model_mount_agentgres_operation_ref: binding.agentgres_admission?.operation_ref ?? null,
    model_mount_agentgres_expected_heads: binding.agentgres_admission?.expected_heads ?? [],
    model_mount_agentgres_state_root_before: binding.agentgres_admission?.state_root_before ?? null,
    model_mount_agentgres_state_root_after: binding.agentgres_admission?.state_root_after ?? null,
    model_mount_agentgres_resulting_head: binding.agentgres_admission?.resulting_head ?? null,
    model_mount_projection_record: binding.projection_record ?? null,
    model_mount_receipt_binding_receipt_refs: binding.receipt_refs ?? [],
  };
}

function admitModelMountProviderExecution(state, request) {
  if (typeof state.admitModelMountProviderExecution !== "function") {
    const error = new Error("Model provider execution requires Rust model_mount provider execution admission.");
    error.status = 500;
    error.code = "model_mount_provider_execution_admission_required";
    throw error;
  }
  return state.admitModelMountProviderExecution(request);
}

function admitModelMountProviderResult(state, request) {
  requireModelMountProviderResultAdmission(state);
  return state.admitModelMountProviderResult(request);
}

function requireModelMountProviderResultAdmission(state) {
  if (typeof state.admitModelMountProviderResult !== "function") {
    const error = new Error("Model provider result requires Rust model_mount provider result admission.");
    error.status = 500;
    error.code = "model_mount_provider_result_admission_required";
    throw error;
  }
}

async function executeModelProviderInvocation({
  input,
  instance,
  kind,
  modelMountProviderExecutionAdmission,
  providerBody,
  selection,
  state,
  token,
}) {
  if (modelMountProviderInvocationRequiresRust(selection)) {
    const providerResult = executeModelMountProviderInvocation(
      state,
      modelMountProviderInvocationRequestForExecution({
        input,
        instance,
        kind,
        modelMountProviderExecutionAdmission,
        selection,
      }),
    );
    rejectProviderCompatTranslation(providerResult);
    return providerResult;
  }
  rejectUnmigratedProviderInvocationExecution(selection);
}

export function modelMountProviderInvocationRequiresRust(selection = {}, options = {}) {
  const stream = Boolean(options.stream);
  return fixtureProviderInvocationSelected(selection) || (!stream && nativeLocalProviderInvocationSelected(selection));
}

export function modelMountProviderStreamInvocationRequiresRust(selection = {}) {
  return nativeLocalProviderInvocationSelected(selection);
}

function modelMountProviderInvocationExecutionBackend(selection = {}) {
  if (nativeLocalProviderInvocationSelected(selection)) {
    return "rust_model_mount_native_local";
  }
  return "rust_model_mount_fixture";
}

function fixtureProviderInvocationSelected(selection = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  const driver = endpoint.driver ?? provider.driver ?? driverNameForProvider(provider);
  return provider.kind === "local_folder" || driver === "fixture" || endpoint.apiFormat === "ioi_fixture";
}

function nativeLocalProviderInvocationSelected(selection = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  const driver = endpoint.driver ?? provider.driver ?? driverNameForProvider(provider);
  return provider.kind === "ioi_native_local" || driver === "native_local" || endpoint.apiFormat === "ioi_native";
}

function rejectUnmigratedProviderInvocationExecution(selection = {}, { stream = false } = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  const driver = endpoint.driver ?? provider.driver ?? driverNameForProvider(provider);
  const error = new Error(
    stream
      ? "Model provider stream execution requires a migrated Rust model_mount provider backend."
      : "Model provider execution requires a migrated Rust model_mount provider backend.",
  );
  error.status = 501;
  error.code = stream
    ? "model_mount_provider_stream_invocation_backend_unmigrated"
    : "model_mount_provider_invocation_backend_unmigrated";
  error.details = {
    provider_id: optionalRef(provider.id),
    provider_kind: optionalRef(provider.kind),
    endpoint_id: optionalRef(endpoint.id),
    api_format: optionalRef(endpoint.apiFormat ?? provider.apiFormat),
    driver: optionalRef(driver),
  };
  throw error;
}

function rejectProviderCompatTranslation(providerResult = {}) {
  const retiredAliases = ["compatTranslation"].filter((field) => Object.hasOwn(providerResult, field));
  const compatTranslation = optionalRef(providerResult.compat_translation);
  const retiredCompatTranslation = optionalRef(providerResult.compatTranslation);
  if (retiredAliases.length === 0 && !compatTranslation) return;
  const error = new Error("Model provider compatibility translations are retired; provider results must match the admitted invocation kind.");
  error.status = 500;
  error.code = "model_mount_provider_compat_translation_forbidden";
  error.details = {
    ...(compatTranslation || retiredCompatTranslation
      ? { compat_translation: compatTranslation ?? retiredCompatTranslation }
      : {}),
    ...(retiredAliases.length > 0 ? { retired_aliases: retiredAliases } : {}),
  };
  throw error;
}

function executeModelMountProviderInvocation(state, request) {
  if (typeof state.executeModelMountProviderInvocation !== "function") {
    const error = new Error("Migrated model provider execution requires Rust model_mount provider invocation execution.");
    error.status = 500;
    error.code = "model_mount_provider_invocation_execution_required";
    throw error;
  }
  return state.executeModelMountProviderInvocation(request);
}

function executeModelMountProviderStreamInvocation(state, request) {
  if (typeof state.executeModelMountProviderStreamInvocation !== "function") {
    const error = new Error("Migrated native-local model stream execution requires Rust model_mount provider stream invocation execution.");
    error.status = 500;
    error.code = "model_mount_provider_stream_invocation_execution_required";
    throw error;
  }
  return state.executeModelMountProviderStreamInvocation(request);
}

function withTextChunksReadableStream(providerResult = {}) {
  const streamHandle = textChunksReadableStream(providerResult.streamChunks ?? []);
  return {
    ...providerResult,
    stream: streamHandle.stream,
    abort: streamHandle.abort,
  };
}

function textChunksReadableStream(chunks = []) {
  const encoder = new TextEncoder();
  const encoded = (Array.isArray(chunks) ? chunks : []).map((chunk) => encoder.encode(String(chunk ?? "")));
  let controllerRef = null;
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    try {
      controllerRef?.close();
    } catch {
      // The consumer may already have canceled the stream.
    }
  };
  const abort = () => close();
  const stream = new ReadableStream({
    start(controller) {
      controllerRef = controller;
      for (const chunk of encoded) {
        if (closed) break;
        controller.enqueue(chunk);
      }
      close();
    },
    cancel() {
      abort();
    },
  });
  return { stream, abort };
}

function withModelMountProviderResultAdmission(providerResult, admission) {
  return {
    ...providerResult,
    model_mount_provider_result_admission_schema_version: "ioi.model_mount.provider_result.v1",
    model_mount_provider_result_admission_ref: admission.provider_result_ref,
    model_mount_provider_result_admission_hash: admission.provider_result_hash,
    model_mount_provider_result_admission_source: admission.source,
    model_mount_provider_result_admission_backend: admission.backend,
    model_mount_provider_result_admission_receipt_refs: admission.receipt_refs ?? [],
    model_mount_provider_result_admission_evidence_refs: admission.evidence_refs ?? [],
    model_mount_provider_result_admission: admission.record,
    backendEvidenceRefs: uniqueRefs([
      ...(providerResult.backendEvidenceRefs ?? []),
      admission.provider_result_ref,
      ...(admission.evidence_refs ?? []),
    ]),
  };
}

function bindModelMountInvocationReceipt(state, request) {
  if (typeof state.bindModelMountInvocationReceipt !== "function") {
    const error = new Error("Model invocation receipt persistence requires Rust receipt_binder binding.");
    error.status = 500;
    error.code = "model_mount_invocation_receipt_binding_required";
    throw error;
  }
  return state.bindModelMountInvocationReceipt(request);
}

function normalizeAgentgresHead(value) {
  const sequence = Number(value?.sequence);
  if (!Number.isInteger(sequence) || sequence < 0) {
    const error = new Error("Model invocation Agentgres admission requires a non-negative operation head sequence.");
    error.status = 500;
    error.code = "model_mount_agentgres_head_invalid";
    throw error;
  }
  return {
    sequence,
    head_ref: requiredStringRef("agentgresHead.head_ref", value?.head_ref),
    state_root: hashRef(value?.state_root, "agentgresHead.state_root"),
  };
}

function nextInvocationReceiptId(state, kind) {
  if (typeof state.nextReceiptId !== "function") {
    const error = new Error("Model invocation admission requires a precomputed receipt id before Rust admission.");
    error.status = 500;
    error.code = "model_mount_invocation_receipt_id_required";
    throw error;
  }
  return state.nextReceiptId(kind);
}

function requiredStringRef(field, value) {
  const normalized = optionalRef(value);
  if (!normalized) {
    const error = new Error(`Model invocation admission missing ${field}.`);
    error.status = 500;
    error.code = "model_mount_invocation_ref_missing";
    error.details = { field };
    throw error;
  }
  return normalized;
}

function optionalRef(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function assertCanonicalModelInvocationRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_INVOCATION_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model invocation request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_mount_invocation_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: [
      "route_id",
      "model_policy",
      "response_id",
      "previous_response_id",
      "send_options",
      "authority_grant_refs",
      "authority_receipt_refs",
      "custody_ref",
      "privacy_profile",
      "node_plaintext_allowed",
    ],
  };
  throw error;
}

export function modelInvocationRustCoreRequiredError(operation_kind, details = {}) {
  const error = new Error("Model invocation execution requires Rust daemon-core ownership.");
  error.status = 501;
  error.code = "model_mount_invocation_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.invocation",
    operation_kind,
    ...details,
    evidence_refs: MODEL_INVOCATION_RUST_CORE_REQUIRED_EVIDENCE_REFS,
  };
  return error;
}

function throwModelInvocationRustCoreRequired(operation_kind, details = {}) {
  throw modelInvocationRustCoreRequiredError(operation_kind, details);
}

function policyHashRef(value) {
  const normalized = requiredStringRef("policy_hash", value);
  return normalized.startsWith("sha256:") ? normalized : `sha256:${normalized}`;
}

function hashRef(value, field) {
  const normalized = requiredStringRef(field, value);
  return normalized.startsWith("sha256:") ? normalized : `sha256:${normalized}`;
}

function receiptRef(value) {
  const normalized = requiredStringRef("receipt_ref", value);
  return normalized.startsWith("receipt://") ? normalized : `receipt://${normalized}`;
}

function uniqueRefs(values = []) {
  const refs = [];
  for (const value of values) {
    const ref = optionalRef(value);
    if (ref && !refs.includes(ref)) refs.push(ref);
  }
  return refs;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

export function capabilityForInvocationKind(kind) {
  if (kind === "embeddings") return "embeddings";
  if (kind === "rerank") return "rerank";
  if (kind === "responses") return "responses";
  return "chat";
}

function invocationReceiptDetails({
  body,
  coalesced,
  coalesceKey,
  continuationSafety,
  hash,
  input,
  instance,
  latencyMs,
  outputText,
  previousResponseId,
  providerResult,
  responseId,
  routeReceipt,
  selection,
  token,
  tokenCount,
  ephemeralMcp,
  includeInvocationFields = true,
}) {
  const details = {
    route_id: selection.route.id,
    route_receipt_id: routeReceipt.id,
    selected_model: selection.endpoint.modelId,
    endpoint_id: selection.endpoint.id,
    provider_id: selection.endpoint.providerId,
    instance_id: instance.id,
    backend: providerResult.backend ?? selection.endpoint.apiFormat,
    backend_id: providerResult.backendId ?? instance.backendId ?? selection.endpoint.backendId ?? null,
    selected_backend: providerResult.backendId ?? instance.backendId ?? selection.endpoint.backendId ?? null,
    policy_hash: hash(body.model_policy ?? {}),
    grant_id: token.grantId,
    token_count: tokenCount,
    latency_ms: latencyMs,
    input_hash: hash(input),
    output_hash: hash(outputText),
    provider_response_kind: providerResult.providerResponseKind ?? null,
    backend_process: providerResult.backendProcess ?? instance.backendProcess ?? null,
    backend_process_id: providerResult.backendProcess?.id ?? instance.backendProcessId ?? null,
    backend_process_pid_hash: providerResult.backendProcess?.pidHash ?? instance.backendProcessPidHash ?? null,
    backend_evidence_refs: providerResult.backendEvidenceRefs ?? [],
    auth_vault_ref_hash: providerResult.authVaultRefHash ?? null,
    provider_auth_evidence_refs: providerResult.providerAuthEvidenceRefs ?? [],
    provider_auth_header_names: providerResult.providerAuthHeaderNames ?? [],
    model_mount_provider_result_admission_schema_version:
      providerResult.model_mount_provider_result_admission_schema_version ?? null,
    model_mount_provider_result_admission_ref: providerResult.model_mount_provider_result_admission_ref ?? null,
    model_mount_provider_result_admission_hash: providerResult.model_mount_provider_result_admission_hash ?? null,
    model_mount_provider_result_admission_source: providerResult.model_mount_provider_result_admission_source ?? null,
    model_mount_provider_result_admission_backend: providerResult.model_mount_provider_result_admission_backend ?? null,
    model_mount_provider_result_admission_receipt_refs:
      providerResult.model_mount_provider_result_admission_receipt_refs ?? [],
    model_mount_provider_result_admission_evidence_refs:
      providerResult.model_mount_provider_result_admission_evidence_refs ?? [],
    model_mount_provider_result_admission: providerResult.model_mount_provider_result_admission ?? null,
    tool_receipt_ids: ephemeralMcp.toolReceiptIds,
    ephemeral_mcp_server_ids: ephemeralMcp.serverIds,
    response_id: responseId,
    previous_response_id: previousResponseId,
    continuation: continuationSafety,
  };
  if (includeInvocationFields) {
    details.send_options = body.send_options ?? null;
    details.memory = body.memory ?? body.send_options?.memory ?? null;
    details.coalesced = coalesced;
    details.coalesce_key_hash = coalesceKey ? hash(coalesceKey) : null;
  }
  return details;
}

function persistRouteSelection(state, routeRecord, selectedModel, receiptId) {
  return routeRecord;
}
