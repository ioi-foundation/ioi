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
  const token = state.authorize(authorization, requiredScope);
  const started = state.now().getTime();
  const input = textFromInput(body);
  const statefulInvocation = responseStateSupported(kind);
  const previousResponseId = statefulInvocation ? optional(body.previous_response_id ?? body.previousResponseId) : null;
  const previousState = previousResponseId ? state.conversationState(previousResponseId) : null;
  const responseId = statefulInvocation ? state.nextResponseId(body.response_id ?? body.responseId) : null;
  const capability = capabilityForInvocationKind(kind);
  const selection = state.selectRoute({
    modelId: body.model,
    routeId: body.route_id ?? body.routeId,
    capability,
    policy: body.model_policy ?? body.modelPolicy ?? {},
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
      providerResult.modelMountProviderResultAdmissionRef,
      ...(providerResult.modelMountProviderResultAdmissionEvidenceRefs ?? []),
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
    ? state.recordConversationState({
        responseId,
        previousState,
        kind,
        input,
        outputText: providerResult.outputText ?? "",
        selection,
        instance,
        receipt,
        routeReceipt,
        tokenCount,
        streamReceiptId: null,
        status: "completed",
        continuationSafety,
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
    compatTranslation: providerResult.compatTranslation ?? null,
    toolReceiptIds: ephemeralMcp.toolReceiptIds,
    responseId,
    previousResponseId,
    conversationState,
  };
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
  const token = state.authorize(authorization, requiredScope);
  const started = state.now().getTime();
  const input = textFromInput(body);
  const statefulInvocation = responseStateSupported(kind);
  const previousResponseId = statefulInvocation ? optional(body.previous_response_id ?? body.previousResponseId) : null;
  const previousState = previousResponseId ? state.conversationState(previousResponseId) : null;
  const responseId = statefulInvocation ? state.nextResponseId(body.response_id ?? body.responseId) : null;
  const capability = capabilityForInvocationKind(kind);
  const selection = state.selectRoute({
    modelId: body.model,
    routeId: body.route_id ?? body.routeId,
    capability,
    policy: body.model_policy ?? body.modelPolicy ?? {},
  });
  const continuationSafety = state.validateContinuationSafety({ previousState, selection, body });
  if (modelMountProviderInvocationRequiresRust(selection)) {
    const error = new Error("Native model stream requires a Rust model_mount stream backend for the selected provider.");
    error.status = 501;
    error.code = "model_mount_native_stream_backend_required";
    throw error;
  }
  const driver = state.driverForProvider(selection.provider);
  if (typeof driver.streamInvoke !== "function" || (typeof driver.supportsStream === "function" && !driver.supportsStream(kind))) {
    const error = new Error("Native model stream requires a provider driver with stream support.");
    error.status = 501;
    error.code = "model_mount_native_stream_capability_required";
    throw error;
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
  let providerResult = await driver.streamInvoke({
    state,
    provider: selection.provider,
    endpoint: selection.endpoint,
    instance,
    kind,
    body: providerBody,
    input,
    token,
  });
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
    streamStatus: "started",
    streamSource: "provider_native",
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
      providerResult.modelMountProviderResultAdmissionRef,
      ...(providerResult.modelMountProviderResultAdmissionEvidenceRefs ?? []),
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
    compatTranslation: providerResult.compatTranslation ?? null,
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
  const routeReceiptRef = receiptRef(requiredStringRef("routeReceipt.id", routeReceipt?.id));
  const invocationReceiptRef = receiptRef(requiredStringRef("receiptId", receiptId));
  const routeDecisionRef = requiredStringRef(
    "routeReceipt.details.modelMountRouteDecisionRef",
    routeReceipt?.details?.modelMountRouteDecisionRef,
  );
  const policy = body.model_policy ?? body.modelPolicy ?? {};
  return {
    schema_version: "ioi.model_mount.invocation_admission.v1",
    invocation_ref: `model-invocation://${requiredStringRef("receiptId", receiptId)}`,
    route_decision_ref: routeDecisionRef,
    route_receipt_ref: routeReceiptRef,
    invocation_receipt_ref: invocationReceiptRef,
    route_ref: requiredStringRef("route.id", selection?.route?.id ?? receiptDetails.routeId),
    provider_ref: requiredStringRef("provider.id", selection?.provider?.id ?? receiptDetails.providerId),
    endpoint_ref: requiredStringRef("endpoint.id", selection?.endpoint?.id ?? receiptDetails.endpointId),
    model_ref: requiredStringRef("endpoint.modelId", selection?.endpoint?.modelId ?? receiptDetails.selectedModel),
    capability: requiredStringRef("capability", capability),
    invocation_kind: requiredStringRef("kind", kind),
    policy_hash: policyHashRef(receiptDetails.policyHash),
    input_hash: hashRef(receiptDetails.inputHash, "input_hash"),
    output_hash: hashRef(receiptDetails.outputHash, "output_hash"),
    idempotency_key: `${receiptKind}:${receiptId}`,
    receipt_refs: uniqueRefs([
      routeReceiptRef,
      invocationReceiptRef,
      ...(Array.isArray(receiptDetails.toolReceiptIds) ? receiptDetails.toolReceiptIds.map(receiptRef) : []),
    ]),
    authority_grant_refs: uniqueRefs([
      optionalRef(receiptDetails.grantId),
      ...(Array.isArray(body.authority_grant_refs) ? body.authority_grant_refs : []),
      ...(Array.isArray(body.authorityGrantRefs) ? body.authorityGrantRefs : []),
    ]),
    authority_receipt_refs: uniqueRefs([
      ...(Array.isArray(body.authority_receipt_refs) ? body.authority_receipt_refs : []),
      ...(Array.isArray(body.authorityReceiptRefs) ? body.authorityReceiptRefs : []),
    ]),
    provider_auth_evidence_refs: uniqueRefs(receiptDetails.providerAuthEvidenceRefs ?? []),
    backend_evidence_refs: uniqueRefs(receiptDetails.backendEvidenceRefs ?? []),
    tool_receipt_refs: uniqueRefs(receiptDetails.toolReceiptIds ?? []),
    custody_ref: optionalRef(
      body.custody_ref ??
        body.custodyRef ??
        selection?.endpoint?.custodyRef ??
        selection?.endpoint?.custody_ref ??
        selection?.provider?.custodyRef ??
        selection?.provider?.custody_ref,
    ),
    privacy_profile: optionalRef(
      body.privacy_profile ??
        body.privacyProfile ??
        policy.privacy_profile ??
        policy.privacyProfile ??
        policy.privacy ??
        selection?.route?.privacy ??
        selection?.provider?.privacyClass,
    ),
    node_plaintext_allowed: Boolean(
      body.node_plaintext_allowed ??
        body.nodePlaintextAllowed ??
        selection?.endpoint?.nodePlaintextAllowed ??
        selection?.provider?.nodePlaintextAllowed ??
        false,
    ),
    workflow_graph_ref: optionalRef(routeReceipt?.details?.workflowGraphId),
    workflow_node_ref: optionalRef(routeReceipt?.details?.workflowNodeId),
    response_ref: optionalRef(receiptDetails.responseId),
    previous_response_ref: optionalRef(receiptDetails.previousResponseId),
    stream_status: optionalRef(streamStatus ?? receiptDetails.streamStatus),
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
  const routeReceiptRef = receiptRef(requiredStringRef("routeReceipt.id", routeReceipt?.id));
  const routeDecisionRef = requiredStringRef(
    "routeReceipt.details.modelMountRouteDecisionRef",
    routeReceipt?.details?.modelMountRouteDecisionRef,
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
  const policy = body.model_policy ?? body.modelPolicy ?? {};
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
      ...(Array.isArray(body.authorityGrantRefs) ? body.authorityGrantRefs : []),
    ]),
    authority_receipt_refs: uniqueRefs([
      ...(Array.isArray(body.authority_receipt_refs) ? body.authority_receipt_refs : []),
      ...(Array.isArray(body.authorityReceiptRefs) ? body.authorityReceiptRefs : []),
    ]),
    provider_auth_evidence_refs: [],
    backend_evidence_refs: uniqueRefs([
      instance.backendId,
      selection?.endpoint?.backendId,
    ]),
    tool_receipt_refs: uniqueRefs(ephemeralMcp.toolReceiptIds ?? []),
    custody_ref: optionalRef(
      body.custody_ref ??
        body.custodyRef ??
        selection?.endpoint?.custodyRef ??
        selection?.endpoint?.custody_ref ??
        selection?.provider?.custodyRef ??
        selection?.provider?.custody_ref,
    ),
    privacy_profile: optionalRef(
      body.privacy_profile ??
        body.privacyProfile ??
        policy.privacy_profile ??
        policy.privacyProfile ??
        policy.privacy ??
        selection?.route?.privacy ??
        selection?.provider?.privacyClass,
    ),
    node_plaintext_allowed: Boolean(
      body.node_plaintext_allowed ??
        body.nodePlaintextAllowed ??
        selection?.endpoint?.nodePlaintextAllowed ??
        selection?.provider?.nodePlaintextAllowed ??
        false,
    ),
    workflow_graph_ref: optionalRef(routeReceipt?.details?.workflowGraphId),
    workflow_node_ref: optionalRef(routeReceipt?.details?.workflowNodeId),
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
    execution_backend: "rust_model_mount_fixture",
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
    execution_backend: "js_provider_driver_observation",
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
    invocationRef: requiredStringRef("admissionRequest.invocation_ref", admissionRequest?.invocation_ref),
    routeRef: requiredStringRef("admissionRequest.route_ref", admissionRequest?.route_ref),
    providerRef: requiredStringRef("admissionRequest.provider_ref", admissionRequest?.provider_ref),
    endpointRef: requiredStringRef("admissionRequest.endpoint_ref", admissionRequest?.endpoint_ref),
    modelRef: requiredStringRef("admissionRequest.model_ref", admissionRequest?.model_ref),
    capability: requiredStringRef("admissionRequest.capability", admissionRequest?.capability),
    invocationKind: requiredStringRef("admissionRequest.invocation_kind", admissionRequest?.invocation_kind),
    inputHash: hashRef(admissionRequest?.input_hash, "admissionRequest.input_hash"),
    outputHash: hashRef(admissionRequest?.output_hash, "admissionRequest.output_hash"),
    policyHash: policyHashRef(admissionRequest?.policy_hash),
    routeDecisionRef: requiredStringRef("admissionRequest.route_decision_ref", admissionRequest?.route_decision_ref),
    routeReceiptRef: requiredStringRef("admissionRequest.route_receipt_ref", admissionRequest?.route_receipt_ref),
    receiptRef: receiptRefValue,
    authorityGrantRefs: admissionRequest?.authority_grant_refs ?? [],
    workflowGraphId: optionalRef(admissionRequest?.workflow_graph_ref) ?? "workflow:model-mount",
    workflowNodeId:
      optionalRef(admissionRequest?.workflow_node_ref) ?? `node:model-mount:${requiredStringRef("receiptId", receiptId)}`,
    privacyProfile: admissionRequest?.privacy_profile ?? "internal",
    nodePlaintextAllowed: Boolean(admissionRequest?.node_plaintext_allowed),
    custodyProofRef: admissionRequest?.custody_ref ?? null,
    idempotencyKey: admissionRequest?.idempotency_key ?? `model_invocation:${receiptId}`,
    stateRootBefore: requiredStringRef("agentgresTransition.stateRootBefore", agentgresTransition?.stateRootBefore),
    projectionWatermark: requiredStringRef("agentgresTransition.projectionWatermark", agentgresTransition?.projectionWatermark),
    agentgresOperationRefs: [
      requiredStringRef("agentgresTransition.operationRef", agentgresTransition?.operationRef),
    ],
    stateRootAfter: requiredStringRef("agentgresTransition.stateRootAfter", agentgresTransition?.stateRootAfter),
    resultingHead: requiredStringRef("agentgresTransition.resultingHead", agentgresTransition?.resultingHead),
    evidenceRefs: uniqueRefs([
      "rust_model_mount_core",
      admission?.invocation_admission_ref,
      ...(admission?.evidence_refs ?? []),
      ...(receiptDetails.providerAuthEvidenceRefs ?? []),
      ...(receiptDetails.backendEvidenceRefs ?? []),
    ]),
  });
  return {
    invocation,
    result,
    expectedHeads: uniqueRefs(agentgresTransition?.expectedHeads ?? []),
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
  if (typeof state.agentgresModelMountingHead !== "function") {
    const error = new Error("Model invocation Agentgres admission requires a current model-mounting operation head.");
    error.status = 500;
    error.code = "model_mount_agentgres_head_required";
    throw error;
  }
  const currentHead = normalizeAgentgresHead(state.agentgresModelMountingHead());
  const nextSequence = currentHead.sequence + 1;
  const operationId = `op_${String(nextSequence).padStart(8, "0")}_${requiredStringRef("receiptKind", receiptKind).replace(/[^a-z0-9]+/gi, "_")}`;
  const operationRef = `agentgres://model-mounting/operation-log/${operationId}`;
  const resultingHead = `agentgres://model-mounting/operation-log/head/${nextSequence}`;
  const stateRootAfter = `sha256:${stableHash({
    schema: "ioi.agentgres.model_mounting_state_root.v1",
    sequence: nextSequence,
    previousHead: currentHead.headRef,
    operationRef,
    receiptId: requiredStringRef("receiptId", receiptId),
    receiptKind,
    routeDecisionRef: admissionRequest?.route_decision_ref ?? null,
    invocationAdmissionRef: admission?.invocation_admission_ref ?? null,
    invocationAdmissionHash: admission?.invocation_admission_hash ?? null,
    inputHash: admissionRequest?.input_hash ?? receiptDetails.inputHash ?? null,
    outputHash: admissionRequest?.output_hash ?? receiptDetails.outputHash ?? null,
  })}`;
  return {
    operationId,
    operationRef,
    expectedHeads: [currentHead.headRef],
    stateRootBefore: currentHead.stateRoot,
    stateRootAfter,
    resultingHead,
    projectionWatermark: `model-mounting-operation-log:${nextSequence}`,
  };
}

export function withModelMountInvocationAdmission(details, admission) {
  return {
    ...details,
    modelMountInvocationAdmissionSchemaVersion: "ioi.model_mount.invocation_admission.v1",
    modelMountInvocationAdmissionRef: admission.invocation_admission_ref,
    modelMountInvocationAdmissionHash: admission.invocation_admission_hash,
    modelMountInvocationAdmissionSource: admission.source,
    modelMountInvocationAdmissionBackend: admission.backend,
    modelMountInvocationAdmissionReceiptRefs: admission.receipt_refs ?? [],
    modelMountInvocationAdmission: admission.record,
  };
}

export function withModelMountProviderExecutionAdmission(details, admission) {
  return {
    ...details,
    modelMountProviderExecutionSchemaVersion: "ioi.model_mount.provider_execution.v1",
    modelMountProviderExecutionRef: admission.provider_execution_ref,
    modelMountProviderExecutionHash: admission.provider_execution_hash,
    modelMountProviderExecutionSource: admission.source,
    modelMountProviderExecutionBackend: admission.backend,
    modelMountProviderExecutionReceiptRefs: admission.receipt_refs ?? [],
    modelMountProviderExecution: admission.record,
  };
}

export function withModelMountInvocationReceiptBinding(details, binding) {
  return {
    ...details,
    modelMountReceiptBindingSource: binding.source,
    modelMountReceiptBindingBackend: binding.backend,
    modelMountReceiptBindingRef: binding.receipt_binding?.binding_hash ?? null,
    modelMountReceiptBinding: binding.receipt_binding ?? null,
    modelMountAcceptedReceiptAppendHash: binding.accepted_receipt_append?.append_hash ?? null,
    modelMountAcceptedReceiptAppend: binding.accepted_receipt_append ?? null,
    modelMountStepModuleInvocation: binding.invocation ?? null,
    modelMountStepModuleResult: binding.result ?? null,
    modelMountRouterAdmission: binding.router_admission ?? null,
    modelMountAgentgresAdmission: binding.agentgres_admission ?? null,
    modelMountAgentgresAdmissionHash: binding.agentgres_admission?.admission_hash ?? null,
    modelMountAgentgresOperationRef: binding.agentgres_admission?.operation_ref ?? null,
    modelMountAgentgresExpectedHeads: binding.agentgres_admission?.expected_heads ?? [],
    modelMountAgentgresStateRootBefore: binding.agentgres_admission?.state_root_before ?? null,
    modelMountAgentgresStateRootAfter: binding.agentgres_admission?.state_root_after ?? null,
    modelMountAgentgresResultingHead: binding.agentgres_admission?.resulting_head ?? null,
    modelMountProjectionRecord: binding.projection_record ?? null,
    modelMountReceiptBindingReceiptRefs: binding.receipt_refs ?? [],
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
    return executeModelMountProviderInvocation(
      state,
      modelMountProviderInvocationRequestForExecution({
        input,
        instance,
        kind,
        modelMountProviderExecutionAdmission,
        selection,
      }),
    );
  }
  requireModelMountProviderResultAdmission(state);
  const providerResult = await state.driverForProvider(selection.provider).invoke({
    state,
    provider: selection.provider,
    endpoint: selection.endpoint,
    instance,
    kind,
    body: providerBody,
    input,
    token,
  });
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
  return withModelMountProviderResultAdmission(providerResult, modelMountProviderResultAdmission);
}

export function modelMountProviderInvocationRequiresRust(selection = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  const driver = endpoint.driver ?? provider.driver ?? driverNameForProvider(provider);
  return provider.kind === "local_folder" || driver === "fixture" || endpoint.apiFormat === "ioi_fixture";
}

function executeModelMountProviderInvocation(state, request) {
  if (typeof state.executeModelMountProviderInvocation !== "function") {
    const error = new Error("Fixture model provider execution requires Rust model_mount provider invocation execution.");
    error.status = 500;
    error.code = "model_mount_provider_invocation_execution_required";
    throw error;
  }
  return state.executeModelMountProviderInvocation(request);
}

function withModelMountProviderResultAdmission(providerResult, admission) {
  return {
    ...providerResult,
    modelMountProviderResultAdmissionSchemaVersion: "ioi.model_mount.provider_result.v1",
    modelMountProviderResultAdmissionRef: admission.provider_result_ref,
    modelMountProviderResultAdmissionHash: admission.provider_result_hash,
    modelMountProviderResultAdmissionSource: admission.source,
    modelMountProviderResultAdmissionBackend: admission.backend,
    modelMountProviderResultAdmissionReceiptRefs: admission.receipt_refs ?? [],
    modelMountProviderResultAdmissionEvidenceRefs: admission.evidence_refs ?? [],
    modelMountProviderResultAdmission: admission.record,
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
    headRef: requiredStringRef("agentgresHead.headRef", value?.headRef),
    stateRoot: hashRef(value?.stateRoot, "agentgresHead.stateRoot"),
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
    routeId: selection.route.id,
    routeReceiptId: routeReceipt.id,
    selectedModel: selection.endpoint.modelId,
    endpointId: selection.endpoint.id,
    providerId: selection.endpoint.providerId,
    instanceId: instance.id,
    backend: providerResult.backend ?? selection.endpoint.apiFormat,
    backendId: providerResult.backendId ?? instance.backendId ?? selection.endpoint.backendId ?? null,
    selectedBackend: providerResult.backendId ?? instance.backendId ?? selection.endpoint.backendId ?? null,
    policyHash: hash(body.model_policy ?? body.modelPolicy ?? {}),
    grantId: token.grantId,
    tokenCount,
    latencyMs,
    inputHash: hash(input),
    outputHash: hash(outputText),
    compatTranslation: providerResult.compatTranslation ?? null,
    providerResponseKind: providerResult.providerResponseKind ?? null,
    backendProcess: providerResult.backendProcess ?? instance.backendProcess ?? null,
    backendProcessId: providerResult.backendProcess?.id ?? instance.backendProcessId ?? null,
    backendProcessPidHash: providerResult.backendProcess?.pidHash ?? instance.backendProcessPidHash ?? null,
    backendEvidenceRefs: providerResult.backendEvidenceRefs ?? [],
    authVaultRefHash: providerResult.authVaultRefHash ?? null,
    providerAuthEvidenceRefs: providerResult.providerAuthEvidenceRefs ?? [],
    providerAuthHeaderNames: providerResult.providerAuthHeaderNames ?? [],
    modelMountProviderResultAdmissionSchemaVersion: providerResult.modelMountProviderResultAdmissionSchemaVersion ?? null,
    modelMountProviderResultAdmissionRef: providerResult.modelMountProviderResultAdmissionRef ?? null,
    modelMountProviderResultAdmissionHash: providerResult.modelMountProviderResultAdmissionHash ?? null,
    modelMountProviderResultAdmissionSource: providerResult.modelMountProviderResultAdmissionSource ?? null,
    modelMountProviderResultAdmissionBackend: providerResult.modelMountProviderResultAdmissionBackend ?? null,
    modelMountProviderResultAdmissionReceiptRefs: providerResult.modelMountProviderResultAdmissionReceiptRefs ?? [],
    modelMountProviderResultAdmissionEvidenceRefs:
      providerResult.modelMountProviderResultAdmissionEvidenceRefs ?? [],
    modelMountProviderResultAdmission: providerResult.modelMountProviderResultAdmission ?? null,
    toolReceiptIds: ephemeralMcp.toolReceiptIds,
    ephemeralMcpServerIds: ephemeralMcp.serverIds,
    responseId,
    previousResponseId,
    continuation: continuationSafety,
  };
  if (includeInvocationFields) {
    details.sendOptions = body.send_options ?? body.sendOptions ?? null;
    details.memory = body.memory ?? body.send_options?.memory ?? body.sendOptions?.memory ?? null;
    details.coalesced = coalesced;
    details.coalesceKeyHash = coalesceKey ? hash(coalesceKey) : null;
  }
  return details;
}

function persistRouteSelection(state, routeRecord, selectedModel, receiptId) {
  const route = {
    ...routeRecord,
    lastSelectedModel: selectedModel,
    lastReceiptId: receiptId,
  };
  state.routes.set(route.id, route);
  state.writeMap("model-routes", state.routes);
  return route;
}
