import * as routeDecision from "./route-decision.mjs";
import {
  estimateTokens,
  inputText,
  summarizeProviderRequestBodyForTrace,
} from "./provider-protocol.mjs";
import {
  modelInvocationCoalesceKey,
  supportsResponseState,
} from "./provider-driver-helpers.mjs";
import { optionalString } from "./provider-registry.mjs";
import { stableHash } from "./io.mjs";

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
      return { instance, ephemeralMcp, providerResult };
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
  const { instance, ephemeralMcp, providerResult } = execution;
  const outputText = providerResult.outputText;
  const latencyMs = Math.max(1, state.now().getTime() - started);
  const tokenCount = providerResult.tokenCount ?? estimateTokenCounts(input, outputText);
  const receiptKind = coalesced ? "model_invocation_coalesced" : "model_invocation";
  const receiptId = nextInvocationReceiptId(state, receiptKind);
  const receiptDetails = invocationReceiptDetails({
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
  });
  const modelMountInvocationAdmission = state.admitModelMountInvocation(
    modelMountInvocationAdmissionRequestForReceipt({
      body,
      capability,
      kind,
      receiptDetails,
      receiptId,
      receiptKind,
      routeReceipt,
      selection,
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
      "rust_model_mount_core",
      modelMountInvocationAdmission.invocation_admission_ref,
      ...(modelMountInvocationAdmission.evidence_refs ?? []),
    ]),
    details: withModelMountInvocationAdmission(receiptDetails, modelMountInvocationAdmission),
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
    summarizeProviderRequestBodyForTrace: summarizeRequest = summarizeProviderRequestBodyForTrace,
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
  const driver = state.driverForProvider(selection.provider);
  if (typeof driver.streamInvoke !== "function" || (typeof driver.supportsStream === "function" && !driver.supportsStream(kind))) {
    return {
      native: false,
      invocation: await state.invokeModel({ authorization, requiredScope, kind, body: { ...body, stream: false } }),
    };
  }
  const routeReceipt = state.routeSelectionReceipt(selection, { body, capability, responseId, previousResponseId });
  const instance = await state.ensureLoaded(selection.endpoint);
  const ephemeralMcp = state.compileEphemeralMcpIntegrations({ authorization, body, input });
  const providerBody = providerRequestBodyForRoute(body, selection.endpoint);
  state.appendOperation?.("model.provider_stream_request_shape", {
    providerId: selection.provider.id,
    providerKind: selection.provider.kind,
    endpointId: selection.endpoint.id,
    routeId: selection.route.id,
    capability,
    requestShape: summarizeRequest(providerBody),
    evidenceRefs: ["model_provider_stream_request_shape"],
  });
  const providerResult = await driver.streamInvoke({
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
    return {
      native: false,
      invocation: await state.invokeModel({ authorization, requiredScope, kind, body: { ...body, stream: false } }),
    };
  }
  const outputText = "";
  const latencyMs = Math.max(1, state.now().getTime() - started);
  const tokenCount = providerResult.tokenCount ?? estimateTokenCounts(input, outputText);
  const receiptId = nextInvocationReceiptId(state, "model_invocation");
  const receiptDetails = {
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
  };
  const modelMountInvocationAdmission = state.admitModelMountInvocation(
    modelMountInvocationAdmissionRequestForReceipt({
      body,
      capability,
      kind,
      receiptDetails,
      receiptId,
      receiptKind: "model_invocation",
      routeReceipt,
      selection,
      streamStatus: "started",
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
      "rust_model_mount_core",
      modelMountInvocationAdmission.invocation_admission_ref,
      ...(modelMountInvocationAdmission.evidence_refs ?? []),
    ]),
    details: withModelMountInvocationAdmission(receiptDetails, modelMountInvocationAdmission),
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

function withModelMountInvocationAdmission(details, admission) {
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
