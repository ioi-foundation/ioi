import assert from "node:assert/strict";
import test from "node:test";

import * as modelInvocationOpsModule from "./model-invocation-operations.mjs";
import {
  capabilityForInvocationKind,
  invokeModel,
  startModelStream,
} from "./model-invocation-operations.mjs";

function testOptionalRef(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function testRequiredRef(field, value) {
  const normalized = testOptionalRef(value);
  if (!normalized) {
    const error = new Error(`test Rust authority fixture missing ${field}`);
    error.code = "test_rust_authority_fixture_ref_missing";
    error.details = { field };
    throw error;
  }
  return normalized;
}

function testHashRef(value, field) {
  const normalized = testRequiredRef(field, value);
  return normalized.startsWith("sha256:") ? normalized : `sha256:${normalized}`;
}

function testReceiptRef(value) {
  const normalized = testRequiredRef("receipt_ref", value);
  return normalized.startsWith("receipt://") ? normalized : `receipt://${normalized}`;
}

function testUniqueRefs(values = []) {
  const refs = [];
  for (const value of values) {
    const ref = testOptionalRef(value);
    if (ref && !refs.includes(ref)) refs.push(ref);
  }
  return refs;
}

function testProviderDriver(selection = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  return testOptionalRef(endpoint.driver ?? provider.driver);
}

function testHostedProviderSelected(selection = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  const driver = testProviderDriver(selection);
  return [
    "openai",
    "anthropic",
    "gemini",
    "custom_http",
    "openai_compatible",
    "ollama",
    "vllm",
    "llama_cpp",
    "lm_studio",
    "depin_tee",
  ].includes(provider.kind) ||
    ["openai", "anthropic", "gemini", "custom", "openai_compatible", "ollama"].includes(
      endpoint.api_format ?? provider.api_format,
    ) ||
    ["openai_compatible", "hosted_provider"].includes(driver);
}

function testRustExecutionBackend(selection = {}, { stream = false } = {}) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  const driver = testProviderDriver(selection);
  const nativeLocal = provider.kind === "ioi_native_local" || driver === "native_local" || endpoint.api_format === "ioi_native";
  if (stream) return testHostedProviderSelected(selection) ? "rust_model_mount_hosted_provider_stream" : "rust_model_mount_native_local_stream";
  if (nativeLocal) return "rust_model_mount_native_local";
  if (provider.kind === "local_folder" || driver === "fixture" || endpoint.api_format === "ioi_fixture") {
    return "rust_model_mount_fixture";
  }
  if (testHostedProviderSelected(selection)) return "rust_model_mount_hosted_provider";
  return "rust_model_mount_fixture";
}

function testProviderAuthEvidenceRefs(selection = {}, hash = (value) => `hash:${value}`) {
  const provider = selection.provider ?? {};
  const endpoint = selection.endpoint ?? {};
  if (!testHostedProviderSelected(selection)) return [];
  const secretRef = testOptionalRef(
    provider.secret_ref ??
      endpoint.secret_ref ??
      provider.auth_vault_ref ??
      endpoint.auth_vault_ref ??
      provider.api_key_vault_ref ??
      endpoint.api_key_vault_ref,
  );
  const refs = [
    "rust_model_mount_hosted_provider_auth_gate",
    "wallet_network_provider_transport_authority_bound",
    "ctee_hosted_provider_secret_not_exposed",
    "provider_env_secret_material_fallback_retired",
  ];
  if (secretRef?.startsWith("vault://")) {
    refs.push("wallet_network_provider_vault_ref_bound");
    refs.push("rust_provider_auth_materialization_bound");
    refs.push("hosted_provider_auth_header_materialized_by_rust");
    refs.push("rust_ctee_egress_resolver_bound");
    refs.push("ctee_outbound_egress_resolver_depth_bound");
    refs.push(`provider_vault_ref_hash:${hash(secretRef)}`);
  } else {
    refs.push("wallet_network_provider_vault_ref_required");
  }
  return testUniqueRefs(refs);
}

function testRustPlanProviderExecutionContract({
  body = {},
  capability = "chat",
  ephemeralMcp = {},
  hash = (value) => `hash:${value}`,
  input,
  instance = {},
  kind,
  providerBody = {},
  routeReceipt,
  selection,
  streamStatus = null,
  token = {},
} = {}) {
  const routeReceiptRef = testReceiptRef(routeReceipt?.id);
  const requestHash = testHashRef(
    hash({
      endpoint_id: selection?.endpoint?.id ?? null,
      invocation_kind: kind,
      provider_body: providerBody,
      stream_status: streamStatus,
    }),
    "request_hash",
  );
  return {
    schema_version: "ioi.model_mount.provider_execution.v1",
    invocation_ref: `model-provider-execution://${requestHash.replace(/^sha256:/, "sha256/")}`,
    route_decision_ref: testRequiredRef(
      "routeReceipt.details.model_mount_route_decision_ref",
      routeReceipt?.details?.model_mount_route_decision_ref,
    ),
    route_receipt_ref: routeReceiptRef,
    route_ref: testRequiredRef("route.id", selection?.route?.id),
    provider_ref: testRequiredRef("provider.id", selection?.provider?.id),
    endpoint_ref: testRequiredRef("endpoint.id", selection?.endpoint?.id),
    model_ref: testRequiredRef("endpoint.model_id", selection?.endpoint?.model_id),
    capability: testRequiredRef("capability", capability),
    invocation_kind: testRequiredRef("kind", kind),
    policy_hash: testHashRef(hash(body.model_policy ?? {}), "policy_hash"),
    input_hash: testHashRef(hash(input ?? ""), "input_hash"),
    request_hash: requestHash,
    idempotency_key: `model_provider_execution:${routeReceiptRef}:${requestHash}`,
    receipt_refs: testUniqueRefs([
      routeReceiptRef,
      ...(Array.isArray(ephemeralMcp.toolReceiptIds) ? ephemeralMcp.toolReceiptIds.map(testReceiptRef) : []),
    ]),
    authority_grant_refs: testUniqueRefs([
      token.grant_ref,
      ...(Array.isArray(body.authority_grant_refs) ? body.authority_grant_refs : []),
    ]),
    authority_receipt_refs: testUniqueRefs(body.authority_receipt_refs ?? []),
    provider_auth_evidence_refs: testProviderAuthEvidenceRefs(selection, hash),
    backend_evidence_refs: testUniqueRefs([
      instance.backend_id,
      selection?.endpoint?.backend_id,
    ]),
    tool_receipt_refs: testUniqueRefs(ephemeralMcp.toolReceiptIds ?? []),
    custody_ref: testOptionalRef(
      body.custody_ref ??
        selection?.endpoint?.custody_ref ??
        selection?.provider?.custody_ref,
    ),
    privacy_profile: testOptionalRef(
      body.privacy_profile ??
        body.model_policy?.privacy_profile ??
        body.model_policy?.privacy ??
        selection?.route?.privacy ??
        selection?.provider?.privacy_class,
    ),
    node_plaintext_allowed: Boolean(
      body.node_plaintext_allowed ??
        selection?.endpoint?.node_plaintext_allowed ??
        selection?.provider?.node_plaintext_allowed ??
        false,
    ),
    workflow_graph_ref: testOptionalRef(routeReceipt?.details?.workflow_graph_id),
    workflow_node_ref: testOptionalRef(routeReceipt?.details?.workflow_node_id),
    stream_status: testOptionalRef(streamStatus),
  };
}

function testRustPlanProviderInvocationContract({
  input,
  instance = {},
  kind,
  providerExecutionAdmission = {},
  selection,
  stream = false,
} = {}) {
  const record = providerExecutionAdmission.record ?? {};
  const provider = selection?.provider ?? {};
  const endpoint = selection?.endpoint ?? {};
  return {
    schema_version: stream ? "ioi.model_mount.provider_stream_invocation.v1" : "ioi.model_mount.provider_invocation.v1",
    provider_execution_ref: testRequiredRef(
      "providerExecutionAdmission.provider_execution_ref",
      providerExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
    ),
    provider_execution_hash: testRequiredRef(
      "providerExecutionAdmission.provider_execution_hash",
      providerExecutionAdmission.provider_execution_hash ?? record.provider_execution_hash,
    ),
    route_decision_ref: testRequiredRef("providerExecution.route_decision_ref", record.route_decision_ref),
    route_receipt_ref: testRequiredRef("providerExecution.route_receipt_ref", record.route_receipt_ref),
    route_ref: testRequiredRef("providerExecution.route_ref", record.route_ref),
    provider_ref: testRequiredRef("providerExecution.provider_ref", record.provider_ref),
    provider_kind: testRequiredRef("provider.kind", provider.kind),
    endpoint_ref: testRequiredRef("providerExecution.endpoint_ref", record.endpoint_ref),
    model_ref: testRequiredRef("providerExecution.model_ref", record.model_ref),
    capability: testRequiredRef("providerExecution.capability", record.capability),
    invocation_kind: testRequiredRef("providerExecution.invocation_kind", record.invocation_kind ?? kind),
    input: String(input ?? ""),
    request_hash: testRequiredRef("providerExecution.request_hash", record.request_hash),
    execution_backend: testRustExecutionBackend(selection, { stream }),
    api_format: testOptionalRef(endpoint.api_format ?? provider.api_format),
    driver: testProviderDriver(selection),
    backend_ref: testOptionalRef(instance.backend_id ?? endpoint.backend_id),
    base_url: testOptionalRef(endpoint.base_url ?? provider.base_url),
    provider_auth_materialization_ref: testOptionalRef(
      endpoint.provider_auth_materialization_ref ?? provider.provider_auth_materialization_ref,
    ),
    outbound_header_binding_ref: testOptionalRef(
      endpoint.outbound_header_binding_ref ?? provider.outbound_header_binding_ref,
    ),
    auth_header_materialization_status: testOptionalRef(
      endpoint.auth_header_materialization_status ?? provider.auth_header_materialization_status,
    ),
    ctee_egress_resolver_ref: testOptionalRef(
      endpoint.ctee_egress_resolver_ref ?? provider.ctee_egress_resolver_ref,
    ),
    ctee_egress_resolver_hash: testOptionalRef(
      endpoint.ctee_egress_resolver_hash ?? provider.ctee_egress_resolver_hash,
    ),
    ctee_egress_resolution_status: testOptionalRef(
      endpoint.ctee_egress_resolution_status ?? provider.ctee_egress_resolution_status,
    ),
    stream_status: testOptionalRef(record.stream_status) ?? (stream ? "started" : null),
    receipt_refs: providerExecutionAdmission.receipt_refs ?? record.receipt_refs ?? [],
    evidence_refs: testUniqueRefs([
      providerExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
      ...(providerExecutionAdmission.evidence_refs ?? []),
    ]),
    admitted_provider_execution: record,
  };
}

function testRustPlanProviderResultAdmissionContract({
  kind,
  providerExecutionAdmission = {},
  providerResult = {},
  selection,
} = {}) {
  const record = providerExecutionAdmission.record ?? {};
  const provider = selection?.provider ?? {};
  const endpoint = selection?.endpoint ?? {};
  const stream = Boolean(testOptionalRef(record.stream_status));
  const outputText = String(providerResult.output_text ?? "");
  return {
    schema_version: "ioi.model_mount.provider_result.v1",
    provider_execution_ref: testRequiredRef(
      "providerExecutionAdmission.provider_execution_ref",
      providerExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
    ),
    provider_execution_hash: testRequiredRef(
      "providerExecutionAdmission.provider_execution_hash",
      providerExecutionAdmission.provider_execution_hash ?? record.provider_execution_hash,
    ),
    route_decision_ref: testRequiredRef("providerExecution.route_decision_ref", record.route_decision_ref),
    route_receipt_ref: testRequiredRef("providerExecution.route_receipt_ref", record.route_receipt_ref),
    route_ref: testRequiredRef("providerExecution.route_ref", record.route_ref),
    provider_ref: testRequiredRef("providerExecution.provider_ref", record.provider_ref),
    provider_kind: testRequiredRef("provider.kind", provider.kind),
    endpoint_ref: testRequiredRef("providerExecution.endpoint_ref", record.endpoint_ref),
    model_ref: testRequiredRef("providerExecution.model_ref", record.model_ref),
    capability: testRequiredRef("providerExecution.capability", record.capability),
    invocation_kind: testRequiredRef("providerExecution.invocation_kind", record.invocation_kind ?? kind),
    request_hash: testRequiredRef("providerExecution.request_hash", record.request_hash),
    output_text: outputText,
    output_hash: testHashRef(`hash:${outputText}`, "output_hash"),
    token_count: providerResult.token_count,
    provider_response_kind: testOptionalRef(providerResult.provider_response_kind),
    execution_backend: testRequiredRef("providerResult.execution_backend", providerResult.execution_backend),
    backend_ref: testOptionalRef(providerResult.backend_id ?? endpoint.backend_id),
    stream_status: testOptionalRef(record.stream_status),
    hosted_transport_request_ref: testOptionalRef(providerResult.hosted_transport_request_ref),
    hosted_transport_request_hash: testOptionalRef(providerResult.hosted_transport_request_hash),
    hosted_transport_response_hash: testOptionalRef(providerResult.hosted_transport_response_hash),
    hosted_transport_status: testOptionalRef(providerResult.hosted_transport_status),
    ctee_egress_resolver_ref: testOptionalRef(providerResult.ctee_egress_resolver_ref),
    ctee_egress_resolver_hash: testOptionalRef(providerResult.ctee_egress_resolver_hash),
    ctee_egress_resolution_status: testOptionalRef(providerResult.ctee_egress_resolution_status),
    receipt_refs: providerExecutionAdmission.receipt_refs ?? record.receipt_refs ?? [],
    provider_auth_evidence_refs: testUniqueRefs(providerResult.provider_auth_evidence_refs ?? []),
    backend_evidence_refs: testUniqueRefs(providerResult.backend_evidence_refs ?? []),
    evidence_refs: testUniqueRefs([
      providerExecutionAdmission.provider_execution_ref ?? record.provider_execution_ref,
      ...(providerExecutionAdmission.evidence_refs ?? []),
      stream ? "rust_model_mount_provider_stream_result_admission" : "rust_model_mount_provider_result_admission",
    ]),
    admitted_provider_execution: record,
  };
}

function testRustPlanInvocationAdmissionContract({
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
  const routeReceiptRef = testReceiptRef(routeReceipt?.id);
  const invocationReceiptRef = testReceiptRef(receiptId);
  return {
    schema_version: "ioi.model_mount.invocation_admission.v1",
    invocation_ref: `model-invocation://${testRequiredRef("receiptId", receiptId)}`,
    route_decision_ref: testRequiredRef(
      "routeReceipt.details.model_mount_route_decision_ref",
      routeReceipt?.details?.model_mount_route_decision_ref,
    ),
    route_receipt_ref: routeReceiptRef,
    invocation_receipt_ref: invocationReceiptRef,
    route_ref: testRequiredRef("route.id", selection?.route?.id ?? receiptDetails.route_id),
    provider_ref: testRequiredRef("provider.id", selection?.provider?.id ?? receiptDetails.provider_id),
    endpoint_ref: testRequiredRef("endpoint.id", selection?.endpoint?.id ?? receiptDetails.endpoint_id),
    model_ref: testRequiredRef("endpoint.model_id", selection?.endpoint?.model_id ?? receiptDetails.selected_model),
    capability: testRequiredRef("capability", capability),
    invocation_kind: testRequiredRef("kind", kind),
    policy_hash: testHashRef(receiptDetails.policy_hash, "policy_hash"),
    input_hash: testHashRef(receiptDetails.input_hash, "input_hash"),
    output_hash: testHashRef(receiptDetails.output_hash, "output_hash"),
    idempotency_key: `${receiptKind}:${receiptId}`,
    receipt_refs: testUniqueRefs([
      routeReceiptRef,
      invocationReceiptRef,
      ...(Array.isArray(receiptDetails.tool_receipt_ids) ? receiptDetails.tool_receipt_ids.map(testReceiptRef) : []),
    ]),
    authority_grant_refs: testUniqueRefs([
      receiptDetails.grant_id,
      ...(Array.isArray(body.authority_grant_refs) ? body.authority_grant_refs : []),
    ]),
    authority_receipt_refs: testUniqueRefs(body.authority_receipt_refs ?? []),
    provider_auth_evidence_refs: testUniqueRefs(receiptDetails.provider_auth_evidence_refs ?? []),
    backend_evidence_refs: testUniqueRefs(receiptDetails.backend_evidence_refs ?? []),
    tool_receipt_refs: testUniqueRefs(receiptDetails.tool_receipt_ids ?? []),
    custody_ref: testOptionalRef(
      body.custody_ref ??
        selection?.endpoint?.custody_ref ??
        selection?.provider?.custody_ref,
    ),
    privacy_profile: testOptionalRef(
      body.privacy_profile ??
        body.model_policy?.privacy_profile ??
        body.model_policy?.privacy ??
        selection?.route?.privacy ??
        selection?.provider?.privacy_class,
    ),
    node_plaintext_allowed: Boolean(
      body.node_plaintext_allowed ??
        selection?.endpoint?.node_plaintext_allowed ??
        selection?.provider?.node_plaintext_allowed ??
        false,
    ),
    workflow_graph_ref: testOptionalRef(routeReceipt?.details?.workflow_graph_id),
    workflow_node_ref: testOptionalRef(routeReceipt?.details?.workflow_node_id),
    response_ref: testOptionalRef(receiptDetails.response_id),
    previous_response_ref: testOptionalRef(receiptDetails.previous_response_id),
    stream_status: testOptionalRef(streamStatus ?? receiptDetails.stream_status),
  };
}

function testRustPlanReceiptBindingContract({
  admission,
  admissionRequest,
  agentgresTransition = {},
  receiptDetails = {},
  receiptId,
} = {}) {
  const receiptRef = testReceiptRef(receiptId);
  const invocationId = `model-mount:${testRequiredRef("admissionRequest.invocation_ref", admissionRequest?.invocation_ref)}`;
  const workflowGraphId = testOptionalRef(admissionRequest?.workflow_graph_ref) ?? "workflow:model-mount";
  const workflowNodeId = testOptionalRef(admissionRequest?.workflow_node_ref) ?? `node:model-mount:${receiptId}`;
  const evidenceRefs = testUniqueRefs([
    "rust_model_mount_core",
    admission?.invocation_admission_ref,
    ...(admission?.evidence_refs ?? []),
    ...(receiptDetails.provider_auth_evidence_refs ?? []),
    ...(receiptDetails.backend_evidence_refs ?? []),
  ]);
  return {
    invocation: {
      schema_version: "ioi.step_module_invocation.v1",
      invocation_id: invocationId,
      module_ref: { kind: "model_mount", ref: "ioi://step-module/model_mount" },
      execution: { backend: "model_mount", owner: "rust_daemon_core" },
      input: {
        route_decision_ref: testRequiredRef("admissionRequest.route_decision_ref", admissionRequest?.route_decision_ref),
        route_receipt_ref: testRequiredRef("admissionRequest.route_receipt_ref", admissionRequest?.route_receipt_ref),
        state_root_before: testRequiredRef("agentgresTransition.state_root_before", agentgresTransition?.state_root_before),
        input_hash: testHashRef(admissionRequest?.input_hash, "admissionRequest.input_hash"),
        output_hash: testHashRef(admissionRequest?.output_hash, "admissionRequest.output_hash"),
      },
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      authority: {
        authority_grant_refs: admissionRequest?.authority_grant_refs ?? [],
      },
    },
    result: {
      schema_version: "ioi.step_module_result.v1",
      invocation_id: invocationId,
      receipt_refs: [receiptRef],
      agentgres_operation_refs: [
        testRequiredRef("agentgresTransition.operation_ref", agentgresTransition?.operation_ref),
      ],
      state_root_after: testRequiredRef("agentgresTransition.state_root_after", agentgresTransition?.state_root_after),
      resulting_head: testRequiredRef("agentgresTransition.resulting_head", agentgresTransition?.resulting_head),
      workflow_projection: {
        component_kind: "ModelInvocationNode",
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        status: "live",
        evidence_refs: evidenceRefs,
      },
    },
    acceptedReceiptTransition: agentgresTransition.acceptedReceiptTransition ?? null,
    receiptRef,
  };
}

function fakeState(overrides = {}) {
  const state = {
    authorizationCalls: [],
    agentgresConversationRecords: new Map(),
    nowMs: 1_000,
    receiptIdCounter: 0,
    receipts: [],
    receiptBindingRequests: [],
    authorityPlanRequests: [],
    providerExecutionRequests: [],
    providerInvocationRequests: [],
    providerStreamInvocationRequests: [],
    providerResultRequests: [],
    transitionRequests: [],
    recordStateCommits: [],
    recordedConversations: [],
    routes: new Map([["route.local-first", { id: "route.local-first" }]]),
    writes: [],
    appendOperations: [],
    authorize(authorization, requiredScope) {
      this.authorizationCalls.push({ authorization, requiredScope });
      return { grant_ref: "grant.test" };
    },
    compileEphemeralMcpIntegrations() {
      return {
        evidence_refs: ["mcp.ephemeral"],
        server_ids: ["mcp.server"],
        tool_receipt_ids: ["receipt.tool"],
      };
    },
    conversationState(responseId) {
      return this.agentgresConversationRecords.get(responseId);
    },
    driverForProvider() {
      return this.driver;
    },
    async ensureLoaded(endpoint) {
      this.loadedEndpointId = endpoint.id;
      return {
        id: "instance.local",
        backend_id: "backend.local",
      };
    },
    invokeModel(args) {
      this.fallbackInvocationArgs = args;
      return { fallback: true, args };
    },
    nextResponseId(requested) {
      return requested ?? "resp.generated";
    },
    now() {
      this.nowMs += 25;
      return { getTime: () => this.nowMs };
    },
    agentgresModelMountingHead() {
      const sequence = this.receipts.length;
      return {
        sequence,
        head_ref: `agentgres://model-mounting/accepted-receipts/head/${sequence}`,
        state_root: `sha256:state-${sequence}`,
        projection_watermark: `model-mounting-accepted-receipts:${sequence}`,
      };
    },
    nextReceiptId(kind) {
      this.receiptIdCounter += 1;
      return `receipt.${this.receiptIdCounter}.${kind}`;
    },
    planModelMountInvocationAuthority(request) {
      this.authorityPlanRequests.push(request);
      const base = {
        schema_version: "ioi.model_mount.invocation_authority_plan.v1",
        source: "rust_daemon_core.model_mount.invocation_authority",
        rust_core_boundary: "model_mount.invocation_authority",
        operation: request.operation,
        evidence_refs: [
          "rust_daemon_core_model_mount_invocation_authority",
          "model_mount_invocation_contract_js_authoring_retired",
          "agentgres_model_invocation_truth_required",
          `rust_model_mount_invocation_authority_${request.operation}`,
        ],
      };
      const ephemeralMcp = {
        toolReceiptIds: request.ephemeral_mcp?.tool_receipt_ids ?? [],
        serverIds: request.ephemeral_mcp?.server_ids ?? [],
        evidenceRefs: request.ephemeral_mcp?.evidence_refs ?? [],
      };
      const hash = (value) => `hash:${value}`;
      if (request.operation === "provider_execution") {
        return {
          ...base,
          provider_execution_request: testRustPlanProviderExecutionContract({
            body: request.body,
            capability: request.capability,
            ephemeralMcp,
            hash,
            input: request.input,
            instance: request.instance,
            kind: request.kind,
            previousResponseId: request.previous_response_id,
            providerBody: request.body,
            responseId: request.response_id,
            routeReceipt: request.route_receipt,
            selection: request.selection,
            streamStatus: request.stream ? "started" : null,
            token: request.token,
          }),
        };
      }
      if (request.operation === "provider_invocation" || request.operation === "provider_stream_invocation") {
        return {
          ...base,
          provider_invocation_request: testRustPlanProviderInvocationContract({
            input: request.input,
            instance: request.instance,
            kind: request.kind,
            providerExecutionAdmission: request.provider_execution_admission,
            selection: request.selection,
            stream: request.operation === "provider_stream_invocation",
          }),
        };
      }
      if (request.operation === "provider_result_admission") {
        return {
          ...base,
          provider_result_admission_request: testRustPlanProviderResultAdmissionContract({
            kind: request.kind,
            providerExecutionAdmission: request.provider_execution_admission,
            providerResult: request.provider_result,
            selection: request.selection,
          }),
        };
      }
      if (request.operation === "invocation_admission") {
        const providerResult = request.provider_result ?? {};
        const providerResultAdmission = request.provider_result_admission ?? {};
        const backendId = providerResult.backend_id ?? request.instance?.backend_id ?? request.selection?.endpoint?.backend_id ?? null;
        const receiptDetails = withTestProviderExecutionAdmission({
          route_id: request.selection.route.id,
          route_receipt_id: request.route_receipt.id,
          selected_model: request.selection.endpoint.model_id,
          endpoint_id: request.selection.endpoint.id,
          provider_id: request.selection.provider.id,
          instance_id: request.instance.id,
          backend: providerResult.execution_backend ?? request.selection.endpoint.api_format,
          backend_id: backendId,
          selected_backend: backendId,
          policy_hash: hash(request.body.model_policy ?? {}),
          required_scope: request.required_scope ?? null,
          grant_id: request.token?.grant_ref ?? null,
          token_count: providerResult.token_count,
          latency_ms: request.latency_ms,
          input_hash: hash(request.input),
          output_hash: hash(providerResult.output_text ?? ""),
          provider_response_kind: providerResult.provider_response_kind ?? null,
          backend_process: request.instance.backend_process ?? null,
          backend_process_id: request.instance.backend_process_id ?? null,
          backend_process_pid_hash: request.instance.backend_process_pid_hash ?? null,
          backend_evidence_refs: providerResult.backend_evidence_refs ?? [],
          provider_auth_evidence_refs: providerResult.provider_auth_evidence_refs ?? [],
          provider_auth_header_names: [],
          model_mount_route_decision_ref: request.route_receipt.details.model_mount_route_decision_ref,
          model_mount_provider_result_admission_schema_version:
            providerResult.model_mount_provider_result_admission_schema_version ?? "ioi.model_mount.provider_result.v1",
          model_mount_provider_result_admission_ref: providerResultAdmission.provider_result_ref ?? null,
          model_mount_provider_result_admission_hash: providerResultAdmission.provider_result_hash ?? null,
          model_mount_provider_result_admission_source: providerResultAdmission.source ?? null,
          model_mount_provider_result_admission_backend: providerResultAdmission.backend ?? null,
          model_mount_provider_result_admission_receipt_refs: providerResultAdmission.receipt_refs ?? [],
          model_mount_provider_result_admission_evidence_refs: providerResultAdmission.evidence_refs ?? [],
          model_mount_provider_result_admission: providerResultAdmission.record ?? null,
          tool_receipt_ids: ephemeralMcp.toolReceiptIds,
          ephemeral_mcp_server_ids: ephemeralMcp.serverIds,
          response_id: request.response_id,
          previous_response_id: request.previous_response_id,
          continuation: request.continuation,
          invocation_kind: request.stream ? "model_mount.invocation.stream_start" : "model_mount.invocation.invoke",
          stream_status: request.stream ? "started" : null,
          stream_source: request.stream ? "provider_native" : null,
          send_options: request.body.send_options ?? null,
          memory: request.body.memory ?? request.body.send_options?.memory ?? null,
        }, request.provider_execution_admission);
        return {
          ...base,
          receipt_details: receiptDetails,
          invocation_admission_request: testRustPlanInvocationAdmissionContract({
            body: request.body,
            capability: request.capability,
            kind: request.kind,
            receiptDetails,
            receiptId: request.receipt_id,
            receiptKind: request.receipt_kind,
            routeReceipt: request.route_receipt,
            selection: request.selection,
            streamStatus: request.stream ? "started" : null,
          }),
        };
      }
      if (request.operation === "accepted_receipt_transition") {
        return {
          ...base,
          accepted_receipt_transition_request: {
            schema_version: "ioi.model_mount.accepted_receipt_transition.v1",
            current_sequence: request.current_head.sequence,
            current_head_ref: request.current_head.head_ref,
            current_state_root: request.current_head.state_root,
            receipt_id: request.receipt_id,
            receipt_kind: request.receipt_kind,
            route_decision_ref: request.invocation_admission_request.route_decision_ref,
            invocation_admission_ref: request.invocation_admission.invocation_admission_ref,
            invocation_admission_hash: request.invocation_admission.invocation_admission_hash,
            input_hash: request.invocation_admission_request.input_hash,
            output_hash: request.invocation_admission_request.output_hash,
          },
        };
      }
      if (request.operation === "receipt_binding") {
        return {
          ...base,
          receipt_binding_request: testRustPlanReceiptBindingContract({
            admission: request.invocation_admission,
            admissionRequest: request.invocation_admission_request,
            agentgresTransition: request.agentgres_transition,
            receiptDetails: request.receipt_details,
            receiptId: request.receipt_id,
          }),
        };
      }
      throw new Error(`unexpected authority operation ${request.operation}`);
    },
    admitModelMountInvocation(request) {
      return {
        source: "rust_model_mount_mock",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          invocation_admission_ref: `model_mount://invocation_admission/${this.receiptIdCounter}`,
          invocation_admission_hash: `sha256:invocation-${this.receiptIdCounter}`,
        },
        invocation_admission_ref: `model_mount://invocation_admission/${this.receiptIdCounter}`,
        invocation_admission_hash: `sha256:invocation-${this.receiptIdCounter}`,
        receipt_refs: request.receipt_refs,
        evidence_refs: ["rust_model_mount_core", `model_mount://invocation_admission/${this.receiptIdCounter}`],
      };
    },
    admitModelMountProviderExecution(request) {
      this.providerExecutionRequests.push(request);
      return {
        source: "rust_model_mount_provider_execution_command",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          provider_execution_ref: `model_mount://provider_execution/${this.providerExecutionRequests.length}`,
          provider_execution_hash: `sha256:provider-execution-${this.providerExecutionRequests.length}`,
        },
        provider_execution_ref: `model_mount://provider_execution/${this.providerExecutionRequests.length}`,
        provider_execution_hash: `sha256:provider-execution-${this.providerExecutionRequests.length}`,
        receipt_refs: request.receipt_refs,
        evidence_refs: [
          "rust_model_mount_core",
          `model_mount://provider_execution/${this.providerExecutionRequests.length}`,
        ],
      };
    },
    admitModelMountProviderResult(request) {
      this.providerResultRequests.push(request);
      return {
        source: "rust_model_mount_provider_result_command",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          provider_result_ref: `model_mount://provider_result/${this.providerResultRequests.length}`,
          provider_result_hash: `sha256:provider-result-${this.providerResultRequests.length}`,
        },
        provider_result_ref: `model_mount://provider_result/${this.providerResultRequests.length}`,
        provider_result_hash: `sha256:provider-result-${this.providerResultRequests.length}`,
        receipt_refs: request.receipt_refs,
        evidence_refs: [
          "rust_model_mount_provider_result_admission",
          `model_mount://provider_result/${this.providerResultRequests.length}`,
        ],
      };
    },
    executeModelMountProviderInvocation(request) {
      this.providerInvocationRequests.push(request);
      return providerInvocationBridgeResult(request, {
        invocationHash: `sha256:provider-invocation-${this.providerInvocationRequests.length}`,
      });
    },
    executeModelMountProviderStreamInvocation(request) {
      this.providerStreamInvocationRequests.push(request);
      return providerStreamInvocationBridgeResult(request, {
        invocationHash: `sha256:provider-stream-invocation-${this.providerStreamInvocationRequests.length}`,
      });
    },
    planModelMountAcceptedReceiptTransition(request) {
      this.transitionRequests.push(request);
      const nextSequence = request.current_sequence + 1;
      const operationId = `op_${String(nextSequence).padStart(8, "0")}_${request.receipt_kind.replace(/[^a-z0-9]+/gi, "_")}`;
      return {
        source: "rust_daemon_core.model_mount.accepted_receipt_transition",
        transition: {
          schema_version: "ioi.model_mount.accepted_receipt_transition.v1",
          operation_id: operationId,
          operation_ref: `agentgres://model-mounting/accepted-receipts/${operationId}`,
          expected_heads: [request.current_head_ref],
          state_root_before: request.current_state_root,
          state_root_after: `sha256:state-${nextSequence}`,
          resulting_head: `agentgres://model-mounting/accepted-receipts/head/${nextSequence}`,
          projection_watermark: `model-mounting-accepted-receipts:${nextSequence}`,
          transition_hash: `sha256:transition-${nextSequence}`,
          evidence_refs: ["rust_model_mount_accepted_receipt_transition"],
        },
        operation_id: operationId,
        operation_ref: `agentgres://model-mounting/accepted-receipts/${operationId}`,
        expected_heads: [request.current_head_ref],
        state_root_before: request.current_state_root,
        state_root_after: `sha256:state-${nextSequence}`,
        resulting_head: `agentgres://model-mounting/accepted-receipts/head/${nextSequence}`,
        projection_watermark: `model-mounting-accepted-receipts:${nextSequence}`,
        transition_hash: `sha256:transition-${nextSequence}`,
        evidence_refs: ["rust_model_mount_accepted_receipt_transition"],
      };
    },
    bindModelMountInvocationReceipt(request) {
      this.receiptBindingRequests.push(request);
      return {
        source: "rust_daemon_core.model_mount.invocation_receipt_binding",
        invocation: request.invocation,
        result: request.result,
        router_admission: {
          schema_version: "ioi.step_module_router_admission.v1",
          invocation_id: request.invocation.invocation_id,
          backend: "model_mount",
          authoritative_transition: true,
        },
        receipt_binding: {
          schema_version: "ioi.step_module_receipt_binding.v1",
          invocation_id: request.invocation.invocation_id,
          receipt_refs: request.result.receipt_refs,
          binding_hash: `sha256:binding-${this.receiptIdCounter}`,
        },
        accepted_receipt_append: {
          schema_version: "ioi.accepted_receipt_append.v1",
          receipt_ref: request.receiptRef,
          invocation_id: request.invocation.invocation_id,
          receipt_binding_ref: `sha256:binding-${this.receiptIdCounter}`,
          append_hash: `sha256:append-${this.receiptIdCounter}`,
        },
        agentgres_admission: {
          schema_version: "ioi.agentgres_admission.v1",
          operation_ref: request.result.agentgres_operation_refs[0],
          expected_heads: request.acceptedReceiptTransition?.expected_heads ?? [],
          state_root_before: request.invocation.input.state_root_before,
          state_root_after: request.result.state_root_after,
          resulting_head: request.result.resulting_head,
          admission_hash: `sha256:agentgres-${this.receiptIdCounter}`,
        },
        projection_record: {
          schema_version: "ioi.step_module_projection.v1",
          component_kind: "ModelInvocationNode",
        },
        receipt_refs: request.result.receipt_refs,
        evidence_refs: ["rust_receipt_binder_core", `sha256:binding-${this.receiptIdCounter}`],
      };
    },
    receipt(kind, payload) {
      const receipt = { id: payload.id ?? `receipt.${this.receipts.length + 1}.${kind}`, kind, ...payload };
      this.receipts.push(receipt);
      return receipt;
    },
    recordConversationState(payload) {
      this.recordedConversations.push(payload);
      return { id: payload.responseId, payload };
    },
    routeSelectionReceipt(selection, payload) {
      this.routeSelectionPayload = { selection, payload };
      return {
        id: "receipt.route",
        kind: "model_route_selection",
        details: {
          model_mount_route_decision_ref: "model_mount://route_decision/test",
          workflow_graph_id: "workflow.graph",
          workflow_node_id: "workflow.node",
        },
      };
    },
    selectRoute(payload) {
      this.selectRoutePayload = payload;
      return selectionWithRouteReceipt(this.routeSelection ?? selection());
    },
    validateContinuationSafety(payload) {
      this.continuationPayload = payload;
      return { mode: "matched" };
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}`,
        content_hash: `sha256:${request.record_id}`,
        admission_hash: `admit:${request.record_id}`,
        commit_hash: `commit:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.record_id}`,
          admission: { admission_hash: `admit:${request.record_id}` },
        },
      };
    },
    persistRustAuthoredReceipt(record) {
      this.receipts.push(record);
      return record;
    },
    appendOperation(kind, payload) {
      this.appendOperations.push({ kind, payload });
    },
    ...overrides,
  };
  state.driver ??= {
    async invoke() {
      return {
        output_text: "provider answer",
        providerResponse: { id: "provider.response" },
        provider_response_kind: "openai.chat",
        token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
      };
    },
  };
  return state;
}

function selection(overrides = {}) {
  const base = {
    route: { id: "route.local-first", fallback: ["endpoint.local"] },
    endpoint: {
      id: "endpoint.local",
      model_id: "model.local",
      provider_id: "provider.local",
      api_format: "openai",
      backend_id: "backend.endpoint",
    },
    provider: {
      id: "provider.local",
      kind: "local_folder",
    },
  };
  return {
    route: { ...base.route, ...(overrides.route ?? {}) },
    endpoint: { ...base.endpoint, ...(overrides.endpoint ?? {}) },
    provider: { ...base.provider, ...(overrides.provider ?? {}) },
  };
}

function selectionWithRouteReceipt(selected = selection()) {
  return {
    ...selected,
    route_decision: {
      route_decision_ref: "model_mount://route_decision/test",
      route_decision_hash: "sha256:route-decision-test",
    },
    route_receipt: {
      id: "receipt.route",
      kind: "model_route_selection",
      details: {
        rust_daemon_core_receipt_author: "ModelMountCore.admit_route_decision",
        model_mount_route_decision_ref: "model_mount://route_decision/test",
        workflow_graph_id: "workflow.graph",
        workflow_node_id: "workflow.node",
      },
      schemaVersion: "ioi.model-mounting.runtime.v1",
    },
  };
}

function deps(overrides = {}) {
  return {
    inputText: () => "user: hello",
    modelInvocationCoalesceKey: () => null,
    optionalString: (value) => (typeof value === "string" && value ? value : null),
    stableHash: (value) => `hash:${value}`,
    supportsResponseState: (kind) => kind === "responses",
    ...overrides,
  };
}

function withTestProviderExecutionAdmission(details, admission) {
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

function providerInvocationBridgeResult(request, options = {}) {
  const nativeLocal = request.execution_backend === "rust_model_mount_native_local";
  const output_text =
    options.output_text ??
    (nativeLocal
      ? `Autopilot native local model response from ${request.model_ref}. input_hash=test`
      : "provider answer");
  const provider_response_kind = nativeLocal ? "rust_model_mount.native_local" : "rust_model_mount.fixture";
  const backend = nativeLocal ? "autopilot.native_local.fixture" : "ioi_fixture";
  const backend_id = nativeLocal ? request.backend_ref ?? "backend.autopilot.native-local.fixture" : "backend.fixture";
  const execution_backend = request.execution_backend ?? "rust_model_mount_fixture";
  const evidenceRefs = [
    "rust_model_mount_provider_invocation",
    request.provider_execution_ref,
    ...(nativeLocal
      ? ["rust_model_mount_native_local_backend", "deterministic_native_local_fixture"]
      : ["rust_model_mount_fixture_backend", "deterministic_fixture"]),
  ];
  const invocationHash = options.invocationHash ?? "sha256:provider-invocation-test";
  const result = {
    source: "rust_model_mount_provider_invocation_command",
    backend: execution_backend,
    result: {
      ...request,
      output_text: output_text,
      token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
      provider_response_kind: provider_response_kind,
      backend,
      backend_id: backend_id,
      execution_backend: execution_backend,
      evidence_refs: evidenceRefs,
      invocation_hash: invocationHash,
    },
    output_text,
    token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
    provider_response: null,
    provider_response_kind,
    execution_backend,
    backend_id,
    provider_execution_ref: request.provider_execution_ref,
    provider_execution_hash: request.provider_execution_hash,
    invocation_hash: invocationHash,
    evidence_refs: evidenceRefs,
    backend_evidence_refs: evidenceRefs,
  };
  if (options.compat_translation) {
    result.compat_translation = options.compat_translation;
  }
  return result;
}

function providerStreamInvocationBridgeResult(request, options = {}) {
  const output_text = options.output_text ?? "rust stream answer";
  const token_count = options.token_count ?? { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 };
  const execution_backend = request.execution_backend ?? "rust_model_mount_native_local_stream";
  const backend_id = request.backend_ref ?? "backend.autopilot.native-local.fixture";
  const streamKind =
    request.invocation_kind === "responses"
      ? "openai_responses_native_local"
      : "openai_chat_completions_native_local";
  const streamChunks =
    options.stream_chunks ?? [
      `{"delta":${JSON.stringify(output_text)},"done":false}\n`,
      `{"delta":"","done":true,"done_reason":"stop","prompt_eval_count":${token_count.prompt_tokens},"eval_count":${token_count.completion_tokens}}\n`,
    ];
  const evidenceRefs = [
    "rust_model_mount_provider_stream_invocation",
    "rust_model_mount_native_local_stream_backend",
    request.provider_execution_ref,
  ];
  const invocationHash = options.invocationHash ?? "sha256:provider-stream-invocation-test";
  const result = {
    source: "rust_model_mount_provider_stream_invocation_command",
    backend: execution_backend,
    result: {
      ...request,
      schema_version: "ioi.model_mount.provider_stream_invocation.v1",
      output_text: output_text,
      token_count: token_count,
      provider_response_kind: "rust_model_mount.native_local.stream",
      backend: "autopilot.native_local.fixture",
      backend_id: backend_id,
      execution_backend: execution_backend,
      stream_format: "ioi_jsonl",
      stream_kind: streamKind,
      stream_chunks: streamChunks,
      evidence_refs: evidenceRefs,
      invocation_hash: invocationHash,
    },
    output_text,
    token_count,
    provider_response: null,
    provider_response_kind: "rust_model_mount.native_local.stream",
    execution_backend,
    backend_id,
    stream_format: "ioi_jsonl",
    stream_kind: streamKind,
    stream_chunks: streamChunks,
    provider_execution_ref: request.provider_execution_ref,
    provider_execution_hash: request.provider_execution_hash,
    invocation_hash: invocationHash,
    evidence_refs: evidenceRefs,
    backend_evidence_refs: evidenceRefs,
  };
  if (options.compat_translation) {
    result.compat_translation = options.compat_translation;
  }
  return result;
}

async function readReadableStreamText(stream) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let text = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return text;
  } finally {
    reader.releaseLock();
  }
}

test("capabilityForInvocationKind maps model APIs to route capabilities", () => {
  assert.equal(capabilityForInvocationKind("embeddings"), "embeddings");
  assert.equal(capabilityForInvocationKind("rerank"), "rerank");
  assert.equal(capabilityForInvocationKind("responses"), "responses");
  assert.equal(capabilityForInvocationKind("chat.completions"), "chat");
});

test("model invocations reject retired camelCase request aliases before authorization", async () => {
  const state = fakeState();
  const body = {
    model: "model.local",
    routeId: "route.local-first",
    modelPolicy: { privacy: "legacy" },
    responseId: "resp.legacy",
    previousResponseId: "resp.previous",
    sendOptions: { memory: { enabled: true } },
  };

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.responses:*",
          kind: "responses",
          body,
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_invocation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "routeId",
        "modelPolicy",
        "responseId",
        "previousResponseId",
        "sendOptions",
      ]);
      assert.equal(Object.hasOwn(error.details, "routeId"), false);
      return true;
    },
  );
  assert.deepEqual(state.authorizationCalls, []);

  await assert.rejects(
    () =>
      startModelStream(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.responses:*",
          kind: "responses",
          body: { model: "model.local", routeId: "route.local-first", stream: true },
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.code, "model_mount_invocation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["routeId"]);
      return true;
    },
  );
  assert.deepEqual(state.authorizationCalls, []);
});

test("model invocations reject retired authority request aliases before authorization", async () => {
  const state = fakeState();
  const body = {
    model: "model.local",
    authorityGrantRefs: ["grant://model-chat"],
    authorityReceiptRefs: ["receipt://wallet/model-chat"],
    custodyRef: "ctee://custody/private-workspace",
    privacyProfile: "private_workspace_ctee",
    nodePlaintextAllowed: true,
  };

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.responses:*",
          kind: "responses",
          body,
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_invocation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "authorityGrantRefs",
        "authorityReceiptRefs",
        "custodyRef",
        "privacyProfile",
        "nodePlaintextAllowed",
      ]);
      assert.equal(Object.hasOwn(error.details, "authorityGrantRefs"), false);
      assert.equal(Object.hasOwn(error.details, "privacyProfile"), false);
      return true;
    },
  );
  assert.deepEqual(state.authorizationCalls, []);
});

test("model invocations reject retired provider vault-ref record aliases before Rust planning", async () => {
  const providerAliasState = fakeState({
    routeSelection: selection({
      endpoint: { api_format: "openai" },
      provider: {
        id: "provider.openai",
        kind: "openai",
        secretRef: "vault://provider.openai/api-key",
      },
    }),
  });

  await assert.rejects(
    () =>
      invokeModel(
        providerAliasState,
        {
          requiredScope: "model.chat:*",
          kind: "responses",
          body: { model: "model.local", response_id: "resp.provider-alias" },
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.code, "model_mount_provider_vault_record_aliases_retired");
      assert.equal(error.details.subject, "provider");
      assert.deepEqual(error.details.retired_aliases, ["secretRef"]);
      assert.deepEqual(error.details.canonical_fields, [
        "secret_ref",
        "auth_vault_ref",
        "api_key_vault_ref",
      ]);
      return true;
    },
  );
  assert.equal(providerAliasState.providerExecutionRequests.length, 0);

  const endpointAliasState = fakeState({
    routeSelection: selection({
      endpoint: {
        api_format: "openai",
        secretRef: "vault://endpoint.openai/api-key",
      },
      provider: {
        id: "provider.openai",
        kind: "openai",
      },
    }),
  });

  await assert.rejects(
    () =>
      invokeModel(
        endpointAliasState,
        {
          requiredScope: "model.chat:*",
          kind: "responses",
          body: { model: "model.local", response_id: "resp.endpoint-alias" },
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.code, "model_mount_provider_vault_record_aliases_retired");
      assert.equal(error.details.subject, "endpoint");
      assert.deepEqual(error.details.retired_aliases, ["secretRef"]);
      return true;
    },
  );
  assert.equal(endpointAliasState.providerExecutionRequests.length, 0);
});

test("invokeModel public facade executes migrated fixture through Rust model_mount core, provider execution, and receipt binding", async () => {
  const state = fakeState();

  const invocation = await invokeModel(
    state,
    {
      authorization: "Bearer token",
      requiredScope: "model.chat:*",
      kind: "responses",
      body: { model: "model.local", response_id: "resp.custom", memory: { enabled: true } },
    },
    deps(),
  );

  assert.equal(invocation.outputText, "provider answer");
  assert.equal(invocation.model, "model.local");
  assert.equal(invocation.receipt.kind, "model_invocation");
  assert.equal(invocation.receipt.schemaVersion, "ioi.model-mounting.runtime.v1");
  assert.ok(invocation.receipt.evidenceRefs.includes("rust_model_mount_core"));
  assert.ok(invocation.receipt.evidenceRefs.includes("model_mount_invocation_positive_rust_path"));
  assert.equal(invocation.receipt.details.required_scope, "model.chat:*");
  assert.equal(
    invocation.receipt.details.rust_daemon_core_receipt_author,
    "daemonCoreModelMountApi.bindModelMountInvocationReceipt",
  );
  assert.equal(
    invocation.receipt.details.model_mount_route_decision_ref,
    "model_mount://route_decision/test",
  );
  assert.equal(
    invocation.receipt.details.model_mount_agentgres_operation_ref,
    "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation",
  );
  assert.equal(invocation.receipt.details.model_mount_provider_execution_ref, "model_mount://provider_execution/1");
  assert.equal(invocation.receipt.details.model_mount_provider_result_admission_ref, "model_mount://provider_result/1");
  assert.equal(invocation.receipt.details.model_mount_invocation_admission_ref, "model_mount://invocation_admission/1");
  assert.equal(invocation.receipt.details.model_mount_step_module_invocation.module_ref.kind, "model_mount");
  assert.equal(
    invocation.receipt.details.model_mount_step_module_result.resulting_head,
    "agentgres://model-mounting/accepted-receipts/head/1",
  );
  assert.deepEqual(state.authorizationCalls, []);
  assert.equal(state.selectRoutePayload.capability, "responses");
  assert.equal(state.routeSelectionPayload, undefined);
  assert.equal(state.loadedEndpointId, "endpoint.local");
  assert.equal(state.providerExecutionRequests.length, 1);
  assert.equal(state.providerInvocationRequests.length, 1);
  assert.equal(state.providerResultRequests.length, 1);
  assert.equal(state.receiptBindingRequests.length, 1);
  assert.equal(state.transitionRequests.length, 1);
  assert.deepEqual(state.authorityPlanRequests.map((request) => request.operation), [
    "provider_execution",
    "provider_invocation",
    "provider_result_admission",
    "invocation_admission",
    "accepted_receipt_transition",
    "receipt_binding",
  ]);
  assert.equal(state.receipts.length, 1);
  assert.deepEqual(state.recordedConversations, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.appendOperations, []);
});

test("startModelStream public facade executes native-local stream through Rust model_mount without JS fallback", async () => {
  const state = fakeState({
    routeSelection: selection({
      route: { id: "route.native-local" },
      endpoint: {
        id: "endpoint.native-local",
        model_id: "model.native",
        provider_id: "provider.native",
        api_format: "ioi_native",
        driver: "native_local",
        backend_id: "backend.native",
      },
      provider: {
        id: "provider.native",
        kind: "ioi_native_local",
        driver: "native_local",
      },
    }),
  });

  const stream = await startModelStream(
    state,
    {
      authorization: "Bearer token",
      requiredScope: "model.responses:*",
      kind: "responses",
      body: { model: "model.native", route_id: "route.native-local", response_id: "resp.stream", stream: true },
    },
    deps(),
  );

  const streamText = await readReadableStreamText(stream.providerStream);
  assert.equal(stream.native, true);
  assert.equal(stream.invocation.outputText, "");
  assert.equal(stream.invocation.model, "model.native");
  assert.equal(stream.invocation.receipt.kind, "model_invocation");
  assert.equal(stream.invocation.receipt.details.stream_status, "started");
  assert.equal(stream.invocation.receipt.details.model_mount_provider_result_admission_ref, "model_mount://provider_result/1");
  assert.equal(stream.providerResult.streamFormat, "ioi_jsonl");
  assert.match(streamText, /done/);
  assert.deepEqual(state.authorizationCalls, []);
  assert.equal(state.selectRoutePayload.routeId, "route.native-local");
  assert.equal(state.routeSelectionPayload, undefined);
  assert.equal(state.providerExecutionRequests.length, 1);
  assert.equal(state.providerStreamInvocationRequests.length, 1);
  assert.equal(state.providerResultRequests.length, 1);
  assert.equal(state.fallbackInvocationArgs, undefined);
  assert.equal(state.receiptBindingRequests.length, 1);
  assert.equal(state.transitionRequests.length, 1);
  assert.deepEqual(state.authorityPlanRequests.map((request) => request.operation), [
    "provider_execution",
    "provider_stream_invocation",
    "provider_result_admission",
    "invocation_admission",
    "accepted_receipt_transition",
    "receipt_binding",
  ]);
  assert.equal(state.receipts.length, 1);
  assert.deepEqual(state.appendOperations, []);
});

test("retired model invocation JS contract helper exports are deleted", () => {
  const retiredExports = [
    "modelMountInvocationAdmissionRequestForReceipt",
    "modelMountProviderExecutionRequestForInvocation",
    "modelMountProviderInvocationRequestForExecution",
    "modelMountProviderStreamInvocationRequestForExecution",
    "modelMountProviderResultAdmissionRequestForExecution",
    "modelMountInvocationReceiptBindingRequestForReceipt",
    "modelMountInvocationAgentgresTransitionForReceipt",
    "modelMountProviderInvocationRequiresRust",
    "modelMountProviderStreamInvocationRequiresRust",
  ];

  for (const exportName of retiredExports) {
    assert.equal(Object.hasOwn(modelInvocationOpsModule, exportName), false, exportName);
  }
});

test("invokeModel fails closed when the Rust invocation authority planner is missing", async () => {
  const state = fakeState({ planModelMountInvocationAuthority: undefined });

  await assert.rejects(
    () =>
      invokeModel(
        state,
        {
          authorization: "Bearer token",
          requiredScope: "model.chat:*",
          kind: "responses",
          body: { model: "model.local", response_id: "resp.custom" },
        },
        deps(),
      ),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_invocation_authority_planner_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.invocation_authority");
      assert.equal(error.details.required_field, "provider_execution_request");
      return true;
    },
  );
  assert.equal(state.providerExecutionRequests.length, 0);
  assert.equal(state.providerInvocationRequests.length, 0);
  assert.equal(state.providerResultRequests.length, 0);
  assert.equal(state.receiptBindingRequests.length, 0);
});
