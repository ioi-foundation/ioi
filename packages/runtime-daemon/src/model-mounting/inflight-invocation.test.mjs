import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

const CAPABILITY_TOKEN_EVIDENCE_REFS = [
  "rust_daemon_core_capability_token_control",
  "wallet_network_capability_token_authority_required",
  "agentgres_capability_token_truth_required",
  "public_capability_token_js_facade_retired",
];

const ROUTE_CONTROL_EVIDENCE_REFS = [
  "model_mount_route_control_rust_owned",
  "rust_daemon_core_route_control_plan",
];

async function withModelState(fn) {
  const state = new ModelMountingState({
    stateDir: mkdtempSync(join(tmpdir(), "ioi-model-state-")),
    cwd: process.cwd(),
    homeDir: process.env.HOME,
    modelMountCore: mockModelMountCore(),
    commitRuntimeModelMountRecordState: mockRuntimeModelMountRecordStateCommit,
    commitRuntimeModelMountReceiptState: mockRuntimeModelMountReceiptStateCommit,
  });
  try {
    return await fn(state);
  } finally {
    state.close();
  }
}

function mockRuntimeModelMountRecordStateCommit(request) {
  return {
    record_id: request.record_id,
    object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
    content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
    admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
    commit_hash: `sha256:commit:${request.operation_kind}:${request.record_id}`,
    written_record: request.record,
    storage_record: {
      object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
      content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
      admission: {
        admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
      },
    },
  };
}

function mockRuntimeModelMountReceiptStateCommit(request) {
  return {
    receipt_id: request.receipt_id,
    object_ref: `agentgres://model-mounting/receipts/${request.receipt_id}`,
    content_hash: `sha256:receipt:${request.receipt_id}`,
    admission_hash: `sha256:admission:receipt:${request.receipt_id}`,
    commit_hash: `sha256:commit:receipt:${request.receipt_id}`,
    written_record: request.receipt,
    storage_record: {
      object_ref: `agentgres://model-mounting/receipts/${request.receipt_id}`,
      content_hash: `sha256:receipt:${request.receipt_id}`,
      admission: {
        admission_hash: `sha256:admission:receipt:${request.receipt_id}`,
      },
    },
  };
}

function mockModelMountCore() {
  const core = {
    providerInvocationCalls: 0,
    planReadProjection(request) {
      return {
        source: "rust_daemon_core.model_mount.read_projection",
        projection_kind: request.projection_kind,
        projection: request.projection_kind === "model_conversation_states"
          ? []
          : {
              schemaVersion: request.schema_version,
              source: "agentgres_model_mounting_projection",
              projectionKind: request.projection_kind,
              generatedAt: request.generated_at,
              watermark: 0,
            },
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
      };
    },
    planProviderControl(request) {
      const body = request.body ?? {};
      const recordId = body.id ?? request.provider_id ?? "provider.test";
      const evidenceRefs = [
        "rust_daemon_core_provider_control",
        "ctee_provider_custody_enforced",
        "agentgres_provider_control_truth_required",
      ];
      return {
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.provider_control",
        record_dir: "model-providers",
        record_id: recordId,
        control_hash: `sha256:provider-control:${recordId}`,
        authority_hash: `sha256:provider-authority:${recordId}`,
        receipt_refs: request.receipt_refs ?? [],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: evidenceRefs,
        record: {
          ...body,
          id: recordId,
          record_id: recordId,
          object: "ioi.model_mount_provider",
          schema_version: request.schema_version,
          plaintext_material_returned: false,
          evidence_refs: evidenceRefs,
          public_response: {
            ...body,
            id: recordId,
            status: body.status ?? "configured",
            private_material_returned: false,
            plaintext_material_persisted: false,
          },
        },
      };
    },
    planArtifactEndpoint(request) {
      const body = request.body ?? {};
      const isEndpoint = request.operation_kind === "model_mount.endpoint.mount";
      const recordId = isEndpoint
        ? body.endpoint_id ?? body.id ?? "endpoint.test"
        : body.model_id ?? body.artifact_id ?? "test-model";
      return {
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.artifact_endpoint",
        record_dir: isEndpoint ? "model-endpoints" : "model-artifacts",
        record_id: recordId,
        control_hash: `sha256:artifact-endpoint:${recordId}`,
        authority_hash: `sha256:artifact-authority:${recordId}`,
        receipt_refs: request.receipt_refs ?? [],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: [
          "public_artifact_endpoint_js_facade_retired",
          "rust_daemon_core_artifact_endpoint",
          "agentgres_artifact_endpoint_truth_required",
        ],
        public_response: {
          ...body,
          id: recordId,
          status: "committed",
        },
        record: {
          ...body,
          id: recordId,
          record_id: recordId,
          schema_version: request.schema_version,
        },
      };
    },
    planCapabilityTokenControl(request) {
      const tokenId = request.token_id ?? "capability_token:test";
      const action = request.operation_kind.split(".").at(-1);
      const recordId = `capability_token_control:${tokenId}:${action}`;
      const token = "ioi_mnt_inflight_test_token";
      const tokenHash = request.token_hash ?? `sha256:${token}`;
      const publicResponse =
        request.operation_kind === "model_mount.capability_token.create"
          ? {
              object: "ioi.model_mount_capability_token",
              status: "issued",
              token_id: tokenId,
              token,
              token_material_returned_once: true,
              token_hash: tokenHash,
              allowed_scopes: request.body?.allowed ?? [],
              denied_scopes: request.body?.denied ?? [],
            }
          : request.operation_kind === "model_mount.capability_token.authorize"
            ? {
                object: "ioi.model_mount_capability_token_authorization",
                status: "authorized",
                token_id: tokenId,
                required_scope: request.required_scope,
              }
            : {
                object: "ioi.model_mount_capability_token_list",
                status: "projected",
                tokens: [{ token_id: tokenId, status: "active" }],
              };
      return {
        schema_version: "ioi.model_mount.capability_token_control_plan.v1",
        object: "ioi.model_mount_capability_token_control_plan",
        status: "planned",
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.capability_token",
        record_dir: "capability-tokens",
        record_id: recordId,
        control_hash: `sha256:capability-token-control:${action}`,
        authority_hash: `sha256:capability-token-authority:${action}`,
        receipt_refs: [`receipt://model_mount/capability_token/${recordId}`],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: CAPABILITY_TOKEN_EVIDENCE_REFS,
        public_response: publicResponse,
        record: {
          id: recordId,
          record_id: recordId,
          object: "ioi.model_mount_capability_token_control",
          status: "planned",
          operation_kind: request.operation_kind,
          token_id: tokenId,
          token_hash: tokenHash,
          rust_core_boundary: "model_mount.capability_token",
          wallet_authority_boundary: "wallet.network.capability_token",
          capability_token_authority: {
            authority_hash: `sha256:capability-token-authority:${action}`,
            required_scope: request.required_scope ?? null,
            authority_grant_refs: request.authority_grant_refs ?? [],
            authority_receipt_refs: request.authority_receipt_refs ?? [],
          },
          receipt_refs: [`receipt://model_mount/capability_token/${recordId}`],
          evidence_refs: CAPABILITY_TOKEN_EVIDENCE_REFS,
          public_response: {
            ...publicResponse,
            plaintext_material_persisted: false,
          },
        },
      };
    },
    planRouteControl(request) {
      const routeId = request.route_id ?? request.body?.route_id ?? "route.local-first";
      const rawEndpoint = request.endpoints?.[0] ?? {};
      const endpoint = {
        id: rawEndpoint.id ?? "endpoint.test",
        provider_id: rawEndpoint.provider_id ?? "provider.test",
        model_id: rawEndpoint.model_id ?? request.body?.model ?? request.body?.model_id ?? "test-model",
        api_format: rawEndpoint.api_format ?? "ioi_fixture",
        driver: rawEndpoint.driver ?? "fixture",
        backend_id: rawEndpoint.backend_id ?? "backend.test",
        status: rawEndpoint.status ?? "mounted",
      };
      const rawProvider = request.providers?.[0] ?? {};
      const provider = {
        id: rawProvider.id ?? endpoint.provider_id ?? "provider.test",
        driver: rawProvider.driver ?? endpoint.driver ?? "fixture",
        kind: rawProvider.kind ?? "local_folder",
        api_format: rawProvider.api_format ?? endpoint.api_format ?? "ioi_fixture",
        status: rawProvider.status ?? "configured",
      };
      const modelId = endpoint.model_id ?? "test-model";
      const recordId = `route_selection:${routeId}:test`;
      const routeDecisionRef = `model_mount://route_decision/${routeId}`;
      const record = {
        id: recordId,
        record_id: recordId,
        object: "ioi.model_mount_route_selection",
        route_id: routeId,
        selected_model: modelId,
        endpoint_id: endpoint.id,
        provider_id: provider.id,
        receipt_refs: ["receipt://route-control/select"],
        evidence_refs: ROUTE_CONTROL_EVIDENCE_REFS,
        route: request.current_route ?? { id: routeId },
        endpoint,
        provider,
        route_decision: {
          route_decision_ref: routeDecisionRef,
          route_ref: routeId,
          endpoint_ref: endpoint.id,
          provider_ref: provider.id,
          model_ref: modelId,
        },
        accepted_receipt_record: {
          id: "receipt.route-selection",
          kind: "model_route_selection",
          schemaVersion: "ioi.model_mount.receipt.v1",
          createdAt: request.generated_at ?? "2026-06-14T00:00:00.000Z",
          evidenceRefs: ["rust_model_mount_core", ...ROUTE_CONTROL_EVIDENCE_REFS],
          details: {
            rust_daemon_core_receipt_author: true,
            model_mount_route_decision_ref: routeDecisionRef,
            route_id: routeId,
            endpoint_id: endpoint.id,
            provider_id: provider.id,
            selected_model: modelId,
          },
        },
      };
      return {
        source: "rust_daemon_core.model_mount.route_control",
        schema_version: "ioi.model_mount.route_control_plan.v1",
        object: "ioi.model_mount_route_control_plan",
        status: "planned",
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.route_control",
        record_dir: "model-route-selections",
        record_id: recordId,
        record,
        receipt_refs: record.receipt_refs,
        evidence_refs: ROUTE_CONTROL_EVIDENCE_REFS,
        control_hash: `sha256:route-control:${routeId}`,
      };
    },
    admitRouteDecision(request) {
      return {
        source: "rust_model_mount_mock",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          route_decision_ref: "model_mount://route_decision/test",
          route_decision_hash: "sha256:test",
        },
        route_decision_ref: "model_mount://route_decision/test",
        route_decision_hash: "sha256:test",
        receipt_refs: request.receipt_refs,
        evidence_refs: ["rust_model_mount_core", "model_mount://route_decision/test"],
      };
    },
    admitInvocation(request) {
      return {
        source: "rust_model_mount_mock",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          invocation_admission_ref: "model_mount://invocation_admission/test",
          invocation_admission_hash: "sha256:invocation-test",
        },
        invocation_admission_ref: "model_mount://invocation_admission/test",
        invocation_admission_hash: "sha256:invocation-test",
        receipt_refs: request.receipt_refs,
        evidence_refs: ["rust_model_mount_core", "model_mount://invocation_admission/test"],
      };
    },
    admitProviderExecution(request) {
      return {
        source: "rust_model_mount_provider_execution_command",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          provider_execution_ref: "model_mount://provider_execution/test",
          provider_execution_hash: "sha256:provider-execution-test",
        },
        provider_execution_ref: "model_mount://provider_execution/test",
        provider_execution_hash: "sha256:provider-execution-test",
        receipt_refs: request.receipt_refs,
        evidence_refs: ["rust_model_mount_core", "model_mount://provider_execution/test"],
      };
    },
    executeProviderInvocation(request) {
      core.providerInvocationCalls += 1;
      return {
        source: "rust_model_mount_provider_invocation_command",
        backend: "rust_model_mount_fixture",
        result: {
          ...request,
          output_text: "provider answer",
          token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
          provider_response_kind: "rust_model_mount.fixture",
          backend: "ioi_fixture",
          backend_id: "backend.fixture",
          execution_backend: "rust_model_mount_fixture",
          evidence_refs: ["rust_model_mount_provider_invocation", request.provider_execution_ref],
          invocation_hash: "sha256:provider-invocation-test",
        },
        output_text: "provider answer",
        token_count: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
        provider_response: null,
        provider_response_kind: "rust_model_mount.fixture",
        execution_backend: "rust_model_mount_fixture",
        backend_id: "backend.fixture",
        provider_execution_ref: request.provider_execution_ref,
        provider_execution_hash: request.provider_execution_hash,
        invocation_hash: "sha256:provider-invocation-test",
        evidence_refs: ["rust_model_mount_provider_invocation", request.provider_execution_ref],
        backend_evidence_refs: ["rust_model_mount_provider_invocation", request.provider_execution_ref],
      };
    },
    planAcceptedReceiptHead(request) {
      return {
        source: "rust_daemon_core.model_mount.accepted_receipt_head",
        sequence: request.sequence,
        head_ref: `agentgres://model-mounting/accepted-receipts/head/${request.sequence}`,
        state_root: `sha256:state-${request.sequence}`,
        projection_watermark: `model-mounting-accepted-receipts:${request.sequence}`,
        head_hash: `sha256:head-${request.sequence}`,
        evidence_refs: ["rust_model_mount_accepted_receipt_head"],
      };
    },
    planAcceptedReceiptTransition(request) {
      const nextSequence = request.current_sequence + 1;
      const operationId = `op_${String(nextSequence).padStart(8, "0")}_${request.receipt_kind.replace(/[^a-z0-9]+/gi, "_")}`;
      return {
        source: "rust_daemon_core.model_mount.accepted_receipt_transition",
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
    planProviderLifecycle(request) {
      return {
        source: "rust_model_mount_provider_lifecycle_command",
        backend: "rust_model_mount_native_local_lifecycle",
        result: {
          ...request,
          status: request.action === "load" ? "loaded" : "unloaded",
          backend: "autopilot.native_local.fixture",
          backend_id: "backend.autopilot.native-local.fixture",
          driver: "native_local",
          lifecycle_hash: "sha256:provider-lifecycle-test",
          evidence_refs: ["rust_model_mount_provider_lifecycle"],
        },
        status: request.action === "load" ? "loaded" : "unloaded",
        backendId: "backend.autopilot.native-local.fixture",
        providerBackend: "autopilot.native_local.fixture",
        driver: "native_local",
        executionBackend: "rust_model_mount_native_local_lifecycle",
        lifecycle_hash: "sha256:provider-lifecycle-test",
        evidence_refs: ["rust_model_mount_provider_lifecycle"],
        backendEvidenceRefs: ["rust_model_mount_provider_lifecycle"],
      };
    },
    admitProviderResult(request) {
      return {
        source: "rust_model_mount_provider_result_command",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          provider_result_ref: "model_mount://provider_result/test",
          provider_result_hash: "sha256:provider-result-test",
        },
        provider_result_ref: "model_mount://provider_result/test",
        provider_result_hash: "sha256:provider-result-test",
        receipt_refs: request.receipt_refs,
        evidence_refs: ["rust_model_mount_provider_result_admission", "model_mount://provider_result/test"],
      };
    },
    bindInvocationReceipt(request) {
      return {
        source: "rust_daemon_core.model_mount.invocation_receipt_binding",
        invocation: request.invocation,
        result: request.result,
        router_admission: {
          schema_version: "ioi.step_module_router_admission.v1",
          backend: "model_mount",
          authoritative_transition: true,
        },
        receipt_binding: {
          schema_version: "ioi.step_module_receipt_binding.v1",
          binding_hash: "sha256:binding-test",
          receipt_refs: request.result.receipt_refs,
        },
        accepted_receipt_append: {
          schema_version: "ioi.accepted_receipt_append.v1",
          append_hash: "sha256:append-test",
          receipt_ref: request.receiptRef,
        },
        agentgres_admission: request.result.agentgres_operation_refs?.length
          ? {
              schema_version: "ioi.agentgres_admission.v1",
              operation_ref: request.result.agentgres_operation_refs[0],
              expected_heads: request.expectedHeads,
              state_root_before: request.invocation.input.state_root_before,
              state_root_after: request.result.state_root_after,
              resulting_head: request.result.resulting_head,
              admission_hash: "sha256:agentgres-test",
            }
          : null,
        projection_record: {
          schema_version: "ioi.step_module_projection.v1",
          component_kind: "ModelInvocationNode",
        },
        receipt_refs: request.result.receipt_refs,
        evidence_refs: ["rust_receipt_binder_core", "sha256:binding-test"],
      };
    },
  };
  return core;
}

function mountTestModel(state) {
  state.upsertProvider({
    id: "provider.test",
    kind: "local_folder",
    label: "test",
    driver: "fixture",
    api_format: "ioi_fixture",
    base_url: "http://127.0.0.1:1",
    capabilities: ["chat"],
    status: "configured",
  });
  state.importModel({ model_id: "test-model", provider_id: "provider.test" });
  state.mountEndpoint({
    id: "endpoint.test",
    model_id: "test-model",
    provider_id: "provider.test",
    driver: "fixture",
    api_format: "ioi_fixture",
    backend_id: "backend.fixture",
  });
}

test("identical low-variance chat invocations stay on the Rust provider path without JS coalescing", async () => {
  await withModelState(async (state) => {
    mountTestModel(state);
    state.ensureLoaded = async (endpoint) => ({
      id: "instance.test",
      endpoint_id: endpoint.id,
      backend_id: "backend.test",
    });
    const token = state.createToken({
      allowed: ["model.chat:*", "route.use:*"],
      denied: [],
    }).token;
    const body = {
      model: "test-model",
      route_id: "route.local-first",
      messages: [{ role: "user", content: "choose the next action" }],
      temperature: 0.1,
    };

    const [first, second] = await Promise.all([
      state.invokeModel({
        authorization: `Bearer ${token}`,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body,
      }),
      state.invokeModel({
        authorization: `Bearer ${token}`,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body,
      }),
    ]);

    assert.equal(Object.hasOwn(state, "inflightModelInvocations"), false);
    assert.equal(state.modelMountCore.providerInvocationCalls, 2);
    assert.equal(first.outputText, "provider answer");
    assert.equal(second.outputText, "provider answer");
    assert.equal(first.receipt.kind, "model_invocation");
    assert.equal(second.receipt.kind, "model_invocation");
    assert.equal(second.receipt.details.coalesced, undefined);
  });
});

test("high-variance chat invocations are not coalesced", async () => {
  await withModelState(async (state) => {
    mountTestModel(state);
    state.ensureLoaded = async (endpoint) => ({
      id: "instance.test",
      endpoint_id: endpoint.id,
      backend_id: "backend.test",
    });
    const token = state.createToken({
      allowed: ["model.chat:*", "route.use:*"],
      denied: [],
    }).token;
    const body = {
      model: "test-model",
      route_id: "route.local-first",
      messages: [{ role: "user", content: "draft a creative variation" }],
      temperature: 0.8,
    };

    const [first, second] = await Promise.all([
      state.invokeModel({
        authorization: `Bearer ${token}`,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body,
      }),
      state.invokeModel({
        authorization: `Bearer ${token}`,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body,
      }),
    ]);

    assert.equal(state.modelMountCore.providerInvocationCalls, 2);
    assert.equal(first.receipt.kind, "model_invocation");
    assert.equal(second.receipt.kind, "model_invocation");
  });
});
