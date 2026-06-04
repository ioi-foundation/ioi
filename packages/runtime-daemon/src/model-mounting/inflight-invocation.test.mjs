import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

async function withModelState(fn) {
  const state = new ModelMountingState({
    stateDir: mkdtempSync(join(tmpdir(), "ioi-model-state-")),
    cwd: process.cwd(),
    homeDir: process.env.HOME,
    modelMountAdmissionRunner: mockModelMountAdmissionRunner(),
  });
  try {
    return await fn(state);
  } finally {
    state.close();
  }
}

function mockModelMountAdmissionRunner() {
  return {
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
        outputText: "provider answer",
        tokenCount: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
        providerResponse: null,
        providerResponseKind: "rust_model_mount.fixture",
        executionBackend: "rust_model_mount_fixture",
        backendId: "backend.fixture",
        provider_execution_ref: request.provider_execution_ref,
        provider_execution_hash: request.provider_execution_hash,
        invocation_hash: "sha256:provider-invocation-test",
        evidence_refs: ["rust_model_mount_provider_invocation", request.provider_execution_ref],
        backendEvidenceRefs: ["rust_model_mount_provider_invocation", request.provider_execution_ref],
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
        source: "rust_model_mount_receipt_binding_command",
        backend: "rust_model_mount_live",
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
}

function mountTestModel(state) {
  state.upsertProvider({
    id: "provider.test",
    kind: "openai_compatible",
    label: "test",
    driver: "openai_compatible",
    api_format: "openai",
    base_url: "http://127.0.0.1:1",
    capabilities: ["chat"],
    status: "configured",
  });
  state.importModel({ model_id: "test-model", provider_id: "provider.test" });
  state.mountEndpoint({
    id: "endpoint.test",
    model_id: "test-model",
    provider_id: "provider.test",
  });
}

test("identical low-variance in-flight chat invocations share one provider call", async () => {
  await withModelState(async (state) => {
    mountTestModel(state);
    state.ensureLoaded = async (endpoint) => ({
      id: "instance.test",
      endpointId: endpoint.id,
      backendId: "backend.test",
    });
    let providerCalls = 0;
    state.driverForProvider = () => ({
      invoke: async () => {
        providerCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 50));
        return {
          outputText: "ok",
          tokenCount: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
          providerResponseKind: null,
        };
      },
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

    assert.equal(providerCalls, 1);
    assert.equal(first.outputText, "ok");
    assert.equal(second.outputText, "ok");
    assert.equal(first.receipt.kind, "model_invocation");
    assert.equal(second.receipt.kind, "model_invocation_coalesced");
    assert.equal(second.receipt.details.coalesced, true);
  });
});

test("high-variance chat invocations are not coalesced", async () => {
  await withModelState(async (state) => {
    mountTestModel(state);
    state.ensureLoaded = async (endpoint) => ({
      id: "instance.test",
      endpointId: endpoint.id,
      backendId: "backend.test",
    });
    let providerCalls = 0;
    state.driverForProvider = () => ({
      invoke: async () => {
        providerCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 50));
        return {
          outputText: `ok ${providerCalls}`,
          tokenCount: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
          providerResponseKind: null,
        };
      },
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

    assert.equal(providerCalls, 2);
    assert.equal(first.receipt.kind, "model_invocation");
    assert.equal(second.receipt.kind, "model_invocation");
  });
});
