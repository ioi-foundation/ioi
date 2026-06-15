import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";
import { createModelMountCore } from "./model-mounting/model-mount-core.mjs";

test("daemon-level typed APIs feed migrated daemon-core surfaces", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-daemon-core-direct-"));
  const calls = [];
  const contextLifecycleCalls = [];
  const runtimeControlCalls = [];
  const threadLifecycleCalls = [];
  const workspaceTrustCalls = [];
  const mcpCalls = [];
  const modelMountCalls = [];
  const threadMemoryCalls = [];
  const agentgresCalls = [];
  const approvalCalls = [];
  const governedAdmissionCalls = [];
  const failCommandInvoker = (request) => {
    calls.push(request);
    throw new Error(`generic command invoker must not run migrated typed APIs: ${request?.operation}`);
  };
  const assertModelMountDirectApiCall = (call, method, schemaVersion) => {
    assert.equal(call.method, method);
    assert.equal(call.request.schema_version, schemaVersion);
    assert.equal(Object.hasOwn(call.request, "operation"), false);
    assert.equal(Object.hasOwn(call.request, "backend"), false);
  };
  const daemonCoreModelMountApi = {
    admitModelMountInvocation(request) {
      modelMountCalls.push({ method: "admitModelMountInvocation", request });
      return {
        source: "direct_model_mount_api",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          invocation_admission_ref: "model_mount://invocation_admission/direct",
          invocation_admission_hash: "sha256:direct-invocation",
        },
        invocation_admission_ref: "model_mount://invocation_admission/direct",
        invocation_admission_hash: "sha256:direct-invocation",
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: ["rust_daemon_core_model_mount_invocation"],
      };
    },
    admitModelMountProviderExecution(request) {
      modelMountCalls.push({ method: "admitModelMountProviderExecution", request });
      return {
        source: "direct_model_mount_api",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          provider_execution_ref: "model_mount://provider_execution/direct",
          provider_execution_hash: "sha256:direct-provider-execution",
        },
        provider_execution_ref: "model_mount://provider_execution/direct",
        provider_execution_hash: "sha256:direct-provider-execution",
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: ["rust_daemon_core_model_mount_provider_execution"],
      };
    },
    executeModelMountProviderInvocation(request) {
      modelMountCalls.push({ method: "executeModelMountProviderInvocation", request });
      return {
        source: "direct_model_mount_api",
        backend: request.execution_backend,
        result: {
          ...request,
          output_text: "direct provider invocation",
          token_count: { total_tokens: 1 },
          provider_response_kind: "rust_model_mount.fixture",
          backend_id: request.backend_ref,
          invocation_hash: "sha256:direct-provider-invocation",
          evidence_refs: ["rust_daemon_core_model_mount_provider_invocation"],
        },
        outputText: "direct provider invocation",
        tokenCount: { total_tokens: 1 },
        providerResponseKind: "rust_model_mount.fixture",
        execution_backend: request.execution_backend,
        backendId: request.backend_ref,
        invocation_hash: "sha256:direct-provider-invocation",
        evidence_refs: ["rust_daemon_core_model_mount_provider_invocation"],
      };
    },
    executeModelMountProviderStreamInvocation(request) {
      modelMountCalls.push({ method: "executeModelMountProviderStreamInvocation", request });
      return {
        source: "direct_model_mount_api",
        backend: request.execution_backend,
        result: {
          ...request,
          output_text: "direct provider stream",
          token_count: { total_tokens: 1 },
          provider_response_kind: "rust_model_mount.native_local.stream",
          backend_id: request.backend_ref,
          stream_format: "ioi_jsonl",
          stream_kind: "openai_responses_native_local",
          stream_chunks: ["{\"delta\":\"direct\",\"done\":false}\n", "{\"delta\":\"\",\"done\":true}\n"],
          invocation_hash: "sha256:direct-provider-stream",
          evidence_refs: ["rust_daemon_core_model_mount_provider_stream_invocation"],
        },
        outputText: "direct provider stream",
        tokenCount: { total_tokens: 1 },
        providerResponseKind: "rust_model_mount.native_local.stream",
        execution_backend: request.execution_backend,
        backendId: request.backend_ref,
        streamFormat: "ioi_jsonl",
        streamKind: "openai_responses_native_local",
        streamChunks: ["{\"delta\":\"direct\",\"done\":false}\n", "{\"delta\":\"\",\"done\":true}\n"],
        invocation_hash: "sha256:direct-provider-stream",
        evidence_refs: ["rust_daemon_core_model_mount_provider_stream_invocation"],
      };
    },
    planModelMountProviderLifecycle(request) {
      modelMountCalls.push({ method: "planModelMountProviderLifecycle", request });
      return {
        source: "direct_model_mount_api",
        backend: request.execution_backend,
        result: {
          ...request,
          status: "loaded",
          backend: "autopilot.native_local.fixture",
          backend_id: request.backend_ref,
          lifecycle_hash: "sha256:direct-provider-lifecycle",
          evidence_refs: ["rust_daemon_core_model_mount_provider_lifecycle"],
        },
        status: "loaded",
        backend_id: request.backend_ref,
        provider_backend: "autopilot.native_local.fixture",
        driver: request.driver,
        execution_backend: request.execution_backend,
        lifecycle_hash: "sha256:direct-provider-lifecycle",
        evidence_refs: ["rust_daemon_core_model_mount_provider_lifecycle"],
      };
    },
    planModelMountProviderInventory(request) {
      modelMountCalls.push({ method: "planModelMountProviderInventory", request });
      return {
        source: "direct_model_mount_api",
        backend: request.execution_backend,
        result: {
          ...request,
          status: "listed",
          backend: "autopilot.native_local.fixture",
          backend_id: request.backend_ref,
          item_refs: ["model_instance://native/direct"],
          item_count: 1,
          inventory_hash: "sha256:direct-provider-inventory",
          evidence_refs: ["rust_daemon_core_model_mount_provider_inventory"],
        },
        status: "listed",
        backend_id: request.backend_ref,
        provider_backend: "autopilot.native_local.fixture",
        driver: request.driver,
        execution_backend: request.execution_backend,
        item_refs: ["model_instance://native/direct"],
        item_count: 1,
        inventory_hash: "sha256:direct-provider-inventory",
        evidence_refs: ["rust_daemon_core_model_mount_provider_inventory"],
      };
    },
    planModelMountInstanceLifecycle(request) {
      modelMountCalls.push({ method: "planModelMountInstanceLifecycle", request });
      return {
        source: "direct_model_mount_api",
        backend: request.execution_backend,
        result: {
          ...request,
          status: "loaded",
          backend_id: request.backend_ref,
          instance_lifecycle_hash: "sha256:direct-instance-lifecycle",
          evidence_refs: ["rust_daemon_core_model_mount_instance_lifecycle"],
        },
        status: "loaded",
        backendId: request.backend_ref,
        driver: request.driver,
        execution_backend: request.execution_backend,
        provider_lifecycle_hash: request.provider_lifecycle_hash,
        instance_lifecycle_hash: "sha256:direct-instance-lifecycle",
        evidence_refs: ["rust_daemon_core_model_mount_instance_lifecycle"],
      };
    },
    admitModelMountProviderResult(request) {
      modelMountCalls.push({ method: "admitModelMountProviderResult", request });
      return {
        source: "direct_model_mount_api",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          provider_result_ref: "model_mount://provider_result/direct",
          provider_result_hash: "sha256:direct-provider-result",
        },
        provider_result_ref: "model_mount://provider_result/direct",
        provider_result_hash: "sha256:direct-provider-result",
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: ["rust_daemon_core_model_mount_provider_result"],
      };
    },
    planModelMountBackendProcess(request) {
      modelMountCalls.push({ method: "planModelMountBackendProcess", request });
      return {
        source: "rust_daemon_core.model_mount.backend_process",
        result: {
          ...request,
          supports_supervision: true,
          supervisor_kind: "external_process",
          public_args: ["llama-server", "--model", "artifact:direct"],
          spawn_args: ["--model", "/models/private/model.gguf"],
          spawn_required: true,
          spawn_status: "spawn_ready",
          plan_hash: "sha256:direct-backend-process",
          evidence_refs: ["rust_model_mount_backend_process_plan"],
        },
        supports_supervision: true,
        supervisor_kind: "external_process",
        public_args: ["llama-server", "--model", "artifact:direct"],
        spawn_args: ["--model", "/models/private/model.gguf"],
        spawn_required: true,
        spawn_status: "spawn_ready",
        plan_hash: "sha256:direct-backend-process",
        evidence_refs: ["rust_model_mount_backend_process_plan"],
      };
    },
    planModelMountBackendLifecycle(request) {
      modelMountCalls.push({ method: "planModelMountBackendLifecycle", request });
      const record = {
        id: "backend-lifecycle-control:direct",
        object: "ioi.model_mount_backend_lifecycle_record",
        backend_id: request.backend_id,
        backend_kind: request.backend_kind,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.backend_lifecycle",
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "public_backend_lifecycle_js_facade_retired",
          "rust_daemon_core_backend_lifecycle",
          "agentgres_backend_lifecycle_truth_required",
        ],
      };
      const publicResponse = {
        object: "ioi.model_mount_backend_lifecycle",
        status: "planned",
        backend_id: request.backend_id,
        backend_kind: request.backend_kind,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.backend_lifecycle",
        backend_status: "start_planned",
        js_backend_registry_read: false,
        js_process_control: false,
        js_log_read: false,
        js_log_write: false,
      };
      return {
        source: "rust_daemon_core.model_mount.backend_lifecycle",
        plan: {
          schema_version: "ioi.model_mount.backend_lifecycle_plan.v1",
          object: "ioi.model_mount_backend_lifecycle_plan",
          status: "planned",
          rust_core_boundary: "model_mount.backend_lifecycle",
          operation_kind: request.operation_kind,
          source: request.source,
          record_dir: "model-backend-lifecycle-controls",
          record_id: record.id,
          record,
          public_response: publicResponse,
          receipt_refs: request.receipt_refs ?? [],
          evidence_refs: record.evidence_refs,
          control_hash: "sha256:direct-backend-lifecycle",
        },
        record_dir: "model-backend-lifecycle-controls",
        record_id: record.id,
        record,
        public_response: publicResponse,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.backend_lifecycle",
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        control_hash: "sha256:direct-backend-lifecycle",
      };
    },
    planModelMountRouteControl(request) {
      modelMountCalls.push({ method: "planModelMountRouteControl", request });
      const record = {
        id: request.route_id ?? request.body?.id ?? "route.direct",
        role: request.body?.role ?? "direct",
        fallback: request.body?.fallback ?? [],
        providerEligibility: request.body?.provider_eligibility ?? [],
        receiptRefs: request.receipt_refs ?? [],
      };
      return {
        source: "rust_daemon_core.model_mount.route_control",
        schema_version: "ioi.model_mount.route_control_plan.v1",
        object: "ioi.model_mount_route_control_plan",
        status: "planned",
        rust_core_boundary: "model_mount.route_control",
        operation_kind: request.operation_kind,
        record_dir: "model-routes",
        record_id: record.id,
        record,
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "model_mount_route_control_rust_owned",
          "rust_daemon_core_route_control_plan",
          "agentgres_route_truth_required",
        ],
        control_hash: "sha256:direct-route-control",
      };
    },
    planModelMountTokenizerRequired(request) {
      modelMountCalls.push({ method: "planModelMountTokenizerRequired", request });
      return {
        source: "rust_daemon_core.model_mount.tokenizer_required",
        record: {
          schema_version: "ioi.model_mount.tokenizer_required_result.v1",
          object: "ioi.model_mount_tokenizer_required",
          status: "rust_core_required",
          status_code: 501,
          code: "model_mount_tokenizer_rust_core_required",
          message:
            "Model tokenization and context-fit utilities require direct Rust daemon-core admission and projection.",
          rust_core_boundary: "model_mount.tokenizer",
          operation: request.operation,
          source: request.source,
          details: request.details ?? {},
        },
        status: "rust_core_required",
        status_code: 501,
        code: "model_mount_tokenizer_rust_core_required",
        rust_core_boundary: "model_mount.tokenizer",
        operation: request.operation,
        details: request.details ?? {},
      };
    },
    planModelMountRouteControlRequired(request) {
      modelMountCalls.push({ method: "planModelMountRouteControlRequired", request });
      return {
        source: "rust_daemon_core.model_mount.route_control_required",
        record: {
          schema_version: "ioi.model_mount.route_control_required_result.v1",
          object: "ioi.model_mount_route_control_required",
          status: "rust_core_required",
          status_code: 501,
          code: "model_mount_route_control_rust_core_required",
          message: "Model route control requires Rust daemon-core ownership.",
          rust_core_boundary: "model_mount.route_control",
          operation: request.operation,
          operation_kind: request.operation_kind,
          source: request.source,
          details: request.details ?? {},
        },
        status: "rust_core_required",
        status_code: 501,
        code: "model_mount_route_control_rust_core_required",
        rust_core_boundary: "model_mount.route_control",
        operation: request.operation,
        operation_kind: request.operation_kind,
        details: request.details ?? {},
      };
    },
    planModelMountTokenizer(request) {
      modelMountCalls.push({ method: "planModelMountTokenizer", request });
      const record = {
        id: "model_tokenizer:tokenize:direct",
        object: "ioi.model_mount_tokenizer_result",
        status: "planned",
        operation: request.operation,
        route_id: request.route_selection?.route?.id ?? "route.direct",
        model: request.route_selection?.endpoint?.modelId ?? "model.direct",
        endpoint_id: request.route_selection?.endpoint?.id ?? "endpoint.direct",
        provider_id: request.route_selection?.provider?.id ?? "provider.direct",
        token_count: 2,
        tokens: ["direct", "tokens"],
      };
      return {
        source: "rust_daemon_core.model_mount.tokenizer",
        plan: {
          schema_version: "ioi.model_mount.tokenizer_plan.v1",
          object: "ioi.model_mount_tokenizer_plan",
          status: "planned",
          rust_core_boundary: "model_mount.tokenizer",
          operation: request.operation,
          source: request.source,
          record_dir: "model-tokenizer-utilities",
          record_id: record.id,
          record,
          receipt_refs: request.receipt_refs ?? [],
          evidence_refs: ["model_mount_tokenizer_rust_owned"],
          control_hash: "sha256:direct-tokenizer-control",
        },
        record_dir: "model-tokenizer-utilities",
        record_id: record.id,
        record,
        operation: request.operation,
        rust_core_boundary: "model_mount.tokenizer",
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: ["model_mount_tokenizer_rust_owned"],
        control_hash: "sha256:direct-tokenizer-control",
      };
    },
    planModelMountConversationState(request) {
      modelMountCalls.push({ method: "planModelMountConversationState", request });
      const record = {
        id: request.response_id,
        object: "ioi.model_mount_conversation_state",
        status: request.status,
        kind: request.kind,
        response_id: request.response_id,
        route_id: request.route_ref,
        endpoint_id: request.endpoint_ref,
        provider_id: request.provider_ref,
        selected_model: request.model_ref,
        route_decision_ref: request.route_decision_ref,
        receipt_id: request.invocation_receipt_ref,
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: ["model_mount_conversation_state_rust_owned"],
        rust_core_boundary: "model_mount.conversation",
        conversation_hash: "sha256:direct-conversation-state",
      };
      return {
        source: "rust_daemon_core.model_mount.conversation_state",
        plan: {
          schema_version: "ioi.model_mount.conversation_state_plan.v1",
          object: "ioi.model_mount_conversation_state_plan",
          status: "planned",
          rust_core_boundary: "model_mount.conversation",
          operation: request.operation,
          operation_kind: "model_mount.conversation.state_write",
          source: request.source,
          record_dir: "model-conversations",
          record_id: record.id,
          record,
          receipt_refs: request.receipt_refs ?? [],
          evidence_refs: ["model_mount_conversation_state_rust_owned"],
          conversation_hash: "sha256:direct-conversation-state",
        },
        record_dir: "model-conversations",
        record_id: record.id,
        record,
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: ["model_mount_conversation_state_rust_owned"],
        operation: request.operation,
        operation_kind: "model_mount.conversation.state_write",
        rust_core_boundary: "model_mount.conversation",
        conversation_hash: "sha256:direct-conversation-state",
      };
    },
    planModelMountStreamCompletion(request) {
      modelMountCalls.push({ method: "planModelMountStreamCompletion", request });
      const record = {
        id: request.response_id,
        object: "ioi.model_mount_conversation_state",
        status: "completed",
        response_id: request.response_id,
        stream_receipt_ref: `receipt://${request.receipt_id}`,
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: ["model_mount_stream_completion_rust_owned"],
        rust_core_boundary: "model_mount.conversation",
        conversation_hash: "sha256:direct-stream-conversation",
        stream_completion_hash: "sha256:direct-stream-completion",
      };
      const receipt = {
        id: request.receipt_id,
        kind: "model_invocation_stream_completed",
        evidenceRefs: ["rust_model_mount_core", "model_mount_stream_completion_rust_owned"],
        details: {
          rust_daemon_core_receipt_author: "ModelMountCore.plan_model_mount_stream_completion",
          model_mount_step_module_result: {
            agentgres_operation_refs: ["agentgres://model-mounting/accepted-receipts/op_direct_stream"],
          },
        },
      };
      return {
        source: "rust_daemon_core.model_mount.stream_completion",
        plan: {
          schema_version: "ioi.model_mount.stream_completion_plan.v1",
          object: "ioi.model_mount_stream_completion_plan",
          status: "planned",
          rust_core_boundary: "model_mount.conversation",
          operation: request.operation,
          operation_kind: "model_mount.conversation.stream_completion",
          source: request.source,
          record_dir: "model-conversations",
          record_id: record.id,
          record,
          receipt,
          receipt_refs: request.receipt_refs ?? [],
          evidence_refs: ["model_mount_stream_completion_rust_owned"],
          stream_completion_hash: "sha256:direct-stream-completion",
          conversation_hash: "sha256:direct-stream-conversation",
        },
        record_dir: "model-conversations",
        record_id: record.id,
        record,
        receipt,
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: ["model_mount_stream_completion_rust_owned"],
        operation: request.operation,
        operation_kind: "model_mount.conversation.stream_completion",
        rust_core_boundary: "model_mount.conversation",
        stream_completion_hash: "sha256:direct-stream-completion",
        conversation_hash: "sha256:direct-stream-conversation",
      };
    },
    planModelMountStreamCancel(request) {
      modelMountCalls.push({ method: "planModelMountStreamCancel", request });
      const record = {
        id: request.response_id,
        object: "ioi.model_mount_conversation_state",
        status: "canceled",
        response_id: request.response_id,
        stream_receipt_ref: `receipt://${request.receipt_id}`,
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "model_mount_stream_cancel_rust_owned",
          "agentgres_model_stream_cancel_truth_required",
        ],
        rust_core_boundary: "model_mount.conversation",
        conversation_hash: "sha256:direct-stream-cancel-conversation",
        stream_cancel_hash: "sha256:direct-stream-cancel",
      };
      const receipt = {
        id: request.receipt_id,
        kind: "model_invocation_stream_canceled",
        evidenceRefs: ["rust_model_mount_core", "model_mount_stream_cancel_rust_owned"],
        details: {
          rust_daemon_core_receipt_author: "ModelMountCore.plan_model_mount_stream_cancel",
          model_mount_step_module_result: {
            agentgres_operation_refs: ["agentgres://model-mounting/accepted-receipts/op_direct_cancel"],
          },
        },
      };
      return {
        source: "rust_daemon_core.model_mount.stream_cancel",
        plan: {
          schema_version: "ioi.model_mount.stream_cancel_plan.v1",
          object: "ioi.model_mount_stream_cancel_plan",
          status: "planned",
          rust_core_boundary: "model_mount.conversation",
          operation: request.operation,
          operation_kind: "model_mount.conversation.stream_cancel",
          source: request.source,
          record_dir: "model-conversations",
          record_id: record.id,
          record,
          receipt,
          receipt_refs: request.receipt_refs ?? [],
          evidence_refs: record.evidence_refs,
          stream_cancel_hash: "sha256:direct-stream-cancel",
          conversation_hash: "sha256:direct-stream-cancel-conversation",
        },
        record_dir: "model-conversations",
        record_id: record.id,
        record,
        receipt,
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        operation: request.operation,
        operation_kind: "model_mount.conversation.stream_cancel",
        rust_core_boundary: "model_mount.conversation",
        stream_cancel_hash: "sha256:direct-stream-cancel",
        conversation_hash: "sha256:direct-stream-cancel-conversation",
      };
    },
    planModelMountArtifactEndpoint(request) {
      modelMountCalls.push({ method: "planModelMountArtifactEndpoint", request });
      const record = {
        id: "endpoint.direct",
        object: "ioi.model_mount_endpoint",
        status: "mounted",
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.artifact_endpoint",
        model_id: request.body?.model_id ?? null,
        provider_id: request.body?.provider_id ?? null,
        public_response: {
          object: "ioi.model_mount_endpoint",
          id: "endpoint.direct",
          endpoint_id: "endpoint.direct",
          model_id: request.body?.model_id ?? null,
          provider_id: request.body?.provider_id ?? null,
          status: "mounted",
          plaintext_transport_material_returned: false,
        },
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "public_artifact_endpoint_js_facade_retired",
          "rust_daemon_core_artifact_endpoint",
          "agentgres_artifact_endpoint_truth_required",
        ],
        control_hash: "sha256:direct-artifact-endpoint-control",
        authority_hash: "sha256:direct-artifact-endpoint-authority",
      };
      return {
        source: "direct_model_mount_api",
        schema_version: "ioi.model_mount.artifact_endpoint_plan.v1",
        object: "ioi.model_mount_artifact_endpoint_plan",
        status: "planned",
        rust_core_boundary: "model_mount.artifact_endpoint",
        operation_kind: request.operation_kind,
        record_dir: "model-endpoints",
        record_id: record.id,
        record,
        public_response: record.public_response,
        receipt_refs: request.receipt_refs ?? [],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        control_hash: record.control_hash,
        authority_hash: record.authority_hash,
      };
    },
    planModelMountStorageControl(request) {
      modelMountCalls.push({ method: "planModelMountStorageControl", request });
      const record = {
        id: "download.direct",
        object: "ioi.model_mount_download",
        status: "queued",
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.storage_control",
        details: {
          model_id: request.body?.model_id ?? null,
          network_transfer_executed: false,
        },
        public_response: {
          object: "ioi.model_mount_download",
          id: "download.direct",
          status: "queued",
          record_dir: "model-downloads",
          record_id: "download.direct",
          operation_kind: request.operation_kind,
          rust_core_boundary: "model_mount.storage_control",
          js_network_transfer_executed: false,
          js_filesystem_mutation_executed: false,
        },
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "public_model_storage_js_facade_retired",
          "rust_daemon_core_model_storage",
          "agentgres_model_storage_truth_required",
        ],
        control_hash: "sha256:direct-storage-control",
        authority_hash: "sha256:direct-storage-authority",
      };
      return {
        source: "direct_model_mount_api",
        backend: "rust_model_mount_storage_control",
        plan: {
          schema_version: "ioi.model_mount.storage_control_plan.v1",
          object: "ioi.model_mount_storage_control_plan",
          status: "planned",
          rust_core_boundary: "model_mount.storage_control",
          operation_kind: request.operation_kind,
          source: request.source,
          record_dir: "model-downloads",
          record_id: record.id,
          record,
          public_response: record.public_response,
          receipt_refs: request.receipt_refs ?? [],
          authority_grant_refs: request.authority_grant_refs ?? [],
          authority_receipt_refs: request.authority_receipt_refs ?? [],
          evidence_refs: record.evidence_refs,
          control_hash: "sha256:direct-storage-control",
          authority_hash: "sha256:direct-storage-authority",
        },
        record_dir: "model-downloads",
        record_id: record.id,
        record,
        public_response: record.public_response,
        receipt_refs: request.receipt_refs ?? [],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.storage_control",
        control_hash: "sha256:direct-storage-control",
        authority_hash: "sha256:direct-storage-authority",
      };
    },
    planModelMountMcpWorkflow(request) {
      modelMountCalls.push({ method: "planModelMountMcpWorkflow", request });
      const record = {
        id: "mcp_import.direct",
        object: "ioi.model_mount_mcp_workflow",
        status: "committed",
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.mcp_workflow",
        details: {
          server_ids: ["mcp.direct"],
          js_registry_mutation: false,
        },
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "rust_daemon_core_model_mount_mcp_workflow",
          "agentgres_mcp_workflow_truth_required",
        ],
        workflow_hash: "sha256:direct-mcp-workflow",
        authority_hash: "sha256:direct-mcp-authority",
      };
      return {
        source: "direct_model_mount_api",
        status: "committed",
        rust_core_boundary: "model_mount.mcp_workflow",
        operation_kind: request.operation_kind,
        record_dir: "mcp-servers",
        record_id: record.id,
        record,
        public_response: {
          status: "committed",
          operation_kind: request.operation_kind,
          server_ids: ["mcp.direct"],
        },
        receipt_refs: request.receipt_refs ?? [],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        workflow_hash: record.workflow_hash,
        authority_hash: record.authority_hash,
      };
    },
    planModelMountServerControl(request) {
      modelMountCalls.push({ method: "planModelMountServerControl", request });
      const record = {
        id: "server-control.direct",
        object: "ioi.model_mount_server_control_record",
        status: "planned",
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.server_control",
        public_response: {
          object: "ioi.model_mount_server_control",
          status: "planned",
          operation_kind: request.operation_kind,
          server_status: "start_planned",
          js_transport_execution: false,
        },
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "public_server_control_js_facade_retired",
          "rust_daemon_core_server_control",
          "agentgres_server_control_truth_required",
        ],
        control_hash: "sha256:direct-server-control",
      };
      return {
        source: "direct_model_mount_api",
        status: "planned",
        rust_core_boundary: "model_mount.server_control",
        operation_kind: request.operation_kind,
        record_dir: "model-server-controls",
        record_id: record.id,
        record,
        public_response: record.public_response,
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        control_hash: record.control_hash,
      };
    },
    planModelMountRuntimeEngine(request) {
      modelMountCalls.push({ method: "planModelMountRuntimeEngine", request });
      const record = {
        id: "runtime-engine-control.direct",
        object: "ioi.model_mount_runtime_engine_record",
        status: "planned",
        engine_id: request.engine_id,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.runtime_engine",
        public_response: {
          object: "ioi.model_mount_runtime_engine",
          status: "planned",
          engine_id: request.engine_id,
          operation_kind: request.operation_kind,
          js_preference_write: false,
          js_profile_write: false,
          js_projection_write: false,
        },
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "public_runtime_engine_js_facade_retired",
          "rust_daemon_core_runtime_engine",
          "agentgres_runtime_engine_truth_required",
        ],
        control_hash: "sha256:direct-runtime-engine",
      };
      return {
        source: "direct_model_mount_api",
        status: "planned",
        rust_core_boundary: "model_mount.runtime_engine",
        operation_kind: request.operation_kind,
        record_dir: "runtime-engine-controls",
        record_id: record.id,
        record,
        public_response: record.public_response,
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        control_hash: record.control_hash,
      };
    },
    planModelMountRuntimeSurvey(request) {
      modelMountCalls.push({ method: "planModelMountRuntimeSurvey", request });
      const receipt = {
        id: "receipt_runtime_survey_direct",
        kind: "runtime_survey",
        schemaVersion: "ioi.model-mounting.runtime.v1",
        createdAt: request.generated_at,
        redaction: "redacted",
        evidenceRefs: [
          "model_mount_runtime_survey_js_facade_retired",
          "rust_daemon_core_runtime_survey",
          "agentgres_runtime_survey_truth_required",
          "rust_model_mount_core",
        ],
        details: {
          checked_at: request.generated_at,
          engine_count: 0,
          selected_engines: [],
          runtime_preference: {},
          hardware: { status: "checked", js_probe_execution: false },
          lm_studio: { status: "not_checked", js_cli_execution: false },
          runtime_survey_hash: "sha256:direct-runtime-survey",
          rust_daemon_core_receipt_author: "model_mount.runtime_survey",
          js_hardware_probe_executed: false,
          js_runtime_engine_read_executed: false,
          js_lm_studio_probe_executed: false,
        },
      };
      return {
        source: "direct_model_mount_api",
        status: "planned",
        rust_core_boundary: "model_mount.runtime_survey",
        operation_kind: request.operation_kind,
        receipt,
        public_response: {
          object: "ioi.model_mount_runtime_survey",
          status: "checked",
          receiptId: receipt.id,
          engineCount: 0,
          rustCoreBoundary: "model_mount.runtime_survey",
        },
        receipt_refs: [receipt.id],
        evidence_refs: receipt.evidenceRefs,
        survey_hash: "sha256:direct-runtime-survey",
      };
    },
    planModelMountReadProjection(request) {
      modelMountCalls.push({ method: "planModelMountReadProjection", request });
      return {
        source: "rust_daemon_core.model_mount.read_projection",
        projection_kind: request.projection_kind,
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
        projection: {
          schemaVersion: request.schema_version,
          source: "agentgres_model_mounting_projection",
        },
      };
    },
    planModelMountCatalogProviderControl(request) {
      modelMountCalls.push({ method: "planModelMountCatalogProviderControl", request });
      const record = {
        id: "catalog-provider-control.direct",
        object: "ioi.model_mount_catalog_provider_control",
        status: "planned",
        operation_kind: request.operation_kind,
        provider_id: request.provider_id,
        rust_core_boundary: "model_mount.catalog_provider_control",
        plaintext_material_returned: false,
        public_response: {
          object: "ioi.model_catalog_provider_config_write",
          provider_id: request.provider_id,
          status: "accepted",
          private_material_returned: false,
        },
      };
      return {
        source: "direct_model_mount_api",
        record_dir: "model-catalog-provider-controls",
        record_id: record.id,
        record,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.catalog_provider_control",
        receipt_refs: request.receipt_refs ?? [],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: [
          "rust_daemon_core_catalog_provider_control",
          "ctee_catalog_provider_custody_enforced",
          "agentgres_catalog_provider_control_truth_required",
        ],
        control_hash: "sha256:direct-catalog-provider-control",
        authority_hash: "sha256:direct-catalog-provider-authority",
      };
    },
    planModelMountProviderControl(request) {
      modelMountCalls.push({ method: "planModelMountProviderControl", request });
      const record = {
        id: request.provider_id,
        object: "ioi.model_mount_provider",
        status: "configured",
        operation_kind: request.operation_kind,
        provider_id: request.provider_id,
        rust_core_boundary: "model_mount.provider_control",
        plaintext_material_returned: false,
        public_response: {
          object: "ioi.model_mount_provider",
          provider_id: request.provider_id,
          status: "configured",
          private_material_returned: false,
          plaintext_material_persisted: false,
        },
        evidence_refs: [
          "rust_daemon_core_provider_control",
          "ctee_provider_custody_enforced",
          "agentgres_provider_control_truth_required",
          "public_provider_control_js_facade_retired",
        ],
      };
      return {
        source: "direct_model_mount_api",
        record_dir: "model-providers",
        record_id: record.id,
        record,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.provider_control",
        receipt_refs: request.receipt_refs ?? [],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        control_hash: "sha256:direct-provider-control",
        authority_hash: "sha256:direct-provider-authority",
      };
    },
    planModelMountCapabilityTokenControl(request) {
      modelMountCalls.push({ method: "planModelMountCapabilityTokenControl", request });
      const record = {
        id: "capability-token-control.direct",
        object: "ioi.model_mount_capability_token_control",
        status: "planned",
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.capability_token",
        public_response: {
          object: "ioi.model_mount_capability_token",
          status: "issued",
          token_id: "capability_token.direct",
          plaintext_material_persisted: false,
          token_hash: "sha256:direct-capability-token",
        },
        evidence_refs: [
          "rust_daemon_core_capability_token_control",
          "wallet_network_capability_token_authority_required",
          "agentgres_capability_token_truth_required",
          "public_capability_token_js_facade_retired",
        ],
      };
      return {
        source: "direct_model_mount_api",
        record_dir: "capability-tokens",
        record_id: record.id,
        record,
        public_response: {
          ...record.public_response,
          token: "ioi_mnt_direct_token",
        },
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.capability_token",
        receipt_refs: request.receipt_refs ?? [],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        control_hash: "sha256:direct-capability-token-control",
        authority_hash: "sha256:direct-capability-token-authority",
      };
    },
    planModelMountVaultControl(request) {
      modelMountCalls.push({ method: "planModelMountVaultControl", request });
      const record = {
        id: "vault-control.direct",
        object: "ioi.model_mount_vault_control",
        status: "planned",
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.vault",
        public_response: {
          object: "ioi.model_mount_vault_ref",
          status: "bound",
          vault_ref_hash: "sha256:direct-vault-ref",
          plaintext_material_persisted: false,
          plaintext_material_returned: false,
        },
        ctee_custody: {
          plaintext_material_persisted: false,
          plaintext_material_returned: false,
        },
        evidence_refs: [
          "rust_daemon_core_vault_control",
          "wallet_network_vault_authority_required",
          "ctee_vault_custody_enforced",
          "agentgres_vault_truth_required",
          "public_vault_js_facade_retired",
        ],
      };
      return {
        source: "direct_model_mount_api",
        record_dir: "vault-refs",
        record_id: record.id,
        record,
        public_response: record.public_response,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.vault",
        receipt_refs: request.receipt_refs ?? [],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        control_hash: "sha256:direct-vault-control",
        authority_hash: "sha256:direct-vault-authority",
      };
    },
    planModelMountReceiptGate(request) {
      modelMountCalls.push({ method: "planModelMountReceiptGate", request });
      const receipt = {
        id: "receipt.workflow_receipt_gate.direct",
        kind: "workflow_receipt_gate",
        redaction: "redacted",
        details: {
          model_mount_receipt_gate_hash: "sha256:direct-receipt-gate",
          model_mount_receipt_binding_ref: "sha256:direct-receipt-binding",
          model_mount_agentgres_operation_ref:
            "agentgres://model-mounting/receipt-gates/direct-receipt-gate",
        },
      };
      return {
        source: "direct_model_mount_api",
        plan: {
          schema_version: "ioi.model_mount.receipt_gate_plan.v1",
          object: "ioi.model_mount_receipt_gate_plan",
          status: "planned",
          rust_core_boundary: "model_mount.receipt_gate",
          operation_kind: request.operation_kind,
          receipt_id: request.receipt_id,
          gate_status: "passed",
          failures: [],
          receipt,
          public_response: {
            object: "ioi.model_mount_receipt_gate_result",
            status: "passed",
            receipt_id: request.receipt_id,
            gate_receipt_id: receipt.id,
            failures: [],
          },
          receipt_refs: [request.receipt_id],
          evidence_refs: [
            "model_mount_receipt_gate_rust_owned",
            "model_mount_receipt_gate_js_facade_retired",
            "rust_receipt_binder_core",
            "agentgres_model_receipt_gate_truth_required",
          ],
          gate_hash: "sha256:direct-receipt-gate",
        },
        receipt,
        public_response: {
          object: "ioi.model_mount_receipt_gate_result",
          status: "passed",
          receipt_id: request.receipt_id,
          gate_receipt_id: receipt.id,
          failures: [],
        },
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.receipt_gate",
        receipt_refs: [request.receipt_id],
        evidence_refs: [
          "model_mount_receipt_gate_rust_owned",
          "model_mount_receipt_gate_js_facade_retired",
          "rust_receipt_binder_core",
          "agentgres_model_receipt_gate_truth_required",
        ],
        gate_hash: "sha256:direct-receipt-gate",
      };
    },
    planModelMountAcceptedReceiptHead(request) {
      modelMountCalls.push({ method: "planModelMountAcceptedReceiptHead", request });
      return {
        source: "rust_daemon_core.model_mount.accepted_receipt_head",
        head: {
          schema_version: request.schema_version,
          sequence: request.sequence,
          head_ref: `agentgres://model-mounting/accepted-receipts/head/${request.sequence}`,
          state_root: "sha256:direct-state-root",
          projection_watermark: `model-mounting-accepted-receipts:${request.sequence}`,
          head_hash: "sha256:direct-head",
          evidence_refs: ["rust_agentgres_receipt_head_planner"],
        },
        sequence: request.sequence,
        head_ref: `agentgres://model-mounting/accepted-receipts/head/${request.sequence}`,
        state_root: "sha256:direct-state-root",
        projection_watermark: `model-mounting-accepted-receipts:${request.sequence}`,
        head_hash: "sha256:direct-head",
        evidence_refs: ["rust_agentgres_receipt_head_planner"],
      };
    },
    planModelMountAcceptedReceiptTransition(request) {
      modelMountCalls.push({ method: "planModelMountAcceptedReceiptTransition", request });
      return {
        source: "rust_daemon_core.model_mount.accepted_receipt_transition",
        transition: {
          schema_version: request.schema_version,
          operation_id: "op_00000001_model_invocation",
          operation_ref: "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation",
          expected_heads: [request.current_head_ref],
          state_root_before: request.current_state_root,
          state_root_after: "sha256:direct-state-after",
          resulting_head: "agentgres://model-mounting/accepted-receipts/head/1",
          projection_watermark: "model-mounting-accepted-receipts:1",
          transition_hash: "sha256:direct-transition",
          evidence_refs: ["rust_agentgres_receipt_state_root_planner"],
        },
        operation_id: "op_00000001_model_invocation",
        operation_ref: "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation",
        expected_heads: [request.current_head_ref],
        state_root_before: request.current_state_root,
        state_root_after: "sha256:direct-state-after",
        resulting_head: "agentgres://model-mounting/accepted-receipts/head/1",
        projection_watermark: "model-mounting-accepted-receipts:1",
        transition_hash: "sha256:direct-transition",
        evidence_refs: ["rust_agentgres_receipt_state_root_planner"],
      };
    },
    bindModelMountInvocationReceipt(request) {
      modelMountCalls.push({ method: "bindModelMountInvocationReceipt", request });
      return {
        source: "rust_daemon_core.model_mount.invocation_receipt_binding",
        invocation: request.invocation,
        result: request.result,
        receipt_binding: {
          schema_version: "ioi.step_module_receipt_binding.v1",
          binding_hash: "sha256:direct-binding",
          receipt_refs: [request.receipt_ref],
        },
        accepted_receipt_append: {
          schema_version: "ioi.accepted_receipt_append.v1",
          append_hash: "sha256:direct-append",
          receipt_ref: request.receipt_ref,
        },
        agentgres_admission: {
          schema_version: "ioi.agentgres_admission.v1",
          operation_ref: request.accepted_receipt_transition?.operation_ref,
          expected_heads: request.accepted_receipt_transition?.expected_heads ?? [],
          admission_hash: "sha256:direct-agentgres",
        },
        projection_record: {
          component_kind: "ModelInvocationNode",
        },
        receipt_refs: [request.receipt_ref],
        evidence_refs: ["rust_receipt_binder_core", "sha256:direct-binding", "sha256:direct-append"],
      };
    },
  };
  const directModelMountCore = createModelMountCore({
    daemonCoreInvoker: failCommandInvoker,
    daemonCoreModelMountApi,
  });
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    modelMountCore: {
      admitInvocation(request) {
        return directModelMountCore.admitInvocation(request);
      },
      admitProviderExecution(request) {
        return directModelMountCore.admitProviderExecution(request);
      },
      executeProviderInvocation(request) {
        return directModelMountCore.executeProviderInvocation(request);
      },
      executeProviderStreamInvocation(request) {
        return directModelMountCore.executeProviderStreamInvocation(request);
      },
      planProviderLifecycle(request) {
        return directModelMountCore.planProviderLifecycle(request);
      },
      planProviderInventory(request) {
        return directModelMountCore.planProviderInventory(request);
      },
      planInstanceLifecycle(request) {
        return directModelMountCore.planInstanceLifecycle(request);
      },
      admitProviderResult(request) {
        return directModelMountCore.admitProviderResult(request);
      },
      planBackendProcess(request) {
        return directModelMountCore.planBackendProcess(request);
      },
      planBackendLifecycle(request) {
        return directModelMountCore.planBackendLifecycle(request);
      },
      planRouteControl(request) {
        return directModelMountCore.planRouteControl(request);
      },
      planTokenizerRequired(request) {
        return directModelMountCore.planTokenizerRequired(request);
      },
      planRouteControlRequired(request) {
        return directModelMountCore.planRouteControlRequired(request);
      },
      planTokenizer(request) {
        return directModelMountCore.planTokenizer(request);
      },
      planConversationState(request) {
        return directModelMountCore.planConversationState(request);
      },
      planStreamCompletion(request) {
        return directModelMountCore.planStreamCompletion(request);
      },
      planStreamCancel(request) {
        return directModelMountCore.planStreamCancel(request);
      },
      planArtifactEndpoint(request) {
        return directModelMountCore.planArtifactEndpoint(request);
      },
      planCatalogProviderControl(request) {
        return directModelMountCore.planCatalogProviderControl(request);
      },
      planProviderControl(request) {
        return directModelMountCore.planProviderControl(request);
      },
      planCapabilityTokenControl(request) {
        return directModelMountCore.planCapabilityTokenControl(request);
      },
      planVaultControl(request) {
        return directModelMountCore.planVaultControl(request);
      },
      planReceiptGate(request) {
        return directModelMountCore.planReceiptGate(request);
      },
      planAcceptedReceiptHead(request) {
        return directModelMountCore.planAcceptedReceiptHead(request);
      },
      planAcceptedReceiptTransition(request) {
        return directModelMountCore.planAcceptedReceiptTransition(request);
      },
      bindInvocationReceipt(request) {
        return directModelMountCore.bindInvocationReceipt(request);
      },
      planReadProjection(request) {
        return directModelMountCore.planReadProjection(request);
      },
      planStorageControl(request) {
        return directModelMountCore.planStorageControl(request);
      },
      planMcpWorkflow(request) {
        return directModelMountCore.planMcpWorkflow(request);
      },
      planServerControl(request) {
        return directModelMountCore.planServerControl(request);
      },
      planRuntimeEngine(request) {
        return directModelMountCore.planRuntimeEngine(request);
      },
      planRuntimeSurvey(request) {
        return directModelMountCore.planRuntimeSurvey(request);
      },
    },
    daemonCoreInvoker: failCommandInvoker,
    daemonCoreModelMountApi,
    daemonCoreContextLifecycleApi: {
      evaluateContextBudgetPolicy(request) {
        contextLifecycleCalls.push({ method: "evaluateContextBudgetPolicy", request });
        return {
          source: "direct_context_lifecycle_api",
          backend: "rust_policy",
          status: "allowed",
          mode: "monitor",
          usage_telemetry: request.usage_telemetry,
          usage_summary: request.usage_telemetry,
          policy_decision_refs: ["policy://direct-context-budget"],
        };
      },
    },
    daemonCoreRuntimeControlApi: {
      planWorkflowEditAdmissionRequired(request) {
        runtimeControlCalls.push({ method: "planWorkflowEditAdmissionRequired", request });
        return {
          status: "rust_core_required",
          status_code: 501,
          code: "runtime_workflow_edit_rust_core_required",
          message: "Runtime workflow edit control requires direct Rust daemon-core admission and persistence.",
          details: {
            rust_core_boundary: "runtime.workflow_edit",
            operation: request.operation,
            operation_kind: request.operation_kind,
            thread_id: request.thread_id,
            proposal_id: request.proposal_id,
            evidence_refs: request.evidence_refs ?? [],
          },
        };
      },
      planDiagnosticsRepairAdmissionRequired(request) {
        runtimeControlCalls.push({ method: "planDiagnosticsRepairAdmissionRequired", request });
        return {
          status: "rust_core_required",
          status_code: 501,
          code: "runtime_diagnostics_repair_rust_core_required",
          message:
            "Runtime diagnostics repair control requires direct Rust daemon-core admission and persistence.",
          details: {
            rust_core_boundary: "runtime.diagnostics_repair",
            operation: request.operation,
            operation_kind: request.operation_kind,
            thread_id: request.thread_id,
            decision_id: request.decision_id,
            gate_event_id: request.gate_event_id,
            snapshot_id: request.snapshot_id,
            evidence_refs: request.evidence_refs ?? [],
          },
        };
      },
      planRunCancelStateUpdate(request) {
        runtimeControlCalls.push({ method: "planRunCancelStateUpdate", request });
        return {
          source: "direct_runtime_control_api",
          backend: "rust_policy",
          status: "planned",
          operation_kind: "run.cancel",
          updated_at: request.canceled_at,
          run: {
            id: request.run_id,
            status: "canceled",
            events: [{ type: "canceled" }],
          },
        };
      },
    },
    daemonCoreThreadLifecycleApi: {
      planThreadTurnAdmissionRequired(request) {
        threadLifecycleCalls.push({ method: "planThreadTurnAdmissionRequired", request });
        return {
          status: "rust_core_required",
          status_code: 501,
          code: "runtime_thread_turn_rust_core_required",
          message:
            "Thread resume and turn creation require direct Rust daemon-core admission and persistence.",
          details: {
            rust_core_boundary: "runtime.thread_turn",
            operation: request.operation,
            operation_kind: request.operation_kind,
            thread_id: request.thread_id,
            agent_id: request.agent_id,
            runtime_profile: request.runtime_profile,
            evidence_refs: request.evidence_refs ?? [],
          },
        };
      },
      planLifecycleAdmissionRequired(request) {
        threadLifecycleCalls.push({ method: "planLifecycleAdmissionRequired", request });
        return {
          status: "rust_core_required",
          status_code: 501,
          code: "runtime_agent_status_control_rust_core_required",
          message: "Agent lifecycle/status control requires direct Rust daemon-core admission and projection.",
          details: {
            rust_core_boundary: "runtime.agent_status_control",
            operation: request.operation,
            operation_kind: request.operation_kind,
            agent_id: request.agent_id,
            requested_status: request.requested_status,
            requested_operation_kind: request.requested_operation_kind,
            evidence_refs: request.evidence_refs ?? [],
          },
        };
      },
      planAgentCreateStateUpdate(request) {
        threadLifecycleCalls.push({ method: "planAgentCreateStateUpdate", request });
        return {
          source: "direct_thread_lifecycle_api",
          backend: "rust_policy",
          status: "planned",
          operation_kind: "agent.create",
          created_at: request.agent?.createdAt,
          updated_at: request.agent?.updatedAt,
          agent: {
            id: request.agent?.id,
            status: request.agent?.status ?? "active",
          },
        };
      },
    },
    daemonCoreWorkspaceTrustApi: {
      planWorkspaceTrustControlStateUpdate(request) {
        workspaceTrustCalls.push({ method: "planWorkspaceTrustControlStateUpdate", request });
        return {
          source: "direct_workspace_trust_api",
          backend: "rust_policy",
          status: "planned",
          operation_kind: request.operation_kind,
          thread_id: request.thread_id,
          event_stream_id: request.event_stream_id,
          event: {
            event_id: request.event_id,
            thread_id: request.thread_id,
            event_kind: "workspace.trust_warning",
            receipt_refs: ["receipt://workspace-trust/direct"],
          },
        };
      },
    },
    daemonCoreMcpApi: {
      planMcpManagerStatusProjection(request) {
        mcpCalls.push({ method: "planMcpManagerStatusProjection", request });
        return {
          source: "direct_mcp_api",
          backend: "rust_policy",
          status: "ready",
          server_count: request.servers?.length ?? 0,
          tool_count: request.tools?.length ?? 0,
          resource_count: request.resources?.length ?? 0,
          prompt_count: request.prompts?.length ?? 0,
          enabled_server_count: request.servers?.filter((server) => server?.enabled !== false).length ?? 0,
          enabled_tool_count: request.enabled_tools?.length ?? 0,
          servers: request.servers ?? [],
          tools: request.tools ?? [],
          resources: request.resources ?? [],
          prompts: request.prompts ?? [],
          validation: request.validation ?? {},
          routes: request.routes ?? {},
        };
      },
    },
    daemonCoreThreadMemoryApi: {
      planRuntimeMemoryControl(request) {
        threadMemoryCalls.push({ method: "planRuntimeMemoryControl", request });
        return {
          source: "direct_thread_memory_api",
          backend: "rust_memory",
          status: "planned",
          operation: request.operation,
          operation_kind: request.operation_kind,
          memory_state_kind: "record",
          state_id: "memory_direct",
          thread_id: request.thread_id,
          agent_id: request.agent_id,
          workspace_root: request.workspace_root,
          payload: {
            schema_version: "ioi.agent-runtime.memory.v1",
            object: "ioi.agent_memory_record",
            id: "memory_direct",
            thread_id: request.thread_id,
            agent_id: request.agent_id,
            fact: request.request?.text ?? "direct memory",
            receipt_refs: ["receipt://thread-memory/direct"],
          },
          receipt_refs: ["receipt://thread-memory/direct"],
        };
      },
    },
    daemonCoreAgentgresApi: {
      commitRuntimeRunState(request) {
        agentgresCalls.push({ method: "commitRuntimeRunState", request });
        return {
          source: "direct_agentgres_api",
          backend: "rust_agentgres_storage",
          commit_hash: "sha256:direct-agentgres-commit",
          record: {
            run_id: request.request.run_id,
          },
        };
      },
      commitRuntimeModelMountReceiptState(request) {
        agentgresCalls.push({ method: "commitRuntimeModelMountReceiptState", request });
        const commitRequest = request.request;
        const recordPath = `receipts/${commitRequest.receipt_id}.json`;
        return {
          source: "direct_agentgres_api",
          backend: "rust_agentgres_storage",
          receipt_id: commitRequest.receipt_id,
          object_ref: `agentgres://model-mounting/receipts/${commitRequest.receipt_id}/records/${recordPath}`,
          content_hash: "sha256:direct-model-mount-receipt-content",
          admission_hash: "sha256:direct-model-mount-receipt-admission",
          commit_hash: "sha256:direct-model-mount-receipt-commit",
          written_record: { record_path: recordPath },
          record: {
            schema_version: "ioi.runtime_model_mount_receipt_state_commit.v1",
            receipt_id: commitRequest.receipt_id,
            operation_kind: commitRequest.operation_kind,
            commit_hash: "sha256:direct-model-mount-receipt-commit",
            record: {
              object_ref: `agentgres://model-mounting/receipts/${commitRequest.receipt_id}/records/${recordPath}`,
              content_hash: "sha256:direct-model-mount-receipt-content",
              admission: { admission_hash: "sha256:direct-model-mount-receipt-admission" },
            },
          },
          storage_record: {
            record_path: recordPath,
            object_ref: `agentgres://model-mounting/receipts/${commitRequest.receipt_id}/records/${recordPath}`,
            content_hash: "sha256:direct-model-mount-receipt-content",
            admission: { admission_hash: "sha256:direct-model-mount-receipt-admission" },
          },
        };
      },
    },
    daemonCoreApprovalApi: {
      projectApprovalQueue(request) {
        approvalCalls.push({ method: "projectApprovalQueue", request });
        return {
          source: "direct_approval_api",
          backend: "rust_authority",
          status: "projected",
          operation_kind: "approval.queue_projection",
          thread_id: request.thread_id,
          approvals: [],
          pending_count: 0,
          resolved_count: 0,
        };
      },
    },
    daemonCoreGovernedAdmissionApi: {
      admitL1SettlementAttempt(attempt, context) {
        governedAdmissionCalls.push({ attempt, context });
        return {
          source: "direct_governed_admission_api",
          backend: "l1_settlement_guard",
          thread_id: context.thread_id,
          agent_id: context.agent_id,
          settlement_admitted: true,
          record: {
            settlement_ref: attempt.settlement_ref,
            trigger_refs: attempt.trigger_refs,
            receipt_refs: attempt.receipt_refs,
          },
        };
      },
    },
  });

  const result = store.l1SettlementCore.admitAttempt(
    {
      settlement_ref: "settlement://direct",
      trigger_refs: ["trigger://direct"],
    },
    {
      thread_id: "thread_direct",
      agent_id: "agent_direct",
    },
  );

  assert.equal(calls.length, 0);
  const contextBudget = store.contextPolicyCore.evaluateContextBudgetPolicy({
    usage_telemetry: { total_tokens: 12 },
    mode: "monitor",
    thread_id: "thread_direct",
  });
  assert.equal(calls.length, 0);
  assert.equal(contextLifecycleCalls.length, 1);
  assert.equal(contextLifecycleCalls[0].method, "evaluateContextBudgetPolicy");
  assert.equal(contextLifecycleCalls[0].request.schema_version, "ioi.runtime.context-budget-policy-request.v1");
  assert.equal(Object.hasOwn(contextLifecycleCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(contextLifecycleCalls[0].request, "backend"), false);
  assert.equal(contextBudget.source, "direct_context_lifecycle_api");
  assert.deepEqual(contextBudget.policy_decision_refs, ["policy://direct-context-budget"]);
  const cancelPlan = store.contextPolicyCore.planRunCancelStateUpdate({
    run_id: "run_direct",
    run: { id: "run_direct", status: "running" },
    canceled_at: "2026-06-14T18:30:00.000Z",
  });
  assert.equal(calls.length, 0);
  assert.equal(runtimeControlCalls.length, 1);
  assert.equal(runtimeControlCalls[0].method, "planRunCancelStateUpdate");
  assert.equal(runtimeControlCalls[0].request.schema_version, "ioi.runtime.run-cancel-state-update-request.v1");
  assert.equal(Object.hasOwn(runtimeControlCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(runtimeControlCalls[0].request, "backend"), false);
  assert.equal(cancelPlan.source, "direct_runtime_control_api");
  assert.equal(cancelPlan.run.status, "canceled");
  const workflowRequired = store.contextPolicyCore.planWorkflowEditAdmissionRequired({
    operation: "workflow_edit_proposal",
    operation_kind: "workflow.edit_proposed",
    thread_id: "thread_direct",
    proposal_id: "proposal_direct",
    evidence_refs: ["workflow_edit_proposal_js_facade_retired"],
  });
  assert.equal(calls.length, 0);
  assert.equal(runtimeControlCalls.length, 2);
  assert.equal(runtimeControlCalls[1].method, "planWorkflowEditAdmissionRequired");
  assert.equal(
    runtimeControlCalls[1].request.schema_version,
    "ioi.runtime.workflow-edit-admission-required-request.v1",
  );
  assert.equal(Object.hasOwn(runtimeControlCalls[1].request, "operation"), true);
  assert.equal(Object.hasOwn(runtimeControlCalls[1].request, "backend"), false);
  assert.equal(workflowRequired.code, "runtime_workflow_edit_rust_core_required");
  assert.equal(Object.hasOwn(workflowRequired, "backend"), false);
  const diagnosticsRequired = store.contextPolicyCore.planDiagnosticsRepairAdmissionRequired({
    operation: "diagnostics_repair_decision_execution",
    operation_kind: "diagnostics.repair_decision.execute",
    thread_id: "thread_direct",
    decision_id: "decision_direct",
    gate_event_id: "event_gate_direct",
    snapshot_id: "snapshot_direct",
    evidence_refs: ["diagnostics_repair_decision_execution_js_facade_retired"],
  });
  assert.equal(calls.length, 0);
  assert.equal(runtimeControlCalls.length, 3);
  assert.equal(runtimeControlCalls[2].method, "planDiagnosticsRepairAdmissionRequired");
  assert.equal(
    runtimeControlCalls[2].request.schema_version,
    "ioi.runtime.diagnostics-repair-admission-required-request.v1",
  );
  assert.equal(Object.hasOwn(runtimeControlCalls[2].request, "backend"), false);
  assert.equal(diagnosticsRequired.code, "runtime_diagnostics_repair_rust_core_required");
  assert.equal(Object.hasOwn(diagnosticsRequired, "backend"), false);
  const agentPlan = store.contextPolicyCore.planAgentCreateStateUpdate({
    agent: {
      id: "agent_direct",
      status: "active",
      createdAt: "2026-06-14T18:35:00.000Z",
      updatedAt: "2026-06-14T18:35:00.000Z",
    },
  });
  assert.equal(calls.length, 0);
  assert.equal(threadLifecycleCalls.length, 1);
  assert.equal(threadLifecycleCalls[0].method, "planAgentCreateStateUpdate");
  assert.equal(
    threadLifecycleCalls[0].request.schema_version,
    "ioi.runtime.agent-create-state-update-request.v1",
  );
  assert.equal(Object.hasOwn(threadLifecycleCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(threadLifecycleCalls[0].request, "backend"), false);
  assert.equal(agentPlan.source, "direct_thread_lifecycle_api");
  assert.equal(agentPlan.operation_kind, "agent.create");
  assert.equal(agentPlan.agent.id, "agent_direct");
  const threadTurnRequired = store.contextPolicyCore.planThreadTurnAdmissionRequired({
    operation: "thread_turn_create",
    operation_kind: "turn.create",
    thread_id: "thread_direct",
    agent_id: "agent_direct",
    runtime_profile: "fixture",
    evidence_refs: ["thread_turn_create_js_run_creation_retired"],
  });
  assert.equal(calls.length, 0);
  assert.equal(threadLifecycleCalls.length, 2);
  assert.equal(threadLifecycleCalls[1].method, "planThreadTurnAdmissionRequired");
  assert.equal(
    threadLifecycleCalls[1].request.schema_version,
    "ioi.runtime.thread-turn-admission-required-request.v1",
  );
  assert.equal(Object.hasOwn(threadLifecycleCalls[1].request, "backend"), false);
  assert.equal(threadTurnRequired.code, "runtime_thread_turn_rust_core_required");
  assert.equal(Object.hasOwn(threadTurnRequired, "backend"), false);
  const lifecycleRequired = store.contextPolicyCore.planLifecycleAdmissionRequired({
    operation: "agent_status_control",
    operation_kind: "agent_status_update",
    agent_id: "agent_direct",
    requested_status: "archived",
    requested_operation_kind: "agent.archive",
    evidence_refs: ["runtime_agent_status_control_js_facade_retired"],
  });
  assert.equal(calls.length, 0);
  assert.equal(threadLifecycleCalls.length, 3);
  assert.equal(threadLifecycleCalls[2].method, "planLifecycleAdmissionRequired");
  assert.equal(
    threadLifecycleCalls[2].request.schema_version,
    "ioi.runtime.lifecycle-admission-required-request.v1",
  );
  assert.equal(Object.hasOwn(threadLifecycleCalls[2].request, "backend"), false);
  assert.equal(lifecycleRequired.code, "runtime_agent_status_control_rust_core_required");
  assert.equal(Object.hasOwn(lifecycleRequired, "backend"), false);
  const workspaceTrustPlan = store.contextPolicyCore.planWorkspaceTrustControlStateUpdate({
    operation_kind: "workspace_trust.warning",
    thread_id: "thread_direct",
    event_stream_id: "thread_direct:events",
    agent: { id: "agent_direct", cwd: stateDir },
    controls: { mode: "review", approval_mode: "human_required" },
    event_id: "evt_workspace_trust_direct",
    created_at: "2026-06-14T18:36:00.000Z",
  });
  assert.equal(calls.length, 0);
  assert.equal(workspaceTrustCalls.length, 1);
  assert.equal(workspaceTrustCalls[0].method, "planWorkspaceTrustControlStateUpdate");
  assert.equal(
    workspaceTrustCalls[0].request.schema_version,
    "ioi.runtime.workspace-trust-control-state-update-request.v1",
  );
  assert.equal(Object.hasOwn(workspaceTrustCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(workspaceTrustCalls[0].request, "backend"), false);
  assert.equal(workspaceTrustPlan.source, "direct_workspace_trust_api");
  assert.equal(workspaceTrustPlan.event.event_kind, "workspace.trust_warning");
  const mcpStatus = store.contextPolicyCore.planMcpManagerStatusProjection({
    servers: [{ id: "mcp.docs", enabled: true }],
    tools: [{ stable_tool_id: "mcp.docs.search" }],
    resources: [],
    prompts: [],
    enabled_tools: [{ stable_tool_id: "mcp.docs.search" }],
  });
  assert.equal(calls.length, 0);
  assert.equal(mcpCalls.length, 1);
  assert.equal(mcpCalls[0].method, "planMcpManagerStatusProjection");
  assert.equal(
    mcpCalls[0].request.schema_version,
    "ioi.runtime.mcp-manager-status-projection-request.v1",
  );
  assert.equal(Object.hasOwn(mcpCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(mcpCalls[0].request, "backend"), false);
  assert.equal(mcpStatus.source, "direct_mcp_api");
  assert.equal(mcpStatus.server_count, 1);
  const invocationAdmission = store.modelMounting.admitModelMountInvocation({
    schema_version: "ioi.model_mount.invocation_admission.v1",
    invocation_ref: "model-invocation://direct",
    route_decision_ref: "model_mount://route_decision/direct",
    route_receipt_ref: "receipt://route/direct",
    invocation_receipt_ref: "receipt://invocation/direct",
    receipt_refs: ["receipt://route/direct", "receipt://invocation/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "admitModelMountInvocation",
    "ioi.model_mount.invocation_admission.v1",
  );
  assert.equal(invocationAdmission.source, "direct_model_mount_api");
  assert.equal(invocationAdmission.invocation_admission_hash, "sha256:direct-invocation");
  const providerExecution = store.modelMounting.admitModelMountProviderExecution({
    schema_version: "ioi.model_mount.provider_execution.v1",
    invocation_ref: "model-provider-execution://direct",
    route_decision_ref: "model_mount://route_decision/direct",
    route_receipt_ref: "receipt://route/direct",
    request_hash: "sha256:direct-request",
    receipt_refs: ["receipt://route/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "admitModelMountProviderExecution",
    "ioi.model_mount.provider_execution.v1",
  );
  assert.equal(providerExecution.provider_execution_hash, "sha256:direct-provider-execution");
  const providerInvocation = store.modelMounting.executeModelMountProviderInvocation({
    schema_version: "ioi.model_mount.provider_invocation.v1",
    provider_execution_ref: providerExecution.provider_execution_ref,
    provider_execution_hash: providerExecution.provider_execution_hash,
    provider_ref: "provider.local",
    provider_kind: "local_folder",
    execution_backend: "rust_model_mount_fixture",
    backend_ref: "backend.fixture",
    input: "hello",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "executeModelMountProviderInvocation",
    "ioi.model_mount.provider_invocation.v1",
  );
  assert.equal(providerInvocation.outputText, "direct provider invocation");
  const providerStream = store.modelMounting.executeModelMountProviderStreamInvocation({
    schema_version: "ioi.model_mount.provider_invocation.v1",
    provider_execution_ref: providerExecution.provider_execution_ref,
    provider_execution_hash: providerExecution.provider_execution_hash,
    provider_ref: "provider.autopilot.local",
    provider_kind: "ioi_native_local",
    execution_backend: "rust_model_mount_native_local_stream",
    backend_ref: "backend.autopilot.native-local.fixture",
    stream_status: "started",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "executeModelMountProviderStreamInvocation",
    "ioi.model_mount.provider_invocation.v1",
  );
  assert.equal(providerStream.streamKind, "openai_responses_native_local");
  const providerLifecycle = store.modelMounting.planModelMountProviderLifecycle({
    schema_version: "ioi.model_mount.provider_lifecycle.v1",
    provider_ref: "provider.autopilot.local",
    provider_kind: "ioi_native_local",
    action: "load",
    execution_backend: "rust_model_mount_native_local_lifecycle",
    driver: "native_local",
    backend_ref: "backend.autopilot.native-local.fixture",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountProviderLifecycle",
    "ioi.model_mount.provider_lifecycle.v1",
  );
  assert.equal(providerLifecycle.lifecycle_hash, "sha256:direct-provider-lifecycle");
  const providerInventory = store.modelMounting.planModelMountProviderInventory({
    schema_version: "ioi.model_mount.provider_inventory.v1",
    provider_ref: "provider.autopilot.local",
    provider_kind: "ioi_native_local",
    action: "list_loaded",
    execution_backend: "rust_model_mount_native_local_inventory",
    driver: "native_local",
    backend_ref: "backend.autopilot.native-local.fixture",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountProviderInventory",
    "ioi.model_mount.provider_inventory.v1",
  );
  assert.deepEqual(providerInventory.itemRefs, ["model_instance://native/direct"]);
  const instanceLifecycle = store.modelMounting.planModelMountInstanceLifecycle({
    schema_version: "ioi.model_mount.instance_lifecycle.v1",
    instance_ref: "model_instance://native/direct",
    provider_ref: "provider.autopilot.local",
    action: "load",
    execution_backend: "rust_model_mount_instance_lifecycle",
    driver: "native_local",
    backend_ref: "backend.autopilot.native-local.fixture",
    provider_lifecycle_hash: providerLifecycle.lifecycle_hash,
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountInstanceLifecycle",
    "ioi.model_mount.instance_lifecycle.v1",
  );
  assert.equal(instanceLifecycle.instance_lifecycle_hash, "sha256:direct-instance-lifecycle");
  const providerResult = store.modelMounting.admitModelMountProviderResult({
    schema_version: "ioi.model_mount.provider_result.v1",
    provider_execution_ref: providerExecution.provider_execution_ref,
    provider_execution_hash: providerExecution.provider_execution_hash,
    invocation_hash: providerStream.invocation_hash,
    execution_backend: "rust_model_mount_native_local_stream",
    output_hash: "sha256:direct-output",
    receipt_refs: ["receipt://invocation/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "admitModelMountProviderResult",
    "ioi.model_mount.provider_result.v1",
  );
  assert.equal(providerResult.provider_result_hash, "sha256:direct-provider-result");
  const backendProcess = store.modelMounting.backendProcessPlan(
    {
      id: "backend.llama",
      kind: "llama_cpp",
      baseUrl: "http://127.0.0.1:8091/v1",
      binaryAvailable: true,
    },
    {
      endpoint: { modelId: "model.direct" },
      loadOptions: {
        context_length: 4096,
        parallel: 2,
      },
    },
  );
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountBackendProcess",
    "ioi.model_mount.backend_process_plan.v1",
  );
  assert.equal(modelMountCalls.at(-1).request.backend_kind, "llama_cpp");
  assert.equal(backendProcess.source, "rust_daemon_core.model_mount.backend_process");
  assert.equal(backendProcess.spawn_status, "spawn_ready");
  const backendLifecycle = store.modelMounting.planBackendLifecycle({
    schema_version: "ioi.model_mount.backend_lifecycle.v1",
    operation_kind: "model_mount.backend.start",
    backend_id: "backend.llama",
    backend_kind: "llama_cpp",
    source: "runtime-daemon.model_mounting.backend_lifecycle",
    body: {
      backend_id: "backend.llama",
      backend_kind: "llama_cpp",
    },
    receipt_refs: ["receipt://backend-lifecycle/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountBackendLifecycle",
    "ioi.model_mount.backend_lifecycle.v1",
  );
  assert.equal(modelMountCalls.at(-1).request.operation_kind, "model_mount.backend.start");
  assert.equal(backendLifecycle.source, "rust_daemon_core.model_mount.backend_lifecycle");
  assert.equal(backendLifecycle.record_id, "backend-lifecycle-control:direct");
  const routeControlPlan = store.modelMounting.planRouteControl({
    schema_version: "ioi.model_mount.route_control.v1",
    operation_kind: "model_mount.route.write",
    source: "runtime-daemon.model_mounting.route_control",
    route_id: "route.direct",
    body: {
      id: "route.direct",
      role: "Direct",
      fallback: ["endpoint.direct"],
      provider_eligibility: ["local_folder"],
    },
    receipt_refs: ["receipt://route-control/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountRouteControl",
    "ioi.model_mount.route_control.v1",
  );
  assert.equal(routeControlPlan.source, "rust_daemon_core.model_mount.route_control");
  assert.equal(routeControlPlan.record_id, "route.direct");
  assert.equal(routeControlPlan.rust_core_boundary, "model_mount.route_control");
  const tokenizerRequired = directModelMountCore.planTokenizerRequired({
    schema_version: "ioi.model_mount.tokenizer_required.v1",
    operation: "context_fit",
    source: "runtime-daemon.model_mounting.tokenizer",
    details: {
      model: "model.direct",
      route_id: "route.direct",
      requested_scope: "model.context:*",
    },
  });
  assert.equal(calls.length, 0);
  assert.equal(modelMountCalls.at(-1).method, "planModelMountTokenizerRequired");
  assert.equal(modelMountCalls.at(-1).request.schema_version, "ioi.model_mount.tokenizer_required.v1");
  assert.equal(modelMountCalls.at(-1).request.operation, "context_fit");
  assert.equal(Object.hasOwn(modelMountCalls.at(-1).request, "backend"), false);
  assert.equal(tokenizerRequired.source, "rust_daemon_core.model_mount.tokenizer_required");
  assert.equal(tokenizerRequired.rust_core_boundary, "model_mount.tokenizer");
  const routeControlRequired = store.modelMounting.routeControlRequired(
    "model_mount.route.selection_update",
    {
      route_id: "route.direct",
      selected_model: "model.direct",
      receipt_id: "receipt-route-direct",
    },
  );
  assert.equal(calls.length, 0);
  assert.equal(modelMountCalls.at(-1).method, "planModelMountRouteControlRequired");
  assert.equal(modelMountCalls.at(-1).request.schema_version, "ioi.model_mount.route_control_required.v1");
  assert.equal(modelMountCalls.at(-1).request.operation, "model_mount.route_control");
  assert.equal(modelMountCalls.at(-1).request.operation_kind, "model_mount.route.selection_update");
  assert.equal(Object.hasOwn(modelMountCalls.at(-1).request, "backend"), false);
  assert.equal(routeControlRequired.source, "rust_daemon_core.model_mount.route_control_required");
  assert.equal(routeControlRequired.rust_core_boundary, "model_mount.route_control");
  const tokenizerPlan = store.modelMounting.planTokenizer({
    schema_version: "ioi.model_mount.tokenizer.v1",
    operation: "tokenize",
    source: "runtime-daemon.model_mounting.tokenizer",
    required_scope: "model.tokenize:*",
    body: { input: "direct tokens" },
    route_selection: {
      route: { id: "route.direct" },
      endpoint: { id: "endpoint.direct", modelId: "model.direct" },
      provider: { id: "provider.direct" },
      route_decision: { route_decision_ref: "model_mount://route_decision/direct" },
    },
    artifacts: [],
    receipt_refs: ["receipt://route/direct"],
  });
  assert.equal(calls.length, 0);
  assert.equal(modelMountCalls.at(-1).method, "planModelMountTokenizer");
  assert.equal(modelMountCalls.at(-1).request.schema_version, "ioi.model_mount.tokenizer.v1");
  assert.equal(modelMountCalls.at(-1).request.operation, "tokenize");
  assert.equal(Object.hasOwn(modelMountCalls.at(-1).request, "backend"), false);
  assert.equal(tokenizerPlan.source, "rust_daemon_core.model_mount.tokenizer");
  assert.equal(tokenizerPlan.record_id, "model_tokenizer:tokenize:direct");
  assert.equal(tokenizerPlan.rust_core_boundary, "model_mount.tokenizer");
  const conversationPlan = store.modelMounting.planModelMountConversationState({
    schema_version: "ioi.model_mount.conversation_state.v1",
    operation: "model_conversation_state_write",
    response_id: "resp.direct",
    kind: "responses",
    status: "completed",
    source: "runtime-daemon.model_mounting.conversation",
    route_ref: "route.direct",
    endpoint_ref: "endpoint.direct",
    provider_ref: "provider.direct",
    model_ref: "model.direct",
    route_decision_ref: "model_mount://route_decision/direct",
    invocation_receipt_ref: "receipt://invocation/direct",
    receipt_refs: ["receipt://invocation/direct"],
  });
  assert.equal(calls.length, 0);
  assert.equal(modelMountCalls.at(-1).method, "planModelMountConversationState");
  assert.equal(modelMountCalls.at(-1).request.schema_version, "ioi.model_mount.conversation_state.v1");
  assert.equal(modelMountCalls.at(-1).request.operation, "model_conversation_state_write");
  assert.equal(Object.hasOwn(modelMountCalls.at(-1).request, "backend"), false);
  assert.equal(conversationPlan.source, "rust_daemon_core.model_mount.conversation_state");
  assert.equal(conversationPlan.record_id, "resp.direct");
  assert.equal(conversationPlan.rust_core_boundary, "model_mount.conversation");
  const streamCompletionPlan = store.modelMounting.planModelMountStreamCompletion({
    schema_version: "ioi.model_mount.stream_completion.v1",
    operation: "model_stream_completion",
    response_id: "resp.direct.stream",
    kind: "responses",
    stream_kind: "responses",
    source: "runtime-daemon.model_mounting.stream_completion",
    receipt_id: "receipt.stream.direct",
    current_sequence: 0,
    current_head_ref: "agentgres://model-mounting/accepted-receipts/head/0",
    current_state_root: "sha256:state-0",
    invocation_receipt_ref: "receipt://invocation/direct",
    route_decision_ref: "model_mount://route_decision/direct",
    route_ref: "route.direct",
    endpoint_ref: "endpoint.direct",
    provider_ref: "provider.direct",
    model_ref: "model.direct",
    chunks_forwarded: 2,
    receipt_refs: ["receipt://invocation/direct"],
  });
  assert.equal(calls.length, 0);
  assert.equal(modelMountCalls.at(-1).method, "planModelMountStreamCompletion");
  assert.equal(modelMountCalls.at(-1).request.schema_version, "ioi.model_mount.stream_completion.v1");
  assert.equal(modelMountCalls.at(-1).request.operation, "model_stream_completion");
  assert.equal(Object.hasOwn(modelMountCalls.at(-1).request, "backend"), false);
  assert.equal(streamCompletionPlan.source, "rust_daemon_core.model_mount.stream_completion");
  assert.equal(streamCompletionPlan.receipt.kind, "model_invocation_stream_completed");
  assert.equal(streamCompletionPlan.rust_core_boundary, "model_mount.conversation");
  const streamCancelPlan = store.modelMounting.planModelMountStreamCancel({
    schema_version: "ioi.model_mount.stream_cancel.v1",
    operation: "model_stream_cancel",
    response_id: "resp.direct.cancel",
    kind: "responses",
    stream_kind: "responses",
    source: "runtime-daemon.model_mounting.stream_cancel",
    receipt_id: "receipt.stream.cancel.direct",
    current_sequence: 1,
    current_head_ref: "agentgres://model-mounting/accepted-receipts/head/1",
    current_state_root: "sha256:state-1",
    invocation_receipt_ref: "receipt://invocation/direct",
    route_decision_ref: "model_mount://route_decision/direct",
    route_ref: "route.direct",
    endpoint_ref: "endpoint.direct",
    provider_ref: "provider.direct",
    model_ref: "model.direct",
    frames_written: 1,
    cancel_reason: "client_disconnect",
    receipt_refs: ["receipt://invocation/direct"],
  });
  assert.equal(calls.length, 0);
  assert.equal(modelMountCalls.at(-1).method, "planModelMountStreamCancel");
  assert.equal(modelMountCalls.at(-1).request.schema_version, "ioi.model_mount.stream_cancel.v1");
  assert.equal(modelMountCalls.at(-1).request.operation, "model_stream_cancel");
  assert.equal(Object.hasOwn(modelMountCalls.at(-1).request, "backend"), false);
  assert.equal(streamCancelPlan.source, "rust_daemon_core.model_mount.stream_cancel");
  assert.equal(streamCancelPlan.receipt.kind, "model_invocation_stream_canceled");
  assert.equal(streamCancelPlan.rust_core_boundary, "model_mount.conversation");
  const artifactEndpointPlan = store.modelMounting.planArtifactEndpoint({
    schema_version: "ioi.model_mount.artifact_endpoint.v1",
    operation_kind: "model_mount.endpoint.mount",
    source: "runtime-daemon.model_mounting.artifact_endpoint",
    body: {
      model_id: "model.direct",
      provider_id: "provider.direct",
    },
    receipt_refs: ["receipt://artifact-endpoint/direct"],
    authority_grant_refs: ["grant://wallet/artifact-endpoint-direct"],
    authority_receipt_refs: ["receipt://wallet/artifact-endpoint-direct"],
    custody_ref: "ctee://custody/artifact-endpoint-direct",
    required_scope: "model.endpoint.mount:model.direct",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountArtifactEndpoint",
    "ioi.model_mount.artifact_endpoint.v1",
  );
  assert.equal(artifactEndpointPlan.source, "direct_model_mount_api");
  assert.equal(artifactEndpointPlan.record_id, "endpoint.direct");
  assert.equal(artifactEndpointPlan.rust_core_boundary, "model_mount.artifact_endpoint");
  const catalogProviderPlan = store.modelMounting.planCatalogProviderControl({
    schema_version: "ioi.model_mount.catalog_provider_control.v1",
    operation_kind: "model_mount.catalog_provider_configuration.write",
    provider_id: "catalog.direct",
    source: "runtime-daemon.model_mounting.catalog_provider_control",
    body: { auth_header_name: "authorization" },
    receipt_refs: ["receipt://catalog-provider/direct"],
    authority_grant_refs: ["grant://wallet/catalog-provider-direct"],
    authority_receipt_refs: ["receipt://wallet/catalog-provider-direct"],
    custody_ref: "ctee://catalog-provider/direct",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountCatalogProviderControl",
    "ioi.model_mount.catalog_provider_control.v1",
  );
  assert.equal(catalogProviderPlan.source, "direct_model_mount_api");
  assert.equal(catalogProviderPlan.record_id, "catalog-provider-control.direct");
  assert.equal(catalogProviderPlan.rust_core_boundary, "model_mount.catalog_provider_control");
  const providerPlan = store.modelMounting.planModelMountProviderControl({
    schema_version: "ioi.model_mount.provider_control.v1",
    operation_kind: "model_mount.provider.write",
    provider_id: "provider.direct",
    source: "runtime-daemon.model_mounting.provider_control",
    body: { kind: "openai", secret_ref: "vault://provider/direct" },
    receipt_refs: ["receipt://provider/direct"],
    authority_grant_refs: ["grant://wallet/provider-direct"],
    authority_receipt_refs: ["receipt://wallet/provider-direct"],
    custody_ref: "ctee://provider/direct",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountProviderControl",
    "ioi.model_mount.provider_control.v1",
  );
  assert.equal(providerPlan.source, "direct_model_mount_api");
  assert.equal(providerPlan.record_id, "provider.direct");
  assert.equal(providerPlan.rust_core_boundary, "model_mount.provider_control");
  const capabilityPlan = store.modelMounting.planCapabilityTokenControl({
    schema_version: "ioi.model_mount.capability_token_control.v1",
    operation_kind: "model_mount.capability_token.create",
    source: "runtime-daemon.model_mounting.capability_token",
    body: { allowed: ["model.chat:*"] },
    receipt_refs: ["receipt://capability-token/direct"],
    authority_grant_refs: ["grant://wallet/capability-token-direct"],
    authority_receipt_refs: ["receipt://wallet/capability-token-direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountCapabilityTokenControl",
    "ioi.model_mount.capability_token_control.v1",
  );
  assert.equal(capabilityPlan.source, "direct_model_mount_api");
  assert.equal(capabilityPlan.record_id, "capability-token-control.direct");
  assert.equal(capabilityPlan.rust_core_boundary, "model_mount.capability_token");
  const vaultPlan = store.modelMounting.planVaultControl({
    schema_version: "ioi.model_mount.vault_control.v1",
    operation_kind: "model_mount.vault_ref.bind",
    source: "runtime-daemon.model_mounting.vault",
    vault_ref: "vault://provider/direct",
    material_hash: "sha256:direct-vault-material",
    body: { label: "Direct vault" },
    receipt_refs: ["receipt://vault/direct"],
    authority_grant_refs: ["grant://wallet/vault-direct"],
    authority_receipt_refs: ["receipt://wallet/vault-direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountVaultControl",
    "ioi.model_mount.vault_control.v1",
  );
  assert.equal(vaultPlan.source, "direct_model_mount_api");
  assert.equal(vaultPlan.record_id, "vault-control.direct");
  assert.equal(vaultPlan.rust_core_boundary, "model_mount.vault");
  const receiptGatePlan = store.modelMounting.planReceiptGate({
    schema_version: "ioi.model_mount.receipt_gate.v1",
    operation_kind: "workflow_receipt_gate",
    receipt_id: "receipt://route/direct",
    receipt: {
      id: "receipt://route/direct",
      kind: "model_route_selection",
      redaction: "redacted",
      details: {},
    },
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountReceiptGate",
    "ioi.model_mount.receipt_gate.v1",
  );
  assert.equal(receiptGatePlan.source, "direct_model_mount_api");
  assert.equal(receiptGatePlan.gate_hash, "sha256:direct-receipt-gate");
  assert.equal(receiptGatePlan.rust_core_boundary, "model_mount.receipt_gate");
  const acceptedHead = store.modelMounting.agentgresModelMountingHead();
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountAcceptedReceiptHead",
    "ioi.model_mount.accepted_receipt_head.v1",
  );
  assert.equal(acceptedHead.source, "rust_daemon_core.model_mount.accepted_receipt_head");
  assert.equal(acceptedHead.head_hash, "sha256:direct-head");
  const acceptedTransition = store.modelMounting.planModelMountAcceptedReceiptTransition({
    schema_version: "ioi.model_mount.accepted_receipt_transition.v1",
    current_sequence: 0,
    current_head_ref: "agentgres://model-mounting/accepted-receipts/head/0",
    current_state_root: "sha256:direct-state-root",
    receipt_id: "receipt.invoke.direct",
    receipt_kind: "model_invocation",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountAcceptedReceiptTransition",
    "ioi.model_mount.accepted_receipt_transition.v1",
  );
  assert.equal(
    acceptedTransition.operation_ref,
    "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation",
  );
  const receiptBinding = store.modelMounting.bindModelMountInvocationReceipt({
    invocation: { invocation_id: "model-invocation://direct" },
    result: { receipt_refs: ["receipt://invocation/direct"] },
    acceptedReceiptTransition: acceptedTransition.transition,
    receiptRef: "receipt://invocation/direct",
  });
  assert.equal(calls.length, 0);
  assert.equal(modelMountCalls.at(-1).method, "bindModelMountInvocationReceipt");
  assert.equal(Object.hasOwn(modelMountCalls.at(-1).request, "operation"), false);
  assert.equal(Object.hasOwn(modelMountCalls.at(-1).request, "backend"), false);
  assert.equal(receiptBinding.source, "rust_daemon_core.model_mount.invocation_receipt_binding");
  assert.equal(receiptBinding.receipt_binding.binding_hash, "sha256:direct-binding");
  const storagePlan = store.modelMounting.planStorageControl({
    schema_version: "ioi.model_mount.storage_control.v1",
    operation_kind: "model_mount.download.queue",
    source: "runtime-daemon.model_mounting.storage_control",
    body: {
      model_id: "local:direct",
      receipt_refs: ["receipt://storage/direct"],
    },
    receipt_refs: ["receipt://storage/direct"],
    authority_grant_refs: ["grant://wallet/storage-direct"],
    authority_receipt_refs: ["receipt://wallet/storage-direct"],
    required_scope: "model.download.queue:local:direct",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountStorageControl",
    "ioi.model_mount.storage_control.v1",
  );
  assert.equal(storagePlan.source, "direct_model_mount_api");
  assert.equal(storagePlan.record_id, "download.direct");
  assert.equal(storagePlan.rust_core_boundary, "model_mount.storage_control");
  const mcpPlan = store.modelMounting.planModelMountMcpWorkflow({
    schema_version: "ioi.model_mount.mcp_workflow.v1",
    operation_kind: "model_mount.mcp_server.import",
    source: "runtime-daemon.model_mounting.mcp_workflow",
    body: {
      mcp_servers: {
        Direct: {
          url: "https://example.test/mcp",
          allowed_tools: ["search"],
        },
      },
    },
    receipt_refs: ["receipt://mcp/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountMcpWorkflow",
    "ioi.model_mount.mcp_workflow.v1",
  );
  assert.equal(mcpPlan.source, "direct_model_mount_api");
  assert.equal(mcpPlan.record_id, "mcp_import.direct");
  assert.equal(mcpPlan.rust_core_boundary, "model_mount.mcp_workflow");
  const serverPlan = store.modelMounting.planServerControl({
    schema_version: "ioi.model_mount.server_control.v1",
    operation_kind: "model_mount.server_control.start",
    source: "runtime-daemon.model_mounting.server_control",
    server_control_id: "server-control.direct",
    body: {
      base_url: "http://daemon.direct",
    },
    receipt_refs: ["receipt://server-control/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountServerControl",
    "ioi.model_mount.server_control.v1",
  );
  assert.equal(serverPlan.source, "direct_model_mount_api");
  assert.equal(serverPlan.record_id, "server-control.direct");
  assert.equal(serverPlan.rust_core_boundary, "model_mount.server_control");
  const runtimeEnginePlan = store.modelMounting.planRuntimeEngine({
    schema_version: "ioi.model_mount.runtime_engine.v1",
    operation_kind: "model_mount.runtime_engine_profile.write",
    source: "runtime-daemon.model_mounting.runtime_engine",
    engine_id: "backend.direct",
    body: {
      engine_id: "backend.direct",
      default_load_options: { gpu_layers: 8 },
    },
    receipt_refs: ["receipt://runtime-engine/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountRuntimeEngine",
    "ioi.model_mount.runtime_engine.v1",
  );
  assert.equal(runtimeEnginePlan.source, "direct_model_mount_api");
  assert.equal(runtimeEnginePlan.record_id, "runtime-engine-control.direct");
  assert.equal(runtimeEnginePlan.rust_core_boundary, "model_mount.runtime_engine");
  const runtimeSurveyPlan = store.modelMounting.runtimeSurvey();
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountRuntimeSurvey",
    "ioi.model_mount.runtime_survey.v1",
  );
  assert.equal(modelMountCalls.at(-1).request.state_dir, stateDir);
  assert.equal(runtimeSurveyPlan.receiptId, "receipt_runtime_survey_direct");
  assert.equal(runtimeSurveyPlan.rustCoreBoundary, "model_mount.runtime_survey");
  assert.equal(agentgresCalls.at(-1).method, "commitRuntimeModelMountReceiptState");
  assert.equal(agentgresCalls.at(-1).request.state_dir, stateDir);
  assert.equal(
    agentgresCalls.at(-1).request.request.receipt_id,
    "receipt_runtime_survey_direct",
  );
  const projectionSummary = store.modelMounting.projectionSummary();
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountReadProjection",
    "ioi.model-mounting.runtime.v1",
  );
  assert.equal(modelMountCalls.at(-1).request.projection_kind, "projection_summary");
  assert.equal(modelMountCalls.at(-1).request.state_dir, stateDir);
  assert.equal(projectionSummary.source, "agentgres_model_mounting_projection");
  const memoryPlan = store.contextPolicyCore.planRuntimeMemoryControl({
    operation: "write",
    operation_kind: "memory.write",
    thread_id: "thread_direct",
    agent_id: "agent_direct",
    workspace_root: stateDir,
    state_dir: stateDir,
    request: { text: "direct memory" },
  });
  assert.equal(calls.length, 0);
  assert.equal(threadMemoryCalls.length, 1);
  assert.equal(threadMemoryCalls[0].method, "planRuntimeMemoryControl");
  assert.equal(
    threadMemoryCalls[0].request.schema_version,
    "ioi.runtime.memory-control-request.v1",
  );
  assert.equal(Object.hasOwn(threadMemoryCalls[0].request, "backend"), false);
  assert.notEqual(threadMemoryCalls[0].request.operation, "plan_runtime_memory_control");
  assert.equal(threadMemoryCalls[0].request.operation_kind, "memory.write");
  assert.equal(memoryPlan.source, "direct_thread_memory_api");
  assert.equal(memoryPlan.payload.id, "memory_direct");
  const queue = store.approvalStateCore.projectApprovalQueue({
    thread_id: "thread_direct",
    state_dir: stateDir,
  });
  assert.equal(calls.length, 0);
  assert.equal(approvalCalls.length, 1);
  assert.equal(approvalCalls[0].request.thread_id, "thread_direct");
  assert.equal(Object.hasOwn(approvalCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(approvalCalls[0].request, "backend"), false);
  assert.equal(queue.source, "direct_approval_api");
  assert.equal(queue.operation_kind, "approval.queue_projection");

  const commit = store.commitRuntimeRunState({
    schema_version: "ioi.runtime_run_state_commit.v1",
    run_id: "run_direct",
  });
  assert.equal(calls.length, 0);
  const runStateCommitCall = agentgresCalls.find((call) => call.method === "commitRuntimeRunState");
  assert.equal(runStateCommitCall.method, "commitRuntimeRunState");
  assert.equal(runStateCommitCall.request.state_dir, stateDir);
  assert.equal(runStateCommitCall.request.request.run_id, "run_direct");
  assert.equal(Object.hasOwn(runStateCommitCall.request, "operation"), false);
  assert.equal(Object.hasOwn(runStateCommitCall.request, "backend"), false);
  assert.equal(commit.source, "direct_agentgres_api");
  assert.equal(commit.commit_hash, "sha256:direct-agentgres-commit");

  assert.equal(governedAdmissionCalls.length, 1);
  assert.deepEqual(governedAdmissionCalls[0].context, {
    thread_id: "thread_direct",
    agent_id: "agent_direct",
  });
  assert.equal(Object.hasOwn(governedAdmissionCalls[0], "operation"), false);
  assert.equal(result.source, "direct_governed_admission_api");
  assert.equal(result.settlement_admitted, true);
  assert.equal(Object.hasOwn(result, "settlement_ref"), false);
  assert.equal(result.record.settlement_ref, "settlement://direct");
});
