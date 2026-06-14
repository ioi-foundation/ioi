import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import { createModelMountingReadProjectionFacade } from "./read-projection-facade.mjs";

function createState() {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-mount-read-"));
  writeConversationRecords(stateDir, [
    {
      id: "legacy-js-record",
      object: "ioi.model_mount_conversation_state",
      created_at: "2026-06-03T00:00:03.000Z",
    },
    {
      id: "resp-state",
      object: "ioi.model_mount_conversation_state",
      created_at: "2026-06-03T00:00:01.000Z",
      rust_core_boundary: "model_mount.conversation",
      conversation_hash: "sha256:conversation-state",
      evidence_refs: [
        "model_mount_conversation_state_rust_owned",
        "agentgres_model_conversation_truth_required",
      ],
    },
    {
      id: "resp-stream",
      object: "ioi.model_mount_conversation_state",
      created_at: "2026-06-03T00:00:02.000Z",
      rust_core_boundary: "model_mount.conversation",
      conversation_hash: "sha256:conversation-stream",
      evidence_refs: [
        "model_mount_stream_completion_rust_owned",
        "agentgres_model_conversation_truth_required",
      ],
    },
  ]);
  writeInstanceRecords(stateDir, [
    {
      id: "legacy-js-instance",
      schema_version: "ioi.model_mount.instance_lifecycle.v1",
      endpoint_id: "endpoint.local",
      model_id: "model.local",
      provider_id: "provider.local",
      action: "load",
      status: "loaded",
      execution_backend: "daemon_js",
      provider_lifecycle_hash: "sha256:provider",
      instance_lifecycle_hash: "sha256:legacy",
    },
    {
      id: "instance.loaded",
      schema_version: "ioi.model_mount.instance_lifecycle.v1",
      endpoint_id: "endpoint.local",
      model_id: "model.local",
      provider_id: "provider.local",
      action: "load",
      status: "loaded",
      execution_backend: "rust_model_mount_instance_lifecycle",
      provider_lifecycle_hash: "sha256:provider",
      instance_lifecycle_hash: "sha256:loaded",
      evidence_refs: [
        "rust_model_mount_instance_lifecycle",
        "agentgres_model_instance_registry_planned",
      ],
    },
    {
      id: "instance.old",
      schema_version: "ioi.model_mount.instance_lifecycle.v1",
      endpoint_id: "endpoint.local",
      model_id: "model.local",
      provider_id: "provider.local",
      action: "evict",
      status: "evicted",
      execution_backend: "rust_model_mount_instance_lifecycle",
      provider_lifecycle_hash: "sha256:provider",
      instance_lifecycle_hash: "sha256:evicted",
      evidence_refs: [
        "rust_model_mount_instance_lifecycle",
        "agentgres_model_instance_registry_planned",
      ],
    },
  ]);
  writeProviderInventoryRecords(stateDir, [
    {
      id: "legacy-js-provider-inventory",
      object: "ioi.model_mount_provider_inventory",
      schema_version: "ioi.model_mount.provider_inventory.v1",
      provider_ref: "provider://legacy",
      provider_kind: "local_folder",
      action: "list_models",
      operation_kind: "model_mount.provider.inventory.list_models",
      status: "listed",
      backend: "ioi_fixture",
      backend_id: "backend.fixture",
      driver: "fixture",
      execution_backend: "daemon_js",
      item_refs: ["model://legacy"],
      item_count: 1,
      inventory_hash: "sha256:legacy-provider-inventory",
      record_dir: "model-provider-inventory",
      record_id: "legacy-js-provider-inventory",
      rust_core_boundary: "daemon_js",
      source: "runtime-daemon.provider_inventory_js",
      evidence_refs: ["legacy_js_provider_inventory"],
    },
    {
      id: "provider_inventory_fixture_list_models",
      object: "ioi.model_mount_provider_inventory",
      schema_version: "ioi.model_mount.provider_inventory.v1",
      provider_ref: "provider://fixture",
      provider_kind: "local_folder",
      action: "list_models",
      operation_kind: "model_mount.provider.inventory.list_models",
      status: "listed",
      backend: "ioi_fixture",
      backend_id: "backend.fixture",
      driver: "fixture",
      execution_backend: "rust_model_mount_fixture_inventory",
      item_refs: ["model://fixture/qwen3"],
      item_count: 1,
      inventory_hash: "sha256:fixture-provider-inventory",
      record_dir: "model-provider-inventory",
      record_id: "provider_inventory_fixture_list_models",
      receipt_refs: [],
      rust_core_boundary: "model_mount.provider_inventory",
      source: "rust_model_mount_provider_inventory_command",
      evidence_refs: [
        "rust_model_mount_provider_inventory",
        "agentgres_provider_inventory_truth_required",
        "rust_model_mount_fixture_inventory_backend",
      ],
    },
    {
      id: "provider_inventory_native_list_loaded",
      object: "ioi.model_mount_provider_inventory",
      schema_version: "ioi.model_mount.provider_inventory.v1",
      provider_ref: "provider://native",
      provider_kind: "ioi_native_local",
      action: "list_loaded",
      operation_kind: "model_mount.provider.inventory.list_loaded",
      status: "listed",
      backend: "autopilot.native_local.fixture",
      backend_id: "backend.autopilot.native-local.fixture",
      driver: "native_local",
      execution_backend: "rust_model_mount_native_local_inventory",
      item_refs: ["model_instance://native/qwen3"],
      item_count: 1,
      inventory_hash: "sha256:native-provider-inventory",
      record_dir: "model-provider-inventory",
      record_id: "provider_inventory_native_list_loaded",
      receipt_refs: [],
      rust_core_boundary: "model_mount.provider_inventory",
      source: "rust_model_mount_provider_inventory_command",
      evidence_refs: [
        "rust_model_mount_provider_inventory",
        "agentgres_provider_inventory_truth_required",
        "rust_model_mount_native_local_inventory_backend",
      ],
    },
  ]);
  writeProviderControlRecords(stateDir, [
    {
      id: "legacy-js-provider",
      record_id: "legacy-js-provider",
      schema_version: "ioi.model_mount.provider_control.v1",
      object: "ioi.model_mount_provider",
      status: "configured",
      operation_kind: "model_mount.provider.write",
      source: "runtime-daemon.provider_js",
      provider_id: "provider.legacy",
      provider_ref: "provider://legacy",
      kind: "openai",
      rust_core_boundary: "daemon_js",
      control_hash: "sha256:legacy",
      plaintext_material_returned: false,
      evidence_refs: ["legacy_js_provider_control"],
    },
    {
      id: "provider.openai",
      record_id: "provider.openai",
      schema_version: "ioi.model_mount.provider_control.v1",
      object: "ioi.model_mount_provider",
      status: "configured",
      operation_kind: "model_mount.provider.write",
      source: "rust_model_mount_provider_control_command",
      provider_id: "provider.openai",
      provider_ref: "provider://openai",
      kind: "openai",
      label: "OpenAI",
      api_format: "openai",
      driver: "hosted_provider",
      base_url: "https://api.openai.example/v1",
      privacy_class: "hosted_private",
      capabilities: ["chat", "responses"],
      auth_scheme: "bearer",
      auth_header_name: "Authorization",
      secret_ref: "vault://provider/openai",
      rust_core_boundary: "model_mount.provider_control",
      wallet_authority_boundary: "wallet.network.provider_control",
      ctee_custody_boundary: "ctee.provider_material",
      plaintext_material_returned: false,
      authority: {
        authority_hash: "sha256:authority:provider.openai",
        required_scope: "provider.write:provider.openai",
        authority_grant_refs: ["wallet://grant/provider-control"],
        authority_receipt_refs: ["receipt://wallet/provider-control"],
      },
      control_hash: "sha256:control:provider.openai",
      evidence_refs: [
        "rust_daemon_core_provider_control",
        "wallet_network_provider_control_authority_required",
        "wallet_network_vault_authority_required",
        "ctee_provider_custody_enforced",
        "agentgres_provider_control_truth_required",
        "public_provider_control_js_facade_retired",
      ],
    },
  ]);
  writeTokenizerRecords(stateDir, [
    {
      id: "legacy-js-tokenizer",
      object: "ioi.model_mount_tokenizer_result",
      status: "planned",
      operation: "tokenize",
      source: "runtime-daemon.tokenizer_js",
      rust_core_boundary: "daemon_js",
      route_selection_boundary: "model_mount.route_selection",
      route_id: "route.local-first",
      model: "model.local",
      endpoint_id: "endpoint.local",
      provider_id: "provider.local",
      input_hash: "sha256:legacy",
      token_count: 1,
      control_hash: "sha256:legacy",
      evidence_refs: ["legacy_js_tokenizer"],
    },
    {
      id: "model_tokenizer:count_tokens:test",
      object: "ioi.model_mount_tokenizer_result",
      status: "planned",
      operation: "count_tokens",
      source: "rust_model_mount_tokenizer_command",
      rust_core_boundary: "model_mount.tokenizer",
      route_selection_boundary: "model_mount.route_selection",
      route_id: "route.local-first",
      model: "model.local",
      endpoint_id: "endpoint.local",
      provider_id: "provider.local",
      input_hash: "sha256:count",
      tokens: ["hello"],
      token_count: 1,
      usage: { prompt_tokens: 1, total_tokens: 1 },
      receipt_refs: ["receipt://route-selection"],
      control_hash: "sha256:count",
      evidence_refs: [
        "model_mount_tokenizer_rust_owned",
        "agentgres_model_tokenizer_truth_required",
      ],
    },
    {
      id: "model_tokenizer:tokenize:test",
      object: "ioi.model_mount_tokenizer_result",
      status: "planned",
      operation: "tokenize",
      source: "rust_model_mount_tokenizer_command",
      rust_core_boundary: "model_mount.tokenizer",
      route_selection_boundary: "model_mount.route_selection",
      route_id: "route.local-first",
      model: "model.local",
      endpoint_id: "endpoint.local",
      provider_id: "provider.local",
      input_hash: "sha256:tokenize",
      tokens: ["hello", "world"],
      token_count: 2,
      usage: { prompt_tokens: 2, total_tokens: 2 },
      receipt_refs: ["receipt://route-selection"],
      control_hash: "sha256:tokenize",
      evidence_refs: [
        "model_mount_tokenizer_rust_owned",
        "agentgres_model_tokenizer_truth_required",
      ],
    },
  ]);
  writeRouteRecords(stateDir, [
    {
      id: "legacy-js-route",
      role: "legacy",
      status: "active",
      updatedAt: "2026-06-03T00:00:00.000Z",
      receiptRefs: ["receipt://legacy-route"],
      routeControl: {
        rust_core_boundary: "daemon_js",
        evidence_refs: ["legacy_js_route_writer"],
      },
    },
    {
      id: "route.local-first",
      role: "default",
      description: "Rust-authored model route.",
      privacy: "local_or_enterprise",
      quality: "adaptive",
      maxCostUsd: 0.25,
      maxLatencyMs: 30000,
      providerEligibility: ["local_folder"],
      fallback: ["endpoint.local"],
      deniedProviders: [],
      status: "active",
      receiptRefs: ["receipt://model-mount/route-control/write"],
      authorityReceiptRefs: [],
      updatedAt: "2026-06-03T00:00:00.000Z",
      routeControl: {
        source: "runtime-daemon.model_mounting.route_control",
        operation_kind: "model_mount.route.write",
        rust_core_boundary: "model_mount.route_control",
        evidence_refs: [
          "model_mount_route_control_rust_owned",
          "rust_daemon_core_route_control_plan",
          "agentgres_route_truth_required",
        ],
      },
    },
    {
      id: "route.research",
      role: "research",
      description: "Rust-authored research route.",
      privacy: "local_or_enterprise",
      quality: "adaptive",
      maxCostUsd: 0.5,
      maxLatencyMs: 1500,
      providerEligibility: ["local_folder"],
      fallback: ["endpoint.research"],
      deniedProviders: [],
      status: "active",
      receiptRefs: ["receipt://model-mount/route-control/research"],
      authorityReceiptRefs: [],
      updatedAt: "2026-06-03T00:00:01.000Z",
      routeControl: {
        source: "runtime-daemon.model_mounting.route_control",
        operation_kind: "model_mount.route.write",
        rust_core_boundary: "model_mount.route_control",
        evidence_refs: [
          "model_mount_route_control_rust_owned",
          "rust_daemon_core_route_control_plan",
          "agentgres_route_truth_required",
        ],
      },
    },
  ]);
  writeRouteSelectionRecords(stateDir, [
    {
      id: "legacy-js-selection",
      object: "ioi.model_mount_route_selection",
      route_id: "route.js",
      selected_model: "model.js",
      endpoint_id: "endpoint.js",
      provider_id: "provider.js",
      rust_core_boundary: "daemon_js",
      route_selection_boundary: "model_mount.route_selection",
      evidence_refs: ["legacy_js_route_decision"],
    },
    {
      id: "route_selection:route.local-first:test",
      object: "ioi.model_mount_route_selection",
      route_id: "route.local-first",
      selected_model: "model.local",
      endpoint_id: "endpoint.local",
      provider_id: "provider.local",
      capability: "chat",
      policy_hash: "sha256:policy",
      receipt_refs: ["receipt://route-control/select"],
      evidence_refs: [
        "model_mount_route_control_rust_owned",
        "rust_daemon_core_route_control_plan",
        "agentgres_route_truth_required",
      ],
      rust_core_boundary: "model_mount.route_control",
      route_selection_boundary: "model_mount.route_selection",
      selected_at: "2026-06-03T00:00:02.000Z",
      route_decision: {
        route_decision_ref: "model_mount://route_decision/route.local-first",
        route_ref: "route.local-first",
        endpoint_ref: "endpoint.local",
        provider_ref: "provider.local",
        model_ref: "model.local",
      },
      accepted_receipt_record: {
        id: "receipt-route",
        kind: "model_route_selection",
        createdAt: "2026-06-03T00:00:02.000Z",
      },
    },
  ]);
  writeRouteEndpointResolutionRecords(stateDir, [
    {
      id: "legacy-js-resolution",
      object: "ioi.model_mount_explicit_model_endpoints",
      route_id: "route.js",
      model_id: "model.js",
      endpoint_ids: ["endpoint.js"],
      rust_core_boundary: "daemon_js",
      route_selection_boundary: "model_mount.route_selection",
      evidence_refs: ["legacy_js_endpoint_resolution"],
    },
    {
      id: "route_endpoint_resolution:route.local-first:test",
      object: "ioi.model_mount_explicit_model_endpoints",
      route_id: "route.local-first",
      model_id: "model.local",
      endpoint_ids: ["endpoint.local"],
      endpoints: [{ id: "endpoint.local", providerId: "provider.local", modelId: "model.local" }],
      receipt_refs: ["receipt://route-control/explicit-endpoints"],
      evidence_refs: [
        "model_mount_route_control_rust_owned",
        "rust_daemon_core_route_control_plan",
        "agentgres_route_truth_required",
      ],
      rust_core_boundary: "model_mount.route_control",
      route_selection_boundary: "model_mount.route_selection",
      source: "runtime-daemon.model_mounting.route_control",
      resolved_at: "2026-06-03T00:00:03.000Z",
    },
  ]);
  writeStorageRecords(stateDir, "model-downloads", [
    {
      id: "legacy-js-download",
      record_id: "legacy-js-download",
      schema_version: "ioi.model_mount.storage_control.v1",
      object: "ioi.model_mount_download",
      status: "queued",
      operation_kind: "model_mount.download.queue",
      rust_core_boundary: "daemon_js",
      details: {
        job_id: "legacy-js-download",
        model_id: "legacy",
      },
      evidence_refs: ["legacy_js_download_truth"],
      control_hash: "sha256:legacy",
      authority_hash: "sha256:legacy",
    },
    storageRecordFixture({
      id: "download.qwen3",
      object: "ioi.model_mount_download",
      operationKind: "model_mount.download.queue",
      status: "queued",
      details: {
        job_id: "download.qwen3",
        model_id: "qwen3",
        bytes_total: 42,
        network_transfer_executed: false,
        plaintext_source_url_returned: false,
      },
      evidenceRefs: [
        "public_catalog_download_js_facade_retired",
        "rust_daemon_core_catalog_download",
        "agentgres_catalog_download_truth_required",
      ],
    }),
  ]);
  writeStorageRecords(stateDir, "model-catalog-imports", [
    storageRecordFixture({
      id: "catalog_import.qwen3",
      object: "ioi.model_mount_catalog_import",
      operationKind: "model_mount.catalog.import_url",
      status: "planned",
      details: {
        model_id: "qwen3",
        source_url_hash: "sha256:source",
        network_transfer_executed: false,
        plaintext_source_url_returned: false,
      },
      evidenceRefs: [
        "public_catalog_download_js_facade_retired",
        "rust_daemon_core_catalog_download",
        "agentgres_catalog_download_truth_required",
      ],
    }),
  ]);
  writeStorageRecords(stateDir, "model-storage-controls", [
    storageRecordFixture({
      id: "storage_cleanup.qwen3",
      object: "ioi.model_mount_storage_control",
      operationKind: "model_mount.storage.cleanup",
      status: "cleanup_planned",
      details: {
        remove_orphans: true,
        filesystem_mutation_executed: false,
      },
      evidenceRefs: ["rust_daemon_core_model_storage_cleanup"],
    }),
  ]);
  writeRuntimeEngineControlRecords(stateDir, [
    {
      id: "legacy-js-runtime-engine",
      schema_version: "ioi.model_mount.runtime_engine_plan.v1",
      object: "ioi.model_mount_runtime_engine_record",
      engine_id: "backend.legacy",
      operation_kind: "model_mount.runtime_engine_profile.write",
      status: "planned",
      source: "runtime-daemon.runtime_engine_js",
      generated_at: "2026-06-03T00:00:00.000Z",
      rust_core_boundary: "daemon_js",
      control_hash: "sha256:legacy-runtime-engine",
      evidence_refs: ["legacy_js_runtime_engine"],
    },
    {
      id: "runtime-engine-control:preference",
      schema_version: "ioi.model_mount.runtime_engine_plan.v1",
      object: "ioi.model_mount_runtime_engine_record",
      engine_id: "backend.llama-cpp",
      operation_kind: "model_mount.runtime_preference.write",
      status: "planned",
      source: "runtime-daemon.model_mounting.runtime_engine",
      generated_at: "2026-06-03T00:00:01.000Z",
      rust_core_boundary: "model_mount.runtime_engine",
      control_hash: "sha256:runtime-engine-preference",
      public_response: {
        object: "ioi.model_mount_runtime_engine",
        status: "planned",
        engine_id: "backend.llama-cpp",
        rust_core_boundary: "model_mount.runtime_engine",
        operation_kind: "model_mount.runtime_preference.write",
        selected_engine_id: "backend.llama-cpp",
        js_preference_write: false,
        js_profile_write: false,
        js_projection_write: false,
      },
      receipt_refs: ["receipt://runtime-engine/preference"],
      evidence_refs: [
        "public_runtime_engine_js_facade_retired",
        "rust_daemon_core_runtime_engine",
        "agentgres_runtime_engine_truth_required",
      ],
    },
    {
      id: "runtime-engine-control:profile",
      schema_version: "ioi.model_mount.runtime_engine_plan.v1",
      object: "ioi.model_mount_runtime_engine_record",
      engine_id: "backend.llama-cpp",
      operation_kind: "model_mount.runtime_engine_profile.write",
      status: "planned",
      source: "runtime-daemon.model_mounting.runtime_engine",
      generated_at: "2026-06-03T00:00:02.000Z",
      rust_core_boundary: "model_mount.runtime_engine",
      control_hash: "sha256:runtime-engine-profile",
      public_response: {
        object: "ioi.model_mount_runtime_engine",
        status: "planned",
        engine_id: "backend.llama-cpp",
        rust_core_boundary: "model_mount.runtime_engine",
        operation_kind: "model_mount.runtime_engine_profile.write",
        profile_recorded: true,
        default_load_options: { gpu_layers: 4 },
        operator_label: "Native local",
        js_preference_write: false,
        js_profile_write: false,
        js_projection_write: false,
      },
      receipt_refs: ["receipt://runtime-engine/profile"],
      evidence_refs: [
        "public_runtime_engine_js_facade_retired",
        "rust_daemon_core_runtime_engine",
        "agentgres_runtime_engine_truth_required",
      ],
    },
    {
      id: "runtime-engine-control:deleted-profile",
      schema_version: "ioi.model_mount.runtime_engine_plan.v1",
      object: "ioi.model_mount_runtime_engine_record",
      engine_id: "backend.deleted",
      operation_kind: "model_mount.runtime_engine_profile.write",
      status: "planned",
      source: "runtime-daemon.model_mounting.runtime_engine",
      generated_at: "2026-06-03T00:00:03.000Z",
      rust_core_boundary: "model_mount.runtime_engine",
      control_hash: "sha256:runtime-engine-deleted-profile",
      public_response: {
        object: "ioi.model_mount_runtime_engine",
        status: "planned",
        engine_id: "backend.deleted",
        rust_core_boundary: "model_mount.runtime_engine",
        operation_kind: "model_mount.runtime_engine_profile.write",
        profile_recorded: true,
      },
      evidence_refs: [
        "public_runtime_engine_js_facade_retired",
        "rust_daemon_core_runtime_engine",
        "agentgres_runtime_engine_truth_required",
      ],
    },
    {
      id: "runtime-engine-control:deleted",
      schema_version: "ioi.model_mount.runtime_engine_plan.v1",
      object: "ioi.model_mount_runtime_engine_record",
      engine_id: "backend.deleted",
      operation_kind: "model_mount.runtime_engine_profile.delete",
      status: "planned",
      source: "runtime-daemon.model_mounting.runtime_engine",
      generated_at: "2026-06-03T00:00:04.000Z",
      rust_core_boundary: "model_mount.runtime_engine",
      control_hash: "sha256:runtime-engine-deleted",
      public_response: {
        object: "ioi.model_mount_runtime_engine",
        status: "planned",
        engine_id: "backend.deleted",
        rust_core_boundary: "model_mount.runtime_engine",
        operation_kind: "model_mount.runtime_engine_profile.delete",
        profile_deleted: true,
      },
      evidence_refs: [
        "public_runtime_engine_js_facade_retired",
        "rust_daemon_core_runtime_engine",
        "agentgres_runtime_engine_truth_required",
      ],
    },
  ]);
  writeBackendLifecycleControlRecords(stateDir, [
    {
      id: "legacy-js-backend-lifecycle",
      schema_version: "ioi.model_mount.backend_lifecycle_plan.v1",
      object: "ioi.model_mount_backend_lifecycle_record",
      backend_id: "backend.legacy",
      backend_kind: "legacy",
      operation_kind: "model_mount.backend.health",
      status: "planned",
      source: "runtime-daemon.backend_lifecycle_js",
      generated_at: "2026-06-03T00:00:00.000Z",
      rust_core_boundary: "daemon_js",
      control_hash: "sha256:legacy-backend",
      evidence_refs: ["legacy_js_backend_lifecycle"],
    },
    {
      id: "backend-lifecycle-control:native-start",
      schema_version: "ioi.model_mount.backend_lifecycle_plan.v1",
      object: "ioi.model_mount_backend_lifecycle_record",
      backend_id: "backend.native",
      backend_kind: "native_local",
      operation_kind: "model_mount.backend.start",
      status: "planned",
      source: "runtime-daemon.model_mounting.backend_lifecycle",
      generated_at: "2026-06-03T00:00:01.000Z",
      rust_core_boundary: "model_mount.backend_lifecycle",
      control_hash: "sha256:backend-native-start",
      public_response: {
        object: "ioi.model_mount_backend_lifecycle",
        status: "planned",
        backend_id: "backend.native",
        backend_kind: "native_local",
        operation_kind: "model_mount.backend.start",
        rust_core_boundary: "model_mount.backend_lifecycle",
        backend_status: "start_planned",
        js_backend_registry_read: false,
        js_process_control: false,
        js_log_read: false,
        js_log_write: false,
      },
      receipt_refs: ["receipt://backend/native/start", "sha256:backend-native-start"],
      evidence_refs: [
        "public_backend_lifecycle_js_facade_retired",
        "rust_daemon_core_backend_lifecycle",
        "agentgres_backend_lifecycle_truth_required",
      ],
    },
    {
      id: "backend-lifecycle-control:ollama-stop",
      schema_version: "ioi.model_mount.backend_lifecycle_plan.v1",
      object: "ioi.model_mount_backend_lifecycle_record",
      backend_id: "backend.ollama",
      backend_kind: "ollama",
      operation_kind: "model_mount.backend.stop",
      status: "planned",
      source: "runtime-daemon.model_mounting.backend_lifecycle",
      generated_at: "2026-06-03T00:00:02.000Z",
      rust_core_boundary: "model_mount.backend_lifecycle",
      control_hash: "sha256:backend-ollama-stop",
      public_response: {
        object: "ioi.model_mount_backend_lifecycle",
        status: "planned",
        backend_id: "backend.ollama",
        backend_kind: "ollama",
        operation_kind: "model_mount.backend.stop",
        rust_core_boundary: "model_mount.backend_lifecycle",
        backend_status: "stop_planned",
        js_backend_registry_read: false,
        js_process_control: false,
        js_log_read: false,
        js_log_write: false,
      },
      receipt_refs: ["receipt://backend/ollama/stop", "sha256:backend-ollama-stop"],
      evidence_refs: [
        "public_backend_lifecycle_js_facade_retired",
        "rust_daemon_core_backend_lifecycle",
        "agentgres_backend_lifecycle_truth_required",
      ],
    },
    {
      id: "backend-lifecycle-control:retired-logs-read",
      schema_version: "ioi.model_mount.backend_lifecycle_plan.v1",
      object: "ioi.model_mount_backend_lifecycle_record",
      backend_id: "backend.native",
      backend_kind: "native_local",
      operation_kind: "model_mount.backend.logs_read",
      status: "planned",
      source: "runtime-daemon.model_mounting.backend_lifecycle",
      generated_at: "2026-06-03T00:00:03.000Z",
      rust_core_boundary: "model_mount.backend_lifecycle",
      control_hash: "sha256:backend-native-logs-read",
      public_response: {
        object: "ioi.model_mount_backend_lifecycle",
        status: "planned",
        backend_id: "backend.native",
        backend_kind: "native_local",
        operation_kind: "model_mount.backend.logs_read",
        rust_core_boundary: "model_mount.backend_lifecycle",
        logs: [],
        count: 0,
      },
      receipt_refs: ["receipt://backend/native/logs-read", "sha256:backend-native-logs-read"],
      evidence_refs: [
        "public_backend_lifecycle_js_facade_retired",
        "rust_daemon_core_backend_lifecycle",
        "agentgres_backend_lifecycle_truth_required",
      ],
    },
  ]);
  writeServerControlRecords(stateDir, [
    {
      id: "legacy-js-server-control",
      schema_version: "ioi.model_mount.server_control_plan.v1",
      object: "ioi.model_mount_server_control_record",
      server_control_id: "server-control.default",
      operation_kind: "model_mount.server_control.start",
      status: "planned",
      source: "runtime-daemon.server_control_js",
      generated_at: "2026-06-03T00:00:00.000Z",
      rust_core_boundary: "daemon_js",
      control_hash: "sha256:legacy-server-control",
      evidence_refs: ["legacy_js_server_control"],
    },
    {
      id: "server-control:native-start",
      schema_version: "ioi.model_mount.server_control_plan.v1",
      object: "ioi.model_mount_server_control_record",
      server_control_id: "server-control.default",
      operation_kind: "model_mount.server_control.start",
      status: "planned",
      source: "runtime-daemon.model_mounting.server_control",
      generated_at: "2026-06-03T00:00:01.000Z",
      rust_core_boundary: "model_mount.server_control",
      control_hash: "sha256:server-start",
      public_response: {
        object: "ioi.model_mount_server_control",
        status: "planned",
        operation_kind: "model_mount.server_control.start",
        server_control_id: "server-control.default",
        rust_core_boundary: "model_mount.server_control",
        server_status: "start_planned",
        js_state_write: false,
        js_log_write: false,
        js_transport_execution: false,
      },
      receipt_refs: ["receipt://server/start", "sha256:server-start"],
      evidence_refs: [
        "public_server_control_js_facade_retired",
        "rust_daemon_core_server_control",
        "agentgres_server_control_truth_required",
      ],
    },
    {
      id: "server-control:record-operation",
      schema_version: "ioi.model_mount.server_control_plan.v1",
      object: "ioi.model_mount_server_control_record",
      server_control_id: "server-control.default",
      operation_kind: "model_mount.server_control.record_operation",
      status: "planned",
      source: "runtime-daemon.model_mounting.server_control",
      generated_at: "2026-06-03T00:00:02.000Z",
      rust_core_boundary: "model_mount.server_control",
      control_hash: "sha256:server-record-operation",
      public_response: {
        object: "ioi.model_mount_server_control",
        status: "planned",
        operation_kind: "model_mount.server_control.record_operation",
        server_control_id: "server-control.default",
        rust_core_boundary: "model_mount.server_control",
        operation: "server_stop",
        operation_status: "blocked",
        operation_recorded: true,
        js_state_write: false,
        js_log_write: false,
        js_transport_execution: false,
      },
      receipt_refs: ["receipt://server/operation", "sha256:server-record-operation"],
      evidence_refs: [
        "public_server_control_js_facade_retired",
        "rust_daemon_core_server_control",
        "agentgres_server_control_truth_required",
      ],
    },
  ]);
  writeProviderLifecycleRecords(stateDir, [
    {
      id: "provider-lifecycle-health",
      record_id: "provider-lifecycle-health",
      object: "ioi.model_mount_provider_lifecycle",
      schema_version: "ioi.model_mount.provider_lifecycle_plan.v1",
      provider_ref: "provider://provider.local",
      provider_kind: "ioi_native_local",
      endpoint_ref: "endpoint://endpoint.local",
      model_ref: "model://model.local",
      action: "health",
      operation_kind: "model_mount.provider.health",
      status: "healthy",
      backend: "autopilot.native_local.fixture",
      backend_id: "backend.autopilot.native-local.fixture",
      driver: "native_local",
      execution_backend: "rust_model_mount_native_local_lifecycle",
      lifecycle_hash: "sha256:provider-lifecycle-health",
      record_dir: "model-provider-lifecycle-controls",
      rust_core_boundary: "model_mount.provider_lifecycle",
      source: "rust_model_mount_provider_lifecycle_command",
      generated_at: "2026-06-03T00:00:03.000Z",
      evidence_refs: [
        "public_provider_lifecycle_js_facade_retired",
        "rust_model_mount_provider_lifecycle",
        "agentgres_provider_lifecycle_truth_required",
      ],
    },
  ]);
  const receipts = [
    {
      id: "receipt-route",
      kind: "model_route_selection",
      details: {
        model_route_decision: { route_id: "route.local-first", selected_model: "model.local" },
        route_id: "route.local-first",
        endpoint_id: "endpoint.local",
        provider_id: "provider.local",
      },
    },
    { id: "receipt-lifecycle", kind: "model_lifecycle", details: {} },
    {
      id: "receipt-provider-health",
      kind: "provider_health",
      details: {
        provider_id: "provider.local",
        status: "stale-js-receipt",
      },
    },
    {
      id: "receipt-vault-health",
      kind: "vault_adapter_health",
      details: {
        status: "healthy",
        implementation: "runtime_memory_vault",
      },
    },
    {
      id: "receipt-runtime",
      kind: "runtime_engine_profile",
      details: {
        runtime_engine_id: "backend.llama-cpp",
      },
    },
  ];
  writeReceiptRecords(stateDir, receipts);
  const state = {
    stateDir,
    artifacts: new Map([
      ["artifact.fixture", { id: "artifact.fixture", modelId: "fixture", family: "fixture", capabilities: ["chat"], discoveredAt: "2026-06-03T00:00:01.000Z" }],
      ["artifact.local", { id: "artifact.local", modelId: "model.local", family: "local", capabilities: ["chat"], discoveredAt: "2026-06-03T00:00:02.000Z" }],
    ]),
    downloads: new Map([["download.one", { id: "download.one", createdAt: "2026-06-03T00:00:01.000Z" }]]),
    endpoints: new Map([["endpoint.local", {
      id: "endpoint.local",
      modelId: "model.local",
      providerId: "provider.local",
      status: "mounted",
      capabilities: ["chat"],
      privacyClass: "local_private",
      lastReceiptId: "receipt-endpoint",
    }]]),
    instances: new Map(),
    conversations: new Map([
      ["legacy-js-record", {
        id: "legacy-js-record",
        object: "ioi.model_mount_conversation_state",
        created_at: "2026-06-03T00:00:03.000Z",
      }],
      ["resp-state", {
        id: "resp-state",
        object: "ioi.model_mount_conversation_state",
        created_at: "2026-06-03T00:00:01.000Z",
        rust_core_boundary: "model_mount.conversation",
        conversation_hash: "sha256:conversation-state",
        evidence_refs: [
          "model_mount_conversation_state_rust_owned",
          "agentgres_model_conversation_truth_required",
        ],
      }],
      ["resp-stream", {
        id: "resp-stream",
        object: "ioi.model_mount_conversation_state",
        created_at: "2026-06-03T00:00:02.000Z",
        rust_core_boundary: "model_mount.conversation",
        conversation_hash: "sha256:conversation-stream",
        evidence_refs: [
          "model_mount_stream_completion_rust_owned",
          "agentgres_model_conversation_truth_required",
        ],
      }],
    ]),
    oauthSessions: new Map(),
    oauthStates: new Map(),
    providers: new Map([["provider.local", {
      id: "provider.local",
      kind: "local",
      status: "running",
      secretRef: "vault://provider.local/api-key",
      lastReceiptId: "receipt-provider",
    }]]),
    routes: new Map([["route.local-first", {
      id: "route.local-first",
      role: "default",
      status: "active",
      fallback: ["endpoint.local"],
      privacy: "local_private",
      providerEligibility: ["provider.local"],
      deniedProviders: [],
      maxCostUsd: 0,
      maxLatencyMs: 1000,
    }]]),
    runtimeEngineProfiles: new Map([["backend.llama-cpp", {
      id: "backend.llama-cpp",
      label: "llama.cpp",
      priority: 1,
      defaultLoadOptions: { gpu: "auto" },
      updatedAt: "2026-06-03T00:00:00.000Z",
      receiptId: "receipt-runtime",
      source: "operator_runtime_engine_profile",
    }]]),
    runtimeSelections: new Map([["default", {
      id: "default",
      selectedEngineId: "backend.llama-cpp",
      selectedAt: "2026-06-03T00:00:00.000Z",
      receiptId: "receipt-runtime",
      source: "operator_runtime_engine_preference",
    }]]),
    vault: {
      vaultRefMetadata(secretRef) {
        return { secretRef, configured: true };
      },
      adapterStatus() {
        return { port: "VaultPort" };
      },
    },
    walletAuthority: {
      adapterStatus() {
        return { port: "WalletAuthorityPort", remoteAdapter: { configured: false } };
      },
    },
    store: {
      adapterStatus() {
        return { port: "AgentgresStorePort" };
      },
    },
    evictExpiredInstances() {},
    coalesceLoadedInstances() {},
    nowIso: () => "2026-06-03T00:00:00.000Z",
    serverStatus: () => ({ status: "running" }),
    lastCatalogSearch: {
      searchedAt: "2026-06-03T00:00:00.000Z",
      query: "local",
      filters: { limit: 2 },
      results: [{ id: "catalog.local", modelId: "model.local" }],
    },
    catalogProviderPorts: () => [{
      id: "catalog.fixture",
      label: "Fixture catalog",
      status: "available",
      formats: ["gguf"],
      evidenceRefs: ["provider_neutral_model_catalog_adapter_boundary"],
    }],
    storageSummary: () => ({
      rootHash: "sha256:model-root",
      totalBytes: 42,
      quotaBytes: null,
      quotaStatus: "ok",
      fileCount: 1,
      orphanCount: 0,
      destructiveActionsRequireUnload: true,
      evidenceRefs: ["model_storage_quota_boundary", "artifact_delete_unload_guard"],
    }),
    listBackends: () => {
      throw new Error("broad read-projection input must not read JS backend registry");
    },
    listBackendProcesses: () => {
      throw new Error("broad read-projection input must not read JS backend process maps");
    },
    listCatalogProviderConfigs: () => [],
    listConversations: () => {
      throw new Error("broad read-projection input must not read JS conversation state maps");
    },
    listMcpServers: () => {
      throw new Error("broad read-projection input must not read JS MCP server maps");
    },
    listReceipts: () => receipts,
    getReceipt: (receiptId) => receipts.find((receipt) => receipt.id === receiptId),
    provider(providerId) {
      const provider = this.providers.get(providerId);
      if (!provider) throw Object.assign(new Error(`Provider not found: ${providerId}`), { status: 404 });
      return provider;
    },
    backendRegistry: () => [{
      id: "backend.llama-cpp",
      kind: "llama_cpp",
      label: "llama.cpp",
      status: "configured",
      supportedFormats: ["gguf"],
      processStatus: "stopped",
      evidenceRefs: ["receipt-runtime"],
    }],
    listRuntimeEngineProfiles: () => {
      throw new Error("broad read-projection input must not read JS runtime engine profiles");
    },
    listRuntimeEngines: () => {
      throw new Error("broad read-projection input must not read JS runtime engine lists");
    },
    listTokens: () => [],
    listVaultRefs: () => [],
    latestRuntimeSurvey: () => null,
    lmStudioRuntimeEngines: () => [],
    runtimePreference: () => {
      throw new Error("broad read-projection input must not read JS runtime preference");
    },
    vaultStatus: () => ({ port: "VaultPort" }),
    workflowNodeBindings: () => [],
  };
  const readProjectionRequests = [];
  const readProjectionPlanner = {
    planReadProjection(request) {
      readProjectionRequests.push(request);
      return {
        source: "rust_model_mount_read_projection_command",
        backend: "rust_model_mount_read_projection",
        projection_kind: request.projection_kind,
        projection: rustProjectionFixture(request),
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
      };
    },
  };
  const facade = createModelMountingReadProjectionFacade({
    modelMountSchemaVersion: "model.mount.schema",
    readProjectionPlanner,
    notFound: (message, details) => Object.assign(new Error(message), {
      status: 404,
      code: "not_found",
      details,
    }),
  });
  for (const key of Object.keys(facade)) {
    state[key] = (...args) => facade[key](state, ...args);
  }
  return { facade, state, readProjectionPlanner, readProjectionRequests };
}

function rustProjectionFixture(request) {
  const state = request.state;
  const receipts = receiptRecordsFromAgentgresStateDir(request.state_dir);
  if (request.projection_kind === "artifacts") {
    return artifactRecordsFromAgentgresStateDir(request.state_dir, "ioi.model_mount_model_artifact");
  }
  if (request.projection_kind === "product_artifacts") {
    return artifactRecordsFromAgentgresStateDir(request.state_dir, "ioi.product_model_artifact");
  }
  if (request.projection_kind === "providers") {
    return providerRecordsFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "endpoints") {
    return endpointRecordsFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "instances") {
    return instanceRecordsFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "provider_inventory_records") {
    return providerInventoryRecordsFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "catalog_search") {
    return catalogSearchFromAgentgresStateDir(request);
  }
  if (request.projection_kind === "model_tokenizer_records") {
    return tokenizerRecordsFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "routes") {
    return routeRecordsFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "model_route_decisions") {
    return routeDecisionsFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "model_route_endpoint_resolutions") {
    return routeEndpointResolutionsFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "model_capabilities") {
    return modelCapabilitiesFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "downloads") return downloadRecordsFromAgentgresStateDir(request.state_dir);
  if (request.projection_kind === "download_status") {
    const download = downloadRecordsFromAgentgresStateDir(request.state_dir)
      .find((record) =>
        record.id === request.download_id ||
        record.record_id === request.download_id ||
        record.details?.job_id === request.download_id);
    if (!download) {
      throw Object.assign(new Error("download job not found"), {
        code: "model_mount_download_not_found",
      });
    }
    return download;
  }
  if (request.projection_kind === "storage_summary") {
    return storageSummaryFromAgentgresStateDir(request);
  }
  if (request.projection_kind === "backends") return backendRecordsFromAgentgresStateDir(request.state_dir);
  if (request.projection_kind === "backend_logs") return backendLogsFromRustRequest(request);
  if (request.projection_kind === "oauth_sessions" || request.projection_kind === "oauth_states") return [];
  if (request.projection_kind === "provider_health") {
    return providerHealthFromLifecycleRecords(request);
  }
  if (request.projection_kind === "server_status") return serverStatusFromRustRequest(request);
  if (request.projection_kind === "server_logs") return serverLogsFromRustRequest(request);
  if (request.projection_kind === "server_events") return serverEventsFromRustRequest(request);
  if (request.projection_kind === "server_log_records") return serverLogRecordsFromRustRequest(request);
  if (request.projection_kind === "workflow_bindings") return workflowBindingsFromRust();
  if (request.projection_kind === "adapter_boundaries") return adapterBoundariesFromState(state);
  if (request.projection_kind === "runtime_engines") {
    return runtimeEngineListFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "runtime_engine_profiles") {
    return runtimeEngineProfilesFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "runtime_preference") {
    return runtimePreferenceFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "runtime_preference_for_endpoint") {
    return runtimePreferenceFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "runtime_default_load_options") {
    return runtimeDefaultLoadOptionsFromAgentgresStateDir(request.state_dir, request.engine_id);
  }
  if (request.projection_kind === "runtime_engine_detail") {
    return runtimeEngineDetailFromAgentgresStateDir(request.state_dir, request.engine_id);
  }
  if (request.projection_kind === "latest_runtime_survey") return latestRuntimeSurveyFromReceipts(receipts);
  if (request.projection_kind === "catalog_status") {
    return catalogStatusFromAgentgresStateDir(request.state_dir, request.schema_version, request.generated_at);
  }
  if (request.projection_kind === "runtime_model_catalog") {
    return runtimeModelCatalogFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "open_ai_model_list") {
    return openAiModelListFromAgentgresStateDir(request.state_dir);
  }
  if (request.projection_kind === "model_conversation_states") {
    return conversationStatesFromAgentgresStateDir(request.state_dir);
  }
  const projection = {
    schemaVersion: request.schema_version,
    source: "agentgres_model_mounting_projection",
    generatedAt: request.generated_at,
    watermark: receipts.length,
    artifacts: artifactRecordsFromAgentgresStateDir(request.state_dir, "ioi.model_mount_model_artifact"),
    productArtifacts: artifactRecordsFromAgentgresStateDir(request.state_dir, "ioi.product_model_artifact"),
    endpoints: endpointRecordsFromAgentgresStateDir(request.state_dir),
    instances: instanceRecordsFromAgentgresStateDir(request.state_dir),
    routes: routeRecordsFromAgentgresStateDir(request.state_dir),
    modelCapabilities: [],
    runtimeModelCatalog: runtimeModelCatalogFromAgentgresStateDir(request.state_dir),
    openAiModelList: openAiModelListFromAgentgresStateDir(request.state_dir),
    backends: backendRecordsFromAgentgresStateDir(request.state_dir),
    backendProcesses: [],
    providers: providerRecordsFromAgentgresStateDir(request.state_dir),
    catalog: catalogStatusFromAgentgresStateDir(request.state_dir, request.schema_version, request.generated_at),
    oauthSessions: [],
    oauthStates: [],
    downloads: downloadRecordsFromAgentgresStateDir(request.state_dir),
    providerHealth: providerHealthFromLifecycleRecords(request),
    runtimeEngines: [],
    runtimeEngineProfiles: [],
    runtimePreference: null,
    runtimeSurvey: latestRuntimeSurveyFromReceipts(receipts),
    grants: state.grants ?? [],
    vaultRefs: state.vault_refs ?? [],
    mcpServers: [],
    conversationStates: [],
    workflowBindings: workflowBindingsFromRust(),
    adapterBoundaries: adapterBoundariesFromState(state),
    lifecycleEvents: receipts.filter((receipt) => receipt.kind === "model_lifecycle"),
    routeReceipts: receipts.filter((receipt) => receipt.kind === "model_route_selection"),
    routeDecisions: routeDecisionsFromAgentgresStateDir(request.state_dir ?? null),
    providerLifecycleRecords: providerLifecycleRecordsFromAgentgresStateDir(request.state_dir),
    runtimeSurveyReceipts: receipts.filter((receipt) => receipt.kind === "runtime_survey"),
    invocationReceipts: receipts.filter((receipt) => receipt.kind === "model_invocation"),
    toolReceipts: receipts.filter((receipt) => receipt.kind === "mcp_tool_invocation"),
    receipts,
  };
  if (request.projection_kind === "snapshot") {
    return {
      schemaVersion: request.schema_version,
      server: serverStatusFromRustRequest(request),
      catalog: catalogStatusFromAgentgresStateDir(request.state_dir, request.schema_version, request.generated_at),
      oauthSessions: [],
      oauthStates: [],
      artifacts: [],
      productArtifacts: [],
      backends: [],
      backendProcesses: [],
      endpoints: [],
      instances: [],
      providers: [],
      routes: [],
      modelCapabilities: [],
      runtimeModelCatalog: [],
      openAiModelList: { object: "list", data: [] },
      downloads: downloadRecordsFromAgentgresStateDir(request.state_dir),
      providerHealth: providerHealthFromLifecycleRecords(request),
      runtimeEngines: [],
      runtimeEngineProfiles: [],
      runtimePreference: null,
      runtimeSurvey: latestRuntimeSurveyFromReceipts(receipts),
      tokens: state.grants ?? [],
      vaultRefs: state.vault_refs ?? [],
      mcpServers: [],
      conversationStates: [],
      workflowNodes: workflowBindingsFromRust(),
      receipts: receipts.slice(-25),
      projection: {
        schemaVersion: projection.schemaVersion,
        source: projection.source,
        watermark: projection.watermark,
        receiptCount: projection.receipts.length,
        generatedAt: projection.generatedAt,
      },
      adapterBoundaries: projection.adapterBoundaries,
    };
  }
  if (request.projection_kind === "projection") return projection;
  if (request.projection_kind === "projection_summary") {
    return {
      schemaVersion: projection.schemaVersion,
      source: projection.source,
      watermark: projection.watermark,
      receiptCount: projection.receipts.length,
      generatedAt: projection.generatedAt,
    };
  }
  if (request.projection_kind === "model_route_decisions") return projection.routeDecisions;
  if (request.projection_kind === "authority_snapshot") {
    const authorityReceipts = receipts.filter((receipt) =>
      [
        "permission_token",
        "permission_token_revocation",
        "vault_ref_binding",
        "vault_ref_removal",
        "vault_adapter_health",
      ].includes(receipt.kind),
    ).slice(-25);
    return {
      schemaVersion: "ioi.wallet-core-lite.authority.v1",
      source: "agentgres_wallet_authority_projection",
      generatedAt: request.generated_at,
      server: serverStatusFromRustRequest(request),
      wallet: state.wallet ?? null,
      vault: state.vault ?? null,
      grants: state.grants ?? [],
      vaultRefs: state.vault_refs ?? [],
      approvals: [],
      approvalQueue: {
        status: "not_configured",
        pendingCount: 0,
        evidenceRefs: ["wallet.network.approval_queue.pending_runtime_adapter"],
      },
      receipts: authorityReceipts,
      summary: {
        activeGrants: 0,
        revokedGrants: 0,
        vaultRefs: (state.vault_refs ?? []).length,
        pendingApprovals: 0,
        receiptCount: authorityReceipts.length,
        remoteWalletConfigured: false,
      },
    };
  }
  if (request.projection_kind === "latest_provider_health") {
    const record = [...providerLifecycleRecordsFromAgentgresStateDir(request.state_dir)].reverse()
      .find((candidate) =>
        candidate.action === "health" &&
        providerIdFromRef(candidate.provider_ref) === request.provider_id);
    if (!record) {
      throw Object.assign(new Error("provider health has not been checked"), {
        code: "model_mount_provider_health_not_found",
      });
    }
    return {
      schemaVersion: request.schema_version,
      source: "agentgres_provider_lifecycle_health_latest",
      providerId: request.provider_id,
      health: providerHealthEnvelope(record),
      record,
      receipt: null,
      replay: {
        schemaVersion: request.schema_version,
        source: "agentgres_provider_lifecycle_projection_replay",
        record,
        receipt: null,
        projectionWatermark: providerLifecycleRecordsFromAgentgresStateDir(request.state_dir).length,
      },
      projectionWatermark: providerLifecycleRecordsFromAgentgresStateDir(request.state_dir).length,
    };
  }
  if (request.projection_kind === "latest_vault_health") {
    const receipt = receipts.filter((candidate) => candidate.kind === "vault_adapter_health").at(-1);
    return {
      schemaVersion: request.schema_version,
      source: "agentgres_vault_health_latest",
      health: receipt.details,
      receipt,
      replay: {
        schemaVersion: request.schema_version,
        source: "agentgres_model_mounting_projection_replay",
        receipt,
        projectionWatermark: projection.watermark,
      },
      projectionWatermark: projection.watermark,
    };
  }
  if (request.projection_kind === "receipt_replay") {
    const receipt = receipts.find((candidate) => candidate.id === request.receipt_id);
    return {
      schemaVersion: request.schema_version,
      source: "agentgres_model_mounting_projection_replay",
      receipt,
      model_route_decision: receipt.details?.model_route_decision ?? null,
      route: null,
      endpoint: null,
      instance: null,
      provider: null,
      toolReceipts: [],
      projectionWatermark: projection.watermark,
    };
  }
  throw new Error(`unsupported projection fixture: ${request.projection_kind}`);
}

function providerHealthFromLifecycleRecords(request) {
  const records = providerLifecycleRecordsFromAgentgresStateDir(request.state_dir);
  const projectionWatermark = records.length;
  return records
    .filter((record) => record.action === "health" && record.operation_kind === "model_mount.provider.health")
    .map((record) => ({
      schemaVersion: request.schema_version,
      source: "agentgres_provider_lifecycle_health",
      providerId: providerIdFromRef(record.provider_ref),
      health: providerHealthEnvelope(record),
      record,
      receipt: null,
      replay: {
        schemaVersion: request.schema_version,
        source: "agentgres_provider_lifecycle_projection_replay",
        record,
        receipt: null,
        projectionWatermark,
      },
      projectionWatermark,
    }));
}

function providerHealthEnvelope(record) {
  return {
    provider_id: providerIdFromRef(record.provider_ref),
    provider_ref: record.provider_ref,
    provider_kind: record.provider_kind,
    status: record.status,
    action: record.action,
    backend: record.backend,
    backend_id: record.backend_id,
    driver: record.driver,
    execution_backend: record.execution_backend,
    operation_kind: record.operation_kind,
    rust_core_boundary: record.rust_core_boundary,
    lifecycle_hash: record.lifecycle_hash,
    evidence_refs: record.evidence_refs ?? [],
  };
}

function providerIdFromRef(providerRef) {
  return String(providerRef ?? "").replace(/^provider:\/\//, "");
}

function latestRuntimeSurveyFromReceipts(receipts = []) {
  const receipt = [...receipts].reverse()
    .find((candidate) => candidate.kind === "runtime_survey");
  if (!receipt) {
    return {
      status: "not_checked",
      receiptId: "none",
      checkedAt: null,
      engineCount: 0,
      selectedEngines: [],
      runtimePreference: null,
      hardware: null,
      lmStudio: { status: "not_checked", evidenceRefs: ["runtime_survey_not_checked"] },
    };
  }
  return {
    status: "checked",
    receiptId: receipt.id,
    checkedAt: receipt.details?.checked_at ?? receipt.createdAt,
    engineCount: receipt.details?.engine_count ?? 0,
    selectedEngines: receipt.details?.selected_engines ?? [],
    runtimePreference: receipt.details?.runtime_preference ?? null,
    hardware: receipt.details?.hardware ?? null,
    lmStudio: receipt.details?.lm_studio ?? { status: "unknown" },
  };
}

function serverStatusFromRustRequest(request) {
  const baseUrl = request.base_url ?? null;
  const serverControls = serverControlRecordsFromAgentgresStateDir(request.state_dir);
  const backendRecords = backendRecordsFromAgentgresStateDir(request.state_dir);
  const providerRecords = providerRecordsFromAgentgresStateDir(request.state_dir);
  const instanceRecords = instanceRecordsFromAgentgresStateDir(request.state_dir);
  const endpointRecords = endpointRecordsFromAgentgresStateDir(request.state_dir);
  const latest = serverControls.at(-1) ?? null;
  const publicResponse = latest?.public_response ?? {};
  const lastReceipt = latest?.receipt_refs?.find((ref) => !String(ref).startsWith("sha256:")) ??
    latest?.receipt_refs?.[0] ??
    null;
  return {
    schemaVersion: request.schema_version,
    status: publicResponse.server_status ?? publicResponse.operation_status ?? latest?.status ?? "stopped",
    gatewayStatus: "running",
    controlStatus: "running",
    lastServerOperation: publicResponse.operation ?? latest?.operation_kind ?? "server_status",
    lastServerOperationAt: latest?.generated_at ?? null,
    lastServerReceiptId: lastReceipt,
    nativeBaseUrl: baseUrl ? `${baseUrl}/api/v1` : "/api/v1",
    openAiCompatibleBaseUrl: baseUrl ? `${baseUrl}/v1` : "/v1",
    loadedInstances: instanceRecords.length,
    mountedEndpoints: endpointRecords.length,
    providerStates: {
      available: providerRecords.length,
      degraded: 0,
    },
    backendStates: {
      available: backendRecords.filter((record) => record.status !== "stop_planned").length,
      degraded: backendRecords.filter((record) => record.status === "stop_planned").length,
    },
    idleTtlSeconds: 900,
    autoEvict: true,
    checkedAt: request.generated_at ?? null,
    source: "agentgres_server_control",
    recordDir: "model-server-controls",
    recordCount: serverControls.length,
    rustCoreBoundary: "model_mount.server_control_projection",
    evidenceRefs: [
      "rust_daemon_core_server_control_projection",
      "agentgres_server_control_replay_required",
      "model_mount_server_status_js_projection_retired",
    ],
  };
}

function serverLogsFromRustRequest(request) {
  const records = serverControlLogEntriesFromAgentgresRequest(request);
  const serverControls = serverControlRecordsFromAgentgresStateDir(request.state_dir);
  return {
    schemaVersion: request.schema_version,
    object: "ioi.model_mount_server_logs",
    status: "projected",
    projectionKind: "server_logs",
    redaction: "redacted",
    records,
    count: records.length,
    receiptId: records.at(-1)?.receiptId ?? null,
    source: "agentgres_server_control",
    recordDir: "model-server-controls",
    recordCount: serverControls.length,
    rustCoreBoundary: "model_mount.server_control_log_projection",
    evidenceRefs: serverLogProjectionEvidenceRefs(),
  };
}

function serverEventsFromRustRequest(request) {
  const records = serverControlLogEntriesFromAgentgresRequest(request);
  const serverControls = serverControlRecordsFromAgentgresStateDir(request.state_dir);
  return {
    schemaVersion: request.schema_version,
    object: "ioi.model_mount_server_events",
    status: "projected",
    events: records.map((record) => ({
      event: record.event,
      timestamp: record.timestamp,
      level: record.level,
      operation_kind: record.operation_kind,
      receiptId: record.receiptId,
      record_id: record.record_id,
      rust_core_boundary: "model_mount.server_control_log_projection",
    })),
    count: records.length,
    receiptId: records.at(-1)?.receiptId ?? null,
    source: "agentgres_server_control",
    recordDir: "model-server-controls",
    recordCount: serverControls.length,
    rustCoreBoundary: "model_mount.server_control_log_projection",
    evidenceRefs: serverLogProjectionEvidenceRefs(),
  };
}

function serverLogRecordsFromRustRequest(request) {
  return {
    ...serverLogsFromRustRequest(request),
    projectionKind: "server_log_records",
  };
}

function serverControlLogEntriesFromAgentgresRequest(request) {
  const limit = Math.min(Number.parseInt(String(request.state?.server_log_query?.limit ?? 80), 10) || 80, 500);
  const records = serverControlRecordsFromAgentgresStateDir(request.state_dir);
  return records.slice(Math.max(records.length - limit, 0)).map((record) => {
    const publicResponse = record.public_response ?? {};
    const event = publicResponse.event ?? publicResponse.operation ?? serverControlEvent(record.operation_kind);
    return {
      event,
      level: publicResponse.level ?? (publicResponse.operation_status === "blocked" ? "warn" : "info"),
      message: publicResponse.message ?? event.split("_").join(" "),
      timestamp: record.generated_at,
      operation_kind: record.operation_kind,
      operation_status: publicResponse.operation_status ?? record.status,
      server_control_id: record.server_control_id,
      receiptId: record.receipt_refs?.find((ref) => !String(ref).startsWith("sha256:")) ?? record.receipt_refs?.[0] ?? null,
      receipt_refs: record.receipt_refs ?? [],
      record_dir: "model-server-controls",
      record_id: record.id,
      control_hash: record.control_hash,
      source: record.source,
      rust_core_boundary: "model_mount.server_control_log_projection",
      evidence_refs: serverLogProjectionEvidenceRefs(),
    };
  });
}

function serverControlEvent(operationKind) {
  return {
    "model_mount.server_control.start": "server_start",
    "model_mount.server_control.stop": "server_stop",
    "model_mount.server_control.restart": "server_restart",
    "model_mount.server_control.write": "server_control_state_write",
    "model_mount.server_control.record_operation": "server_operation_recorded",
    "model_mount.server_control.log_append": "server_log_appended",
  }[operationKind] ?? "server_control_recorded";
}

function serverLogProjectionEvidenceRefs() {
  return [
    "rust_daemon_core_server_control_log_projection",
    "agentgres_server_control_log_replay_required",
    "model_mount_server_log_read_js_control_path_retired",
  ];
}

function catalogStatusFromAgentgresStateDir(stateDir, schemaVersion, generatedAt) {
  const records = providerInventoryRecordsFromAgentgresStateDir(stateDir);
  const providers = catalogProviderStatusesFromInventory(records);
  const results = catalogStatusResultsFromInventory(records);
  if (!stateDir) {
    return {
      schemaVersion,
      checkedAt: null,
      providers: [],
      adapterBoundary: {
        port: "ModelCatalogProviderPort",
        operations: ["search", "resolveVariant", "importUrl", "download", "health"],
        evidenceRefs: ["provider_neutral_model_catalog_adapter_boundary"],
      },
      filters: {
        formats: ["gguf", "mlx", "safetensors"],
        quantization: ["Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "F16", "BF16", "IQ"],
        compatibility: ["native_local_fixture", "llama_cpp", "ollama", "vllm", "mlx"],
      },
      storage: null,
      lastSearch: null,
      results: [],
    };
  }
  return {
    schemaVersion,
    checkedAt: generatedAt ?? null,
    providers,
    adapterBoundary: {
      port: "ModelCatalogProviderPort",
      operations: ["search", "resolveVariant", "importUrl", "download", "health"],
      evidenceRefs: ["provider_neutral_model_catalog_adapter_boundary"],
    },
    filters: {
      formats: ["gguf", "mlx", "safetensors"],
      quantization: ["Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "F16", "BF16", "IQ"],
      compatibility: ["native_local_fixture", "llama_cpp", "ollama", "vllm", "mlx"],
    },
    storage: {
      object: "ioi.model_catalog_storage_status",
      source: "agentgres_provider_inventory",
      record_dir: "model-provider-inventory",
      record_count: records.length,
      rust_core_boundary: "model_mount.catalog_status",
      evidence_refs: catalogStatusEvidenceRefs(),
    },
    lastSearch: {
      object: "ioi.model_catalog_status_last_search",
      source: "agentgres_provider_inventory",
      query: "",
      provider_count: providers.length,
      inventory_record_count: records.length,
      result_count: results.length,
      rust_core_boundary: "model_mount.catalog_status",
      evidence_refs: catalogStatusEvidenceRefs(),
    },
    results,
    source: "agentgres_provider_inventory",
    rust_core_boundary: "model_mount.catalog_status",
    evidence_refs: catalogStatusEvidenceRefs(),
  };
}

function catalogProviderStatusesFromInventory(records) {
  const providerRefs = [...new Set(records.map((record) => record.provider_ref).filter(Boolean))].sort();
  return providerRefs.map((providerRef) => {
    const providerRecords = records.filter((record) => record.provider_ref === providerRef);
    const [first] = providerRecords;
    return {
      id: providerRef,
      object: "ioi.model_catalog_provider_status",
      provider_ref: providerRef,
      provider_kind: first.provider_kind,
      backend: first.backend,
      backend_id: first.backend_id,
      driver: first.driver,
      status: "available",
      actions: [...new Set(providerRecords.map((record) => record.action).filter(Boolean))].sort(),
      inventory_record_ids: [...new Set(providerRecords.map((record) => record.record_id).filter(Boolean))].sort(),
      inventory_hashes: [...new Set(providerRecords.map((record) => record.inventory_hash).filter(Boolean))].sort(),
      model_count: providerRecords
        .filter((record) => record.action === "list_models")
        .reduce((count, record) => count + (record.item_refs?.length ?? 0), 0),
      loaded_instance_count: providerRecords
        .filter((record) => record.action === "list_loaded")
        .reduce((count, record) => count + (record.item_refs?.length ?? 0), 0),
      source: "agentgres_provider_inventory",
      rust_core_boundary: "model_mount.catalog_status",
      evidence_refs: catalogStatusEvidenceRefs(),
    };
  });
}

function catalogStatusResultsFromInventory(records) {
  return records
    .filter((record) => record.action === "list_models")
    .flatMap((record) => (record.item_refs ?? []).map((itemRef) => ({
      id: `catalog_status_${recordIdSegment(record.record_id, "record")}_${recordIdSegment(itemRef, "model")}`,
      object: "ioi.model_catalog_status_result",
      model_ref: itemRef,
      model_id: modelIdFromItemRef(itemRef),
      provider_ref: record.provider_ref,
      provider_kind: record.provider_kind,
      backend: record.backend,
      backend_id: record.backend_id,
      driver: record.driver,
      inventory_record_id: record.record_id,
      inventory_hash: record.inventory_hash,
      source: "agentgres_provider_inventory",
      rust_core_boundary: "model_mount.catalog_status",
      evidence_refs: catalogStatusEvidenceRefs(),
    })))
    .sort((left, right) =>
      String(left.model_ref ?? "").localeCompare(String(right.model_ref ?? "")) ||
      String(left.provider_ref ?? "").localeCompare(String(right.provider_ref ?? "")));
}

function catalogStatusEvidenceRefs() {
  return [
    "rust_daemon_core_catalog_status_projection",
    "agentgres_catalog_status_replay_required",
    "agentgres_provider_inventory_truth_required",
    "model_catalog_status_js_readback_retired",
  ];
}

function adapterBoundariesFromState(state) {
  void state;
  return {
    wallet: {
      port: "WalletAuthorityPort",
      implementation: "wallet_network_authority",
      methods: ["authorizeCapabilityExit", "listTokens", "revokeToken", "adapterStatus"],
      evidenceRefs: [
        "wallet.network.authority_boundary",
        "rust_daemon_core_wallet_authority_projection_required",
      ],
    },
    vault: {
      port: "VaultPort",
      implementation: "ctee_private_workspace_vault",
      methods: ["bindVaultRef", "resolveVaultRef", "listVaultRefs", "removeVaultRef", "adapterStatus"],
      plaintextPersistence: false,
      evidenceRefs: [
        "ctee_no_plaintext_custody_boundary",
        "rust_daemon_core_vault_projection_required",
      ],
    },
    oauth: {
      port: "OAuthCredentialProvider",
      implementation: "agentgres_vault_oauth_session",
      methods: [
        "startAuthorization",
        "completeAuthorization",
        "exchangeAuthorizationCode",
        "refreshAccessToken",
        "revokeSession",
        "resolveAccessHeader",
      ],
      plaintextPersistence: false,
      evidenceRefs: [
        "OAuthCredentialProvider",
        "VaultOAuthAuthorizationState",
        "VaultOAuthSession",
        "oauth_tokens_not_persisted",
      ],
    },
    agentgres: {
      port: "AgentgresStorePort",
      implementation: "agentgres_admitted_model_mounting_store",
      methods: ["appendAcceptedReceipt", "recordState", "expectedHeads", "adapterStatus"],
      evidenceRefs: [
        "agentgres_model_mount_read_truth_required",
        "rust_daemon_core_agentgres_projection_required",
      ],
    },
  };
}

function workflowBindingsFromRust() {
  return [
    ["Model Call", "chat"],
    ["Structured Output", "responses"],
    ["Verifier", "chat"],
    ["Planner", "chat"],
    ["Embedding", "embeddings"],
    ["Reranker", "rerank"],
    ["Vision", "vision"],
    ["Local Tool/MCP", "mcp"],
    ["Model Router", "chat"],
    ["Receipt Gate", "receipt_gate"],
  ].map(([node, capability]) => ({
    node,
    modelId: null,
    supportsExplicitModelId: true,
    supportsModelPolicy: true,
    capability,
    receiptRequired: true,
    routeId: "route.local-first",
    daemonApi: node === "Receipt Gate" ? "/api/v1/workflows/receipt-gate" : "/api/v1/workflows/nodes/execute",
  }));
}

function writeConversationRecords(stateDir, records = []) {
  const conversationDir = path.join(stateDir, "model-conversations");
  fs.mkdirSync(conversationDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(conversationDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeInstanceRecords(stateDir, records = []) {
  const instanceDir = path.join(stateDir, "model-instances");
  fs.mkdirSync(instanceDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(instanceDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeProviderInventoryRecords(stateDir, records = []) {
  const providerInventoryDir = path.join(stateDir, "model-provider-inventory");
  fs.mkdirSync(providerInventoryDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(providerInventoryDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeProviderLifecycleRecords(stateDir, records = []) {
  const providerLifecycleDir = path.join(stateDir, "model-provider-lifecycle-controls");
  fs.mkdirSync(providerLifecycleDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(providerLifecycleDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeProviderControlRecords(stateDir, records = []) {
  const providerDir = path.join(stateDir, "model-providers");
  fs.mkdirSync(providerDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(providerDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeTokenizerRecords(stateDir, records = []) {
  const tokenizerDir = path.join(stateDir, "model-tokenizer-utilities");
  fs.mkdirSync(tokenizerDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(tokenizerDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeRouteRecords(stateDir, records = []) {
  const routeDir = path.join(stateDir, "model-routes");
  fs.mkdirSync(routeDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(routeDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeRouteSelectionRecords(stateDir, records = []) {
  const routeSelectionDir = path.join(stateDir, "model-route-selections");
  fs.mkdirSync(routeSelectionDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(routeSelectionDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeRouteEndpointResolutionRecords(stateDir, records = []) {
  const endpointResolutionDir = path.join(stateDir, "model-route-endpoint-resolutions");
  fs.mkdirSync(endpointResolutionDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(endpointResolutionDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeStorageRecords(stateDir, recordDirName, records = []) {
  const recordDir = path.join(stateDir, recordDirName);
  fs.mkdirSync(recordDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(recordDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeRuntimeEngineControlRecords(stateDir, records = []) {
  const recordDir = path.join(stateDir, "runtime-engine-controls");
  fs.mkdirSync(recordDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(recordDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeBackendLifecycleControlRecords(stateDir, records = []) {
  const recordDir = path.join(stateDir, "model-backend-lifecycle-controls");
  fs.mkdirSync(recordDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(recordDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeServerControlRecords(stateDir, records = []) {
  const recordDir = path.join(stateDir, "model-server-controls");
  fs.mkdirSync(recordDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(recordDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function writeReceiptRecords(stateDir, records = []) {
  const recordDir = path.join(stateDir, "receipts");
  fs.mkdirSync(recordDir, { recursive: true });
  for (const record of records) {
    fs.writeFileSync(
      path.join(recordDir, `${record.id}.json`),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  }
}

function receiptRecordsFromAgentgresStateDir(stateDir) {
  if (typeof stateDir !== "string" || stateDir.length === 0) return [];
  const recordDir = path.join(stateDir, "receipts");
  if (!fs.existsSync(recordDir)) return [];
  return fs.readdirSync(recordDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(recordDir, file), "utf8")))
    .filter((record) => typeof record?.id === "string" && typeof record?.kind === "string")
    .sort((left, right) =>
      String(left.createdAt ?? left.created_at ?? left.generated_at ?? "").localeCompare(
        String(right.createdAt ?? right.created_at ?? right.generated_at ?? ""),
      ) ||
      String(left.id ?? "").localeCompare(String(right.id ?? "")));
}

function storageRecordFixture({
  id,
  object,
  operationKind,
  status,
  details,
  evidenceRefs = [],
}) {
  const allEvidenceRefs = [
    "public_model_storage_js_facade_retired",
    "rust_daemon_core_model_storage",
    "agentgres_model_storage_truth_required",
    ...evidenceRefs,
  ];
  return {
    id,
    record_id: id,
    schema_version: "ioi.model_mount.storage_control.v1",
    object,
    status,
    operation_kind: operationKind,
    source: "runtime-daemon.model_mounting.storage_control",
    generated_at: "2026-06-03T00:00:00.000Z",
    rust_core_boundary: "model_mount.storage_control",
    details,
    authority: {
      wallet_authority_boundary: "wallet.network.model_mount_storage",
      ctee_custody_boundary: "ctee.model_mount_storage",
      plaintext_material_returned: false,
    },
    public_response: {
      object,
      status,
      id,
      record_id: id,
      operation_kind: operationKind,
      rust_core_boundary: "model_mount.storage_control",
      details,
      js_filesystem_mutation_executed: false,
      js_network_transfer_executed: false,
    },
    receipt_refs: ["receipt://storage/test"],
    evidence_refs: allEvidenceRefs,
    control_hash: `sha256:control:${id}`,
    authority_hash: `sha256:authority:${id}`,
  };
}

function instanceRecordsFromAgentgresStateDir(stateDir) {
  if (!stateDir) return [];
  const instanceDir = path.join(stateDir, "model-instances");
  if (!fs.existsSync(instanceDir)) return [];
  return fs.readdirSync(instanceDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(instanceDir, file), "utf8")))
    .filter((record) =>
      record?.schema_version === "ioi.model_mount.instance_lifecycle.v1" &&
      record?.deleted !== true &&
      typeof record?.id === "string" &&
      typeof record?.endpoint_id === "string" &&
      typeof record?.model_id === "string" &&
      typeof record?.provider_id === "string" &&
      typeof record?.action === "string" &&
      typeof record?.status === "string" &&
      record?.execution_backend === "rust_model_mount_instance_lifecycle" &&
      typeof record?.provider_lifecycle_hash === "string" &&
      typeof record?.instance_lifecycle_hash === "string" &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("rust_model_mount_instance_lifecycle") &&
      record.evidence_refs.includes("agentgres_model_instance_registry_planned"))
    .sort((left, right) =>
      String(left.id ?? "").localeCompare(String(right.id ?? "")) ||
      String(left.status ?? "").localeCompare(String(right.status ?? "")));
}

function providerInventoryRecordsFromAgentgresStateDir(stateDir) {
  if (!stateDir) return [];
  const providerInventoryDir = path.join(stateDir, "model-provider-inventory");
  if (!fs.existsSync(providerInventoryDir)) return [];
  return fs.readdirSync(providerInventoryDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(providerInventoryDir, file), "utf8")))
    .filter((record) =>
      record?.deleted !== true &&
      record?.object === "ioi.model_mount_provider_inventory" &&
      record?.schema_version === "ioi.model_mount.provider_inventory.v1" &&
      typeof record?.id === "string" &&
      record?.record_id === record.id &&
      record?.record_dir === "model-provider-inventory" &&
      typeof record?.provider_ref === "string" &&
      typeof record?.provider_kind === "string" &&
      typeof record?.action === "string" &&
      typeof record?.operation_kind === "string" &&
      typeof record?.status === "string" &&
      typeof record?.inventory_hash === "string" &&
      record?.rust_core_boundary === "model_mount.provider_inventory" &&
      ["rust_model_mount_fixture_inventory", "rust_model_mount_native_local_inventory"].includes(
        record?.execution_backend,
      ) &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("rust_model_mount_provider_inventory") &&
      record.evidence_refs.includes("agentgres_provider_inventory_truth_required"))
    .sort((left, right) =>
      String(left.provider_ref ?? "").localeCompare(String(right.provider_ref ?? "")) ||
      String(left.action ?? "").localeCompare(String(right.action ?? "")) ||
      String(left.id ?? "").localeCompare(String(right.id ?? "")));
}

function providerLifecycleRecordsFromAgentgresStateDir(stateDir) {
  if (!stateDir) return [];
  const providerLifecycleDir = path.join(stateDir, "model-provider-lifecycle-controls");
  if (!fs.existsSync(providerLifecycleDir)) return [];
  return fs.readdirSync(providerLifecycleDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(providerLifecycleDir, file), "utf8")))
    .filter((record) =>
      record?.deleted !== true &&
      record?.object === "ioi.model_mount_provider_lifecycle" &&
      record?.schema_version === "ioi.model_mount.provider_lifecycle_plan.v1" &&
      typeof record?.id === "string" &&
      record?.record_id === record.id &&
      record?.record_dir === "model-provider-lifecycle-controls" &&
      record?.rust_core_boundary === "model_mount.provider_lifecycle" &&
      typeof record?.provider_ref === "string" &&
      typeof record?.provider_kind === "string" &&
      typeof record?.action === "string" &&
      typeof record?.operation_kind === "string" &&
      typeof record?.status === "string" &&
      typeof record?.backend === "string" &&
      typeof record?.backend_id === "string" &&
      typeof record?.driver === "string" &&
      typeof record?.execution_backend === "string" &&
      typeof record?.lifecycle_hash === "string" &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("rust_model_mount_provider_lifecycle") &&
      record.evidence_refs.includes("agentgres_provider_lifecycle_truth_required"))
    .sort((left, right) =>
      String(left.generated_at ?? "").localeCompare(String(right.generated_at ?? "")) ||
      String(left.id ?? "").localeCompare(String(right.id ?? "")));
}

function providerControlRecordsFromAgentgresStateDir(stateDir) {
  if (!stateDir) return [];
  const providerDir = path.join(stateDir, "model-providers");
  if (!fs.existsSync(providerDir)) return [];
  return fs.readdirSync(providerDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(providerDir, file), "utf8")))
    .filter((record) =>
      record?.deleted !== true &&
      record?.object === "ioi.model_mount_provider" &&
      record?.schema_version === "ioi.model_mount.provider_control.v1" &&
      record?.operation_kind === "model_mount.provider.write" &&
      record?.rust_core_boundary === "model_mount.provider_control" &&
      typeof record?.id === "string" &&
      record?.record_id === record.id &&
      typeof record?.provider_id === "string" &&
      typeof record?.provider_ref === "string" &&
      typeof record?.kind === "string" &&
      typeof record?.status === "string" &&
      typeof record?.control_hash === "string" &&
      record?.plaintext_material_returned === false &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("rust_daemon_core_provider_control") &&
      record.evidence_refs.includes("agentgres_provider_control_truth_required") &&
      record.evidence_refs.includes("public_provider_control_js_facade_retired"))
    .sort((left, right) =>
      String(left.provider_ref ?? "").localeCompare(String(right.provider_ref ?? "")) ||
      String(left.record_id ?? "").localeCompare(String(right.record_id ?? "")));
}

function providerRecordFromProviderControl(record) {
  return withoutNulls({
    id: record.provider_id,
    object: "ioi.model_mount_provider",
    provider_id: record.provider_id,
    provider_ref: record.provider_ref,
    provider_kind: record.kind,
    kind: record.kind,
    label: record.label,
    status: record.status,
    api_format: record.api_format,
    driver: record.driver,
    base_url: record.base_url,
    privacy_class: record.privacy_class,
    capabilities: record.capabilities ?? [],
    auth_scheme: record.auth_scheme,
    auth_header_name: record.auth_header_name,
    auth_material_status: record.secret_ref ? "wallet_vault_ref_bound" : "not_required",
    private_material_returned: record.plaintext_material_returned,
    plaintext_material_persisted: false,
    record_dir: "model-providers",
    record_id: record.record_id,
    source: "agentgres_provider_control",
    rust_core_boundary: "model_mount.provider_control",
    provider_projection_boundary: "model_mount.provider_control_projection",
    wallet_authority_boundary: record.wallet_authority_boundary,
    ctee_custody_boundary: record.ctee_custody_boundary,
    authority_hash: record.authority?.authority_hash,
    control_hash: record.control_hash,
    evidence_refs: providerControlProjectionEvidenceRefs(record),
  });
}

function artifactRecordsFromAgentgresStateDir(stateDir, objectKind) {
  return providerInventoryRecordsFromAgentgresStateDir(stateDir)
    .filter((record) => record.action === "list_models")
    .flatMap((record) => (record.item_refs ?? []).map((itemRef) => ({
      id: `artifact_${recordIdSegment(record.record_id, "record")}_${recordIdSegment(itemRef, "model")}`,
      object: objectKind,
      model_ref: itemRef,
      model_id: modelIdFromItemRef(itemRef),
      provider_ref: record.provider_ref,
      provider_kind: record.provider_kind,
      backend: record.backend,
      backend_id: record.backend_id,
      driver: record.driver,
      inventory_record_id: record.record_id,
      inventory_hash: record.inventory_hash,
      source: "agentgres_provider_inventory",
      rust_core_boundary: "model_mount.provider_inventory.materialization",
      evidence_refs: [
        "rust_daemon_core_provider_inventory_materialization",
        "agentgres_provider_inventory_truth_required",
        "model_mount_topology_js_materialization_retired",
      ],
    })))
    .sort((left, right) =>
      String(left.model_ref ?? "").localeCompare(String(right.model_ref ?? "")) ||
      String(left.provider_ref ?? "").localeCompare(String(right.provider_ref ?? "")));
}

function providerRecordsFromAgentgresStateDir(stateDir) {
  const providers = new Map();
  for (const record of providerInventoryRecordsFromAgentgresStateDir(stateDir)) {
    if (providers.has(record.provider_ref)) continue;
    providers.set(record.provider_ref, {
      id: record.provider_ref,
      object: "ioi.model_mount_provider",
      provider_ref: record.provider_ref,
      provider_kind: record.provider_kind,
      backend: record.backend,
      backend_id: record.backend_id,
      driver: record.driver,
      inventory_record_id: record.record_id,
      inventory_hash: record.inventory_hash,
      source: "agentgres_provider_inventory",
      rust_core_boundary: "model_mount.provider_inventory.materialization",
      evidence_refs: [
        "rust_daemon_core_provider_inventory_materialization",
        "agentgres_provider_inventory_truth_required",
        "model_mount_topology_js_materialization_retired",
      ],
    });
  }
  for (const record of providerControlRecordsFromAgentgresStateDir(stateDir)) {
    providers.set(record.provider_ref, providerRecordFromProviderControl(record));
  }
  return [...providers.values()].sort((left, right) =>
    String(left.provider_ref ?? "").localeCompare(String(right.provider_ref ?? "")));
}

function providerControlProjectionEvidenceRefs(record) {
  return [
    ...(Array.isArray(record?.evidence_refs) ? record.evidence_refs : []),
    "rust_daemon_core_provider_control_projection",
    "agentgres_provider_control_truth_required",
    "model_mount_provider_map_lookup_js_retired",
  ].filter((value, index, array) => array.indexOf(value) === index);
}

function runtimeModelCatalogFromAgentgresStateDir(stateDir) {
  return providerInventoryRecordsFromAgentgresStateDir(stateDir)
    .filter((record) => record.action === "list_models")
    .flatMap((record) => (record.item_refs ?? []).map((itemRef) => ({
      id: modelIdFromItemRef(itemRef),
      object: "ioi.runtime_model_catalog_entry",
      model_ref: itemRef,
      provider_ref: record.provider_ref,
      provider_kind: record.provider_kind,
      backend: record.backend,
      backend_id: record.backend_id,
      driver: record.driver,
      inventory_record_id: record.record_id,
      inventory_hash: record.inventory_hash,
      source: "agentgres_provider_inventory",
      rust_core_boundary: "model_mount.provider_inventory.materialization",
      evidence_refs: [
        "rust_daemon_core_provider_inventory_materialization",
        "agentgres_provider_inventory_truth_required",
        "model_mount_runtime_catalog_js_materialization_retired",
      ],
    })))
    .sort((left, right) =>
      String(left.id ?? "").localeCompare(String(right.id ?? "")) ||
      String(left.provider_ref ?? "").localeCompare(String(right.provider_ref ?? "")));
}

function openAiModelListFromAgentgresStateDir(stateDir) {
  return {
    object: "list",
    data: providerInventoryRecordsFromAgentgresStateDir(stateDir)
      .filter((record) => record.action === "list_models")
      .flatMap((record) => (record.item_refs ?? []).map((itemRef) => ({
        id: modelIdFromItemRef(itemRef),
        object: "model",
        owned_by: "ioi",
        model_ref: itemRef,
        provider_ref: record.provider_ref,
        inventory_record_id: record.record_id,
        inventory_hash: record.inventory_hash,
        rust_core_boundary: "model_mount.provider_inventory.materialization",
        evidence_refs: [
          "rust_daemon_core_provider_inventory_materialization",
          "agentgres_provider_inventory_truth_required",
          "openai_model_list_js_materialization_retired",
        ],
      })))
      .sort((left, right) =>
        String(left.id ?? "").localeCompare(String(right.id ?? "")) ||
        String(left.provider_ref ?? "").localeCompare(String(right.provider_ref ?? ""))),
  };
}

function modelCapabilitiesFromAgentgresStateDir(stateDir) {
  const endpoints = new Map(endpointRecordsFromAgentgresStateDir(stateDir).map((endpoint) => [endpoint.id, endpoint]));
  const providers = new Map();
  for (const provider of providerRecordsFromAgentgresStateDir(stateDir)) {
    if (provider.id) providers.set(provider.id, provider);
    if (provider.provider_ref) providers.set(provider.provider_ref, provider);
  }
  const artifacts = new Map(
    artifactRecordsFromAgentgresStateDir(stateDir, "ioi.model_mount_model_artifact")
      .map((artifact) => [artifact.model_id, artifact]),
  );
  const loadedEndpointIds = new Set(
    instanceRecordsFromAgentgresStateDir(stateDir)
      .filter((instance) => instance.status === "loaded")
      .map((instance) => instance.endpoint_id),
  );
  return routeRecordsFromAgentgresStateDir(stateDir)
    .map((route) => modelCapabilityForRoute(route, {
      artifacts,
      endpoints,
      loadedEndpointIds,
      providers,
    }))
    .sort((left, right) => String(left.route_id ?? "").localeCompare(String(right.route_id ?? "")));
}

function modelCapabilityForRoute(route, context) {
  const candidates = (route.fallback ?? []).map((endpointId, priority) =>
    modelCapabilityCandidate(route, endpointId, priority, context));
  const readyCandidates = candidates.filter((candidate) => candidate.ready);
  const selectedCandidate = readyCandidates[0] ?? candidates[0] ?? null;
  const capability = selectedCandidate?.capability ?? "chat";
  const evidenceRefs = uniqueStrings(candidates.flatMap((candidate) => candidate.evidence_refs ?? []));
  const missingVaultCount = candidates
    .filter((candidate) => candidate.vault_required && !candidate.vault_ready).length;
  const requiredVaultCount = candidates.filter((candidate) => candidate.vault_required).length;
  const configuredVaultCount = candidates
    .filter((candidate) => candidate.vault_required && candidate.vault_ready).length;
  const available = route.status === "active" && readyCandidates.length > 0;
  return {
    schema_version: "ioi.model-capability.v1",
    object: "ioi.model_capability",
    id: `model-capability:${route.id}`,
    route_id: route.id,
    role: route.role,
    model_role: route.role,
    capability,
    primitive_capability: `prim:model.${capability}`,
    authority_scope_requirements: [`route.use:${route.id}`, `model.${capability}:*`],
    policy_target: String(route.id ?? "").startsWith("route.") ? `model.${route.id}` : `model.route.${route.id}`,
    privacy_tier: route.privacy ?? "",
    provider_priority: route.providerEligibility ?? [],
    fallback_policy: {
      allowed: (route.fallback ?? []).length > 1,
      endpoint_ids: route.fallback ?? [],
      denied_providers: route.deniedProviders ?? [],
      selected_endpoint_id: selectedCandidate?.endpoint_id ?? null,
      deterministic_order: true,
    },
    fallback_evidence: candidates.map((candidate) => candidate.evidence),
    cost_estimate_visibility: {
      visible: true,
      max_cost_usd: route.maxCostUsd ?? null,
      max_latency_ms: route.maxLatencyMs ?? null,
      source: "model_route_policy",
    },
    credential_readiness: {
      status: modelCapabilityReadinessStatus(route, candidates),
      reason: modelCapabilityReadinessReason(route, candidates),
      evidence_refs: evidenceRefs,
    },
    vault_readiness: {
      status: missingVaultCount === 0 ? "ready" : "missing",
      required_count: requiredVaultCount,
      configured_count: configuredVaultCount,
      missing_count: missingVaultCount,
    },
    byok_required: requiredVaultCount > 0,
    receipt_behavior: {
      receipt_required: true,
      required_receipt_types: ["model_route_selection", "model_invocation"],
    },
    workflow_availability: {
      available,
      reason: available
        ? "At least one route candidate is executable."
        : "No executable model route candidate is ready.",
      config_fields: ["model_ref", "route_id", "model_binding"],
      evidence_refs: evidenceRefs,
    },
    agent_availability: {
      available,
      reason: available
        ? "Agent runtime can request this route capability."
        : "Agent runtime must resolve model readiness first.",
      evidence_refs: evidenceRefs,
    },
    candidates,
    source: "agentgres_model_capability_replay",
    rust_core_boundary: "model_mount.model_capability_projection",
    state_dir_replay_required: true,
    evidence_refs: [
      "rust_daemon_core_model_capability_projection",
      "agentgres_model_capability_replay_required",
      "model_mount_model_capability_js_projection_retired",
    ],
  };
}

function modelCapabilityCandidate(route, endpointId, priority, { artifacts, endpoints, loadedEndpointIds, providers }) {
  const endpoint = endpoints.get(endpointId) ?? null;
  const provider = endpoint?.provider_id ? providers.get(endpoint.provider_id) ?? null : null;
  const artifact = endpoint?.model_id ? artifacts.get(endpoint.model_id) ?? null : null;
  const vaultRequired = providerRequiresVault(provider);
  const vaultReady = !vaultRequired || Boolean(provider?.secret_configured || provider?.vault_boundary?.configured);
  const providerReady = provider ? providerIsReady(provider) : false;
  const endpointReady = endpoint
    ? endpoint.status === "mounted" || loadedEndpointIds.has(endpoint.id)
    : false;
  const ready = route.status === "active" && endpointReady && providerReady && vaultReady;
  const reason = modelCapabilityCandidateReason({
    endpoint,
    endpointReady,
    provider,
    providerReady,
    vaultRequired,
    vaultReady,
  });
  const evidenceRefs = uniqueStrings([
    ...(endpoint?.evidence_refs ?? []),
    ...(provider?.evidence_refs ?? []),
    ...(artifact?.evidence_refs ?? []),
  ]);
  return {
    endpoint_id: endpointId,
    priority,
    model_id: endpoint?.model_id ?? null,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.provider_kind ?? null,
    capability: firstCapability(endpoint?.capabilities ?? artifact?.capabilities),
    privacy_tier: endpoint?.privacy_tier ?? provider?.privacy_tier ?? route.privacy ?? "",
    status: ready ? "ready" : "blocked",
    ready,
    vault_required: vaultRequired,
    vault_ready: vaultReady,
    reason,
    evidence_refs: evidenceRefs,
    evidence: {
      endpoint_id: endpointId,
      provider_id: provider?.id ?? null,
      status: ready ? "ready" : "blocked",
      reason,
      vault_required: vaultRequired,
      vault_ready: vaultReady,
    },
  };
}

function providerIsReady(provider) {
  return !provider.status || ["available", "configured", "running", "listed"].includes(String(provider.status));
}

function providerRequiresVault(provider) {
  if (!provider) return false;
  return Boolean(provider.vault_boundary?.required) ||
    ["openai", "anthropic", "gemini", "custom_http"].includes(String(provider.provider_kind));
}

function modelCapabilityReadinessStatus(route, candidates) {
  if (route.status !== "active") return "disabled";
  if (candidates.some((candidate) => candidate.ready)) return "ready";
  if (candidates.some((candidate) => candidate.vault_required && !candidate.vault_ready)) return "missing";
  return "degraded";
}

function modelCapabilityReadinessReason(route, candidates) {
  if (route.status !== "active") return "Model route is disabled.";
  if (candidates.some((candidate) => candidate.ready)) return "Route has an executable candidate.";
  return candidates[0]?.reason ?? "Route has no configured fallback candidates.";
}

function modelCapabilityCandidateReason({ endpoint, endpointReady, provider, providerReady, vaultRequired, vaultReady }) {
  if (!endpoint) return "Route fallback endpoint is not registered.";
  if (!provider) return "Endpoint provider is not registered.";
  if (!providerReady) return `Provider status is ${provider.status ?? ""}.`;
  if (vaultRequired && !vaultReady) return "Provider requires wallet vault credentials.";
  if (!endpointReady) return `Endpoint status is ${endpoint.status ?? ""}.`;
  return "Endpoint, provider, and credential posture are ready.";
}

function firstCapability(capabilities) {
  return Array.isArray(capabilities) && capabilities.length > 0 ? String(capabilities[0]) : "chat";
}

function uniqueStrings(values) {
  return [...new Set(values.filter((value) => typeof value === "string" && value.trim().length > 0))];
}

function modelIdFromItemRef(itemRef) {
  return String(itemRef).split(/[/:]/).filter(Boolean).at(-1) ?? String(itemRef);
}

function recordIdSegment(value, fallback) {
  let segment = String(value ?? "")
    .replace(/[^A-Za-z0-9._-]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (segment.length === 0) segment = fallback;
  return segment;
}

function catalogSearchFromAgentgresStateDir(request) {
  const input = request.state.catalog_search ?? {};
  const query = String(input.query ?? "").trim();
  const providerRef = String(input.provider_ref ?? "").trim();
  const limit = Math.max(1, Math.min(Number.parseInt(String(input.limit ?? 50), 10) || 50, 100));
  const queryLower = query.toLowerCase();
  const providerRefLower = providerRef.toLowerCase();
  const results = [];
  for (const record of providerInventoryRecordsFromAgentgresStateDir(request.state_dir)) {
    if (record.action !== "list_models") continue;
    if (providerRefLower && String(record.provider_ref ?? "").toLowerCase() !== providerRefLower) continue;
    for (const itemRef of record.item_refs ?? []) {
      const haystack = [
        itemRef,
        record.provider_ref,
        record.provider_kind,
        record.backend,
        record.backend_id,
        record.driver,
      ].join(" ").toLowerCase();
      if (queryLower && !haystack.includes(queryLower)) continue;
      results.push({
        id: `catalog_search_${record.record_id}_${String(itemRef).replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^_+|_+$/g, "")}`,
        object: "ioi.model_catalog_search_entry",
        model_ref: itemRef,
        model_id: String(itemRef).split(/[/:]/).filter(Boolean).at(-1),
        provider_ref: record.provider_ref,
        provider_kind: record.provider_kind,
        backend: record.backend,
        backend_id: record.backend_id,
        driver: record.driver,
        inventory_record_id: record.record_id,
        inventory_hash: record.inventory_hash,
        source: "agentgres_provider_inventory",
        rust_core_boundary: "model_mount.catalog_search",
        evidence_refs: [
          "rust_daemon_core_catalog_search_projection",
          "agentgres_provider_inventory_truth_required",
          "model_catalog_search_js_orchestrator_retired",
        ],
      });
      if (results.length >= limit) break;
    }
    if (results.length >= limit) break;
  }
  return {
    schema_version: request.schema_version,
    object: "ioi.model_catalog_search_result",
    source: "rust_model_mount_catalog_search_projection",
    rust_core_boundary: "model_mount.catalog_search",
    generated_at: request.generated_at,
    query,
    filters: {
      format: input.format ?? "",
      quantization: input.quantization ?? "",
      provider_ref: providerRef,
    },
    result_count: results.length,
    results,
    evidence_refs: [
      "rust_daemon_core_catalog_search_projection",
      "agentgres_catalog_search_replay_required",
      "agentgres_provider_inventory_truth_required",
      "model_catalog_search_js_orchestrator_retired",
    ],
  };
}

function tokenizerRecordsFromAgentgresStateDir(stateDir) {
  const tokenizerDir = path.join(stateDir, "model-tokenizer-utilities");
  return fs.readdirSync(tokenizerDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(tokenizerDir, file), "utf8")))
    .filter((record) =>
      record?.deleted !== true &&
      record?.object === "ioi.model_mount_tokenizer_result" &&
      typeof record?.id === "string" &&
      ["tokenize", "count_tokens", "context_fit"].includes(record?.operation) &&
      record?.rust_core_boundary === "model_mount.tokenizer" &&
      record?.route_selection_boundary === "model_mount.route_selection" &&
      typeof record?.route_id === "string" &&
      typeof record?.model === "string" &&
      typeof record?.endpoint_id === "string" &&
      typeof record?.provider_id === "string" &&
      typeof record?.input_hash === "string" &&
      typeof record?.control_hash === "string" &&
      Number.isInteger(record?.token_count) &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("model_mount_tokenizer_rust_owned") &&
      record.evidence_refs.includes("agentgres_model_tokenizer_truth_required"))
    .sort((left, right) =>
      String(left.operation ?? "").localeCompare(String(right.operation ?? "")) ||
      String(left.id ?? "").localeCompare(String(right.id ?? "")));
}

function routeRecordsFromAgentgresStateDir(stateDir) {
  const routeDir = path.join(stateDir, "model-routes");
  return fs.readdirSync(routeDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(routeDir, file), "utf8")))
    .filter((record) =>
      record?.deleted !== true &&
      typeof record?.id === "string" &&
      typeof record?.role === "string" &&
      typeof record?.status === "string" &&
      typeof record?.updatedAt === "string" &&
      Array.isArray(record?.receiptRefs) &&
      record.receiptRefs.some((receiptRef) => typeof receiptRef === "string" && receiptRef.length > 0) &&
      record?.routeControl?.rust_core_boundary === "model_mount.route_control" &&
      Array.isArray(record?.routeControl?.evidence_refs) &&
      record.routeControl.evidence_refs.includes("model_mount_route_control_rust_owned") &&
      record.routeControl.evidence_refs.includes("rust_daemon_core_route_control_plan") &&
      record.routeControl.evidence_refs.includes("agentgres_route_truth_required"))
    .sort((left, right) =>
      String(left.id ?? "").localeCompare(String(right.id ?? "")) ||
      String(left.status ?? "").localeCompare(String(right.status ?? "")));
}

function routeDecisionsFromAgentgresStateDir(stateDir) {
  if (!stateDir) return [];
  const routeSelectionDir = path.join(stateDir, "model-route-selections");
  return fs.readdirSync(routeSelectionDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(routeSelectionDir, file), "utf8")))
    .filter((record) =>
      record?.deleted !== true &&
      record?.object === "ioi.model_mount_route_selection" &&
      typeof record?.id === "string" &&
      typeof record?.route_id === "string" &&
      typeof record?.selected_model === "string" &&
      typeof record?.endpoint_id === "string" &&
      typeof record?.provider_id === "string" &&
      record?.rust_core_boundary === "model_mount.route_control" &&
      record?.route_selection_boundary === "model_mount.route_selection" &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("model_mount_route_control_rust_owned") &&
      record.evidence_refs.includes("rust_daemon_core_route_control_plan") &&
      record.evidence_refs.includes("agentgres_route_truth_required"))
    .map((record) => ({
      ...(record.route_decision && typeof record.route_decision === "object" ? record.route_decision : {}),
      route_id: record.route_id,
      selected_model: record.selected_model,
      endpoint_id: record.endpoint_id,
      provider_id: record.provider_id,
      ...(record.capability ? { capability: record.capability } : {}),
      ...(record.policy_hash ? { policy_hash: record.policy_hash } : {}),
      ...(record.selected_at ? { selected_at: record.selected_at } : {}),
      record_dir: "model-route-selections",
      record_id: record.id,
      receipt_id: record.accepted_receipt_record?.id ?? record.receipt_refs?.[0] ?? null,
      receipt_created_at: record.accepted_receipt_record?.createdAt ?? record.selected_at ?? null,
      receipt_kind: record.accepted_receipt_record?.kind ?? "model_route_selection",
      receipt_refs: record.receipt_refs ?? [],
      evidence_refs: record.evidence_refs,
      rust_core_boundary: record.rust_core_boundary,
      route_selection_boundary: record.route_selection_boundary,
    }))
    .sort((left, right) =>
      String(left.route_id ?? "").localeCompare(String(right.route_id ?? "")) ||
      String(left.record_id ?? "").localeCompare(String(right.record_id ?? "")));
}

function routeEndpointResolutionsFromAgentgresStateDir(stateDir) {
  if (!stateDir) return [];
  const endpointResolutionDir = path.join(stateDir, "model-route-endpoint-resolutions");
  return fs.readdirSync(endpointResolutionDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(endpointResolutionDir, file), "utf8")))
    .filter((record) =>
      record?.deleted !== true &&
      record?.object === "ioi.model_mount_explicit_model_endpoints" &&
      typeof record?.id === "string" &&
      typeof record?.route_id === "string" &&
      typeof record?.model_id === "string" &&
      Array.isArray(record?.endpoint_ids) &&
      record.endpoint_ids.length > 0 &&
      record?.rust_core_boundary === "model_mount.route_control" &&
      record?.route_selection_boundary === "model_mount.route_selection" &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("model_mount_route_control_rust_owned") &&
      record.evidence_refs.includes("rust_daemon_core_route_control_plan") &&
      record.evidence_refs.includes("agentgres_route_truth_required"))
    .map((record) => ({
      ...record,
      record_dir: "model-route-endpoint-resolutions",
    }))
    .sort((left, right) =>
      String(left.route_id ?? "").localeCompare(String(right.route_id ?? "")) ||
      String(left.model_id ?? "").localeCompare(String(right.model_id ?? "")) ||
      String(left.id ?? "").localeCompare(String(right.id ?? "")));
}

function endpointRecordsFromAgentgresStateDir(stateDir) {
  const records = [];
  const seen = new Set();
  for (const resolution of routeEndpointResolutionsFromAgentgresStateDir(stateDir)) {
    const endpoints = Array.isArray(resolution.endpoints) && resolution.endpoints.length > 0
      ? resolution.endpoints
      : (resolution.endpoint_ids ?? []).map((endpointId) => ({ id: endpointId }));
    for (const endpoint of endpoints) {
      const endpointId = typeof endpoint?.id === "string" && endpoint.id.length > 0
        ? endpoint.id
        : null;
      const modelId = typeof endpoint?.model_id === "string" && endpoint.model_id.length > 0
        ? endpoint.model_id
        : typeof endpoint?.modelId === "string" && endpoint.modelId.length > 0
          ? endpoint.modelId
          : resolution.model_id;
      if (!endpointId || !modelId) continue;
      const providerId = typeof endpoint?.provider_id === "string" && endpoint.provider_id.length > 0
        ? endpoint.provider_id
        : typeof endpoint?.providerId === "string" && endpoint.providerId.length > 0
          ? endpoint.providerId
          : null;
      const key = `${endpointId}:${resolution.route_id}:${modelId}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const evidenceRefs = [
        ...(Array.isArray(resolution.evidence_refs) ? resolution.evidence_refs : []),
        "rust_daemon_core_model_endpoint_projection",
        "agentgres_model_route_endpoint_resolution_replay_required",
        "model_mount_endpoint_list_js_facade_retired",
      ].filter((value, index, array) => array.indexOf(value) === index);
      records.push({
        id: endpointId,
        object: "ioi.model_mount_endpoint",
        endpoint_id: endpointId,
        model_id: modelId,
        ...(providerId ? { provider_id: providerId } : {}),
        status: typeof endpoint?.status === "string" && endpoint.status.length > 0
          ? endpoint.status
          : "mounted",
        route_id: resolution.route_id,
        endpoint_resolution_record_id: resolution.id,
        record_dir: "model-route-endpoint-resolutions",
        receipt_refs: resolution.receipt_refs ?? [],
        evidence_refs: evidenceRefs,
        source: "agentgres_route_endpoint_resolution",
        rust_core_boundary: "model_mount.route_control",
        route_selection_boundary: "model_mount.route_selection",
      });
    }
  }
  return records.sort((left, right) =>
    String(left.id ?? "").localeCompare(String(right.id ?? "")) ||
    String(left.route_id ?? "").localeCompare(String(right.route_id ?? "")) ||
    String(left.model_id ?? "").localeCompare(String(right.model_id ?? "")));
}

function downloadRecordsFromAgentgresStateDir(stateDir) {
  return storageRecordsFromAgentgresStateDir(stateDir, "model-downloads")
    .filter((record) =>
      record.object === "ioi.model_mount_download" &&
      ["model_mount.download.queue", "model_mount.download.cancel"].includes(record.operation_kind) &&
      typeof record.details?.job_id === "string" &&
      (
        record.operation_kind !== "model_mount.download.queue" ||
        typeof record.details?.model_id === "string"
      ) &&
      (
        record.operation_kind !== "model_mount.download.queue" ||
        (
          record.evidence_refs.includes("public_catalog_download_js_facade_retired") &&
          record.evidence_refs.includes("rust_daemon_core_catalog_download") &&
          record.evidence_refs.includes("agentgres_catalog_download_truth_required")
        )
      ) &&
      (
        record.operation_kind !== "model_mount.download.cancel" ||
        record.evidence_refs.includes("rust_daemon_core_model_download_cancel")
      ))
    .map((record) => storageProjectionRecord(record, "model-downloads"))
    .sort((left, right) =>
      String(left.id ?? "").localeCompare(String(right.id ?? "")) ||
      String(left.status ?? "").localeCompare(String(right.status ?? "")));
}

function catalogImportRecordsFromAgentgresStateDir(stateDir) {
  return storageRecordsFromAgentgresStateDir(stateDir, "model-catalog-imports")
    .filter((record) =>
      record.object === "ioi.model_mount_catalog_import" &&
      record.operation_kind === "model_mount.catalog.import_url" &&
      typeof record.details?.model_id === "string" &&
      typeof record.details?.source_url_hash === "string" &&
      record.evidence_refs.includes("public_catalog_download_js_facade_retired") &&
      record.evidence_refs.includes("rust_daemon_core_catalog_download") &&
      record.evidence_refs.includes("agentgres_catalog_download_truth_required"))
    .map((record) => storageProjectionRecord(record, "model-catalog-imports"))
    .sort((left, right) => String(left.id ?? "").localeCompare(String(right.id ?? "")));
}

function storageControlRecordsFromAgentgresStateDir(stateDir) {
  return storageRecordsFromAgentgresStateDir(stateDir, "model-storage-controls")
    .filter((record) =>
      record.object === "ioi.model_mount_storage_control" &&
      (
        (
          record.operation_kind === "model_mount.artifact.delete" &&
          record.evidence_refs.includes("rust_daemon_core_model_artifact_delete")
        ) ||
        (
          record.operation_kind === "model_mount.storage.cleanup" &&
          record.evidence_refs.includes("rust_daemon_core_model_storage_cleanup")
        )
      ))
    .map((record) => storageProjectionRecord(record, "model-storage-controls"))
    .sort((left, right) => String(left.id ?? "").localeCompare(String(right.id ?? "")));
}

function storageRecordsFromAgentgresStateDir(stateDir, recordDirName) {
  if (!stateDir) return [];
  const recordDir = path.join(stateDir, recordDirName);
  if (!fs.existsSync(recordDir)) return [];
  return fs.readdirSync(recordDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(recordDir, file), "utf8")))
    .filter((record) =>
      record?.deleted !== true &&
      record?.schema_version === "ioi.model_mount.storage_control.v1" &&
      typeof record?.id === "string" &&
      record?.record_id === record.id &&
      typeof record?.status === "string" &&
      typeof record?.operation_kind === "string" &&
      record?.rust_core_boundary === "model_mount.storage_control" &&
      typeof record?.control_hash === "string" &&
      typeof record?.authority_hash === "string" &&
      record?.details && typeof record.details === "object" && !Array.isArray(record.details) &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("public_model_storage_js_facade_retired") &&
      record.evidence_refs.includes("rust_daemon_core_model_storage") &&
      record.evidence_refs.includes("agentgres_model_storage_truth_required"));
}

function storageProjectionRecord(record, recordDirName) {
  return {
    id: record.id,
    record_id: record.record_id,
    record_dir: recordDirName,
    object: record.object,
    status: record.status,
    operation_kind: record.operation_kind,
    source: "agentgres_model_mount_storage_control",
    generated_at: record.generated_at,
    rust_core_boundary: record.rust_core_boundary,
    storage_projection_boundary: "model_mount.storage_projection",
    details: record.details,
    public_response: record.public_response,
    authority: record.authority,
    receipt_refs: record.receipt_refs ?? [],
    evidence_refs: record.evidence_refs,
    control_hash: record.control_hash,
    authority_hash: record.authority_hash,
  };
}

function storageSummaryFromAgentgresStateDir(request) {
  const downloads = downloadRecordsFromAgentgresStateDir(request.state_dir);
  const catalogImports = catalogImportRecordsFromAgentgresStateDir(request.state_dir);
  const storageControls = storageControlRecordsFromAgentgresStateDir(request.state_dir);
  const totalBytes = downloads
    .map((record) => record.details?.bytes_total)
    .filter((value) => Number.isInteger(value) && value >= 0)
    .reduce((sum, value) => sum + value, 0);
  return {
    schema_version: request.schema_version,
    object: "ioi.model_mount_storage_summary",
    source: "rust_model_mount_storage_summary_projection",
    rust_core_boundary: "model_mount.storage_projection",
    generated_at: request.generated_at,
    state_dir_replay_required: true,
    filesystem_scanned: false,
    record_dirs: [
      "model-catalog-imports",
      "model-downloads",
      "model-storage-controls",
    ],
    record_counts: {
      catalog_imports: catalogImports.length,
      downloads: downloads.length,
      storage_controls: storageControls.length,
    },
    catalog_import_count: catalogImports.length,
    download_count: downloads.length,
    active_download_count: downloads.filter((record) => record.status === "queued").length,
    cancelled_download_count: downloads.filter((record) => record.status === "cancelled").length,
    storage_control_count: storageControls.length,
    total_bytes: totalBytes > 0 ? totalBytes : null,
    quota_bytes: null,
    orphan_count: null,
    destructive_actions_require_unload: true,
    evidence_refs: [
      "rust_daemon_core_model_storage_projection",
      "agentgres_model_storage_replay_required",
      "public_model_storage_js_facade_retired",
      "model_mount_storage_summary_js_facade_retired",
    ],
  };
}

function backendLifecycleControlRecordsFromAgentgresStateDir(stateDir) {
  if (!stateDir) return [];
  const recordDir = path.join(stateDir, "model-backend-lifecycle-controls");
  if (!fs.existsSync(recordDir)) return [];
  return fs.readdirSync(recordDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(recordDir, file), "utf8")))
    .filter((record) =>
      record?.deleted !== true &&
      record?.schema_version === "ioi.model_mount.backend_lifecycle_plan.v1" &&
      record?.object === "ioi.model_mount_backend_lifecycle_record" &&
      typeof record?.id === "string" &&
      typeof record?.backend_id === "string" &&
      typeof record?.operation_kind === "string" &&
      typeof record?.status === "string" &&
      typeof record?.generated_at === "string" &&
      typeof record?.control_hash === "string" &&
      record?.rust_core_boundary === "model_mount.backend_lifecycle" &&
      [
        "model_mount.backend.health",
        "model_mount.backend.start",
        "model_mount.backend.stop",
      ].includes(record?.operation_kind) &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("public_backend_lifecycle_js_facade_retired") &&
      record.evidence_refs.includes("rust_daemon_core_backend_lifecycle") &&
      record.evidence_refs.includes("agentgres_backend_lifecycle_truth_required"))
    .sort((left, right) =>
      String(left.generated_at ?? "").localeCompare(String(right.generated_at ?? "")) ||
      String(left.id ?? "").localeCompare(String(right.id ?? "")));
}

function backendLogsFromRustRequest(request) {
  const query = request.state?.backend_log_query ?? {};
  const backendId = typeof query.backend_id === "string" ? query.backend_id : "";
  const limit = Math.min(Number.parseInt(String(query.limit ?? 80), 10) || 80, 500);
  const records = backendLifecycleControlRecordsFromAgentgresStateDir(request.state_dir)
    .filter((record) => record.backend_id === backendId);
  const entries = records.slice(Math.max(records.length - limit, 0)).map((record) => {
    const event = {
      "model_mount.backend.health": "backend_health",
      "model_mount.backend.start": "backend_start",
      "model_mount.backend.stop": "backend_stop",
    }[record.operation_kind] ?? "backend_lifecycle_recorded";
    return {
      event,
      level: "info",
      message: event.split("_").join(" "),
      timestamp: record.generated_at,
      backend_id: record.backend_id,
      backend_kind: record.backend_kind ?? null,
      operation_kind: record.operation_kind,
      operation_status: record.status,
      backend_status: record.public_response?.backend_status ?? null,
      receipt_refs: record.receipt_refs ?? [],
      record_dir: "model-backend-lifecycle-controls",
      record_id: record.id,
      control_hash: record.control_hash,
      source: record.source,
      rust_core_boundary: "model_mount.backend_lifecycle_log_projection",
      evidence_refs: backendLogProjectionEvidenceRefs(),
    };
  });
  return {
    schemaVersion: request.schema_version,
    object: "ioi.model_mount_backend_logs",
    status: "projected",
    projectionKind: "backend_logs",
    backend_id: backendId,
    redaction: "redacted",
    records: entries,
    logs: entries,
    count: entries.length,
    source: "agentgres_backend_lifecycle_control",
    recordDir: "model-backend-lifecycle-controls",
    recordCount: records.length,
    rustCoreBoundary: "model_mount.backend_lifecycle_log_projection",
    evidenceRefs: backendLogProjectionEvidenceRefs(),
  };
}

function backendLogProjectionEvidenceRefs() {
  return [
    "rust_daemon_core_backend_lifecycle_log_projection",
    "agentgres_backend_lifecycle_log_replay_required",
    "model_mount_backend_log_read_js_control_path_retired",
  ];
}

function backendRecordsFromAgentgresStateDir(stateDir) {
  const latestByBackend = new Map();
  for (const record of backendLifecycleControlRecordsFromAgentgresStateDir(stateDir)) {
    latestByBackend.set(record.backend_id, record);
  }
  return [...latestByBackend.values()]
    .sort((left, right) => String(left.backend_id).localeCompare(String(right.backend_id)))
    .map((record) => withoutNulls({
      id: record.backend_id,
      object: "ioi.model_mount_backend",
      backend_id: record.backend_id,
      backend_kind: record.backend_kind ?? null,
      status: record.public_response?.backend_status ?? record.status,
      lifecycle_status: record.status,
      source: "agentgres_backend_lifecycle_control",
      generated_at: record.generated_at,
      record_dir: "model-backend-lifecycle-controls",
      record_id: record.id,
      operation_kind: record.operation_kind,
      rust_core_boundary: record.rust_core_boundary,
      backend_lifecycle_projection_boundary: "model_mount.backend_lifecycle_projection",
      public_response: record.public_response ?? null,
      receipt_refs: record.receipt_refs ?? [],
      evidence_refs: backendLifecycleProjectionEvidenceRefs(record),
      control_hash: record.control_hash,
    }));
}

function backendLifecycleProjectionEvidenceRefs(record) {
  return [
    ...(record.evidence_refs ?? []),
    "rust_daemon_core_backend_lifecycle_projection",
    "agentgres_backend_lifecycle_replay_required",
    "model_mount_backend_list_js_facade_retired",
  ];
}

function serverControlRecordsFromAgentgresStateDir(stateDir) {
  if (!stateDir) return [];
  const recordDir = path.join(stateDir, "model-server-controls");
  if (!fs.existsSync(recordDir)) return [];
  return fs.readdirSync(recordDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(recordDir, file), "utf8")))
    .filter((record) =>
      record?.deleted !== true &&
      record?.schema_version === "ioi.model_mount.server_control_plan.v1" &&
      record?.object === "ioi.model_mount_server_control_record" &&
      typeof record?.id === "string" &&
      typeof record?.server_control_id === "string" &&
      typeof record?.operation_kind === "string" &&
      typeof record?.status === "string" &&
      typeof record?.generated_at === "string" &&
      typeof record?.control_hash === "string" &&
      record?.rust_core_boundary === "model_mount.server_control" &&
      [
        "model_mount.server_control.start",
        "model_mount.server_control.stop",
        "model_mount.server_control.restart",
        "model_mount.server_control.write",
        "model_mount.server_control.record_operation",
        "model_mount.server_control.log_append",
      ].includes(record?.operation_kind) &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("public_server_control_js_facade_retired") &&
      record.evidence_refs.includes("rust_daemon_core_server_control") &&
      record.evidence_refs.includes("agentgres_server_control_truth_required"))
    .sort((left, right) =>
      String(left.generated_at ?? "").localeCompare(String(right.generated_at ?? "")) ||
      String(left.id ?? "").localeCompare(String(right.id ?? "")));
}

function runtimeEngineControlRecordsFromAgentgresStateDir(stateDir) {
  if (!stateDir) return [];
  const recordDir = path.join(stateDir, "runtime-engine-controls");
  if (!fs.existsSync(recordDir)) return [];
  return fs.readdirSync(recordDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(recordDir, file), "utf8")))
    .filter((record) =>
      record?.deleted !== true &&
      record?.schema_version === "ioi.model_mount.runtime_engine_plan.v1" &&
      record?.object === "ioi.model_mount_runtime_engine_record" &&
      typeof record?.id === "string" &&
      typeof record?.engine_id === "string" &&
      typeof record?.status === "string" &&
      typeof record?.generated_at === "string" &&
      typeof record?.control_hash === "string" &&
      record?.rust_core_boundary === "model_mount.runtime_engine" &&
      [
        "model_mount.runtime_preference.write",
        "model_mount.runtime_engine_profile.write",
        "model_mount.runtime_engine_profile.delete",
      ].includes(record?.operation_kind) &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("public_runtime_engine_js_facade_retired") &&
      record.evidence_refs.includes("rust_daemon_core_runtime_engine") &&
      record.evidence_refs.includes("agentgres_runtime_engine_truth_required"))
    .sort((left, right) =>
      String(left.generated_at ?? "").localeCompare(String(right.generated_at ?? "")) ||
      String(left.id ?? "").localeCompare(String(right.id ?? "")));
}

function runtimeEngineListFromAgentgresStateDir(stateDir) {
  const projection = runtimeEngineProjectionStateFromAgentgresStateDir(stateDir);
  return [...projection.enginesById.values()];
}

function runtimeEngineProfilesFromAgentgresStateDir(stateDir) {
  const projection = runtimeEngineProjectionStateFromAgentgresStateDir(stateDir);
  return [...projection.profilesByEngine.values()];
}

function runtimePreferenceFromAgentgresStateDir(stateDir) {
  return runtimeEngineProjectionStateFromAgentgresStateDir(stateDir).preference;
}

function runtimeDefaultLoadOptionsFromAgentgresStateDir(stateDir, engineId) {
  const profile = runtimeEngineProjectionStateFromAgentgresStateDir(stateDir)
    .profilesByEngine.get(engineId);
  return profile?.default_load_options ?? null;
}

function runtimeEngineDetailFromAgentgresStateDir(stateDir, engineId) {
  const engine = runtimeEngineProjectionStateFromAgentgresStateDir(stateDir)
    .enginesById.get(engineId);
  if (!engine) {
    throw Object.assign(new Error("runtime engine not found"), {
      code: "model_mount_runtime_engine_not_found",
    });
  }
  return engine;
}

function runtimeEngineProjectionStateFromAgentgresStateDir(stateDir) {
  const records = runtimeEngineControlRecordsFromAgentgresStateDir(stateDir);
  const profilesByEngine = new Map();
  const latestRecordByEngine = new Map();
  let preference = null;
  for (const record of records) {
    latestRecordByEngine.set(record.engine_id, record);
    if (record.operation_kind === "model_mount.runtime_preference.write") {
      preference = runtimePreferenceProjectionFromControlRecord(record);
    }
    if (record.operation_kind === "model_mount.runtime_engine_profile.write") {
      profilesByEngine.set(record.engine_id, runtimeProfileProjectionFromControlRecord(record));
    }
    if (record.operation_kind === "model_mount.runtime_engine_profile.delete") {
      profilesByEngine.delete(record.engine_id);
    }
  }
  const selectedEngineId = preference?.selected_engine_id ?? null;
  const engineIds = new Set(profilesByEngine.keys());
  if (selectedEngineId) engineIds.add(selectedEngineId);
  const enginesById = new Map();
  for (const engineId of [...engineIds].sort()) {
    const profile = profilesByEngine.get(engineId) ?? null;
    const latestRecord = latestRecordByEngine.get(engineId) ?? null;
    const engine = runtimeEngineProjectionFromState({
      engineId,
      profile,
      preference,
      latestRecord,
      selectedEngineId,
    });
    if (engine) enginesById.set(engineId, engine);
  }
  return {
    enginesById,
    profilesByEngine: new Map([...profilesByEngine.entries()].sort(([left], [right]) =>
      String(left).localeCompare(String(right)))),
    preference,
  };
}

function runtimePreferenceProjectionFromControlRecord(record) {
  const selectedEngineId = record.public_response?.selected_engine_id ?? record.engine_id;
  return withoutNulls({
    id: "runtime_preference",
    object: "ioi.model_mount_runtime_preference",
    status: record.status,
    selected_engine_id: selectedEngineId,
    engine_id: record.engine_id,
    source: "agentgres_runtime_engine_control",
    generated_at: record.generated_at,
    record_dir: "runtime-engine-controls",
    record_id: record.id,
    operation_kind: record.operation_kind,
    rust_core_boundary: record.rust_core_boundary,
    runtime_engine_projection_boundary: "model_mount.runtime_engine_projection",
    public_response: record.public_response ?? null,
    receipt_refs: record.receipt_refs ?? [],
    evidence_refs: runtimeEngineProjectionEvidenceRefs(record),
    control_hash: record.control_hash,
  });
}

function runtimeProfileProjectionFromControlRecord(record) {
  return withoutNulls({
    id: record.engine_id,
    object: "ioi.model_mount_runtime_engine_profile",
    status: record.status,
    engine_id: record.engine_id,
    operator_label: record.public_response?.operator_label ?? null,
    default_load_options: record.public_response?.default_load_options ?? null,
    profile_recorded: record.public_response?.profile_recorded ?? null,
    source: "agentgres_runtime_engine_control",
    generated_at: record.generated_at,
    record_dir: "runtime-engine-controls",
    record_id: record.id,
    operation_kind: record.operation_kind,
    rust_core_boundary: record.rust_core_boundary,
    runtime_engine_projection_boundary: "model_mount.runtime_engine_projection",
    public_response: record.public_response ?? null,
    receipt_refs: record.receipt_refs ?? [],
    evidence_refs: runtimeEngineProjectionEvidenceRefs(record),
    control_hash: record.control_hash,
  });
}

function runtimeEngineProjectionFromState({
  engineId,
  profile,
  preference,
  latestRecord,
  selectedEngineId,
}) {
  const selected = selectedEngineId === engineId;
  const sourceRecord = profile ?? (selected ? preference : null) ?? latestRecord;
  if (!sourceRecord) return null;
  return withoutNulls({
    id: engineId,
    object: "ioi.model_mount_runtime_engine",
    engine_id: engineId,
    status: profile ? "configured" : selected ? "selected" : "planned",
    selected,
    operator_label: profile?.operator_label ?? null,
    default_load_options: profile?.default_load_options ?? null,
    source: "agentgres_runtime_engine_control",
    record_dir: "runtime-engine-controls",
    record_id: sourceRecord.record_id ?? sourceRecord.id,
    profile_record_id: profile?.record_id ?? null,
    preference_record_id: selected ? preference?.record_id ?? null : null,
    operation_kind: sourceRecord.operation_kind,
    generated_at: sourceRecord.generated_at,
    rust_core_boundary: "model_mount.runtime_engine",
    runtime_engine_projection_boundary: "model_mount.runtime_engine_projection",
    receipt_refs: sourceRecord.receipt_refs ?? [],
    evidence_refs: runtimeEngineProjectionEvidenceRefs(sourceRecord),
    control_hash: sourceRecord.control_hash,
  });
}

function runtimeEngineProjectionEvidenceRefs(record) {
  return [
    ...(Array.isArray(record?.evidence_refs) ? record.evidence_refs : []),
    "rust_daemon_core_runtime_engine_projection",
    "agentgres_runtime_engine_replay_required",
    "model_mount_runtime_engine_js_projection_retired",
  ].filter((value, index, array) => array.indexOf(value) === index);
}

function withoutNulls(object) {
  return Object.fromEntries(
    Object.entries(object).filter(([, value]) => value !== null && value !== undefined),
  );
}

function conversationStatesFromAgentgresStateDir(stateDir) {
  const conversationDir = path.join(stateDir, "model-conversations");
  return fs.readdirSync(conversationDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => JSON.parse(fs.readFileSync(path.join(conversationDir, file), "utf8")))
    .filter((record) =>
      record?.object === "ioi.model_mount_conversation_state" &&
      record?.rust_core_boundary === "model_mount.conversation" &&
      typeof record?.conversation_hash === "string" &&
      Array.isArray(record?.evidence_refs) &&
      record.evidence_refs.includes("agentgres_model_conversation_truth_required") &&
      (
        record.evidence_refs.includes("model_mount_conversation_state_rust_owned") ||
        record.evidence_refs.includes("model_mount_stream_completion_rust_owned")
      ))
    .sort((left, right) =>
      String(right.created_at ?? "").localeCompare(String(left.created_at ?? "")) ||
      String(right.id ?? "").localeCompare(String(left.id ?? "")));
}

test("read projection facade delegates product-safe lists and capabilities", () => {
  const { facade, state, readProjectionRequests } = createState();

  const runtimeCatalog = facade.runtimeModelCatalogList(state);
  assert.deepEqual(runtimeCatalog.map((entry) => entry.id), ["qwen3"]);
  assert.equal(runtimeCatalog[0].rust_core_boundary, "model_mount.provider_inventory.materialization");
  assert.deepEqual(facade.openAiModelList(state).data.map((entry) => entry.id), ["qwen3"]);
  assert.deepEqual(facade.listProductArtifacts(state).map((artifact) => artifact.model_ref), [
    "model://fixture/qwen3",
  ]);
  assert.deepEqual(facade.listArtifacts(state).map((artifact) => artifact.model_ref), [
    "model://fixture/qwen3",
  ]);
  const providers = facade.listProviders(state);
  assert.deepEqual(providers.map((provider) => provider.provider_ref), [
    "provider://fixture",
    "provider://native",
    "provider://openai",
  ]);
  const providerControlProjection = providers.find((provider) => provider.provider_id === "provider.openai");
  assert.equal(providerControlProjection.provider_projection_boundary, "model_mount.provider_control_projection");
  assert.equal(providerControlProjection.record_dir, "model-providers");
  assert.equal(providerControlProjection.private_material_returned, false);
  assert.equal(providerControlProjection.evidence_refs.includes("model_mount_provider_map_lookup_js_retired"), true);
  const endpoints = facade.listEndpoints(state);
  assert.deepEqual(endpoints.map((endpoint) => endpoint.id), ["endpoint.local"]);
  assert.equal(endpoints[0].provider_id, "provider.local");
  assert.equal(Object.hasOwn(endpoints[0], "providerId"), false);
  assert.deepEqual(facade.listInstances(state).map((instance) => instance.id), [
    "instance.loaded",
    "instance.old",
  ]);
  assert.deepEqual(facade.providerInventoryRecords(state).map((record) => record.id), [
    "provider_inventory_fixture_list_models",
    "provider_inventory_native_list_loaded",
  ]);
  assert.deepEqual(facade.modelTokenizerRecords(state).map((record) => record.id), [
    "model_tokenizer:count_tokens:test",
    "model_tokenizer:tokenize:test",
  ]);
  assert.deepEqual(facade.listRoutes(state).map((route) => route.id), [
    "route.local-first",
    "route.research",
  ]);
  const modelCapabilities = facade.listModelCapabilities(state);
  assert.deepEqual(modelCapabilities.map((capability) => capability.route_id), [
    "route.local-first",
    "route.research",
  ]);
  assert.equal(modelCapabilities[0].schema_version, "ioi.model-capability.v1");
  assert.equal(modelCapabilities[0].rust_core_boundary, "model_mount.model_capability_projection");
  assert.equal(modelCapabilities[0].credential_readiness.status, "degraded");
  assert.equal(modelCapabilities[0].candidates[0].reason, "Endpoint provider is not registered.");
  assert.equal(Object.hasOwn(modelCapabilities[0], "routeId"), false);
  const downloads = facade.listDownloads(state);
  assert.deepEqual(downloads.map((download) => download.id), ["download.qwen3"]);
  assert.equal(downloads[0].storage_projection_boundary, "model_mount.storage_projection");
  assert.equal(downloads[0].details.model_id, "qwen3");
  assert.equal(downloads.some((download) => download.id === "legacy-js-download"), false);
  const downloadStatus = facade.downloadStatus(state, "download.qwen3");
  assert.equal(downloadStatus.id, "download.qwen3");
  assert.equal(downloadStatus.details.bytes_total, 42);
  assert.throws(
    () => facade.downloadStatus(state, "missing"),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.code, "not_found");
      assert.deepEqual(error.details, { job_id: "missing" });
      return true;
    },
  );
  const storageSummary = facade.storageSummary(state);
  assert.equal(storageSummary.source, "rust_model_mount_storage_summary_projection");
  assert.equal(storageSummary.rust_core_boundary, "model_mount.storage_projection");
  assert.equal(storageSummary.filesystem_scanned, false);
  assert.deepEqual(storageSummary.record_counts, {
    catalog_imports: 1,
    downloads: 1,
    storage_controls: 1,
  });
  const backends = facade.listBackends(state);
  assert.deepEqual(backends.map((record) => record.id), ["backend.native", "backend.ollama"]);
  assert.equal(backends[0].status, "start_planned");
  assert.equal(backends[0].backend_lifecycle_projection_boundary, "model_mount.backend_lifecycle_projection");
  assert.equal(backends[0].evidence_refs.includes("agentgres_backend_lifecycle_replay_required"), true);
  assert.equal(backends.some((record) => record.id === "backend.legacy"), false);
  assert.deepEqual(facade.listConversations(state).map((record) => record.id), [
    "resp-stream",
    "resp-state",
  ]);
  assert.deepEqual(facade.listOAuthSessions(state), []);
  assert.deepEqual(facade.listOAuthStates(state), []);
  const providerHealth = facade.listProviderHealth(state);
  assert.equal(providerHealth.length, 1);
  assert.equal(providerHealth[0].schemaVersion, "model.mount.schema");
  assert.equal(providerHealth[0].source, "agentgres_provider_lifecycle_health");
  assert.equal(providerHealth[0].providerId, "provider.local");
  assert.equal(providerHealth[0].health.status, "healthy");
  assert.equal(providerHealth[0].record.id, "provider-lifecycle-health");
  assert.equal(providerHealth[0].receipt, null);
  assert.equal(providerHealth[0].replay.record.id, "provider-lifecycle-health");
  assert.equal(providerHealth[0].projectionWatermark, 1);
  const workflowBindings = facade.workflowNodeBindings(state);
  assert.equal(workflowBindings.find((binding) => binding.node === "Embedding").capability, "embeddings");
  assert.equal(workflowBindings.find((binding) => binding.node === "Reranker").capability, "rerank");
  assert.equal(workflowBindings.find((binding) => binding.node === "Receipt Gate").daemonApi, "/api/v1/workflows/receipt-gate");
  assert.equal(facade.adapterBoundaries(state).agentgres.port, "AgentgresStorePort");
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "runtime_model_catalog",
    "open_ai_model_list",
    "product_artifacts",
    "artifacts",
    "providers",
    "endpoints",
    "instances",
    "provider_inventory_records",
    "model_tokenizer_records",
    "routes",
    "model_capabilities",
    "downloads",
    "download_status",
    "download_status",
    "storage_summary",
    "backends",
    "model_conversation_states",
    "oauth_sessions",
    "oauth_states",
    "provider_health",
    "workflow_bindings",
    "adapter_boundaries",
  ]);
  assert.equal(readProjectionRequests.find((request) => request.projection_kind === "oauth_sessions").state
    && Object.keys(readProjectionRequests.find((request) => request.projection_kind === "oauth_sessions").state).length, 0);
  assert.equal(readProjectionRequests.find((request) => request.projection_kind === "oauth_states").state
    && Object.keys(readProjectionRequests.find((request) => request.projection_kind === "oauth_states").state).length, 0);
  assert.equal(readProjectionRequests.find((request) => request.projection_kind === "oauth_sessions").state_dir, state.stateDir);
  assert.equal(readProjectionRequests.find((request) => request.projection_kind === "oauth_states").state_dir, state.stateDir);
  assert.equal(readProjectionRequests.filter((request) => request.projection_kind !== "projection")
    .every((request) => !Object.hasOwn(request.state, "server")), true);
  const workflowRequest = readProjectionRequests.find((request) => request.projection_kind === "workflow_bindings");
  assert.deepEqual(workflowRequest.state, {});
  const adapterRequest = readProjectionRequests.find((request) => request.projection_kind === "adapter_boundaries");
  assert.deepEqual(adapterRequest.state, {});
  const providerHealthRequest = readProjectionRequests.find((request) => request.projection_kind === "provider_health");
  assert.deepEqual(providerHealthRequest.state, {});
  assert.equal(providerHealthRequest.state_dir, state.stateDir);
  assert.equal(Object.hasOwn(providerHealthRequest.state, "provider_health"), false);
  assert.equal(Object.hasOwn(providerHealthRequest.state, "receipts"), false);
  const conversationRequest = readProjectionRequests.find((request) => request.projection_kind === "model_conversation_states");
  assert.deepEqual(conversationRequest.state, {});
  assert.equal(conversationRequest.state_dir, state.stateDir);
  assert.equal(Object.hasOwn(conversationRequest.state, "receipts"), false);
  const instanceRequest = readProjectionRequests.find((request) => request.projection_kind === "instances");
  assert.deepEqual(instanceRequest.state, {});
  assert.equal(instanceRequest.state_dir, state.stateDir);
  assert.equal(Object.hasOwn(instanceRequest.state, "instances"), false);
  const endpointRequests = readProjectionRequests.filter((request) => request.projection_kind === "endpoints");
  assert.equal(endpointRequests.length, 1);
  assert.equal(endpointRequests.every((request) => request.state_dir === state.stateDir), true);
  assert.equal(endpointRequests.every((request) => Object.keys(request.state).length === 0), true);
  assert.equal(endpointRequests.every((request) => !Object.hasOwn(request.state, "endpoints")), true);
  const providerInventoryRequest = readProjectionRequests.find((request) =>
    request.projection_kind === "provider_inventory_records");
  assert.deepEqual(providerInventoryRequest.state, {});
  assert.equal(providerInventoryRequest.state_dir, state.stateDir);
  assert.equal(Object.hasOwn(providerInventoryRequest.state, "providers"), false);
  assert.equal(Object.hasOwn(providerInventoryRequest.state, "artifacts"), false);
  for (const projectionKind of [
    "runtime_model_catalog",
    "open_ai_model_list",
    "product_artifacts",
    "artifacts",
    "providers",
  ]) {
    const materializationRequest = readProjectionRequests.find((request) =>
      request.projection_kind === projectionKind);
    assert.deepEqual(materializationRequest.state, {});
    assert.equal(materializationRequest.state_dir, state.stateDir);
    assert.equal(Object.hasOwn(materializationRequest.state, "providers"), false);
    assert.equal(Object.hasOwn(materializationRequest.state, "artifacts"), false);
    assert.equal(Object.hasOwn(materializationRequest.state, "provider_inventory"), false);
  }
  const tokenizerRequest = readProjectionRequests.find((request) =>
    request.projection_kind === "model_tokenizer_records");
  assert.deepEqual(tokenizerRequest.state, {});
  assert.equal(tokenizerRequest.state_dir, state.stateDir);
  assert.equal(Object.hasOwn(tokenizerRequest.state, "artifacts"), false);
  assert.equal(Object.hasOwn(tokenizerRequest.state, "routes"), false);
  const routeRequest = readProjectionRequests.find((request) => request.projection_kind === "routes");
  assert.deepEqual(routeRequest.state, {});
  assert.equal(routeRequest.state_dir, state.stateDir);
  assert.equal(Object.hasOwn(routeRequest.state, "routes"), false);
  const modelCapabilitiesRequest = readProjectionRequests.find((request) =>
    request.projection_kind === "model_capabilities");
  assert.deepEqual(modelCapabilitiesRequest.state, {});
  assert.equal(modelCapabilitiesRequest.state_dir, state.stateDir);
  assert.equal(Object.hasOwn(modelCapabilitiesRequest.state, "model_capabilities"), false);
  assert.equal(Object.hasOwn(modelCapabilitiesRequest.state, "routes"), false);
  const downloadRequest = readProjectionRequests.find((request) => request.projection_kind === "downloads");
  assert.deepEqual(downloadRequest.state, {});
  assert.equal(downloadRequest.state_dir, state.stateDir);
  const downloadStatusRequests = readProjectionRequests.filter((request) =>
    request.projection_kind === "download_status");
  assert.equal(downloadStatusRequests.length, 2);
  assert.deepEqual(downloadStatusRequests.map((request) => request.download_id), [
    "download.qwen3",
    "missing",
  ]);
  assert.equal(downloadStatusRequests.every((request) => request.state_dir === state.stateDir), true);
  assert.equal(downloadStatusRequests.every((request) => Object.keys(request.state).length === 0), true);
  const storageSummaryRequest = readProjectionRequests.find((request) =>
    request.projection_kind === "storage_summary");
  assert.deepEqual(storageSummaryRequest.state, {});
  assert.equal(storageSummaryRequest.state_dir, state.stateDir);
  const backendRequest = readProjectionRequests.find((request) =>
    request.projection_kind === "backends");
  assert.deepEqual(backendRequest.state, {});
  assert.equal(backendRequest.state_dir, state.stateDir);
  const topologyRequests = readProjectionRequests.filter((request) =>
    ["artifacts", "product_artifacts", "providers", "endpoints", "instances", "provider_inventory_records", "model_tokenizer_records", "routes", "model_capabilities", "downloads", "download_status", "storage_summary", "backends", "runtime_model_catalog", "open_ai_model_list"].includes(
      request.projection_kind,
    ));
  assert.equal(topologyRequests.every((request) => Object.keys(request.state).length === 0), true);
  assert.equal(readProjectionRequests.slice(0, 3).every((request) => Object.keys(request.state).length === 0), true);
  assert.equal(readProjectionRequests.some((request) => Object.hasOwn(request.state, "adapter_boundaries")), false);
  assert.equal(readProjectionRequests.some((request) => Object.hasOwn(request.state, "workflow_bindings")), false);
  assert.equal(readProjectionRequests.some((request) => Object.hasOwn(request.state, "model_capabilities")), false);
  assert.equal(readProjectionRequests.some((request) => Object.hasOwn(request.state, "product_artifacts")), false);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind).slice(-2), [
    "workflow_bindings",
    "adapter_boundaries",
  ]);
});

test("read projection facade delegates backend logs through Rust replay only", () => {
  const { facade, state, readProjectionRequests } = createState();
  let listFilesCalled = false;

  const logs = facade.backendLogs(state, "backend.native", {
    limit: "4",
    authorization: "Bearer secret-token",
    listFiles() {
      listFilesCalled = true;
      return ["/state/backend-logs/backend.native.jsonl"];
    },
  });

  assert.equal(logs.projectionKind, "backend_logs");
  assert.equal(logs.redaction, "redacted");
  assert.deepEqual(logs.records.map((record) => record.event), ["backend_start"]);
  assert.equal(
    logs.records.some((record) => record.operation_kind === "model_mount.backend.logs_read"),
    false,
  );
  assert.equal(logs.evidenceRefs.includes("model_mount_backend_log_read_js_control_path_retired"), true);
  assert.equal(listFilesCalled, false);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), ["backend_logs"]);
  assert.deepEqual(readProjectionRequests[0].state, {
    backend_log_query: {
      backend_id: "backend.native",
      limit: 4,
    },
  });
  assert.equal(readProjectionRequests[0].state.backend_log_query.authorization, undefined);
  assert.equal(readProjectionRequests[0].state.backend_log_query.listFiles, undefined);
  assert.equal(readProjectionRequests[0].state_dir, state.stateDir);
});

test("read projection facade delegates catalog search through Rust provider inventory replay", () => {
  const { facade, state, readProjectionRequests } = createState();

  const search = facade.catalogSearch(state, {
    query: " qwen ",
    provider_ref: "provider://fixture",
    providerRef: "provider://legacy",
    limit: "10",
  });

  assert.equal(search.source, "rust_model_mount_catalog_search_projection");
  assert.equal(search.rust_core_boundary, "model_mount.catalog_search");
  assert.equal(search.query, "qwen");
  assert.equal(search.result_count, 1);
  assert.equal(search.results[0].model_ref, "model://fixture/qwen3");
  assert.equal(search.results[0].inventory_record_id, "provider_inventory_fixture_list_models");
  assert.equal(search.results.some((result) => result.provider_ref === "provider://legacy"), false);
  assert.equal(search.results.some((result) => result.provider_ref === "provider://native"), false);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), ["catalog_search"]);
  assert.equal(readProjectionRequests[0].state_dir, state.stateDir);
  assert.deepEqual(readProjectionRequests[0].state, {
    catalog_search: {
      query: "qwen",
      provider_ref: "provider://fixture",
      limit: 10,
    },
  });
  assert.equal(Object.hasOwn(readProjectionRequests[0].state.catalog_search, "providerRef"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "providers"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "artifacts"), false);
});

test("read projection facade delegates runtime-engine reads through Rust projections", () => {
  const { facade, state, readProjectionRequests } = createState();

  const engines = facade.runtimeEngineList(state);
  assert.equal(engines.length, 1);
  assert.equal(engines[0].id, "backend.llama-cpp");
  assert.equal(engines[0].selected, true);
  assert.deepEqual(engines[0].default_load_options, { gpu_layers: 4 });
  assert.equal(engines[0].runtime_engine_projection_boundary, "model_mount.runtime_engine_projection");
  assert.equal(engines[0].evidence_refs.includes("agentgres_runtime_engine_replay_required"), true);
  assert.equal(engines.some((engine) => engine.id === "backend.legacy"), false);
  assert.equal(engines.some((engine) => engine.id === "backend.deleted"), false);

  const profiles = facade.runtimeEngineProfileList(state);
  assert.equal(profiles.length, 1);
  assert.equal(profiles[0].engine_id, "backend.llama-cpp");
  assert.deepEqual(profiles[0].default_load_options, { gpu_layers: 4 });
  assert.equal(profiles[0].operator_label, "Native local");
  assert.equal(profiles[0].record_dir, "runtime-engine-controls");

  const preference = facade.runtimePreferenceProjection(state);
  assert.equal(preference.selected_engine_id, "backend.llama-cpp");
  assert.equal(preference.record_id, "runtime-engine-control:preference");

  const endpointPreference = facade.runtimePreferenceForEndpointProjection(state, {
    backendId: "backend.llama-cpp",
  });
  assert.equal(endpointPreference.selected_engine_id, "backend.llama-cpp");

  const defaultLoadOptions = facade.runtimeDefaultLoadOptionsProjection(state, "backend.llama-cpp");
  assert.deepEqual(defaultLoadOptions, { gpu_layers: 4 });

  const detail = facade.runtimeEngineProjection(state, "backend.llama-cpp");
  assert.equal(detail.id, "backend.llama-cpp");
  assert.equal(detail.profile_record_id, "runtime-engine-control:profile");
  assert.equal(detail.preference_record_id, "runtime-engine-control:preference");

  assert.throws(
    () => facade.runtimeEngineProjection(state, "backend.missing"),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.engine_id === "backend.missing",
  );

  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "runtime_engines",
    "runtime_engine_profiles",
    "runtime_preference",
    "runtime_preference_for_endpoint",
    "runtime_default_load_options",
    "runtime_engine_detail",
    "runtime_engine_detail",
  ]);
  assert.equal(readProjectionRequests.every((request) => Object.keys(request.state).length === 0), true);
  assert.equal(readProjectionRequests.every((request) => request.state_dir === state.stateDir), true);
  assert.equal(readProjectionRequests[4].engine_id, "backend.llama-cpp");
  assert.equal(readProjectionRequests[5].engine_id, "backend.llama-cpp");
  assert.equal(readProjectionRequests[6].engine_id, "backend.missing");
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "server")), true);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "projection")), true);
});

test("read projection facade composes snapshots, projection, and receipt replay", () => {
  const { facade, state, readProjectionRequests } = createState();

  const snapshot = facade.snapshot(state, "http://127.0.0.1:3200");
  assert.equal(snapshot.schemaVersion, "model.mount.schema");
  assert.equal(snapshot.server.status, "blocked");
  assert.equal(snapshot.catalog.adapterBoundary.port, "ModelCatalogProviderPort");
  assert.equal(snapshot.catalog.lastSearch.result_count, 1);
  assert.equal(snapshot.catalog.storage.record_count, 2);
  assert.deepEqual(snapshot.catalog.providers.map((provider) => provider.provider_ref), [
    "provider://fixture",
    "provider://native",
  ]);
  assert.deepEqual(snapshot.catalog.results.map((result) => result.model_ref), ["model://fixture/qwen3"]);
  assert.equal(Object.hasOwn(snapshot, "catalogProviderConfigs"), false);
  assert.equal(snapshot.artifacts.length, 0);
  assert.equal(snapshot.endpoints.length, 0);
  assert.equal(snapshot.providers.length, 0);
  assert.equal(snapshot.routes.length, 0);
  assert.deepEqual(snapshot.downloads.map((download) => download.id), ["download.qwen3"]);
  assert.equal(snapshot.modelCapabilities.length, 0);
  assert.equal(snapshot.projection.source, "agentgres_model_mounting_projection");
  assert.equal(snapshot.adapterBoundaries.agentgres.port, "AgentgresStorePort");

  const projection = facade.projection(state);
  assert.equal(projection.schemaVersion, "model.mount.schema");
  assert.deepEqual(projection.artifacts.map((artifact) => artifact.model_ref), ["model://fixture/qwen3"]);
  assert.deepEqual(projection.endpoints.map((endpoint) => endpoint.id), ["endpoint.local"]);
  assert.deepEqual(projection.providers.map((provider) => provider.provider_ref), [
    "provider://fixture",
    "provider://native",
    "provider://openai",
  ]);
  assert.deepEqual(projection.routes.map((route) => route.id), [
    "route.local-first",
    "route.research",
  ]);
  assert.deepEqual(projection.downloads.map((download) => download.id), ["download.qwen3"]);
  assert.equal(projection.modelCapabilities.length, 0);
  assert.equal(projection.routeReceipts.length, 1);
  assert.equal(projection.lifecycleEvents.length, 1);
  assert.equal(projection.catalog.adapterBoundary.port, "ModelCatalogProviderPort");
  assert.equal(projection.catalog.lastSearch.result_count, 1);
  assert.equal(projection.catalog.storage.record_count, 2);
  assert.deepEqual(projection.catalog.providers.map((provider) => provider.provider_ref), [
    "provider://fixture",
    "provider://native",
  ]);
  assert.deepEqual(projection.catalog.results.map((result) => result.model_ref), ["model://fixture/qwen3"]);
  assert.equal(Object.hasOwn(projection, "catalogProviderConfigs"), false);
  assert.equal(projection.adapterBoundaries.agentgres.port, "AgentgresStorePort");
  assert.equal(projection.adapterBoundaries.oauth.plaintextPersistence, false);

  const projectionWritePlan = facade.canonicalProjectionWritePlan(state);
  assert.equal(projectionWritePlan.source, "rust_model_mount_read_projection_command");
  assert.equal(projectionWritePlan.projection_kind, "projection");
  assert.equal(projectionWritePlan.projection.source, "agentgres_model_mounting_projection");
  assert.equal(projectionWritePlan.evidence_refs.includes("agentgres_model_mount_read_truth"), true);

  const summary = facade.projectionSummary(state);
  assert.equal(summary.schemaVersion, "model.mount.schema");
  assert.equal(summary.receiptCount, 5);

  const replay = facade.receiptReplay(state, "receipt-route");
  assert.equal(replay.schemaVersion, "model.mount.schema");
  assert.equal(replay.route, null);
  assert.equal(replay.endpoint, null);
  assert.equal(replay.provider, null);
  assert.equal(replay.model_route_decision.selected_model, "model.local");
  assert.equal(Object.hasOwn(replay, "modelRouteDecision"), false);

  const routeDecisions = facade.modelRouteDecisions(state);
  assert.equal(routeDecisions[0].receipt_id, "receipt-route");
  assert.equal(routeDecisions[0].selected_model, "model.local");
  assert.equal(routeDecisions[0].record_dir, "model-route-selections");
  assert.equal(routeDecisions[0].record_id, "route_selection:route.local-first:test");

  const endpointResolutions = facade.modelRouteEndpointResolutions(state);
  assert.equal(endpointResolutions[0].route_id, "route.local-first");
  assert.equal(endpointResolutions[0].model_id, "model.local");
  assert.equal(endpointResolutions[0].record_dir, "model-route-endpoint-resolutions");

  const authority = facade.authoritySnapshot(state, "http://127.0.0.1:3200");
  assert.equal(authority.schemaVersion, "ioi.wallet-core-lite.authority.v1");
  assert.equal(authority.wallet, null);
  assert.deepEqual(authority.grants, []);
  assert.deepEqual(authority.vaultRefs, []);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "snapshot",
    "projection",
    "projection",
    "projection_summary",
    "receipt_replay",
    "model_route_decisions",
    "model_route_endpoint_resolutions",
    "authority_snapshot",
  ]);
  const snapshotRequest = readProjectionRequests[0];
  assert.equal(Object.hasOwn(snapshotRequest.state, "catalog"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "backends"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "backend_processes"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "catalog_status_input"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "catalog_provider_configs"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "oauth_sessions"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "oauth_states"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "runtime_engines"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "runtime_engine_profiles"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "runtime_preference"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "mcp_servers"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "conversation_states"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "grants"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "vault_refs"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "agentgres_store"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "wallet"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "vault"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "provider_health"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "runtime_survey_input"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "server_status_input"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "artifacts"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "endpoints"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "instances"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "providers"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "routes"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "downloads"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "product_artifact_policy"), false);
  const projectionRequest = readProjectionRequests[1];
  assert.equal(Object.hasOwn(projectionRequest.state, "catalog"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "backends"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "backend_processes"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "catalog_status_input"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "catalog_provider_configs"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "oauth_sessions"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "oauth_states"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "runtime_engines"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "runtime_engine_profiles"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "runtime_preference"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "mcp_servers"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "conversation_states"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "grants"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "vault_refs"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "agentgres_store"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "wallet"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "vault"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "provider_health"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "runtime_survey_input"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "server_status_input"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "artifacts"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "endpoints"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "instances"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "providers"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "routes"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "downloads"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "product_artifact_policy"), false);
  const summaryRequest = readProjectionRequests.find((request) => request.projection_kind === "projection_summary");
  assert.deepEqual(summaryRequest.state, {});
  assert.equal(summaryRequest.state_dir, state.stateDir);
  const replayRequest = readProjectionRequests.find((request) => request.projection_kind === "receipt_replay");
  assert.deepEqual(replayRequest.state, {});
  assert.equal(replayRequest.state_dir, state.stateDir);
  assert.equal(replayRequest.receipt_id, "receipt-route");
  assert.equal(Object.hasOwn(replayRequest.state, "routes"), false);
  assert.equal(Object.hasOwn(replayRequest.state, "endpoints"), false);
  assert.equal(Object.hasOwn(replayRequest.state, "instances"), false);
  assert.equal(Object.hasOwn(replayRequest.state, "providers"), false);
  assert.equal(Object.hasOwn(replayRequest.state, "server"), false);
  assert.equal(Object.hasOwn(replayRequest.state, "artifacts"), false);
  const routeDecisionRequest = readProjectionRequests.find((request) => request.projection_kind === "model_route_decisions");
  assert.deepEqual(routeDecisionRequest.state, {});
  assert.equal(routeDecisionRequest.state_dir, state.stateDir);
  assert.equal(Object.hasOwn(routeDecisionRequest.state, "receipts"), false);
  const endpointResolutionRequest = readProjectionRequests.find(
    (request) => request.projection_kind === "model_route_endpoint_resolutions",
  );
  assert.deepEqual(endpointResolutionRequest.state, {});
  assert.equal(endpointResolutionRequest.state_dir, state.stateDir);
  assert.equal(Object.hasOwn(endpointResolutionRequest.state, "receipts"), false);
  const authorityRequest = readProjectionRequests.at(-1);
  assert.deepEqual(authorityRequest.state, {});
  assert.equal(authorityRequest.state_dir, state.stateDir);
  assert.equal(Object.hasOwn(authorityRequest.state, "providers"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "artifacts"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "server_status_input"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "grants"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "vault_refs"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "wallet"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "vault"), false);
});

test("read projection facade delegates server status through Rust projection", () => {
  const { facade, state, readProjectionRequests } = createState();

  const status = facade.serverStatus(state, "http://127.0.0.1:3200");

  assert.equal(status.schemaVersion, "model.mount.schema");
  assert.equal(status.status, "blocked");
  assert.equal(status.gatewayStatus, "running");
  assert.equal(status.lastServerOperation, "server_stop");
  assert.equal(status.lastServerReceiptId, "receipt://server/operation");
  assert.equal(status.recordCount, 2);
  assert.equal(status.rustCoreBoundary, "model_mount.server_control_projection");
  assert.equal(status.evidenceRefs.includes("agentgres_server_control_replay_required"), true);
  assert.equal(status.nativeBaseUrl, "http://127.0.0.1:3200/api/v1");
  assert.equal(status.openAiCompatibleBaseUrl, "http://127.0.0.1:3200/v1");
  assert.equal(status.loadedInstances, 2);
  assert.equal(status.mountedEndpoints, 1);
  assert.deepEqual(status.providerStates, { available: 3, degraded: 0 });
  assert.deepEqual(status.backendStates, { available: 1, degraded: 1 });
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), ["server_status"]);
  assert.deepEqual(readProjectionRequests[0].state, {});
  assert.equal(readProjectionRequests[0].state_dir, state.stateDir);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "server_status_input"), false);
  assert.equal(readProjectionRequests[0].base_url, "http://127.0.0.1:3200");
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "receipts"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "projection"), false);
});

test("read projection facade delegates server logs and events through Rust projection", () => {
  const { facade, state, readProjectionRequests } = createState();
  writeServerControlRecords(state.stateDir, [
    {
      id: "server-control:restart",
      schema_version: "ioi.model_mount.server_control_plan.v1",
      object: "ioi.model_mount_server_control_record",
      server_control_id: "server-control.default",
      operation_kind: "model_mount.server_control.restart",
      status: "planned",
      source: "runtime-daemon.model_mounting.server_control",
      generated_at: "2026-06-03T00:00:03.000Z",
      rust_core_boundary: "model_mount.server_control",
      control_hash: "sha256:server-restart",
      public_response: {
        object: "ioi.model_mount_server_control",
        status: "planned",
        operation_kind: "model_mount.server_control.restart",
        server_control_id: "server-control.default",
        rust_core_boundary: "model_mount.server_control",
        server_status: "restart_planned",
        js_state_write: false,
        js_log_write: false,
        js_transport_execution: false,
      },
      receipt_refs: ["receipt://server/restart", "sha256:server-restart"],
      evidence_refs: [
        "public_server_control_js_facade_retired",
        "rust_daemon_core_server_control",
        "agentgres_server_control_truth_required",
      ],
    },
    {
      id: "server-control:log-append",
      schema_version: "ioi.model_mount.server_control_plan.v1",
      object: "ioi.model_mount_server_control_record",
      server_control_id: "server-control.default",
      operation_kind: "model_mount.server_control.log_append",
      status: "planned",
      source: "runtime-daemon.model_mounting.server_control",
      generated_at: "2026-06-03T00:00:04.000Z",
      rust_core_boundary: "model_mount.server_control",
      control_hash: "sha256:server-log-append",
      public_response: {
        object: "ioi.model_mount_server_control",
        status: "planned",
        operation_kind: "model_mount.server_control.log_append",
        server_control_id: "server-control.default",
        rust_core_boundary: "model_mount.server_control",
        event: "provider_probe",
        level: "info",
        message: "provider probe completed",
        log_appended: true,
        js_state_write: false,
        js_log_write: false,
        js_transport_execution: false,
      },
      receipt_refs: ["receipt://server/log-append", "sha256:server-log-append"],
      evidence_refs: [
        "public_server_control_js_facade_retired",
        "rust_daemon_core_server_control",
        "agentgres_server_control_truth_required",
      ],
    },
    {
      id: "server-control:retired-logs-read",
      schema_version: "ioi.model_mount.server_control_plan.v1",
      object: "ioi.model_mount_server_control_record",
      server_control_id: "server-control.default",
      operation_kind: "model_mount.server_control.logs_read",
      status: "planned",
      source: "runtime-daemon.model_mounting.server_control",
      generated_at: "2026-06-03T00:00:05.000Z",
      rust_core_boundary: "model_mount.server_control",
      control_hash: "sha256:retired-logs-read",
      public_response: {
        object: "ioi.model_mount_server_control",
        status: "planned",
        operation_kind: "model_mount.server_control.logs_read",
        server_control_id: "server-control.default",
      },
      receipt_refs: ["receipt://server/logs-read", "sha256:retired-logs-read"],
      evidence_refs: [
        "public_server_control_js_facade_retired",
        "rust_daemon_core_server_control",
        "agentgres_server_control_truth_required",
      ],
    },
  ]);

  const logs = facade.serverLogs(state, {
    limit: "2",
    event: "server_restart",
    authorization: "Bearer secret-token",
  });
  const events = facade.serverEvents(state, { limit: "2" });
  const records = facade.serverLogRecords(state, { limit: 1 });

  assert.deepEqual(logs.records.map((record) => record.event), ["server_restart", "provider_probe"]);
  assert.deepEqual(events.events.map((event) => event.event), ["server_restart", "provider_probe"]);
  assert.deepEqual(records.records.map((record) => record.event), ["provider_probe"]);
  assert.equal(logs.redaction, "redacted");
  assert.equal(logs.recordCount, 4);
  assert.equal(events.events.some((event) => event.event === "server_events_read"), false);
  assert.equal(logs.evidenceRefs.includes("model_mount_server_log_read_js_control_path_retired"), true);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "server_logs",
    "server_events",
    "server_log_records",
  ]);
  assert.deepEqual(readProjectionRequests[0].state, {
    server_log_query: {
      limit: 2,
    },
  });
  assert.equal(readProjectionRequests[0].state.server_log_query.authorization, undefined);
  assert.equal(readProjectionRequests[0].state_dir, state.stateDir);
});

test("read projection facade delegates catalog status through Rust projection", () => {
  const { facade, state, readProjectionRequests } = createState();

  const status = facade.catalogStatus(state);

  assert.equal(status.schemaVersion, "model.mount.schema");
  assert.equal(status.adapterBoundary.port, "ModelCatalogProviderPort");
  assert.deepEqual(status.providers.map((provider) => provider.provider_ref), [
    "provider://fixture",
    "provider://native",
  ]);
  assert.equal(status.providers[0].rust_core_boundary, "model_mount.catalog_status");
  assert.equal(status.providers[0].model_count, 1);
  assert.equal(status.providers[1].loaded_instance_count, 1);
  assert.equal(status.storage.record_count, 2);
  assert.equal(status.lastSearch.result_count, 1);
  assert.deepEqual(status.results.map((result) => result.model_ref), ["model://fixture/qwen3"]);
  assert.equal(status.results[0].inventory_record_id, "provider_inventory_fixture_list_models");
  assert.equal(status.source, "agentgres_provider_inventory");
  assert.equal(status.rust_core_boundary, "model_mount.catalog_status");
  assert.equal(status.evidence_refs.includes("agentgres_catalog_status_replay_required"), true);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), ["catalog_status"]);
  assert.deepEqual(readProjectionRequests[0].state, {});
  assert.equal(readProjectionRequests[0].state_dir, state.stateDir);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "catalog_status_input"), false);
});

test("read projection facade projects latest provider and vault health envelopes", () => {
  const { facade, state, readProjectionRequests } = createState();

  const providerHealth = facade.latestProviderHealth(state, "provider.local");
  assert.equal(providerHealth.schemaVersion, "model.mount.schema");
  assert.equal(providerHealth.source, "agentgres_provider_lifecycle_health_latest");
  assert.equal(providerHealth.providerId, "provider.local");
  assert.equal(providerHealth.health.status, "healthy");
  assert.equal(providerHealth.health.provider_id, "provider.local");
  assert.equal(providerHealth.record.id, "provider-lifecycle-health");
  assert.equal(providerHealth.receipt, null);
  assert.equal(providerHealth.replay.record.id, "provider-lifecycle-health");
  assert.equal(providerHealth.projectionWatermark, 1);

  const vaultHealth = facade.latestVaultHealth(state);
  assert.equal(vaultHealth.schemaVersion, "model.mount.schema");
  assert.equal(vaultHealth.source, "agentgres_vault_health_latest");
  assert.equal(vaultHealth.health.implementation, "runtime_memory_vault");
  assert.equal(vaultHealth.receipt.id, "receipt-vault-health");
  assert.equal(vaultHealth.replay.receipt.id, "receipt-vault-health");
  assert.equal(vaultHealth.projectionWatermark, 5);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "latest_provider_health",
    "latest_vault_health",
  ]);
  assert.equal(readProjectionRequests[0].provider_id, "provider.local");
  assert.deepEqual(readProjectionRequests[0].state, {});
  assert.equal(readProjectionRequests[0].state_dir, state.stateDir);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "provider_health"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "providers"), false);
  assert.deepEqual(readProjectionRequests[1].state, {});
  assert.equal(readProjectionRequests[1].state_dir, state.stateDir);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "server")), true);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "artifacts")), true);
});

test("read projection facade delegates latest runtime survey through Rust projection", () => {
  const { facade, state, readProjectionRequests } = createState();

  const notChecked = facade.latestRuntimeSurvey(state);
  assert.equal(notChecked.status, "not_checked");
  assert.equal(notChecked.receiptId, "none");
  assert.equal(notChecked.engineCount, 0);
  assert.equal(notChecked.runtimePreference, null);
  assert.equal(notChecked.hardware, null);
  assert.equal(notChecked.lmStudio.status, "not_checked");

  writeReceiptRecords(state.stateDir, [{
    id: "receipt-runtime-survey",
    kind: "runtime_survey",
    createdAt: "2026-06-03T00:01:00.000Z",
    details: {
      checked_at: "2026-06-03T00:01:00.000Z",
      engine_count: 1,
      selected_engines: ["backend.llama-cpp"],
      runtime_preference: { selectedEngineId: "backend.llama-cpp" },
      hardware: { cpuCount: 16 },
      lm_studio: { status: "available" },
    },
  }]);
  const checked = facade.latestRuntimeSurvey(state);
  assert.equal(checked.status, "checked");
  assert.equal(checked.receiptId, "receipt-runtime-survey");
  assert.deepEqual(checked.selectedEngines, ["backend.llama-cpp"]);
  assert.deepEqual(checked.hardware, { cpuCount: 16 });
  assert.equal(checked.lmStudio.status, "available");

  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "latest_runtime_survey",
    "latest_runtime_survey",
  ]);
  assert.deepEqual(readProjectionRequests[0].state, {});
  assert.equal(readProjectionRequests[0].state_dir, state.stateDir);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "runtime_survey_input"), false);
  assert.deepEqual(readProjectionRequests[1].state, {});
  assert.equal(readProjectionRequests[1].state_dir, state.stateDir);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "server")), true);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "runtime_survey")), true);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "runtime_survey_input")), true);
});

test("read projection facade preserves latest health not-found errors", () => {
  const { facade, state, readProjectionPlanner, readProjectionRequests } = createState();

  readProjectionPlanner.planReadProjection = (request) => {
    readProjectionRequests.push(request);
    if (request.projection_kind === "latest_provider_health") {
      throw Object.assign(new Error("provider health has not been checked"), {
        code: "model_mount_provider_health_not_found",
      });
    }
    if (request.projection_kind === "latest_vault_health") {
      throw Object.assign(new Error("vault adapter health has not been checked"), {
        code: "model_mount_vault_health_not_found",
      });
    }
    return {
      source: "rust_model_mount_read_projection_command",
      backend: "rust_model_mount_read_projection",
      projection_kind: request.projection_kind,
      projection: rustProjectionFixture(request),
    };
  };

  assert.throws(
    () => facade.latestProviderHealth(state, "provider.local"),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.providerId === "provider.local",
  );

  assert.throws(
    () => facade.latestVaultHealth(state),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.receiptKind === "vault_adapter_health",
  );
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "latest_provider_health",
    "latest_vault_health",
  ]);
  assert.equal(readProjectionRequests[0].provider_id, "provider.local");
  assert.deepEqual(readProjectionRequests[0].state, {});
  assert.equal(readProjectionRequests[0].state_dir, state.stateDir);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "provider_health"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "providers"), false);
  assert.deepEqual(readProjectionRequests[1].state, {});
  assert.equal(readProjectionRequests[1].state_dir, state.stateDir);
});
