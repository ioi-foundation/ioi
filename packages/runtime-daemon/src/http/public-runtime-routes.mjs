import crypto from "node:crypto";

import {
  createAgent as createLifecycleAgent,
  createThread as createLifecycleThread,
} from "../runtime-agent-run-lifecycle.mjs";
import { admitArtifactAvailabilityIncident } from "../runtime-artifact-availability-incident.mjs";
import { planHarnessAdapterContainerLane } from "../runtime-harness-container-lane.mjs";
import { runHarnessPublicFixtureRun } from "../runtime-harness-public-fixture-run.mjs";
import { admitHypervisorApprovedOperation } from "../runtime-hypervisor-approved-operation-admission.mjs";
import { dispatchHypervisorApprovedOperationPlan } from "../runtime-hypervisor-approved-operation-dispatch.mjs";
import { buildHypervisorCoreTaxonomy } from "../runtime-hypervisor-core-taxonomy.mjs";
import { admitManagedWorkerInstanceLifecycleTransition } from "../runtime-managed-worker-instance-lifecycle-admission.mjs";
import { admitHarnessSessionBinding } from "../runtime-harness-session-binding-admission.mjs";
import { buildHarnessSessionLaunch } from "../runtime-harness-session-launch.mjs";
import { buildHarnessSessionReadiness } from "../runtime-harness-session-readiness.mjs";
import { buildHarnessSessionSpawn } from "../runtime-harness-session-spawn.mjs";
import { deriveWorkspaceInitializer } from "../runtime-environment-status-projection.mjs";
import { createHarnessReceiptSink } from "../runtime-harness-receipt-sink.mjs";
import { admitHarnessSessionTerminalAttach } from "../runtime-harness-session-terminal-attach.mjs";
import { admitHypervisorSessionLaunchRecipe } from "../runtime-hypervisor-session-launch-recipe-admission.mjs";
import { admitModelRouteMutation } from "../runtime-model-route-mutation-admission.mjs";
import { admitModelWeightCustodyRoute } from "../runtime-model-weight-custody-admission.mjs";
import { admitPhysicalActionIntent } from "../runtime-physical-action-intent-admission.mjs";
import { admitPrivateWorkspaceMount } from "../runtime-private-workspace-mount-admission.mjs";
import { admitServiceCompositionReceiptBundle } from "../runtime-service-composition-receipt-bundle.mjs";
import { admitWorkerPackageInstall } from "../runtime-worker-package-install-admission.mjs";
import { admitCodeEditorAdapterLaunchPlan } from "../runtime-code-editor-adapter-launch-plan-admission.mjs";

export function createPublicRuntimeRequestHandler(deps) {
  const {
    RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    agentgresAdmissionClient = null,
    baseUrlForRequest,
    createLifecycleAgent: createLifecycleAgentDep = createLifecycleAgent,
    createLifecycleThread: createLifecycleThreadDep = createLifecycleThread,
    ensureProviderAvailable = null,
    executeApprovedOperationPlan = null,
    executeHarnessContainerLane = null,
    executeHarnessSpawnLane = null,
    eventStreamIdForThread = null,
    handleAgentRoute,
    handleModelMountingNativeRoute,
    handleOpenAiCompatibilityRoute,
    handleRunRoute,
    handleThreadRoute,
    initialThreadRuntimeControls = null,
    isOpenAiCompatibilityRoute,
    mcpRegistryForWorkspace = null,
    normalizeBooleanOption,
    notFound,
    optionalString,
    provisionSessionWorkspace = null,
    readBody,
    runtimeError = null,
    runtimeModeForOptions = null,
    runtimeThreadSchemaVersion = null,
    summarizeAgentOptions = null,
    threadIdForAgent = null,
    threadStatusForAgent = null,
    usageRequestMetadataFromUrl,
    usageTelemetryWithRequestMetadata,
    writeError,
    writeJsonResponse,
    writeMcpJsonRpcResponse,
  } = deps;
  const lifecycleRuntimeError = typeof runtimeError === "function" ? runtimeError : undefined;
  function requiredPublicRuntimeContextPolicyCore(contextPolicyCore, rustCoreBoundary) {
    if (contextPolicyCore) {
      return contextPolicyCore;
    }
    const error = {
      status: 501,
      code: "runtime_route_context_policy_core_required",
      message: "Public runtime routes require the explicit Rust daemon-core policy boundary.",
      details: {
        rust_core_boundary: rustCoreBoundary,
        retired_store_fallback: "context_policy_core_store_mount",
      },
    };
    throw lifecycleRuntimeError ? lifecycleRuntimeError(error) : Object.assign(new Error(error.message), error);
  }

  return async function handleRequest({ request, response, store, contextPolicyCore = null }) {
    const requestId = `req_${crypto.randomUUID()}`;
    response.setHeader("x-request-id", requestId);
    response.setHeader("access-control-allow-origin", "*");
    response.setHeader("access-control-allow-headers", "authorization,content-type,last-event-id,x-api-key");
    response.setHeader("access-control-allow-methods", "GET,POST,PATCH,DELETE,OPTIONS");
    if (request.method === "OPTIONS") {
      response.statusCode = 204;
      response.end();
      return;
    }

    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const segments = url.pathname.split("/").filter(Boolean);
    // Unified-Rust-daemon migration: the thread/agent/run/turn lifecycle is owned by the
    // Rust hypervisor-daemon (binds 127.0.0.1:8765). The JS daemon's lifecycle COLLECTION
    // routes are retired (demoted to non-serving); non-lifecycle routes are preserved.
    if (
      segments[0] === "v1" &&
      !segments[2] &&
      (segments[1] === "threads" ||
        segments[1] === "agents" ||
        segments[1] === "runs" ||
        segments[1] === "tasks" ||
        segments[1] === "jobs")
    ) {
      response.statusCode = 410;
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          error: {
            code: "runtime_lifecycle_retired_served_by_rust_daemon",
            message:
              "The runtime thread/agent/run lifecycle is served by the Rust hypervisor-daemon; the JS daemon no longer owns it.",
            retryable: false,
            requestId,
            details: { path: url.pathname, rust_daemon_endpoint: "http://127.0.0.1:8765" },
          },
        }),
      );
      return;
    }
    try {
      if (segments[0] === "api" && segments[1] === "v1") {
        await handleModelMountingNativeRoute({ request, response, store, url, segments });
        return;
      }
      if (segments[0] === "v1" && isOpenAiCompatibilityRoute(request, url)) {
        await handleOpenAiCompatibilityRoute({ request, response, store, url });
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/doctor") {
        // The redacted runtime-readiness report is served by the Rust hypervisor-daemon.
        writeJsonResponse(
          response,
          {
            error: {
              code: "runtime_lifecycle_retired_served_by_rust_daemon",
              message:
                "The doctor report is served by the Rust hypervisor-daemon; the JS daemon no longer owns it.",
              retryable: false,
              details: { path: url.pathname, rust_daemon_endpoint: "http://127.0.0.1:8765" },
            },
          },
          410,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hypervisor/home-cockpit") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_projection.hypervisor_home_cockpit",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_home_cockpit_projection",
          operation_kind: "runtime.lifecycle_projection.hypervisor_home_cockpit",
          projection_kind: "hypervisor_home_cockpit",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(url.searchParams.get("project_id")),
          source: "public_runtime_routes./v1/hypervisor/home-cockpit",
        });
        writeJsonResponse(
          response,
          projected.projection ?? projected.record?.projection ?? projected,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hypervisor/session-operations") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_projection.hypervisor_session_operations",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_session_operations_projection",
          operation_kind: "runtime.lifecycle_projection.hypervisor_session_operations",
          projection_kind: "hypervisor_session_operations",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(url.searchParams.get("project_id")),
          session_ref: optionalString(url.searchParams.get("session_ref")),
          source: "public_runtime_routes./v1/hypervisor/session-operations",
        });
        writeJsonResponse(
          response,
          projected.projection ?? projected.record?.projection ?? projected,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hypervisor/project-state") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_projection.hypervisor_project_state",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_project_state_projection",
          operation_kind: "runtime.lifecycle_projection.hypervisor_project_state",
          projection_kind: "hypervisor_project_state",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(url.searchParams.get("project_id")),
          source: "public_runtime_routes./v1/hypervisor/project-state",
        });
        writeJsonResponse(
          response,
          projected.projection ?? projected.record?.projection ?? projected,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hypervisor/automation-compositor") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_projection.hypervisor_automation_compositor",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_automation_compositor_projection",
          operation_kind:
            "runtime.lifecycle_projection.hypervisor_automation_compositor",
          projection_kind: "hypervisor_automation_compositor",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(url.searchParams.get("project_id")),
          source: "public_runtime_routes./v1/hypervisor/automation-compositor",
        });
        writeJsonResponse(
          response,
          projected.projection ?? projected.record?.projection ?? projected,
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/hypervisor/automation-runs/proposals") {
        const body = await readBody(request);
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_operation.hypervisor_automation_run_proposal",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_automation_run_proposal",
          operation_kind:
            "runtime.lifecycle_operation.hypervisor_automation_run_proposal",
          projection_kind: "hypervisor_automation_run_proposal",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(
            body.selected_project_id ?? body.project_id ?? body.project_ref,
          ),
          template_ref: optionalString(body.template_ref),
          run_recipe_ref: optionalString(body.run_recipe_ref),
          graph_ref: optionalString(body.graph_ref),
          launch_action_ref: optionalString(body.launch_action_ref),
          requested_operation: optionalString(body.operation_kind),
          required_scope_refs: Array.isArray(body.required_scope_refs)
            ? body.required_scope_refs.filter(
                (scopeRef) => typeof scopeRef === "string" && scopeRef,
              )
            : [],
          model_route_policy_ref: optionalString(body.model_route_policy_ref),
          receipt_policy_ref: optionalString(body.receipt_policy_ref),
          context_chamber_refs: Array.isArray(body.context_chamber_refs)
            ? body.context_chamber_refs.filter(
                (chamberRef) => typeof chamberRef === "string" && chamberRef,
              )
            : [],
          artifact_refs: Array.isArray(body.artifact_refs)
            ? body.artifact_refs.filter(
                (artifactRef) => typeof artifactRef === "string" && artifactRef,
              )
            : [],
          latest_receipt_refs: Array.isArray(body.latest_receipt_refs)
            ? body.latest_receipt_refs.filter(
                (receiptRef) => typeof receiptRef === "string" && receiptRef,
              )
            : [],
          state_root_ref: optionalString(body.state_root_ref),
          source:
            "public_runtime_routes./v1/hypervisor/automation-runs/proposals",
        });
        writeJsonResponse(
          response,
          projected.proposal ??
            projected.record?.proposal ??
            projected.record?.projection ??
            projected.record ??
            projected,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hypervisor/agents") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_projection.hypervisor_agents",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_agents_projection",
          operation_kind: "runtime.lifecycle_projection.hypervisor_agents",
          projection_kind: "agents",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(url.searchParams.get("project_id")),
          source: "public_runtime_routes./v1/hypervisor/agents",
        });
        writeJsonResponse(
          response,
          projected.projection ?? projected.record?.projection ?? projected,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hypervisor/model-infrastructure") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_projection.hypervisor_model_infrastructure",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_model_infrastructure_projection",
          operation_kind:
            "runtime.lifecycle_projection.hypervisor_model_infrastructure",
          projection_kind: "hypervisor_model_infrastructure",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(url.searchParams.get("project_id")),
          session_ref: optionalString(url.searchParams.get("session_ref")),
          source: "public_runtime_routes./v1/hypervisor/model-infrastructure",
        });
        writeJsonResponse(
          response,
          projected.projection ?? projected.record?.projection ?? projected,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hypervisor/privacy-posture") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_projection.hypervisor_privacy_posture",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_privacy_posture_projection",
          operation_kind:
            "runtime.lifecycle_projection.hypervisor_privacy_posture",
          projection_kind: "hypervisor_privacy_posture",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(url.searchParams.get("project_id")),
          session_ref: optionalString(url.searchParams.get("session_ref")),
          source: "public_runtime_routes./v1/hypervisor/privacy-posture",
        });
        writeJsonResponse(
          response,
          projected.projection ?? projected.record?.projection ?? projected,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hypervisor/provider-placement") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_projection.hypervisor_provider_placement",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_provider_placement_projection",
          operation_kind: "runtime.lifecycle_projection.hypervisor_provider_placement",
          projection_kind: "hypervisor_provider_placement",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(url.searchParams.get("project_id")),
          source: "public_runtime_routes./v1/hypervisor/provider-placement",
        });
        writeJsonResponse(
          response,
          projected.projection ?? projected.record?.projection ?? projected,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hypervisor/receipt-evidence") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_projection.hypervisor_receipt_evidence",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_receipt_evidence_projection",
          operation_kind: "runtime.lifecycle_projection.hypervisor_receipt_evidence",
          projection_kind: "hypervisor_receipt_evidence",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(url.searchParams.get("project_id")),
          session_ref: optionalString(url.searchParams.get("session_ref")),
          receipt_page_cursor: optionalString(
            url.searchParams.get("page_cursor"),
          ),
          receipt_page_size: optionalString(url.searchParams.get("page_size")),
          source: "public_runtime_routes./v1/hypervisor/receipt-evidence",
        });
        writeJsonResponse(
          response,
          projected.projection ?? projected.record?.projection ?? projected,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hypervisor/core-taxonomy") {
        writeJsonResponse(response, buildHypervisorCoreTaxonomy());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/hypervisor/provider-operations") {
        const body = await readBody(request);
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_operation.hypervisor_provider_operation_proposal",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_provider_operation_proposal",
          operation_kind:
            "runtime.lifecycle_operation.hypervisor_provider_operation_proposal",
          projection_kind: "hypervisor_provider_operation_proposal",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(body.project_id ?? body.project_ref),
          candidate_ref: optionalString(body.candidate_ref),
          direct_provider_ref: optionalString(body.direct_provider_ref),
          requested_operation: optionalString(body.operation_kind),
          wallet_authority_scope_refs: Array.isArray(
            body.wallet_authority_scope_refs,
          )
            ? body.wallet_authority_scope_refs.filter(
                (scopeRef) => typeof scopeRef === "string" && scopeRef,
              )
            : [],
          storage_policy_ref: optionalString(body.storage_policy_ref),
          restore_policy_ref: optionalString(body.restore_policy_ref),
          source: "public_runtime_routes./v1/hypervisor/provider-operations",
        });
        writeJsonResponse(
          response,
          projected.proposal ??
            projected.record?.proposal ??
            projected.record?.projection ??
            projected.record ??
            projected,
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/hypervisor/session-operations/proposals") {
        const body = await readBody(request);
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_operation.hypervisor_session_operation_proposal",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_session_operation_proposal",
          operation_kind:
            "runtime.lifecycle_operation.hypervisor_session_operation_proposal",
          projection_kind: "hypervisor_session_operation_proposal",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(body.project_id ?? body.project_ref),
          session_ref: optionalString(body.session_ref),
          environment_ref: optionalString(body.environment_ref),
          provider_candidate_ref: optionalString(body.provider_candidate_ref),
          requested_operation: optionalString(body.operation_kind),
          target_ref: optionalString(body.target_ref),
          authority_scope_refs: Array.isArray(body.authority_scope_refs)
            ? body.authority_scope_refs.filter(
                (scopeRef) => typeof scopeRef === "string" && scopeRef,
              )
            : [],
          access_lease_ref: optionalString(body.access_lease_ref),
          log_lease_ref: optionalString(body.log_lease_ref),
          archive_ref: optionalString(body.archive_ref),
          restore_ref: optionalString(body.restore_ref),
          source:
            "public_runtime_routes./v1/hypervisor/session-operations/proposals",
        });
        writeJsonResponse(
          response,
          projected.proposal ??
            projected.record?.proposal ??
            projected.record?.projection ??
            projected.record ??
            projected,
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/hypervisor/project-operations") {
        const body = await readBody(request);
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.lifecycle_operation.hypervisor_project_operation_proposal",
        );
        const projected = routeContextPolicyCore.projectRuntimeLifecycle({
          operation: "hypervisor_project_operation_proposal",
          operation_kind:
            "runtime.lifecycle_operation.hypervisor_project_operation_proposal",
          projection_kind: "hypervisor_project_operation_proposal",
          base_url: baseUrlForRequest(request),
          workspace_root: store.defaultCwd,
          state_dir: store.stateDir,
          home_dir: store.homeDir,
          runtime_schema_version: store.schemaVersion,
          project_id: optionalString(body.project_id ?? body.project_ref),
          workspace_ref: optionalString(body.workspace_ref),
          requested_operation: optionalString(body.operation_kind),
          agentgres_object_head_ref: optionalString(
            body.agentgres_object_head_ref,
          ),
          state_root_ref: optionalString(body.state_root_ref),
          archive_ref: optionalString(body.archive_ref),
          restore_ref: optionalString(body.restore_ref),
          latest_receipt_refs: Array.isArray(body.latest_receipt_refs)
            ? body.latest_receipt_refs.filter(
                (receiptRef) => typeof receiptRef === "string" && receiptRef,
              )
            : [],
          source: "public_runtime_routes./v1/hypervisor/project-operations",
        });
        writeJsonResponse(
          response,
          projected.proposal ??
            projected.record?.proposal ??
            projected.record?.projection ??
            projected.record ??
            projected,
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/hypervisor/approved-operations") {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitHypervisorApprovedOperation(body),
          202,
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/hypervisor/approved-operation-dispatches") {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          await dispatchHypervisorApprovedOperationPlan(body, {
            executeApprovedOperationPlan,
          }),
          202,
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/hypervisor/harness-container-lanes") {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          planHarnessAdapterContainerLane({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/harness-container-lanes",
          }),
          202,
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/hypervisor/harness-public-fixture-runs") {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          await runHarnessPublicFixtureRun(
            {
              ...body,
              source:
                optionalString(body.source) ??
                "public_runtime_routes./v1/hypervisor/harness-public-fixture-runs",
            },
            {
              executeContainerLane:
                typeof executeHarnessContainerLane === "function"
                  ? executeHarnessContainerLane
                  : undefined,
            },
          ),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/model-route-mutation-admissions"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitModelRouteMutation({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/model-route-mutation-admissions",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/session-launch-recipe-admissions"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitHypervisorSessionLaunchRecipe({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/session-launch-recipe-admissions",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/harness-session-binding-admissions"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitHarnessSessionBinding({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/harness-session-binding-admissions",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/harness-session-launches"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          buildHarnessSessionLaunch({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/harness-session-launches",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/harness-session-spawns"
      ) {
        const body = await readBody(request);
        const spawnRequest = {
          ...body,
          source:
            optionalString(body.source) ??
            "public_runtime_routes./v1/hypervisor/harness-session-spawns",
        };
        // Phase 1: provision a REAL isolated workspace before resolving the
        // spawn contract, so a harness never edits the daemon cwd / repo. The
        // spawn builder stays synchronous; provisioning is the async route
        // concern (and is a no-op when the dep is not injected, e.g. in the
        // offline shell-contract mock daemon).
        if (typeof provisionSessionWorkspace === "function") {
          const launchContract =
            body && typeof body.session_launch === "object" && body.session_launch
              ? body.session_launch
              : null;
          const provision = await provisionSessionWorkspace({
            initializer: deriveWorkspaceInitializer({
              workspaceMountPolicy: launchContract?.workspace_mount_policy,
              contextUrl: body.context_url,
              gitSpec: body.git ?? body.git_spec,
              authorityScopeRefs: launchContract?.authority_scope_refs,
            }),
            sessionRef: launchContract?.session_route_ref,
            baseWorkspaceRoot: store.defaultCwd,
          });
          spawnRequest.workspace_root = provision.workspace_root;
          spawnRequest.workspace_provision = provision;
        }
        writeJsonResponse(
          response,
          buildHarnessSessionSpawn(spawnRequest, {
            baseWorkspaceRoot: store.defaultCwd,
            defaultWorkspaceRoot: store.defaultCwd,
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/harness-session-readiness"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          await buildHarnessSessionReadiness({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/harness-session-readiness",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/harness-session-terminal-attachments"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitHarnessSessionTerminalAttach({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/harness-session-terminal-attachments",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/harness-session-turn-lanes"
      ) {
        const body = await readBody(request);
        if (typeof executeHarnessSpawnLane !== "function") {
          writeJsonResponse(
            response,
            {
              error: {
                code: "harness_spawn_lane_executor_unconfigured",
                message:
                  "The daemon was started without a harness spawn lane executor.",
              },
            },
            501,
          );
          return;
        }
        const spawnContract =
          body && typeof body.spawn === "object" && body.spawn
            ? body.spawn
            : {};
        // Phase 4: gate the workspace-mutating lane on the wallet capability
        // lease the spawn carries BEFORE running — a missing lease is a 403
        // step-up, not a silent proceed.
        if (agentgresAdmissionClient) {
          agentgresAdmissionClient.assertCapabilityLease({
            operationKind: "workspace_write",
            authorityScopeRefs: spawnContract.authority_scope_refs,
          });
        }
        // Phase 2: run one real execution lane — spawn the admitted harness in
        // the provisioned workspace, feed the task intent, and report the files
        // it wrote. The harness drives the model; the daemon owns the spawn.
        const laneResult = await executeHarnessSpawnLane({
          spawn: body.spawn,
          intent:
            optionalString(body.intent) ?? optionalString(body.seed_intent),
          model_endpoint: optionalString(body.model_endpoint),
        });
        // Phase 4: admit each consequential write as Agentgres truth and emit
        // real receipts for the Receipts/Replay surface.
        if (
          agentgresAdmissionClient &&
          laneResult.exit_status === "success" &&
          Array.isArray(laneResult.files_written)
        ) {
          const receiptSink = createHarnessReceiptSink(
            spawnContract.session_route_ref,
          );
          for (const file of laneResult.files_written) {
            receiptSink.record(
              await agentgresAdmissionClient.admitOperation({
                operation_kind: "workspace_write",
                session_ref: spawnContract.session_route_ref,
                authority_scope_refs: spawnContract.authority_scope_refs,
                payload: { workspace_root: laneResult.workspace_root, file },
              }),
            );
          }
          laneResult.governance = receiptSink.projection();
        }
        writeJsonResponse(response, laneResult, 200);
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/model-weight-custody-admissions"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitModelWeightCustodyRoute({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/model-weight-custody-admissions",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/private-workspace-mount-admissions"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitPrivateWorkspaceMount({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/private-workspace-mount-admissions",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/managed-worker-lifecycle-admissions"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitManagedWorkerInstanceLifecycleTransition({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/managed-worker-lifecycle-admissions",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/physical-action-intent-admissions"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitPhysicalActionIntent({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/physical-action-intent-admissions",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/worker-package-install-admissions"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitWorkerPackageInstall({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/worker-package-install-admissions",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/code-editor-adapter-launch-plans"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitCodeEditorAdapterLaunchPlan({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/code-editor-adapter-launch-plans",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/service-composition-receipt-bundles"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitServiceCompositionReceiptBundle({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/service-composition-receipt-bundles",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/artifact-availability-incidents"
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          admitArtifactAvailabilityIncident({
            ...body,
            source:
              optionalString(body.source) ??
              "public_runtime_routes./v1/hypervisor/artifact-availability-incidents",
          }),
          202,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/computer-use/browser-discovery") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.computer_use.projection.browser_discovery",
        );
        writeJsonResponse(
          response,
          routeContextPolicyCore.projectRuntimeComputerUse({
            operation: "runtime_computer_use_projection",
            operation_kind: "runtime.computer_use.projection.browser_discovery",
            projection_kind: "browser_discovery",
            workspace_root: store.defaultCwd,
            state_dir: store.stateDir,
            include_cdp_probe: normalizeBooleanOption(url.searchParams.get("probe"), true),
            include_tab_metadata: normalizeBooleanOption(url.searchParams.get("include_tabs"), false),
            reveal_tab_titles: normalizeBooleanOption(url.searchParams.get("reveal_tab_titles"), false),
            source: "public_runtime_routes./v1/computer-use/browser-discovery",
          }).browser_discovery,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/computer-use/providers") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.computer_use.projection.provider_registry",
        );
        writeJsonResponse(
          response,
          routeContextPolicyCore.projectRuntimeComputerUse({
            operation: "runtime_computer_use_projection",
            operation_kind: "runtime.computer_use.projection.provider_registry",
            projection_kind: "provider_registry",
            workspace_root: store.defaultCwd,
            state_dir: store.stateDir,
            source: "public_runtime_routes./v1/computer-use/providers",
          }).provider_registry,
        );
        return;
      }
      if (
        request.method === "GET" &&
        (url.pathname === "/v1/skills" || url.pathname === "/v1/hooks")
      ) {
        // The skill/hook registry projection is served by the Rust hypervisor-daemon
        // (kernel skill_hook_registry projection over the workspace + user sources).
        writeJsonResponse(
          response,
          {
            error: {
              code: "runtime_lifecycle_retired_served_by_rust_daemon",
              message:
                "The skill/hook registry projection is served by the Rust hypervisor-daemon; the JS daemon no longer owns it.",
              retryable: false,
              details: { path: url.pathname, rust_daemon_endpoint: "http://127.0.0.1:8765" },
            },
          },
          410,
        );
        return;
      }
      if (
        request.method === "GET" &&
        (url.pathname === "/v1/repositories" ||
          url.pathname === "/v1/repository-context" ||
          url.pathname === "/v1/branch-policy" ||
          url.pathname === "/v1/github-context" ||
          url.pathname === "/v1/pr-attempts" ||
          url.pathname === "/v1/issue-context" ||
          url.pathname === "/v1/review-gate" ||
          url.pathname === "/v1/github/pr-create-plan")
      ) {
        // The repository-workflow projections (real-git repository context, branch policy,
        // GitHub context, PR attempts, issue context, review gate, PR-create plan, and the
        // repository list) are served by the Rust hypervisor-daemon (kernel
        // repository_workflow projection over `git -C <workspace_root>`).
        writeJsonResponse(
          response,
          {
            error: {
              code: "runtime_lifecycle_retired_served_by_rust_daemon",
              message:
                "The repository-workflow projection is served by the Rust hypervisor-daemon; the JS daemon no longer owns it.",
              retryable: false,
              details: { path: url.pathname, rust_daemon_endpoint: "http://127.0.0.1:8765" },
            },
          },
          410,
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/agents") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.agent_create",
        );
        writeJsonResponse(response, await createLifecycleAgentDep(store, (await readBody(request)).options ?? {}, {
          ensureProviderAvailable,
          initialThreadRuntimeControls,
          lifecycleAdmissionRunner: routeContextPolicyCore,
          mcpRegistryForWorkspace: lifecycleMcpRegistryForContextPolicyCore(routeContextPolicyCore),
          runtimeError: lifecycleRuntimeError,
          runtimeModeForOptions,
          summarizeAgentOptions,
        }));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/agents") {
        writeJsonResponse(response, store.projectRuntimeLifecycleProjection("agents"));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/threads") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.thread_create",
        );
        writeJsonResponse(response, await createLifecycleThreadDep(store, await readBody(request), {
          ensureProviderAvailable,
          eventStreamIdForThread,
          initialThreadRuntimeControls,
          lifecycleAdmissionRunner: routeContextPolicyCore,
          mcpRegistryForWorkspace: lifecycleMcpRegistryForContextPolicyCore(routeContextPolicyCore),
          runtimeError: lifecycleRuntimeError,
          runtimeThreadSchemaVersion,
          runtimeModeForOptions,
          summarizeAgentOptions,
          threadIdForAgent,
          threadStatusForAgent,
        }));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/threads") {
        writeJsonResponse(response, store.projectRuntimeLifecycleProjection("threads"));
        return;
      }
      if (
        request.method === "GET" &&
        (url.pathname === "/v1/usage" ||
          url.pathname === "/v1/authority-evidence" ||
          url.pathname === "/v1/workflow-capability-preflights")
      ) {
        // Usage telemetry + authority-evidence summaries are served by the Rust daemon
        // (the kernel usage_list / authority_evidence_summary projections).
        writeJsonResponse(
          response,
          {
            error: {
              code: "runtime_lifecycle_retired_served_by_rust_daemon",
              message:
                "This projection is served by the Rust hypervisor-daemon; the JS daemon no longer owns it.",
              retryable: false,
              details: { path: url.pathname, rust_daemon_endpoint: "http://127.0.0.1:8765" },
            },
          },
          410,
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/context-budget") {
        writeJsonResponse(
          response,
          store.evaluateContextBudget({ request: await readBody(request) }),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/studio/intent-frame") {
        // The Studio intent-frame projection is served by the Rust hypervisor-daemon.
        writeJsonResponse(
          response,
          {
            error: {
              code: "runtime_lifecycle_retired_served_by_rust_daemon",
              message:
                "The Studio intent-frame projection is served by the Rust hypervisor-daemon; the JS daemon no longer owns it.",
              retryable: false,
              details: { path: url.pathname, rust_daemon_endpoint: "http://127.0.0.1:8765" },
            },
          },
          410,
        );
        return;
      }
      if (segments[0] === "v1" && segments[1] === "conversation-artifacts") {
        // Conversation-artifact list/create/get/revisions/actions/export/promote are served
        // by the Rust hypervisor-daemon (kernel conversation_artifact projection + control).
        writeJsonResponse(
          response,
          {
            error: {
              code: "runtime_lifecycle_retired_served_by_rust_daemon",
              message:
                "Conversation artifacts are served by the Rust hypervisor-daemon; the JS daemon no longer owns them.",
              retryable: false,
              details: { path: url.pathname, rust_daemon_endpoint: "http://127.0.0.1:8765" },
            },
          },
          410,
        );
        return;
      }
      if (
        segments[0] === "v1" &&
        segments[1] === "threads" &&
        segments[2] &&
        segments[3] === "mcp" &&
        segments[4] === "serve" &&
        !segments[5]
      ) {
        const threadId = decodeURIComponent(segments[2]);
        assertNoMcpServeQueryContext(url);
        if (request.method === "GET") {
          writeJsonResponse(response, store.mcpServeStatus(threadId));
          return;
        }
        if (request.method === "POST") {
          const { message, context } = mcpServeProtocolParts(await readBody(request));
          writeMcpJsonRpcResponse(
            response,
            await store.handleMcpServeJsonRpc(threadId, message, { ...context, thread_id: threadId }),
          );
          return;
        }
      }
      if (segments[0] === "v1" && segments[1] === "threads" && segments[2]) {
        await handleThreadRoute({ request, response, store, url, segments });
        return;
      }
      if (segments[0] === "v1" && segments[1] === "agents" && segments[2]) {
        await handleAgentRoute({ request, response, store, url, segments, contextPolicyCore });
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/runs") {
        const agentId = url.searchParams.get("agent_id") ?? undefined;
        writeJsonResponse(
          response,
          store.projectRuntimeLifecycleProjection(
            agentId ? "agent_runs" : "runs",
            agentId ? { agent_id: agentId } : {},
          ),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/tasks") {
        writeJsonResponse(response, await store.createRuntimeTask(await readBody(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/tasks") {
        writeJsonResponse(response, store.listRuntimeTasks(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "tasks" && segments[2] && request.method === "POST" && segments[3] === "cancel") {
        writeJsonResponse(response, store.cancelRuntimeTask(decodeURIComponent(segments[2])));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "tasks" && segments[2] && !segments[3] && request.method === "GET") {
        writeJsonResponse(response, store.getRuntimeTask(decodeURIComponent(segments[2])));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/jobs") {
        writeJsonResponse(response, store.listRuntimeJobs(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "jobs" && segments[2] && request.method === "POST" && segments[3] === "cancel") {
        writeJsonResponse(response, store.cancelRuntimeJob(decodeURIComponent(segments[2])));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "jobs" && segments[2]) {
        writeJsonResponse(response, store.getRuntimeJob(decodeURIComponent(segments[2])));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "runs" && segments[2]) {
        await handleRunRoute({ request, response, store, url, segments });
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models") {
        writeJsonResponse(response, store.modelMounting.runtimeModelCatalogList());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models/artifacts") {
        writeJsonResponse(response, store.modelMounting.listArtifacts());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models/endpoints") {
        writeJsonResponse(response, store.modelMounting.listEndpoints());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models/providers") {
        writeJsonResponse(response, store.modelMounting.listProviders());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models/routes") {
        writeJsonResponse(response, store.modelMounting.listRoutes());
        return;
      }
      if (
        request.method === "GET" &&
        segments[0] === "v1" &&
        segments[1] === "models" &&
        segments[2] &&
        !segments[3] &&
        !["artifacts", "catalog", "endpoints", "providers", "routes"].includes(segments[2])
      ) {
        writeJsonResponse(response, store.modelMounting.getModel(decodeURIComponent(segments[2])));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/snapshot") {
        writeJsonResponse(response, store.modelMounting.snapshot(baseUrlForRequest(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/projection") {
        writeJsonResponse(response, store.modelMounting.projection());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/mcp") {
        writeJsonResponse(response, store.modelMounting.listMcpServers());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/mcp/import") {
        writeJsonResponse(response, await store.modelMounting.importMcpJson(await readBody(request)), 201);
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/mcp/invoke") {
        writeJsonResponse(
          response,
          await store.modelMounting.invokeMcpTool({
            authorization: request.headers.authorization,
            body: await readBody(request),
          }),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/workflows/nodes/execute") {
        writeJsonResponse(
          response,
          await store.modelMounting.executeWorkflowNode({
            authorization: request.headers.authorization,
            body: await readBody(request),
          }),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/workflows/receipt-gate") {
        writeJsonResponse(response, store.modelMounting.validateReceiptGate(await readBody(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/routes") {
        store.modelMounting.authorize(request.headers.authorization, "route.write:*");
        writeJsonResponse(response, store.modelMounting.upsertRoute(await readBody(request)), 201);
        return;
      }
      if (
        request.method === "POST" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "routes" &&
        segments[3] &&
        segments[4] === "test"
      ) {
        store.modelMounting.authorize(request.headers.authorization, `route.use:${decodeURIComponent(segments[3])}`);
        writeJsonResponse(response, store.modelMounting.testRoute(decodeURIComponent(segments[3]), await readBody(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models/catalog/search") {
        writeJsonResponse(response, await store.modelMounting.catalogSearch(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "catalog" &&
        segments[3] === "providers" &&
        segments[4]
      ) {
        const providerId = decodeURIComponent(segments[4]);
        if (request.method === "GET" && !segments[5]) {
          writeJsonResponse(response, store.modelMounting.getCatalogProviderConfig(providerId));
          return;
        }
        if (request.method === "PATCH" && !segments[5]) {
          store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
          writeJsonResponse(response, store.modelMounting.configureCatalogProvider(providerId, await readBody(request)));
          return;
        }
        if (segments[5] === "oauth" && segments[6]) {
          if (request.method === "POST" && segments[6] === "start") {
            store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
            store.modelMounting.authorize(request.headers.authorization, "vault.write:*");
            writeJsonResponse(response, store.modelMounting.startCatalogProviderOAuth(providerId, await readBody(request)), 201);
            return;
          }
          if (request.method === "POST" && segments[6] === "callback") {
            store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
            store.modelMounting.authorize(request.headers.authorization, "vault.write:*");
            writeJsonResponse(response, await store.modelMounting.completeCatalogProviderOAuth(providerId, await readBody(request)), 201);
            return;
          }
          if (request.method === "POST" && segments[6] === "exchange") {
            store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
            store.modelMounting.authorize(request.headers.authorization, "vault.write:*");
            writeJsonResponse(response, await store.modelMounting.exchangeCatalogProviderOAuth(providerId, await readBody(request)), 201);
            return;
          }
          if (request.method === "POST" && segments[6] === "refresh") {
            store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
            store.modelMounting.authorize(request.headers.authorization, "vault.write:*");
            writeJsonResponse(response, await store.modelMounting.refreshCatalogProviderOAuth(providerId));
            return;
          }
          if (request.method === "POST" && segments[6] === "revoke") {
            store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
            store.modelMounting.authorize(request.headers.authorization, "vault.delete:*");
            writeJsonResponse(response, store.modelMounting.revokeCatalogProviderOAuth(providerId));
            return;
          }
        }
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/catalog/import-url") {
        store.modelMounting.authorize(request.headers.authorization, "model.download:*");
        store.modelMounting.authorize(request.headers.authorization, "model.import:*");
        writeJsonResponse(response, await store.modelMounting.catalogImportUrl(await readBody(request)), 202);
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/artifacts/import") {
        store.modelMounting.authorize(request.headers.authorization, "model.import:*");
        writeJsonResponse(response, store.modelMounting.importModel(await readBody(request)), 201);
        return;
      }
      if (
        request.method === "DELETE" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "artifacts" &&
        segments[3] &&
        !segments[4]
      ) {
        store.modelMounting.authorize(request.headers.authorization, "model.delete:*");
        writeJsonResponse(response, store.modelMounting.deleteModelArtifact(decodeURIComponent(segments[3]), await readBody(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/endpoints") {
        store.modelMounting.authorize(request.headers.authorization, "model.mount:*");
        writeJsonResponse(response, store.modelMounting.mountEndpoint(await readBody(request)), 201);
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/downloads") {
        store.modelMounting.authorize(request.headers.authorization, "model.download:*");
        writeJsonResponse(response, await store.modelMounting.downloadModel(await readBody(request)), 202);
        return;
      }
      if (
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "downloads" &&
        segments[3]
      ) {
        if (request.method === "GET" && segments[4] === "status") {
          writeJsonResponse(response, store.modelMounting.downloadStatus(decodeURIComponent(segments[3])));
          return;
        }
        if (request.method === "POST" && segments[4] === "cancel") {
          store.modelMounting.authorize(request.headers.authorization, "model.download:*");
          writeJsonResponse(response, store.modelMounting.cancelDownload(decodeURIComponent(segments[3]), await readBody(request)));
          return;
        }
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/storage/cleanup") {
        store.modelMounting.authorize(request.headers.authorization, "model.delete:*");
        writeJsonResponse(response, store.modelMounting.cleanupModelStorage(await readBody(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/tokens") {
        writeJsonResponse(response, store.modelMounting.listTokens());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/tokens") {
        writeJsonResponse(response, store.modelMounting.createToken(await readBody(request)), 201);
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/tokens/tokenize") {
        writeJsonResponse(
          response,
          store.modelMounting.tokenizeModel({
            authorization: request.headers.authorization,
            requiredScope: "model.tokenize:*",
            body: await readBody(request),
          }),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/tokens/count") {
        writeJsonResponse(
          response,
          store.modelMounting.countModelTokens({
            authorization: request.headers.authorization,
            requiredScope: "model.tokenize:*",
            body: await readBody(request),
          }),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/context/fit") {
        writeJsonResponse(
          response,
          store.modelMounting.fitModelContext({
            authorization: request.headers.authorization,
            requiredScope: "model.context:*",
            body: await readBody(request),
          }),
        );
        return;
      }
      if (
        request.method === "DELETE" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "tokens" &&
        segments[3] &&
        !segments[4]
      ) {
        writeJsonResponse(response, store.modelMounting.revokeToken(decodeURIComponent(segments[3])));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/vault/refs") {
        store.modelMounting.authorize(request.headers.authorization, "vault.read:*");
        writeJsonResponse(response, store.modelMounting.listVaultRefs());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/vault/refs") {
        store.modelMounting.authorize(request.headers.authorization, "vault.write:*");
        writeJsonResponse(response, store.modelMounting.bindVaultRef(await readBody(request)), 201);
        return;
      }
      if (request.method === "DELETE" && url.pathname === "/v1/model-mount/vault/refs") {
        store.modelMounting.authorize(request.headers.authorization, "vault.delete:*");
        writeJsonResponse(response, store.modelMounting.removeVaultRef(await readBody(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/vault/refs/meta") {
        store.modelMounting.authorize(request.headers.authorization, "vault.read:*");
        writeJsonResponse(response, store.modelMounting.vaultRefMetadata(await readBody(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/vault/status") {
        store.modelMounting.authorize(request.headers.authorization, "vault.read:*");
        writeJsonResponse(response, store.modelMounting.vaultStatus());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/vault/health") {
        store.modelMounting.authorize(request.headers.authorization, "vault.read:*");
        writeJsonResponse(response, store.modelMounting.vaultHealth());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/vault/health/latest") {
        store.modelMounting.authorize(request.headers.authorization, "vault.read:*");
        writeJsonResponse(response, store.modelMounting.latestVaultHealth());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/providers") {
        writeJsonResponse(response, store.modelMounting.listProviders());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/providers") {
        store.modelMounting.authorize(request.headers.authorization, "provider.write:*");
        writeJsonResponse(response, store.modelMounting.upsertProvider(await readBody(request)), 201);
        return;
      }
      if (
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "providers" &&
        segments[3]
      ) {
        const providerId = decodeURIComponent(segments[3]);
        if (request.method === "PATCH" && !segments[4]) {
          store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
          writeJsonResponse(response, store.modelMounting.upsertProvider({ ...(await readBody(request)), id: providerId }));
          return;
        }
        if (request.method === "GET" && segments[4] === "health" && segments[5] === "latest") {
          writeJsonResponse(response, store.modelMounting.latestProviderHealth(providerId));
          return;
        }
        if (request.method === "POST" && segments[4] === "health") {
          writeJsonResponse(response, await store.modelMounting.providerHealth(providerId));
          return;
        }
        if (request.method === "GET" && segments[4] === "models") {
          writeJsonResponse(response, await store.modelMounting.listProviderModels(providerId));
          return;
        }
        if (request.method === "GET" && segments[4] === "loaded") {
          writeJsonResponse(response, await store.modelMounting.listProviderLoaded(providerId));
          return;
        }
        if (request.method === "POST" && segments[4] === "start") {
          store.modelMounting.authorize(request.headers.authorization, `provider.control:${providerId}`);
          writeJsonResponse(response, await store.modelMounting.startProvider(providerId));
          return;
        }
        if (request.method === "POST" && segments[4] === "stop") {
          store.modelMounting.authorize(request.headers.authorization, `provider.control:${providerId}`);
          writeJsonResponse(response, await store.modelMounting.stopProvider(providerId));
          return;
        }
      }
      if (
        (request.method === "POST" || request.method === "DELETE") &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "endpoints" &&
        segments[3]
      ) {
        const endpointId = decodeURIComponent(segments[3]);
        if (request.method === "POST" && segments[4] === "load") {
          store.modelMounting.authorize(request.headers.authorization, "model.load:*");
          writeJsonResponse(response, await store.modelMounting.loadModel({ ...(await readBody(request)), endpoint_id: endpointId }), 201);
          return;
        }
        if (request.method === "POST" && segments[4] === "unload") {
          store.modelMounting.authorize(request.headers.authorization, "model.unload:*");
          writeJsonResponse(response, await store.modelMounting.unloadModel({ ...(await readBody(request)), endpoint_id: endpointId }));
          return;
        }
        if (request.method === "DELETE" && !segments[4]) {
          store.modelMounting.authorize(request.headers.authorization, "model.unmount:*");
          writeJsonResponse(response, store.modelMounting.unmountEndpoint({ ...(await readBody(request)), endpoint_id: endpointId }));
          return;
        }
      }
      if (request.method === "GET" && url.pathname === "/v1/model-capabilities") {
        writeJsonResponse(response, store.modelMounting.listModelCapabilities());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/server/status") {
        writeJsonResponse(response, store.modelMounting.serverStatus(baseUrlForRequest(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/server/start") {
        store.modelMounting.authorize(request.headers.authorization, "server.control:*");
        writeJsonResponse(response, store.modelMounting.serverStart(baseUrlForRequest(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/server/stop") {
        store.modelMounting.authorize(request.headers.authorization, "server.control:*");
        writeJsonResponse(response, store.modelMounting.serverStop(baseUrlForRequest(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/server/restart") {
        store.modelMounting.authorize(request.headers.authorization, "server.control:*");
        writeJsonResponse(response, store.modelMounting.serverRestart(baseUrlForRequest(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/server/logs") {
        store.modelMounting.authorize(request.headers.authorization, "server.logs:*");
        writeJsonResponse(response, store.modelMounting.serverLogs(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/server/events") {
        store.modelMounting.authorize(request.headers.authorization, "server.logs:*");
        writeJsonResponse(response, store.modelMounting.serverEvents(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/backends") {
        writeJsonResponse(response, store.modelMounting.listBackends());
        return;
      }
      if (
        request.method === "POST" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "backends" &&
        segments[3] &&
        segments[4] === "health"
      ) {
        writeJsonResponse(response, store.modelMounting.backendHealth(decodeURIComponent(segments[3])));
        return;
      }
      if (
        request.method === "POST" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "backends" &&
        segments[3] &&
        segments[4] === "start"
      ) {
        store.modelMounting.authorize(request.headers.authorization, `backend.control:${decodeURIComponent(segments[3])}`);
        writeJsonResponse(response, store.modelMounting.startBackend(decodeURIComponent(segments[3]), await readBody(request)));
        return;
      }
      if (
        request.method === "POST" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "backends" &&
        segments[3] &&
        segments[4] === "stop"
      ) {
        store.modelMounting.authorize(request.headers.authorization, `backend.control:${decodeURIComponent(segments[3])}`);
        writeJsonResponse(response, store.modelMounting.stopBackend(decodeURIComponent(segments[3])));
        return;
      }
      if (
        request.method === "GET" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "backends" &&
        segments[3] &&
        segments[4] === "logs"
      ) {
        writeJsonResponse(response, store.modelMounting.backendLogs(decodeURIComponent(segments[3])));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/runtime/engines") {
        writeJsonResponse(response, store.modelMounting.listRuntimeEngines());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/runtime/survey") {
        writeJsonResponse(response, store.modelMounting.runtimeSurvey());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/runtime/select") {
        writeJsonResponse(response, store.modelMounting.selectRuntimeEngine(await readBody(request)));
        return;
      }
      if (
        (request.method === "GET" || request.method === "PATCH" || request.method === "DELETE" || request.method === "POST") &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "runtime" &&
        segments[3] === "engines" &&
        segments[4]
      ) {
        if (request.method === "POST" && segments[5] === "select") {
          writeJsonResponse(
            response,
            store.modelMounting.selectRuntimeEngine({
              ...(await readBody(request)),
              engine_id: decodeURIComponent(segments[4]),
            }),
          );
          return;
        }
        if (request.method === "PATCH" && !segments[5]) {
          writeJsonResponse(
            response,
            store.modelMounting.updateRuntimeEngine(decodeURIComponent(segments[4]), await readBody(request)),
          );
          return;
        }
        if (request.method === "DELETE" && !segments[5]) {
          writeJsonResponse(response, store.modelMounting.removeRuntimeEngineOverride(decodeURIComponent(segments[4])));
          return;
        }
        if (request.method === "GET" && !segments[5]) {
          writeJsonResponse(response, store.modelMounting.runtimeEngine(decodeURIComponent(segments[4])));
          return;
        }
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/instances") {
        writeJsonResponse(response, store.modelMounting.listInstances());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/instances/loaded") {
        writeJsonResponse(
          response,
          store.modelMounting.listInstances().filter((instance) => instance.status === "loaded"),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/instances/load") {
        store.modelMounting.authorize(request.headers.authorization, "model.load:*");
        writeJsonResponse(response, await store.modelMounting.loadModel(await readBody(request)), 201);
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/instances/unload") {
        store.modelMounting.authorize(request.headers.authorization, "model.unload:*");
        writeJsonResponse(response, await store.modelMounting.unloadModel(await readBody(request)));
        return;
      }
      if (
        request.method === "POST" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "instances" &&
        segments[3] &&
        segments[4] === "unload"
      ) {
        store.modelMounting.authorize(request.headers.authorization, "model.unload:*");
        writeJsonResponse(
          response,
          await store.modelMounting.unloadModel({ instance_id: decodeURIComponent(segments[3]), ...(await readBody(request)) }),
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/authority") {
        writeJsonResponse(response, store.modelMounting.authoritySnapshot(baseUrlForRequest(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/receipts") {
        writeJsonResponse(response, store.modelMounting.listReceipts());
        return;
      }
      if (
        request.method === "GET" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "receipts" &&
        segments[3] &&
        segments[4] === "replay"
      ) {
        writeJsonResponse(response, store.modelMounting.receiptReplay(decodeURIComponent(segments[3])));
        return;
      }
      if (
        request.method === "GET" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "receipts" &&
        segments[3] &&
        !segments[4]
      ) {
        writeJsonResponse(response, store.modelMounting.getReceipt(decodeURIComponent(segments[3])));
        return;
      }
      // GET /v1/repositories is retired above with the rest of the repository-workflow
      // family (served by the Rust hypervisor-daemon).
      if (
        request.method === "GET" &&
        (url.pathname === "/v1/account" || url.pathname === "/v1/runtime/nodes")
      ) {
        // Account summary + runtime node inventory are served by the Rust hypervisor-daemon.
        writeJsonResponse(
          response,
          {
            error: {
              code: "runtime_lifecycle_retired_served_by_rust_daemon",
              message:
                "This route is served by the Rust hypervisor-daemon; the JS daemon no longer owns it.",
              retryable: false,
              details: { path: url.pathname, rust_daemon_endpoint: "http://127.0.0.1:8765" },
            },
          },
          410,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/tools") {
        writeJsonResponse(response, store.toolApi.listTools(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      throw notFound("Public daemon route not found.", {
        method: request.method,
        path: url.pathname,
      });
    } catch (error) {
      writeError(response, error);
    }
  };

  function lifecycleMcpRegistryForContextPolicyCore(contextPolicyCore) {
    if (typeof mcpRegistryForWorkspace !== "function") {
      return null;
    }
    return (cwd, options = {}) =>
      mcpRegistryForWorkspace(cwd, {
        ...options,
        contextPolicyCore,
      });
  }
}

function assertNoMcpServeQueryContext(url) {
  if (url.searchParams.size === 0) return;
  const error = new Error("MCP serve query-string context is retired; send the stable protocol admission body.");
  error.status = 400;
  error.code = "runtime_mcp_serve_query_context_retired";
  error.details = {
    retired_query_fields: [...url.searchParams.keys()],
    canonical_transport: "ioi.runtime.mcp-serve-client.v1 body",
  };
  throw error;
}

function mcpServeProtocolParts(body) {
  const record = body && typeof body === "object" && !Array.isArray(body) ? body : null;
  if (record && Object.hasOwn(record, "message")) {
    const { message, ...context } = record;
    return { message, context };
  }
  const error = new Error("MCP serve requires the stable protocol admission envelope.");
  error.status = 400;
  error.code = "runtime_mcp_serve_protocol_envelope_required";
  error.details = {
    schema_version: "ioi.runtime.mcp-serve-client.v1",
    required_fields: ["schema_version", "message"],
  };
  throw error;
}
