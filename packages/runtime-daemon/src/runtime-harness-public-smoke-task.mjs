import { runtimeError } from "./runtime-http-utils.mjs";
import {
  buildHarnessContainerLaneReceipt,
  planHarnessAdapterContainerLane,
} from "./runtime-harness-container-lane.mjs";
import { normalizeArray, objectRecord, optionalString, safeId } from "./runtime-value-helpers.mjs";

export const HARNESS_PUBLIC_SMOKE_RUN_SCHEMA_VERSION =
  "ioi.hypervisor.harness_public_smoke_run.v1";

const DEFAULT_FIXTURE_ID = "harness-testbed:public-code-edit-smoke";
const DEFAULT_TASK_REF = "task:fixture/public-code-edit-smoke";

export async function runHarnessPublicSmokeTask(request = {}, deps = {}) {
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const createdAt = optionalString(request.created_at) ?? nowIso();
  const fixtureId = optionalString(request.fixture_id) ?? DEFAULT_FIXTURE_ID;
  const taskRef = optionalString(request.task_ref) ?? DEFAULT_TASK_REF;
  const minInstalledAdapters = Number.isFinite(request.min_installed_adapters)
    ? Number(request.min_installed_adapters)
    : 2;
  const installedAdapterIds = new Set(uniqueStringRefs(request.installed_adapter_ids));
  const candidates = normalizeCandidateLanes(request.candidate_lanes);
  const installedCandidates = candidates.filter((candidate) =>
    installedAdapterIds.has(candidate.adapter_id),
  );

  if (installedCandidates.length < minInstalledAdapters) {
    throw runtimeError({
      status: 409,
      code: "harness_public_smoke_insufficient_installed_adapters",
      message:
        "Harness public smoke task requires enough installed adapters to compare the same fixture under daemon gates.",
      details: {
        required: minInstalledAdapters,
        installed_adapter_ids: [...installedAdapterIds].sort(),
        candidate_adapter_ids: candidates.map((candidate) => candidate.adapter_id),
      },
    });
  }

  const runId =
    optionalString(request.run_id) ??
    `harness-public-smoke:${safeId(fixtureId)}:${createdAt.replace(/[^0-9a-z]+/gi, "").slice(0, 14)}`;
  const attempts = [];
  for (const candidate of installedCandidates.slice(0, minInstalledAdapters)) {
    const plan = planHarnessAdapterContainerLane(
      {
        ...candidate,
        command_argv: commandArgvForFixture(candidate, fixtureId),
        mounts: candidate.mounts ?? publicSmokeMounts(),
        network_policy: candidate.network_policy ?? "disabled",
        env_policy_ref:
          candidate.env_policy_ref ?? "env-policy:harness-adapter/no-plaintext-env",
        privacy_posture_ref:
          candidate.privacy_posture_ref ?? "privacy-posture:public-trunk",
        authority_scope_refs: candidate.authority_scope_refs ?? [
          "scope:workspace.read",
          "scope:workspace.patch",
        ],
        receipt_policy_ref:
          candidate.receipt_policy_ref ?? "receipt-policy:harness-adapter/container",
        created_at: createdAt,
      },
      { nowIso },
    );

    const outcome = deps.executeContainerLane
      ? await deps.executeContainerLane({ plan, fixture_id: fixtureId, task_ref: taskRef })
      : { exit_status: "not_executed", exit_code: null };
    const receipt = buildHarnessContainerLaneReceipt(plan, {
      exit_status: outcome.exit_status,
      exit_code: outcome.exit_code ?? null,
      agentgres_operation_refs: outcome.agentgres_operation_refs ?? [],
      artifact_refs: outcome.artifact_refs ?? [],
      created_at: outcome.created_at ?? nowIso(),
    });

    attempts.push({
      attempt_id: `harness-smoke-attempt:${safeId(candidate.selection_ref)}`,
      selection_ref: candidate.selection_ref,
      adapter_id: candidate.adapter_id,
      fixture_id: fixtureId,
      task_ref: taskRef,
      plan_id: plan.plan_id,
      receipt_id: receipt.receipt_id,
      exit_status: receipt.exit_status,
      exit_code: receipt.exit_code,
      container_image_ref: plan.container_image_ref,
      command_argv_hash: plan.command_argv_hash,
      network_policy: plan.network_policy,
      mounts: plan.mounts,
      runtimeTruthSource: "daemon-runtime",
      receipt,
    });
  }

  return {
    schema_version: HARNESS_PUBLIC_SMOKE_RUN_SCHEMA_VERSION,
    run_id: runId,
    fixture_id: fixtureId,
    task_ref: taskRef,
    candidate_selection_refs: attempts.map((attempt) => attempt.selection_ref),
    attempt_refs: attempts.map((attempt) => attempt.attempt_id),
    receipt_refs: attempts.map((attempt) => attempt.receipt_id),
    attempts,
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
  };
}

function normalizeCandidateLanes(value) {
  const candidates = normalizeArray(value).map((candidate, index) => {
    const record = objectRecord(candidate);
    if (!record) {
      throw runtimeError({
        status: 400,
        code: "harness_public_smoke_candidate_invalid",
        message: "Harness public smoke candidates must be objects.",
        details: { index },
      });
    }
    const adapterId = requiredString(record.adapter_id, `candidate_lanes[${index}].adapter_id`);
    return {
      ...record,
      adapter_id: adapterId,
      selection_ref:
        optionalString(record.selection_ref) ?? `agent-harness-adapter:${adapterId}`,
      runtime: optionalString(record.runtime) ?? "docker",
      container_image_ref: requiredString(
        record.container_image_ref,
        `candidate_lanes[${index}].container_image_ref`,
      ),
    };
  });
  if (candidates.length === 0) {
    throw runtimeError({
      status: 400,
      code: "harness_public_smoke_candidates_required",
      message: "Harness public smoke task requires adapter candidates.",
      details: {},
    });
  }
  return candidates;
}

function commandArgvForFixture(candidate, fixtureId) {
  if (candidate.command_argv) {
    return candidate.command_argv;
  }
  return [
    "harness-adapter",
    "run",
    candidate.adapter_id,
    "--fixture",
    fixtureId,
  ];
}

function publicSmokeMounts() {
  return [
    {
      mount_ref: "mount:public-trunk",
      source_ref: "artifact://workspace/public-trunk",
      target_path: "/workspace",
      access: "read_only",
      custody: "public_trunk",
    },
    {
      mount_ref: "mount:scratch",
      source_ref: "artifact://workspace/scratch",
      target_path: "/scratch",
      access: "read_write_scratch",
      custody: "redacted_projection",
    },
  ];
}

function requiredString(value, field) {
  const text = optionalString(value);
  if (!text) {
    throw runtimeError({
      status: 400,
      code: "harness_public_smoke_required_field_missing",
      message: `Harness public smoke task is missing required field: ${field}.`,
      details: { field },
    });
  }
  return text;
}

function uniqueStringRefs(values) {
  return [...new Set(normalizeArray(values).map((value) => String(value)).filter(Boolean))];
}
