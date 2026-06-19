import { runtimeError } from "./runtime-http-utils.mjs";
import {
  booleanValue,
  normalizeArray,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

export const HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_REQUEST_SCHEMA_VERSION =
  "ioi.hypervisor.session_launch_recipe_admission_request.v1";

export const HYPERVISOR_SESSION_LAUNCH_RECIPE_SCHEMA_VERSION =
  "ioi.hypervisor.session_launch_recipe.v1";

export const HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_SCHEMA_VERSION =
  "ioi.runtime.hypervisor_session_launch_recipe_admission.v1";

const TARGET_BINDING_SCHEMA_VERSION =
  "ioi.hypervisor.new_session_target_binding.v1";

const RECIPE_KINDS = new Set([
  "mission",
  "workbench",
  "agent",
  "automation",
  "foundry_job",
  "provider_environment_job",
  "privacy_workspace",
]);

const MODEL_MOUNT_POLICIES = new Set([
  "inherit",
  "select",
  "required",
  "forbidden",
]);

const HARNESS_PROFILE_POLICIES = new Set([
  "default",
  "select",
  "external_adapter",
]);

const SURFACE_BY_KIND = new Map([
  ["mission", "sessions"],
  ["workbench", "workbench"],
  ["agent", "agents"],
  ["automation", "automations"],
  ["foundry_job", "foundry"],
  ["provider_environment_job", "environments"],
  ["privacy_workspace", "privacy"],
]);

const RETIRED_ALIASES = [
  "recipeId",
  "recipeRef",
  "targetBindingRef",
  "targetKind",
  "surfaceId",
  "projectRef",
  "sessionRouteRef",
  "modelRouteRef",
  "privacyPostureRef",
  "authorityScopeRefs",
  "receiptPreviewRef",
  "requiresDaemonGate",
  "agentgresOperationRefs",
  "receiptRefs",
  "stateRoot",
];

export function admitHypervisorSessionLaunchRecipe(request = {}, deps = {}) {
  assertNoRetiredAliases(request);

  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const schemaVersion = requiredString(request.schema_version, "schema_version");
  const recipe = recordValue(request.recipe);
  const targetBinding = recordValue(request.target_binding);
  const modelRouteRef = prefixedString(
    request.model_route_ref,
    "model_route_ref",
    "model-route:",
  );
  const privacyPostureRef = prefixedString(
    request.privacy_posture_ref,
    "privacy_posture_ref",
    "privacy:",
  );
  const authorityScopeRefs = prefixedRefs(
    request.authority_scope_refs,
    "authority_scope_refs",
    "scope:",
  );
  const receiptPreviewRef = prefixedString(
    request.receipt_preview_ref,
    "receipt_preview_ref",
    "receipt-preview:",
  );
  const expectedReceiptRefs = prefixedRefs(
    request.expected_receipt_refs,
    "expected_receipt_refs",
    "receipt",
  );
  const requiresDaemonGate =
    booleanValue(request.requires_daemon_gate) ?? false;
  const runtimeTruthSource = optionalString(request.runtimeTruthSource) ?? null;
  const agentgresOperationRefs = prefixedRefs(
    request.agentgres_operation_refs,
    "agentgres_operation_refs",
    "agentgres://operation/",
    { allowEmpty: true },
  );
  const receiptRefs = prefixedRefs(
    request.receipt_refs,
    "receipt_refs",
    "receipt://",
    { allowEmpty: true },
  );
  const stateRoot = optionalString(request.state_root) ?? null;

  if (
    schemaVersion !==
    HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_REQUEST_SCHEMA_VERSION
  ) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_request_schema_invalid",
      message:
        "Hypervisor session launch recipe admission requires the canonical request schema.",
      details: { schema_version: schemaVersion },
    });
  }
  if (!requiresDaemonGate || runtimeTruthSource !== "daemon-runtime") {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_daemon_gate_required",
      message:
        "Hypervisor session launch recipe admission requires daemon gates and daemon runtime truth.",
      details: { requires_daemon_gate: requiresDaemonGate, runtimeTruthSource },
    });
  }
  if (!expectedReceiptRefs.includes(receiptPreviewRef)) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_receipt_preview_unbound",
      message:
        "Hypervisor session launch recipe admission must bind the receipt preview in expected receipt refs.",
      details: { receipt_preview_ref: receiptPreviewRef },
    });
  }

  const normalizedRecipe = normalizeRecipe(recipe);
  const normalizedTargetBinding = normalizeTargetBinding(targetBinding);
  assertRecipeTargetBinding(normalizedRecipe, normalizedTargetBinding);

  const admissionId =
    optionalString(request.admission_id) ??
    `hypervisor-session-launch-recipe-admission:${safeId(
      normalizedTargetBinding.target_binding_ref,
    )}`;
  const admissionReceiptRef =
    optionalString(request.admission_receipt_ref) ??
    `receipt://hypervisor/session-launch-recipe/${safeId(
      normalizedTargetBinding.target_binding_ref,
    )}/admitted`;
  const operationRef =
    agentgresOperationRefs[0] ??
    `agentgres://operation/hypervisor/session-launch-recipe/${safeId(
      normalizedTargetBinding.target_binding_ref,
    )}`;

  return {
    schema_version: HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_SCHEMA_VERSION,
    admission_id: admissionId,
    decision: "admitted",
    admission_state: "admitted_for_session_binding",
    recipe_ref: normalizedRecipe.recipe_id,
    recipe_kind: normalizedRecipe.kind,
    surface_id: normalizedRecipe.surface_id,
    target_binding_ref: normalizedTargetBinding.target_binding_ref,
    project_ref: normalizedTargetBinding.project_ref,
    operator_intent_ref: normalizedTargetBinding.operator_intent_ref,
    session_route_ref: normalizedTargetBinding.session_route_ref,
    code_editor_adapter_target_ref:
      normalizedTargetBinding.code_editor_adapter_target_ref,
    model_route_ref: modelRouteRef,
    privacy_posture_ref: privacyPostureRef,
    authority_scope_refs: authorityScopeRefs,
    receipt_preview_ref: receiptPreviewRef,
    expected_receipt_refs: expectedReceiptRefs,
    agentgres_operation_refs: uniqueStrings([
      ...agentgresOperationRefs,
      operationRef,
    ]),
    receipt_refs: uniqueStrings([...receiptRefs, admissionReceiptRef]),
    state_root:
      stateRoot ??
      `agentgres://state-root/hypervisor/session-launch-recipe/${safeId(
        normalizedTargetBinding.target_binding_ref,
      )}`,
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    admitted_at: optionalString(request.admitted_at) ?? nowIso(),
    recipe_invariant:
      "New Session recipes become launchable only after daemon admission binds recipe, target binding, project, route, model, privacy, authority scopes, receipts, and Agentgres operation refs.",
  };
}

function normalizeRecipe(value) {
  const recipe = recordValue(value);
  if (
    !recipe ||
    recipe.schema_version !== HYPERVISOR_SESSION_LAUNCH_RECIPE_SCHEMA_VERSION
  ) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_schema_invalid",
      message:
        "Hypervisor session launch recipe admission requires a canonical recipe object.",
      details: {
        expected_schema_version:
          HYPERVISOR_SESSION_LAUNCH_RECIPE_SCHEMA_VERSION,
      },
    });
  }
  const recipeId = requiredString(recipe.recipe_id, "recipe.recipe_id");
  const kind = enumValue(recipe.kind, "recipe.kind", RECIPE_KINDS);
  const surfaceId = requiredString(recipe.surface_id, "recipe.surface_id");
  const modelMountPolicy = enumValue(
    recipe.model_mount_policy,
    "recipe.model_mount_policy",
    MODEL_MOUNT_POLICIES,
  );
  const harnessProfilePolicy = enumValue(
    recipe.harness_profile_policy,
    "recipe.harness_profile_policy",
    HARNESS_PROFILE_POLICIES,
  );
  const requiredInputs = stringList(recipe.required_inputs, "recipe.required_inputs");
  const authorityScopeTemplates = prefixedRefs(
    recipe.authority_scope_templates,
    "recipe.authority_scope_templates",
    "scope:",
  );
  const privacyPostureTemplates = stringList(
    recipe.privacy_posture_templates,
    "recipe.privacy_posture_templates",
  );
  if (SURFACE_BY_KIND.get(kind) !== surfaceId) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_surface_mismatch",
      message: "Hypervisor session launch recipe kind must map to its canonical surface.",
      details: { kind, surface_id: surfaceId },
    });
  }
  return {
    recipe_id: recipeId,
    kind,
    surface_id: surfaceId,
    model_mount_policy: modelMountPolicy,
    harness_profile_policy: harnessProfilePolicy,
    required_inputs: requiredInputs,
    authority_scope_templates: authorityScopeTemplates,
    privacy_posture_templates: privacyPostureTemplates,
  };
}

function normalizeTargetBinding(value) {
  const binding = recordValue(value);
  if (!binding || binding.schema_version !== TARGET_BINDING_SCHEMA_VERSION) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_target_binding_invalid",
      message:
        "Hypervisor session launch recipe admission requires the canonical target binding.",
      details: { expected_schema_version: TARGET_BINDING_SCHEMA_VERSION },
    });
  }
  return {
    target_binding_ref: prefixedString(
      binding.target_binding_ref,
      "target_binding.target_binding_ref",
      "target-binding:",
    ),
    recipe_ref: requiredString(binding.recipe_ref, "target_binding.recipe_ref"),
    target_kind: enumValue(
      binding.target_kind,
      "target_binding.target_kind",
      RECIPE_KINDS,
    ),
    surface_id: requiredString(binding.surface_id, "target_binding.surface_id"),
    project_ref: requiredString(binding.project_ref, "target_binding.project_ref"),
    operator_intent_ref: optionalString(binding.operator_intent_ref) ?? null,
    session_route_ref: prefixedString(
      binding.session_route_ref,
      "target_binding.session_route_ref",
      "session-route:",
    ),
    code_editor_adapter_target_ref:
      optionalString(binding.code_editor_adapter_target_ref) ?? null,
  };
}

function assertRecipeTargetBinding(recipe, binding) {
  if (
    recipe.recipe_id !== binding.recipe_ref ||
    recipe.kind !== binding.target_kind ||
    recipe.surface_id !== binding.surface_id
  ) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_target_mismatch",
      message:
        "Hypervisor session launch recipe admission requires recipe and target binding to agree.",
      details: {
        recipe_ref: recipe.recipe_id,
        binding_recipe_ref: binding.recipe_ref,
        recipe_kind: recipe.kind,
        target_kind: binding.target_kind,
        recipe_surface: recipe.surface_id,
        target_surface: binding.surface_id,
      },
    });
  }
  const routeToken = routeSafeId(recipe.recipe_id);
  if (!binding.session_route_ref.includes(routeToken)) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_route_unbound",
      message: "Target binding session route must bind the selected recipe.",
      details: {
        recipe_ref: recipe.recipe_id,
        expected_route_token: routeToken,
        session_route_ref: binding.session_route_ref,
      },
    });
  }
  if (recipe.kind === "workbench" && !binding.code_editor_adapter_target_ref) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_workbench_adapter_required",
      message:
        "Workbench launch recipes require a code editor adapter target binding.",
      details: { recipe_ref: recipe.recipe_id },
    });
  }
}

function assertNoRetiredAliases(record = {}) {
  const present = RETIRED_ALIASES.filter((alias) =>
    Object.prototype.hasOwnProperty.call(record, alias),
  );
  if (present.length > 0) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_retired_aliases",
      message:
        "Hypervisor session launch recipe admission rejects retired camelCase aliases.",
      details: { aliases: present },
    });
  }
}

function recordValue(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function requiredString(value, field) {
  const string = optionalString(value);
  if (!string) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_field_required",
      message: `Hypervisor session launch recipe admission requires ${field}.`,
      details: { field },
    });
  }
  return string;
}

function prefixedString(value, field, prefix) {
  const string = requiredString(value, field);
  if (!string.startsWith(prefix)) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_prefix_invalid",
      message: `${field} must start with ${prefix}.`,
      details: { field, prefix, value: string },
    });
  }
  return string;
}

function prefixedRefs(value, field, prefix, { allowEmpty = false } = {}) {
  const refs = uniqueStrings(
    normalizeArray(value)
      .map((item) => optionalString(item))
      .filter(Boolean),
  );
  if (!allowEmpty && refs.length === 0) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_refs_required",
      message: `Hypervisor session launch recipe admission requires ${field}.`,
      details: { field },
    });
  }
  for (const ref of refs) {
    if (!ref.startsWith(prefix)) {
      throw admissionError({
        code: "hypervisor_session_launch_recipe_ref_prefix_invalid",
        message: `${field} entries must start with ${prefix}.`,
        details: { field, prefix, value: ref },
      });
    }
  }
  return refs;
}

function stringList(value, field) {
  const refs = uniqueStrings(
    normalizeArray(value)
      .map((item) => optionalString(item))
      .filter(Boolean),
  );
  if (refs.length === 0) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_list_required",
      message: `Hypervisor session launch recipe admission requires ${field}.`,
      details: { field },
    });
  }
  return refs;
}

function enumValue(value, field, allowed) {
  const string = requiredString(value, field);
  if (!allowed.has(string)) {
    throw admissionError({
      code: "hypervisor_session_launch_recipe_enum_invalid",
      message: `${field} has an unsupported value.`,
      details: { field, value: string, allowed: [...allowed] },
    });
  }
  return string;
}

function routeSafeId(value) {
  return (
    String(value ?? "recipe")
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 96) || "recipe"
  );
}

function admissionError({ code, message, details = {}, status = 400 }) {
  return runtimeError({
    status,
    code,
    message,
    details,
  });
}
