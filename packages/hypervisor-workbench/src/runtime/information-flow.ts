import {
  type InformationFlowLabelV1,
  validateArchitectureContract,
} from "./generated/architecture-contracts";

export const INFORMATION_FLOW_LABEL_CONTRACT_ID =
  "schema://ioi/foundations/information-flow-label/v1";
export const RUNTIME_TOOL_CONTRACT_ID =
  "schema://ioi/components/connectors-tools/runtime-tool-contract/v1";
export const DECLASSIFICATION_APPROVAL_CONTRACT_ID =
  "schema://ioi/foundations/declassification-approval/v1";

type JsonObject = Record<string, unknown>;

export type InformationFlowEffectBinding = {
  effectHash: string;
  requestHash: string;
  reviewedRepresentationHash: string | null;
};

export type InformationFlowAdmission = {
  label: unknown;
  toolContract: unknown;
  destination: string;
  binding: InformationFlowEffectBinding;
  declassificationApproval?: unknown;
};

export type InformationFlowDecision =
  | { ok: true }
  | { ok: false; code: string; message: string };

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

async function sha256Canonical(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return `sha256:${[...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")}`;
}

function at(value: unknown, ...path: string[]): unknown {
  return path.reduce<unknown>(
    (current, key) => (isObject(current) ? current[key] : undefined),
    value,
  );
}

function textAt(value: unknown, ...path: string[]): string | null {
  const current = at(value, ...path);
  return typeof current === "string" ? current : null;
}

function stringSetAt(value: unknown, ...path: string[]): Set<string> | null {
  const current = at(value, ...path);
  if (!Array.isArray(current) || !current.every((item) => typeof item === "string")) {
    return null;
  }
  return new Set(current);
}

function deny(code: string, message: string): InformationFlowDecision {
  return { ok: false, code, message };
}

function destinationMatches(pattern: string, destination: string): boolean {
  const wildcard = pattern.endsWith("*");
  const declared = wildcard ? pattern.slice(0, -1) : pattern;
  try {
    const declaredUrl = new URL(declared);
    const destinationUrl = new URL(destination);
    if (declaredUrl.origin !== destinationUrl.origin) return false;
    return wildcard
      ? declared.endsWith("/") && destination.startsWith(declared)
      : declaredUrl.href === destinationUrl.href;
  } catch {
    return false;
  }
}

function destinationAllowed(
  value: unknown,
  path: string[],
  destination: string,
): boolean {
  const patterns = at(value, ...path);
  return (
    Array.isArray(patterns) &&
    patterns.some(
      (pattern) =>
        typeof pattern === "string" && destinationMatches(pattern, destination),
    )
  );
}

function hasUntrustedDerivation(label: unknown): boolean {
  return (
    [
      "external_untrusted",
      "connector_output",
      "tool_output",
      "memory_import",
    ].includes(textAt(label, "origin") ?? "") ||
    textAt(label, "integrity") === "untrusted" ||
    textAt(label, "instruction_authority") === "untrusted"
  );
}

const confidentialityOrder = [
  "public",
  "internal",
  "confidential",
  "private",
  "restricted",
  "unknown",
] as const;

export function evaluateInformationFlow(
  admission: InformationFlowAdmission,
): InformationFlowDecision {
  const labelResult = validateArchitectureContract(
    INFORMATION_FLOW_LABEL_CONTRACT_ID,
    admission.label,
  );
  if (!labelResult.ok) {
    return deny(
      "ifc_label_invalid",
      `information-flow label is not contract-valid: ${labelResult.errors.join(", ")}`,
    );
  }
  const toolResult = validateArchitectureContract(
    RUNTIME_TOOL_CONTRACT_ID,
    admission.toolContract,
  );
  if (!toolResult.ok) {
    return deny(
      "ifc_tool_contract_invalid",
      `runtime tool contract is not contract-valid: ${toolResult.errors.join(", ")}`,
    );
  }

  const axes = [
    textAt(admission.label, "origin"),
    textAt(admission.label, "integrity"),
    textAt(admission.label, "confidentiality"),
    textAt(admission.label, "instruction_authority"),
    textAt(admission.label, "retention", "disposition"),
  ];
  if (axes.includes("unknown")) {
    return deny(
      "ifc_unknown_label",
      "unknown information-flow axes cannot cross a consequential effect boundary",
    );
  }
  if (textAt(admission.label, "instruction_authority") !== "authoritative") {
    return deny(
      "ifc_instruction_not_authoritative",
      "context-only, absent, or untrusted instructions cannot authorize a consequential effect",
    );
  }

  const confidentiality = textAt(admission.label, "confidentiality") ?? "unknown";
  const privateOrHigher = confidentialityOrder.indexOf(
    confidentiality as (typeof confidentialityOrder)[number],
  ) >= 3;
  if (privateOrHigher && hasUntrustedDerivation(admission.label)) {
    return deny(
      "ifc_private_untrusted_egress",
      "private-or-higher context derived from untrusted content cannot egress",
    );
  }
  if (textAt(admission.label, "egress_policy", "mode") === "deny") {
    return deny("ifc_label_egress_denied", "the data label denies egress");
  }
  if (
    !destinationAllowed(
      admission.label,
      ["egress_policy", "allowed_destination_patterns"],
      admission.destination,
    )
  ) {
    return deny(
      "ifc_label_destination_denied",
      "destination is outside the label egress policy",
    );
  }
  if (
    textAt(admission.toolContract, "egress_policy", "default") !==
      "allow_declared" ||
    !destinationAllowed(
      admission.toolContract,
      ["egress_policy", "allowed_destination_patterns"],
      admission.destination,
    )
  ) {
    return deny(
      "ifc_tool_destination_denied",
      "destination is not declared by the exact RuntimeToolContract revision",
    );
  }

  let effectiveClass = confidentiality;
  if (
    privateOrHigher ||
    textAt(admission.label, "egress_policy", "mode") ===
      "declassification_required"
  ) {
    const approval = admission.declassificationApproval;
    const approvalResult = validateArchitectureContract(
      DECLASSIFICATION_APPROVAL_CONTRACT_ID,
      approval,
    );
    if (!approvalResult.ok) {
      return deny(
        "ifc_declassification_invalid",
        `declassification approval is not contract-valid: ${approvalResult.errors.join(", ")}`,
      );
    }
    if (textAt(approval, "status") !== "active") {
      return deny(
        "ifc_declassification_inactive",
        "declassification approval is not active",
      );
    }
    const expiresAt = Date.parse(textAt(approval, "expires_at") ?? "");
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      return deny(
        "ifc_declassification_expired",
        "declassification approval has expired",
      );
    }
    if (admission.binding.reviewedRepresentationHash === null) {
      return deny(
        "ifc_reviewed_representation_required",
        "protected egress requires the exact reviewed representation",
      );
    }
    const exactPairs: Array<[string | null, string | null]> = [
      [
        textAt(approval, "tool_contract_revision_ref"),
        textAt(admission.toolContract, "revision_ref"),
      ],
      [textAt(approval, "label_ref"), textAt(admission.label, "label_ref")],
      [
        textAt(approval, "label_content_hash"),
        textAt(admission.label, "content_hash"),
      ],
      [textAt(approval, "exact_effect_hash"), admission.binding.effectHash],
      [textAt(approval, "exact_request_hash"), admission.binding.requestHash],
      [
        textAt(approval, "reviewed_representation_hash"),
        admission.binding.reviewedRepresentationHash,
      ],
      [textAt(approval, "destination"), admission.destination],
      [textAt(approval, "purpose"), textAt(admission.label, "purpose")],
    ];
    if (exactPairs.some(([actual, expected]) => actual !== expected)) {
      return deny(
        "ifc_declassification_binding_mismatch",
        "declassification approval does not bind this exact effect and review",
      );
    }
    effectiveClass = textAt(approval, "declassified_to") ?? "unknown";
  }

  const toolClasses = stringSetAt(admission.toolContract, "data_class_allowlist");
  const labelClasses = stringSetAt(
    admission.label,
    "egress_policy",
    "allowed_data_classes",
  );
  if (!toolClasses?.has(effectiveClass) || !labelClasses?.has(effectiveClass)) {
    return deny(
      "ifc_data_class_denied",
      `effective data class '${effectiveClass}' is outside an allowlist`,
    );
  }
  return { ok: true };
}

function worstAxis(
  parents: InformationFlowLabelV1[],
  read: (value: InformationFlowLabelV1) => string,
  order: readonly string[],
): string {
  return parents
    .map(read)
    .sort((left, right) => order.indexOf(right) - order.indexOf(left))[0];
}

function intersect(values: string[][]): string[] {
  return [...new Set(values[0] ?? [])]
    .filter((candidate) => values.every((items) => items.includes(candidate)))
    .sort();
}

export function deriveInformationFlowLabel(
  parents: InformationFlowLabelV1[],
  labelRef: string,
  contentHash: string,
  derivationKind:
    | "join"
    | "summarization"
    | "model_substitution"
    | "memory_import"
    | "tool_output",
): InformationFlowLabelV1 {
  if (parents.length === 0) throw new Error("ifc_derivation_empty");
  for (const parent of parents) {
    const validation = validateArchitectureContract(
      INFORMATION_FLOW_LABEL_CONTRACT_ID,
      parent,
    );
    if (!validation.ok) throw new Error(`ifc_label_invalid:${validation.errors.join(",")}`);
  }
  const purposeSet = [...new Set(parents.map((parent) => parent.purpose))].sort();
  const profileSet = [...new Set(parents.map((parent) => parent.profile_ref))];
  const parentRefs = [...new Set(parents.map((parent) => parent.label_ref))].sort();
  const closure = [
    ...new Set([
      labelRef,
      ...parentRefs,
      ...parents.flatMap((parent) => parent.derivation_closure_refs),
    ]),
  ].sort();
  const derived = {
    schema_version: "ioi.foundations.information-flow-label.v1" as const,
    label_ref: labelRef,
    profile_ref:
      profileSet.length === 1 ? profileSet[0] : "policy://ifc/join-v1",
    content_hash: contentHash,
    origin: worstAxis(
      parents,
      (parent) => parent.origin,
      [
        "operator",
        "admitted_artifact",
        "model_output",
        "memory_import",
        "connector_output",
        "tool_output",
        "external_untrusted",
        "unknown",
      ],
    ) as InformationFlowLabelV1["origin"],
    integrity: worstAxis(
      parents,
      (parent) => parent.integrity,
      ["verified", "admitted", "declared", "untrusted", "unknown"],
    ) as InformationFlowLabelV1["integrity"],
    confidentiality: worstAxis(
      parents,
      (parent) => parent.confidentiality,
      confidentialityOrder,
    ) as InformationFlowLabelV1["confidentiality"],
    instruction_authority: worstAxis(
      parents,
      (parent) => parent.instruction_authority,
      ["authoritative", "context_only", "none", "untrusted", "unknown"],
    ) as InformationFlowLabelV1["instruction_authority"],
    egress_policy: {
      mode: worstAxis(
        parents,
        (parent) => parent.egress_policy.mode,
        ["allow_declared", "declassification_required", "deny"],
      ) as InformationFlowLabelV1["egress_policy"]["mode"],
      allowed_destination_patterns: intersect(
        parents.map((parent) => parent.egress_policy.allowed_destination_patterns),
      ),
      allowed_data_classes: intersect(
        parents.map((parent) => parent.egress_policy.allowed_data_classes),
      ) as InformationFlowLabelV1["egress_policy"]["allowed_data_classes"],
    },
    purpose:
      purposeSet.length === 1
        ? purposeSet[0]
        : `composed:[${purposeSet.join("|")}]`,
    retention: {
      max_seconds: Math.min(...parents.map((parent) => parent.retention.max_seconds)),
      disposition: worstAxis(
        parents,
        (parent) => parent.retention.disposition,
        ["retain_under_policy", "return_to_owner", "delete", "unknown"],
      ) as InformationFlowLabelV1["retention"]["disposition"],
    },
    derivation_kind: derivationKind,
    derivation_parent_refs: parentRefs,
    derivation_closure_refs: closure,
  };
  const validation = validateArchitectureContract(
    INFORMATION_FLOW_LABEL_CONTRACT_ID,
    derived,
  );
  if (!validation.ok) {
    throw new Error(`ifc_derived_label_invalid:${validation.errors.join(",")}`);
  }
  return derived;
}

export const summarizeInformationFlowLabel = (
  parents: InformationFlowLabelV1[],
  labelRef: string,
  contentHash: string,
) => deriveInformationFlowLabel(parents, labelRef, contentHash, "summarization");

export const modelSubstitutionInformationFlowLabel = (
  parents: InformationFlowLabelV1[],
  labelRef: string,
  contentHash: string,
) => deriveInformationFlowLabel(parents, labelRef, contentHash, "model_substitution");

export const memoryImportInformationFlowLabel = (
  parents: InformationFlowLabelV1[],
  labelRef: string,
  contentHash: string,
) => deriveInformationFlowLabel(parents, labelRef, contentHash, "memory_import");

const integrityOrder: InformationFlowLabelV1["integrity"][] = [
  "verified",
  "admitted",
  "declared",
  "untrusted",
  "unknown",
];
const instructionAuthorityOrder: InformationFlowLabelV1["instruction_authority"][] = [
  "authoritative",
  "context_only",
  "none",
  "untrusted",
  "unknown",
];

function moreRestrictive<T extends string>(left: T, right: T, order: T[]): T {
  return order.indexOf(left) >= order.indexOf(right) ? left : right;
}

/**
 * Compile independently admitted effect authority over the actual input label
 * set. Authority may authorize the effect, but cannot weaken any data-control
 * axis inherited from those inputs.
 */
export async function compileAdmittedInformationFlowEffectLabel(
  parents: InformationFlowLabelV1[],
  authorityLabel: InformationFlowLabelV1,
  exactRequestContentHash: string,
): Promise<InformationFlowLabelV1> {
  const authorityValidation = validateArchitectureContract(
    INFORMATION_FLOW_LABEL_CONTRACT_ID,
    authorityLabel,
  );
  if (!authorityValidation.ok) {
    throw new Error(
      `ifc_effect_authority_label_invalid:${authorityValidation.errors.join(",")}`,
    );
  }
  if (authorityLabel.instruction_authority !== "authoritative") {
    throw new Error("ifc_effect_authority_required");
  }
  if (parents.length === 0) throw new Error("ifc_effect_parent_labels_required");
  const parentBindings = (await Promise.all(
    parents.map(async (parent) => ({
      label_ref: parent.label_ref,
      content_hash: parent.content_hash,
      label_body_hash: await sha256Canonical(parent),
    })),
  ))
    .sort((left, right) =>
      left.label_ref.localeCompare(right.label_ref) ||
      left.content_hash.localeCompare(right.content_hash) ||
      left.label_body_hash.localeCompare(right.label_body_hash),
    );
  const effectiveIdentityHash = await sha256Canonical({
    authority_label_ref: authorityLabel.label_ref,
    authority_label_content_hash: authorityLabel.content_hash,
    authority_label_body_hash: await sha256Canonical(authorityLabel),
    parent_bindings: parentBindings,
    exact_request_content_hash: exactRequestContentHash,
  });
  const effectiveLabelRef = `ifc-label://runtime/effect/${effectiveIdentityHash.replace(
    "sha256:",
    "",
  )}`;
  const effective = deriveInformationFlowLabel(
    [...parents, authorityLabel],
    effectiveLabelRef,
    exactRequestContentHash,
    "join",
  );
  effective.instruction_authority = "authoritative";
  const validation = validateArchitectureContract(
    INFORMATION_FLOW_LABEL_CONTRACT_ID,
    effective,
  );
  if (!validation.ok) {
    throw new Error(`ifc_effect_label_invalid:${validation.errors.join(",")}`);
  }
  return effective;
}

export function deriveBoundaryInformationFlowLabel(
  parents: InformationFlowLabelV1[],
  labelRef: string,
  contentHash: string,
  derivationKind:
    | "summarization"
    | "model_substitution"
    | "memory_import"
    | "tool_output",
  origin: InformationFlowLabelV1["origin"],
  integrity: Exclude<InformationFlowLabelV1["integrity"], "unknown">,
  authorityCeiling: Exclude<
    InformationFlowLabelV1["instruction_authority"],
    "authoritative" | "unknown"
  >,
): InformationFlowLabelV1 {
  const derived = deriveInformationFlowLabel(
    parents,
    labelRef,
    contentHash,
    derivationKind,
  );
  derived.origin = origin;
  derived.integrity = moreRestrictive(
    derived.integrity,
    integrity,
    integrityOrder,
  );
  derived.instruction_authority = moreRestrictive(
    derived.instruction_authority,
    authorityCeiling,
    instructionAuthorityOrder,
  );
  const validation = validateArchitectureContract(
    INFORMATION_FLOW_LABEL_CONTRACT_ID,
    derived,
  );
  if (!validation.ok) {
    throw new Error(`ifc_derived_label_invalid:${validation.errors.join(",")}`);
  }
  return derived;
}

/** Raw model/provider output is untrusted content until separately verified. */
export const modelOutputInformationFlowLabel = (
  parents: InformationFlowLabelV1[],
  labelRef: string,
  contentHash: string,
) =>
  deriveBoundaryInformationFlowLabel(
    parents,
    labelRef,
    contentHash,
    "model_substitution",
    "model_output",
    "untrusted",
    "none",
  );

export const browserObservationInformationFlowLabel = (
  parents: InformationFlowLabelV1[],
  labelRef: string,
  contentHash: string,
) =>
  deriveBoundaryInformationFlowLabel(
    parents,
    labelRef,
    contentHash,
    "tool_output",
    "external_untrusted",
    "untrusted",
    "none",
  );

export const mcpOutputInformationFlowLabel = (
  parents: InformationFlowLabelV1[],
  labelRef: string,
  contentHash: string,
) =>
  deriveBoundaryInformationFlowLabel(
    parents,
    labelRef,
    contentHash,
    "tool_output",
    "tool_output",
    "untrusted",
    "none",
  );
