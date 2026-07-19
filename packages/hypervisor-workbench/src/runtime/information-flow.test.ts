import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import type { InformationFlowLabelV1 } from "./generated/architecture-contracts";
import {
  compileAdmittedInformationFlowEffectLabel,
  deriveInformationFlowLabel,
  evaluateInformationFlow,
  modelOutputInformationFlowLabel,
  type InformationFlowEffectBinding,
} from "./information-flow";

type FixtureCase = {
  id: string;
  origin: InformationFlowLabelV1["origin"];
  integrity: InformationFlowLabelV1["integrity"];
  confidentiality: InformationFlowLabelV1["confidentiality"];
  instruction_authority: InformationFlowLabelV1["instruction_authority"];
  with_approval: boolean;
  mutation: "none" | "destination" | "request" | "reviewed_representation";
  tool_destination_declarations: string[];
  expected_ok: boolean;
  expected_code: string | null;
};

type Fixture = {
  destination: string;
  changed_destination: string;
  request: Record<string, unknown>;
  changed_request: Record<string, unknown>;
  reviewed_representation: Record<string, unknown>;
  changed_reviewed_representation: Record<string, unknown>;
  cases: FixtureCase[];
};

const fixture = JSON.parse(
  readFileSync(
    "tests/fixtures/information-flow/ifc-cases.v1.json",
    "utf8",
  ),
) as Fixture;

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

function hash(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function bindingFor(
  destination: string,
  request: unknown,
  reviewed: unknown,
): InformationFlowEffectBinding {
  return {
    effectHash: hash({ method: "POST", destination, request }),
    requestHash: hash(request),
    reviewedRepresentationHash: hash(reviewed),
  };
}

function labelFor(case_: FixtureCase): InformationFlowLabelV1 {
  const protectedClass = ["private", "restricted"].includes(
    case_.confidentiality,
  );
  return {
    schema_version: "ioi.foundations.information-flow-label.v1",
    label_ref: "ifc-label://test/input",
    profile_ref: "policy://ifc/default-v1",
    content_hash: `sha256:${"a".repeat(64)}`,
    origin: case_.origin,
    integrity: case_.integrity,
    confidentiality: case_.confidentiality,
    instruction_authority: case_.instruction_authority,
    egress_policy: {
      mode: protectedClass ? "declassification_required" : "allow_declared",
      allowed_destination_patterns: ["https://api.example.test/v1/*"],
      allowed_data_classes: [
        "public",
        "internal",
        "confidential",
        "private",
        "restricted",
      ],
    },
    purpose: "test-effect",
    retention: { max_seconds: 60, disposition: "delete" },
    derivation_kind: "direct",
    derivation_parent_refs: [],
    derivation_closure_refs: ["ifc-label://test/input"],
  };
}

function toolFor(destinations: string[]) {
  return {
    schema_version: "ioi.components.connectors-tools.runtime-tool-contract.v1",
    tool_id: "tool://example.send",
    revision_ref: "tool://example.send/revision/1.0.0",
    predecessor_revision_ref: null,
    content_hash: `sha256:${"b".repeat(64)}`,
    namespace: "example",
    display_name: "Send example",
    version: "1.0.0",
    risk_class: "external_message",
    effect_class: "external_message",
    primitive_capabilities_required: ["prim:net.request"],
    authority_scopes_required: ["scope:example.send"],
    approval_required: true,
    evidence_required: ["request_preview"],
    owner: "connector://example",
    data_class_allowlist: ["public", "internal", "confidential"],
    egress_policy: {
      default: "allow_declared",
      allowed_destination_patterns: destinations,
    },
  };
}

function approvalFor(
  label: InformationFlowLabelV1,
  tool: ReturnType<typeof toolFor>,
  binding: InformationFlowEffectBinding,
) {
  return {
    schema_version: "ioi.foundations.declassification-approval.v1",
    approval_ref: "approval://test/exact",
    issuer_ref: "wallet://test",
    subject_ref: "agent://test",
    authority_grant_ref: "grant://test/declassify",
    tool_contract_revision_ref: tool.revision_ref,
    label_ref: label.label_ref,
    label_content_hash: label.content_hash,
    decision: "allow",
    declassified_to: "public",
    exact_effect_hash: binding.effectHash,
    exact_request_hash: binding.requestHash,
    reviewed_representation_hash: binding.reviewedRepresentationHash,
    destination: fixture.destination,
    purpose: label.purpose,
    issued_at: "2026-07-16T00:00:00Z",
    expires_at: "2099-07-16T00:05:00Z",
    status: "active",
    approval_receipt_ref: "receipt://test/exact",
  };
}

test("shared adversarial fixture matrix matches TypeScript projection", () => {
  const baseline = bindingFor(
    fixture.destination,
    fixture.request,
    fixture.reviewed_representation,
  );
  for (const case_ of fixture.cases) {
    const label = labelFor(case_);
    const tool = toolFor(case_.tool_destination_declarations);
    const approval = case_.with_approval
      ? approvalFor(label, tool, baseline)
      : undefined;
    const destination =
      case_.mutation === "destination"
        ? fixture.changed_destination
        : fixture.destination;
    const request =
      case_.mutation === "request" ? fixture.changed_request : fixture.request;
    const reviewed =
      case_.mutation === "reviewed_representation"
        ? fixture.changed_reviewed_representation
        : fixture.reviewed_representation;
    const result = evaluateInformationFlow({
      label,
      toolContract: tool,
      destination,
      binding: bindingFor(destination, request, reviewed),
      declassificationApproval: approval,
    });
    assert.equal(result.ok, case_.expected_ok, case_.id);
    if (!result.ok) assert.equal(result.code, case_.expected_code, case_.id);
  }
});

test("derivation preserves labels and transitive parent closure", () => {
  const publicLabel = labelFor(fixture.cases[fixture.cases.length - 1]);
  const privateLabel = labelFor(fixture.cases[0]);
  privateLabel.label_ref = "ifc-label://test/private-parent";
  privateLabel.derivation_closure_refs = [
    "ifc-label://test/grandparent",
    privateLabel.label_ref,
  ];
  for (const kind of [
    "summarization",
    "model_substitution",
    "memory_import",
  ] as const) {
    const derived = deriveInformationFlowLabel(
      [publicLabel, privateLabel],
      `ifc-label://test/${kind}`,
      `sha256:${"c".repeat(64)}`,
      kind,
    );
    assert.equal(derived.confidentiality, "private");
    assert.equal(derived.integrity, "untrusted");
    assert.equal(derived.instruction_authority, "authoritative");
    assert.ok(
      derived.derivation_closure_refs.includes("ifc-label://test/grandparent"),
    );
  }
});

test("effect compilation cannot launder actual private untrusted parents", async () => {
  const parent = labelFor(fixture.cases[0]);
  parent.label_ref = "ifc-label://test/private-parent";
  parent.origin = "external_untrusted";
  parent.integrity = "untrusted";
  parent.confidentiality = "private";
  parent.instruction_authority = "untrusted";
  const authority = labelFor(fixture.cases[fixture.cases.length - 1]);
  authority.label_ref = "ifc-label://test/effect-authority";
  authority.origin = "operator";
  authority.integrity = "verified";
  authority.confidentiality = "public";
  authority.instruction_authority = "authoritative";
  authority.egress_policy.mode = "allow_declared";
  const effective = await compileAdmittedInformationFlowEffectLabel(
    [parent],
    authority,
    hash(fixture.request),
  );
  assert.equal(effective.confidentiality, "private");
  assert.equal(effective.integrity, "untrusted");
  assert.equal(effective.instruction_authority, "authoritative");
  const decision = evaluateInformationFlow({
    label: effective,
    toolContract: toolFor([fixture.destination]),
    destination: fixture.destination,
    binding: bindingFor(
      fixture.destination,
      fixture.request,
      fixture.reviewed_representation,
    ),
  });
  assert.deepEqual(decision, {
    ok: false,
    code: "ifc_private_untrusted_egress",
    message:
      "private-or-higher context derived from untrusted content cannot egress",
  });
});

test("raw model output from private verified input remains untrusted content-only", async () => {
  const privateInput = labelFor(fixture.cases[fixture.cases.length - 1]);
  privateInput.label_ref = "ifc-label://test/private-verified-input";
  privateInput.origin = "operator";
  privateInput.integrity = "verified";
  privateInput.confidentiality = "private";
  privateInput.instruction_authority = "context_only";
  privateInput.egress_policy.mode = "declassification_required";
  const modelOutput = modelOutputInformationFlowLabel(
    [privateInput],
    "ifc-label://test/raw-model-output",
    hash({ text: "provider response" }),
  );
  assert.equal(modelOutput.origin, "model_output");
  assert.equal(modelOutput.integrity, "untrusted");
  assert.equal(modelOutput.instruction_authority, "none");

  const authority = labelFor(fixture.cases[fixture.cases.length - 1]);
  authority.label_ref = "ifc-label://test/followup-authority";
  authority.origin = "operator";
  authority.integrity = "verified";
  authority.confidentiality = "public";
  authority.instruction_authority = "authoritative";
  authority.egress_policy.mode = "allow_declared";
  const effective = await compileAdmittedInformationFlowEffectLabel(
    [modelOutput],
    authority,
    hash(fixture.request),
  );
  const decision = evaluateInformationFlow({
    label: effective,
    toolContract: toolFor([fixture.destination]),
    destination: fixture.destination,
    binding: bindingFor(
      fixture.destination,
      fixture.request,
      fixture.reviewed_representation,
    ),
  });
  assert.equal(decision.ok, false);
  if (!decision.ok) assert.equal(decision.code, "ifc_private_untrusted_egress");
});

test("effective effect label identity binds request and ordered parent identity", async () => {
  const parent = labelFor(fixture.cases[fixture.cases.length - 1]);
  parent.label_ref = "ifc-label://test/effect-parent";
  parent.instruction_authority = "context_only";
  const authority = labelFor(fixture.cases[fixture.cases.length - 1]);
  authority.label_ref = "ifc-label://test/effect-authority";
  authority.instruction_authority = "authoritative";
  const first = await compileAdmittedInformationFlowEffectLabel(
    [parent],
    authority,
    `sha256:${"c".repeat(64)}`,
  );
  const changedRequest = await compileAdmittedInformationFlowEffectLabel(
    [parent],
    authority,
    `sha256:${"d".repeat(64)}`,
  );
  assert.notEqual(first.label_ref, changedRequest.label_ref);

  const axisChangedParent: InformationFlowLabelV1 = {
    ...parent,
    confidentiality: "confidential",
  };
  const axisChanged = await compileAdmittedInformationFlowEffectLabel(
    [axisChangedParent],
    authority,
    `sha256:${"c".repeat(64)}`,
  );
  assert.notEqual(first.label_ref, axisChanged.label_ref);

  const changedParent: InformationFlowLabelV1 = {
    ...parent,
    content_hash: `sha256:${"e".repeat(64)}`,
  };
  const changedClosure = await compileAdmittedInformationFlowEffectLabel(
    [changedParent],
    authority,
    `sha256:${"c".repeat(64)}`,
  );
  assert.notEqual(first.label_ref, changedClosure.label_ref);
  assert.ok(first.derivation_closure_refs.includes(authority.label_ref));
});
