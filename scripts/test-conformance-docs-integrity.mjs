import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkConformanceDocsIntegrity } from "./lib/conformance-docs-integrity.mjs";
import {
  hashPlatformFaultMatrixValue,
  parsePlatformFaultMatrixJson,
  PLATFORM_FAULT_REVIEWED_SCENARIO_COUNT,
  validatePlatformFaultMatrix,
} from "./lib/platform-fault-matrix.mjs";
import {
  hashSovereignLocalCompletenessValue,
  parseSovereignLocalCompletenessJson,
  validateSovereignLocalCompletenessMatrix,
} from "./lib/sovereign-local-completeness-matrix.mjs";

test("attestation assurance broken links fail the conformance docs tier", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-conformance-docs-regression-"),
  );
  try {
    const conformanceRoot = path.join(root, "docs/conformance");
    const hypervisorCore = path.join(conformanceRoot, "hypervisor-core");
    fs.mkdirSync(hypervisorCore, { recursive: true });
    const assurance = path.join(hypervisorCore, "attestation-assurance.md");
    fs.writeFileSync(
      assurance,
      "# Attestation Assurance\n\n[Missing evidence](./missing-evidence.md)\n",
    );
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), [
      "docs/conformance/hypervisor-core/attestation-assurance.md has broken local link: [Missing evidence](./missing-evidence.md)",
    ]);

    fs.writeFileSync(
      path.join(hypervisorCore, "missing-evidence.md"),
      "# Evidence Owner\n\n## Claim Classes (`claim_class`)\n",
    );
    fs.writeFileSync(
      assurance,
      "# Attestation Assurance\n\n[Evidence](./missing-evidence.md#evidence-owner)\n",
    );
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), []);

    fs.writeFileSync(
      assurance,
      "# Attestation Assurance\n\n[Claim class](./missing-evidence.md#claim-classes-claim_class)\n",
    );
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), []);

    fs.writeFileSync(
      assurance,
      "# Attestation Assurance\n\n[Wrong anchor](./missing-evidence.md#absent)\n",
    );
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), [
      "docs/conformance/hypervisor-core/attestation-assurance.md has broken local anchor: [Wrong anchor](./missing-evidence.md#absent)",
    ]);

    fs.writeFileSync(
      assurance,
      "# Attestation Assurance\n\n[Missing reference][evidence]\n",
    );
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), [
      "docs/conformance/hypervisor-core/attestation-assurance.md has missing reference definition: [Missing reference][evidence]",
    ]);

    fs.writeFileSync(
      assurance,
      [
        "# Attestation Assurance",
        "",
        "[Full reference][evidence]",
        "[Collapsed reference][]",
        "[Shortcut reference]",
        "![Reference image][diagram]",
        "![Inline image](./assurance.png)",
        "",
        "[evidence]: ./missing-evidence.md#evidence-owner",
        "[collapsed reference]: ./missing-evidence.md",
        "[shortcut reference]: ./missing-evidence.md",
        "[diagram]: ./assurance.png",
        "",
      ].join("\n"),
    );
    fs.writeFileSync(path.join(hypervisorCore, "assurance.png"), "png");
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), []);

    fs.writeFileSync(
      assurance,
      [
        "# Attestation Assurance",
        "",
        "[Multiline inline](",
        "  ./missing-evidence.md#evidence-owner",
        ")",
        "",
        "[Multiline full][evidence]",
        "[Multiline collapsed][]",
        "[Multiline shortcut]",
        "![Multiline image][diagram]",
        "",
        "[evidence]:",
        "  <./missing-evidence.md#evidence-owner>",
        '  "Evidence title"',
        "[multiline collapsed]:",
        "  ./missing-evidence.md",
        "[multiline shortcut]:",
        "  ./missing-evidence.md",
        "[diagram]:",
        "  ./assurance.png",
        "",
      ].join("\n"),
    );
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), []);

    fs.writeFileSync(
      assurance,
      "# Attestation Assurance\n\n[Missing shortcut]\n",
    );
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), [
      "docs/conformance/hypervisor-core/attestation-assurance.md has missing reference definition: [Missing shortcut]",
    ]);

    fs.writeFileSync(
      assurance,
      "# Attestation Assurance\n\n[Missing collapsed][]\n",
    );
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), [
      "docs/conformance/hypervisor-core/attestation-assurance.md has missing reference definition: [Missing collapsed][]",
    ]);

    fs.writeFileSync(
      assurance,
      "# Attestation Assurance\n\n- [x] Complete\n- [-] In progress\n",
    );
    assert.deepEqual(
      checkConformanceDocsIntegrity({ root }),
      [],
      "checkbox syntax is exempt only at the start of a list item",
    );

    fs.writeFileSync(
      assurance,
      "# Attestation Assurance\n\nSee [x] for evidence. See [-] for status.\n",
    );
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), [
      "docs/conformance/hypervisor-core/attestation-assurance.md has missing reference definition: [x]",
      "docs/conformance/hypervisor-core/attestation-assurance.md has missing reference definition: [-]",
    ]);

    fs.writeFileSync(
      assurance,
      [
        "# Attestation Assurance",
        "",
        "[Broken multiline][evidence]",
        "",
        "[evidence]:",
        "  <./absent-multiline-reference.md>",
        '  "Broken target"',
        "",
      ].join("\n"),
    );
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), [
      "docs/conformance/hypervisor-core/attestation-assurance.md has broken local link: [Broken multiline][evidence]",
    ]);

    fs.writeFileSync(
      assurance,
      [
        "# Attestation Assurance",
        "",
        "[Broken multiline inline](",
        "  ./absent-multiline-inline.md",
        ")",
        "",
      ].join("\n"),
    );
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), [
      [
        "docs/conformance/hypervisor-core/attestation-assurance.md has broken local link:",
        "[Broken multiline inline](\n  ./absent-multiline-inline.md\n)",
      ].join(" "),
    ]);

    fs.writeFileSync(
      assurance,
      [
        "# Attestation Assurance",
        "",
        "[Broken target][evidence]",
        "",
        "[evidence]: ./absent-reference-target.md",
        "",
      ].join("\n"),
    );
    assert.deepEqual(checkConformanceDocsIntegrity({ root }), [
      "docs/conformance/hypervisor-core/attestation-assurance.md has broken local link: [Broken target][evidence]",
    ]);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const platformFaultMatrix = parsePlatformFaultMatrixJson(fs.readFileSync(
  path.join(
    repoRoot,
    "docs/conformance/hypervisor-core/platform-fault-matrix.v1.json",
  ),
  "utf8",
));
const sovereignLocalMatrix = JSON.parse(fs.readFileSync(
  path.join(
    repoRoot,
    "docs/conformance/hypervisor-core/sovereign-local-completeness-matrix.v1.json",
  ),
  "utf8",
));

function expectPlatformMatrixFailure(mutator, pattern) {
  const fixture = structuredClone(platformFaultMatrix);
  mutator(fixture);
  assert.match(
    validatePlatformFaultMatrix(fixture).join("\n"),
    pattern,
  );
}

function expectMatrixFailure(mutator, pattern) {
  const fixture = structuredClone(sovereignLocalMatrix);
  mutator(fixture);
  assert.match(
    validateSovereignLocalCompletenessMatrix(fixture).join("\n"),
    pattern,
  );
}

test("platform fault matrix is machine-validated and hash-stable", () => {
  assert.equal(
    platformFaultMatrix.scenarios.length,
    PLATFORM_FAULT_REVIEWED_SCENARIO_COUNT,
  );
  assert.deepEqual(validatePlatformFaultMatrix(platformFaultMatrix), []);
  const matrixHash = hashPlatformFaultMatrixValue(platformFaultMatrix);
  assert.equal(
    matrixHash,
    "sha256:36d9e756f5335c7083f968ebff5e25b413de732fa49e11558d62da95848c175e",
  );

  const reordered = Object.fromEntries(
    Object.entries(platformFaultMatrix).reverse(),
  );
  assert.equal(
    hashPlatformFaultMatrixValue(reordered),
    matrixHash,
    "object-key order must not alter the RFC 8785-style JCS hash",
  );
  const mutated = structuredClone(platformFaultMatrix);
  mutated.status = "implemented";
  assert.notEqual(hashPlatformFaultMatrixValue(mutated), matrixHash);
  assert.throws(
    () => parsePlatformFaultMatrixJson(
      '{"status":"target_fixture_only","status":"target_fixture_only"}',
    ),
    /duplicate JSON key status/u,
  );
  assert.throws(
    () => parsePlatformFaultMatrixJson('{"invalid":"\\ud800"}'),
    /lone Unicode surrogates/u,
  );
});

test("platform fault matrix fails closed on cleanup and activation drift", () => {
  expectPlatformMatrixFailure(
    (fixture) => {
      fixture.scenarios.push(structuredClone(fixture.scenarios[0]));
    },
    /duplicates|exactly the reviewed 32 scenarios/u,
  );
  expectPlatformMatrixFailure(
    (fixture) => {
      fixture.status = "executable";
    },
    /status must remain target_fixture_only/u,
  );
  expectPlatformMatrixFailure(
    (fixture) => {
      fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "provider-unreachable-cleanup-obligation-persists"
      )).input.cleanup_obligation.status = "completed";
    },
    /provider-unreachable cleanup must retain/u,
  );
  expectPlatformMatrixFailure(
    (fixture) => {
      fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "unknown-deletion-outcome-requires-cleanup-reconciliation"
      )).input.deletion_attempt.effect_outcome = "success";
    },
    /unknown cleanup deletion outcome must remain reconciling/u,
  );
  expectPlatformMatrixFailure(
    (fixture) => {
      const absence = fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "ambiguous-provider-not-found-does-not-close-cleanup"
      )).input.provider_absence_observation;
      absence.exact_identity_binding = true;
    },
    /provider not-found without exact namespace and identity/u,
  );
  for (const scenarioId of [
    "failed-activation-cannot-advance-active-head",
    "partial-activation-without-adjudication-cannot-advance-active-head",
    "unknown-activation-cannot-advance-active-head",
    "late-superseded-activation-cannot-reclaim-active-head",
  ]) {
    expectPlatformMatrixFailure(
      (fixture) => {
        const scenario = fixture.scenarios.find((entry) => (
          entry.scenario_id === scenarioId
        ));
        scenario.expected_active_head_ref =
          "activation://illegitimate-head-advance";
      },
      new RegExp(`${scenarioId} must preserve the exact prior active head`, "u"),
    );
  }
  expectPlatformMatrixFailure(
    (fixture) => {
      fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "late-superseded-activation-cannot-reclaim-active-head"
      )).input.late_success_observation = false;
    },
    /late superseded activation must not reclaim/u,
  );
  expectPlatformMatrixFailure(
    (fixture) => {
      fixture.scenarios[0].required_reason_codes = [
        "substituted_reason_code",
      ];
    },
    /reviewed semantic fingerprint/u,
  );
});

test("conformance docs integrity enforces the platform matrix and CPO roster", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-platform-conformance-regression-"),
  );
  try {
    const hypervisorCore = path.join(
      root,
      "docs/conformance/hypervisor-core",
    );
    fs.mkdirSync(hypervisorCore, { recursive: true });
    const drifted = structuredClone(platformFaultMatrix);
    drifted.status = "executable";
    fs.writeFileSync(
      path.join(hypervisorCore, "platform-fault-matrix.v1.json"),
      `${JSON.stringify(drifted, null, 2)}\n`,
    );
    fs.writeFileSync(
      path.join(hypervisorCore, "platform-operability.md"),
      Array.from(
        { length: 11 },
        (_, index) => `### CPO-${index + 1} — Requirement`,
      ).join("\n\n"),
    );
    const failures = checkConformanceDocsIntegrity({ root }).join("\n");
    assert.match(failures, /status must remain target_fixture_only/u);
    assert.match(failures, /reviewed semantic fingerprint/u);
    assert.match(failures, /must define exactly CPO-1 through CPO-12/u);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("sovereign-local matrix is machine-validated and hash-stable", () => {
  assert.deepEqual(
    validateSovereignLocalCompletenessMatrix(sovereignLocalMatrix),
    [],
  );
  const matrixHash = hashSovereignLocalCompletenessValue(
    "matrix",
    sovereignLocalMatrix,
  );
  assert.match(matrixHash, /^sha256:[a-f0-9]{64}$/u);

  const reordered = Object.fromEntries(
    Object.entries(sovereignLocalMatrix).reverse(),
  );
  assert.equal(
    hashSovereignLocalCompletenessValue("matrix", reordered),
    matrixHash,
    "object-key order must not alter the RFC 8785-style JCS hash",
  );
  assert.equal(
    hashSovereignLocalCompletenessValue(
      "matrix",
      JSON.parse(JSON.stringify(sovereignLocalMatrix)),
    ),
    matrixHash,
    "JSON whitespace must not alter the matrix hash",
  );
  const mutated = structuredClone(sovereignLocalMatrix);
  mutated.status = "mutated";
  assert.notEqual(
    hashSovereignLocalCompletenessValue("matrix", mutated),
    matrixHash,
    "a scalar mutation must alter the matrix hash",
  );
  assert.notEqual(
    hashSovereignLocalCompletenessValue(
      "claim-profile",
      sovereignLocalMatrix.claim_profiles[0],
    ),
    hashSovereignLocalCompletenessValue(
      "claim-profile",
      sovereignLocalMatrix.claim_profiles[1],
    ),
  );
  assert.equal(
    hashSovereignLocalCompletenessValue("execution-case", {
      numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27],
      string: "\u20ac$\u000f\nA'B\"\\\"/",
      literals: [null, true, false],
    }),
    "sha256:3e0351e278d4f58da19641c08d4f45d55b6bf8d156fea510e8e18409f91a520a",
    "the RFC 8785 number, string, and literal vector must stay byte-stable",
  );
  assert.throws(
    () => hashSovereignLocalCompletenessValue("matrix", "\ud800"),
    /lone Unicode surrogates/u,
  );
  assert.throws(
    () => parseSovereignLocalCompletenessJson(
      '{"status":"target_fixture_only","status":"target_fixture_only"}',
    ),
    /duplicate JSON key status/u,
  );
  assert.throws(
    () => parseSovereignLocalCompletenessJson('{"invalid":"\\ud800"}'),
    /lone Unicode surrogates/u,
  );
});

test("sovereign-local matrix fails closed on semantic substitutions", () => {
  expectMatrixFailure(
    (fixture) => {
      fixture.scenarios.push(structuredClone(fixture.scenarios[0]));
    },
    /duplicates|exactly the reviewed 42 scenarios/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.claim_profiles[0].required_prerequisite_claim_profile_ids = [
        "production_self_hosted",
      ];
    },
    /prerequisite cycle/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.scenarios[0].required_for_claims = ["unknown_claim"];
    },
    /unknown unknown_claim/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.operation_disposition_vocabulary[0] = "success";
    },
    /operation disposition vocabulary changed/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.scenarios = fixture.scenarios.filter((scenario) => (
        scenario.requirement_id !== "SLC-01"
        || scenario.scenario_kind !== "adversarial"
      ));
    },
    /SLC-01 lacks positive and adversarial coverage/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.scenarios.find((scenario) => (
        scenario.requirement_id === "SLC-07"
      )).fixture_binding = "each_fixture_independently";
    },
    /must jointly bind embedded and server fixtures/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.scenarios[0].required_for_claims = [
        "multi_node_high_availability",
      ];
    },
    /out-of-scope claim|unknown multi_node_high_availability/u,
  );
  expectMatrixFailure(
    (fixture) => {
      delete fixture.scenarios.find((scenario) => (
        scenario.scenario_id === "slc-05-changed-body-replay-is-refused"
      )).input.idempotency_key;
    },
    /same-key\/different-body replay contract/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.scenarios.find((scenario) => (
        scenario.scenario_id === "slc-02-local-exact-effect-admitted"
      )).required_evidence[1] = "placeholder-evidence";
    },
    /must bind the exact provider, decision, mandatory grant, optional lease pair, and receipt/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "slc-02-authenticated-without-authority-refused"
      )).expected_operation_disposition = "available";
    },
    /reviewed semantic fingerprint/u,
  );
  expectMatrixFailure(
    (fixture) => {
      for (const scenario of fixture.scenarios) {
        scenario.required_for_claims = [];
      }
    },
    /reviewed semantic fingerprint/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.claim_profiles.find((claim) => (
        claim.claim_profile_id === "minimum_l0_local_completeness"
      )).required_fixture_profile_ids = ["self_hosted_org_single_node"];
    },
    /reviewed semantic fingerprint/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.fixture_profiles.find((profile) => (
        profile.fixture_profile_id === "embedded_single_operator_offline"
      )).network_policy.non_loopback_egress = "allowed";
    },
    /reviewed semantic fingerprint/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.evaluation_rules = {};
    },
    /reviewed semantic fingerprint/u,
  );
  expectMatrixFailure(
    (fixture) => {
      const changedBody = fixture.scenarios.find((scenario) => (
        scenario.scenario_id === "slc-05-changed-body-replay-is-refused"
      ));
      changedBody.fixture_profile_ids = [];
      changedBody.required_for_claims = [];
      changedBody.expected_report_verdict = "incomplete";
      changedBody.forbidden_observations = [];
    },
    /reviewed semantic fingerprint/u,
  );
  expectMatrixFailure(
    (fixture) => {
      const installer = fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "slc-01-untrusted-installer-refused-before-execution"
      ));
      installer.required_evidence = installer.required_evidence.filter(
        (entry) => entry !== "installer_execution_count_zero",
      );
    },
    /pre-execution installer integrity contract/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "slc-02-route-and-mcp-authorization-surface-closed"
      )).input.mcp_authorization = "mcp_specific_policy_path";
    },
    /complete same-PEP route and MCP contract/u,
  );
  expectMatrixFailure(
    (fixture) => {
      const update = fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "slc-03-untrusted-update-refused-and-previous-build-preserved"
      ));
      update.required_evidence = update.required_evidence.filter(
        (entry) => entry !== "rollback_state_before_after_equal",
      );
    },
    /previous-build-preserving update refusal contract/u,
  );
  expectMatrixFailure(
    (fixture) => {
      const safeExport = fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "slc-06-default-export-excludes-secret-material-and-rebinds"
      ));
      safeExport.required_evidence = safeExport.required_evidence.filter(
        (entry) => entry !== "export_plaintext_secret_scan_count_zero",
      );
    },
    /default secret-exclusion and destination-rebind contract/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "slc-06-same-size-artifact-substitution-zero-target-mutation"
      )).input.declared_and_substituted_byte_length = "different";
    },
    /full-stream zero-mutation refusal contract/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "slc-08-attachment-drift-explicit-no-implicit-reconciliation"
      )).input.attachment_states_under_test.pop();
    },
    /explicit no-reconciliation drift contract/u,
  );
  expectMatrixFailure(
    (fixture) => {
      const quiescence = fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "slc-10-all-writer-classes-quiesced-during-migration"
      ));
      quiescence.required_evidence = quiescence.required_evidence.filter(
        (entry) => entry
          !== "identity_membership_mutation_blocked_or_durably_held",
      );
    },
    /post-checkpoint writer-refusal contract/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.scenarios.find((scenario) => (
        scenario.scenario_id
          === "slc-10-fence-observation-failure-or-timeout-only-takeover-refused"
      )).input.source_liveness = "assumed_absent_after_timeout";
    },
    /no-age-only-takeover contract/u,
  );
  expectMatrixFailure(
    (fixture) => {
      fixture.external_conditional_nonclaims.find((claim) => (
        claim.claim_id === "portable_secret_export"
      )).required_external_evidence.pop();
    },
    /portable_secret_export must remain an external conditional nonclaim/u,
  );
});
