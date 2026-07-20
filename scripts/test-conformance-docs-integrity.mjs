import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkConformanceDocsIntegrity } from "./lib/conformance-docs-integrity.mjs";
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
const sovereignLocalMatrix = JSON.parse(fs.readFileSync(
  path.join(
    repoRoot,
    "docs/conformance/hypervisor-core/sovereign-local-completeness-matrix.v1.json",
  ),
  "utf8",
));

function expectMatrixFailure(mutator, pattern) {
  const fixture = structuredClone(sovereignLocalMatrix);
  mutator(fixture);
  assert.match(
    validateSovereignLocalCompletenessMatrix(fixture).join("\n"),
    pattern,
  );
}

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
    /duplicates|exactly the reviewed 32 scenarios/u,
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
});
