import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { checkConformanceDocsIntegrity } from "./lib/conformance-docs-integrity.mjs";

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
      "docs/conformance/hypervisor-core/attestation-assurance.md has broken local link: ./missing-evidence.md",
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
      "docs/conformance/hypervisor-core/attestation-assurance.md has broken local anchor: ./missing-evidence.md#absent",
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
