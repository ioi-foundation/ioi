import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import test from "node:test";

import { collectStudioArtifactConformanceReport } from "./studio-artifact-conformance.mjs";

function writeFile(targetPath, contents) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.writeFileSync(targetPath, contents);
}

test("conformance report flags benchmark ids and retained skill names in production sources", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "studio-artifact-conformance-"));
  try {
    const evidenceRoot = path.join(root, "docs", "evidence", "studio-artifact-surface");
    const benchmarkCatalog = {
      version: 1,
      cases: [
        {
          benchmarkId: "html-quantum-explainer",
          caseBindings: ["html-quantum-explainer-baseline"],
        },
      ],
    };
    const corpusSummary = {
      cases: [
        {
          id: "html-quantum-explainer-baseline",
          selectedSkillNames: ["frontend-skill"],
        },
      ],
      benchmarkSuite: { cases: [] },
    };
    writeFile(
      path.join(root, "crates", "api", "src", "studio", "planning.rs"),
      "const ROUTE = 'html-quantum-explainer';",
    );
    writeFile(
      path.join(
        root,
        "apps",
        "autopilot",
        "src-tauri",
        "src",
        "kernel",
        "studio",
        "skills.rs",
      ),
      "const SKILL = 'frontend-skill';",
    );

    const report = collectStudioArtifactConformanceReport({
      repoRoot: root,
      evidenceRoot,
      corpusSummary,
      benchmarkCatalog,
    });

    assert.equal(report.passing, false);
    assert.equal(report.checks[0].status, "fail");
    assert.equal(report.checks[1].status, "fail");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("conformance report flags paraphrase scaffold drift and shimmed parity success", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "studio-artifact-conformance-"));
  try {
    const evidenceRoot = path.join(root, "docs", "evidence", "studio-artifact-surface");
    const benchmarkCatalog = {
      version: 1,
      cases: [
        {
          benchmarkId: "html-rollout-with-charts",
          caseBindings: ["case-a", "case-b"],
        },
      ],
    };
    const corpusSummary = {
      cases: [
        { id: "case-a", scaffoldFamily: "comparison_story", selectedSkillNames: [] },
        { id: "case-b", scaffoldFamily: "guided_tutorial", selectedSkillNames: [] },
      ],
      benchmarkSuite: {
        cases: [
          {
            benchmarkId: "html-quantum-explainer",
            trackedParityTarget: true,
            matchedClassification: "pass",
            matchedVerificationStatus: "ready",
            shimDependent: true,
          },
        ],
      },
    };

    const report = collectStudioArtifactConformanceReport({
      repoRoot: root,
      evidenceRoot,
      corpusSummary,
      benchmarkCatalog,
    });

    assert.equal(report.passing, false);
    assert.equal(report.checks[2].status, "fail");
    assert.equal(report.checks[3].status, "fail");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
