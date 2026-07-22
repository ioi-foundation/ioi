import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  GUIDE_FILE,
  GUIDE_PATCH_FILE,
  GUIDE_PATCH_MANIFEST_FILE,
  validateStatelessMasterGuide,
  validateStatelessMasterGuideBundle,
} from "./check-stateless-master-guide.mjs";

const repoRoot = path.resolve(import.meta.dirname, "..");
const stages = Array.from(
  { length: 15 },
  (_, index) =>
    `### M${index} — Stage ${index}\n\nDoctrine and proof definition only.`,
).join("\n\n");
const validGuide = `# IOI Target-End-State Master Implementation Guide

Document role: sole internal M0–M14 implementation sequencer.

Status truth rule: durable cut status lives in machine-checked
ioi.program.work_item.v1 records. program-state.json is a derived local
orientation projection and not a second sequencer.

${stages}
`;
const manifestSource = fs.readFileSync(
  path.join(repoRoot, GUIDE_PATCH_MANIFEST_FILE),
  "utf8",
);
const patchSource = fs.readFileSync(
  path.join(repoRoot, GUIDE_PATCH_FILE),
  "utf8",
);

const messages = (source) =>
  validateStatelessMasterGuide({ source }).errors.join("\n");

test("stateless master-guide contract accepts doctrine and pointers", () => {
  assert.equal(messages(validGuide), "");
  assert.equal(
    messages(
      validGuide.replace(
        "Doctrine and proof definition only.",
        "M2 defines one active writer, an active lease, and fencing doctrine.",
      ),
    ),
    "",
    "active-writer doctrine must not be mistaken for live stage status",
  );
  assert.equal(
    messages(
      `${validGuide}\nSource disposition: \`absorbed_complete\`. Completed work is retained as history and regression evidence.`,
    ),
    "",
    "guide-owned source disposition vocabulary is not live cut status",
  );
});

test("stateless master-guide contract rejects ordinary live status narratives", () => {
  for (const [narrative, expected] of [
    ["Status: active — held cut.", /live Status:/u],
    [
      "Current implementation evidence (2026-07-22): merged.",
      /current implementation-evidence/u,
    ],
    [
      "Current state: M2 is active and M1 verified.",
      /current-state narrative/u,
    ],
    ["M3 remains pending.", /stage-state narrative/u],
    [
      "Implementation merged in PR #999.",
      /merged-implementation PR narrative/u,
    ],
    [
      "Canon absorption is complete; the old phase list is closed.",
      /implementation-completion narrative/u,
    ],
    ["Track 1 is complete.", /implementation-completion narrative/u],
    ["Implementation is complete.", /implementation-completion narrative/u],
    [
      "`packages/design-system` exists and Hypervisor Web consumes it.",
      /code-existence and consumer-adoption narrative/u,
    ],
    [
      "The built effect-fence v1 remains unchanged.",
      /built-contract narrative/u,
    ],
  ]) {
    assert.match(messages(`${validGuide}\n${narrative}`), expected, narrative);
  }
});

test("stateless master-guide contract rejects an incomplete stage spine", () => {
  assert.match(
    messages(validGuide.replace(/^### M14[^\n]*\n\n[^\n]*$/mu, "")),
    /exactly M0–M14/u,
  );
});

test("tracked guide-patch work record validates when the private guide is absent", () => {
  const result = validateStatelessMasterGuideBundle({
    guideSource: null,
    manifestSource,
    patchSource,
  });
  assert.deepEqual(result.errors, []);
  assert.equal(result.skipped, true);
  assert.equal(
    result.stageCount,
    15,
    "clean-checkout mode must validate reconstructed guide semantics",
  );
});

test("tracked guide-patch work record rejects tampering", () => {
  const patchResult = validateStatelessMasterGuideBundle({
    guideSource: null,
    manifestSource,
    patchSource: patchSource.replace(
      "Document role: sole internal M0–M14 implementation sequencer.",
      "Document role: changed after review.",
    ),
  });
  assert.match(patchResult.errors.join("\n"), /patch sha256/u);

  const manifest = JSON.parse(manifestSource);
  manifest.classification = "AUTHORITY";
  const manifestResult = validateStatelessMasterGuideBundle({
    guideSource: null,
    manifestSource: `${JSON.stringify(manifest)}\n`,
    patchSource,
  });
  assert.match(manifestResult.errors.join("\n"), /classified WORK-RECORD/u);
});

const guidePath = path.join(repoRoot, GUIDE_FILE);
test(
  "a present private guide must match the reviewed result and patch base",
  { skip: !fs.existsSync(guidePath) },
  () => {
    const reviewedGuide = fs.readFileSync(guidePath, "utf8");
    const reviewed = validateStatelessMasterGuideBundle({
      guideSource: reviewedGuide,
      manifestSource,
      patchSource,
    });
    assert.deepEqual(reviewed.errors, []);
    assert.equal(reviewed.skipped, false);

    const drifted = validateStatelessMasterGuideBundle({
      guideSource: `${reviewedGuide}\nImplementation merged in PR #999.\n`,
      manifestSource,
      patchSource,
    });
    assert.match(drifted.errors.join("\n"), /reviewed result sha256/u);
    assert.match(
      drifted.errors.join("\n"),
      /merged-implementation PR narrative/u,
    );
  },
);
