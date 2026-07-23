import assert from "node:assert/strict";
import test from "node:test";
import {
  validateStatelessMasterGuide,
  validateStatelessMasterGuideBundle,
} from "./check-stateless-master-guide.mjs";

const stages = Array.from(
  { length: 15 },
  (_, index) =>
    `### M${index} — Stage ${index}\n\nDoctrine and proof definition only.`,
).join("\n\n");
const validGuide = `# IOI Target-End-State Master Implementation Guide

Document role: sole internal M0–M14 implementation sequencer.

Status truth rule: durable cut status lives in the ignored, machine-local
ioi.program.work_item.v1 records. program-state.json is a derived local
orientation projection and not a second sequencer.

${stages}
`;
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

test("stateless master-guide contract rejects a canon-hosted implementation queue", () => {
  assert.match(
    messages(
      `${validGuide}\nRead docs/architecture/_meta/work-items/README.md.`,
    ),
    /private implementation queue/u,
  );
});

test("stateless master-guide contract rejects an incomplete stage spine", () => {
  assert.match(
    messages(validGuide.replace(/^### M14[^\n]*\n\n[^\n]*$/mu, "")),
    /exactly M0–M14/u,
  );
});

test("clean checkout makes an honest private-estate skip", () => {
  const result = validateStatelessMasterGuideBundle({
    guideSource: null,
  });
  assert.deepEqual(result.errors, []);
  assert.equal(result.skipped, true);
  assert.equal(result.stageCount, 0);
});

test("a present private guide is validated semantically", () => {
  const result = validateStatelessMasterGuideBundle({
    guideSource: validGuide,
    manifestSource: null,
    patchSource: null,
  });
  assert.match(result.errors.join("\n"), /missing private guide patch/u);
  assert.equal(result.skipped, false);
});
