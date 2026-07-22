import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateCanonToCodeDelta } from "./check-canon-to-code-delta.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const source = fs.readFileSync(
  path.join(repoRoot, "docs/architecture/_meta/canon-to-code-delta.md"),
  "utf8",
);

function messages(mutatedSource) {
  return validateCanonToCodeDelta({
    repoRoot,
    source: mutatedSource,
  }).errors.join("\n");
}

test("canon-to-code delta accepts the committed manifest and table", () => {
  assert.equal(messages(source), "");
});

test("canon-to-code delta rejects duplicate identities and missing rows", () => {
  const duplicated = source.replace(
    '"id":"delta-temporal-verification-profile"',
    '"id":"delta-authority-scope-request-envelope"',
  );
  assert.match(messages(duplicated), /duplicates row identity/u);

  const missing = source.replace(
    "| `TemporalVerificationProfile`, `TemporalValidityEvaluation`",
    "| `UndeclaredTemporalProfile`, `TemporalValidityEvaluation`",
  );
  assert.match(
    messages(missing),
    /requires missing delta row TemporalVerificationProfile/u,
  );
});

test("canon-to-code delta rejects bad owner links and manifest paths", () => {
  const badOwner = source.replace(
    "../foundations/common-objects-and-envelopes.md",
    "../foundations/not-a-canonical-owner.md",
  );
  assert.match(messages(badOwner), /invalid canonical-owner link/u);

  const badAnchor = source.replace(
    "packages/wallet-protocol/schemas/principal-authority-resolution.schema.json",
    "packages/wallet-protocol/schemas/not-present.schema.json",
  );
  assert.match(messages(badAnchor), /code anchor does not exist/u);

  const driftedTableAnchor = source.replace(
    "`packages/wallet-protocol/schemas/principal-authority-resolution.schema.json` (`implementation`)",
    "`packages/wallet-protocol/schemas/principal-authority-resolution.schema.json` (`precedent`)",
  );
  assert.match(
    messages(driftedTableAnchor),
    /table anchors do not exactly match/u,
  );
});

test("canon-to-code delta keeps coverage exact and proof/status routing pointer-only", () => {
  const driftedCoverage = source.replace(
    "| partial | request/review/receipt",
    "| complete | request/review/receipt",
  );
  assert.match(
    messages(driftedCoverage),
    /disagrees with exact table coverage complete/u,
  );

  const proseStatus = source.replace(
    "[work-item records](./work-items/README.md)",
    "proof passes in this cut",
  );
  assert.match(
    messages(proseStatus),
    /must route proof\/status by work-item pointer only/u,
  );
});

test("canon-to-code delta rejects live or merged delivery narratives in table rows", () => {
  const liveNarrative = source.replace(
    "immutable, content-addressed pursuit specification interpreted by the Goal Kernel",
    "current live implementation of a pursuit specification interpreted by the Goal Kernel",
  );
  assert.match(
    messages(liveNarrative),
    /prohibited live\/merged implementation-status narrative/u,
  );

  const mergedNarrative = source.replace(
    "daemon profile admission and selected scoped-step resolution with exact receipts",
    "M5 merged and live plane; daemon profile admission and selected scoped-step resolution",
  );
  assert.match(
    messages(mergedNarrative),
    /prohibited live\/merged implementation-status narrative/u,
  );
});

test("canon-to-code delta does not promote an unmanifested prose path", () => {
  const proseOnly = source.replace(
    "## Sequencer routing",
    "An explanatory note mentions `future/not-present.rs` without declaring an anchor.\n\n## Sequencer routing",
  );
  assert.equal(messages(proseOnly), "");
});
