import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { materializeReviewedSdl } from "./certified-campaign-config.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..", "..", "..", "..");
const template = readFileSync(
  path.join(repo, "internal-docs/architecture/protocols/aft/bench/akash/deploy.sdl"),
  "utf8",
);
const digest = `sha256:${"a".repeat(64)}`;
const valid = {
  plan: {
    campaign_id: "u1-campaign-a",
    benchmark_source_commit: "b".repeat(40),
    image_digest: digest,
    benchmark_protocol_version: "res-p4.3.v1",
    result_schema_version: "ioi.aft.benchmark-campaign.v1",
    benchmark_warmups: 1,
    benchmark_repeats: 5,
    ceiling_amount: "1000",
  },
  sdl_values: {
    registry_host: "ghcr.io",
    image_reference: `ghcr.io/ioi-foundation/ioi-aft-bench@${digest}`,
    secret_canary: "u1-canary-abcdefgh",
  },
};

test("materializes every reviewed non-secret token into the hashed SDL", () => {
  const rendered = materializeReviewedSdl(template, valid);
  assert.match(rendered, /AFT_BENCH_CAMPAIGN_ID=u1-campaign-a/u);
  assert.match(rendered, new RegExp(`@${digest}`));
  assert.match(rendered, /AFT_BENCH_REPEATS=5/u);
  assert.doesNotMatch(rendered, /OWNER_(?:APPROVED|SEEDED)|IMMUTABLE_IMAGE_DIGEST|PRIVATE_REGISTRY/u);
});

test("rejects an image reference that differs from the authority-bound digest", () => {
  const config = structuredClone(valid);
  config.sdl_values.image_reference = `ghcr.io/ioi-foundation/ioi-aft-bench@sha256:${"c".repeat(64)}`;
  assert.throws(() => materializeReviewedSdl(template, config), /approved digest/u);
});

test("rejects an incomplete benchmark protocol contract", () => {
  const config = structuredClone(valid);
  config.plan.benchmark_repeats = 4;
  assert.throws(() => materializeReviewedSdl(template, config), /RES-P4.3/u);
});

test("plain C7 SDL passes unchanged but unresolved reviewed tokens do not", () => {
  const plain = "services:\n  web:\n    image: nginx@sha256:abc\n";
  assert.equal(materializeReviewedSdl(plain, {}), plain);
  assert.throws(() => materializeReviewedSdl(template, {}), /unresolved owner-review/u);
});
