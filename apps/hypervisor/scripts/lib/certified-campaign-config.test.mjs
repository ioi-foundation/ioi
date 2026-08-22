import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  certifiedRemainingDelayMs,
  certifiedWorkloadDeadlineMs,
  materializeReviewedSdl,
  validateCertifiedCampaignConfig,
} from "./certified-campaign-config.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..", "..", "..", "..");
const template = readFileSync(
  path.join(repo, "internal-docs/architecture/protocols/aft/bench/akash/deploy.sdl"),
  "utf8",
);
const digest = `sha256:${"a".repeat(64)}`;
const valid = {
  schema_version: "ioi.hypervisor.certified-provider-campaign.v1",
  plan: {
    campaign_id: "u1-campaign-a",
    benchmark_source_commit: "b".repeat(40),
    image_digest: digest,
    benchmark_protocol_version: "res-p4.3.v2",
    result_schema_version: "ioi.aft.benchmark-campaign.v1",
    benchmark_warmups: 1,
    benchmark_repeats: 5,
    max_duration_seconds: 7_200,
    result_tls_server_certificate_sha256: `sha256:${"c".repeat(64)}`,
    ceiling_amount: "1000",
    ceiling_denom: "uact",
    teardown_policy: "always_teardown_required",
    provider_selector: {
      mode: "exact",
      provider_address: "akash19zzh7whjt4vfwxd5wtj3tjtyatnpntfhldshd8",
      selection: "only_qualified_bid_from_exact_provider",
    },
  },
  sdl_values: {
    registry_host: "ghcr.io",
    image_reference: `ghcr.io/ioi-foundation/ioi-aft-bench@${digest}`,
    secret_canary: "u1-canary-abcdefgh",
  },
};

test("accepts a fully resolved bounded U1 campaign config", () => {
  const config = structuredClone(valid);
  config.plan.deposit_usd = 1;
  assert.equal(validateCertifiedCampaignConfig(config), config);
});

test("starts the workload duration at readiness and never sleeps past its deadline", () => {
  assert.equal(certifiedWorkloadDeadlineMs(1_000, 7_200), 7_201_000);
  assert.equal(certifiedRemainingDelayMs(7_180_000, 7_201_000, 15_000), 15_000);
  assert.equal(certifiedRemainingDelayMs(7_195_000, 7_201_000, 15_000), 6_000);
  assert.equal(certifiedRemainingDelayMs(7_201_000, 7_201_000, 15_000), 0);
  assert.throws(() => certifiedWorkloadDeadlineMs(-1, 7_200), /readinessProvenAtMs/u);
  assert.throws(() => certifiedRemainingDelayMs(0, 1, -1), /requestedMs/u);
});

test("rejects unresolved provider, spend, and image review choices before execution", () => {
  for (const mutate of [
    (config) => { config.plan.provider_selector.provider_address = "OWNER_SELECTED_AKASH_PROVIDER_ADDRESS"; },
    (config) => { config.plan.deposit_usd = "OWNER_APPROVED_DEPOSIT_USD"; },
    (config) => { config.plan.ceiling_amount = "OWNER_APPROVED_UACT_CEILING"; },
    (config) => { config.sdl_values.image_reference = "ghcr.io/ioi-foundation/ioi-aft-bench@sha256:OWNER_APPROVED_64_HEX_DIGEST"; },
  ]) {
    const config = structuredClone(valid);
    config.plan.deposit_usd = 1;
    mutate(config);
    assert.throws(() => validateCertifiedCampaignConfig(config), /unresolved owner-review/u);
  }
});

test("rejects unbounded or non-exact U1 authority", () => {
  const invalidDeposit = structuredClone(valid);
  invalidDeposit.plan.deposit_usd = 5.01;
  assert.throws(() => validateCertifiedCampaignConfig(invalidDeposit), /deposit_usd/u);

  const marketplace = structuredClone(valid);
  marketplace.plan.deposit_usd = 1;
  marketplace.plan.provider_selector = { mode: "any_marketplace", selection: "lowest_qualified_bid" };
  assert.throws(() => validateCertifiedCampaignConfig(marketplace), /exact Akash provider/u);

  const topup = structuredClone(valid);
  topup.plan.deposit_usd = 1;
  topup.plan.auto_topup = true;
  assert.throws(() => validateCertifiedCampaignConfig(topup), /auto_topup/u);

  const unpinned = structuredClone(valid);
  unpinned.plan.deposit_usd = 1;
  delete unpinned.plan.result_tls_server_certificate_sha256;
  assert.throws(() => validateCertifiedCampaignConfig(unpinned), /certificate SHA-256 pin/u);

  for (const duration of [undefined, 59, 86_401, 7_200.5]) {
    const invalidDuration = structuredClone(valid);
    invalidDuration.plan.deposit_usd = 1;
    invalidDuration.plan.max_duration_seconds = duration;
    assert.throws(() => validateCertifiedCampaignConfig(invalidDuration), /max_duration_seconds/u);
  }
});

test("materializes every reviewed non-secret token into the hashed SDL", () => {
  const rendered = materializeReviewedSdl(template, valid);
  assert.match(rendered, /AFT_BENCH_CAMPAIGN_ID=u1-campaign-a/u);
  assert.match(rendered, new RegExp(`@${digest}`));
  assert.match(rendered, /AFT_BENCH_REPEATS=5/u);
  assert.match(rendered, /port:\s*8080[\s\S]*?as:\s*443/u);
  assert.doesNotMatch(rendered, /as:\s*80(?:\s|$)/u);
  assert.doesNotMatch(rendered, /OWNER_(?:APPROVED|SEEDED)|IMMUTABLE_IMAGE_DIGEST|PRIVATE_REGISTRY/u);
});

test("rejects a U1 result service exposed only over plaintext", () => {
  const plaintext = template.replace(/as:\s*443/u, "as: 80");
  assert.throws(
    () => materializeReviewedSdl(plaintext, valid),
    /provider-terminated HTTPS on external port 443/u,
  );
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
