import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(__dirname, "..");

async function read(relativePath) {
  return readFile(resolve(packageRoot, relativePath), "utf8");
}

test("SDK package depends on @ioi/wallet-protocol as the contract source", async () => {
  const packageJson = JSON.parse(await read("package.json"));

  assert.equal(packageJson.dependencies["@ioi/wallet-protocol"], "0.1.0");
  assert.equal(packageJson.name, "@ioi/wallet-sdk");
});

test("SDK source imports wallet semantics from the protocol package", async () => {
  const files = [
    "src/authority-review.ts",
    "src/capabilities.ts",
    "src/client.ts",
    "src/receipts.ts",
    "src/route-sources.ts",
    "src/index.ts",
  ];

  for (const file of files) {
    const source = await read(file);
    assert.match(source, /@ioi\/wallet-protocol/);
  }

  const authorityReviewSource = await read("src/authority-review.ts");
  assert.match(authorityReviewSource, /WALLET_PROTOCOL_SCHEMA_VERSION/);
  assert.match(authorityReviewSource, /WalletPresentationProfile/);
  assert.match(authorityReviewSource, /recommended_presentation_profile/);
  assert.match(authorityReviewSource, /allowed_approval_modes/);
  assert.match(authorityReviewSource, /scope:/);

  const clientSource = await read("src/client.ts");
  assert.match(clientSource, /WALLET_NETWORK_PROTOCOL_METHODS/);

  const routeSourcesSource = await read("src/route-sources.ts");
  assert.match(routeSourcesSource, /buildCandidateEvidenceFromSourceAdapter/);
  assert.match(routeSourcesSource, /exchangeRouteSourceAdapter/);
  assert.match(routeSourcesSource, /tradeVenueSourceAdapter/);
  assert.match(routeSourcesSource, /createHttpCandidateSourceClient/);
  assert.match(routeSourcesSource, /assertCandidateEvidenceExecutable/);
  assert.match(routeSourcesSource, /candidate_source_only/);
});

test("SDK dist keeps protocol package imports instead of embedding protocol truth", async () => {
  const dist = await read("dist/index.js");

  assert.match(dist, /@ioi\/wallet-protocol/);
  assert.doesNotMatch(dist, /ioi\.wallet\.protocol\.v1/);
});

test("SDK HTTP candidate source client validates executable evidence from route sources", async () => {
  const sdk = await import("../dist/index.js");
  const calls = [];
  const client = sdk.createHttpCandidateSourceClient({
    base_url: "https://routes.example/",
    validation: { now: "2026-06-17T12:00:00.000Z" },
    fetch: async (url, init) => {
      calls.push({ url, init });
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            candidate_evidence: [
              {
                candidate_id: "route-candidate:eth/usdc/1",
                source: "decentralized.exchange",
                adapter_id: "adapter:decentralized-exchange",
                observed_at: "2026-06-17T12:01:00.000Z",
                expires_at: "2026-06-17T12:05:00.000Z",
                coverage_state: "assessed",
                evidence_refs: ["evidence://route/simulation/1"],
                risk_labels: ["No Bridge"],
                claims: { venue_count: "2" },
              },
            ],
          };
        },
      };
    },
  });

  const evidence = await client.getExchangeRouteCandidates({
    adapter_id: "adapter:decentralized-exchange",
    source: "decentralized.exchange",
    body: { from_asset: "USDC", to_asset: "ETH" },
  });

  assert.equal(calls[0].url, "https://routes.example/v1/route-candidates");
  assert.equal(JSON.parse(calls[0].init.body).adapter_id, "adapter:decentralized-exchange");
  assert.equal(evidence[0].candidate_id, "route-candidate:eth/usdc/1");
});

test("SDK HTTP candidate source client rejects evidence from the wrong adapter", async () => {
  const sdk = await import("../dist/index.js");
  const client = sdk.createHttpCandidateSourceClient({
    base_url: "https://trade.example",
    validation: { now: "2026-06-17T12:00:00.000Z" },
    fetch: async () => ({
      ok: true,
      status: 200,
      async json() {
        return [
          {
            candidate_id: "venue-candidate:perp/eth/1",
            source: "unknown-source",
            adapter_id: "adapter:wrong",
            observed_at: "2026-06-17T12:01:00.000Z",
            expires_at: "2026-06-17T12:05:00.000Z",
            coverage_state: "assessed",
            evidence_refs: ["evidence://trade/simulation/1"],
            risk_labels: ["Venue Risk"],
            claims: { market: "ETH-PERP" },
          },
        ];
      },
    }),
  });

  await assert.rejects(
    () =>
      client.getTradeVenueCandidates({
        adapter_id: "adapter:decentralized-trade",
        source: "decentralized.trade",
      }),
    /must match the declared adapter and source/,
  );
});
