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

  const capabilitiesSource = await read("src/capabilities.ts");
  assert.match(capabilitiesSource, /buildCapabilityLease/);
  assert.match(capabilitiesSource, /buildCapabilityLeaseRevocation/);
  assert.match(capabilitiesSource, /WALLET_PROTOCOL_SCHEMA_VERSION/);

  const clientSource = await read("src/client.ts");
  assert.match(clientSource, /WALLET_NETWORK_PROTOCOL_METHODS/);
  assert.match(clientSource, /revokeCapabilityLease/);

  const routeSourcesSource = await read("src/route-sources.ts");
  assert.match(routeSourcesSource, /buildCandidateEvidenceFromSourceAdapter/);
  assert.match(routeSourcesSource, /exchangeRouteSourceAdapter/);
  assert.match(routeSourcesSource, /tradeVenueSourceAdapter/);
  assert.match(routeSourcesSource, /createHttpCandidateSourceClient/);
  assert.match(routeSourcesSource, /createDecentralizedExchangeCandidateSourceClient/);
  assert.match(routeSourcesSource, /createDecentralizedTradeCandidateSourceClient/);
  assert.match(routeSourcesSource, /DECENTRALIZED_EXCHANGE_ROUTE_ADAPTER_ID/);
  assert.match(routeSourcesSource, /DECENTRALIZED_TRADE_VENUE_ADAPTER_ID/);
  assert.match(routeSourcesSource, /assertCandidateEvidenceExecutable/);
  assert.match(routeSourcesSource, /candidate_source_only/);
});

test("SDK dist keeps protocol package imports instead of embedding protocol truth", async () => {
  const dist = await read("dist/index.js");

  assert.match(dist, /@ioi\/wallet-protocol/);
  assert.doesNotMatch(dist, /ioi\.wallet\.protocol\.v1/);
});

test("SDK builds and submits capability lease revocations through wallet protocol methods", async () => {
  const sdk = await import("../dist/index.js");
  const lease = sdk.buildCapabilityLease({
    lease_id: "lease:unit:gmail-send",
    subject_id: "agent:unit",
    holder_id: "account:unit",
    capability_scope: "scope:gmail.send",
    policy_hash: "hash:policy-unit",
    revocation_epoch: 7,
    issued_at: "2026-06-17T12:00:00.000Z",
    expires_at: "2026-06-17T13:00:00.000Z",
    receipt_refs: ["receipt:lease-issued-unit"],
  });
  const revocation = sdk.buildCapabilityLeaseRevocation({
    revocation_id: "revocation:unit:gmail-send",
    lease_id: lease.lease_id,
    initiator_id: "user:unit",
    holder_id: lease.holder_id,
    capability_scope: lease.capability_scope,
    policy_hash: lease.policy_hash,
    revocation_epoch: lease.revocation_epoch + 1,
    revoked_at: "2026-06-17T12:30:00.000Z",
    receipt_refs: ["receipt:lease-revoked-unit"],
  });
  const calls = [];
  const client = new sdk.WalletNetworkClient({
    async request(method, body) {
      calls.push({ method, body });
      return body;
    },
  });

  assert.equal(lease.capability_scope, "scope:gmail.send");
  assert.equal(revocation.schema_version, "ioi.wallet.protocol.v1");
  assert.equal(revocation.lease_id, lease.lease_id);
  assert.equal(revocation.revocation_epoch, 8);

  await client.issueCapabilityLease(lease);
  await client.revokeCapabilityLease(revocation);

  assert.deepEqual(
    calls.map((call) => call.method),
    ["wallet.capability.lease.issue", "wallet.capability.lease.revoke"],
  );
  assert.equal(calls[1].body.receipt_refs[0], "receipt:lease-revoked-unit");

  assert.throws(
    () =>
      sdk.buildCapabilityLeaseRevocation({
        revocation_id: "revocation:bad",
        lease_id: lease.lease_id,
        initiator_id: "user:unit",
        holder_id: lease.holder_id,
        capability_scope: "gmail.send",
        policy_hash: lease.policy_hash,
        revocation_epoch: 9,
        revoked_at: "2026-06-17T12:31:00.000Z",
      }),
    /scope: prefix/,
  );
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

test("SDK exposes first-party decentralized.exchange and trade candidate clients", async () => {
  const sdk = await import("../dist/index.js");
  const calls = [];
  const fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, body });
    const isExchange = body.source === "decentralized.exchange";
    return {
      ok: true,
      status: 200,
      async json() {
        return {
          candidate_evidence: [
            {
              candidate_id: isExchange
                ? "route-candidate:decentralized-exchange/usdc-eth"
                : "venue-candidate:decentralized-trade/eth-perp",
              source: body.source,
              adapter_id: body.adapter_id,
              observed_at: "2026-06-17T12:01:00.000Z",
              expires_at: "2026-06-17T12:05:00.000Z",
              coverage_state: "assessed",
              evidence_refs: [
                isExchange
                  ? "evidence://decentralized.exchange/route/1"
                  : "evidence://decentralized.trade/venue/1",
              ],
              risk_labels: isExchange ? ["No Bridge"] : ["Venue Risk"],
              claims: isExchange
                ? { route_source_count: "3" }
                : { market: "ETH-PERP" },
            },
          ],
        };
      },
    };
  };

  const exchange = sdk.createDecentralizedExchangeCandidateSourceClient({
    base_url: "https://decentralized.exchange",
    validation: { now: "2026-06-17T12:00:00.000Z" },
    fetch,
  });
  const trade = sdk.createDecentralizedTradeCandidateSourceClient({
    base_url: "https://decentralized.trade/api",
    validation: { now: "2026-06-17T12:00:00.000Z" },
    fetch,
  });

  assert.equal(exchange.adapter.source, "decentralized.exchange");
  assert.equal(exchange.adapter.trust_boundary, "candidate_source_only");
  assert.equal(trade.adapter.source, "decentralized.trade");
  assert.equal(trade.adapter.trust_boundary, "candidate_source_only");

  const routeEvidence = await exchange.getRouteCandidates({
    body: { from_asset: "USDC", to_asset: "ETH" },
  });
  const venueEvidence = await trade.getVenueCandidates({
    body: { market: "ETH-PERP", side: "long" },
  });

  assert.deepEqual(
    calls.map((call) => [call.url, call.body.adapter_id, call.body.source]),
    [
      [
        "https://decentralized.exchange/v1/route-candidates",
        "adapter:decentralized-exchange",
        "decentralized.exchange",
      ],
      [
        "https://decentralized.trade/api/v1/venue-candidates",
        "adapter:decentralized-trade",
        "decentralized.trade",
      ],
    ],
  );
  assert.equal(
    routeEvidence[0].candidate_id,
    "route-candidate:decentralized-exchange/usdc-eth",
  );
  assert.equal(
    venueEvidence[0].candidate_id,
    "venue-candidate:decentralized-trade/eth-perp",
  );
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
