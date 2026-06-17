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
});

test("SDK dist keeps protocol package imports instead of embedding protocol truth", async () => {
  const dist = await read("dist/index.js");

  assert.match(dist, /@ioi\/wallet-protocol/);
  assert.doesNotMatch(dist, /ioi\.wallet\.protocol\.v1/);
});
