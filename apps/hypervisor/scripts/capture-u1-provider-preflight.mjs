#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { qualifyU1Provider, sha256Bytes } from "./lib/u1-provider-preflight.mjs";

const arg = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
};
const provider = arg("--provider");
const outputDirArg = arg("--output-dir");
const input = arg("--input");
if (!provider || !outputDirArg) {
  throw new Error("usage: --provider <akash-address> --output-dir <private-dir> [--input <provider-response.json>]");
}
const outputDir = path.resolve(outputDirArg);
mkdirSync(outputDir, { recursive: true, mode: 0o700 });
const sourceUrl = `https://console-api.akash.network/v1/providers/${provider}`;
let raw;
if (input) {
  raw = readFileSync(path.resolve(input));
} else {
  const response = await fetch(sourceUrl, { signal: AbortSignal.timeout(20_000) });
  if (!response.ok) throw new Error(`provider preflight fetch refused: HTTP ${response.status}`);
  raw = Buffer.from(await response.arrayBuffer());
}
const record = JSON.parse(raw.toString("utf8"));
const decision = qualifyU1Provider(record, provider);
const evidence = {
  schema_version: "ioi.aft.u1-provider-preflight.v1",
  captured_at: new Date().toISOString(),
  source_url: sourceUrl,
  provider_response_sha256: sha256Bytes(raw),
  ...decision,
};
writeFileSync(path.join(outputDir, "provider-response.json"), raw, { mode: 0o600 });
writeFileSync(path.join(outputDir, "provider-preflight.json"), `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify({
  qualified: evidence.qualified,
  provider_address: provider,
  provider_response_sha256: evidence.provider_response_sha256,
  output: path.join(outputDir, "provider-preflight.json"),
  refusal_codes: evidence.refusal_codes,
}));
if (!evidence.qualified) process.exitCode = 1;
