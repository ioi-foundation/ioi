#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { verifyPlacementAttestation } from "./lib/u1-placement-attestation.mjs";

const arg = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
};
const attestationArg = arg("--attestation");
const publicKeyArg = arg("--public-key");
const campaignAArg = arg("--campaign-a");
const campaignBArg = arg("--campaign-b");
const outputPath = arg("--output") ? path.resolve(arg("--output")) : null;
if (![attestationArg, publicKeyArg, campaignAArg, campaignBArg].every(Boolean)) {
  throw new Error("usage: --attestation <json> --public-key <provider-secp256k1-public.pem> --campaign-a <certificate.json> --campaign-b <certificate.json> [--output <json>]");
}
const attestationPath = path.resolve(attestationArg);
const publicKeyPath = path.resolve(publicKeyArg);
const campaignAPath = path.resolve(campaignAArg);
const campaignBPath = path.resolve(campaignBArg);
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const result = verifyPlacementAttestation(
  readJson(attestationPath),
  fs.readFileSync(publicKeyPath),
  [readJson(campaignAPath), readJson(campaignBPath)],
);
const record = { schema_version: "ioi.check.u1-placement-attestation.v2", ...result };
if (outputPath) fs.writeFileSync(outputPath, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify(record, null, 2));
process.exit(result.ok ? 0 : 1);
