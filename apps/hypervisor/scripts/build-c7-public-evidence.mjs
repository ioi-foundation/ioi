#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import {
  buildPublicEvidence,
  writePublicEvidenceBundle,
} from "./lib/c7-public-evidence.mjs";

const arg = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
};
const certificatePath = arg("--certificate");
const verificationPath = arg("--verification");
const outputDir = arg("--output");
if (!certificatePath || !verificationPath || !outputDir) {
  throw new Error("usage: --certificate <json> --verification <json> --output <empty-dir>");
}
const certificate = JSON.parse(fs.readFileSync(path.resolve(certificatePath), "utf8"));
const verification = JSON.parse(fs.readFileSync(path.resolve(verificationPath), "utf8"));
const summary = buildPublicEvidence(certificate, verification);
const result = writePublicEvidenceBundle(
  path.resolve(outputDir),
  summary,
  verification,
  process.env.IOI_PUBLIC_EVIDENCE_CANARY || "",
);
console.log(JSON.stringify({ ok: true, ...result, certificate_hash: certificate.certificate_hash }));
