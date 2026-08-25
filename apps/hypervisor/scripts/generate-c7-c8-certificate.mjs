#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { sealCertificate } from "./lib/c7-c8-certificate.mjs";

const arg = (name) => { const index = process.argv.indexOf(name); return index >= 0 ? process.argv[index + 1] : null; };
const evidenceDir = arg("--evidence");
const output = arg("--output");
if (!evidenceDir || !output) {
  console.error("usage: generate-c7-c8-certificate --evidence <dir> --output <certificate.json>");
  process.exit(2);
}
const input = path.join(path.resolve(evidenceDir), "run-evidence.json");
if (!fs.existsSync(input)) {
  console.error(`run evidence missing: ${input}`);
  process.exit(2);
}
const evidence = JSON.parse(fs.readFileSync(input, "utf8"));
const certificate = sealCertificate(evidence);
fs.writeFileSync(path.resolve(output), `${JSON.stringify(certificate, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify({ ok: true, certificate: path.resolve(output), certificate_hash: certificate.certificate_hash }));
