#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { assemblePortableBundle, validatePortableBundleShape } from "./lib/c8-v3-portable-bundle.mjs";

const arg = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
};
const specPath = arg("--spec");
const output = arg("--output");
if (!specPath || !output) throw new Error("usage: --spec <assembly-spec.json> --output <new-directory>");
const spec = JSON.parse(fs.readFileSync(path.resolve(specPath), "utf8"));
const result = assemblePortableBundle(spec, path.resolve(output));
const validation = validatePortableBundleShape(result.bundle);
if (!validation.ok) throw new Error(`portable bundle refused: ${validation.failures.join(",")}`);
console.log(JSON.stringify({ ok: true, output: path.resolve(output), bundle_ref: result.bundle.bundle_ref, bundle_hash: result.bundle.bundle_hash, certificate_ref: result.certificate.certificate_ref, certificate_hash: result.certificate.certificate_hash }));
