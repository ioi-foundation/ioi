#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const arg = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
};
const directoryArg = arg("--directory");
const outputName = arg("--output") || "artifact-manifest.json";
if (!directoryArg || path.basename(outputName) !== outputName) {
  throw new Error("usage: --directory <flat-directory> [--output artifact-manifest.json]");
}
const directory = path.resolve(directoryArg);
const mediaType = (name) => name.endsWith(".json")
  ? "application/json"
  : name.endsWith(".yaml") || name.endsWith(".yml")
    ? "application/yaml"
    : name.endsWith(".log") || name.endsWith(".txt") || name.endsWith(".md")
      ? "text/plain"
      : "application/octet-stream";
const entries = fs.readdirSync(directory)
  .filter((name) => name !== outputName)
  .sort()
  .map((name) => {
    const file = path.join(directory, name);
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`artifact directory must be flat and contain regular files only: ${name}`);
    }
    const bytes = fs.readFileSync(file);
    return {
      path: name,
      bytes: bytes.length,
      media_type: mediaType(name),
      sha256: `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`,
    };
  });
const output = path.join(directory, outputName);
const temporary = `${output}.${process.pid}.tmp`;
fs.writeFileSync(temporary, `${JSON.stringify({
  schema_version: "ioi.artifact-directory-manifest.v1",
  entries,
}, null, 2)}\n`, { mode: 0o600, flag: "wx" });
fs.renameSync(temporary, output);
console.log(JSON.stringify({ ok: true, output, artifact_count: entries.length }));
