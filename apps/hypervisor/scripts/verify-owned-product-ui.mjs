#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const ownedRoot = path.join(appRoot, "product-ui", "owned", "public");
const manifestPath = path.join(
  appRoot,
  "product-ui",
  "owned",
  "vendor-manifest.json",
);
const sha256 = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

function walkFiles(directory) {
  return fs
    .readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) return walkFiles(absolute);
      assert.ok(entry.isFile(), `owned tree contains a non-file: ${absolute}`);
      return [path.relative(ownedRoot, absolute).split(path.sep).join("/")];
    })
    .sort();
}

assert.ok(fs.existsSync(manifestPath), "owned product UI manifest is missing");
assert.ok(fs.existsSync(path.join(ownedRoot, "index.html")), "owned product UI index is missing");
assert.equal(
  fs.realpathSync(ownedRoot),
  ownedRoot,
  "owned product UI root must not resolve through a symlink",
);

const manifestBytes = fs.readFileSync(manifestPath);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
assert.equal(manifest.src, "product-ui/public", "unexpected legacy parity source");
assert.equal(
  manifest.dest,
  "product-ui/owned/public",
  "manifest does not target the shipped owned tree",
);
assert.ok(
  manifest.files && typeof manifest.files === "object",
  "owned product UI manifest has no file ledger",
);

const actualFiles = walkFiles(ownedRoot);
const declaredFiles = Object.keys(manifest.files).sort();
assert.deepEqual(
  actualFiles,
  declaredFiles,
  "owned tree and vendor manifest file sets differ",
);

const treeHash = createHash("sha256");
for (const relative of declaredFiles) {
  const record = manifest.files[relative];
  assert.ok(
    ["beautified", "owned-edit", "verbatim"].includes(record.mode),
    `${relative}: unsupported ownership mode ${JSON.stringify(record.mode)}`,
  );
  assert.match(record.src_sha256, /^[a-f0-9]{64}$/u, `${relative}: invalid source digest`);
  assert.match(record.out_sha256, /^[a-f0-9]{64}$/u, `${relative}: invalid owned digest`);
  if (record.mode === "beautified") {
    assert.equal(record.gate, "esbuild-ast-equal", `${relative}: missing AST gate`);
  }
  if (record.mode === "verbatim") {
    assert.equal(
      record.out_sha256,
      record.src_sha256,
      `${relative}: a verbatim record cannot change bytes`,
    );
  }
  const bytes = fs.readFileSync(path.join(ownedRoot, relative));
  const actualSha256 = sha256(bytes);
  assert.equal(
    actualSha256,
    record.out_sha256,
    `${relative}: owned bytes differ from the committed ledger`,
  );
  treeHash.update(relative);
  treeHash.update("\0");
  treeHash.update(actualSha256);
  treeHash.update("\0");
}

const evidence = {
  schema_version: "ioi.hypervisor-owned-product-ui-integrity.v1",
  status: "passed",
  files: declaredFiles.length,
  manifest_sha256: sha256(manifestBytes),
  tree_sha256: treeHash.digest("hex"),
  index_sha256: sha256(fs.readFileSync(path.join(ownedRoot, "index.html"))),
};

if (process.argv.includes("--json")) console.log(JSON.stringify(evidence));
else {
  console.log(
    `owned product UI integrity: ${evidence.files} files, tree sha256:${evidence.tree_sha256}`,
  );
}
