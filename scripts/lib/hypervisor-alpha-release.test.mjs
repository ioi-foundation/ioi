// The release library's own gate: a signed tree verifies under the pinned key and ONLY under it;
// any changed byte, any unlisted file, any missing file, and any manifest edit is a failure.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  MANIFEST_FILE, RELEASE_SCHEMA, RELEASE_TARGET, SIGNATURE_FILE, canonicalManifestBytes, digestTree,
  generateSignerKey, signManifestBytes, signerKeyId, verifyReleaseDir,
} from "./hypervisor-alpha-release.mjs";

function makeRelease() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "alpha-release-test-"));
  fs.mkdirSync(path.join(dir, "bin"));
  fs.writeFileSync(path.join(dir, "bin", "hypervisor-daemon"), "#!/bin/sh\necho daemon\n", { mode: 0o755 });
  fs.writeFileSync(path.join(dir, "install.mjs"), "// installer\n");
  const signer = generateSignerKey();
  const files = digestTree(dir);
  const daemon = files.find((f) => f.path === "bin/hypervisor-daemon");
  const manifest = {
    schema: RELEASE_SCHEMA, version: "0.0.0-test", target: RELEASE_TARGET,
    components: { daemon: { path: daemon.path, sha256: daemon.sha256, size: daemon.size } },
    files,
    signer: { algorithm: "ed25519", key_id: signerKeyId(signer.publicKeyPem), public_key_pem: signer.publicKeyPem },
  };
  const bytes = canonicalManifestBytes(manifest);
  fs.writeFileSync(path.join(dir, MANIFEST_FILE), bytes);
  fs.writeFileSync(path.join(dir, SIGNATURE_FILE), `${signManifestBytes(bytes, signer.privateKeyPem)}\n`);
  return { dir, signer, manifest };
}

test("a signed release verifies under its pinned signer key", () => {
  const { dir, signer } = makeRelease();
  const result = verifyReleaseDir(dir, { trustedPublicKeyPem: signer.publicKeyPem });
  assert.deepEqual(result.failures, []);
  assert.equal(result.ok, true);
  assert.equal(result.manifest.version, "0.0.0-test");
});

test("verification refuses without a pinned key and under a different key", () => {
  const { dir } = makeRelease();
  assert.equal(verifyReleaseDir(dir, {}).ok, false);
  const other = generateSignerKey();
  const result = verifyReleaseDir(dir, { trustedPublicKeyPem: other.publicKeyPem });
  assert.equal(result.ok, false);
  assert.match(result.failures.join("\n"), /does not verify under the pinned signer/u);
});

test("a changed byte, an unlisted file, a missing file and a manifest edit each fail", () => {
  const changed = makeRelease();
  fs.appendFileSync(path.join(changed.dir, "bin", "hypervisor-daemon"), "x");
  assert.match(verifyReleaseDir(changed.dir, { trustedPublicKeyPem: changed.signer.publicKeyPem }).failures.join("\n"), /size mismatch|digest mismatch/u);

  const extra = makeRelease();
  fs.writeFileSync(path.join(extra.dir, "bin", "extra"), "planted\n");
  assert.match(verifyReleaseDir(extra.dir, { trustedPublicKeyPem: extra.signer.publicKeyPem }).failures.join("\n"), /unlisted file present: bin\/extra/u);

  const missing = makeRelease();
  fs.rmSync(path.join(missing.dir, "install.mjs"));
  assert.match(verifyReleaseDir(missing.dir, { trustedPublicKeyPem: missing.signer.publicKeyPem }).failures.join("\n"), /listed file missing: install.mjs/u);

  const edited = makeRelease();
  const manifest = JSON.parse(fs.readFileSync(path.join(edited.dir, MANIFEST_FILE), "utf8"));
  manifest.version = "9.9.9";
  fs.writeFileSync(path.join(edited.dir, MANIFEST_FILE), canonicalManifestBytes(manifest));
  assert.match(verifyReleaseDir(edited.dir, { trustedPublicKeyPem: edited.signer.publicKeyPem }).failures.join("\n"), /does not verify/u);
});

test("the signer key id is derived from the public key, so a swapped key cannot keep the id", () => {
  const a = generateSignerKey();
  const b = generateSignerKey();
  assert.notEqual(signerKeyId(a.publicKeyPem), signerKeyId(b.publicKeyPem));
  assert.match(signerKeyId(a.publicKeyPem), /^ed25519:[0-9a-f]{32}$/u);
});

// ---- the installer's own verbs (R-206, M12.2): preview writes nothing; uninstall removes only its footprint
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const INSTALLER = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "install-hypervisor-alpha-release.mjs");

function installer(args) {
  const out = execFileSync(process.execPath, [INSTALLER, ...args], { encoding: "utf8" });
  return JSON.parse(out.slice(out.indexOf("{")));
}

/** Every file under `dir` with its bytes' digest, so "byte-identical" is a comparison and not a claim. */
function snapshot(dir) {
  if (!fs.existsSync(dir)) return null;
  return Object.fromEntries(digestTree(dir).map((f) => [f.path, f.sha256]));
}

function makePrefixWithForeignMaterial() {
  const prefix = fs.mkdtempSync(path.join(os.tmpdir(), "alpha-prefix-test-"));
  fs.mkdirSync(path.join(prefix, "data", "keys"), { recursive: true });
  fs.writeFileSync(path.join(prefix, "data", "keys", "identity.pem"), "-----BEGIN PRIVATE KEY-----\nnot-really\n-----END PRIVATE KEY-----\n");
  fs.writeFileSync(path.join(prefix, "data", "agentgres.db"), "truth\n");
  fs.mkdirSync(path.join(prefix, "backups"));
  fs.writeFileSync(path.join(prefix, "backups", "snapshot-1.tar"), "backup bytes\n");
  return prefix;
}

test("preview writes nothing, under a missing prefix and under one that already holds foreign material", () => {
  const { dir, signer } = makeRelease();
  const trust = path.join(dir, "..", `alpha-trust-${path.basename(dir)}.pem`);
  fs.writeFileSync(trust, signer.publicKeyPem);

  const missing = path.join(os.tmpdir(), `alpha-preview-missing-${process.pid}-${Date.now()}`);
  const plan = installer(["preview", "--release", dir, "--trust", trust, "--prefix", missing]);
  assert.equal(plan.read_only, true);
  assert.equal(fs.existsSync(missing), false, "preview must not create the prefix");
  assert.equal(plan.would_write.release_dir, path.join(missing, "releases", "0.0.0-test"));
  assert.equal(plan.would_write.current_link, path.join(missing, "current"));
  assert.equal(plan.would_write.already_installed, false);
  assert.deepEqual(plan.preserved_if_present, []);
  assert.match(plan.egress, /^none during/u);
  assert.match(plan.data_custody.data_dir, /outside the prefix/u);

  const prefix = makePrefixWithForeignMaterial();
  const before = snapshot(prefix);
  const plan2 = installer(["preview", "--release", dir, "--trust", trust, "--prefix", prefix]);
  assert.deepEqual(snapshot(prefix), before, "preview must leave every byte under the prefix as it found it");
  assert.deepEqual(plan2.preserved_if_present.sort(), [path.join(prefix, "backups"), path.join(prefix, "data")]);
  fs.rmSync(trust);
});

test("uninstall removes exactly the installer's footprint and leaves foreign material byte-identical, listed", () => {
  const { dir, signer } = makeRelease();
  const trust = path.join(dir, "..", `alpha-trust-${path.basename(dir)}.pem`);
  fs.writeFileSync(trust, signer.publicKeyPem);
  const prefix = makePrefixWithForeignMaterial();
  const foreignBefore = { data: snapshot(path.join(prefix, "data")), backups: snapshot(path.join(prefix, "backups")) };

  const installed = installer(["install", "--release", dir, "--trust", trust, "--prefix", prefix]);
  installer(["activate", "--prefix", prefix, "--version", installed.version]);
  assert.equal(fs.existsSync(path.join(prefix, "releases", "0.0.0-test")), true);
  assert.equal(fs.existsSync(path.join(prefix, "current")), true);
  assert.equal(fs.existsSync(path.join(prefix, "state", "activation.json")), true);

  const result = installer(["uninstall", "--prefix", prefix]);
  assert.equal(result.ok, true);
  assert.deepEqual(result.removed.sort(), [path.join(prefix, "current"), path.join(prefix, "releases"), path.join(prefix, "state")]);
  assert.deepEqual(result.preserved.sort(), [path.join(prefix, "backups"), path.join(prefix, "data")]);
  assert.match(result.data_wipe, /not performed and not a verb/u);
  for (const entry of ["releases", "current", "state"]) assert.equal(fs.existsSync(path.join(prefix, entry)), false, `${entry} must be gone`);
  assert.deepEqual(snapshot(path.join(prefix, "data")), foreignBefore.data, "keys and truth under the prefix must be byte-identical");
  assert.deepEqual(snapshot(path.join(prefix, "backups")), foreignBefore.backups, "backups under the prefix must be byte-identical");

  const again = installer(["uninstall", "--prefix", prefix]);
  assert.deepEqual(again.removed, []);
  assert.deepEqual(again.preserved.sort(), [path.join(prefix, "backups"), path.join(prefix, "data")]);

  const gone = installer(["uninstall", "--prefix", path.join(os.tmpdir(), `alpha-uninstall-missing-${process.pid}-${Date.now()}`)]);
  assert.deepEqual(gone.removed, []);
  assert.match(gone.note, /does not exist/u);
  fs.rmSync(trust);
});

test("the installer has no data-wipe verb: a wipe flag on uninstall is refused before anything is touched", () => {
  const prefix = makePrefixWithForeignMaterial();
  const before = snapshot(prefix);
  const refused = spawnSync(process.execPath, [INSTALLER, "uninstall", "--prefix", prefix, "--wipe-data", "yes"], { encoding: "utf8" });
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /no data-wipe verb/u);
  assert.deepEqual(snapshot(prefix), before);
});
