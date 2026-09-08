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
