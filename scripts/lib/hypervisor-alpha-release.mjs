// hypervisor-alpha-release — the packaged release of the Hypervisor bounded alpha
// (bounded-alpha-profile.md steps 1 and 12; core-clients-surfaces.md § Zero-To-Operable Local
// Deployment). One library owns the manifest shape, the file-digest census, the signer and the
// verification so the packager, the installer and the journey verify the SAME thing.
//
// A release is a directory (or its .tar.zst) with:
//   release.json   the manifest: version, target, provenance, every file's sha256 and size, the
//                  components and their prerequisites, the SBOM, and the signer's public key
//   release.sig    base64 Ed25519 signature over sha256(release.json bytes)
//   bin/           hypervisor-daemon, mint-approval-grant, wallet-network-local-authority
//   node-bins/     orchestration, workload, guardian, ioi-signer (the authority node's validator
//                  processes for the Solo/IAVL profile)
//   app/           the served App: apps/hypervisor scripts + surfaces + product-ui (owned tree)
//                  + the node packages its import graph reaches
//   shims/         packages/hypervisor-harness-shims
//   install.mjs    the installer (verify / install / activate / rollback / status)
//
// Verification never trusts the manifest for its own integrity: the signature is checked against
// a public key the operator PINS (never one read from the package), then every listed file is
// re-hashed, and any file present but unlisted is a failure.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const RELEASE_SCHEMA = "ioi.hypervisor.alpha-release.v1";
export const RELEASE_TARGET = "linux-x86_64";
export const MANIFEST_FILE = "release.json";
export const SIGNATURE_FILE = "release.sig";

export const sha256Bytes = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
export const sha256File = (file) => {
  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(file, "r");
  try {
    const buffer = Buffer.alloc(1 << 20);
    let read = 0;
    while ((read = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) hash.update(buffer.subarray(0, read));
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest("hex");
};

/** Every regular file under `root` (relative POSIX paths, sorted), excluding the manifest/signature. */
export function walkFiles(root, { exclude = new Set([MANIFEST_FILE, SIGNATURE_FILE]) } = {}) {
  const out = [];
  const visit = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const abs = path.join(dir, entry.name);
      const rel = path.relative(root, abs).split(path.sep).join("/");
      if (entry.isSymbolicLink()) throw new Error(`release trees carry no symlinks: ${rel}`);
      if (entry.isDirectory()) visit(abs);
      else if (entry.isFile() && !exclude.has(rel)) out.push(rel);
    }
  };
  visit(root);
  return out;
}

export function digestTree(root) {
  return walkFiles(root).map((rel) => {
    const abs = path.join(root, rel);
    const stat = fs.statSync(abs);
    return { path: rel, sha256: sha256File(abs), size: stat.size, mode: (stat.mode & 0o777).toString(8) };
  });
}

// ---- signer ---------------------------------------------------------------------------------

export function generateSignerKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
  };
}

export function signerKeyId(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return `ed25519:${sha256Bytes(der).slice(0, 32)}`;
}

export function signManifestBytes(manifestBytes, privateKeyPem) {
  const key = crypto.createPrivateKey(privateKeyPem);
  return crypto.sign(null, Buffer.from(sha256Bytes(manifestBytes), "hex"), key).toString("base64");
}

export function verifyManifestSignature(manifestBytes, signatureBase64, publicKeyPem) {
  try {
    const key = crypto.createPublicKey(publicKeyPem);
    return crypto.verify(null, Buffer.from(sha256Bytes(manifestBytes), "hex"), key, Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}

// ---- verification -----------------------------------------------------------------------------

/**
 * Verify an unpacked release directory against a PINNED signer public key. Returns
 * { ok, manifest, manifestSha256, failures[] }. `ok` is false on any failure; nothing is trusted
 * from the manifest until the signature under the pinned key has passed.
 */
export function verifyReleaseDir(dir, { trustedPublicKeyPem } = {}) {
  const failures = [];
  const manifestPath = path.join(dir, MANIFEST_FILE);
  const signaturePath = path.join(dir, SIGNATURE_FILE);
  if (!trustedPublicKeyPem) failures.push("no pinned signer public key was supplied (verification refuses to trust a key carried by the package)");
  if (!fs.existsSync(manifestPath)) failures.push(`${MANIFEST_FILE} is absent`);
  if (!fs.existsSync(signaturePath)) failures.push(`${SIGNATURE_FILE} is absent`);
  if (failures.length) return { ok: false, manifest: null, manifestSha256: null, failures };
  const manifestBytes = fs.readFileSync(manifestPath);
  const manifestSha256 = sha256Bytes(manifestBytes);
  const signature = fs.readFileSync(signaturePath, "utf8").trim();
  if (!verifyManifestSignature(manifestBytes, signature, trustedPublicKeyPem)) {
    failures.push("release.sig does not verify under the pinned signer public key");
    return { ok: false, manifest: null, manifestSha256, failures };
  }
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString("utf8")); } catch (error) { failures.push(`release.json is not JSON: ${error.message}`); return { ok: false, manifest: null, manifestSha256, failures }; }
  if (manifest.schema !== RELEASE_SCHEMA) failures.push(`unexpected schema ${manifest.schema}`);
  if (manifest.target !== RELEASE_TARGET) failures.push(`unexpected target ${manifest.target}`);
  if (signerKeyId(trustedPublicKeyPem) !== manifest.signer?.key_id) failures.push("manifest signer key_id is not the pinned key's id");
  const listed = new Map((manifest.files || []).map((f) => [f.path, f]));
  const present = walkFiles(dir);
  for (const rel of present) {
    const entry = listed.get(rel);
    if (!entry) { failures.push(`unlisted file present: ${rel}`); continue; }
    const abs = path.join(dir, rel);
    const size = fs.statSync(abs).size;
    if (size !== entry.size) { failures.push(`size mismatch: ${rel}`); continue; }
    if (sha256File(abs) !== entry.sha256) failures.push(`digest mismatch: ${rel}`);
  }
  for (const rel of listed.keys()) if (!present.includes(rel)) failures.push(`listed file missing: ${rel}`);
  for (const [name, component] of Object.entries(manifest.components || {})) {
    if (component.path && listed.get(component.path)?.sha256 !== component.sha256) failures.push(`component ${name} digest disagrees with its file entry`);
  }
  return { ok: failures.length === 0, manifest, manifestSha256, failures };
}

export function canonicalManifestBytes(manifest) {
  return Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}
