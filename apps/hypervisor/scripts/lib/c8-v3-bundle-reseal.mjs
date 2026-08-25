import fs from "node:fs";
import path from "node:path";
import { contentHash, sealSelfHash } from "./c8-v3-portable-bundle.mjs";

// Fully reseals a mutated portable bundle so that rejection tests semantics
// rather than a broken outer hash: the mutated object is rehashed, every
// dependent object that carries a copy of that hash is rewritten and rehashed,
// the certificate's bindings are rewritten, and the certificate and bundle are
// resealed. `refs` names the roles the dependency fix-ups need; every key is
// optional and a bundle that omits one simply skips that fix-up.

// A portable bundle may legitimately carry two versions of one logical object
// under a single ref — the real trajectory transition does exactly that. A
// target is therefore addressed by ref, and by file where the ref alone is
// ambiguous. Never by first match: an ambiguous ref fails closed.
const asTarget = (target) => (typeof target === "string" ? { ref: target, file: null } : target);
const sameTarget = (left, right) => {
  const a = asTarget(left);
  const b = asTarget(right);
  if (!a?.ref || !b?.ref || a.ref !== b.ref) return false;
  return a.file === null || b.file === null || a.file === b.file;
};

export function readBundleObject(directory, bundle, target) {
  const { ref, file } = asTarget(target);
  const matches = [...bundle.objects, ...bundle.trust_inputs]
    .filter((entry) => entry.ref === ref && (file === null || entry.file === file));
  if (matches.length === 0) throw new Error(`portable descriptor missing: ${ref}${file ? ` (${file})` : ""}`);
  if (matches.length > 1) throw new Error(`portable descriptor ref is version-ambiguous without a file: ${ref}`);
  const [descriptor] = matches;
  return [descriptor, JSON.parse(fs.readFileSync(path.join(directory, descriptor.file), "utf8"))];
}

// Rebinds only the bindings that carried `previousHash`. Rewriting every binding
// that merely names the ref would silently retarget the sibling version.
export function replaceCertificateBinding(value, reference, hash, previousHash) {
  if (Array.isArray(value)) {
    for (const item of value) replaceCertificateBinding(item, reference, hash, previousHash);
    return;
  }
  if (!value || typeof value !== "object") return;
  if (value.ref === reference && value.hash === previousHash) value.hash = hash;
  for (const [key, child] of Object.entries(value)) {
    if (key.endsWith("_ref") && child === reference) {
      const hashKey = `${key.slice(0, -4)}_hash`;
      if (Object.hasOwn(value, hashKey) && value[hashKey] === previousHash) value[hashKey] = hash;
    }
    replaceCertificateBinding(child, reference, hash, previousHash);
  }
}

export function fullyResealBundle({ directory, refs, objectRef, mutate, mutateCertificate }) {
  let bundle = JSON.parse(fs.readFileSync(path.join(directory, "bundle.json"), "utf8"));
  let certificate = JSON.parse(fs.readFileSync(path.join(directory, "certificate.json"), "utf8"));
  const writeBoundObject = (target, value) => {
    const [descriptor] = readBundleObject(directory, bundle, target);
    const previousHash = descriptor.hash;
    try { value = sealSelfHash(value); } catch { /* objects without self-hash contracts use their full JCS hash */ }
    fs.writeFileSync(path.join(directory, descriptor.file), `${JSON.stringify(value, null, 2)}\n`);
    descriptor.hash = contentHash(value);
    replaceCertificateBinding(certificate, descriptor.ref, descriptor.hash, previousHash);
    return descriptor.hash;
  };
  if (objectRef) {
    const [, value] = readBundleObject(directory, bundle, objectRef);
    mutate(value);
    const changedHash = writeBoundObject(objectRef, value);
    if (sameTarget(objectRef, refs.request)) {
      const [, claims] = readBundleObject(directory, bundle, refs.claims);
      claims.subject_hash = changedHash;
      writeBoundObject(refs.claims, claims);
      for (const dependentRef of [refs.drawRequest, refs.drawReceipt, refs.decision]) {
        const [, dependent] = readBundleObject(directory, bundle, dependentRef);
        dependent.candidate_operation_hash = changedHash;
        writeBoundObject(dependentRef, dependent);
      }
    }
    if (sameTarget(objectRef, refs.result) || sameTarget(objectRef, refs.environment)) {
      const hashField = sameTarget(objectRef, refs.result) ? "result_hash" : "environment_hash";
      for (const dependentRef of [refs.retrieval, refs.campaign]) {
        const [, dependent] = readBundleObject(directory, bundle, dependentRef);
        dependent[hashField] = changedHash;
        writeBoundObject(dependentRef, dependent);
      }
    }
    if (sameTarget(objectRef, refs.settlement)) {
      const [, campaignObject] = readBundleObject(directory, bundle, refs.campaign);
      campaignObject.terminal_settlement_hash = changedHash;
      writeBoundObject(refs.campaign, campaignObject);
    }
    if (sameTarget(objectRef, refs.before) || sameTarget(objectRef, refs.after)) {
      const [, decisionObject] = readBundleObject(directory, bundle, refs.decision);
      decisionObject[sameTarget(objectRef, refs.before) ? "state_before_hash" : "state_after_hash"] = changedHash;
      writeBoundObject(refs.decision, decisionObject);
    }
    if (sameTarget(objectRef, refs.isolationRequirements) || sameTarget(objectRef, refs.isolationEvidence)) {
      const [, isolationObject] = readBundleObject(directory, bundle, refs.isolation);
      if (sameTarget(objectRef, refs.isolationRequirements)) isolationObject.requirements_hash = changedHash;
      else isolationObject.enforcement_coverage_refs_and_hashes.find((entry) => entry.ref === asTarget(objectRef).ref).hash = changedHash;
      writeBoundObject(refs.isolation, isolationObject);
    }
  }
  if (mutateCertificate) mutateCertificate(certificate);
  certificate = sealSelfHash(certificate);
  fs.writeFileSync(path.join(directory, "certificate.json"), `${JSON.stringify(certificate, null, 2)}\n`);
  bundle.certificate_hash = certificate.certificate_hash;
  bundle = sealSelfHash(bundle);
  fs.writeFileSync(path.join(directory, "bundle.json"), `${JSON.stringify(bundle, null, 2)}\n`);
}
