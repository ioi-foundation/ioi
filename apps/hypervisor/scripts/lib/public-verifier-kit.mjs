// M06.11 — THE PUBLISHED VERIFICATION PACKAGE ("the kit"), assembled from tracked sources and sealed.
// (docs/architecture/foundations/verifiable-bounded-agency.md § The published verification package;
// ioi-authority-protocol.md § Stable Release Gates; register R-218.)
//
// WHAT A KIT IS. One content-addressed directory holding everything a relying party needs to verify a portable
// evidence bundle with every IOI endpoint unavailable: the registered schemas and their invariants, the
// canonicalization and hashing rules, the trust-root and revocation input contract, the executable positive and
// negative vectors, the typed failure vocabulary, the version and downgrade rules, the clean-room verifier, and
// a statement of what a passing implementation may and may not claim. Its manifest lists every member with its
// digest and its own self-hash; its signature is verified against a key the CONSUMER pins and never against one
// the package carries — a package that authenticated itself would be authenticating nothing.
//
// WHY IT IS BUILT, NOT STORED. A tracked tarball drifts from the schemas it claims to publish and nobody
// re-derives it. The kit is assembled from the tracked sources on every run and its manifest digest is compared
// against a value pinned in a tracked evidence record, which is the estate's certificate posture (M12.9, M12.15):
// generated at run time, required to regenerate exactly the digest sealed on the day it was recorded.
//
// THE MEMBER LIST IS COMPUTED, NEVER HAND-WRITTEN. The verifier's members come from walking its import graph,
// so a kit cannot omit a file the verifier needs and still run, and cannot carry one it does not.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { builtinModules } from "node:module";

export const KIT_SCHEMA = "ioi.m06-11.public-verifier-kit.v1";
export const ENCODING_PROFILE_REF = "encoding-profile://ioi/jcs-json/v1";
const BUILTINS = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);
const IMPORT_RE = /(?:^|\n)\s*(?:import|export)[^;\n]*?from\s*["']([^"']+)["']|\bimport\s*\(\s*["']([^"']+)["']\s*\)/gu;

const sha256Bytes = (bytes) => `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
export const sha256File = (file) => sha256Bytes(fs.readFileSync(file));
export function stableStringifyKit(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringifyKit).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringifyKit(value[key])}`).join(",")}}`;
}
export const kitHash = (manifest) => {
  const copy = { ...manifest };
  delete copy.kit_hash;
  return sha256Bytes(stableStringifyKit(copy));
};

/**
 * The import closure of one entry module, following only relative specifiers. Returns the files in the closure
 * and every bare specifier it reached, so the caller can assert what the closure depends on rather than read it.
 */
export function importClosure(entryFile) {
  const files = [];
  const bare = new Set();
  const seen = new Set();
  const queue = [path.resolve(entryFile)];
  while (queue.length) {
    const file = queue.shift();
    if (seen.has(file)) continue;
    seen.add(file);
    files.push(file);
    const source = fs.readFileSync(file, "utf8");
    for (const match of source.matchAll(IMPORT_RE)) {
      const specifier = match[1] ?? match[2];
      if (!specifier) continue;
      if (specifier.startsWith(".")) { queue.push(path.resolve(path.dirname(file), specifier)); continue; }
      bare.add(specifier);
    }
  }
  return { files: files.sort(), bare: [...bare].sort() };
}

/**
 * Hermeticity, asserted as a property of the bytes rather than read off a comment: every bare specifier is a
 * `node:` builtin, no member escapes the kit with `../`, none names an absolute path, a loopback address or a
 * URL, and none imports the estate's own canonicalization or generated projections.
 */
export function hermeticityFindings(files) {
  const findings = [];
  for (const file of files) {
    const source = fs.readFileSync(file, "utf8");
    const name = path.basename(file);
    for (const match of source.matchAll(IMPORT_RE)) {
      const specifier = match[1] ?? match[2];
      if (!specifier) continue;
      if (specifier.startsWith("..")) findings.push(`escaping_import:${name}:${specifier}`);
      else if (specifier.startsWith("/")) findings.push(`absolute_import:${name}:${specifier}`);
      else if (!specifier.startsWith(".") && !BUILTINS.has(specifier)) findings.push(`third_party_import:${name}:${specifier}`);
    }
    // A kit member that named a host, a port or a repository path would be reaching out of the clean room even
    // if nothing in the closure imported it.
    // The forbidden reference is to an estate IMPLEMENTATION FILE, never to a published schema name: the
    // verifier must carry `ioi.hypervisor.c7-c8-certificate.v2` as a self-hash key, because that is what the
    // published contract calls the schema. Naming a `.mjs`, `.ts` or `.rs` of the canonical side is the defect.
    for (const [pattern, code] of [[/127\.0\.0\.1|localhost|0\.0\.0\.0/u, "loopback_literal"], [/https?:\/\//u, "url_literal"], [/\/home\/|\/Users\/|process\.cwd\(\)/u, "host_path_literal"], [/c7-c8-certificate\.mjs|c8-v3-portable-bundle\.mjs|c8-v3-bundle-reseal\.mjs|architecture-contracts\.(?:ts|mjs|rs)|aft-c8-verifier/u, "canonical_implementation_reference"]]) {
      // The verifier's own prose names the estate's helpers to say it does not use them; only CODE counts, so
      // comment lines are stripped before the scan.
      const code_only = source.split("\n").filter((line) => !/^\s*(\/\/|\*|\/\*)/u.test(line)).join("\n");
      if (pattern.test(code_only)) findings.push(`${code}:${name}`);
    }
  }
  return findings;
}

/**
 * Assemble the kit. `members` is the caller's declared content beyond the verifier's own closure: the schemas,
 * the invariants and the vectors, each as {kitPath, sourcePath}. Nothing is invented here — a member the caller
 * does not name is not in the kit, and a member whose source is missing is a refusal.
 */
export function assembleKit({ kitDir, verifierEntry, members, builtAt, failureVocabulary, versionRules, nonclaims }) {
  fs.mkdirSync(kitDir, { recursive: true });
  const closure = importClosure(verifierEntry);
  const placed = [];
  for (const file of closure.files) {
    const kitPath = path.basename(file);
    fs.copyFileSync(file, path.join(kitDir, kitPath));
    placed.push({ path: kitPath, role: file === path.resolve(verifierEntry) ? "verifier_entry" : "verifier_module" });
  }
  for (const member of members) {
    const target = path.join(kitDir, member.kitPath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    if (!fs.existsSync(member.sourcePath)) throw new Error(`kit member source missing: ${member.sourcePath}`);
    fs.copyFileSync(member.sourcePath, target);
    placed.push({ path: member.kitPath, role: member.role });
  }
  const manifest = {
    schema_version: KIT_SCHEMA,
    kit_ref: "verifier-kit://ioi/c8-portable-evidence/v1",
    built_at: builtAt,
    // The rule a consumer needs before it can hash anything, stated rather than implied.
    canonicalization: {
      encoding_profile_ref: ENCODING_PROFILE_REF,
      rule: "JSON with object members sorted by key as UTF-16 code units, no insignificant whitespace, ECMAScript shortest-round-trip numbers; a non-finite number is refused rather than serialized.",
      self_hash_rule: "An object whose schema declares a self-hash member is hashed with that member removed; a canonical-JSON preimage is hashed over its `canonical_json` string; a standing-authority envelope is hashed with its body hash removed and its domain constant added; a trajectory admission decision is hashed with its decision hash and decision ref removed.",
    },
    trust_inputs_contract: {
      rule: "The relying party provisions the acceptance policy and the verifier-independence profile BEFORE the producer assembles the bundle; both are carried as trust inputs and bound by hash. The policy names the trust roots, the audience, the accepted schemas, environment classes, honesty classes and verdicts, the maximum certificate age and whether a revocation input is required.",
      revocation: "A policy that requires a revocation check refuses a bundle carrying no revocation trust input; the check is over the published inputs and never a hosted lookup.",
      per_verifier_provision: "The policy names ONE verifier-independence profile and that profile carries ONE verifier build hash, which the verifier compares against its own bytes. A second implementation therefore needs its own provisioned profile and policy in the same bundle; it may not borrow the first's.",
    },
    failure_vocabulary: [...failureVocabulary].sort(),
    version_rules: versionRules,
    nonclaims: [...nonclaims],
    members: placed.map(({ path: kitPath, role }) => {
      const bytes = fs.readFileSync(path.join(kitDir, kitPath));
      return { path: kitPath, role, sha256: sha256Bytes(bytes), bytes: bytes.length };
    }).sort((a, b) => a.path.localeCompare(b.path)),
  };
  manifest.kit_hash = kitHash(manifest);
  fs.writeFileSync(path.join(kitDir, "kit.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return { manifest, closure };
}

export function signKit({ kitDir, privateKeyPem }) {
  const manifestBytes = fs.readFileSync(path.join(kitDir, "kit.json"));
  const signature = crypto.sign(null, Buffer.from(sha256Bytes(manifestBytes)), crypto.createPrivateKey(privateKeyPem));
  fs.writeFileSync(path.join(kitDir, "kit.sig"), `${signature.toString("base64")}\n`);
  return signature.toString("base64");
}

/**
 * Verify a kit the way a consumer must: against a PINNED public key it supplies, re-deriving every member's
 * digest from the bytes on disk and the manifest's own hash from the manifest. A kit that carried its own key
 * would be refused here — the parameter is the only way in.
 */
export function verifyKit({ kitDir, pinnedPublicKeyPem }) {
  const findings = [];
  if (!pinnedPublicKeyPem) return ["no_pinned_signer_public_key"];
  const manifestPath = path.join(kitDir, "kit.json");
  if (!fs.existsSync(manifestPath)) return ["kit_manifest_missing"];
  const manifestBytes = fs.readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  if (manifest.schema_version !== KIT_SCHEMA) findings.push("kit_schema_invalid");
  if (kitHash(manifest) !== manifest.kit_hash) findings.push("kit_hash_mismatch");
  const signaturePath = path.join(kitDir, "kit.sig");
  if (!fs.existsSync(signaturePath)) findings.push("kit_signature_missing");
  else {
    const signature = Buffer.from(fs.readFileSync(signaturePath, "utf8").trim(), "base64");
    let valid = false;
    try { valid = crypto.verify(null, Buffer.from(sha256Bytes(manifestBytes)), crypto.createPublicKey(pinnedPublicKeyPem), signature); } catch { valid = false; }
    if (!valid) findings.push("kit_signature_invalid");
  }
  for (const member of manifest.members ?? []) {
    const file = path.join(kitDir, member.path);
    if (!fs.existsSync(file)) { findings.push(`kit_member_missing:${member.path}`); continue; }
    if (sha256File(file) !== member.sha256) findings.push(`kit_member_digest_mismatch:${member.path}`);
  }
  const listed = new Set((manifest.members ?? []).map((m) => m.path));
  const walk = (dir, prefix = "") => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(path.join(dir, entry.name), rel);
      else if (!["kit.json", "kit.sig"].includes(rel) && !listed.has(rel)) findings.push(`kit_member_unlisted:${rel}`);
    }
  };
  walk(kitDir);
  if (!(manifest.nonclaims ?? []).length) findings.push("kit_nonclaims_missing");
  if (!(manifest.failure_vocabulary ?? []).length) findings.push("kit_failure_vocabulary_missing");
  if (manifest.canonicalization?.encoding_profile_ref !== ENCODING_PROFILE_REF) findings.push("kit_encoding_profile_missing");
  return findings;
}

/** A clean room is a directory with the kit in it and nothing else of ours: no repository, no dependencies. */
export function cleanRoomFindings(roomDir, repoRoot) {
  const findings = [];
  if (fs.existsSync(path.join(roomDir, ".git"))) findings.push("clean_room_has_git");
  if (fs.existsSync(path.join(roomDir, "node_modules"))) findings.push("clean_room_has_node_modules");
  if (fs.existsSync(path.join(roomDir, "package.json"))) findings.push("clean_room_has_package_json");
  const resolved = fs.realpathSync(roomDir);
  if (resolved.startsWith(`${fs.realpathSync(repoRoot)}${path.sep}`)) findings.push("clean_room_inside_the_repository");
  let cursor = resolved;
  while (cursor !== path.dirname(cursor)) {
    cursor = path.dirname(cursor);
    if (fs.existsSync(path.join(cursor, ".git")) || fs.existsSync(path.join(cursor, "node_modules"))) { findings.push(`clean_room_ancestor_carries:${cursor}`); break; }
  }
  return findings;
}
