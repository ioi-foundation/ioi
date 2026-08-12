// verifier-census — the RUNTIME assertion census a verifier emits about its own completed run.
//
// Why this exists: the verifier family had no floor. Deleting assertions from a verifier left CI
// green, because a verifier that asserts less still passes. `check:verifier-floors` closes that
// hole, and this module is the evidence it consumes.
//
// The count is RUNTIME, not source. A commented-out `ok(...)`, an assertion inside a branch that
// never executed, and an assertion deleted outright are indistinguishable to this census — all
// three simply do not appear in `results`, and all three are exactly what the floor must catch.
// A grep of the source would count the commented-out one.
//
// The census binds the verifier's own source digest. A census emitted by one revision cannot
// certify another: `check:verifier-floors` recomputes the digest from the file on disk and refuses
// any artifact whose digest disagrees. That is what makes a stale artifact fail closed instead of
// silently certifying an edited verifier.
//
// Emission is opt-in via IOI_VERIFIER_CENSUS_DIR so ordinary local runs stay unchanged. A missing
// artifact is never "skip" at the gate — it is RED. A verifier that crashes, exits early, or is
// BLOCKED emits nothing, and the gate reports the absence rather than passing over it.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

/**
 * Write this run's assertion census, if IOI_VERIFIER_CENSUS_DIR is set.
 *
 * @param {object} args
 * @param {string} args.verifierId  stable id, matching the row in verifier-floors.v1.json
 * @param {string} args.sourceUrl   the verifier's own import.meta.url
 * @param {Array<{name: string, pass: boolean}>} args.results  the executed assertion records
 * @returns {string|null} the artifact path written, or null when census emission is off
 */
export function emitVerifierCensus({ verifierId, sourceUrl, results }) {
  const configured = process.env.IOI_VERIFIER_CENSUS_DIR;
  if (!configured) return null;

  if (!verifierId || typeof verifierId !== "string") {
    throw new Error("emitVerifierCensus: verifierId is required");
  }
  if (!Array.isArray(results)) {
    throw new Error(`emitVerifierCensus(${verifierId}): results must be the executed assertion array`);
  }

  const sourcePath = fileURLToPath(sourceUrl);
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
  const sourceBytes = fs.readFileSync(sourcePath);

  // A relative census dir resolves against the REPO ROOT, never the verifier's cwd. npm runs these
  // with cwd=apps/hypervisor while the gate reads from the root, so a cwd-relative path silently
  // split the emitter and the reader into two directories — artifacts written where nothing looks.
  const dir = path.isAbsolute(configured) ? configured : path.resolve(repoRoot, configured);

  // The assertion-name digest travels with the count so a reviewer can tell "10 assertions were
  // replaced" from "10 assertions were renamed": the count holds and the digest moves.
  const names = results.map((r) => String(r?.name ?? ""));
  const census = {
    census_version: "ioi.verifier-census.v1",
    verifier_id: verifierId,
    source_path: path.relative(repoRoot, sourcePath).split(path.sep).join("/"),
    source_sha256: sha256(sourceBytes),
    executed_assertions: results.length,
    passed: results.filter((r) => r?.pass).length,
    failed: results.filter((r) => !r?.pass).length,
    assertion_names_sha256: sha256(names.join("\n")),
  };

  fs.mkdirSync(dir, { recursive: true });
  const out = path.join(dir, `${verifierId}.json`);
  fs.writeFileSync(out, `${JSON.stringify(census, null, 2)}\n`);
  return out;
}
