// Test/fixture wallet signer: mints a real dcrypt-signed ApprovalGrant via the Rust
// `mint-approval-grant` bin (deterministic Ed25519 key + authority_id derived from the
// pubkey + a real signature over the canonical signing_bytes). The grant passes the
// runtime approval-decision authority's structural verify AND the settlement layer's
// cryptographic verify_approval_grant_signature — no test-only bypass.
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
let built = false;

export function mintApprovalGrant(options = {}) {
  const binary = path.join(repoRoot, "target", "debug", "mint-approval-grant");
  if (!built) {
    const build = spawnSync(
      "cargo",
      ["build", "-p", "ioi-node", "--bin", "mint-approval-grant"],
      { cwd: repoRoot, encoding: "utf8" },
    );
    if (build.status !== 0) {
      throw new Error(`Failed to build mint-approval-grant:\n${build.stdout}\n${build.stderr}`);
    }
    built = true;
  }
  const args = [];
  if (options.seed) args.push("--seed", options.seed);
  if (options.expiresAt) args.push("--expires-at", String(options.expiresAt));
  // policyHash / requestHash may be bare hex or "sha256:<hex>" (the lease form).
  if (options.policyHash) args.push("--policy-hash", options.policyHash);
  if (options.requestHash) args.push("--request-hash", options.requestHash);
  if (options.audience) args.push("--audience", options.audience);
  const result = spawnSync(binary, args, { cwd: repoRoot, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`mint-approval-grant failed:\n${result.stdout}\n${result.stderr}`);
  }
  return JSON.parse(result.stdout.trim());
}
