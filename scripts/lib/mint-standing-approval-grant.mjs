// Held-bar signer for the separate StandingApprovalGrant signature domain. Production signing
// belongs to wallet/device custody; this wrapper only invokes the real Rust type and Ed25519
// implementation so integration tests have no verification bypass.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
let built = false;

const required = (value, label) => {
  if (value === undefined || value === null || String(value).length === 0) {
    throw new Error(`${label} is required`);
  }
  return String(value);
};

export function mintStandingApprovalGrant(options = {}) {
  // A packaged release ships the signer at bin/mint-standing-approval-grant outside any cargo
  // target dir, exactly as it ships bin/mint-approval-grant; the installed prefix names it here.
  // Until 2026-09-10 this signer had no such override, so R-14's deployment attach pass — which
  // landed AFTER the package-mode qualification — fell back to `cargo build` on a no-checkout host
  // where cargo is deliberately unreachable, and step 5c failed with "Failed to build". An env
  // that names an ABSENT binary is refused rather than silently rebuilt: a package must carry
  // what it claims to carry.
  const binary = process.env.IOI_MINT_STANDING_APPROVAL_GRANT_BINARY
    || path.join(repoRoot, "target", "debug", "mint-standing-approval-grant");
  if (!built && !existsSync(binary)) {
    if (process.env.IOI_MINT_STANDING_APPROVAL_GRANT_BINARY) {
      throw new Error(`IOI_MINT_STANDING_APPROVAL_GRANT_BINARY names an absent signer: ${binary}`);
    }
    const build = spawnSync(
      "cargo",
      ["build", "-p", "ioi-node", "--bin", "mint-standing-approval-grant"],
      { cwd: repoRoot, encoding: "utf8" },
    );
    if (build.status !== 0) {
      throw new Error(
        `Failed to build mint-standing-approval-grant:\n${build.stdout}\n${build.stderr}`,
      );
    }
  }
  built = true;
  const fields = [
    ["--seed", "seed"],
    ["--standing-envelope-hash", "standingEnvelopeHash"],
    ["--policy-hash", "policyHash"],
    ["--audience", "audience"],
    ["--nonce", "nonce"],
    ["--counter", "counter"],
    ["--issued-at-ms", "issuedAtMs"],
    ["--expires-at-ms", "expiresAtMs"],
    ["--max-usages", "maxUsages"],
    ["--max-cumulative-deposit-microusd", "maxCumulativeDepositMicrousd"],
    ["--max-cumulative-spend-microusd", "maxCumulativeSpendMicrousd"],
    ["--review-receipt-hash", "reviewReceiptHash"],
    ["--approval-ceremony-context-hash", "approvalCeremonyContextHash"],
    ["--auth-factor-receipt-hash", "authFactorReceiptHash"],
  ];
  const args = fields.flatMap(([flag, field]) => [flag, required(options[field], field)]);
  const result = spawnSync(binary, args, { cwd: repoRoot, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(
      `mint-standing-approval-grant failed:\n${result.stdout}\n${result.stderr}`,
    );
  }
  return JSON.parse(result.stdout.trim());
}
