// Held-bar signer for the separate StandingApprovalGrant signature domain. Production signing
// belongs to wallet/device custody; this wrapper only invokes the real Rust type and Ed25519
// implementation so integration tests have no verification bypass.
import { spawnSync } from "node:child_process";
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
  const binary = path.join(repoRoot, "target", "debug", "mint-standing-approval-grant");
  if (!built) {
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
    built = true;
  }
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
