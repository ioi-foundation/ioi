// The ONE wallet-authority seam for the serve (#67 mandatory authority preflight).
//
// The fixture signer (repo scripts/lib/mint-approval-grant.mjs — a deterministic PUBLIC-seed
// Ed25519 test wallet) is test/fixture-only: production serve/module code must never import or
// invoke it. This adapter is the only place the serve touches wallet grants:
//
//   - PRODUCTION (no flag): mintTestGrant() returns null — a lane needing a grant parks in the
//     honest `awaiting_wallet_authority` state and surfaces the daemon's challenge verbatim so an
//     EXTERNAL wallet holder can sign it. The governed Build workflow's paste handoff
//     (challenge out → opaque signed grant back, held in memory only for the one forward POST)
//     is the production transport.
//   - DEV/TEST (IOI_WALLET_TEST_SIGNER=1): mintTestGrant() dynamically imports the fixture signer
//     and mints against the given challenge hashes — the explicit verifier/dev flag the mandate
//     allows. The import happens ONLY inside the flag check; no static edge to the signer exists.
export const TEST_SIGNER_FLAG = "IOI_WALLET_TEST_SIGNER";

export function testSignerEnabled() {
  return process.env[TEST_SIGNER_FLAG] === "1";
}

// Returns a signed grant under the test flag, null when no signer is attached (production).
// Throws only for a REAL mint failure under the flag — callers distinguish "no signer" (park
// awaiting authority) from "signer broke" (a 5xx-class fault).
export async function mintTestGrant({ policyHash, requestHash }) {
  if (!testSignerEnabled()) return null;
  const { mintApprovalGrant } = await import("../../../../scripts/lib/mint-approval-grant.mjs");
  return mintApprovalGrant({ policyHash, requestHash });
}

// ---- The deployment-local approver (ADR 0052; the bounded-alpha single-operator profile) ------
//
// The alpha profile's authority is a deployment-local wallet.network node whose approval key the
// OPERATOR holds. IOI_HYPERVISOR_LOCAL_APPROVER_KEY_PATH names that key: a file the operator
// custodies (32-byte seed as 64 hex chars, or the raw 32 bytes), readable only by the serve's
// user. Unlike the test signer, this key NEVER signs automatically: a lane that needs a grant
// parks in `awaiting_operator_approval` with the exact effect, and only an explicit operator
// approval action (the Sessions surface / the approve endpoint, under the operator's own session)
// calls mintLocalApproverGrant for that one challenge. Deny mints nothing. The daemon still
// resolves the deployment authority independently and refuses a grant from any other signer.
export const LOCAL_APPROVER_KEY_PATH = "IOI_HYPERVISOR_LOCAL_APPROVER_KEY_PATH";

export function localApproverEnabled() {
  return typeof process.env[LOCAL_APPROVER_KEY_PATH] === "string" && process.env[LOCAL_APPROVER_KEY_PATH].length > 0;
}

async function readLocalApproverSeedHex() {
  const keyPath = process.env[LOCAL_APPROVER_KEY_PATH];
  const { readFileSync, statSync } = await import("node:fs");
  const stat = statSync(keyPath);
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(`local approver key ${keyPath} is readable by group/other (mode ${(stat.mode & 0o777).toString(8)}); refusing to sign with a shared key`);
  }
  const raw = readFileSync(keyPath);
  const text = raw.toString("utf8").trim();
  if (/^[0-9a-fA-F]{64}$/u.test(text)) return text.toLowerCase();
  if (raw.length === 32) return raw.toString("hex");
  throw new Error(`local approver key ${keyPath} is neither 64 hex characters nor 32 raw bytes`);
}

// Mint ONE grant for ONE exact challenge with the deployment-held approver key. Only an operator
// approval action may call this; nothing else in the serve imports it.
export async function mintLocalApproverGrant({ policyHash, requestHash, audience }) {
  if (!localApproverEnabled()) return null;
  if (!policyHash || !requestHash) throw new Error("local approver refuses to sign without both policy_hash and request_hash");
  // The grant's audience is the daemon's wallet capability account, carried on the challenge the
  // run parked on. wallet.network consumes a grant only when its audience is the consuming signer,
  // so a grant without it can never be consumed; refuse to mint a dead grant.
  if (!/^[0-9a-f]{64}$/u.test(String(audience || ""))) {
    throw new Error("local approver refuses to sign without the daemon's capability audience (the challenge carried none — is the daemon's wallet client configured?)");
  }
  const seed = await readLocalApproverSeedHex();
  const { mintApprovalGrant } = await import("../../../../scripts/lib/mint-approval-grant.mjs");
  // Exactly one use: the grant authorizes THIS challenge once and can never be replayed.
  return mintApprovalGrant({ seed, policyHash, requestHash, audience, maxUsages: 1 });
}

// The operator's approval is ALSO an act against the deployment's authority node: the one-use
// grant is recorded on wallet.network as the approval decision for the challenge's scope. Two
// recorders exist, both the estate's own protocols: the deployment node's control binary
// (IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR names the node; the binary transacts from the daemon's
// capability account under the daemon's transaction lock) and the cargo test fixture's command
// directory (IOI_HYPERVISOR_WALLET_FIXTURE_COMMANDS_DIR, qualification only). Neither configured
// → the approval refuses, because an unrecorded grant can never be consumed.
export const LOCAL_AUTHORITY_STATE_DIR = "IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR";
export const FIXTURE_COMMANDS_DIR = "IOI_HYPERVISOR_WALLET_FIXTURE_COMMANDS_DIR";

export async function recordLocalApproverGrant({ grant, targetScope }) {
  if (!grant || !targetScope) throw new Error("approval recording needs the grant and the challenge's target scope");
  const stateDir = process.env[LOCAL_AUTHORITY_STATE_DIR];
  if (stateDir) {
    const { spawnSync } = await import("node:child_process");
    const { readFileSync, existsSync, mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
    const path = await import("node:path");
    const os = await import("node:os");
    const binary = process.env.IOI_WALLET_AUTHORITY_BINARY || path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../../../target/debug/wallet-network-local-authority");
    if (!existsSync(binary)) throw new Error(`authority control binary is absent at ${binary}`);
    const passFile = path.join(stateDir, "keys", "guardian.pass");
    const env = { ...process.env, ...(process.env.IOI_GUARDIAN_KEY_PASS ? {} : existsSync(passFile) ? { IOI_GUARDIAN_KEY_PASS: readFileSync(passFile, "utf8").trim() } : {}) };
    const tmp = mkdtempSync(path.join(os.tmpdir(), "ioi-approval-"));
    const grantFile = path.join(tmp, "grant.json");
    try {
      writeFileSync(grantFile, JSON.stringify(grant), { mode: 0o600 });
      const result = spawnSync(binary, ["record-approval", "--state-dir", stateDir, "--grant-file", grantFile, "--target-scope", targetScope], { encoding: "utf8", env });
      if (result.status !== 0) throw new Error(`record-approval failed: ${(result.stderr || result.stdout || "").trim().slice(-400)}`);
      const line = (result.stdout || "").trim().split("\n").reverse().find((l) => l.startsWith("{"));
      return { recorder: "deployment-node", ...(line ? JSON.parse(line) : {}) };
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }
  const commandsDir = process.env[FIXTURE_COMMANDS_DIR];
  if (commandsDir) {
    const { mkdirSync, writeFileSync, renameSync, existsSync, readFileSync, rmSync } = await import("node:fs");
    const { randomUUID } = await import("node:crypto");
    const path = await import("node:path");
    const principalRef = process.env.IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF || "";
    if (!principalRef) throw new Error("fixture recording needs IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF");
    const commandId = randomUUID();
    const dir = path.join(commandsDir, commandId);
    mkdirSync(dir, { mode: 0o700 });
    const hex = (v) => String(v || "").replace(/^sha256:/u, "");
    const payload = { schema_version: 1, operation: "record_approval", principal_ref: principalRef, policy_hash: hex(grant.policy_hash_hex || Buffer.from(grant.policy_hash || []).toString("hex")), request_hash: hex(grant.request_hash_hex || Buffer.from(grant.request_hash || []).toString("hex")), approval_grant: grant, target_scope: targetScope };
    writeFileSync(path.join(dir, "request.json.tmp"), JSON.stringify(payload), { mode: 0o600 });
    renameSync(path.join(dir, "request.json.tmp"), path.join(dir, "request.json"));
    const responsePath = path.join(dir, "response.json");
    const deadline = Date.now() + 900_000;
    while (!existsSync(responsePath)) {
      if (Date.now() > deadline) throw new Error("fixture record_approval timed out");
      await new Promise((r) => setTimeout(r, 50));
    }
    const response = JSON.parse(readFileSync(responsePath, "utf8"));
    rmSync(dir, { recursive: true, force: true });
    if (!response.ok) throw new Error(`fixture record_approval refused: ${response.error || "unknown"}`);
    return { recorder: "fixture", request_hash: response.request_hash };
  }
  throw new Error("no approval recorder is configured (set IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR to the deployment authority node); an unrecorded grant can never be consumed");
}

// The typed parked state when the deployment-local approver holds the key: the run waits for the
// operator's explicit decision on the exact effect. Hashes are public commitments, never secrets.
export function awaitingOperatorApproval(approval) {
  return {
    ok: false,
    status: "awaiting_operator_approval",
    error: {
      code: "operator_approval_required",
      message: "this crossing needs the operator's approval of the exact effect — review it on Work / Sessions and approve or deny",
    },
    approval: approval || null,
  };
}

// The typed parked state for lanes that need a grant and have no signer: the challenge rides
// verbatim (hashes only name WHAT to sign — they are public commitments, never secrets).
export function awaitingWalletAuthority(approval) {
  return {
    ok: false,
    status: "awaiting_wallet_authority",
    error: {
      code: "wallet_authority_required",
      message: "this crossing requires an externally signed wallet grant — no signer is attached to the serve (the dev test signer mounts only under IOI_WALLET_TEST_SIGNER=1)",
    },
    approval: approval || null,
  };
}
