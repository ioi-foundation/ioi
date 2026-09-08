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
  return mintApprovalGrant({ seed, policyHash, requestHash, audience });
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
