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
