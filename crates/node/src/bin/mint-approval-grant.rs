//! Deterministic ApprovalGrant minter — a test/fixture stand-in for the wallet
//! approver (which, in production, is a separate signing device/process).
//!
//! Mints a fully-valid, REAL Ed25519-signed `ioi_types::app::ApprovalGrant`: a
//! deterministic keypair (from a seed), the `authority_id` derived from its public
//! key via `account_id_from_key_material`, non-zero binding hashes, and a real
//! signature over the canonical `signing_bytes()`. The grant therefore passes BOTH
//! the runtime approval-decision authority's structural `grant.verify()` AND the
//! settlement-layer cryptographic `verify_approval_grant_signature`. No test-only
//! bypass — the routes verify the grant exactly the way production does.
//!
//! Usage: `mint-approval-grant [--seed <hex32>] [--audience <hex32>]
//! [--expires-at <ms>] [--max-usages <count>]`. Prints the grant as a single line
//! of JSON on stdout.

use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use ioi_types::app::action::ApprovalGrant;
use ioi_types::app::{account_id_from_key_material, SignatureSuite};

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

/// Decode a 32-byte hash from a hex string (bare or `sha256:`-prefixed); defaults to a
/// repeated `default_byte` (e.g. the lease policy_hash form, or the legacy fixtures).
fn hash32(args: &[String], name: &str, default_byte: u8) -> [u8; 32] {
    let mut out = [default_byte; 32];
    if let Some(raw) = flag(args, name) {
        let hex_str = raw.trim().trim_start_matches("sha256:");
        let decoded = hex::decode(hex_str).expect("hash must be hex");
        assert_eq!(decoded.len(), 32, "{name} must be 32 bytes (64 hex chars)");
        out.copy_from_slice(&decoded);
    }
    out
}

fn exact_hex32(args: &[String], name: &str, default_byte: u8) -> [u8; 32] {
    let mut out = [default_byte; 32];
    if let Some(raw) = flag(args, name) {
        assert!(
            !raw.starts_with("sha256:"),
            "{name} must be bare 32-byte hex"
        );
        let decoded = hex::decode(raw.trim()).expect("value must be hex");
        assert_eq!(decoded.len(), 32, "{name} must be 32 bytes (64 hex chars)");
        out.copy_from_slice(&decoded);
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Deterministic 32-byte seed (defaults to the kernel test fixture's [7u8; 32]).
    let seed_hex = flag(&args, "--seed").unwrap_or_else(|| "07".repeat(32));
    let mut seed = [0u8; 32];
    let decoded = hex::decode(&seed_hex).expect("--seed must be hex");
    assert_eq!(decoded.len(), 32, "--seed must be 32 bytes (64 hex chars)");
    seed.copy_from_slice(&decoded);
    // expires_at in ms — far future by default so the grant is valid at settlement.
    let expires_at: u64 = flag(&args, "--expires-at")
        .unwrap_or_else(|| "1850000000000".to_string())
        .parse()
        .expect("--expires-at must be a u64 (ms)");
    let max_usages: u32 = flag(&args, "--max-usages")
        .unwrap_or_else(|| "1".to_string())
        .parse()
        .expect("--max-usages must be a u32");
    assert!(max_usages > 0, "--max-usages must be positive");

    let private_key = Ed25519PrivateKey::from_bytes(&seed).expect("private key from seed");
    let keypair = Ed25519KeyPair::from_private_key(&private_key).expect("keypair from private key");
    let public_key = keypair.public_key().to_bytes();
    let authority_id = account_id_from_key_material(SignatureSuite::ED25519, &public_key)
        .expect("derive authority_id from public key");

    let mut grant = ApprovalGrant {
        schema_version: 1,
        authority_id,
        // Bound at signing time by the wallet; the runtime decision authority compares
        // these to daemon-derived expected hashes (the request-time lease's policy_hash).
        request_hash: hash32(&args, "--request-hash", 1),
        policy_hash: hash32(&args, "--policy-hash", 2),
        // Preserve the historical fixture audience unless a real wallet capability client
        // is explicitly selected by the caller.
        audience: exact_hex32(&args, "--audience", 3),
        nonce: [4u8; 32],
        counter: 1,
        expires_at,
        max_usages: Some(max_usages),
        window_id: None,
        pii_action: None,
        scoped_exception: None,
        review_request_hash: None,
        approver_public_key: public_key,
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    };
    let signing_bytes = grant.signing_bytes().expect("canonical signing bytes");
    grant.approver_sig = keypair
        .sign(&signing_bytes)
        .expect("sign canonical payload")
        .to_bytes()
        .to_vec();

    // Sanity: the minted grant must pass the structural verify (the runtime gate).
    grant.verify().expect("minted grant must verify");

    println!(
        "{}",
        serde_json::to_string(&grant).expect("serialize grant")
    );
}

#[cfg(test)]
mod tests {
    use super::exact_hex32;

    #[test]
    fn audience_keeps_the_legacy_default_and_accepts_exact_hex() {
        assert_eq!(exact_hex32(&[], "--audience", 3), [3u8; 32]);
        let args = vec!["--audience".to_string(), "ab".repeat(32)];
        assert_eq!(exact_hex32(&args, "--audience", 3), [0xabu8; 32]);
    }

    #[test]
    #[should_panic(expected = "--audience must be bare 32-byte hex")]
    fn audience_refuses_hash_prefixed_input() {
        let args = vec![
            "--audience".to_string(),
            format!("sha256:{}", "ab".repeat(32)),
        ];
        let _ = exact_hex32(&args, "--audience", 3);
    }
}
