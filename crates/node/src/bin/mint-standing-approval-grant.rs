//! Deterministic real-signature standing-grant minter for held-bar fixtures.
//!
//! Production authority is signed by the wallet/device plane. This binary exists only so the
//! real wallet.network fixture can exercise exactly the same closed type, signing bytes, and
//! cryptographic verification without a test-only bypass or exposing a signer to model code.

use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use ioi_types::app::action::StandingApprovalGrant;
use ioi_types::app::{account_id_from_key_material, SignatureSuite};

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn required_hash32(args: &[String], name: &str, allow_prefix: bool) -> [u8; 32] {
    let raw = flag(args, name).unwrap_or_else(|| panic!("{name} is required"));
    if !allow_prefix && raw.starts_with("sha256:") {
        panic!("{name} must be bare 32-byte hex");
    }
    let raw = raw.strip_prefix("sha256:").unwrap_or(&raw);
    assert_eq!(raw, raw.to_ascii_lowercase(), "{name} must be lowercase");
    let decoded = hex::decode(raw).unwrap_or_else(|_| panic!("{name} must be hexadecimal"));
    assert_eq!(decoded.len(), 32, "{name} must be 32 bytes");
    let mut output = [0u8; 32];
    output.copy_from_slice(&decoded);
    assert_ne!(output, [0u8; 32], "{name} must not be zero");
    output
}

fn required_u64(args: &[String], name: &str) -> u64 {
    flag(args, name)
        .unwrap_or_else(|| panic!("{name} is required"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} must be a u64"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let seed = required_hash32(&args, "--seed", false);
    let private_key = Ed25519PrivateKey::from_bytes(&seed).expect("private key from seed");
    let keypair = Ed25519KeyPair::from_private_key(&private_key).expect("keypair from private key");
    let public_key = keypair.public_key().to_bytes();
    let authority_id = account_id_from_key_material(SignatureSuite::ED25519, &public_key)
        .expect("derive authority id");
    let max_usages =
        u32::try_from(required_u64(&args, "--max-usages")).expect("--max-usages must be a u32");
    let mut grant = StandingApprovalGrant {
        schema_version: 1,
        authority_id,
        standing_envelope_hash: required_hash32(&args, "--standing-envelope-hash", true),
        policy_hash: required_hash32(&args, "--policy-hash", true),
        audience: required_hash32(&args, "--audience", false),
        nonce: required_hash32(&args, "--nonce", false),
        counter: required_u64(&args, "--counter"),
        issued_at_ms: required_u64(&args, "--issued-at-ms"),
        expires_at_ms: required_u64(&args, "--expires-at-ms"),
        max_usages,
        max_cumulative_deposit_microusd: required_u64(&args, "--max-cumulative-deposit-microusd"),
        max_cumulative_spend_microusd: required_u64(&args, "--max-cumulative-spend-microusd"),
        review_receipt_hash: required_hash32(&args, "--review-receipt-hash", true),
        approval_ceremony_context_hash: required_hash32(
            &args,
            "--approval-ceremony-context-hash",
            true,
        ),
        auth_factor_receipt_hash: required_hash32(&args, "--auth-factor-receipt-hash", true),
        approver_public_key: public_key,
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    };
    grant.approver_sig = keypair
        .sign(&grant.signing_bytes().expect("canonical signing bytes"))
        .expect("sign standing grant")
        .to_bytes()
        .to_vec();
    grant.verify().expect("minted standing grant must verify");
    println!(
        "{}",
        serde_json::to_string(&grant).expect("serialize standing grant")
    );
}

#[cfg(test)]
mod tests {
    use super::required_hash32;

    #[test]
    #[should_panic(expected = "--audience must be bare 32-byte hex")]
    fn audience_refuses_prefixed_hash() {
        let args = vec![
            "--audience".to_string(),
            format!("sha256:{}", "ab".repeat(32)),
        ];
        let _ = required_hash32(&args, "--audience", false);
    }
}
