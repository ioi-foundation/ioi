// Path: crates/types/src/app/wallet_network/vault.rs

use crate::app::action::ActionTarget;
use crate::app::SignatureSuite;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Product surface where a wallet.network action was initiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum VaultSurface {
    /// Desktop control-plane surface.
    Desktop,
    /// Browser extension bridge surface.
    Extension,
    /// Mobile notifier/approver surface.
    Mobile,
}

/// Legacy wallet curve used for owner anchoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum OwnerWalletCurve {
    /// Legacy ECDSA curve used by Ethereum-style EOAs.
    Secp256k1,
    /// EdDSA curve used by modern wallets/keys.
    Ed25519,
}

/// Post-quantum suite used by the manager layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum VaultPqSuite {
    /// ML-DSA-44 (Dilithium class) signature suite.
    MlDsa44,
    /// ML-KEM-768 (Kyber class) key encapsulation suite.
    Kyber768,
}

/// External owner wallet anchor linked to a local Vault identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct OwnerAnchor {
    /// Network namespace (for example: "ethereum:mainnet").
    pub network: String,
    /// Owner address/public account identifier.
    pub address: String,
    /// Owner key curve.
    pub curve: OwnerWalletCurve,
    /// Signed message proving ownership linkage.
    pub link_signature: Vec<u8>,
    /// Signature suite used for the linkage proof.
    pub signature_suite: SignatureSuite,
    /// UNIX timestamp (ms) when linked.
    pub linked_at_ms: u64,
}

/// Hybrid identity representing the agency manager layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct VaultIdentity {
    /// Stable vault identity id.
    pub vault_id: [u8; 32],
    /// Anchored owner wallets.
    #[serde(default)]
    pub owner_anchors: Vec<OwnerAnchor>,
    /// PQ signature suite used for manager control messages.
    pub pq_signing_suite: VaultPqSuite,
    /// PQ KEM suite used for envelope encryption to trusted runtimes.
    pub pq_kem_suite: VaultPqSuite,
    /// PQ signing public key bytes.
    pub pq_signing_public_key: Vec<u8>,
    /// PQ KEM public key bytes.
    pub pq_kem_public_key: Vec<u8>,
    /// Created timestamp.
    pub created_at_ms: u64,
    /// Last updated timestamp.
    pub updated_at_ms: u64,
}

/// Secret category managed by the local vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// API key style bearer credential.
    ApiKey,
    /// User password credential.
    Password,
    /// Short-lived or refresh token credential.
    AccessToken,
    /// X.509 or similar certificate material.
    Certificate,
    /// Custom provider-specific secret category.
    Custom(String),
}

/// Encrypted secret record persisted by the Vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct VaultSecretRecord {
    /// Stable id for the secret.
    pub secret_id: String,
    /// Human-readable alias (for example: "openai", "twitter").
    pub alias: String,
    /// Secret class.
    pub kind: SecretKind,
    /// Ciphertext payload encrypted at rest.
    pub ciphertext: Vec<u8>,
    /// Optional metadata (region/owner/provider labels).
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Created timestamp.
    pub created_at_ms: u64,
    /// Optional rotated timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at_ms: Option<u64>,
}

/// Scoped policy rule authored by a human for autonomous execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct VaultPolicyRule {
    /// Stable rule identifier.
    pub rule_id: String,
    /// Human label for UI.
    pub label: String,
    /// Target capability affected by this rule.
    pub target: ActionTarget,
    /// Auto-approve if rule constraints are satisfied.
    pub auto_approve: bool,
    /// Optional value ceiling in micro-USD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_value_usd_micros: Option<u64>,
    /// Optional TTL for approval/session context in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_secs: Option<u64>,
    /// Optional allowlisted domains for network-capable actions.
    #[serde(default)]
    pub domain_allowlist: Vec<String>,
}
