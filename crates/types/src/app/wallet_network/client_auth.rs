use super::vault::VaultSurface;
use crate::app::SignatureSuite;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Root authority record for wallet.network control-plane mutations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WalletControlPlaneRootRecord {
    /// Account id allowed to bootstrap and govern the local vault control plane.
    pub account_id: [u8; 32],
    /// Signature suite associated with the root authority.
    pub signature_suite: SignatureSuite,
    /// Canonical public key bytes for auditing and replay-safe export/import.
    pub public_key: Vec<u8>,
    /// First registration timestamp.
    pub registered_at_ms: u64,
    /// Last update timestamp.
    pub updated_at_ms: u64,
    /// Optional metadata for migration / provenance labels.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// Client role authorized by wallet.network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum WalletClientRole {
    /// Control-plane client that may mutate connector auth, secrets, and policy.
    ControlPlaneAdmin,
    /// Capability client that may request bindings and spend leased capability.
    Capability,
}

/// Lifecycle state of a registered wallet client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum WalletClientState {
    /// Client is active and may be authorized for wallet calls.
    Active,
    /// Client is temporarily suspended.
    Suspended,
    /// Client has been revoked and must not be trusted.
    Revoked,
}

/// Durable client registration stored by wallet.network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WalletRegisteredClientRecord {
    /// Account id derived from the client's signing public key.
    pub client_id: [u8; 32],
    /// Human-readable label for audit and UX.
    pub label: String,
    /// Surface this client is allowed to represent.
    pub surface: VaultSurface,
    /// Signature suite used by this client.
    pub signature_suite: SignatureSuite,
    /// Canonical public key bytes for the client signer.
    pub public_key: Vec<u8>,
    /// Authorization tier granted to the client.
    pub role: WalletClientRole,
    /// Registration lifecycle state.
    pub state: WalletClientState,
    /// First registration timestamp.
    pub registered_at_ms: u64,
    /// Last update timestamp.
    pub updated_at_ms: u64,
    /// Optional expiry timestamp for the registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    /// Optional provider-family allowlist for connector operations.
    #[serde(default)]
    pub allowed_provider_families: Vec<String>,
    /// Free-form metadata.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// Root control-plane bootstrap/update request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WalletConfigureControlRootParams {
    /// Canonical root record to store.
    pub root: WalletControlPlaneRootRecord,
}

/// Insert or update a registered wallet client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WalletRegisterClientParams {
    /// Client record to insert or update.
    pub client: WalletRegisteredClientRecord,
}

/// Revoke or suspend a registered wallet client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WalletRevokeClientParams {
    /// Client id to revoke or suspend.
    pub client_id: [u8; 32],
    /// Optional operator-supplied reason.
    #[serde(default)]
    pub reason: String,
    /// Replacement state to apply.
    pub state: WalletClientState,
}

/// Fetch a single wallet client registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WalletGetClientParams {
    /// Stable request identifier for replay protection.
    pub request_id: [u8; 32],
    /// Client id to fetch.
    pub client_id: [u8; 32],
}

/// Receipt for wallet client lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WalletGetClientReceipt {
    /// Stable request identifier.
    pub request_id: [u8; 32],
    /// Lookup execution timestamp.
    pub fetched_at_ms: u64,
    /// Returned client record.
    pub client: WalletRegisteredClientRecord,
}

/// List registered wallet clients, optionally filtered by role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WalletListClientsParams {
    /// Stable request identifier for replay protection.
    pub request_id: [u8; 32],
    /// Optional role filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<WalletClientRole>,
}

/// Receipt for wallet client listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WalletListClientsReceipt {
    /// Stable request identifier.
    pub request_id: [u8; 32],
    /// Listing timestamp.
    pub listed_at_ms: u64,
    /// Returned clients.
    #[serde(default)]
    pub clients: Vec<WalletRegisteredClientRecord>,
}
