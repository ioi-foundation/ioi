// Path: crates/services/src/wallet_network/mod.rs

use async_trait::async_trait;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::{
    MailConnectorGetParams, MailConnectorUpsertParams, MailDeleteSpamParams, MailListRecentParams,
    MailReadLatestParams, MailReplyParams, MailboxTotalCountParams, OwnerAnchor,
    SecretInjectionGrant, SecretInjectionRequestRecord, SessionChannelClose,
    SessionChannelDelegationRules, SessionChannelOpenAck, SessionChannelOpenConfirm,
    SessionChannelOpenInit, SessionChannelOpenTry, SessionChannelOrdering, SessionGrant,
    SessionLease, SessionLeaseMode, SessionReceiptCommit, SessionReceiptCommitDirection,
    VaultIdentity, VaultPolicyRule, VaultSecretRecord, WalletApprovalDecision,
    WalletInterceptionContext,
};
use ioi_types::app::ActionTarget;
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::BTreeSet;

mod handlers;
mod keys;
pub(crate) mod mail_ontology;
mod mail_transport;
mod support;
mod validation;

#[cfg(test)]
mod tests;

/// Parameters for issuing a session grant, optionally as a narrowed sub-grant.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct IssueSessionGrantParams {
    pub grant: SessionGrant,
    #[serde(default)]
    pub parent_session_id: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_rules: Option<SessionChannelDelegationRules>,
}

/// Parameters for emergency revocation epoch bump.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Encode, Decode)]
pub struct BumpRevocationEpochParams {
    #[serde(default)]
    pub reason: String,
}

/// Parameters for consuming an issued approval token in a one-shot/lease-safe way.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct ConsumeApprovalTokenParams {
    /// Approved request hash to consume.
    pub request_hash: [u8; 32],
    /// Optional explicit consume timestamp in ms; if 0, block timestamp is used.
    #[serde(default)]
    pub consumed_at_ms: u64,
}

/// Mutable approval-token usage state tracked by wallet_network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ApprovalConsumptionState {
    pub request_hash: [u8; 32],
    pub target: ActionTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_audience: Option<[u8; 32]>,
    pub issued_revocation_epoch: u64,
    #[serde(default)]
    pub token_nonce: [u8; 32],
    #[serde(default)]
    pub token_counter: u64,
    pub expires_at_ms: u64,
    pub max_usages: u32,
    pub uses_consumed: u32,
    pub remaining_usages: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_consumed_at_ms: Option<u64>,
}

/// Mutable lease usage/replay state for connector capability operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct LeaseConsumptionState {
    pub channel_id: [u8; 32],
    pub lease_id: [u8; 32],
    pub mode: SessionLeaseMode,
    pub audience: [u8; 32],
    pub revocation_epoch: u64,
    pub expires_at_ms: u64,
    pub consumed_count: u32,
    #[serde(default)]
    pub consumed_operation_ids: Vec<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_consumed_at_ms: Option<u64>,
}

/// Mutable delegation-control state for recursive sub-grant issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionDelegationState {
    /// Session/grant id this state is attached to.
    pub session_id: [u8; 32],
    /// Root ancestor session id.
    pub root_session_id: [u8; 32],
    /// Current depth where root=0.
    pub depth: u8,
    /// Max allowed depth across this branch.
    pub max_depth: u8,
    /// Whether this node can delegate further.
    pub can_redelegate: bool,
    /// Remaining issuance budget for descendants (None = unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_issuance_budget: Option<u32>,
    /// Number of direct children issued from this node.
    pub children_issued: u32,
}

/// Per-issuer replay guard for lease issuance counters/nonces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct LeaseReplayState {
    pub channel_id: [u8; 32],
    pub issuer_id: [u8; 32],
    pub last_counter: u64,
    #[serde(default)]
    pub seen_nonces: Vec<[u8; 32]>,
}

/// Replay window tracker for lease issuance counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct LeaseCounterReplayWindowState {
    pub channel_id: [u8; 32],
    pub issuer_id: [u8; 32],
    pub ordering: SessionChannelOrdering,
    pub highest_counter: u64,
    #[serde(default)]
    pub seen_counters: BTreeSet<u64>,
}

/// Replay window tracker for connector action sequences under a lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct LeaseActionReplayWindowState {
    pub channel_id: [u8; 32],
    pub lease_id: [u8; 32],
    pub ordering: SessionChannelOrdering,
    pub highest_seq: u64,
    #[serde(default)]
    pub seen_seqs: BTreeSet<u64>,
    #[serde(default)]
    pub seen_nonces: Vec<[u8; 32]>,
}

/// Replay window tracker for receipt sequence commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ReceiptReplayWindowState {
    pub channel_id: [u8; 32],
    pub direction: SessionReceiptCommitDirection,
    pub ordering: SessionChannelOrdering,
    pub highest_end_seq: u64,
    #[serde(default)]
    pub seen_end_seqs: BTreeSet<u64>,
}

/// Native wallet.network control-plane service.
#[derive(Debug, Default, Clone)]
pub struct WalletNetworkService;

#[async_trait]
impl UpgradableService for WalletNetworkService {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }

    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[async_trait]
impl BlockchainService for WalletNetworkService {
    fn id(&self) -> &str {
        "wallet_network"
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &str {
        "v1"
    }

    fn capabilities(&self) -> ioi_types::service_configs::Capabilities {
        ioi_types::service_configs::Capabilities::empty()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "create_identity@v1" => {
                let identity: VaultIdentity = codec::from_bytes_canonical(params)?;
                handlers::identity::create_identity(state, ctx, identity)
            }
            "link_owner@v1" => {
                let owner: OwnerAnchor = codec::from_bytes_canonical(params)?;
                handlers::identity::link_owner(state, ctx, owner)
            }
            "store_secret_record@v1" => {
                let secret: VaultSecretRecord = codec::from_bytes_canonical(params)?;
                handlers::identity::store_secret_record(state, ctx, secret)
            }
            "upsert_policy_rule@v1" => {
                let policy: VaultPolicyRule = codec::from_bytes_canonical(params)?;
                handlers::identity::upsert_policy_rule(state, ctx, policy)
            }
            "open_channel_init@v1" => {
                let open: SessionChannelOpenInit = codec::from_bytes_canonical(params)?;
                handlers::channel::open_channel_init(state, ctx, open)
            }
            "open_channel_try@v1" => {
                let open_try: SessionChannelOpenTry = codec::from_bytes_canonical(params)?;
                handlers::channel::open_channel_try(state, ctx, open_try)
            }
            "open_channel_ack@v1" => {
                let open_ack: SessionChannelOpenAck = codec::from_bytes_canonical(params)?;
                handlers::channel::open_channel_ack(state, ctx, open_ack)
            }
            "open_channel_confirm@v1" => {
                let open_confirm: SessionChannelOpenConfirm = codec::from_bytes_canonical(params)?;
                handlers::channel::open_channel_confirm(state, ctx, open_confirm)
            }
            "close_channel@v1" => {
                let close: SessionChannelClose = codec::from_bytes_canonical(params)?;
                handlers::channel::close_channel(state, ctx, close)
            }
            "issue_session_grant@v1" => {
                let params: IssueSessionGrantParams = codec::from_bytes_canonical(params)?;
                handlers::session::issue_session_grant(state, ctx, params)
            }
            "issue_session_lease@v1" => {
                let lease: SessionLease = codec::from_bytes_canonical(params)?;
                handlers::session::issue_session_lease(state, ctx, lease)
            }
            "mail_connector_upsert@v1" => {
                let request: MailConnectorUpsertParams = codec::from_bytes_canonical(params)?;
                handlers::connectors::mail_connector_upsert(state, ctx, request)
            }
            "mail_connector_get@v1" => {
                let request: MailConnectorGetParams = codec::from_bytes_canonical(params)?;
                handlers::connectors::mail_connector_get(state, ctx, request)
            }
            "mail_read_latest@v1" => {
                let request: MailReadLatestParams = codec::from_bytes_canonical(params)?;
                handlers::connectors::mail_read_latest(state, ctx, request)
            }
            "mail_list_recent@v1" => {
                let request: MailListRecentParams = codec::from_bytes_canonical(params)?;
                handlers::connectors::mail_list_recent(state, ctx, request)
            }
            "mailbox_total_count@v1" => {
                let request: MailboxTotalCountParams = codec::from_bytes_canonical(params)?;
                handlers::connectors::mailbox_total_count(state, ctx, request)
            }
            "mail_delete_spam@v1" => {
                let request: MailDeleteSpamParams = codec::from_bytes_canonical(params)?;
                handlers::connectors::mail_delete_spam(state, ctx, request)
            }
            "mail_reply@v1" => {
                let request: MailReplyParams = codec::from_bytes_canonical(params)?;
                handlers::connectors::mail_reply(state, ctx, request)
            }
            "commit_receipt_root@v1" => {
                let receipt_commit: SessionReceiptCommit = codec::from_bytes_canonical(params)?;
                handlers::channel::commit_receipt_root(state, ctx, receipt_commit)
            }
            "record_secret_injection_request@v1" => {
                let record: SecretInjectionRequestRecord = codec::from_bytes_canonical(params)?;
                handlers::secrets::record_secret_injection_request(state, ctx, record)
            }
            "grant_secret_injection@v1" => {
                let grant: SecretInjectionGrant = codec::from_bytes_canonical(params)?;
                handlers::secrets::grant_secret_injection(state, ctx, grant)
            }
            "record_interception@v1" => {
                let interception: WalletInterceptionContext = codec::from_bytes_canonical(params)?;
                handlers::approval::record_interception(state, ctx, interception)
            }
            "record_approval@v1" => {
                let approval: WalletApprovalDecision = codec::from_bytes_canonical(params)?;
                handlers::approval::record_approval(state, ctx, approval)
            }
            "consume_approval_token@v1" => {
                let consume: ConsumeApprovalTokenParams = codec::from_bytes_canonical(params)?;
                handlers::approval::consume_approval_token(state, ctx, consume)
            }
            "panic_stop@v1" => {
                let params: BumpRevocationEpochParams = codec::from_bytes_canonical(params)?;
                handlers::approval::panic_stop(state, ctx, params)
            }
            _ => Err(TransactionError::Unsupported(format!(
                "wallet_network does not support method '{}'",
                method
            ))),
        }
    }
}
