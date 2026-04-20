use super::super::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::pii_substrate;
use crate::wallet_network::mail_ontology::{
    parse_confidence_band, parse_volume_band, spam_confidence_band, MAIL_ONTOLOGY_SIGNAL_VERSION,
    SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
};
use crate::wallet_network::LeaseActionReplayWindowState;
use ioi_api::state::{service_namespace_prefix, NamespacedStateAccess, StateAccess};
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{InferenceOptions, PiiClass};
use ioi_types::app::wallet_network::{
    MailConnectorEnsureBindingParams, MailConnectorRecord, MailDeleteSpamParams,
    MailDeleteSpamReceipt, MailListRecentParams, MailListRecentReceipt, MailReadLatestParams,
    MailReadLatestReceipt, MailReplyParams, MailReplyReceipt, SessionChannelRecord,
    SessionChannelState, SessionLease,
};
use ioi_types::app::{ExecutionContractReceiptEvent, KernelEvent};
use ioi_types::codec;
use ioi_types::error::{TransactionError, VmError};
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::ActiveServiceMeta;
use lettre::message::Mailbox;
use serde::Deserialize;
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

include!("wallet_mail/mail_binding.rs");

const CHANNEL_PREFIX: &[u8] = b"channel::";
const LEASE_PREFIX: &[u8] = b"lease::";
const LEASE_ACTION_WINDOW_PREFIX: &[u8] = b"lease_action_window::";
const MAIL_CONNECTOR_PREFIX: &[u8] = b"mail_connector::";
const MAIL_READ_RECEIPT_PREFIX: &[u8] = b"mail_read_receipt::";
const MAIL_LIST_RECEIPT_PREFIX: &[u8] = b"mail_list_receipt::";
const MAIL_DELETE_RECEIPT_PREFIX: &[u8] = b"mail_delete_receipt::";
const MAIL_REPLY_RECEIPT_PREFIX: &[u8] = b"mail_reply_receipt::";
const WALLET_SERVICE_ID: &str = "wallet_network";
const MAIL_CONNECTOR_ENSURE_BINDING_METHOD: &str = "mail_connector_ensure_binding@v1";
const CEC_CONTRACT_VERSION: &str = "cec.v0.4";
const MAIL_REPLY_SYNTHESIS_MAX_ATTEMPTS: usize = 3;

const MAIL_READ_CAPABILITY_ALIASES: &[&str] =
    &["mail.read.latest", "mail:read", "mail.read", "email:read"];
const MAIL_LIST_CAPABILITY_ALIASES: &[&str] = &[
    "mail.list.recent",
    "mail:list",
    "mail.list",
    "email:list",
    "mail.read.latest",
    "mail:read",
    "mail.read",
    "email:read",
];
const MAIL_DELETE_CAPABILITY_ALIASES: &[&str] = &[
    "mail.delete.spam",
    "mail.delete",
    "mail.write",
    "mail:write",
    "email:write",
    "mail.modify",
    "email:modify",
];
const MAIL_REPLY_CAPABILITY_ALIASES: &[&str] = &[
    "mail.reply",
    "mail.send",
    "mail.write",
    "mail:write",
    "email:write",
    "mail.compose",
    "email:compose",
    "mail.modify",
    "email:modify",
];
const MAIL_REPLY_SYNTHESIS_MODEL_ID: &str = "mail_reply_synthesis.v1";

include!("wallet_mail/draft_synthesis.rs");

include!("wallet_mail/parsing.rs");

include!("wallet_mail/tool_dispatch.rs");

#[cfg(test)]
#[path = "wallet_mail/tests.rs"]
mod tests;
