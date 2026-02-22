use super::config::normalize_delete_limit;
use super::constants::{
    MAIL_CONNECTOR_DEFAULT_MAILBOX, MAIL_DELETE_RECEIPT_PREFIX, MAIL_LIST_RECEIPT_PREFIX,
    MAIL_READ_RECEIPT_PREFIX, MAIL_REPLY_RECEIPT_PREFIX,
};
use super::rpc::{build_wallet_call_tx, query_wallet_state, submit_tx_and_wait};
use super::types::{
    WalletMailDeleteSpamResult, WalletMailListRecentResult, WalletMailMessageView,
    WalletMailReadLatestResult, WalletMailReplyResult,
};
use super::utils::{decode_hex_32, generate_op_nonce, generate_operation_id};
use crate::kernel::state::get_rpc_client;
use crate::models::AppState;
use ioi_types::app::{
    ChainTransaction, MailDeleteSpamParams, MailDeleteSpamReceipt, MailListRecentParams,
    MailListRecentReceipt, MailMessageSummary, MailReadLatestParams, MailReadLatestReceipt,
    MailReplyParams, MailReplyReceipt,
};
use ioi_types::codec;
use std::sync::Mutex;
use tauri::State;

fn to_message_view(message: MailMessageSummary) -> WalletMailMessageView {
    WalletMailMessageView {
        message_id: message.message_id,
        from: message.from,
        subject: message.subject,
        received_at_ms: message.received_at_ms,
        preview: message.preview,
    }
}

async fn submit_and_read_receipt<T: parity_scale_codec::Decode>(
    state: &State<'_, Mutex<AppState>>,
    tx: ChainTransaction,
    receipt_key: Vec<u8>,
) -> Result<T, String> {
    let mut client = get_rpc_client(state).await?;
    submit_tx_and_wait(&mut client, tx).await?;

    let receipt_bytes = query_wallet_state(&mut client, receipt_key).await?;
    codec::from_bytes_canonical(&receipt_bytes).map_err(|e| e.to_string())
}

pub(super) async fn execute_wallet_mail_read_latest(
    state: &State<'_, Mutex<AppState>>,
    channel_id: &str,
    lease_id: &str,
    op_seq: u64,
    mailbox: Option<String>,
) -> Result<WalletMailReadLatestResult, String> {
    if op_seq == 0 {
        return Err("opSeq must be >= 1".to_string());
    }
    let channel_id = decode_hex_32("channelId", channel_id)?;
    let lease_id = decode_hex_32("leaseId", lease_id)?;
    let operation_id = generate_operation_id();

    let params = MailReadLatestParams {
        operation_id,
        channel_id,
        lease_id,
        op_seq,
        op_nonce: Some(generate_op_nonce()),
        mailbox: mailbox.unwrap_or_else(|| MAIL_CONNECTOR_DEFAULT_MAILBOX.to_string()),
        requested_at_ms: crate::kernel::state::now(),
    };
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;
    let tx = build_wallet_call_tx("mail_read_latest@v1", params_bytes)?;

    let receipt_key = [MAIL_READ_RECEIPT_PREFIX, operation_id.as_slice()].concat();
    let receipt: MailReadLatestReceipt = submit_and_read_receipt(state, tx, receipt_key).await?;

    Ok(WalletMailReadLatestResult {
        operation_id_hex: hex::encode(receipt.operation_id),
        channel_id_hex: hex::encode(receipt.channel_id),
        lease_id_hex: hex::encode(receipt.lease_id),
        mailbox: receipt.mailbox,
        audience_hex: hex::encode(receipt.audience),
        executed_at_ms: receipt.executed_at_ms,
        message: to_message_view(receipt.message),
    })
}

pub(super) async fn execute_wallet_mail_list_recent(
    state: &State<'_, Mutex<AppState>>,
    channel_id: &str,
    lease_id: &str,
    op_seq: u64,
    mailbox: Option<String>,
    limit: Option<u32>,
) -> Result<WalletMailListRecentResult, String> {
    if op_seq == 0 {
        return Err("opSeq must be >= 1".to_string());
    }
    let channel_id = decode_hex_32("channelId", channel_id)?;
    let lease_id = decode_hex_32("leaseId", lease_id)?;
    let operation_id = generate_operation_id();

    let params = MailListRecentParams {
        operation_id,
        channel_id,
        lease_id,
        op_seq,
        op_nonce: Some(generate_op_nonce()),
        mailbox: mailbox.unwrap_or_else(|| MAIL_CONNECTOR_DEFAULT_MAILBOX.to_string()),
        limit: limit.unwrap_or(5).clamp(1, 20),
        requested_at_ms: crate::kernel::state::now(),
    };
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;
    let tx = build_wallet_call_tx("mail_list_recent@v1", params_bytes)?;

    let receipt_key = [MAIL_LIST_RECEIPT_PREFIX, operation_id.as_slice()].concat();
    let receipt: MailListRecentReceipt = submit_and_read_receipt(state, tx, receipt_key).await?;

    Ok(WalletMailListRecentResult {
        operation_id_hex: hex::encode(receipt.operation_id),
        channel_id_hex: hex::encode(receipt.channel_id),
        lease_id_hex: hex::encode(receipt.lease_id),
        mailbox: receipt.mailbox,
        audience_hex: hex::encode(receipt.audience),
        executed_at_ms: receipt.executed_at_ms,
        messages: receipt.messages.into_iter().map(to_message_view).collect(),
    })
}

pub(super) async fn execute_wallet_mail_delete_spam(
    state: &State<'_, Mutex<AppState>>,
    channel_id: &str,
    lease_id: &str,
    op_seq: u64,
    mailbox: Option<String>,
    max_delete: Option<u32>,
) -> Result<WalletMailDeleteSpamResult, String> {
    if op_seq == 0 {
        return Err("opSeq must be >= 1".to_string());
    }
    let channel_id = decode_hex_32("channelId", channel_id)?;
    let lease_id = decode_hex_32("leaseId", lease_id)?;
    let operation_id = generate_operation_id();

    let params = MailDeleteSpamParams {
        operation_id,
        channel_id,
        lease_id,
        op_seq,
        op_nonce: Some(generate_op_nonce()),
        mailbox: mailbox.unwrap_or_else(|| MAIL_CONNECTOR_DEFAULT_MAILBOX.to_string()),
        max_delete: normalize_delete_limit(max_delete),
        requested_at_ms: crate::kernel::state::now(),
    };
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;
    let tx = build_wallet_call_tx("mail_delete_spam@v1", params_bytes)?;

    let receipt_key = [MAIL_DELETE_RECEIPT_PREFIX, operation_id.as_slice()].concat();
    let receipt: MailDeleteSpamReceipt = submit_and_read_receipt(state, tx, receipt_key).await?;

    Ok(WalletMailDeleteSpamResult {
        operation_id_hex: hex::encode(receipt.operation_id),
        channel_id_hex: hex::encode(receipt.channel_id),
        lease_id_hex: hex::encode(receipt.lease_id),
        mailbox: receipt.mailbox,
        audience_hex: hex::encode(receipt.audience),
        executed_at_ms: receipt.executed_at_ms,
        deleted_count: receipt.deleted_count,
    })
}

pub(super) async fn execute_wallet_mail_reply(
    state: &State<'_, Mutex<AppState>>,
    channel_id: &str,
    lease_id: &str,
    op_seq: u64,
    mailbox: Option<String>,
    to: String,
    subject: String,
    body: String,
    reply_to_message_id: Option<String>,
) -> Result<WalletMailReplyResult, String> {
    if op_seq == 0 {
        return Err("opSeq must be >= 1".to_string());
    }
    let channel_id = decode_hex_32("channelId", channel_id)?;
    let lease_id = decode_hex_32("leaseId", lease_id)?;
    let operation_id = generate_operation_id();

    let params = MailReplyParams {
        operation_id,
        channel_id,
        lease_id,
        op_seq,
        op_nonce: Some(generate_op_nonce()),
        mailbox: mailbox.unwrap_or_else(|| MAIL_CONNECTOR_DEFAULT_MAILBOX.to_string()),
        to,
        subject,
        body,
        reply_to_message_id,
        requested_at_ms: crate::kernel::state::now(),
    };
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;
    let tx = build_wallet_call_tx("mail_reply@v1", params_bytes)?;

    let receipt_key = [MAIL_REPLY_RECEIPT_PREFIX, operation_id.as_slice()].concat();
    let receipt: MailReplyReceipt = submit_and_read_receipt(state, tx, receipt_key).await?;

    Ok(WalletMailReplyResult {
        operation_id_hex: hex::encode(receipt.operation_id),
        channel_id_hex: hex::encode(receipt.channel_id),
        lease_id_hex: hex::encode(receipt.lease_id),
        mailbox: receipt.mailbox,
        audience_hex: hex::encode(receipt.audience),
        executed_at_ms: receipt.executed_at_ms,
        to: receipt.to,
        subject: receipt.subject,
        sent_message_id: receipt.sent_message_id,
    })
}
