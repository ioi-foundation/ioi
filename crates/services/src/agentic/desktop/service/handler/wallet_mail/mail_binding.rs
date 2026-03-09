#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WalletMailToolMethod {
    ReadLatest,
    ListRecent,
    DeleteSpam,
    Reply,
}

impl WalletMailToolMethod {
    fn method_name(self) -> &'static str {
        match self {
            Self::ReadLatest => "mail_read_latest@v1",
            Self::ListRecent => "mail_list_recent@v1",
            Self::DeleteSpam => "mail_delete_spam@v1",
            Self::Reply => "mail_reply@v1",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct InferredMailBinding {
    channel_id: [u8; 32],
    lease_id: [u8; 32],
}

fn wallet_mail_method_from_tool_name(name: &str) -> Option<WalletMailToolMethod> {
    let normalized = name.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "wallet_network__mail_read_latest" | "wallet_mail_read_latest" | "mail__read_latest" => {
            Some(WalletMailToolMethod::ReadLatest)
        }
        "wallet_network__mail_list_recent" | "wallet_mail_list_recent" | "mail__list_recent" => {
            Some(WalletMailToolMethod::ListRecent)
        }
        "wallet_network__mail_delete_spam" | "wallet_mail_delete_spam" | "mail__delete_spam" => {
            Some(WalletMailToolMethod::DeleteSpam)
        }
        "wallet_network__mail_reply" | "wallet_mail_reply" | "mail__reply" => {
            Some(WalletMailToolMethod::Reply)
        }
        _ => None,
    }
}

fn is_wallet_mail_namespace_tool_name(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    normalized.starts_with("wallet_network__mail_")
        || normalized.starts_with("wallet_mail_")
        || normalized.starts_with("mail__")
}

fn channel_storage_key(channel_id: &[u8; 32]) -> Vec<u8> {
    [CHANNEL_PREFIX, channel_id.as_slice()].concat()
}

fn lease_action_window_storage_key(channel_id: &[u8; 32], lease_id: &[u8; 32]) -> Vec<u8> {
    [
        LEASE_ACTION_WINDOW_PREFIX,
        channel_id.as_slice(),
        b"::",
        lease_id.as_slice(),
    ]
    .concat()
}

fn mail_read_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [MAIL_READ_RECEIPT_PREFIX, operation_id.as_slice()].concat()
}

fn mail_list_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [MAIL_LIST_RECEIPT_PREFIX, operation_id.as_slice()].concat()
}

fn mail_delete_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [MAIL_DELETE_RECEIPT_PREFIX, operation_id.as_slice()].concat()
}

fn mail_reply_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [MAIL_REPLY_RECEIPT_PREFIX, operation_id.as_slice()].concat()
}

fn mail_connector_storage_key(mailbox: &str) -> Vec<u8> {
    [MAIL_CONNECTOR_PREFIX, normalize_mailbox(mailbox).as_bytes()].concat()
}

fn load_active_service_meta(
    state: &dyn StateAccess,
    service_id: &str,
) -> Result<ActiveServiceMeta, TransactionError> {
    let key = active_service_key(service_id);
    let bytes = state
        .get(&key)
        .map_err(TransactionError::State)?
        .ok_or_else(|| {
            TransactionError::Invalid(format!(
                "active service metadata is missing for '{}'",
                service_id
            ))
        })?;
    codec::from_bytes_canonical(&bytes).map_err(Into::into)
}

fn mailbox_connector_configured(
    state: &dyn StateAccess,
    mailbox_hint: &str,
) -> Result<bool, TransactionError> {
    state
        .get(&mail_connector_storage_key(mailbox_hint))
        .map(|value| value.is_some())
        .map_err(TransactionError::State)
}

fn inference_vm_error_to_tx(err: VmError) -> TransactionError {
    TransactionError::Invalid(err.to_string())
}

fn is_missing_mail_binding_error(error: &TransactionError) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("no wallet mail lease binding available")
        || text.contains("unable to resolve wallet mail channel_id")
        || text.contains("unable to resolve wallet mail lease_id")
}

async fn ensure_wallet_mail_binding(
    state: &mut dyn StateAccess,
    wallet_service: &std::sync::Arc<dyn ioi_api::services::BlockchainService>,
    call_context: ServiceCallContext<'_>,
    method: WalletMailToolMethod,
    mailbox: &str,
    session_id: [u8; 32],
    step_index: u32,
    now_ms: u64,
) -> Result<(), TransactionError> {
    let request_id = compute_sha256_id(&format!(
        "wallet-mail-binding:{}:{}:{}:{}",
        hex::encode(session_id),
        step_index,
        normalize_mailbox(mailbox),
        now_ms
    ));
    let params = MailConnectorEnsureBindingParams {
        request_id,
        mailbox: normalize_mailbox(mailbox),
        audience: Some(call_context.signer_account_id.0),
        lease_ttl_ms: None,
        requested_capability: capability_aliases(method)
            .first()
            .map(|value| value.to_string()),
    };
    let payload = codec::to_bytes_canonical(&params)?;
    let mut wallet_ctx = TxContext {
        block_height: call_context.block_height,
        block_timestamp: call_context.block_timestamp,
        chain_id: call_context.chain_id,
        signer_account_id: call_context.signer_account_id,
        services: call_context.services,
        simulation: call_context.simulation,
        is_internal: call_context.is_internal,
    };
    wallet_service
        .handle_service_call(
            state,
            MAIL_CONNECTOR_ENSURE_BINDING_METHOD,
            &payload,
            &mut wallet_ctx,
        )
        .await
}

fn capability_aliases(method: WalletMailToolMethod) -> &'static [&'static str] {
    match method {
        WalletMailToolMethod::ReadLatest => MAIL_READ_CAPABILITY_ALIASES,
        WalletMailToolMethod::ListRecent => MAIL_LIST_CAPABILITY_ALIASES,
        WalletMailToolMethod::DeleteSpam => MAIL_DELETE_CAPABILITY_ALIASES,
        WalletMailToolMethod::Reply => MAIL_REPLY_CAPABILITY_ALIASES,
    }
}

fn capability_matches(method: WalletMailToolMethod, capabilities: &[String]) -> bool {
    capabilities.iter().any(|capability| {
        let normalized = capability.trim().to_ascii_lowercase();
        capability_aliases(method)
            .iter()
            .any(|alias| normalized == *alias)
    })
}

fn normalize_mailbox(mailbox: &str) -> String {
    let trimmed = mailbox.trim();
    if trimmed.is_empty() {
        "primary".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn mailbox_constraint_matches(constraint: Option<&String>, mailbox: &str) -> bool {
    constraint
        .map(|value| normalize_mailbox(value) == normalize_mailbox(mailbox))
        .unwrap_or(true)
}

fn infer_mail_binding(
    state: &dyn StateAccess,
    method: WalletMailToolMethod,
    signer_account_id: [u8; 32],
    mailbox_hint: &str,
    now_ms: u64,
) -> Result<InferredMailBinding, TransactionError> {
    let mailbox = normalize_mailbox(mailbox_hint);
    let mut best: Option<(SessionLease, SessionChannelRecord)> = None;

    let scan = state
        .prefix_scan(LEASE_PREFIX)
        .map_err(|e| TransactionError::State(e))?;
    for row in scan {
        let Ok((_, value)) = row else {
            continue;
        };
        let Ok(lease) = codec::from_bytes_canonical::<SessionLease>(&value) else {
            continue;
        };
        if lease.audience != signer_account_id || now_ms > lease.expires_at_ms {
            continue;
        }
        if !capability_matches(method, &lease.capability_subset) {
            continue;
        }
        if !mailbox_constraint_matches(lease.constraints_subset.get("mailbox"), &mailbox) {
            continue;
        }

        let channel_key = channel_storage_key(&lease.channel_id);
        let Some(channel_bytes) = state.get(&channel_key).map_err(TransactionError::State)? else {
            continue;
        };
        let Ok(channel) = codec::from_bytes_canonical::<SessionChannelRecord>(&channel_bytes)
        else {
            continue;
        };
        if channel.state != SessionChannelState::Open || now_ms > channel.envelope.expires_at_ms {
            continue;
        }
        if !capability_matches(method, &channel.envelope.capability_set) {
            continue;
        }
        if !mailbox_constraint_matches(channel.envelope.constraints.get("mailbox"), &mailbox) {
            continue;
        }

        let replace = best
            .as_ref()
            .map(|(current_lease, _)| lease.issued_at_ms >= current_lease.issued_at_ms)
            .unwrap_or(true);
        if replace {
            best = Some((lease, channel));
        }
    }

    let Some((lease, _channel)) = best else {
        return Err(TransactionError::Invalid(format!(
            "no wallet mail lease binding available for method '{}' (mailbox='{}')",
            method.method_name(),
            mailbox
        )));
    };

    Ok(InferredMailBinding {
        channel_id: lease.channel_id,
        lease_id: lease.lease_id,
    })
}
