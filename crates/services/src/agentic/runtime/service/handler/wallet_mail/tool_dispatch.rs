fn emit_execution_contract_receipt_event(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    stage: &str,
    key: &str,
    satisfied: bool,
    evidence_material: &str,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let evidence_payload = format!(
        "intent_id={};stage={};key={};satisfied={};evidence={}",
        intent_id, stage, key, satisfied, evidence_material
    );
    let evidence_commit_hash = sha256(evidence_payload.as_bytes())
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string());
    let _ = tx.send(KernelEvent::ExecutionContractReceipt(
        ExecutionContractReceiptEvent {
            contract_version: CEC_CONTRACT_VERSION.to_string(),
            session_id,
            step_index,
            intent_id: intent_id.to_string(),
            stage: stage.to_string(),
            key: key.to_string(),
            satisfied,
            timestamp_ms,
            evidence_commit_hash,
            verifier_command_commit_hash: None,
            probe_source: None,
            observed_value: None,
            evidence_type: None,
            provider_id: None,
            synthesized_payload_hash: None,
        },
    ));
}

async fn execute_wallet_mail_dynamic_tool_on_state(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    wallet_service: &std::sync::Arc<dyn ioi_api::services::BlockchainService>,
    call_context: ServiceCallContext<'_>,
    method: WalletMailToolMethod,
    args: &JsonMap<String, JsonValue>,
    mailbox_hint: &str,
    latest_user_message: Option<&str>,
    session_id: [u8; 32],
    step_index: u32,
    now_ms: u64,
) -> Result<(bool, Option<String>, Option<String>), TransactionError> {
    let channel_id = pick_hex_32(args, &["channel_id", "channelId"])?;
    let lease_id = pick_hex_32(args, &["lease_id", "leaseId"])?;
    let inferred = if channel_id.is_none() || lease_id.is_none() {
        match infer_mail_binding(
            state,
            method,
            call_context.signer_account_id.0,
            mailbox_hint,
            now_ms,
        ) {
            Ok(binding) => Some(binding),
            Err(error) if is_missing_mail_binding_error(&error) => {
                ensure_wallet_mail_binding(
                    state,
                    wallet_service,
                    call_context,
                    method,
                    mailbox_hint,
                    session_id,
                    step_index,
                    now_ms,
                )
                .await?;
                Some(infer_mail_binding(
                    state,
                    method,
                    call_context.signer_account_id.0,
                    mailbox_hint,
                    now_ms,
                )?)
            }
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    let channel_id = channel_id
        .or(inferred.map(|binding| binding.channel_id))
        .ok_or_else(|| {
            TransactionError::Invalid("unable to resolve wallet mail channel_id".to_string())
        })?;
    let lease_id = lease_id
        .or(inferred.map(|binding| binding.lease_id))
        .ok_or_else(|| {
            TransactionError::Invalid("unable to resolve wallet mail lease_id".to_string())
        })?;

    let op_seq = pick_u64(args, &["op_seq", "opSeq"])
        .filter(|value| *value >= 1)
        .unwrap_or_else(|| infer_next_op_seq(state, channel_id, lease_id));
    let operation_id = pick_hex_32(args, &["operation_id", "operationId"])?.unwrap_or_else(|| {
        compute_sha256_id(&format!(
            "{}:{}:{}:{}:{}",
            hex::encode(session_id),
            step_index,
            method.method_name(),
            op_seq,
            now_ms
        ))
    });
    let op_nonce = pick_hex_32(args, &["op_nonce", "opNonce"])?
        .unwrap_or_else(|| op_nonce_from_operation(operation_id, step_index));
    let requested_at_ms = pick_u64(args, &["requested_at_ms", "requestedAtMs"]).unwrap_or(now_ms);

    let mut reply_output_draft = None::<MailReplyDraft>;
    let (params_bytes, receipt_operation_id) = match method {
        WalletMailToolMethod::ReadLatest => {
            let params = MailReadLatestParams {
                operation_id,
                channel_id,
                lease_id,
                op_seq,
                op_nonce: Some(op_nonce),
                mailbox: mailbox_hint.to_string(),
                requested_at_ms,
            };
            (codec::to_bytes_canonical(&params)?, params.operation_id)
        }
        WalletMailToolMethod::ListRecent => {
            let params = MailListRecentParams {
                operation_id,
                channel_id,
                lease_id,
                op_seq,
                op_nonce: Some(op_nonce),
                mailbox: mailbox_hint.to_string(),
                limit: pick_u32(args, &["limit"]).unwrap_or(25).clamp(1, 200),
                requested_at_ms,
            };
            (codec::to_bytes_canonical(&params)?, params.operation_id)
        }
        WalletMailToolMethod::DeleteSpam => {
            let params = MailDeleteSpamParams {
                operation_id,
                channel_id,
                lease_id,
                op_seq,
                op_nonce: Some(op_nonce),
                mailbox: mailbox_hint.to_string(),
                max_delete: pick_u32(args, &["max_delete", "maxDelete"]).unwrap_or(25),
                requested_at_ms,
            };
            (codec::to_bytes_canonical(&params)?, params.operation_id)
        }
        WalletMailToolMethod::Reply => {
            let sender_display_name = load_mailbox_sender_display_name(state, mailbox_hint)?;
            let reply_to_message_id =
                pick_string(args, &["reply_to_message_id", "replyToMessageId"])
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string);
            let draft = match resolve_explicit_mail_reply_draft(args)? {
                ExplicitMailReplyDraftResolution::Accepted(explicit_draft) => explicit_draft,
                ExplicitMailReplyDraftResolution::Absent => {
                    let latest_user_message = latest_user_message.ok_or_else(|| {
                        TransactionError::Invalid(
                            "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requires the latest user request to synthesize a draft when explicit canonical fields are absent"
                                .to_string(),
                        )
                    })?;
                    synthesize_mail_reply_draft(
                        service,
                        latest_user_message,
                        sender_display_name.as_deref(),
                        reply_to_message_id.as_deref(),
                        session_id,
                        None,
                        None,
                    )
                    .await?
                }
                ExplicitMailReplyDraftResolution::NeedsSynthesis {
                    candidate,
                    lint_error,
                } => {
                    let latest_user_message = latest_user_message.ok_or_else(|| {
                        TransactionError::Invalid(format!(
                            "{}; latest user request is required for pre-execution draft synthesis",
                            lint_error
                        ))
                    })?;
                    synthesize_mail_reply_draft(
                        service,
                        latest_user_message,
                        sender_display_name.as_deref(),
                        reply_to_message_id.as_deref(),
                        session_id,
                        Some(&candidate),
                        Some(&lint_error),
                    )
                    .await?
                }
            };
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                "mail.reply",
                "provider_selection",
                "payload_synthesis",
                true,
                &format!(
                    "mailbox={};recipient={};subject={}",
                    mailbox_hint, draft.to, draft.subject
                ),
            );
            reply_output_draft = Some(draft.clone());

            let params = MailReplyParams {
                operation_id,
                channel_id,
                lease_id,
                op_seq,
                op_nonce: Some(op_nonce),
                mailbox: mailbox_hint.to_string(),
                to: draft.to,
                subject: draft.subject,
                body: draft.body,
                reply_to_message_id,
                requested_at_ms,
            };
            (codec::to_bytes_canonical(&params)?, params.operation_id)
        }
    };

    let mut wallet_ctx = TxContext {
        block_height: call_context.block_height,
        block_timestamp: call_context.block_timestamp,
        chain_id: call_context.chain_id,
        signer_account_id: call_context.signer_account_id,
        services: call_context.services,
        simulation: call_context.simulation,
        is_internal: call_context.is_internal,
    };

    if let Err(error) = wallet_service
        .handle_service_call(state, method.method_name(), &params_bytes, &mut wallet_ctx)
        .await
    {
        return Ok((
            false,
            None,
            Some(format!(
                "ERROR_CLASS=UnexpectedState wallet_network dynamic call '{}' failed: {}",
                method.method_name(),
                error
            )),
        ));
    }

    let output = match method {
        WalletMailToolMethod::ReadLatest => {
            let receipt_key = mail_read_receipt_storage_key(&receipt_operation_id);
            let receipt_bytes = state
                .get(&receipt_key)
                .map_err(TransactionError::State)?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "wallet_network read receipt missing after execution".to_string(),
                    )
                })?;
            let receipt: MailReadLatestReceipt = codec::from_bytes_canonical(&receipt_bytes)?;
            let message_spam_band = if receipt.message.spam_confidence_band.trim().is_empty() {
                spam_confidence_band(receipt.message.spam_confidence_bps).to_string()
            } else {
                receipt.message.spam_confidence_band.clone()
            };
            json!({
                "operation": method.method_name(),
                "mailbox": receipt.mailbox,
                "executed_at_utc": iso_datetime_from_unix_ms(receipt.executed_at_ms),
                "message": {
                    "message_id": receipt.message.message_id,
                    "from": receipt.message.from,
                    "subject": receipt.message.subject,
                    "received_at_ms": receipt.message.received_at_ms,
                    "received_at_utc": iso_datetime_from_unix_ms(receipt.message.received_at_ms),
                    "preview": truncate_chars(&receipt.message.preview, 280),
                    "spam_confidence_bps": receipt.message.spam_confidence_bps,
                    "spam_confidence_band": message_spam_band,
                    "spam_signal_tags": receipt.message.spam_signal_tags,
                },
                "citation": format!(
                    "imap://{}/{}",
                    normalize_mailbox(&receipt.mailbox),
                    receipt.message.message_id
                ),
            })
            .to_string()
        }
        WalletMailToolMethod::ListRecent => {
            let receipt_key = mail_list_receipt_storage_key(&receipt_operation_id);
            let receipt_bytes = state
                .get(&receipt_key)
                .map_err(TransactionError::State)?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "wallet_network list receipt missing after execution".to_string(),
                    )
                })?;
            let receipt: MailListRecentReceipt = codec::from_bytes_canonical(&receipt_bytes)?;
            let mailbox = receipt.mailbox.clone();
            let requested_limit = if receipt.requested_limit == 0 {
                receipt.messages.len() as u32
            } else {
                receipt.requested_limit
            };
            let evaluated_count = if receipt.evaluated_count == 0 {
                receipt.messages.len() as u32
            } else {
                receipt.evaluated_count
            };
            let parse_confidence_bps = if receipt.parse_confidence_bps == 0 {
                if evaluated_count == 0 {
                    10_000
                } else {
                    ((receipt.messages.len() as u32).saturating_mul(10_000)
                        / evaluated_count.max(1)) as u16
                }
            } else {
                receipt.parse_confidence_bps
            };
            let parse_volume_band_value = if receipt.parse_volume_band.trim().is_empty() {
                parse_volume_band(receipt.messages.len()).to_string()
            } else {
                receipt.parse_volume_band.clone()
            };
            let mailbox_total_count = if receipt.mailbox_total_count == 0 {
                evaluated_count.max(receipt.messages.len() as u32)
            } else {
                receipt.mailbox_total_count
            };
            let ontology_version = if receipt.ontology_version.trim().is_empty() {
                MAIL_ONTOLOGY_SIGNAL_VERSION.to_string()
            } else {
                receipt.ontology_version.clone()
            };
            let mut high_confidence_spam_candidates = 0u32;
            let mut high_confidence_non_spam_candidates = 0u32;
            let messages = receipt
                .messages
                .into_iter()
                .map(|message| {
                    let spam_band = if message.spam_confidence_band.trim().is_empty() {
                        spam_confidence_band(message.spam_confidence_bps).to_string()
                    } else {
                        message.spam_confidence_band.clone()
                    };
                    if message.spam_confidence_bps >= SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS {
                        high_confidence_spam_candidates =
                            high_confidence_spam_candidates.saturating_add(1);
                    } else if spam_band == "high" {
                        high_confidence_non_spam_candidates =
                            high_confidence_non_spam_candidates.saturating_add(1);
                    }
                    json!({
                        "message_id": message.message_id.clone(),
                        "from": message.from,
                        "subject": message.subject,
                        "received_at_ms": message.received_at_ms,
                        "received_at_utc": iso_datetime_from_unix_ms(message.received_at_ms),
                        "preview": truncate_chars(&message.preview, 220),
                        "spam_confidence_bps": message.spam_confidence_bps,
                        "spam_confidence_band": spam_band,
                        "spam_signal_tags": message.spam_signal_tags,
                        "citation": format!(
                            "imap://{}/{}",
                            normalize_mailbox(&mailbox),
                            message.message_id
                        ),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "operation": method.method_name(),
                "mailbox": mailbox,
                "executed_at_utc": iso_datetime_from_unix_ms(receipt.executed_at_ms),
                "analysis": {
                    "ontology_version": ontology_version,
                    "requested_limit": requested_limit,
                    "evaluated_count": evaluated_count,
                    "returned_count": messages.len(),
                    "parse_error_count": receipt.parse_error_count,
                    "parse_confidence_bps": parse_confidence_bps,
                    "parse_confidence_band": parse_confidence_band(parse_confidence_bps),
                    "parse_volume_band": parse_volume_band_value,
                    "mailbox_total_count": mailbox_total_count,
                    "high_confidence_spam_candidates": high_confidence_spam_candidates,
                    "high_confidence_non_spam_candidates": high_confidence_non_spam_candidates,
                    "spam_high_confidence_threshold_bps": SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
                },
                "messages": messages,
            })
            .to_string()
        }
        WalletMailToolMethod::DeleteSpam => {
            let receipt_key = mail_delete_receipt_storage_key(&receipt_operation_id);
            let receipt_bytes = state
                .get(&receipt_key)
                .map_err(TransactionError::State)?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "wallet_network delete receipt missing after execution".to_string(),
                    )
                })?;
            let receipt: MailDeleteSpamReceipt = codec::from_bytes_canonical(&receipt_bytes)?;
            let ontology_version = if receipt.ontology_version.trim().is_empty() {
                MAIL_ONTOLOGY_SIGNAL_VERSION.to_string()
            } else {
                receipt.ontology_version.clone()
            };
            let confidence_threshold_bps = if receipt.spam_confidence_threshold_bps == 0 {
                SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS
            } else {
                receipt.spam_confidence_threshold_bps
            };
            let evaluated_count = if receipt.evaluated_count == 0 {
                receipt.deleted_count
            } else {
                receipt.evaluated_count
            };
            let high_confidence_deleted_count =
                if receipt.high_confidence_deleted_count == 0 && receipt.deleted_count > 0 {
                    receipt.deleted_count
                } else {
                    receipt.high_confidence_deleted_count
                };
            let skipped_low_confidence_count = if receipt.skipped_low_confidence_count == 0
                && evaluated_count >= high_confidence_deleted_count
            {
                evaluated_count.saturating_sub(high_confidence_deleted_count)
            } else {
                receipt.skipped_low_confidence_count
            };
            let mailbox_total_count_before = if receipt.mailbox_total_count_before == 0 {
                evaluated_count
            } else {
                receipt.mailbox_total_count_before
            };
            let mailbox_total_count_after = if receipt.mailbox_total_count_after == 0 {
                mailbox_total_count_before.saturating_sub(high_confidence_deleted_count)
            } else {
                receipt.mailbox_total_count_after
            };
            let mailbox_total_count_delta = if receipt.mailbox_total_count_delta == 0
                && mailbox_total_count_before >= mailbox_total_count_after
            {
                mailbox_total_count_before.saturating_sub(mailbox_total_count_after)
            } else {
                receipt.mailbox_total_count_delta
            };
            let cleanup_scope = if receipt.cleanup_scope.trim().is_empty() {
                if normalize_mailbox(&receipt.mailbox) == "primary"
                    || normalize_mailbox(&receipt.mailbox) == "inbox"
                {
                    "primary_inbox".to_string()
                } else {
                    "spam_mailbox".to_string()
                }
            } else {
                receipt.cleanup_scope.clone()
            };
            let preserved_transactional_or_personal_count =
                receipt.preserved_transactional_or_personal_count;
            let preserved_trusted_system_count = receipt.preserved_trusted_system_count;
            let preserved_low_confidence_other_count = receipt.preserved_low_confidence_other_count;
            let preserved_due_to_delete_cap_count = receipt.preserved_due_to_delete_cap_count;
            let preserved_reason_counts = if receipt.preserved_reason_counts.is_empty() {
                BTreeMap::from([
                    (
                        "transactional_or_personal".to_string(),
                        preserved_transactional_or_personal_count,
                    ),
                    (
                        "trusted_system_sender".to_string(),
                        preserved_trusted_system_count,
                    ),
                    (
                        "low_confidence_other".to_string(),
                        preserved_low_confidence_other_count,
                    ),
                    (
                        "delete_cap_guardrail".to_string(),
                        preserved_due_to_delete_cap_count,
                    ),
                ])
            } else {
                receipt.preserved_reason_counts.clone()
            };
            let total_preserved_count = preserved_transactional_or_personal_count
                .saturating_add(preserved_trusted_system_count)
                .saturating_add(preserved_low_confidence_other_count)
                .saturating_add(preserved_due_to_delete_cap_count);
            let classification_mode = if cleanup_scope.eq_ignore_ascii_case("primary_inbox") {
                "high_confidence_unwanted_preserve_transactional_personal"
            } else {
                "high_confidence_spam_only"
            };
            json!({
                "operation": method.method_name(),
                "mailbox": receipt.mailbox,
                "cleanup_scope": cleanup_scope,
                "deleted_count": receipt.deleted_count,
                "evaluated_count": evaluated_count,
                "high_confidence_deleted_count": high_confidence_deleted_count,
                "skipped_low_confidence_count": skipped_low_confidence_count,
                "mailbox_total_count_before": mailbox_total_count_before,
                "mailbox_total_count_after": mailbox_total_count_after,
                "mailbox_total_count_delta": mailbox_total_count_delta,
                "preserved_transactional_or_personal_count": preserved_transactional_or_personal_count,
                "preserved_trusted_system_count": preserved_trusted_system_count,
                "preserved_low_confidence_other_count": preserved_low_confidence_other_count,
                "preserved_due_to_delete_cap_count": preserved_due_to_delete_cap_count,
                "preserved_reason_counts": preserved_reason_counts,
                "total_preserved_count": total_preserved_count,
                "preservation_evidence": {
                    "transactional_or_personal_count": preserved_transactional_or_personal_count,
                    "trusted_system_sender_count": preserved_trusted_system_count,
                    "low_confidence_other_count": preserved_low_confidence_other_count,
                    "due_to_delete_cap_count": preserved_due_to_delete_cap_count,
                    "reason_counts": preserved_reason_counts,
                    "total_preserved_count": total_preserved_count,
                    "preserve_modes": [
                        "transactional_or_personal",
                        "trusted_system_sender",
                        "low_confidence_other",
                        "delete_cap_guardrail"
                    ]
                },
                "classification_policy": {
                    "mode": classification_mode,
                    "ontology_version": ontology_version,
                    "spam_confidence_threshold_bps": confidence_threshold_bps,
                },
                "executed_at_utc": iso_datetime_from_unix_ms(receipt.executed_at_ms),
                "citation": format!(
                    "imap://{}/cleanup/{}",
                    normalize_mailbox(&receipt.mailbox),
                    hex::encode(receipt.operation_id)
                ),
            })
            .to_string()
        }
        WalletMailToolMethod::Reply => {
            let receipt_key = mail_reply_receipt_storage_key(&receipt_operation_id);
            let receipt_bytes = state
                .get(&receipt_key)
                .map_err(TransactionError::State)?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "wallet_network reply receipt missing after execution".to_string(),
                    )
                })?;
            let receipt: MailReplyReceipt = codec::from_bytes_canonical(&receipt_bytes)?;
            json!({
                "operation": method.method_name(),
                "mailbox": receipt.mailbox,
                "to": receipt.to,
                "subject": receipt.subject,
                "body": reply_output_draft
                    .as_ref()
                    .map(|draft| draft.body.clone())
                    .unwrap_or_default(),
                "sent_message_id": receipt.sent_message_id,
                "executed_at_utc": iso_datetime_from_unix_ms(receipt.executed_at_ms),
                "citation": format!(
                    "mailto:{}?subject={}",
                    receipt.to,
                    receipt.subject
                ),
            })
            .to_string()
        }
    };

    Ok((true, Some(output), None))
}

pub(crate) async fn try_execute_wallet_mail_dynamic_tool(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    dynamic_tool: &JsonValue,
    latest_user_message: Option<&str>,
    session_id: [u8; 32],
    step_index: u32,
) -> Result<Option<(bool, Option<String>, Option<String>)>, TransactionError> {
    let Some(tool_name) = dynamic_tool.get("name").and_then(|value| value.as_str()) else {
        return Ok(None);
    };
    let Some(method) = wallet_mail_method_from_tool_name(tool_name) else {
        if is_wallet_mail_namespace_tool_name(tool_name) {
            return Ok(Some((
                false,
                None,
                Some(format!(
                    "ERROR_CLASS=UnsupportedTool unsupported wallet mail tool '{}'",
                    tool_name.trim()
                )),
            )));
        }
        return Ok(None);
    };

    let wallet_service = call_context
        .services
        .services()
        .find(|service| service.id() == "wallet_network")
        .cloned()
        .ok_or_else(|| {
            TransactionError::Invalid(
                "wallet_network service is not active in the ServiceDirectory".to_string(),
            )
        })?;

    let arguments = dynamic_tool
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| JsonValue::Object(JsonMap::new()));
    let args = extract_dynamic_args_object(&arguments)?;

    let now_ms = call_context.block_timestamp / 1_000_000;
    let mailbox_hint = pick_string(&args, &["mailbox", "mailbox_name", "mailboxName"])
        .map(normalize_mailbox)
        .unwrap_or_else(|| "primary".to_string());
    if mailbox_connector_configured(state, &mailbox_hint)? {
        let result = execute_wallet_mail_dynamic_tool_on_state(
            service,
            state,
            &wallet_service,
            call_context,
            method,
            &args,
            &mailbox_hint,
            latest_user_message,
            session_id,
            step_index,
            now_ms,
        )
        .await?;
        return Ok(Some(result));
    }

    let wallet_meta = load_active_service_meta(state, WALLET_SERVICE_ID)?;
    {
        let wallet_prefix = service_namespace_prefix(WALLET_SERVICE_ID);
        let mut wallet_state = NamespacedStateAccess::new(state, wallet_prefix, &wallet_meta);
        if mailbox_connector_configured(&wallet_state, &mailbox_hint)? {
            let result = execute_wallet_mail_dynamic_tool_on_state(
                service,
                &mut wallet_state,
                &wallet_service,
                call_context,
                method,
                &args,
                &mailbox_hint,
                latest_user_message,
                session_id,
                step_index,
                now_ms,
            )
            .await?;
            return Ok(Some(result));
        }
    }

    let result = execute_wallet_mail_dynamic_tool_on_state(
        service,
        state,
        &wallet_service,
        call_context,
        method,
        &args,
        &mailbox_hint,
        latest_user_message,
        session_id,
        step_index,
        now_ms,
    )
    .await?;
    Ok(Some(result))
}
