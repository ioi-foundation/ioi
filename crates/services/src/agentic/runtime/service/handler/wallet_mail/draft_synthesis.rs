#[derive(Clone, Debug, PartialEq, Eq)]
struct MailDraftToken {
    id: String,
    placeholder: String,
    raw_value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MailReplyDraft {
    to: String,
    subject: String,
    body: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MailReplyDraftCandidate {
    to: Option<String>,
    subject: Option<String>,
    body: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MailReplySynthesisContext {
    sanitized_request: String,
    email_tokens: Vec<MailDraftToken>,
    replacement_tokens: Vec<MailDraftToken>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MailReplySignatureMode {
    #[default]
    Omit,
    SenderName,
}

#[derive(Debug, Deserialize)]
struct MailReplySynthesisOutput {
    to_token: String,
    subject: String,
    body: String,
    #[serde(default)]
    signoff: Option<String>,
    #[serde(default)]
    signature_mode: MailReplySignatureMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExplicitMailReplyDraftResolution {
    Absent,
    Accepted(MailReplyDraft),
    NeedsSynthesis {
        candidate: MailReplyDraftCandidate,
        lint_error: String,
    },
}

fn mail_token_placeholder(token_id: &str) -> String {
    format!("{{{{{}}}}}", token_id)
}

fn unresolved_mail_draft_placeholder_present(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("<redacted:")
        || lowered.contains("[your name]")
        || lowered.contains("[your-name]")
        || lowered.contains("[your_name]")
        || lowered.contains("{{")
        || lowered.contains("}}")
}

fn validate_mail_draft_text(label: &str, value: String) -> Result<String, TransactionError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply produced empty {}",
            label
        )));
    }
    if unresolved_mail_draft_placeholder_present(trimmed) {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply produced unresolved placeholders in {}",
            label
        )));
    }
    Ok(trimmed.to_string())
}

fn rehydrate_mail_draft_text(
    value: &str,
    replacement_tokens: &[MailDraftToken],
) -> Result<String, TransactionError> {
    let mut out = value.to_string();
    for token in replacement_tokens {
        out = out.replace(&token.placeholder, &token.raw_value);
    }
    validate_mail_draft_text("text", out)
}

fn assemble_mail_reply_body(
    body: String,
    signoff: Option<String>,
    signature_mode: MailReplySignatureMode,
    sender_display_name: Option<&str>,
) -> Result<String, TransactionError> {
    let mut out = validate_mail_draft_text("body", body)?;
    let signoff = match signoff {
        Some(value) if !value.trim().is_empty() => {
            Some(validate_mail_draft_text("signoff", value)?)
        }
        _ => None,
    };
    let sender_display_name = sender_display_name
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match (signoff, signature_mode) {
        (Some(signoff), MailReplySignatureMode::Omit) => {
            out.push_str("\n\n");
            out.push_str(&signoff);
        }
        (Some(signoff), MailReplySignatureMode::SenderName) => {
            let sender_display_name = sender_display_name.ok_or_else(|| {
                TransactionError::Invalid(
                    "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requested sender-name signature without a configured mailbox sender display name".to_string(),
                )
            })?;
            out.push_str("\n\n");
            out.push_str(&signoff);
            out.push('\n');
            out.push_str(sender_display_name);
        }
        (None, MailReplySignatureMode::SenderName) => {
            let sender_display_name = sender_display_name.ok_or_else(|| {
                TransactionError::Invalid(
                    "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requested sender-name signature without a configured mailbox sender display name".to_string(),
                )
            })?;
            out.push_str("\n\n");
            out.push_str(sender_display_name);
        }
        (None, MailReplySignatureMode::Omit) => {}
    }

    Ok(out)
}

fn resolve_explicit_mail_reply_draft(
    args: &JsonMap<String, JsonValue>,
) -> Result<ExplicitMailReplyDraftResolution, TransactionError> {
    let to = pick_nonempty_string(args, &["to"]);
    let subject = pick_nonempty_string(args, &["subject"]);
    let body = pick_nonempty_string(args, &["body"]);
    if to.is_none() && subject.is_none() && body.is_none() {
        return Ok(ExplicitMailReplyDraftResolution::Absent);
    }

    let candidate = MailReplyDraftCandidate {
        to: to.clone(),
        subject: subject.clone(),
        body: body.clone(),
    };
    let Some(raw_to) = to else {
        return Ok(ExplicitMailReplyDraftResolution::NeedsSynthesis {
            candidate,
            lint_error: "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requires canonical 'to', 'subject', and 'body' when explicit draft fields are provided".to_string(),
        });
    };
    let Some(to) = canonicalize_mail_recipient(&raw_to) else {
        let lint_error = if is_redacted_email_placeholder(&raw_to) {
            "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply explicit recipient was redacted and requires pre-execution draft synthesis from the user request".to_string()
        } else {
            "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requires a valid canonical recipient email address".to_string()
        };
        return Ok(ExplicitMailReplyDraftResolution::NeedsSynthesis {
            candidate,
            lint_error,
        });
    };
    let Some(subject) = subject else {
        return Ok(ExplicitMailReplyDraftResolution::NeedsSynthesis {
            candidate,
            lint_error: "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requires canonical 'to', 'subject', and 'body' when explicit draft fields are provided".to_string(),
        });
    };
    let subject = validate_mail_draft_text("subject", subject);
    let subject = match subject {
        Ok(value) => value,
        Err(error) => {
            return Ok(ExplicitMailReplyDraftResolution::NeedsSynthesis {
                candidate,
                lint_error: error.to_string(),
            })
        }
    };
    let Some(body) = body else {
        return Ok(ExplicitMailReplyDraftResolution::NeedsSynthesis {
            candidate,
            lint_error: "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requires canonical 'to', 'subject', and 'body' when explicit draft fields are provided".to_string(),
        });
    };
    let body = validate_mail_draft_text("body", body);
    let body = match body {
        Ok(value) => value,
        Err(error) => {
            return Ok(ExplicitMailReplyDraftResolution::NeedsSynthesis {
                candidate,
                lint_error: error.to_string(),
            })
        }
    };

    Ok(ExplicitMailReplyDraftResolution::Accepted(MailReplyDraft {
        to,
        subject,
        body,
    }))
}

fn build_mail_reply_synthesis_context(
    latest_user_message: &str,
    candidate_recipient: Option<&str>,
) -> Result<MailReplySynthesisContext, TransactionError> {
    let evidence = pii_substrate::build_evidence_graph(latest_user_message).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=SynthesisFailed failed to inspect mail request PII substrate: {}",
            e
        ))
    })?;
    let mut email_spans = evidence
        .spans
        .iter()
        .filter(|span| span.pii_class == PiiClass::Email)
        .collect::<Vec<_>>();
    email_spans.sort_by_key(|span| (span.start_index, span.end_index));

    let mut sanitized_request = String::with_capacity(latest_user_message.len());
    let mut last_index = 0usize;
    let mut email_tokens = Vec::<MailDraftToken>::new();
    let mut replacement_tokens = Vec::<MailDraftToken>::new();

    for span in email_spans {
        let start = span.start_index as usize;
        let end = span.end_index as usize;
        if start >= end
            || end > latest_user_message.len()
            || !latest_user_message.is_char_boundary(start)
            || !latest_user_message.is_char_boundary(end)
            || start < last_index
        {
            continue;
        }
        let raw_email = latest_user_message[start..end].trim();
        if raw_email.is_empty() || raw_email.parse::<Mailbox>().is_err() {
            continue;
        }
        sanitized_request.push_str(&latest_user_message[last_index..start]);
        let token = if let Some(existing) = email_tokens
            .iter()
            .find(|candidate| candidate.raw_value.eq_ignore_ascii_case(raw_email))
            .cloned()
        {
            existing
        } else {
            let token_id = format!("EMAIL_{}", email_tokens.len() + 1);
            let token = MailDraftToken {
                placeholder: mail_token_placeholder(&token_id),
                id: token_id,
                raw_value: raw_email.to_string(),
            };
            email_tokens.push(token.clone());
            replacement_tokens.push(token.clone());
            token
        };
        sanitized_request.push_str(&token.placeholder);
        last_index = end;
    }
    sanitized_request.push_str(&latest_user_message[last_index..]);

    if let Some(raw_email) = candidate_recipient
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(canonicalize_mail_recipient)
    {
        let already_present = email_tokens
            .iter()
            .any(|candidate| candidate.raw_value.eq_ignore_ascii_case(&raw_email));
        if !already_present {
            let token_id = format!("EMAIL_{}", email_tokens.len() + 1);
            let token = MailDraftToken {
                placeholder: mail_token_placeholder(&token_id),
                id: token_id,
                raw_value: raw_email,
            };
            email_tokens.push(token.clone());
            replacement_tokens.push(token);
        }
    }

    if email_tokens.is_empty() {
        return Err(TransactionError::Invalid(
            "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply could not derive any recipient email token from the latest user request".to_string(),
        ));
    }

    Ok(MailReplySynthesisContext {
        sanitized_request,
        email_tokens,
        replacement_tokens,
    })
}

fn build_mail_reply_synthesis_prompt(
    context: &MailReplySynthesisContext,
    sender_name_available: bool,
    reply_to_message_id: Option<&str>,
    candidate_payload_json: Option<&str>,
    validation_error: Option<&str>,
    previous_output_json: Option<&str>,
) -> Result<Vec<u8>, TransactionError> {
    let email_token_lines = context
        .email_tokens
        .iter()
        .map(|token| format!("- {}", token.id))
        .collect::<Vec<_>>();
    let payload = json!([
        {
            "role": "system",
            "content": "You synthesize a final outbound email draft for the mail.reply intent. Return exactly one JSON object with this schema: {\"to_token\":\"EMAIL_1\",\"subject\":\"...\",\"body\":\"...\",\"signoff\":null,\"signature_mode\":\"omit\"}. Rules: 1) to_token must equal one listed email token exactly. 2) subject must be final send-ready plain text. 3) body must contain only the actual message content; never include sender names or unresolved placeholders in body. 4) signoff must be null or a plain closing phrase like \"Best regards,\" and must not include a sender name. 5) signature_mode must be exactly \"sender_name\" only when sender_name_available=true and you want the local runtime to append the configured mailbox sender display name after signoff; otherwise use \"omit\". 6) Do not invent recipients, dates, or facts not present in the request. 7) You may mention listed email token placeholders in subject/body only when the user explicitly wants those values present. 8) Never output placeholders like [Your Name], [your-name], <REDACTED:email>, <REDACTED:name>, {{SENDER_NAME}}, or any other unresolved placeholder."
        },
        {
            "role": "user",
            "content": format!(
                "Request:\\n{}\\n\\nAvailable email tokens:\\n{}\\n\\nSender name available:\\n{}\\n\\nReply-to message id:\\n{}\\n\\nUpstream candidate draft:\\n{}\\n\\nCurrent draft lint issue:\\n{}\\n\\nPrevious invalid synthesis output:\\n{}",
                context.sanitized_request,
                email_token_lines.join("\n"),
                if sender_name_available { "true" } else { "false" },
                reply_to_message_id.unwrap_or("none"),
                candidate_payload_json.unwrap_or("none"),
                validation_error.unwrap_or("none"),
                previous_output_json.unwrap_or("none")
            )
        }
    ]);
    serde_json::to_vec(&payload).map_err(|e| {
        TransactionError::Serialization(format!(
            "mail reply synthesis prompt encoding failed: {}",
            e
        ))
    })
}

async fn synthesize_mail_reply_draft(
    service: &RuntimeAgentService,
    latest_user_message: &str,
    sender_display_name: Option<&str>,
    reply_to_message_id: Option<&str>,
    session_id: [u8; 32],
    candidate: Option<&MailReplyDraftCandidate>,
    validation_error: Option<&str>,
) -> Result<MailReplyDraft, TransactionError> {
    let runtime: &dyn InferenceRuntime = service.reasoning_inference.as_ref();
    let sender_display_name = sender_display_name
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let candidate_recipient = candidate
        .and_then(|candidate| candidate.to.as_deref())
        .and_then(canonicalize_mail_recipient);
    let context =
        build_mail_reply_synthesis_context(latest_user_message, candidate_recipient.as_deref())?;
    let candidate_payload_json = candidate.map(|candidate| {
        serde_json::to_string(&json!({
            "to": candidate.to,
            "subject": candidate.subject,
            "body": candidate.body,
        }))
        .unwrap_or_else(|_| "null".to_string())
    });
    let mut current_validation_error = validation_error.map(ToString::to_string);
    let mut previous_output_json = None::<String>;

    for attempt_idx in 0..MAIL_REPLY_SYNTHESIS_MAX_ATTEMPTS {
        let prompt = build_mail_reply_synthesis_prompt(
            &context,
            sender_display_name.is_some(),
            reply_to_message_id,
            candidate_payload_json.as_deref(),
            current_validation_error.as_deref(),
            previous_output_json.as_deref(),
        )?;
        let inference_input = service
            .prepare_cloud_inference_input(
                Some(session_id),
                "mail_reply_synthesis",
                MAIL_REPLY_SYNTHESIS_MODEL_ID,
                &prompt,
            )
            .await?;
        let output = runtime
            .execute_inference(
                [0u8; 32],
                &inference_input,
                InferenceOptions {
                    temperature: 0.0,
                    json_mode: true,
                    max_tokens: 512,
                    ..Default::default()
                },
            )
            .await
            .map_err(inference_vm_error_to_tx)?;
        let raw_output = String::from_utf8(output).map_err(|e| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=SynthesisFailed mail reply synthesis produced non-UTF8 output: {}",
                e
            ))
        })?;
        let parsed: Result<MailReplySynthesisOutput, TransactionError> =
            serde_json::from_str(raw_output.trim()).map_err(|e| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=SynthesisFailed mail reply synthesis returned invalid JSON: {}",
                    e
                ))
            });
        let draft = parsed.and_then(|parsed| {
            let to = context
                .email_tokens
                .iter()
                .find(|token| token.id == parsed.to_token.trim())
                .map(|token| token.raw_value.clone())
                .ok_or_else(|| {
                    TransactionError::Invalid(format!(
                        "ERROR_CLASS=SynthesisFailed mail reply synthesis selected unknown recipient token '{}'",
                        parsed.to_token.trim()
                    ))
                })?;
            let subject =
                rehydrate_mail_draft_text(&parsed.subject, &context.replacement_tokens)?;
            let body = assemble_mail_reply_body(
                rehydrate_mail_draft_text(&parsed.body, &context.replacement_tokens)?,
                parsed.signoff,
                parsed.signature_mode,
                sender_display_name,
            )?;
            Ok(MailReplyDraft { to, subject, body })
        });
        match draft {
            Ok(draft) => return Ok(draft),
            Err(error) if attempt_idx + 1 < MAIL_REPLY_SYNTHESIS_MAX_ATTEMPTS => {
                current_validation_error = Some(error.to_string());
                previous_output_json = Some(raw_output.trim().to_string());
            }
            Err(error) => return Err(error),
        }
    }

    Err(TransactionError::Invalid(
        "ERROR_CLASS=SynthesisFailed mail reply synthesis exhausted all correction attempts"
            .to_string(),
    ))
}
