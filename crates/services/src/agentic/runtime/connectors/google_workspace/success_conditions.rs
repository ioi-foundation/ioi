fn extract_first_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in raw[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '{' {
            brace_depth = brace_depth.saturating_add(1);
            continue;
        }
        if ch == '}' {
            brace_depth = brace_depth.saturating_sub(1);
            if brace_depth == 0 {
                let end = start + idx + 1;
                return Some(raw[start..end].to_string());
            }
        }
    }
    None
}

fn parse_json_payload_from_history(history_entry: &str) -> Option<Value> {
    extract_first_json_object(history_entry)
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
}

fn expected_mailbox_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter_map(canonicalize_email_recipient)
        .collect::<Vec<_>>()
}

fn gmail_to_header_matches(actual_to: Option<&str>, expected_to: &str) -> bool {
    let Some(actual_to) = actual_to else {
        return false;
    };
    let expected = canonicalize_email_recipient(expected_to)
        .unwrap_or_else(|| expected_to.trim().to_ascii_lowercase());
    expected_mailbox_list(actual_to)
        .into_iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(&expected))
}

fn gmail_body_matches(actual_body: Option<&str>, expected_body: &str) -> bool {
    actual_body
        .map(|body| body.trim() == expected_body.trim())
        .unwrap_or(false)
}

fn verify_google_success_conditions_boxed<'a>(
    agent_state: &'a AgentState,
    tool_name: &'a str,
    tool_args: &'a Value,
    history_entry: &'a str,
) -> SuccessConditionVerificationFuture<'a> {
    Box::pin(async move {
        let normalized = tool_name.trim().to_ascii_lowercase();
        let (message_id, required_label) = match normalized.as_str() {
            "connector__google__gmail_draft_email" => {
                let payload = parse_json_payload_from_history(history_entry).ok_or_else(|| {
                    "Google draft verification could not parse structured action output."
                        .to_string()
                })?;
                (
                    payload
                        .get("message")
                        .and_then(|message| message.get("id"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| {
                            "Google draft verification payload was missing message.id.".to_string()
                        })?,
                    "DRAFT",
                )
            }
            "connector__google__gmail_send_email" => {
                let payload = parse_json_payload_from_history(history_entry).ok_or_else(|| {
                    "Google send verification could not parse structured action output.".to_string()
                })?;
                (
                    payload
                        .get("id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| {
                            "Google send verification payload was missing message id.".to_string()
                        })?,
                    "SENT",
                )
            }
            _ => return Ok(None),
        };

        let expected_to = tool_args.get("to").and_then(Value::as_str).ok_or_else(|| {
            "Google mail verification requires a grounded `to` argument.".to_string()
        })?;
        let expected_subject = tool_args
            .get("subject")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "Google mail verification requires a grounded `subject` argument.".to_string()
            })?;
        let expected_body = tool_args
            .get("body")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "Google mail verification requires a grounded `body` argument.".to_string()
            })?;
        let readback = google_api::gmail_readback_message(&message_id).await?;
        let to_match = gmail_to_header_matches(readback.to.as_deref(), expected_to);
        let subject_match = readback
            .subject
            .as_deref()
            .map(|actual| actual.trim() == expected_subject.trim())
            .unwrap_or(false);
        let body_match = gmail_body_matches(readback.body_text.as_deref(), expected_body);
        let label_match = readback
            .label_ids
            .iter()
            .any(|label| label.eq_ignore_ascii_case(required_label));
        if !(to_match && subject_match && body_match && label_match) {
            return Err(format!(
                "ERROR_CLASS=PostconditionFailed Google mail verification failed. message_id={} to_match={} subject_match={} body_match={} label_match={}",
                readback.message_id, to_match, subject_match, body_match, label_match
            ));
        }

        Ok(Some(ConnectorSuccessConditionProof {
            evidence: vec![ConnectorSuccessConditionEvidence {
                key: "mail.reply.completed".to_string(),
                evidence: format!(
                    "message_id={};thread_id={};label={};to={};subject={}",
                    readback.message_id,
                    readback.thread_id.unwrap_or_default(),
                    required_label,
                    expected_to,
                    expected_subject
                ),
                observed_value: Some(readback.message_id),
                evidence_type: Some("gmail_readback".to_string()),
                provider_id: google_selected_provider_id(agent_state),
            }],
        }))
    })
}

pub fn google_connector_success_condition_verifier_bindings(
) -> Vec<ConnectorSuccessConditionVerifierBinding> {
    vec![ConnectorSuccessConditionVerifierBinding {
        connector_id: GOOGLE_CONNECTOR_ID,
        verify: verify_google_success_conditions_boxed,
    }]
}

pub fn is_google_duplicate_safe_tool_name(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "connector__google__gmail_read_emails"
            | "connector__google__gmail_get_thread"
            | "connector__google__gmail_list_labels"
            | "connector__google__calendar_get_event"
            | "connector__google__calendar_list_events_for_date"
            | "connector__google__docs_read_document"
            | "connector__google__sheets_read_range"
            | "connector__google__sheets_get_spreadsheet"
            | "connector__google__tasks_list_tasks"
            | "connector__google__workflow_standup_report"
            | "connector__google__workflow_meeting_prep"
            | "connector__google__workflow_weekly_digest"
    )
}

pub fn google_read_policy_targets() -> Vec<String> {
    let mut targets = google_connector_action_specs()
        .into_iter()
        .filter(|spec| {
            spec.kind == "read"
                || matches!(
                    spec.tool_name,
                    "connector__google__workflow_standup_report"
                        | "connector__google__workflow_meeting_prep"
                        | "connector__google__workflow_weekly_digest"
                )
        })
        .map(|spec| spec.tool_name.to_string())
        .collect::<Vec<_>>();
    targets.push(BIGQUERY_READ_TARGET.to_string());
    targets
}

pub fn google_dynamic_tool_target(raw_json: &Value) -> Option<ActionTarget> {
    let name = raw_json.get("name").and_then(Value::as_str)?;
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty() || !is_google_connector_tool_name(&normalized) {
        return None;
    }

    if normalized == BIGQUERY_TOOL_NAME {
        let arguments = parse_dynamic_arguments(raw_json);
        let query = arguments
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let label = if is_bigquery_read_query(query) {
            BIGQUERY_READ_TARGET
        } else {
            BIGQUERY_WRITE_TARGET
        };
        return Some(ActionTarget::Custom(label.to_string()));
    }

    Some(ActionTarget::Custom(normalized))
}

