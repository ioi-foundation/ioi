fn build_google_workspace_args(
    spec: &GoogleConnectorActionSpec,
    input: &Value,
) -> Result<Vec<String>, String> {
    match spec.id {
        "gmail.read_emails" => {
            let mut args = vec![
                "gmail".into(),
                "+triage".into(),
                "--max".into(),
                optional_u64(input, "max").unwrap_or(20).to_string(),
                "--format".into(),
                "json".into(),
            ];
            if let Some(query) = optional_string(input, "query") {
                args.push("--query".into());
                args.push(query);
            }
            if optional_bool(input, "includeLabels").unwrap_or(false) {
                args.push("--labels".into());
            }
            Ok(args)
        }
        "gmail.send_email" => {
            let mut args = vec![
                "gmail".into(),
                "+send".into(),
                "--to".into(),
                required_string(input, "to")?,
                "--subject".into(),
                required_string(input, "subject")?,
                "--body".into(),
                required_string(input, "body")?,
                "--format".into(),
                "json".into(),
            ];
            if let Some(thread_id) = optional_string(input, "threadId") {
                args.push("--thread-id".into());
                args.push(thread_id);
            }
            if let Some(in_reply_to) = optional_string(input, "inReplyTo") {
                args.push("--in-reply-to".into());
                args.push(in_reply_to);
            }
            if let Some(references) = optional_string(input, "references") {
                args.push("--references".into());
                args.push(references);
            }
            Ok(args)
        }
        "gmail.draft_email" => {
            let raw = build_gmail_raw_message(
                &required_string(input, "to")?,
                &required_string(input, "subject")?,
                &required_string(input, "body")?,
                optional_string(input, "inReplyTo").as_deref(),
                optional_string(input, "references").as_deref(),
            );
            let mut message = json!({ "raw": raw });
            if let Some(thread_id) = optional_string(input, "threadId") {
                message["threadId"] = Value::String(thread_id);
            }
            Ok(vec![
                "gmail".into(),
                "drafts".into(),
                "create".into(),
                "--params".into(),
                json!({ "userId": "me" }).to_string(),
                "--json".into(),
                json!({ "message": message }).to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "gmail.mark_as_read" => build_gmail_modify_args(
            required_string(input, "messageId")?,
            json!({ "removeLabelIds": ["UNREAD"] }),
        ),
        "gmail.archive_email" => build_gmail_modify_args(
            required_string(input, "messageId")?,
            json!({ "removeLabelIds": ["INBOX"] }),
        ),
        "gmail.apply_label" => {
            let labels = split_multivalue(&required_string(input, "labelIds")?);
            if labels.is_empty() {
                return Err("At least one Gmail label ID is required.".to_string());
            }
            build_gmail_modify_args(
                required_string(input, "messageId")?,
                json!({ "addLabelIds": labels }),
            )
        }
        "gmail.create_label" => Ok(vec![
            "gmail".into(),
            "users".into(),
            "labels".into(),
            "create".into(),
            "--params".into(),
            json!({ "userId": "me" }).to_string(),
            "--json".into(),
            json!({
                "name": required_string(input, "name")?,
                "messageListVisibility": optional_string(input, "messageListVisibility").unwrap_or_else(|| "show".to_string()),
                "labelListVisibility": optional_string(input, "labelListVisibility").unwrap_or_else(|| "labelShow".to_string())
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "gmail.get_thread" => Ok(vec![
            "gmail".into(),
            "users".into(),
            "threads".into(),
            "get".into(),
            "--params".into(),
            json!({
                "userId": "me",
                "id": required_string(input, "threadId")?,
                "format": optional_string(input, "format").unwrap_or_else(|| "full".to_string())
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "gmail.list_labels" => Ok(vec![
            "gmail".into(),
            "users".into(),
            "labels".into(),
            "list".into(),
            "--params".into(),
            json!({ "userId": "me" }).to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "gmail.watch_emails" => {
            let mut args = vec![
                "gmail".into(),
                "+watch".into(),
                "--max-messages".into(),
                optional_u64(input, "maxMessages").unwrap_or(10).to_string(),
                "--poll-interval".into(),
                optional_u64(input, "pollInterval").unwrap_or(5).to_string(),
                "--msg-format".into(),
                optional_string(input, "msgFormat").unwrap_or_else(|| "full".to_string()),
                "--format".into(),
                "json".into(),
            ];
            if let Some(project) = optional_string(input, "project") {
                args.push("--project".into());
                args.push(project);
            }
            if let Some(subscription) = optional_string(input, "subscription") {
                args.push("--subscription".into());
                args.push(subscription);
            }
            if let Some(topic) = optional_string(input, "topic") {
                args.push("--topic".into());
                args.push(topic);
            }
            if let Some(label_ids) = optional_string(input, "labelIds") {
                args.push("--label-ids".into());
                args.push(label_ids);
            }
            if optional_bool(input, "once").unwrap_or(true) {
                args.push("--once".into());
            }
            if optional_bool(input, "cleanup").unwrap_or(false) {
                args.push("--cleanup".into());
            }
            if let Some(output_dir) = optional_string(input, "outputDir") {
                args.push("--output-dir".into());
                args.push(output_dir);
            }
            Ok(args)
        }
        "bigquery.execute_query" => {
            let project_id = optional_string(input, "projectId")
                .or_else(default_google_project_id)
                .ok_or_else(|| {
                    "BigQuery projectId is required. Set `projectId`, `GOOGLE_CLOUD_PROJECT`, or `GOOGLE_WORKSPACE_PROJECT_ID`.".to_string()
                })?;
            let mut body = json!({
                "query": required_string(input, "query")?,
                "useLegacySql": optional_bool(input, "useLegacySql").unwrap_or(false),
                "maxResults": optional_u64(input, "maxResults").unwrap_or(100),
            });
            if let Some(location) = optional_string(input, "location") {
                body["location"] = Value::String(location);
            }
            Ok(vec![
                "bigquery:v2".into(),
                "jobs".into(),
                "query".into(),
                "--params".into(),
                json!({ "projectId": project_id }).to_string(),
                "--json".into(),
                body.to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "calendar.get_event" => Ok(vec![
            "calendar".into(),
            "events".into(),
            "get".into(),
            "--params".into(),
            json!({
                "calendarId": optional_string(input, "calendarId").unwrap_or_else(|| "primary".to_string()),
                "eventId": required_string(input, "eventId")?
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "calendar.list_events_for_date" => {
            let date = required_string(input, "date")?;
            let (time_min, time_max) = date_to_day_bounds(&date)?;
            Ok(vec![
                "calendar".into(),
                "events".into(),
                "list".into(),
                "--params".into(),
                json!({
                    "calendarId": optional_string(input, "calendarId").unwrap_or_else(|| "primary".to_string()),
                    "timeMin": time_min,
                    "timeMax": time_max,
                    "singleEvents": true,
                    "orderBy": "startTime",
                    "maxResults": optional_u64(input, "maxResults").unwrap_or(25)
                })
                .to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "calendar.create_event" => {
            let mut args = vec![
                "calendar".into(),
                "+insert".into(),
                "--calendar".into(),
                optional_string(input, "calendarId").unwrap_or_else(|| "primary".to_string()),
                "--summary".into(),
                required_string(input, "summary")?,
                "--start".into(),
                required_string(input, "start")?,
                "--end".into(),
                required_string(input, "end")?,
                "--format".into(),
                "json".into(),
            ];
            if let Some(location) = optional_string(input, "location") {
                args.push("--location".into());
                args.push(location);
            }
            if let Some(description) = optional_string(input, "description") {
                args.push("--description".into());
                args.push(description);
            }
            if let Some(attendees) = optional_string(input, "attendees") {
                for attendee in split_multivalue(&attendees) {
                    args.push("--attendee".into());
                    args.push(attendee);
                }
            }
            Ok(args)
        }
        "calendar.update_event" => {
            let calendar_id =
                optional_string(input, "calendarId").unwrap_or_else(|| "primary".to_string());
            let event_id = required_string(input, "eventId")?;
            let mut body = json!({});
            let mut changed = false;

            if let Some(summary) = optional_string(input, "summary") {
                body["summary"] = Value::String(summary);
                changed = true;
            }
            if let Some(start) = optional_string(input, "start") {
                body["start"] = json!({ "dateTime": start });
                changed = true;
            }
            if let Some(end) = optional_string(input, "end") {
                body["end"] = json!({ "dateTime": end });
                changed = true;
            }
            if let Some(location) = optional_string(input, "location") {
                body["location"] = Value::String(location);
                changed = true;
            }
            if let Some(description) = optional_string(input, "description") {
                body["description"] = Value::String(description);
                changed = true;
            }
            if let Some(attendees) = optional_string(input, "attendees") {
                body["attendees"] = Value::Array(
                    split_multivalue(&attendees)
                        .into_iter()
                        .map(|email| json!({ "email": email }))
                        .collect(),
                );
                changed = true;
            }

            if !changed {
                return Err("Provide at least one field to update.".to_string());
            }

            Ok(vec![
                "calendar".into(),
                "events".into(),
                "patch".into(),
                "--params".into(),
                json!({
                    "calendarId": calendar_id,
                    "eventId": event_id
                })
                .to_string(),
                "--json".into(),
                body.to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "calendar.delete_event" => Ok(vec![
            "calendar".into(),
            "events".into(),
            "delete".into(),
            "--params".into(),
            json!({
                "calendarId": optional_string(input, "calendarId").unwrap_or_else(|| "primary".to_string()),
                "eventId": required_string(input, "eventId")?
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "docs.create_document" => Ok(vec![
            "docs".into(),
            "documents".into(),
            "create".into(),
            "--json".into(),
            json!({ "title": required_string(input, "title")? }).to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "docs.read_document" => Ok(vec![
            "docs".into(),
            "documents".into(),
            "get".into(),
            "--params".into(),
            json!({ "documentId": required_string(input, "documentId")? }).to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "docs.append_text" => Ok(vec![
            "docs".into(),
            "+write".into(),
            "--document".into(),
            required_string(input, "documentId")?,
            "--text".into(),
            required_string(input, "text")?,
            "--format".into(),
            "json".into(),
        ]),
        "docs.replace_text" => Ok(vec![
            "docs".into(),
            "documents".into(),
            "batchUpdate".into(),
            "--params".into(),
            json!({ "documentId": required_string(input, "documentId")? }).to_string(),
            "--json".into(),
            json!({
                "requests": [{
                    "replaceAllText": {
                        "containsText": {
                            "text": required_string(input, "searchText")?,
                            "matchCase": optional_bool(input, "matchCase").unwrap_or(false)
                        },
                        "replaceText": required_string(input, "replaceText")?
                    }
                }]
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "sheets.read_range" => Ok(vec![
            "sheets".into(),
            "+read".into(),
            "--spreadsheet".into(),
            required_string(input, "spreadsheetId")?,
            "--range".into(),
            required_string(input, "range")?,
            "--format".into(),
            "json".into(),
        ]),
        "sheets.create_spreadsheet" => Ok(vec![
            "sheets".into(),
            "spreadsheets".into(),
            "create".into(),
            "--json".into(),
            json!({ "properties": { "title": required_string(input, "title")? } }).to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "sheets.write_range" => {
            let values = normalize_sheet_values(required_json_value(input, "valuesJson")?)?;
            Ok(vec![
                "sheets".into(),
                "spreadsheets".into(),
                "values".into(),
                "update".into(),
                "--params".into(),
                json!({
                    "spreadsheetId": required_string(input, "spreadsheetId")?,
                    "range": required_string(input, "range")?,
                    "valueInputOption": optional_string(input, "valueInputOption").unwrap_or_else(|| "USER_ENTERED".to_string())
                })
                .to_string(),
                "--json".into(),
                json!({ "values": values }).to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "sheets.append_rows" => Ok(vec![
            "sheets".into(),
            "+append".into(),
            "--spreadsheet".into(),
            required_string(input, "spreadsheetId")?,
            "--json-values".into(),
            normalize_sheet_values(required_json_value(input, "valuesJson")?)?.to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "sheets.clear_range" => Ok(vec![
            "sheets".into(),
            "spreadsheets".into(),
            "values".into(),
            "clear".into(),
            "--params".into(),
            json!({
                "spreadsheetId": required_string(input, "spreadsheetId")?,
                "range": required_string(input, "range")?
            })
            .to_string(),
            "--json".into(),
            "{}".into(),
            "--format".into(),
            "json".into(),
        ]),
        "sheets.get_spreadsheet" => {
            let mut params = json!({
                "spreadsheetId": required_string(input, "spreadsheetId")?,
                "includeGridData": optional_bool(input, "includeGridData").unwrap_or(false)
            });
            if let Some(ranges) = optional_string(input, "ranges") {
                params["ranges"] = Value::Array(
                    split_multivalue(&ranges)
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                );
            }
            Ok(vec![
                "sheets".into(),
                "spreadsheets".into(),
                "get".into(),
                "--params".into(),
                params.to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "drive.upload_file" => {
            let mut args = vec![
                "drive".into(),
                "+upload".into(),
                required_string(input, "filePath")?,
                "--format".into(),
                "json".into(),
            ];
            if let Some(parent_id) = optional_string(input, "parentId") {
                args.push("--parent".into());
                args.push(parent_id);
            }
            if let Some(name) = optional_string(input, "name") {
                args.push("--name".into());
                args.push(name);
            }
            Ok(args)
        }
        "drive.share_file" => Ok(vec![
            "drive".into(),
            "permissions".into(),
            "create".into(),
            "--params".into(),
            json!({
                "fileId": required_string(input, "fileId")?,
                "sendNotificationEmail": false
            })
            .to_string(),
            "--json".into(),
            json!({
                "role": optional_string(input, "role").unwrap_or_else(|| "reader".to_string()),
                "type": "user",
                "emailAddress": required_string(input, "email")?
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "tasks.list_tasks" => Ok(vec![
            "tasks".into(),
            "tasks".into(),
            "list".into(),
            "--params".into(),
            json!({
                "tasklist": optional_string(input, "tasklist").unwrap_or_else(|| "@default".to_string()),
                "showCompleted": optional_bool(input, "showCompleted").unwrap_or(false),
                "maxResults": optional_u64(input, "maxResults").unwrap_or(20)
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "tasks.create_task" => {
            let mut body = json!({ "title": required_string(input, "title")? });
            if let Some(notes) = optional_string(input, "notes") {
                body["notes"] = Value::String(notes);
            }
            if let Some(due) = optional_string(input, "due") {
                body["due"] = Value::String(due);
            }
            Ok(vec![
                "tasks".into(),
                "tasks".into(),
                "insert".into(),
                "--params".into(),
                json!({ "tasklist": optional_string(input, "tasklist").unwrap_or_else(|| "@default".to_string()) }).to_string(),
                "--json".into(),
                body.to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "chat.send_message" => Ok(vec![
            "chat".into(),
            "+send".into(),
            "--space".into(),
            required_string(input, "space")?,
            "--text".into(),
            required_string(input, "text")?,
            "--format".into(),
            "json".into(),
        ]),
        "workflow.standup_report" => Ok(vec![
            "workflow".into(),
            "+standup-report".into(),
            "--format".into(),
            "json".into(),
        ]),
        "workflow.meeting_prep" => {
            let mut args = vec![
                "workflow".into(),
                "+meeting-prep".into(),
                "--format".into(),
                "json".into(),
            ];
            if let Some(calendar) = optional_string(input, "calendar") {
                args.push("--calendar".into());
                args.push(calendar);
            }
            Ok(args)
        }
        "workflow.email_to_task" => {
            let mut args = vec![
                "workflow".into(),
                "+email-to-task".into(),
                "--message-id".into(),
                required_string(input, "messageId")?,
                "--format".into(),
                "json".into(),
            ];
            if let Some(tasklist) = optional_string(input, "tasklist") {
                args.push("--tasklist".into());
                args.push(tasklist);
            }
            Ok(args)
        }
        "workflow.weekly_digest" => Ok(vec![
            "workflow".into(),
            "+weekly-digest".into(),
            "--format".into(),
            "json".into(),
        ]),
        "workflow.file_announce" => {
            let mut args = vec![
                "workflow".into(),
                "+file-announce".into(),
                "--file-id".into(),
                required_string(input, "fileId")?,
                "--space".into(),
                required_string(input, "space")?,
                "--format".into(),
                "json".into(),
            ];
            if let Some(message) = optional_string(input, "message") {
                args.push("--message".into());
                args.push(message);
            }
            Ok(args)
        }
        "events.subscribe" => {
            let mut args = vec![
                "events".into(),
                "+subscribe".into(),
                "--max-messages".into(),
                optional_u64(input, "maxMessages").unwrap_or(10).to_string(),
                "--poll-interval".into(),
                optional_u64(input, "pollInterval").unwrap_or(5).to_string(),
                "--format".into(),
                "json".into(),
            ];
            if let Some(target) = optional_string(input, "target") {
                args.push("--target".into());
                args.push(target);
            }
            if let Some(event_types) = optional_string(input, "eventTypes") {
                args.push("--event-types".into());
                args.push(event_types);
            }
            if let Some(project) = optional_string(input, "project") {
                args.push("--project".into());
                args.push(project);
            }
            if let Some(subscription) = optional_string(input, "subscription") {
                args.push("--subscription".into());
                args.push(subscription);
            }
            if optional_bool(input, "once").unwrap_or(true) {
                args.push("--once".into());
            }
            if optional_bool(input, "cleanup").unwrap_or(false) {
                args.push("--cleanup".into());
            }
            if optional_bool(input, "noAck").unwrap_or(false) {
                args.push("--no-ack".into());
            }
            if let Some(output_dir) = optional_string(input, "outputDir") {
                args.push("--output-dir".into());
                args.push(output_dir);
            }
            Ok(args)
        }
        "events.renew" => {
            let mut args = vec![
                "events".into(),
                "+renew".into(),
                "--within".into(),
                optional_string(input, "within").unwrap_or_else(|| "1h".to_string()),
                "--format".into(),
                "json".into(),
            ];
            if optional_bool(input, "all").unwrap_or(false) {
                args.push("--all".into());
            } else {
                args.push("--name".into());
                args.push(required_string(input, "name")?);
            }
            Ok(args)
        }
        "expert.raw_request" => build_google_raw_request_args(input),
        other => Err(format!("Unsupported Google connector action '{}'", other)),
    }
}

fn build_google_raw_request_args(input: &Value) -> Result<Vec<String>, String> {
    let service = required_string(input, "service")?;
    let method = required_string(input, "method")?;
    let mut args = vec![service];

    if let Some(resource_path) = optional_string(input, "resourcePath") {
        for segment in split_resource_path(&resource_path) {
            args.push(segment);
        }
    }
    args.push(method);

    if let Some(params_json) = optional_json_string(input, "paramsJson")? {
        args.push("--params".into());
        args.push(params_json);
    }
    if let Some(body_json) = optional_json_string(input, "bodyJson")? {
        args.push("--json".into());
        args.push(body_json);
    }
    if let Some(upload_path) = optional_string(input, "uploadPath") {
        args.push("--upload".into());
        args.push(upload_path);
    }
    if optional_bool(input, "pageAll").unwrap_or(false) {
        args.push("--page-all".into());
        args.push("--page-limit".into());
        args.push(optional_u64(input, "pageLimit").unwrap_or(25).to_string());
        args.push("--page-delay-ms".into());
        args.push(
            optional_u64(input, "pageDelayMs")
                .unwrap_or(100)
                .to_string(),
        );
    }
    args.push("--format".into());
    args.push("json".into());
    Ok(args)
}

fn build_gmail_modify_args(message_id: String, body: Value) -> Result<Vec<String>, String> {
    Ok(vec![
        "gmail".into(),
        "users".into(),
        "messages".into(),
        "modify".into(),
        "--params".into(),
        json!({ "userId": "me", "id": message_id }).to_string(),
        "--json".into(),
        body.to_string(),
        "--format".into(),
        "json".into(),
    ])
}

async fn normalize_google_action_input(
    spec: &GoogleConnectorActionSpec,
    input: &Value,
) -> Result<Value, String> {
    let mut normalized = input.clone();
    match spec.id {
        "gmail.send_email" | "gmail.draft_email" => {
            let Some(raw_to) = input.get("to").and_then(Value::as_str) else {
                return Ok(normalized);
            };
            let resolved_to = resolve_google_mail_recipient(raw_to).await?;
            if let Some(object) = normalized.as_object_mut() {
                object.insert("to".to_string(), Value::String(resolved_to));
            }
        }
        _ => {}
    }
    Ok(normalized)
}

async fn resolve_google_mail_recipient(raw: &str) -> Result<String, String> {
    if let Some(canonical) = canonicalize_email_recipient(raw) {
        return Ok(canonical);
    }

    if !looks_like_connected_account_alias(raw, &["google", "gmail", "google workspace"]) {
        return Ok(raw.trim().to_string());
    }

    let auth = google_auth::access_context(&[]).await?;
    resolve_connected_account_alias(
        raw,
        auth.account_email.as_deref(),
        &["google", "gmail", "google workspace"],
    )
    .ok_or_else(|| {
            "Autopilot could not determine the connected Google account email. Use an explicit recipient address or reconnect the Google connector.".to_string()
        })
}

fn resolve_connected_account_alias(
    raw: &str,
    connected_account_email: Option<&str>,
    provider_terms: &[&str],
) -> Option<String> {
    if !looks_like_connected_account_alias(raw, provider_terms) {
        return None;
    }
    connected_account_email.and_then(canonicalize_email_recipient)
}

fn canonicalize_email_recipient(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let candidate =
        if trimmed.len() >= "mailto:".len() && trimmed[..7].eq_ignore_ascii_case("mailto:") {
            trimmed[7..]
                .split(['?', '#'])
                .next()
                .map(str::trim)
                .unwrap_or("")
        } else {
            trimmed
        };

    if candidate.is_empty() {
        return None;
    }

    candidate
        .parse::<Mailbox>()
        .ok()
        .map(|mailbox| mailbox.to_string())
}

fn normalize_alias_phrase(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn looks_like_connected_account_alias(raw: &str, provider_terms: &[&str]) -> bool {
    let normalized = normalize_alias_phrase(raw);
    if normalized.is_empty() {
        return false;
    }

    let generic_aliases = [
        "connected address",
        "my connected address",
        "your connected address",
        "connected email",
        "my connected email",
        "your connected email",
        "connected email address",
        "my connected email address",
        "your connected email address",
        "connected account",
        "my connected account",
        "your connected account",
        "connected account email",
        "my connected account email",
        "your connected account email",
    ];
    if generic_aliases.contains(&normalized.as_str()) {
        return true;
    }

    provider_terms.iter().any(|provider| {
        let provider = normalize_alias_phrase(provider);
        [
            format!("connected {} address", provider),
            format!("my connected {} address", provider),
            format!("your connected {} address", provider),
            format!("connected {} email", provider),
            format!("my connected {} email", provider),
            format!("your connected {} email", provider),
            format!("connected {} email address", provider),
            format!("my connected {} email address", provider),
            format!("your connected {} email address", provider),
            format!("connected {} account", provider),
            format!("my connected {} account", provider),
            format!("your connected {} account", provider),
            format!("connected {} account email", provider),
            format!("my connected {} account email", provider),
            format!("your connected {} account email", provider),
        ]
        .iter()
        .any(|candidate| candidate == &normalized)
    })
}

fn summarize_action(spec: &GoogleConnectorActionSpec, data: &Value, input: &Value) -> String {
    match spec.id {
        "gmail.read_emails" => {
            let count = data
                .as_array()
                .map(|items| items.len())
                .or_else(|| {
                    data.get("messages")
                        .and_then(Value::as_array)
                        .map(|items| items.len())
                })
                .unwrap_or(0);
            format!("Loaded {} Gmail messages.", count)
        }
        "gmail.send_email" => format!(
            "Sent Gmail message to {}.",
            input
                .get("to")
                .and_then(Value::as_str)
                .unwrap_or("recipient")
        ),
        "gmail.draft_email" => format!(
            "Created Gmail draft for {}.",
            input
                .get("to")
                .and_then(Value::as_str)
                .unwrap_or("recipient")
        ),
        "gmail.mark_as_read" => "Marked Gmail message as read.".to_string(),
        "gmail.archive_email" => "Archived Gmail message.".to_string(),
        "gmail.apply_label" => "Applied Gmail labels.".to_string(),
        "gmail.create_label" => format!(
            "Created Gmail label '{}'.",
            data.get("name")
                .and_then(Value::as_str)
                .or_else(|| input.get("name").and_then(Value::as_str))
                .unwrap_or("label")
        ),
        "gmail.get_thread" => {
            let count = data
                .get("messages")
                .and_then(Value::as_array)
                .map(|messages| messages.len())
                .unwrap_or(0);
            format!("Loaded Gmail thread with {} messages.", count)
        }
        "gmail.list_labels" => {
            let count = data
                .get("labels")
                .and_then(Value::as_array)
                .map(|labels| labels.len())
                .unwrap_or(0);
            format!("Loaded {} Gmail labels.", count)
        }
        "gmail.watch_emails" => "Initialized Gmail watch flow.".to_string(),
        "bigquery.execute_query" => {
            if is_bigquery_read_query(
                input
                    .get("query")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ) {
                let rows = data
                    .get("rows")
                    .and_then(Value::as_array)
                    .map(|items| items.len())
                    .unwrap_or(0);
                format!("Executed BigQuery read query and returned {} rows.", rows)
            } else {
                "Executed BigQuery mutation query.".to_string()
            }
        }
        "calendar.get_event" => {
            let summary = data
                .get("summary")
                .and_then(Value::as_str)
                .unwrap_or("event");
            format!("Loaded calendar event '{}'.", summary)
        }
        "calendar.list_events_for_date" => {
            let count = data
                .get("items")
                .and_then(Value::as_array)
                .map(|items| items.len())
                .unwrap_or(0);
            format!("Loaded {} calendar events for the selected date.", count)
        }
        "calendar.create_event" => format!(
            "Created calendar event '{}'.",
            data.get("summary")
                .and_then(Value::as_str)
                .or_else(|| input.get("summary").and_then(Value::as_str))
                .unwrap_or("event")
        ),
        "calendar.update_event" => "Updated calendar event.".to_string(),
        "calendar.delete_event" => "Deleted calendar event.".to_string(),
        "docs.create_document" => format!(
            "Created Google Doc '{}'.",
            data.get("title")
                .and_then(Value::as_str)
                .or_else(|| input.get("title").and_then(Value::as_str))
                .unwrap_or("document")
        ),
        "docs.read_document" => "Loaded Google Doc.".to_string(),
        "docs.append_text" => "Appended text to Google Doc.".to_string(),
        "docs.replace_text" => "Replaced text in Google Doc.".to_string(),
        "sheets.read_range" => "Loaded Google Sheets range.".to_string(),
        "sheets.create_spreadsheet" => format!(
            "Created Google Sheet '{}'.",
            data.get("properties")
                .and_then(|properties| properties.get("title"))
                .and_then(Value::as_str)
                .or_else(|| input.get("title").and_then(Value::as_str))
                .unwrap_or("spreadsheet")
        ),
        "sheets.write_range" => "Wrote values to Google Sheet.".to_string(),
        "sheets.append_rows" => "Appended rows to Google Sheet.".to_string(),
        "sheets.clear_range" => "Cleared Google Sheet range.".to_string(),
        "sheets.get_spreadsheet" => "Loaded Google Spreadsheet metadata.".to_string(),
        "drive.upload_file" => format!(
            "Uploaded Drive file '{}'.",
            data.get("name")
                .and_then(Value::as_str)
                .or_else(|| input.get("name").and_then(Value::as_str))
                .unwrap_or("file")
        ),
        "drive.share_file" => format!(
            "Shared Drive file with {}.",
            input
                .get("email")
                .and_then(Value::as_str)
                .unwrap_or("recipient")
        ),
        "tasks.list_tasks" => {
            let count = data
                .get("items")
                .and_then(Value::as_array)
                .map(|items| items.len())
                .unwrap_or(0);
            format!("Loaded {} Google Tasks.", count)
        }
        "tasks.create_task" => format!(
            "Created Google Task '{}'.",
            data.get("title")
                .and_then(Value::as_str)
                .or_else(|| input.get("title").and_then(Value::as_str))
                .unwrap_or("task")
        ),
        "chat.send_message" => "Sent Google Chat message.".to_string(),
        "workflow.standup_report" => "Generated standup report.".to_string(),
        "workflow.meeting_prep" => "Prepared meeting context.".to_string(),
        "workflow.email_to_task" => "Created task from email.".to_string(),
        "workflow.weekly_digest" => "Generated weekly digest.".to_string(),
        "workflow.file_announce" => "Announced file in Google Chat.".to_string(),
        "events.subscribe" => "Initialized Workspace Events subscription flow.".to_string(),
        "events.renew" => "Renewed Workspace Events subscription.".to_string(),
        "expert.raw_request" => "Executed Google expert raw request.".to_string(),
        _ => "Google connector action completed.".to_string(),
    }
}

async fn run_gws_command(
    args: &[String],
    timeout_secs: u64,
    required_scopes: &[&str],
) -> Result<GwsCommandOutput, String> {
    let stdout = google_api::run_google_command(args, timeout_secs, required_scopes).await?;
    Ok(GwsCommandOutput { stdout })
}

fn parse_jsonish_output(stdout: &str) -> Value {
    serde_json::from_str(stdout).unwrap_or_else(|_| {
        let parsed_lines = stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(serde_json::from_str::<Value>)
            .collect::<Result<Vec<_>, _>>();

        match parsed_lines {
            Ok(lines) if !lines.is_empty() => Value::Array(lines),
            _ => json!({ "stdout": stdout }),
        }
    })
}

fn parse_dynamic_arguments(raw_json: &Value) -> Value {
    match raw_json.get("arguments") {
        Some(Value::String(encoded)) => serde_json::from_str(encoded).unwrap_or_else(|_| json!({})),
        Some(value) => value.clone(),
        None => json!({}),
    }
}

fn build_gmail_raw_message(
    to: &str,
    subject: &str,
    body: &str,
    in_reply_to: Option<&str>,
    references: Option<&str>,
) -> String {
    let mut headers = vec![
        format!("To: {}", to.trim()),
        format!("Subject: {}", subject.trim()),
    ];
    if let Some(value) = in_reply_to.map(str::trim).filter(|value| !value.is_empty()) {
        headers.push(format!("In-Reply-To: {}", value));
    }
    if let Some(value) = references.map(str::trim).filter(|value| !value.is_empty()) {
        headers.push(format!("References: {}", value));
    }
    headers.push("Content-Type: text/plain; charset=UTF-8".to_string());
    let mime = format!("{}\r\n\r\n{}", headers.join("\r\n"), body);
    URL_SAFE_NO_PAD.encode(mime.as_bytes())
}

fn default_google_project_id() -> Option<String> {
    std::env::var("GOOGLE_CLOUD_PROJECT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GOOGLE_WORKSPACE_PROJECT_ID")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
}

fn required_string(input: &Value, key: &str) -> Result<String, String> {
    optional_string(input, key)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("'{}' is required.", key))
}

fn optional_string(input: &Value, key: &str) -> Option<String> {
    input
        .get(key)
        .and_then(Value::as_str)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn optional_bool(input: &Value, key: &str) -> Option<bool> {
    input.get(key).and_then(|value| match value {
        Value::Bool(value) => Some(*value),
        Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

fn optional_u64(input: &Value, key: &str) -> Option<u64> {
    input.get(key).and_then(|value| match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    })
}

fn required_json_value(input: &Value, key: &str) -> Result<Value, String> {
    let raw = required_string(input, key)?;
    serde_json::from_str::<Value>(&raw)
        .map_err(|error| format!("'{}' must be valid JSON: {}", key, error))
}

fn optional_json_string(input: &Value, key: &str) -> Result<Option<String>, String> {
    let Some(raw) = optional_string(input, key) else {
        return Ok(None);
    };
    let value = serde_json::from_str::<Value>(&raw)
        .map_err(|error| format!("'{}' must be valid JSON: {}", key, error))?;
    Ok(Some(value.to_string()))
}

fn split_multivalue(raw: &str) -> Vec<String> {
    raw.split(|ch| ch == ',' || ch == '\n')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn split_resource_path(raw: &str) -> Vec<String> {
    raw.split(|ch: char| ch.is_whitespace() || ch == '.' || ch == '/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn normalize_sheet_values(values: Value) -> Result<Value, String> {
    match values {
        Value::Array(rows) => {
            if rows.is_empty() {
                Ok(Value::Array(Vec::new()))
            } else if rows.iter().all(Value::is_array) {
                Ok(Value::Array(rows))
            } else {
                Ok(Value::Array(vec![Value::Array(rows)]))
            }
        }
        other => Err(format!(
            "Sheet values must be a JSON array or array of arrays, received {}.",
            other
        )),
    }
}

fn is_bigquery_read_query(query: &str) -> bool {
    let normalized = query
        .trim_start()
        .trim_start_matches(|ch: char| ch == '(')
        .trim_start()
        .to_ascii_lowercase();
    normalized.starts_with("select")
        || normalized.starts_with("with")
        || normalized.starts_with("show")
        || normalized.starts_with("describe")
        || normalized.starts_with("explain")
}

fn date_to_day_bounds(date: &str) -> Result<(String, String), String> {
    let format = time::format_description::parse("[year]-[month]-[day]")
        .map_err(|error| format!("Failed to build date parser: {}", error))?;
    let parsed = time::Date::parse(date, &format)
        .map_err(|error| format!("Invalid date '{}': {}", date, error))?;
    let start = parsed
        .with_hms(0, 0, 0)
        .map_err(|error| error.to_string())?;
    let end = start + TimeDuration::days(1);
    let start_rfc3339 = start
        .assume_utc()
        .format(&Rfc3339)
        .map_err(|error| error.to_string())?;
    let end_rfc3339 = end
        .assume_utc()
        .format(&Rfc3339)
        .map_err(|error| error.to_string())?;
    Ok((start_rfc3339, end_rfc3339))
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn command_timeout_secs_for_action(action_id: &str) -> u64 {
    match action_id {
        "gmail.watch_emails" | "events.subscribe" | "events.renew" => 300,
        _ => GWS_DEFAULT_TIMEOUT_SECS,
    }
}

