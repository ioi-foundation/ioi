use super::*;

pub async fn bootstrap_workspace_profile() -> Result<Value, String> {
    let auth = google_auth::access_context(&[]).await?;
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| format!("Failed to build Google bootstrap client: {}", error))?;

    let mut field_profiles = Map::new();
    let mut service_states = Map::new();
    let mut warnings = Vec::new();

    bootstrap_gmail_profile(
        &client,
        &auth.access_token,
        &auth.granted_scopes,
        &mut field_profiles,
        &mut service_states,
        &mut warnings,
    )
    .await;
    bootstrap_calendar_profile(
        &client,
        &auth.access_token,
        &auth.granted_scopes,
        &mut field_profiles,
        &mut service_states,
        &mut warnings,
    )
    .await;
    bootstrap_tasks_profile(
        &client,
        &auth.access_token,
        &auth.granted_scopes,
        &mut field_profiles,
        &mut service_states,
        &mut warnings,
    )
    .await;
    bootstrap_projects_profile(
        &client,
        &auth.access_token,
        &auth.granted_scopes,
        &mut field_profiles,
        &mut service_states,
        &mut warnings,
    )
    .await;
    bootstrap_static_service_states(&auth.granted_scopes, &mut service_states);

    Ok(json!({
        "accountEmail": auth.account_email,
        "grantedScopes": auth.granted_scopes,
        "fieldProfiles": field_profiles,
        "serviceStates": service_states,
        "warnings": warnings,
        "generatedAtUtc": OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default(),
    }))
}

pub(super) fn parse_google_command(args: &[String]) -> Result<ParsedGoogleCommand, String> {
    let Some((service, rest)) = args.split_first() else {
        return Err("Google command was empty.".to_string());
    };

    let mut path = Vec::new();
    let mut params = json!({});
    let mut body = None;
    let mut upload_path = None;
    let mut page_all = false;
    let mut page_limit = 25_u64;
    let mut page_delay_ms = 100_u64;
    let mut options: HashMap<String, Vec<String>> = HashMap::new();

    let mut idx = 0;
    while idx < rest.len() {
        let token = &rest[idx];
        if !token.starts_with("--") {
            path.push(token.clone());
            idx += 1;
            continue;
        }

        let key = token.trim_start_matches("--").to_string();
        let next = rest.get(idx + 1);
        match key.as_str() {
            "params" => {
                let raw = next.ok_or_else(|| "--params requires a JSON object.".to_string())?;
                params = serde_json::from_str(raw)
                    .map_err(|error| format!("Failed to parse --params JSON: {}", error))?;
                idx += 2;
            }
            "json" => {
                let raw = next.ok_or_else(|| "--json requires a JSON object.".to_string())?;
                body = Some(
                    serde_json::from_str(raw)
                        .map_err(|error| format!("Failed to parse --json payload: {}", error))?,
                );
                idx += 2;
            }
            "upload" => {
                let raw = next.ok_or_else(|| "--upload requires a file path.".to_string())?;
                upload_path = Some(raw.clone());
                idx += 2;
            }
            "page-all" => {
                page_all = true;
                idx += 1;
            }
            "page-limit" => {
                let raw = next.ok_or_else(|| "--page-limit requires a value.".to_string())?;
                page_limit = raw
                    .parse::<u64>()
                    .map_err(|error| format!("Invalid --page-limit '{}': {}", raw, error))?;
                idx += 2;
            }
            "page-delay-ms" => {
                let raw = next.ok_or_else(|| "--page-delay-ms requires a value.".to_string())?;
                page_delay_ms = raw
                    .parse::<u64>()
                    .map_err(|error| format!("Invalid --page-delay-ms '{}': {}", raw, error))?;
                idx += 2;
            }
            "format" => {
                idx += if next.is_some() { 2 } else { 1 };
            }
            _ => {
                if let Some(value) = next.filter(|value| !value.starts_with("--")) {
                    options.entry(key).or_default().push(value.clone());
                    idx += 2;
                } else {
                    options.entry(key).or_default().push("true".to_string());
                    idx += 1;
                }
            }
        }
    }

    Ok(ParsedGoogleCommand {
        service: service.to_ascii_lowercase(),
        path,
        params,
        body,
        upload_path,
        page_all,
        page_limit,
        page_delay_ms,
        options,
    })
}

async fn bootstrap_gmail_profile(
    client: &Client,
    access_token: &str,
    granted_scopes: &[String],
    field_profiles: &mut Map<String, Value>,
    service_states: &mut Map<String, Value>,
    warnings: &mut Vec<Value>,
) {
    let missing_scopes =
        google_auth::granted_scopes_missing(granted_scopes, &["gmail.readonly", "gmail.modify"]);
    if !missing_scopes.is_empty() {
        service_states.insert(
            "gmail".to_string(),
            service_state(
                "needs_scope",
                format!(
                    "Reconnect to grant Gmail access needed for labels, threads, and inbox triage."
                ),
                missing_scopes,
                None,
            ),
        );
        return;
    }

    match google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/users/me/labels", GMAIL_BASE_URL),
        None,
        None,
    )
    .await
    {
        Ok(response) => {
            let mut suggestions = value_array(response.get("labels"))
                .into_iter()
                .filter_map(|label| {
                    let id = label.get("id").and_then(Value::as_str)?.trim().to_string();
                    let name = label
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or(&id)
                        .trim()
                        .to_string();
                    let label_type = label
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    Some(option_entry(
                        if label_type.eq_ignore_ascii_case("system") {
                            format!("{} (system)", name)
                        } else {
                            name
                        },
                        id,
                    ))
                })
                .collect::<Vec<_>>();
            suggestions.sort_by(|left, right| {
                option_label(left)
                    .cmp(&option_label(right))
                    .then(option_value(right).cmp(&option_value(left)))
            });

            let default_value = suggestions
                .iter()
                .find(|option| option_value(option) == "INBOX")
                .map(option_value)
                .or_else(|| suggestions.first().map(option_value));

            insert_field_profile(
                field_profiles,
                "labelIds",
                default_value,
                Vec::new(),
                suggestions.clone(),
                Some(
                    "Autocomplete discovered Gmail labels instead of typing raw label IDs."
                        .to_string(),
                ),
                Some("chips".to_string()),
            );

            service_states.insert(
                "gmail".to_string(),
                service_state(
                    "ready",
                    format!(
                        "Discovered {} Gmail labels for this account.",
                        suggestions.len()
                    ),
                    Vec::new(),
                    Some(json!({ "labelCount": suggestions.len() })),
                ),
            );
        }
        Err(error) => {
            warnings.push(json!({
                "service": "gmail",
                "message": error
            }));
            service_states.insert(
                "gmail".to_string(),
                service_state(
                    "degraded",
                    "Google is connected, but Gmail labels could not be discovered automatically."
                        .to_string(),
                    Vec::new(),
                    Some(json!({ "error": error })),
                ),
            );
        }
    }
}

async fn bootstrap_calendar_profile(
    client: &Client,
    access_token: &str,
    granted_scopes: &[String],
    field_profiles: &mut Map<String, Value>,
    service_states: &mut Map<String, Value>,
    warnings: &mut Vec<Value>,
) {
    let missing_scopes =
        google_auth::granted_scopes_missing(granted_scopes, &["calendar.readonly", "calendar"]);
    if !missing_scopes.is_empty() {
        service_states.insert(
            "calendar".to_string(),
            service_state(
                "needs_scope",
                "Reconnect to grant Calendar access before scheduling or reading events."
                    .to_string(),
                missing_scopes,
                None,
            ),
        );
        return;
    }

    match google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/users/me/calendarList", CALENDAR_BASE_URL),
        Some(vec![("maxResults".to_string(), "100".to_string())]),
        None,
    )
    .await
    {
        Ok(response) => {
            let mut options = vec![option_entry("Primary calendar", "primary")];
            let mut discovered = value_array(response.get("items"))
                .into_iter()
                .filter_map(|calendar| {
                    let id = calendar
                        .get("id")
                        .and_then(Value::as_str)?
                        .trim()
                        .to_string();
                    let summary = calendar
                        .get("summary")
                        .and_then(Value::as_str)
                        .unwrap_or(&id)
                        .trim()
                        .to_string();
                    let primary = calendar
                        .get("primary")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    Some(option_entry(
                        if primary {
                            format!("{} (primary)", summary)
                        } else {
                            summary
                        },
                        id,
                    ))
                })
                .collect::<Vec<_>>();
            discovered.sort_by(|left, right| option_label(left).cmp(&option_label(right)));
            for option in discovered {
                let value = option_value(&option);
                if options
                    .iter()
                    .any(|existing| option_value(existing) == value)
                {
                    continue;
                }
                options.push(option);
            }

            let default_value = options
                .iter()
                .find(|option| option_value(option) == "primary")
                .map(option_value)
                .or_else(|| options.first().map(option_value));
            let description =
                Some("Use a discovered calendar instead of typing a raw calendar ID.".to_string());

            insert_field_profile(
                field_profiles,
                "calendarId",
                default_value.clone(),
                options.clone(),
                Vec::new(),
                description.clone(),
                Some("select".to_string()),
            );
            insert_field_profile(
                field_profiles,
                "calendar",
                default_value,
                options.clone(),
                Vec::new(),
                description,
                Some("select".to_string()),
            );

            service_states.insert(
                "calendar".to_string(),
                service_state(
                    "ready",
                    format!("Discovered {} calendars for this account.", options.len()),
                    Vec::new(),
                    Some(json!({ "calendarCount": options.len() })),
                ),
            );
        }
        Err(error) => {
            warnings.push(json!({
                "service": "calendar",
                "message": error
            }));
            service_states.insert(
                "calendar".to_string(),
                service_state(
                    "degraded",
                    "Google is connected, but calendar defaults could not be discovered."
                        .to_string(),
                    Vec::new(),
                    Some(json!({ "error": error })),
                ),
            );
        }
    }
}

async fn bootstrap_tasks_profile(
    client: &Client,
    access_token: &str,
    granted_scopes: &[String],
    field_profiles: &mut Map<String, Value>,
    service_states: &mut Map<String, Value>,
    warnings: &mut Vec<Value>,
) {
    let missing_scopes =
        google_auth::granted_scopes_missing(granted_scopes, &["tasks.readonly", "tasks"]);
    if !missing_scopes.is_empty() {
        service_states.insert(
            "tasks".to_string(),
            service_state(
                "needs_scope",
                "Reconnect to grant Google Tasks access before listing or creating follow-ups."
                    .to_string(),
                missing_scopes,
                None,
            ),
        );
        return;
    }

    match google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/users/@me/lists", TASKS_BASE_URL),
        Some(vec![("maxResults".to_string(), "100".to_string())]),
        None,
    )
    .await
    {
        Ok(response) => {
            let mut options = vec![option_entry("Default task list", "@default")];
            let mut discovered = value_array(response.get("items"))
                .into_iter()
                .filter_map(|tasklist| {
                    let id = tasklist
                        .get("id")
                        .and_then(Value::as_str)?
                        .trim()
                        .to_string();
                    let title = tasklist
                        .get("title")
                        .and_then(Value::as_str)
                        .unwrap_or(&id)
                        .trim()
                        .to_string();
                    Some(option_entry(title, id))
                })
                .collect::<Vec<_>>();
            discovered.sort_by(|left, right| option_label(left).cmp(&option_label(right)));
            options.extend(discovered);

            insert_field_profile(
                field_profiles,
                "tasklist",
                Some("@default".to_string()),
                options.clone(),
                Vec::new(),
                Some(
                    "Choose a discovered task list instead of typing the task list ID manually."
                        .to_string(),
                ),
                Some("select".to_string()),
            );

            service_states.insert(
                "tasks".to_string(),
                service_state(
                    "ready",
                    format!("Discovered {} Google Task lists.", options.len()),
                    Vec::new(),
                    Some(json!({ "taskListCount": options.len() })),
                ),
            );
        }
        Err(error) => {
            warnings.push(json!({
                "service": "tasks",
                "message": error
            }));
            service_states.insert(
                "tasks".to_string(),
                service_state(
                    "degraded",
                    "Google is connected, but task lists could not be discovered automatically."
                        .to_string(),
                    Vec::new(),
                    Some(json!({ "error": error })),
                ),
            );
        }
    }
}

async fn bootstrap_projects_profile(
    client: &Client,
    access_token: &str,
    granted_scopes: &[String],
    field_profiles: &mut Map<String, Value>,
    service_states: &mut Map<String, Value>,
    warnings: &mut Vec<Value>,
) {
    let env_project = default_google_project_id();
    let missing_scopes =
        google_auth::granted_scopes_missing(granted_scopes, &["cloud-platform", "bigquery"]);
    if !missing_scopes.is_empty() {
        service_states.insert(
            "bigquery".to_string(),
            service_state(
                "needs_scope",
                "Reconnect to grant BigQuery or Cloud Platform access before running queries."
                    .to_string(),
                missing_scopes.clone(),
                Some(json!({ "defaultProjectId": env_project })),
            ),
        );
        service_states.insert(
            "events".to_string(),
            service_state(
                "needs_scope",
                "Reconnect to grant Pub/Sub, Cloud project, and chat event read access before starting durable event streams."
                    .to_string(),
                google_auth::granted_scopes_missing(
                    granted_scopes,
                    &["pubsub", "cloud-platform", "chat.messages.readonly"],
                ),
                Some(json!({ "defaultProjectId": env_project })),
            ),
        );
        return;
    }

    let mut options = Vec::new();
    if let Some(project_id) = env_project.clone() {
        options.push(option_entry(
            format!("Default project ({})", project_id),
            project_id,
        ));
    }

    match google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/projects", BIGQUERY_BASE_URL),
        Some(vec![("maxResults".to_string(), "50".to_string())]),
        None,
    )
    .await
    {
        Ok(response) => {
            let mut discovered = value_array(response.get("projects"))
                .into_iter()
                .filter_map(|project| {
                    let project_id = project
                        .get("projectReference")
                        .and_then(|reference| reference.get("projectId"))
                        .and_then(Value::as_str)
                        .or_else(|| project.get("id").and_then(Value::as_str))?
                        .trim()
                        .to_string();
                    let name = project
                        .get("friendlyName")
                        .and_then(Value::as_str)
                        .unwrap_or(&project_id)
                        .trim()
                        .to_string();
                    Some(option_entry(name, project_id))
                })
                .collect::<Vec<_>>();
            discovered.sort_by(|left, right| option_label(left).cmp(&option_label(right)));
            for option in discovered {
                let value = option_value(&option);
                if options
                    .iter()
                    .any(|existing| option_value(existing) == value)
                {
                    continue;
                }
                options.push(option);
            }
        }
        Err(error) => {
            warnings.push(json!({
                "service": "projects",
                "message": error
            }));
        }
    }

    if !options.is_empty() {
        let default_value = env_project.or_else(|| options.first().map(option_value));
        let description = Some(
            "Select a discovered Google Cloud project instead of typing a raw project ID."
                .to_string(),
        );
        for field_id in ["projectId", "project"] {
            insert_field_profile(
                field_profiles,
                field_id,
                default_value.clone(),
                options.clone(),
                Vec::new(),
                description.clone(),
                Some("select".to_string()),
            );
        }
        service_states.insert(
            "bigquery".to_string(),
            service_state(
                "ready",
                format!(
                    "{} Google Cloud projects are available for BigQuery defaults.",
                    options.len()
                ),
                Vec::new(),
                Some(json!({ "projectCount": options.len(), "defaultProjectId": default_value })),
            ),
        );
        let event_missing = google_auth::granted_scopes_missing(
            granted_scopes,
            &["pubsub", "cloud-platform", "chat.messages.readonly"],
        );
        service_states.insert(
            "events".to_string(),
            if event_missing.is_empty() {
                service_state(
                    "ready",
                    "Event automation is ready once you choose a Workspace target resource."
                        .to_string(),
                    Vec::new(),
                    Some(json!({ "projectCount": options.len(), "defaultProjectId": default_value })),
                )
            } else {
                service_state(
                    "needs_scope",
                    "Reconnect to grant Pub/Sub, Cloud project, and chat event read access before running durable event streams."
                        .to_string(),
                    event_missing,
                    Some(json!({ "projectCount": options.len(), "defaultProjectId": default_value })),
                )
            },
        );
    } else {
        let event_missing = google_auth::granted_scopes_missing(
            granted_scopes,
            &["pubsub", "cloud-platform", "chat.messages.readonly"],
        );
        service_states.insert(
            "bigquery".to_string(),
            service_state(
                "manual_input",
                "BigQuery is connected, but you still need to choose or type a project ID."
                    .to_string(),
                Vec::new(),
                Some(json!({ "defaultProjectId": env_project })),
            ),
        );
        service_states.insert(
            "events".to_string(),
            if event_missing.is_empty() {
                service_state(
                    "manual_input",
                    "Event automation is connected, but you still need a project and target resource."
                        .to_string(),
                    Vec::new(),
                    Some(json!({ "defaultProjectId": env_project })),
                )
            } else {
                service_state(
                    "needs_scope",
                    "Reconnect to grant Pub/Sub, Cloud project, and chat event read access before starting durable event streams."
                        .to_string(),
                    event_missing,
                    Some(json!({ "defaultProjectId": env_project })),
                )
            },
        );
    }
}

fn bootstrap_static_service_states(
    granted_scopes: &[String],
    service_states: &mut Map<String, Value>,
) {
    for (service, required_scopes, ready_summary, manual_summary) in [
        (
            "docs",
            vec!["documents"],
            "Docs actions are ready for document creation and editing.",
            "Reconnect to grant Docs access before editing documents.",
        ),
        (
            "sheets",
            vec!["spreadsheets"],
            "Sheets actions are ready for reads and writes.",
            "Reconnect to grant Sheets access before reading or editing spreadsheets.",
        ),
        (
            "drive",
            vec!["drive"],
            "Drive actions are ready for uploads and sharing.",
            "Reconnect to grant Drive access before uploading or sharing files.",
        ),
        (
            "chat",
            vec!["chat.messages.create"],
            "Chat is ready, but you still choose the destination space when sending messages.",
            "Reconnect to grant Google Chat access before sending messages.",
        ),
    ] {
        if service_states.contains_key(service) {
            continue;
        }
        let missing = google_auth::granted_scopes_missing(granted_scopes, &required_scopes);
        service_states.insert(
            service.to_string(),
            if missing.is_empty() {
                service_state("ready", ready_summary.to_string(), Vec::new(), None)
            } else {
                service_state("needs_scope", manual_summary.to_string(), missing, None)
            },
        );
    }

    let workflow_missing = google_auth::granted_scopes_missing(
        granted_scopes,
        &["gmail.readonly", "calendar.readonly", "tasks"],
    );
    service_states.insert(
        "workflow".to_string(),
        if workflow_missing.is_empty() {
            service_state(
                "ready",
                "Cross-service workflows are ready to use Gmail, Calendar, Tasks, and Chat defaults."
                    .to_string(),
                Vec::new(),
                None,
            )
        } else {
            service_state(
                "manual_input",
                "Workflow recipes are available, but some dependent Google services still need scopes."
                    .to_string(),
                workflow_missing,
                None,
            )
        },
    );
}

fn insert_field_profile(
    profiles: &mut Map<String, Value>,
    field_id: &str,
    default_value: Option<String>,
    options: Vec<Value>,
    suggestions: Vec<Value>,
    description: Option<String>,
    input_mode: Option<String>,
) {
    let mut profile = Map::new();
    if let Some(default_value) = default_value {
        profile.insert("defaultValue".to_string(), Value::String(default_value));
    }
    if !options.is_empty() {
        profile.insert("options".to_string(), Value::Array(options));
    }
    if !suggestions.is_empty() {
        profile.insert("suggestions".to_string(), Value::Array(suggestions));
    }
    if let Some(description) = description {
        profile.insert("description".to_string(), Value::String(description));
    }
    if let Some(input_mode) = input_mode {
        profile.insert("inputMode".to_string(), Value::String(input_mode));
    }
    profiles.insert(field_id.to_string(), Value::Object(profile));
}

fn service_state(
    status: &str,
    summary: String,
    missing_scopes: Vec<String>,
    details: Option<Value>,
) -> Value {
    let mut state = Map::new();
    state.insert("status".to_string(), Value::String(status.to_string()));
    state.insert("summary".to_string(), Value::String(summary));
    if !missing_scopes.is_empty() {
        state.insert(
            "missingScopes".to_string(),
            Value::Array(missing_scopes.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(details) = details {
        state.insert("details".to_string(), details);
    }
    Value::Object(state)
}

fn option_entry(label: impl Into<String>, value: impl Into<String>) -> Value {
    json!({
        "label": label.into(),
        "value": value.into(),
    })
}

fn option_label(option: &Value) -> String {
    option
        .get("label")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn option_value(option: &Value) -> String {
    option
        .get("value")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

pub(super) fn default_google_project_id() -> Option<String> {
    std::env::var("GOOGLE_CLOUD_PROJECT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GOOGLE_WORKSPACE_PROJECT_ID")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
}
