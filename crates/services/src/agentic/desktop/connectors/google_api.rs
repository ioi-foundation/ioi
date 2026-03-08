use super::google_auth;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use reqwest::{header, Client, Method};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::time::{sleep, timeout, Duration};

const GMAIL_BASE_URL: &str = "https://gmail.googleapis.com/gmail/v1";
const CALENDAR_BASE_URL: &str = "https://www.googleapis.com/calendar/v3";
const DOCS_BASE_URL: &str = "https://docs.googleapis.com/v1";
const SHEETS_BASE_URL: &str = "https://sheets.googleapis.com/v4";
const DRIVE_BASE_URL: &str = "https://www.googleapis.com/drive/v3";
const DRIVE_UPLOAD_BASE_URL: &str = "https://www.googleapis.com/upload/drive/v3";
const TASKS_BASE_URL: &str = "https://tasks.googleapis.com/tasks/v1";
const CHAT_BASE_URL: &str = "https://chat.googleapis.com/v1";
const BIGQUERY_BASE_URL: &str = "https://bigquery.googleapis.com/bigquery/v2";
const PUBSUB_BASE_URL: &str = "https://pubsub.googleapis.com/v1";
const WORKSPACE_EVENTS_BASE_URL: &str = "https://workspaceevents.googleapis.com/v1";

#[derive(Debug, Clone)]
pub struct GmailMessageReadback {
    pub message_id: String,
    pub thread_id: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub body_text: Option<String>,
    pub label_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct ParsedGoogleCommand {
    service: String,
    path: Vec<String>,
    params: Value,
    body: Option<Value>,
    upload_path: Option<String>,
    page_all: bool,
    page_limit: u64,
    page_delay_ms: u64,
    options: HashMap<String, Vec<String>>,
}

pub async fn run_google_command(
    args: &[String],
    timeout_secs: u64,
    required_scopes: &[&str],
) -> Result<String, String> {
    let parsed = parse_google_command(args)?;
    let future = async move {
        let auth = google_auth::access_context(required_scopes).await?;
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|error| format!("Failed to build Google API client: {}", error))?;
        let data = execute_google_command(&client, &auth.access_token, parsed).await?;
        serde_json::to_string_pretty(&data)
            .map_err(|error| format!("Failed to serialize Google API response: {}", error))
    };

    timeout(Duration::from_secs(timeout_secs), future)
        .await
        .map_err(|_| {
            format!(
                "Timed out waiting for Google API request after {} seconds.",
                timeout_secs
            )
        })?
}

pub async fn gmail_readback_message(message_id: &str) -> Result<GmailMessageReadback, String> {
    let auth = google_auth::access_context(&["gmail.readonly", "gmail.modify"]).await?;
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| format!("Failed to build Google API client: {}", error))?;
    let message = gmail_get_message(
        &client,
        &auth.access_token,
        message_id,
        "full",
        Some("To,Subject"),
    )
    .await?;
    let headers = gmail_header_map(&message);
    let label_ids = value_array(message.get("labelIds"))
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    Ok(GmailMessageReadback {
        message_id: message
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or(message_id)
            .to_string(),
        thread_id: message
            .get("threadId")
            .and_then(Value::as_str)
            .map(str::to_string),
        to: headers.get("to").cloned(),
        subject: headers.get("subject").cloned(),
        body_text: gmail_plaintext_body(&message),
        label_ids,
    })
}

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

fn parse_google_command(args: &[String]) -> Result<ParsedGoogleCommand, String> {
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
                    let label_type = label.get("type").and_then(Value::as_str).unwrap_or_default();
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
                Some("Autocomplete discovered Gmail labels instead of typing raw label IDs.".to_string()),
                Some("chips".to_string()),
            );

            service_states.insert(
                "gmail".to_string(),
                service_state(
                    "ready",
                    format!("Discovered {} Gmail labels for this account.", suggestions.len()),
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
                    let id = calendar.get("id").and_then(Value::as_str)?.trim().to_string();
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
                if options.iter().any(|existing| option_value(existing) == value) {
                    continue;
                }
                options.push(option);
            }

            let default_value = options
                .iter()
                .find(|option| option_value(option) == "primary")
                .map(option_value)
                .or_else(|| options.first().map(option_value));
            let description = Some(
                "Use a discovered calendar instead of typing a raw calendar ID.".to_string(),
            );

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
                    let id = tasklist.get("id").and_then(Value::as_str)?.trim().to_string();
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
                Some("Choose a discovered task list instead of typing the task list ID manually."
                    .to_string()),
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
        options.push(option_entry(format!("Default project ({})", project_id), project_id));
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
                if options.iter().any(|existing| option_value(existing) == value) {
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
        let description =
            Some("Select a discovered Google Cloud project instead of typing a raw project ID."
                .to_string());
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
                format!("{} Google Cloud projects are available for BigQuery defaults.", options.len()),
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

async fn execute_google_command(
    client: &Client,
    access_token: &str,
    command: ParsedGoogleCommand,
) -> Result<Value, String> {
    match (command.service.as_str(), command.path.first().map(String::as_str)) {
        ("gmail", Some("+triage")) => execute_gmail_triage(client, access_token, &command).await,
        ("gmail", Some("+send")) => execute_gmail_send(client, access_token, &command).await,
        ("gmail", Some("+watch")) => execute_gmail_watch(client, access_token, &command).await,
        ("calendar", Some("+insert")) => {
            execute_calendar_insert(client, access_token, &command).await
        }
        ("docs", Some("+write")) => execute_docs_append(client, access_token, &command).await,
        ("sheets", Some("+read")) => execute_sheets_read(client, access_token, &command).await,
        ("sheets", Some("+append")) => execute_sheets_append(client, access_token, &command).await,
        ("drive", Some("+upload")) => execute_drive_upload(client, access_token, &command).await,
        ("chat", Some("+send")) => execute_chat_send(client, access_token, &command).await,
        ("workflow", Some("+standup-report")) => {
            execute_workflow_standup_report(client, access_token).await
        }
        ("workflow", Some("+meeting-prep")) => {
            execute_workflow_meeting_prep(client, access_token, &command).await
        }
        ("workflow", Some("+email-to-task")) => {
            execute_workflow_email_to_task(client, access_token, &command).await
        }
        ("workflow", Some("+weekly-digest")) => {
            execute_workflow_weekly_digest(client, access_token).await
        }
        ("workflow", Some("+file-announce")) => {
            execute_workflow_file_announce(client, access_token, &command).await
        }
        ("events", Some("+subscribe")) => {
            execute_workspace_events_subscribe(client, access_token, &command).await
        }
        ("events", Some("+renew")) => {
            execute_workspace_events_renew(client, access_token, &command).await
        }
        _ => execute_google_raw_command(client, access_token, &command).await,
    }
}

async fn execute_gmail_triage(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let max_results = option_u64(command, "max").unwrap_or(20);
    let mut query = vec![
        ("userId".to_string(), "me".to_string()),
        ("maxResults".to_string(), max_results.to_string()),
    ];
    if let Some(value) = option_string(command, "query") {
        query.push(("q".to_string(), value));
    }

    let list = google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/users/me/messages", GMAIL_BASE_URL),
        Some(query),
        None,
    )
    .await?;

    let include_labels = option_bool(command, "labels").unwrap_or(false);
    let mut messages = Vec::new();
    for message in value_array(list.get("messages")).into_iter().take(max_results as usize) {
        let message_id = message
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| "Gmail list response was missing a message ID.".to_string())?;
        let detail = gmail_get_message(
            client,
            access_token,
            message_id,
            "metadata",
            Some("From,Subject,Date"),
        )
        .await?;
        let headers = gmail_header_map(&detail);
        let mut entry = Map::new();
        entry.insert("id".to_string(), Value::String(message_id.to_string()));
        entry.insert(
            "threadId".to_string(),
            detail
                .get("threadId")
                .cloned()
                .unwrap_or(Value::Null),
        );
        entry.insert(
            "from".to_string(),
            headers
                .get("from")
                .cloned()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        entry.insert(
            "subject".to_string(),
            headers
                .get("subject")
                .cloned()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        entry.insert(
            "date".to_string(),
            headers
                .get("date")
                .cloned()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        entry.insert(
            "snippet".to_string(),
            detail.get("snippet").cloned().unwrap_or(Value::Null),
        );
        entry.insert(
            "preview".to_string(),
            detail.get("snippet").cloned().unwrap_or(Value::Null),
        );
        if include_labels {
            entry.insert(
                "labelIds".to_string(),
                detail
                    .get("labelIds")
                    .cloned()
                    .unwrap_or_else(|| Value::Array(Vec::new())),
            );
        }
        messages.push(Value::Object(entry));
    }

    Ok(json!({ "messages": messages }))
}

async fn execute_gmail_send(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let raw = build_gmail_raw_message(
        &required_option(command, "to")?,
        &required_option(command, "subject")?,
        &required_option(command, "body")?,
    );
    google_json_request(
        client,
        access_token,
        Method::POST,
        &format!("{}/users/me/messages/send", GMAIL_BASE_URL),
        Some(vec![("userId".to_string(), "me".to_string())]),
        Some(json!({ "raw": raw })),
    )
    .await
}

async fn execute_gmail_watch(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let topic_name = if let Some(topic) = option_string(command, "topic") {
        normalize_pubsub_topic_name(option_string(command, "project"), topic)?
    } else {
        let project = option_string(command, "project")
            .ok_or_else(|| "Gmail watch requires either `topic` or `project`.".to_string())?;
        let topic = format!("autopilot-gmail-watch-{}", short_timestamp_suffix());
        let full = normalize_pubsub_topic_name(Some(project.clone()), topic)?;
        ensure_pubsub_topic(client, access_token, &full).await?;
        full
    };

    let project_for_subscription = option_string(command, "project")
        .or_else(|| google_project_from_pubsub_resource(&topic_name, "topics"));
    let subscription_name = if let Some(subscription) = option_string(command, "subscription") {
        normalize_pubsub_subscription_name(project_for_subscription.clone(), subscription)?
    } else {
        let project = project_for_subscription.ok_or_else(|| {
            "Gmail watch requires `project` or a fully-qualified `topic` name to create the Pub/Sub subscription."
                .to_string()
        })?;
        normalize_pubsub_subscription_name(
            Some(project),
            format!("autopilot-gmail-watch-{}", short_timestamp_suffix()),
        )?
    };
    ensure_pubsub_subscription(client, access_token, &subscription_name, &topic_name).await?;

    let mut body = json!({ "topicName": topic_name });
    if let Some(label_ids) = option_string(command, "label-ids") {
        body["labelIds"] = Value::Array(
            split_csv_like(&label_ids)
                .into_iter()
                .map(Value::String)
                .collect(),
        );
    }

    let watch = google_json_request(
        client,
        access_token,
        Method::POST,
        &format!("{}/users/me/watch", GMAIL_BASE_URL),
        Some(vec![("userId".to_string(), "me".to_string())]),
        Some(body),
    )
    .await?;

    Ok(json!({
        "watch": watch,
        "subscription": subscription_name,
        "topic": topic_name,
        "streaming": {
            "once": option_bool(command, "once").unwrap_or(true),
            "pollIntervalSeconds": option_u64(command, "poll-interval").unwrap_or(5),
            "outputDir": option_string(command, "output-dir"),
            "note": "Native Google watch setup completed. Continuous local streaming is not persisted by the connector runtime."
        }
    }))
}

async fn execute_calendar_insert(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let calendar_id = required_option(command, "calendar")?;
    let mut body = json!({
        "summary": required_option(command, "summary")?,
        "start": { "dateTime": required_option(command, "start")? },
        "end": { "dateTime": required_option(command, "end")? }
    });
    if let Some(location) = option_string(command, "location") {
        body["location"] = Value::String(location);
    }
    if let Some(description) = option_string(command, "description") {
        body["description"] = Value::String(description);
    }
    let attendees = option_values(command, "attendee")
        .into_iter()
        .map(|email| json!({ "email": email }))
        .collect::<Vec<_>>();
    if !attendees.is_empty() {
        body["attendees"] = Value::Array(attendees);
    }
    google_json_request(
        client,
        access_token,
        Method::POST,
        &format!("{}/calendars/{}/events", CALENDAR_BASE_URL, url_encode(&calendar_id)),
        None,
        Some(body),
    )
    .await
}

async fn execute_docs_append(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let document_id = required_option(command, "document")?;
    let text = required_option(command, "text")?;
    let document = google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/documents/{}", DOCS_BASE_URL, url_encode(&document_id)),
        None,
        None,
    )
    .await?;
    let end_index = docs_document_end_index(&document);
    google_json_request(
        client,
        access_token,
        Method::POST,
        &format!(
            "{}/documents/{}:batchUpdate",
            DOCS_BASE_URL,
            url_encode(&document_id)
        ),
        None,
        Some(json!({
            "requests": [{
                "insertText": {
                    "location": { "index": end_index },
                    "text": text
                }
            }]
        })),
    )
    .await
}

async fn execute_sheets_read(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let spreadsheet_id = required_option(command, "spreadsheet")?;
    let range = required_option(command, "range")?;
    google_json_request(
        client,
        access_token,
        Method::GET,
        &format!(
            "{}/spreadsheets/{}/values/{}",
            SHEETS_BASE_URL,
            url_encode(&spreadsheet_id),
            url_encode(&range)
        ),
        None,
        None,
    )
    .await
}

async fn execute_sheets_append(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let spreadsheet_id = required_option(command, "spreadsheet")?;
    let values_raw = required_option(command, "json-values")?;
    let values = serde_json::from_str::<Value>(&values_raw)
        .map_err(|error| format!("Invalid --json-values payload: {}", error))?;
    let range = option_string(command, "range").unwrap_or_else(|| "Sheet1".to_string());
    google_json_request(
        client,
        access_token,
        Method::POST,
        &format!(
            "{}/spreadsheets/{}/values/{}:append",
            SHEETS_BASE_URL,
            url_encode(&spreadsheet_id),
            url_encode(&range)
        ),
        Some(vec![
            ("valueInputOption".to_string(), "USER_ENTERED".to_string()),
            ("insertDataOption".to_string(), "INSERT_ROWS".to_string()),
        ]),
        Some(json!({ "values": values })),
    )
    .await
}

async fn execute_drive_upload(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let file_path = command
        .path
        .get(1)
        .cloned()
        .ok_or_else(|| "Drive upload requires a file path.".to_string())?;
    let bytes = fs::read(&file_path)
        .map_err(|error| format!("Failed to read Drive upload file '{}': {}", file_path, error))?;
    let file_name = option_string(command, "name").unwrap_or_else(|| {
        Path::new(&file_path)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("upload.bin")
            .to_string()
    });
    let mut metadata = json!({ "name": file_name });
    if let Some(parent) = option_string(command, "parent") {
        metadata["parents"] = Value::Array(vec![Value::String(parent)]);
    }
    google_drive_multipart_upload(client, access_token, metadata, bytes).await
}

async fn execute_chat_send(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let space = required_option(command, "space")?;
    let text = required_option(command, "text")?;
    google_json_request(
        client,
        access_token,
        Method::POST,
        &format!("{}/{}/messages", CHAT_BASE_URL, space.trim_matches('/')),
        None,
        Some(json!({ "text": text })),
    )
    .await
}

async fn execute_workflow_standup_report(
    client: &Client,
    access_token: &str,
) -> Result<Value, String> {
    let date = today_ymd();
    let unread = execute_gmail_triage(
        client,
        access_token,
        &ParsedGoogleCommand {
            service: "gmail".to_string(),
            path: vec!["+triage".to_string()],
            params: json!({}),
            body: None,
            upload_path: None,
            page_all: false,
            page_limit: 25,
            page_delay_ms: 100,
            options: HashMap::from([
                ("max".to_string(), vec!["10".to_string()]),
                ("query".to_string(), vec!["is:unread newer_than:7d".to_string()]),
            ]),
        },
    )
    .await?;
    let calendar = google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/calendars/primary/events", CALENDAR_BASE_URL),
        Some(vec![
            ("timeMin".to_string(), day_start_rfc3339(&date)?),
            ("timeMax".to_string(), day_end_rfc3339(&date)?),
            ("singleEvents".to_string(), "true".to_string()),
            ("orderBy".to_string(), "startTime".to_string()),
            ("maxResults".to_string(), "10".to_string()),
        ]),
        None,
    )
    .await?;
    let tasks = google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/lists/@default/tasks", TASKS_BASE_URL),
        Some(vec![
            ("showCompleted".to_string(), "false".to_string()),
            ("maxResults".to_string(), "10".to_string()),
        ]),
        None,
    )
    .await?;

    Ok(json!({
        "generatedAtUtc": now_rfc3339(),
        "calendarDate": date,
        "unreadMessages": unread.get("messages").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "todayEvents": calendar.get("items").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "openTasks": tasks.get("items").cloned().unwrap_or_else(|| Value::Array(Vec::new()))
    }))
}

async fn execute_workflow_meeting_prep(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let calendar_id = option_string(command, "calendar").unwrap_or_else(|| "primary".to_string());
    let now = now_rfc3339();
    let events = google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/calendars/{}/events", CALENDAR_BASE_URL, url_encode(&calendar_id)),
        Some(vec![
            ("timeMin".to_string(), now),
            ("singleEvents".to_string(), "true".to_string()),
            ("orderBy".to_string(), "startTime".to_string()),
            ("maxResults".to_string(), "3".to_string()),
        ]),
        None,
    )
    .await?;
    let next_event = value_array(events.get("items")).into_iter().next().unwrap_or(Value::Null);
    let unread = execute_gmail_triage(
        client,
        access_token,
        &ParsedGoogleCommand {
            service: "gmail".to_string(),
            path: vec!["+triage".to_string()],
            params: json!({}),
            body: None,
            upload_path: None,
            page_all: false,
            page_limit: 25,
            page_delay_ms: 100,
            options: HashMap::from([
                ("max".to_string(), vec!["5".to_string()]),
                ("query".to_string(), vec!["is:unread newer_than:3d".to_string()]),
            ]),
        },
    )
    .await?;
    Ok(json!({
        "generatedAtUtc": now_rfc3339(),
        "nextEvent": next_event,
        "recentUnreadMessages": unread.get("messages").cloned().unwrap_or_else(|| Value::Array(Vec::new()))
    }))
}

async fn execute_workflow_email_to_task(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let message_id = required_option(command, "message-id")?;
    let tasklist = option_string(command, "tasklist").unwrap_or_else(|| "@default".to_string());
    let message = gmail_get_message(client, access_token, &message_id, "metadata", Some("From,Subject,Date"))
        .await?;
    let headers = gmail_header_map(&message);
    let title = headers
        .get("subject")
        .cloned()
        .unwrap_or_else(|| "Follow up email".to_string());
    let notes = format!(
        "From: {}\nDate: {}\nSnippet: {}\nMessage ID: {}",
        headers.get("from").cloned().unwrap_or_default(),
        headers.get("date").cloned().unwrap_or_default(),
        message.get("snippet").and_then(Value::as_str).unwrap_or_default(),
        message_id
    );
    let task = google_json_request(
        client,
        access_token,
        Method::POST,
        &format!("{}/lists/{}/tasks", TASKS_BASE_URL, url_encode(&tasklist)),
        None,
        Some(json!({
            "title": title,
            "notes": notes
        })),
    )
    .await?;

    Ok(json!({
        "message": message,
        "task": task
    }))
}

async fn execute_workflow_weekly_digest(
    client: &Client,
    access_token: &str,
) -> Result<Value, String> {
    let now = OffsetDateTime::now_utc();
    let start = now - TimeDuration::days(7);
    let events = google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/calendars/primary/events", CALENDAR_BASE_URL),
        Some(vec![
            ("timeMin".to_string(), format_time(start)),
            ("timeMax".to_string(), format_time(now)),
            ("singleEvents".to_string(), "true".to_string()),
            ("orderBy".to_string(), "startTime".to_string()),
            ("maxResults".to_string(), "25".to_string()),
        ]),
        None,
    )
    .await?;
    let mail = execute_gmail_triage(
        client,
        access_token,
        &ParsedGoogleCommand {
            service: "gmail".to_string(),
            path: vec!["+triage".to_string()],
            params: json!({}),
            body: None,
            upload_path: None,
            page_all: false,
            page_limit: 25,
            page_delay_ms: 100,
            options: HashMap::from([
                ("max".to_string(), vec!["15".to_string()]),
                ("query".to_string(), vec!["newer_than:7d".to_string()]),
            ]),
        },
    )
    .await?;
    Ok(json!({
        "generatedAtUtc": now_rfc3339(),
        "windowStartUtc": format_time(start),
        "windowEndUtc": format_time(now),
        "calendarEvents": events.get("items").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "recentMessages": mail.get("messages").cloned().unwrap_or_else(|| Value::Array(Vec::new()))
    }))
}

async fn execute_workflow_file_announce(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let file_id = required_option(command, "file-id")?;
    let space = required_option(command, "space")?;
    let file = google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/files/{}", DRIVE_BASE_URL, url_encode(&file_id)),
        Some(vec![(
            "fields".to_string(),
            "id,name,webViewLink,webContentLink,mimeType".to_string(),
        )]),
        None,
    )
    .await?;
    let name = file
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("file");
    let link = file
        .get("webViewLink")
        .and_then(Value::as_str)
        .or_else(|| file.get("webContentLink").and_then(Value::as_str))
        .unwrap_or_default();
    let prefix = option_string(command, "message").unwrap_or_default();
    let text = if prefix.trim().is_empty() {
        format!("Shared file: {} {}", name, link)
    } else {
        format!("{}\n\n{} {}", prefix, name, link)
    };
    let message = google_json_request(
        client,
        access_token,
        Method::POST,
        &format!("{}/{}/messages", CHAT_BASE_URL, space.trim_matches('/')),
        None,
        Some(json!({ "text": text })),
    )
    .await?;
    Ok(json!({
        "file": file,
        "message": message
    }))
}

async fn execute_workspace_events_subscribe(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let project = option_string(command, "project")
        .or_else(default_google_project_id)
        .ok_or_else(|| "Workspace Events subscribe requires `project` or GOOGLE_CLOUD_PROJECT.".to_string())?;
    let topic_name = normalize_pubsub_topic_name(
        Some(project.clone()),
        format!("autopilot-workspace-events-{}", short_timestamp_suffix()),
    )?;
    let subscription_name = normalize_pubsub_subscription_name(
        Some(project.clone()),
        option_string(command, "subscription")
            .unwrap_or_else(|| format!("autopilot-workspace-events-{}", short_timestamp_suffix())),
    )?;
    ensure_pubsub_topic(client, access_token, &topic_name).await?;
    ensure_pubsub_subscription(client, access_token, &subscription_name, &topic_name).await?;

    let target = required_option(command, "target")?;
    let event_types = split_csv_like(&required_option(command, "event-types")?);
    if event_types.is_empty() {
        return Err("Workspace Events subscribe requires at least one event type.".to_string());
    }

    let create = google_json_request(
        client,
        access_token,
        Method::POST,
        &format!("{}/subscriptions", WORKSPACE_EVENTS_BASE_URL),
        None,
        Some(json!({
            "targetResource": target,
            "eventTypes": event_types,
            "notificationEndpoint": { "pubsubTopic": topic_name },
            "payloadOptions": {
                "includeResource": false
            },
            "ttl": "86400s"
        })),
    )
    .await?;
    let subscription = workspace_events_wait_for_subscription_operation(client, access_token, &create).await?;

    Ok(json!({
        "subscription": subscription,
        "pubsubTopic": topic_name,
        "pubsubSubscription": subscription_name,
        "streaming": {
            "once": option_bool(command, "once").unwrap_or(true),
            "pollIntervalSeconds": option_u64(command, "poll-interval").unwrap_or(5),
            "outputDir": option_string(command, "output-dir"),
            "note": "Native Workspace Events subscription created. Local pull-loop persistence is not yet implemented."
        }
    }))
}

async fn execute_workspace_events_renew(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    if option_bool(command, "all").unwrap_or(false) {
        let listed = google_json_request(
            client,
            access_token,
            Method::GET,
            &format!("{}/subscriptions", WORKSPACE_EVENTS_BASE_URL),
            None,
            None,
        )
        .await?;
        let mut renewed = Vec::new();
        for subscription in value_array(listed.get("subscriptions")) {
            if let Some(name) = subscription.get("name").and_then(Value::as_str) {
                let operation = google_json_request(
                    client,
                    access_token,
                    Method::POST,
                    &format!(
                        "{}/{}:reactivate",
                        WORKSPACE_EVENTS_BASE_URL,
                        name.trim_start_matches("subscriptions/")
                    ),
                    None,
                    Some(json!({})),
                )
                .await?;
                renewed.push(workspace_events_wait_for_subscription_operation(
                    client,
                    access_token,
                    &operation,
                )
                .await?);
            }
        }
        return Ok(json!({ "subscriptions": renewed }));
    }

    let name = required_option(command, "name")?;
    let operation = google_json_request(
        client,
        access_token,
        Method::POST,
        &format!(
            "{}/{}:reactivate",
            WORKSPACE_EVENTS_BASE_URL,
            name.trim_start_matches("subscriptions/")
        ),
        None,
        Some(json!({})),
    )
    .await?;
    workspace_events_wait_for_subscription_operation(client, access_token, &operation).await
}

async fn execute_google_raw_command(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    match command.service.as_str() {
        "gmail" => execute_gmail_raw_command(client, access_token, command).await,
        "calendar" => execute_calendar_raw_command(client, access_token, command).await,
        "docs" => execute_docs_raw_command(client, access_token, command).await,
        "sheets" => execute_sheets_raw_command(client, access_token, command).await,
        "drive" => execute_drive_raw_command(client, access_token, command).await,
        "tasks" => execute_tasks_raw_command(client, access_token, command).await,
        "chat" => execute_chat_raw_command(client, access_token, command).await,
        "bigquery:v2" | "bigquery" => execute_bigquery_raw_command(client, access_token, command).await,
        "workspaceevents:v1" | "workspaceevents" | "events:v1" => {
            execute_workspace_events_raw_command(client, access_token, command).await
        }
        "pubsub:v1" | "pubsub" => execute_pubsub_raw_command(client, access_token, command).await,
        other => Err(format!("Unsupported native Google service '{}'.", other)),
    }
}

async fn execute_gmail_raw_command(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let path = command.path.iter().map(String::as_str).collect::<Vec<_>>();
    let mut params = object_map(command.params.clone())?;
    match path.as_slice() {
        ["users", "labels", "list"] => {
            let user = take_string(&mut params, "userId").unwrap_or_else(|| "me".to_string());
            google_json_request(
                client,
                access_token,
                Method::GET,
                &format!("{}/users/{}/labels", GMAIL_BASE_URL, url_encode(&user)),
                Some(map_to_query_pairs(params)),
                None,
            )
            .await
        }
        ["users", "labels", "create"] => {
            let user = take_string(&mut params, "userId").unwrap_or_else(|| "me".to_string());
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!("{}/users/{}/labels", GMAIL_BASE_URL, url_encode(&user)),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        ["users", "threads", "get"] => {
            let user = take_string(&mut params, "userId").unwrap_or_else(|| "me".to_string());
            let id = take_string(&mut params, "id")
                .ok_or_else(|| "gmail.users.threads.get requires `id`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::GET,
                &format!(
                    "{}/users/{}/threads/{}",
                    GMAIL_BASE_URL,
                    url_encode(&user),
                    url_encode(&id)
                ),
                Some(map_to_query_pairs(params)),
                None,
            )
            .await
        }
        ["users", "messages", "modify"] => {
            let user = take_string(&mut params, "userId").unwrap_or_else(|| "me".to_string());
            let id = take_string(&mut params, "id")
                .ok_or_else(|| "gmail.users.messages.modify requires `id`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!(
                    "{}/users/{}/messages/{}/modify",
                    GMAIL_BASE_URL,
                    url_encode(&user),
                    url_encode(&id)
                ),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        ["users", "messages", "send"] => {
            let user = take_string(&mut params, "userId").unwrap_or_else(|| "me".to_string());
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!("{}/users/{}/messages/send", GMAIL_BASE_URL, url_encode(&user)),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        ["drafts", "create"] | ["users", "drafts", "create"] => {
            let user = take_string(&mut params, "userId").unwrap_or_else(|| "me".to_string());
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!("{}/users/{}/drafts", GMAIL_BASE_URL, url_encode(&user)),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        ["users", "watch"] => {
            let user = take_string(&mut params, "userId").unwrap_or_else(|| "me".to_string());
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!("{}/users/{}/watch", GMAIL_BASE_URL, url_encode(&user)),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        _ => Err(format!(
            "Unsupported native Gmail command path '{}'.",
            command.path.join(" ")
        )),
    }
}

async fn execute_calendar_raw_command(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let path = command.path.iter().map(String::as_str).collect::<Vec<_>>();
    let mut params = object_map(command.params.clone())?;
    match path.as_slice() {
        ["events", "get"] => {
            let calendar_id = take_string(&mut params, "calendarId")
                .ok_or_else(|| "calendar.events.get requires `calendarId`.".to_string())?;
            let event_id = take_string(&mut params, "eventId")
                .ok_or_else(|| "calendar.events.get requires `eventId`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::GET,
                &format!(
                    "{}/calendars/{}/events/{}",
                    CALENDAR_BASE_URL,
                    url_encode(&calendar_id),
                    url_encode(&event_id)
                ),
                Some(map_to_query_pairs(params)),
                None,
            )
            .await
        }
        ["events", "list"] => {
            let calendar_id = take_string(&mut params, "calendarId")
                .ok_or_else(|| "calendar.events.list requires `calendarId`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::GET,
                &format!(
                    "{}/calendars/{}/events",
                    CALENDAR_BASE_URL,
                    url_encode(&calendar_id)
                ),
                Some(map_to_query_pairs(params)),
                None,
            )
            .await
        }
        ["events", "patch"] => {
            let calendar_id = take_string(&mut params, "calendarId")
                .ok_or_else(|| "calendar.events.patch requires `calendarId`.".to_string())?;
            let event_id = take_string(&mut params, "eventId")
                .ok_or_else(|| "calendar.events.patch requires `eventId`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::PATCH,
                &format!(
                    "{}/calendars/{}/events/{}",
                    CALENDAR_BASE_URL,
                    url_encode(&calendar_id),
                    url_encode(&event_id)
                ),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        ["events", "delete"] => {
            let calendar_id = take_string(&mut params, "calendarId")
                .ok_or_else(|| "calendar.events.delete requires `calendarId`.".to_string())?;
            let event_id = take_string(&mut params, "eventId")
                .ok_or_else(|| "calendar.events.delete requires `eventId`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::DELETE,
                &format!(
                    "{}/calendars/{}/events/{}",
                    CALENDAR_BASE_URL,
                    url_encode(&calendar_id),
                    url_encode(&event_id)
                ),
                Some(map_to_query_pairs(params)),
                None,
            )
            .await
        }
        _ => Err(format!(
            "Unsupported native Calendar command path '{}'.",
            command.path.join(" ")
        )),
    }
}

async fn execute_docs_raw_command(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let path = command.path.iter().map(String::as_str).collect::<Vec<_>>();
    let mut params = object_map(command.params.clone())?;
    match path.as_slice() {
        ["documents", "create"] => {
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!("{}/documents", DOCS_BASE_URL),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        ["documents", "get"] => {
            let document_id = take_string(&mut params, "documentId")
                .ok_or_else(|| "docs.documents.get requires `documentId`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::GET,
                &format!("{}/documents/{}", DOCS_BASE_URL, url_encode(&document_id)),
                Some(map_to_query_pairs(params)),
                None,
            )
            .await
        }
        ["documents", "batchUpdate"] => {
            let document_id = take_string(&mut params, "documentId")
                .ok_or_else(|| "docs.documents.batchUpdate requires `documentId`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!(
                    "{}/documents/{}:batchUpdate",
                    DOCS_BASE_URL,
                    url_encode(&document_id)
                ),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        _ => Err(format!(
            "Unsupported native Docs command path '{}'.",
            command.path.join(" ")
        )),
    }
}

async fn execute_sheets_raw_command(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let path = command.path.iter().map(String::as_str).collect::<Vec<_>>();
    let mut params = object_map(command.params.clone())?;
    match path.as_slice() {
        ["spreadsheets", "create"] => {
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!("{}/spreadsheets", SHEETS_BASE_URL),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        ["spreadsheets", "get"] => {
            let spreadsheet_id = take_string(&mut params, "spreadsheetId")
                .ok_or_else(|| "sheets.spreadsheets.get requires `spreadsheetId`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::GET,
                &format!(
                    "{}/spreadsheets/{}",
                    SHEETS_BASE_URL,
                    url_encode(&spreadsheet_id)
                ),
                Some(map_to_query_pairs(params)),
                None,
            )
            .await
        }
        ["spreadsheets", "values", "update"] => {
            let spreadsheet_id = take_string(&mut params, "spreadsheetId")
                .ok_or_else(|| "sheets.values.update requires `spreadsheetId`.".to_string())?;
            let range = take_string(&mut params, "range")
                .ok_or_else(|| "sheets.values.update requires `range`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::PUT,
                &format!(
                    "{}/spreadsheets/{}/values/{}",
                    SHEETS_BASE_URL,
                    url_encode(&spreadsheet_id),
                    url_encode(&range)
                ),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        ["spreadsheets", "values", "append"] => {
            let spreadsheet_id = take_string(&mut params, "spreadsheetId")
                .ok_or_else(|| "sheets.values.append requires `spreadsheetId`.".to_string())?;
            let range = take_string(&mut params, "range")
                .ok_or_else(|| "sheets.values.append requires `range`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!(
                    "{}/spreadsheets/{}/values/{}:append",
                    SHEETS_BASE_URL,
                    url_encode(&spreadsheet_id),
                    url_encode(&range)
                ),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        ["spreadsheets", "values", "clear"] => {
            let spreadsheet_id = take_string(&mut params, "spreadsheetId")
                .ok_or_else(|| "sheets.values.clear requires `spreadsheetId`.".to_string())?;
            let range = take_string(&mut params, "range")
                .ok_or_else(|| "sheets.values.clear requires `range`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!(
                    "{}/spreadsheets/{}/values/{}:clear",
                    SHEETS_BASE_URL,
                    url_encode(&spreadsheet_id),
                    url_encode(&range)
                ),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        _ => Err(format!(
            "Unsupported native Sheets command path '{}'.",
            command.path.join(" ")
        )),
    }
}

async fn execute_drive_raw_command(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let path = command.path.iter().map(String::as_str).collect::<Vec<_>>();
    let mut params = object_map(command.params.clone())?;
    match path.as_slice() {
        ["permissions", "create"] => {
            let file_id = take_string(&mut params, "fileId")
                .ok_or_else(|| "drive.permissions.create requires `fileId`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!(
                    "{}/files/{}/permissions",
                    DRIVE_BASE_URL,
                    url_encode(&file_id)
                ),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        ["files", "get"] => {
            let file_id = take_string(&mut params, "fileId")
                .ok_or_else(|| "drive.files.get requires `fileId`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::GET,
                &format!("{}/files/{}", DRIVE_BASE_URL, url_encode(&file_id)),
                Some(map_to_query_pairs(params)),
                None,
            )
            .await
        }
        ["files", "create"] if command.upload_path.is_some() => {
            let metadata = command.body.clone().unwrap_or_else(|| json!({}));
            let upload_path = command
                .upload_path
                .clone()
                .ok_or_else(|| "drive.files.create upload requires `uploadPath`.".to_string())?;
            let bytes = fs::read(&upload_path).map_err(|error| {
                format!("Failed to read Drive upload file '{}': {}", upload_path, error)
            })?;
            google_drive_multipart_upload(client, access_token, metadata, bytes).await
        }
        _ => Err(format!(
            "Unsupported native Drive command path '{}'.",
            command.path.join(" ")
        )),
    }
}

async fn execute_tasks_raw_command(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let path = command.path.iter().map(String::as_str).collect::<Vec<_>>();
    let mut params = object_map(command.params.clone())?;
    match path.as_slice() {
        ["tasks", "list"] => {
            let tasklist = take_string(&mut params, "tasklist")
                .ok_or_else(|| "tasks.tasks.list requires `tasklist`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::GET,
                &format!("{}/lists/{}/tasks", TASKS_BASE_URL, url_encode(&tasklist)),
                Some(map_to_query_pairs(params)),
                None,
            )
            .await
        }
        ["tasks", "insert"] => {
            let tasklist = take_string(&mut params, "tasklist")
                .ok_or_else(|| "tasks.tasks.insert requires `tasklist`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!("{}/lists/{}/tasks", TASKS_BASE_URL, url_encode(&tasklist)),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        _ => Err(format!(
            "Unsupported native Tasks command path '{}'.",
            command.path.join(" ")
        )),
    }
}

async fn execute_chat_raw_command(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let path = command.path.iter().map(String::as_str).collect::<Vec<_>>();
    match path.as_slice() {
        ["spaces", "messages", "create"] => {
            let mut params = object_map(command.params.clone())?;
            let space = take_string(&mut params, "parent")
                .or_else(|| take_string(&mut params, "space"))
                .ok_or_else(|| "chat.spaces.messages.create requires `parent` or `space`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!("{}/{}/messages", CHAT_BASE_URL, space.trim_matches('/')),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        _ => Err(format!(
            "Unsupported native Chat command path '{}'.",
            command.path.join(" ")
        )),
    }
}

async fn execute_bigquery_raw_command(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let path = command.path.iter().map(String::as_str).collect::<Vec<_>>();
    let mut params = object_map(command.params.clone())?;
    match path.as_slice() {
        ["jobs", "query"] => {
            let project_id = take_string(&mut params, "projectId")
                .ok_or_else(|| "bigquery.jobs.query requires `projectId`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::POST,
                &format!("{}/projects/{}/queries", BIGQUERY_BASE_URL, url_encode(&project_id)),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        _ => Err(format!(
            "Unsupported native BigQuery command path '{}'.",
            command.path.join(" ")
        )),
    }
}

async fn execute_workspace_events_raw_command(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let path = command.path.iter().map(String::as_str).collect::<Vec<_>>();
    let mut params = object_map(command.params.clone())?;
    match path.as_slice() {
        ["subscriptions", "list"] => {
            let query = map_to_query_pairs(params);
            if command.page_all {
                paginate_google_collection(
                    client,
                    access_token,
                    &format!("{}/subscriptions", WORKSPACE_EVENTS_BASE_URL),
                    query,
                    command.page_limit,
                    command.page_delay_ms,
                    "subscriptions",
                )
                .await
            } else {
                google_json_request(
                    client,
                    access_token,
                    Method::GET,
                    &format!("{}/subscriptions", WORKSPACE_EVENTS_BASE_URL),
                    Some(query),
                    None,
                )
                .await
            }
        }
        ["subscriptions", "get"] => {
            let name = take_string(&mut params, "name")
                .ok_or_else(|| "workspaceevents.subscriptions.get requires `name`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::GET,
                &workspace_subscription_url(&name),
                Some(map_to_query_pairs(params)),
                None,
            )
            .await
        }
        ["subscriptions", "patch"] => {
            let name = take_string(&mut params, "name")
                .ok_or_else(|| "workspaceevents.subscriptions.patch requires `name`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::PATCH,
                &workspace_subscription_url(&name),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        ["subscriptions", "create"] => {
            let operation = google_json_request(
                client,
                access_token,
                Method::POST,
                &format!("{}/subscriptions", WORKSPACE_EVENTS_BASE_URL),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await?;
            workspace_events_wait_for_subscription_operation(client, access_token, &operation).await
        }
        ["subscriptions", "reactivate"] => {
            let name = take_string(&mut params, "name")
                .ok_or_else(|| "workspaceevents.subscriptions.reactivate requires `name`.".to_string())?;
            let operation = google_json_request(
                client,
                access_token,
                Method::POST,
                &format!("{}:reactivate", workspace_subscription_url(&name)),
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await?;
            workspace_events_wait_for_subscription_operation(client, access_token, &operation).await
        }
        _ => Err(format!(
            "Unsupported native Workspace Events command path '{}'.",
            command.path.join(" ")
        )),
    }
}

async fn execute_pubsub_raw_command(
    client: &Client,
    access_token: &str,
    command: &ParsedGoogleCommand,
) -> Result<Value, String> {
    let path = command.path.iter().map(String::as_str).collect::<Vec<_>>();
    let mut params = object_map(command.params.clone())?;
    match path.as_slice() {
        ["projects", "topics", "create"] => {
            let topic = take_string(&mut params, "topic")
                .ok_or_else(|| "pubsub.projects.topics.create requires `topic`.".to_string())?;
            google_json_request(
                client,
                access_token,
                Method::PUT,
                &normalize_pubsub_topic_name(None, topic)?,
                Some(map_to_query_pairs(params)),
                command.body.clone(),
            )
            .await
        }
        _ => Err(format!(
            "Unsupported native Pub/Sub command path '{}'.",
            command.path.join(" ")
        )),
    }
}

async fn gmail_get_message(
    client: &Client,
    access_token: &str,
    message_id: &str,
    format: &str,
    metadata_headers: Option<&str>,
) -> Result<Value, String> {
    let mut query = vec![("format".to_string(), format.to_string())];
    if let Some(headers) = metadata_headers {
        for header_name in split_csv_like(headers) {
            query.push(("metadataHeaders".to_string(), header_name));
        }
    }
    google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/users/me/messages/{}", GMAIL_BASE_URL, url_encode(message_id)),
        Some(query),
        None,
    )
    .await
}

fn gmail_header_map(message: &Value) -> HashMap<String, String> {
    value_array(
        message
            .get("payload")
            .and_then(|payload| payload.get("headers")),
    )
    .into_iter()
    .filter_map(|header| {
        let name = header.get("name")?.as_str()?.trim().to_ascii_lowercase();
        let value = header.get("value")?.as_str()?.trim().to_string();
        Some((name, value))
    })
    .collect()
}

fn gmail_plaintext_body(message: &Value) -> Option<String> {
    let payload = message.get("payload")?;
    gmail_plaintext_body_from_part(payload)
}

fn gmail_plaintext_body_from_part(part: &Value) -> Option<String> {
    let mime = part
        .get("mimeType")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if mime == "text/plain"
        || (mime.is_empty()
            && part
                .get("body")
                .and_then(|body| body.get("data"))
                .and_then(Value::as_str)
                .is_some())
    {
        if let Some(decoded) = part
            .get("body")
            .and_then(|body| body.get("data"))
            .and_then(Value::as_str)
            .and_then(decode_gmail_body_data)
        {
            return Some(decoded);
        }
    }

    value_array(part.get("parts"))
        .into_iter()
        .find_map(|part| gmail_plaintext_body_from_part(&part))
}

fn decode_gmail_body_data(raw: &str) -> Option<String> {
    let decoded = URL_SAFE_NO_PAD.decode(raw.as_bytes()).ok()?;
    Some(String::from_utf8_lossy(&decoded).to_string())
}

fn docs_document_end_index(document: &Value) -> i64 {
    value_array(document.get("body").and_then(|body| body.get("content")))
        .into_iter()
        .filter_map(|item| item.get("endIndex").and_then(Value::as_i64))
        .max()
        .unwrap_or(1)
        .saturating_sub(1)
}

async fn workspace_events_wait_for_subscription_operation(
    client: &Client,
    access_token: &str,
    operation: &Value,
) -> Result<Value, String> {
    let Some(name) = operation.get("name").and_then(Value::as_str) else {
        return Ok(operation.clone());
    };
    let url = if name.starts_with("http://") || name.starts_with("https://") {
        name.to_string()
    } else {
        format!("{}/{}", WORKSPACE_EVENTS_BASE_URL, name.trim_start_matches('/'))
    };

    for _ in 0..20 {
        let polled = google_json_request(client, access_token, Method::GET, &url, None, None).await?;
        if polled.get("done").and_then(Value::as_bool).unwrap_or(false) {
            if let Some(error) = polled.get("error") {
                return Err(format!("Workspace Events operation failed: {}", error));
            }
            if let Some(response) = polled.get("response") {
                return Ok(response.clone());
            }
            return Ok(polled);
        }
        sleep(Duration::from_millis(500)).await;
    }

    Ok(operation.clone())
}

async fn ensure_pubsub_topic(
    client: &Client,
    access_token: &str,
    topic_name: &str,
) -> Result<Value, String> {
    google_json_request(
        client,
        access_token,
        Method::PUT,
        &format!("{}/{}", PUBSUB_BASE_URL, topic_name),
        None,
        Some(json!({})),
    )
    .await
}

async fn ensure_pubsub_subscription(
    client: &Client,
    access_token: &str,
    subscription_name: &str,
    topic_name: &str,
) -> Result<Value, String> {
    google_json_request(
        client,
        access_token,
        Method::PUT,
        &format!("{}/{}", PUBSUB_BASE_URL, subscription_name),
        None,
        Some(json!({
            "topic": topic_name
        })),
    )
    .await
}

async fn google_drive_multipart_upload(
    client: &Client,
    access_token: &str,
    metadata: Value,
    file_bytes: Vec<u8>,
) -> Result<Value, String> {
    let boundary = format!("ioi-google-upload-{}", short_timestamp_suffix());
    let metadata_json = metadata.to_string();
    let mut payload = Vec::new();
    payload.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    payload.extend_from_slice(b"Content-Type: application/json; charset=UTF-8\r\n\r\n");
    payload.extend_from_slice(metadata_json.as_bytes());
    payload.extend_from_slice(b"\r\n");
    payload.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    payload.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    payload.extend_from_slice(&file_bytes);
    payload.extend_from_slice(b"\r\n");
    payload.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    let response = client
        .post(format!("{}/files", DRIVE_UPLOAD_BASE_URL))
        .query(&[("uploadType", "multipart")])
        .bearer_auth(access_token)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/related; boundary={}", boundary),
        )
        .body(payload)
        .send()
        .await
        .map_err(|error| format!("Google Drive upload failed: {}", error))?;
    parse_google_response(response).await
}

async fn paginate_google_collection(
    client: &Client,
    access_token: &str,
    url: &str,
    mut query: Vec<(String, String)>,
    page_limit: u64,
    page_delay_ms: u64,
    items_key: &str,
) -> Result<Value, String> {
    let mut collected = Vec::new();
    let mut next_page_token: Option<String> = None;
    let mut pages = 0_u64;

    loop {
        if let Some(token) = next_page_token.clone() {
            retain_query_key(&mut query, "pageToken");
            query.push(("pageToken".to_string(), token));
        }
        let page = google_json_request(client, access_token, Method::GET, url, Some(query.clone()), None).await?;
        collected.extend(value_array(page.get(items_key)));
        next_page_token = page
            .get("nextPageToken")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        pages += 1;
        if next_page_token.is_none() || pages >= page_limit {
            break;
        }
        sleep(Duration::from_millis(page_delay_ms)).await;
    }

    Ok(json!({
        items_key: collected,
        "pageCount": pages
    }))
}

async fn google_json_request(
    client: &Client,
    access_token: &str,
    method: Method,
    url: &str,
    query: Option<Vec<(String, String)>>,
    body: Option<Value>,
) -> Result<Value, String> {
    let mut request = client.request(method, url).bearer_auth(access_token);
    if let Some(query) = query {
        request = request.query(&query);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("Google API request failed for '{}': {}", url, error))?;
    parse_google_response(response).await
}

async fn parse_google_response(response: reqwest::Response) -> Result<Value, String> {
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| format!("Failed to read Google API response: {}", error))?;
    if !status.is_success() {
        return Err(format!("Google API request failed with {}: {}", status, text));
    }
    if text.trim().is_empty() {
        return Ok(json!({ "ok": true, "status": status.as_u16() }));
    }
    serde_json::from_str(&text).map_err(|error| {
        format!(
            "Failed to parse Google API JSON response '{}': {}",
            text, error
        )
    })
}

fn retain_query_key(query: &mut Vec<(String, String)>, key: &str) {
    query.retain(|(existing, _)| existing != key);
}

fn workspace_subscription_url(name: &str) -> String {
    let normalized = if name.starts_with("subscriptions/") {
        name.to_string()
    } else {
        format!("subscriptions/{}", name)
    };
    format!("{}/{}", WORKSPACE_EVENTS_BASE_URL, normalized)
}

fn map_to_query_pairs(params: Map<String, Value>) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for (key, value) in params {
        match value {
            Value::Null => {}
            Value::Bool(value) => pairs.push((key, value.to_string())),
            Value::Number(value) => pairs.push((key, value.to_string())),
            Value::String(value) => pairs.push((key, value)),
            Value::Array(values) => {
                for value in values {
                    pairs.push((key.clone(), value_to_query_string(value)));
                }
            }
            other => pairs.push((key, other.to_string())),
        }
    }
    pairs
}

fn value_to_query_string(value: Value) -> String {
    match value {
        Value::String(value) => value,
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        other => other.to_string(),
    }
}

fn object_map(value: Value) -> Result<Map<String, Value>, String> {
    match value {
        Value::Object(map) => Ok(map),
        Value::Null => Ok(Map::new()),
        other => Err(format!("Expected JSON object, received {}.", other)),
    }
}

fn take_string(map: &mut Map<String, Value>, key: &str) -> Option<String> {
    map.remove(key)
        .and_then(|value| match value {
            Value::String(text) => Some(text.trim().to_string()),
            Value::Number(number) => Some(number.to_string()),
            Value::Bool(value) => Some(value.to_string()),
            _ => None,
        })
        .filter(|value| !value.is_empty())
}

fn option_string(command: &ParsedGoogleCommand, key: &str) -> Option<String> {
    command
        .options
        .get(key)
        .and_then(|values| values.last().cloned())
        .filter(|value| !value.trim().is_empty())
}

fn required_option(command: &ParsedGoogleCommand, key: &str) -> Result<String, String> {
    option_string(command, key).ok_or_else(|| format!("Google command option '--{}' is required.", key))
}

fn option_values(command: &ParsedGoogleCommand, key: &str) -> Vec<String> {
    command
        .options
        .get(key)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect()
}

fn option_bool(command: &ParsedGoogleCommand, key: &str) -> Option<bool> {
    command.options.get(key).and_then(|values| {
        values.last().and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        })
    })
}

fn option_u64(command: &ParsedGoogleCommand, key: &str) -> Option<u64> {
    command
        .options
        .get(key)
        .and_then(|values| values.last())
        .and_then(|value| value.parse::<u64>().ok())
}

fn value_array(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn split_csv_like(raw: &str) -> Vec<String> {
    raw.split(|ch| ch == ',' || ch == '\n')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn normalize_pubsub_topic_name(
    project: Option<String>,
    topic: String,
) -> Result<String, String> {
    if topic.starts_with("projects/") {
        return Ok(topic);
    }
    let project = project
        .or_else(default_google_project_id)
        .ok_or_else(|| "A Google Cloud project ID is required to build a Pub/Sub topic name.".to_string())?;
    Ok(format!(
        "projects/{}/topics/{}",
        project,
        topic.trim_start_matches("topics/")
    ))
}

fn normalize_pubsub_subscription_name(
    project: Option<String>,
    subscription: String,
) -> Result<String, String> {
    if subscription.starts_with("projects/") {
        return Ok(subscription);
    }
    let project = project
        .or_else(default_google_project_id)
        .ok_or_else(|| {
            "A Google Cloud project ID is required to build a Pub/Sub subscription name."
                .to_string()
        })?;
    Ok(format!(
        "projects/{}/subscriptions/{}",
        project,
        subscription.trim_start_matches("subscriptions/")
    ))
}

fn google_project_from_pubsub_resource(resource: &str, kind: &str) -> Option<String> {
    let segments = resource.split('/').collect::<Vec<_>>();
    if segments.len() >= 4 && segments[0] == "projects" && segments[2] == kind {
        return Some(segments[1].to_string());
    }
    None
}

fn build_gmail_raw_message(to: &str, subject: &str, body: &str) -> String {
    let mime = format!(
        "To: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{}",
        to.trim(),
        subject.trim(),
        body
    );
    URL_SAFE_NO_PAD.encode(mime.as_bytes())
}

fn today_ymd() -> String {
    OffsetDateTime::now_utc()
        .date()
        .format(
            &time::format_description::parse("[year]-[month]-[day]")
                .expect("valid date format"),
        )
        .unwrap_or_else(|_| "1970-01-01".to_string())
}

fn day_start_rfc3339(date: &str) -> Result<String, String> {
    let (start, _) = date_to_day_bounds(date)?;
    Ok(start)
}

fn day_end_rfc3339(date: &str) -> Result<String, String> {
    let (_, end) = date_to_day_bounds(date)?;
    Ok(end)
}

fn date_to_day_bounds(date: &str) -> Result<(String, String), String> {
    let format = time::format_description::parse("[year]-[month]-[day]")
        .map_err(|error| format!("Failed to build date parser: {}", error))?;
    let parsed =
        time::Date::parse(date, &format).map_err(|error| format!("Invalid date '{}': {}", date, error))?;
    let start = parsed.with_hms(0, 0, 0).map_err(|error| error.to_string())?;
    let end = start + TimeDuration::days(1);
    Ok((format_time(start.assume_utc()), format_time(end.assume_utc())))
}

fn now_rfc3339() -> String {
    format_time(OffsetDateTime::now_utc())
}

fn format_time(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn short_timestamp_suffix() -> String {
    OffsetDateTime::now_utc().unix_timestamp().to_string()
}

fn url_encode(raw: &str) -> String {
    url::form_urlencoded::byte_serialize(raw.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::{map_to_query_pairs, normalize_pubsub_topic_name, parse_google_command};
    use serde_json::json;

    #[test]
    fn parses_google_command_flags() {
        let command = parse_google_command(&[
            "gmail".to_string(),
            "+triage".to_string(),
            "--max".to_string(),
            "5".to_string(),
            "--query".to_string(),
            "is:unread".to_string(),
            "--labels".to_string(),
        ])
        .expect("command");
        assert_eq!(command.service, "gmail");
        assert_eq!(command.path, vec!["+triage".to_string()]);
        assert_eq!(
            command.options.get("query").cloned().unwrap_or_default(),
            vec!["is:unread".to_string()]
        );
        assert_eq!(
            command.options.get("labels").cloned().unwrap_or_default(),
            vec!["true".to_string()]
        );
    }

    #[test]
    fn maps_query_pairs_with_arrays() {
        let pairs = map_to_query_pairs(
            json!({
                "fields": ["a", "b"],
                "maxResults": 10
            })
            .as_object()
            .cloned()
            .expect("object"),
        );
        assert!(pairs.contains(&("fields".to_string(), "a".to_string())));
        assert!(pairs.contains(&("fields".to_string(), "b".to_string())));
        assert!(pairs.contains(&("maxResults".to_string(), "10".to_string())));
    }

    #[test]
    fn normalizes_pubsub_topic_names() {
        let full = normalize_pubsub_topic_name(Some("demo-project".to_string()), "demo-topic".to_string())
            .expect("topic");
        assert_eq!(full, "projects/demo-project/topics/demo-topic");
    }
}
