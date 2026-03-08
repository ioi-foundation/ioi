use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dotenvy::from_path_iter;
use once_cell::sync::Lazy;
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::runtime::Handle;
use url::Url;

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const GOOGLE_AUTH_TIMEOUT_SECS: u64 = 900;
const GOOGLE_AUTH_FILE_NAME: &str = "google_workspace_oauth.json";
const GOOGLE_CLIENT_FILE_NAME: &str = "google_workspace_client.json";

static PENDING_GOOGLE_AUTH: Lazy<Mutex<Option<PendingGoogleAuthSession>>> =
    Lazy::new(|| Mutex::new(None));
static LAST_GOOGLE_AUTH_ERROR: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));
static GOOGLE_LOCAL_ENV_LOADED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleAuthStatus {
    pub status: String,
    pub summary: String,
    pub data: Value,
}

#[derive(Debug, Clone)]
pub struct GoogleAccessContext {
    pub access_token: String,
    pub account_email: Option<String>,
    pub granted_scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleAuthRecord {
    account_email: Option<String>,
    access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at_utc: Option<String>,
    #[serde(default)]
    granted_scopes: Vec<String>,
    #[serde(default = "default_token_type")]
    token_type: String,
}

#[derive(Debug, Clone)]
struct GoogleOauthClientConfig {
    client_id: String,
    client_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleOauthClientRecord {
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
}

#[derive(Debug, Clone)]
struct PendingGoogleAuthSession {
    state: String,
    code_verifier: String,
    redirect_uri: String,
    auth_url: String,
    started_at_utc: String,
    expires_at_utc: String,
    requested_scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct GoogleTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleUserInfo {
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleOauthClientStatus {
    pub configured: bool,
    pub source: String,
    pub client_id_preview: Option<String>,
    pub has_client_secret: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_path: Option<String>,
}

pub async fn status() -> Result<GoogleAuthStatus, String> {
    let oauth_client = oauth_client_status();
    let token_storage = token_storage_status()?;

    if let Some(pending) = current_pending_session() {
        return Ok(GoogleAuthStatus {
            status: "needs_auth".to_string(),
            summary: "Awaiting Google OAuth completion in your browser.".to_string(),
            data: json!({
                "authPending": true,
                "authUrl": pending.auth_url,
                "startedAtUtc": pending.started_at_utc,
                "expiresAtUtc": pending.expires_at_utc,
                "storage": "native_oauth",
                "oauthClient": oauth_client,
                "requestedScopes": pending.requested_scopes,
                "tokenStorage": token_storage
            }),
        });
    }

    let Some(mut record) = load_google_auth_record()? else {
        let summary = last_auth_error()
            .unwrap_or_else(|| "Google auth is not connected. Use Connect to start native OAuth.".to_string());
        return Ok(GoogleAuthStatus {
            status: "needs_auth".to_string(),
            summary,
            data: json!({
                "auth_method": "none",
                "storage": "native_oauth",
                "oauthClient": oauth_client,
                "tokenStorage": token_storage
            }),
        });
    };

    if should_refresh(&record) {
        let client = load_google_oauth_client()?;
        refresh_google_access_token(&client, &mut record).await?;
        save_google_auth_record(&record)?;
    }

    let summary = match record.account_email.as_deref() {
        Some(account) if !account.trim().is_empty() => {
            format!("Google auth is connected for {} using native OAuth.", account)
        }
        _ => "Google auth is connected using native OAuth.".to_string(),
    };

    Ok(GoogleAuthStatus {
        status: "connected".to_string(),
        summary,
        data: json!({
            "auth_method": "oauth",
            "storage": "native_oauth",
            "account": record.account_email,
            "scopes": record.granted_scopes,
            "expiresAtUtc": record.expires_at_utc,
            "oauthClient": oauth_client,
            "tokenStorage": token_storage
        }),
    })
}

pub async fn login(requested_scopes: Option<Vec<String>>) -> Result<GoogleAuthStatus, String> {
    let client = load_google_oauth_client()?;
    let requested_scopes = resolve_requested_google_oauth_scopes(requested_scopes)?;

    if let Some(pending) = current_pending_session() {
        let _ = open_url_in_browser(&pending.auth_url);
        return Ok(GoogleAuthStatus {
            status: "needs_auth".to_string(),
            summary: "Google OAuth is already in progress. Complete sign-in in your browser.".to_string(),
            data: json!({
                "authPending": true,
                "authUrl": pending.auth_url,
                "startedAtUtc": pending.started_at_utc,
                "expiresAtUtc": pending.expires_at_utc,
                "storage": "native_oauth",
                "requestedScopes": pending.requested_scopes,
                "oauthClient": oauth_client_status(),
                "tokenStorage": token_storage_status()?
            }),
        });
    }

    clear_last_auth_error();

    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("Failed to bind Google OAuth callback listener: {}", error))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("Failed to configure Google OAuth listener: {}", error))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("Failed to resolve OAuth callback port: {}", error))?
        .port();

    let redirect_uri = format!("http://127.0.0.1:{}", port);
    let state = random_url_safe_token(24);
    let code_verifier = random_url_safe_token(48);
    let code_challenge = pkce_code_challenge(&code_verifier);
    let now = OffsetDateTime::now_utc();
    let started_at_utc = format_rfc3339(now);
    let expires_at_utc = format_rfc3339(now + time::Duration::seconds(GOOGLE_AUTH_TIMEOUT_SECS as i64));
    let auth_url = build_google_auth_url(
        &client.client_id,
        &redirect_uri,
        &state,
        &code_challenge,
        &requested_scopes,
    )?;

    let pending = PendingGoogleAuthSession {
        state: state.clone(),
        code_verifier: code_verifier.clone(),
        redirect_uri: redirect_uri.clone(),
        auth_url: auth_url.clone(),
        started_at_utc: started_at_utc.clone(),
        expires_at_utc: expires_at_utc.clone(),
        requested_scopes: requested_scopes.clone(),
    };
    {
        let mut slot = PENDING_GOOGLE_AUTH
            .lock()
            .map_err(|_| "Failed to acquire Google auth state lock.".to_string())?;
        *slot = Some(pending.clone());
    }

    let runtime = Handle::current();
    let redirect_uri_for_exchange = redirect_uri.clone();
    tokio::task::spawn_blocking(move || {
        let session_state = state.clone();
        let auth_result = wait_for_google_callback(listener, &state, GOOGLE_AUTH_TIMEOUT_SECS)
            .and_then(|code| {
                runtime.block_on(async {
                    complete_google_oauth_login(
                        &client,
                        &code,
                        &code_verifier,
                        &redirect_uri_for_exchange,
                        requested_scopes,
                    )
                    .await
                })
            });

        if pending_session_matches(&session_state) {
            match auth_result {
                Ok(record) => {
                    if let Err(error) = save_google_auth_record(&record) {
                        set_last_auth_error(error);
                    } else {
                        clear_last_auth_error();
                    }
                }
                Err(error) => set_last_auth_error(error),
            }
        }

        if let Ok(mut slot) = PENDING_GOOGLE_AUTH.lock() {
            if slot
                .as_ref()
                .map(|pending| pending.state.as_str() == session_state.as_str())
                .unwrap_or(false)
            {
                *slot = None;
            }
        }
    });

    let browser_summary = if open_url_in_browser(&auth_url).is_ok() {
        "Google OAuth opened in your browser. Complete sign-in to finish connecting."
    } else {
        "Google OAuth is ready. Open the provided auth URL in your browser to finish connecting."
    };

    Ok(GoogleAuthStatus {
        status: "needs_auth".to_string(),
        summary: browser_summary.to_string(),
        data: json!({
            "authPending": true,
            "authUrl": auth_url,
            "redirectUri": redirect_uri,
            "startedAtUtc": started_at_utc,
            "expiresAtUtc": expires_at_utc,
            "storage": "native_oauth",
            "requestedScopes": pending.requested_scopes,
            "oauthClient": oauth_client_status(),
            "tokenStorage": token_storage_status()?
        }),
    })
}

pub async fn logout() -> Result<GoogleAuthStatus, String> {
    clear_last_auth_error();
    if let Ok(mut slot) = PENDING_GOOGLE_AUTH.lock() {
        *slot = None;
    }

    let path = google_auth_storage_path()?;
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|error| format!("Failed to remove Google auth state '{}': {}", path.display(), error))?;
    }

    Ok(GoogleAuthStatus {
        status: "needs_auth".to_string(),
        summary: "Disconnected Google OAuth credentials.".to_string(),
        data: json!({
            "auth_method": "none",
            "storage": "native_oauth",
            "oauthClient": oauth_client_status(),
            "tokenStorage": token_storage_status()?
        }),
    })
}

pub async fn cancel_pending_login() -> Result<GoogleAuthStatus, String> {
    if let Ok(mut slot) = PENDING_GOOGLE_AUTH.lock() {
        *slot = None;
    }

    clear_last_auth_error();
    let mut auth = status().await?;
    auth.summary = "Canceled the in-progress Google sign-in attempt.".to_string();
    Ok(auth)
}

pub async fn access_context(required_scopes: &[&str]) -> Result<GoogleAccessContext, String> {
    let mut record = load_google_auth_record()?
        .ok_or_else(|| "Google auth is not connected. Use Connect to start native OAuth.".to_string())?;

    if should_refresh(&record) {
        let client = load_google_oauth_client()?;
        refresh_google_access_token(&client, &mut record).await?;
        save_google_auth_record(&record)?;
    }

    let missing_scopes = missing_required_scopes(&record.granted_scopes, required_scopes);
    if !missing_scopes.is_empty() {
        return Err(format!(
            "Google auth is missing required scopes: {}. Reconnect the Google connector to grant them.",
            missing_scopes.join(", ")
        ));
    }

    Ok(GoogleAccessContext {
        access_token: record.access_token,
        account_email: record.account_email,
        granted_scopes: record.granted_scopes,
    })
}

pub fn granted_scopes_missing(
    granted_scopes: &[String],
    required_scopes: &[&str],
) -> Vec<String> {
    missing_required_scopes(granted_scopes, required_scopes)
}

pub fn oauth_client_status() -> GoogleOauthClientStatus {
    if let Ok(Some(record)) = load_google_oauth_client_record() {
        return GoogleOauthClientStatus {
            configured: true,
            source: "local".to_string(),
            client_id_preview: Some(mask_client_id(&record.client_id)),
            has_client_secret: record.client_secret.is_some(),
            storage_path: google_client_storage_path()
                .ok()
                .map(|path| path.display().to_string()),
        };
    }

    if let Some(client_id) =
        env_string(&["GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_WORKSPACE_OAUTH_CLIENT_ID"])
    {
        return GoogleOauthClientStatus {
            configured: true,
            source: "env".to_string(),
            client_id_preview: Some(mask_client_id(&client_id)),
            has_client_secret: env_string(&[
                "GOOGLE_OAUTH_CLIENT_SECRET",
                "GOOGLE_WORKSPACE_OAUTH_CLIENT_SECRET",
            ])
            .is_some(),
            storage_path: google_client_storage_path()
                .ok()
                .map(|path| path.display().to_string()),
        };
    }

    GoogleOauthClientStatus {
        configured: false,
        source: "none".to_string(),
        client_id_preview: None,
        has_client_secret: false,
        storage_path: google_client_storage_path()
            .ok()
            .map(|path| path.display().to_string()),
    }
}

pub fn save_oauth_client(
    client_id: String,
    client_secret: Option<String>,
) -> Result<GoogleOauthClientStatus, String> {
    let trimmed_client_id = client_id.trim();
    if trimmed_client_id.is_empty() {
        return Err("Google OAuth client ID is required.".to_string());
    }
    if !trimmed_client_id.ends_with(".apps.googleusercontent.com") {
        return Err(
            "Google OAuth client ID should look like a Desktop app client from Google Cloud Console."
                .to_string(),
        );
    }

    let record = GoogleOauthClientRecord {
        client_id: trimmed_client_id.to_string(),
        client_secret: client_secret
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
    };
    save_google_oauth_client_record(&record)?;
    clear_last_auth_error();
    Ok(GoogleOauthClientStatus {
        configured: true,
        source: "local".to_string(),
        client_id_preview: Some(mask_client_id(&record.client_id)),
        has_client_secret: record.client_secret.is_some(),
        storage_path: google_client_storage_path()
            .ok()
            .map(|path| path.display().to_string()),
    })
}

pub fn clear_oauth_client() -> Result<GoogleOauthClientStatus, String> {
    let path = google_client_storage_path()?;
    if path.exists() {
        fs::remove_file(&path).map_err(|error| {
            format!(
                "Failed to remove Google OAuth client config '{}': {}",
                path.display(),
                error
            )
        })?;
    }
    clear_last_auth_error();
    Ok(oauth_client_status())
}

fn current_pending_session() -> Option<PendingGoogleAuthSession> {
    let Ok(mut slot) = PENDING_GOOGLE_AUTH.lock() else {
        return None;
    };
    let pending = slot.clone()?;
    if parse_rfc3339(&pending.expires_at_utc)
        .map(|expires| expires <= OffsetDateTime::now_utc())
        .unwrap_or(false)
    {
        *slot = None;
        return None;
    }
    Some(pending)
}

fn pending_session_matches(expected_state: &str) -> bool {
    let Ok(slot) = PENDING_GOOGLE_AUTH.lock() else {
        return false;
    };
    slot.as_ref()
        .map(|pending| pending.state == expected_state)
        .unwrap_or(false)
}

fn last_auth_error() -> Option<String> {
    LAST_GOOGLE_AUTH_ERROR
        .lock()
        .ok()
        .and_then(|value| value.clone())
}

fn set_last_auth_error(message: String) {
    if let Ok(mut value) = LAST_GOOGLE_AUTH_ERROR.lock() {
        *value = Some(message);
    }
}

fn clear_last_auth_error() {
    if let Ok(mut value) = LAST_GOOGLE_AUTH_ERROR.lock() {
        *value = None;
    }
}

fn load_google_auth_record() -> Result<Option<GoogleAuthRecord>, String> {
    let path = google_auth_storage_path()?;
    if path.exists() {
        let raw = fs::read_to_string(&path)
            .map_err(|error| format!("Failed to read Google auth state '{}': {}", path.display(), error))?;
        let record = serde_json::from_str::<GoogleAuthRecord>(&raw)
            .map_err(|error| format!("Failed to parse Google auth state '{}': {}", path.display(), error))?;
        return Ok(Some(record));
    }

    if let Some(record) = load_google_auth_record_from_env()? {
        return Ok(Some(record));
    }

    Ok(None)
}

fn load_google_auth_record_from_env() -> Result<Option<GoogleAuthRecord>, String> {
    let refresh_token = env_string(&[
        "GOOGLE_OAUTH_REFRESH_TOKEN",
        "GOOGLE_WORKSPACE_REFRESH_TOKEN",
    ]);
    let access_token = env_string(&[
        "GOOGLE_OAUTH_ACCESS_TOKEN",
        "GOOGLE_WORKSPACE_ACCESS_TOKEN",
    ]);

    if refresh_token.is_none() && access_token.is_none() {
        return Ok(None);
    }

    Ok(Some(GoogleAuthRecord {
        account_email: env_string(&[
            "GOOGLE_OAUTH_ACCOUNT_EMAIL",
            "GOOGLE_WORKSPACE_ACCOUNT_EMAIL",
        ]),
        access_token: access_token.unwrap_or_default(),
        refresh_token,
        expires_at_utc: None,
        granted_scopes: default_google_oauth_scopes(),
        token_type: "Bearer".to_string(),
    }))
}

fn save_google_auth_record(record: &GoogleAuthRecord) -> Result<(), String> {
    let path = google_auth_storage_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create Google auth directory '{}': {}",
                parent.display(),
                error
            )
        })?;
    }
    let payload = serde_json::to_string_pretty(record)
        .map_err(|error| format!("Failed to serialize Google auth state: {}", error))?;
    fs::write(&path, payload)
        .map_err(|error| format!("Failed to write Google auth state '{}': {}", path.display(), error))
}

fn google_auth_storage_path() -> Result<PathBuf, String> {
    if let Some(path) = env_string(&["IOI_GOOGLE_AUTH_PATH"]) {
        return Ok(PathBuf::from(path));
    }

    if let Some(base) = env_string(&["XDG_CONFIG_HOME"]) {
        return Ok(PathBuf::from(base).join("ioi").join(GOOGLE_AUTH_FILE_NAME));
    }
    if let Some(base) = env_string(&["APPDATA"]) {
        return Ok(PathBuf::from(base).join("ioi").join(GOOGLE_AUTH_FILE_NAME));
    }
    if let Some(home) = env_string(&["HOME"]) {
        return Ok(PathBuf::from(home).join(".config").join("ioi").join(GOOGLE_AUTH_FILE_NAME));
    }

    Err("Unable to resolve a Google auth storage path. Set IOI_GOOGLE_AUTH_PATH.".to_string())
}

fn load_google_oauth_client() -> Result<GoogleOauthClientConfig, String> {
    if let Some(record) = load_google_oauth_client_record()? {
        return Ok(GoogleOauthClientConfig {
            client_id: record.client_id,
            client_secret: record.client_secret,
        });
    }

    let client_id = env_string(&[
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_WORKSPACE_OAUTH_CLIENT_ID",
    ])
    .ok_or_else(|| {
        "Missing Google OAuth client ID. Set GOOGLE_OAUTH_CLIENT_ID or GOOGLE_WORKSPACE_OAUTH_CLIENT_ID. For local Autopilot dev, add it to .env.google-e2e.local at the repo root or export it before starting the app.".to_string()
    })?;

    Ok(GoogleOauthClientConfig {
        client_id,
        client_secret: env_string(&[
            "GOOGLE_OAUTH_CLIENT_SECRET",
            "GOOGLE_WORKSPACE_OAUTH_CLIENT_SECRET",
        ]),
    })
}

fn load_google_oauth_client_record() -> Result<Option<GoogleOauthClientRecord>, String> {
    let path = google_client_storage_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&path).map_err(|error| {
        format!(
            "Failed to read Google OAuth client config '{}': {}",
            path.display(),
            error
        )
    })?;
    let record = serde_json::from_str::<GoogleOauthClientRecord>(&raw).map_err(|error| {
        format!(
            "Failed to parse Google OAuth client config '{}': {}",
            path.display(),
            error
        )
    })?;
    Ok(Some(record))
}

fn save_google_oauth_client_record(record: &GoogleOauthClientRecord) -> Result<(), String> {
    let path = google_client_storage_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create Google OAuth client config directory '{}': {}",
                parent.display(),
                error
            )
        })?;
    }
    let payload = serde_json::to_string_pretty(record)
        .map_err(|error| format!("Failed to serialize Google OAuth client config: {}", error))?;
    fs::write(&path, payload).map_err(|error| {
        format!(
            "Failed to write Google OAuth client config '{}': {}",
            path.display(),
            error
        )
    })
}

fn default_google_oauth_scopes() -> Vec<String> {
    let mut scopes = HashSet::new();
    scopes.insert("openid".to_string());
    scopes.insert("email".to_string());
    for scope in [
        "gmail.readonly",
        "gmail.modify",
        "calendar.readonly",
        "calendar",
        "documents.readonly",
        "documents",
        "spreadsheets.readonly",
        "spreadsheets",
        "drive.readonly",
        "drive",
        "tasks",
        "chat.messages.create",
        "chat.messages.readonly",
        "bigquery",
        "pubsub",
        "cloud-platform",
    ] {
        for expanded in expand_google_scope(scope) {
            scopes.insert(expanded);
        }
    }
    let mut values = scopes.into_iter().collect::<Vec<_>>();
    values.sort();
    values
}

fn resolve_requested_google_oauth_scopes(
    requested_scopes: Option<Vec<String>>,
) -> Result<Vec<String>, String> {
    let Some(requested_scopes) = requested_scopes else {
        return Ok(default_google_oauth_scopes());
    };

    let mut scopes = HashSet::new();
    scopes.insert("openid".to_string());
    scopes.insert("email".to_string());
    let mut selected_scope_count = 0_u32;

    for raw_scope in requested_scopes {
        let trimmed = raw_scope.trim();
        if trimmed.is_empty() {
            continue;
        }
        selected_scope_count += 1;
        for expanded in expand_google_scope(trimmed) {
            scopes.insert(expanded);
        }
    }

    if selected_scope_count == 0 {
        return Err("Select at least one Google capability before continuing to consent.".to_string());
    }

    let mut values = scopes.into_iter().collect::<Vec<_>>();
    values.sort();
    Ok(values)
}

fn missing_required_scopes(granted_scopes: &[String], required_scopes: &[&str]) -> Vec<String> {
    let granted = granted_scopes
        .iter()
        .flat_map(|scope| expand_granted_google_scope(scope))
        .collect::<HashSet<_>>();
    let mut missing = Vec::new();
    for required in required_scopes {
        for expanded in expand_google_scope(required) {
            if !granted.contains(&expanded) {
                missing.push((*required).to_string());
                break;
            }
        }
    }
    missing.sort();
    missing.dedup();
    missing
}

fn expand_granted_google_scope(scope: &str) -> Vec<String> {
    let mut expanded = expand_google_scope(scope);
    let implied = match scope.trim() {
        "https://www.googleapis.com/auth/gmail.modify" | "gmail.modify" => {
            expand_google_scope("gmail.readonly")
        }
        "https://www.googleapis.com/auth/calendar" | "calendar" => {
            expand_google_scope("calendar.readonly")
        }
        "https://www.googleapis.com/auth/documents" | "documents" => {
            expand_google_scope("documents.readonly")
        }
        "https://www.googleapis.com/auth/spreadsheets" | "spreadsheets" => {
            expand_google_scope("spreadsheets.readonly")
        }
        "https://www.googleapis.com/auth/drive" | "drive" => {
            expand_google_scope("drive.readonly")
        }
        "https://www.googleapis.com/auth/tasks" | "tasks" => {
            vec!["https://www.googleapis.com/auth/tasks.readonly".to_string()]
        }
        other if other.ends_with("/tasks") => {
            vec!["https://www.googleapis.com/auth/tasks.readonly".to_string()]
        }
        _ => Vec::new(),
    };
    expanded.extend(implied);
    expanded.sort();
    expanded.dedup();
    expanded
}

fn expand_google_scope(scope: &str) -> Vec<String> {
    match scope.trim() {
        "" => Vec::new(),
        "openid" => vec!["openid".to_string()],
        "email" => vec!["email".to_string(), "https://www.googleapis.com/auth/userinfo.email".to_string()],
        "gmail.readonly" => vec!["https://www.googleapis.com/auth/gmail.readonly".to_string()],
        "gmail.modify" => vec!["https://www.googleapis.com/auth/gmail.modify".to_string()],
        "calendar.readonly" => vec!["https://www.googleapis.com/auth/calendar.readonly".to_string()],
        "calendar" => vec!["https://www.googleapis.com/auth/calendar".to_string()],
        "documents.readonly" => vec!["https://www.googleapis.com/auth/documents.readonly".to_string()],
        "documents" => vec!["https://www.googleapis.com/auth/documents".to_string()],
        "spreadsheets.readonly" => vec!["https://www.googleapis.com/auth/spreadsheets.readonly".to_string()],
        "spreadsheets" => vec!["https://www.googleapis.com/auth/spreadsheets".to_string()],
        "drive.readonly" => vec!["https://www.googleapis.com/auth/drive.readonly".to_string()],
        "drive" => vec!["https://www.googleapis.com/auth/drive".to_string()],
        "tasks" => vec!["https://www.googleapis.com/auth/tasks".to_string()],
        "chat.messages.create" => {
            vec!["https://www.googleapis.com/auth/chat.messages.create".to_string()]
        }
        "chat.messages.readonly" => {
            vec!["https://www.googleapis.com/auth/chat.messages.readonly".to_string()]
        }
        "bigquery" => vec!["https://www.googleapis.com/auth/bigquery".to_string()],
        "pubsub" => vec!["https://www.googleapis.com/auth/pubsub".to_string()],
        "cloud-platform" => vec!["https://www.googleapis.com/auth/cloud-platform".to_string()],
        other if other.starts_with("http://") || other.starts_with("https://") => {
            vec![other.to_string()]
        }
        other => vec![format!("https://www.googleapis.com/auth/{}", other)],
    }
}

fn should_refresh(record: &GoogleAuthRecord) -> bool {
    if record.access_token.trim().is_empty() {
        return true;
    }
    let Some(expires_at_utc) = record.expires_at_utc.as_deref() else {
        return false;
    };
    let Some(expires_at) = parse_rfc3339(expires_at_utc) else {
        return true;
    };
    expires_at <= OffsetDateTime::now_utc() + time::Duration::minutes(5)
}

async fn complete_google_oauth_login(
    client: &GoogleOauthClientConfig,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    fallback_scopes: Vec<String>,
) -> Result<GoogleAuthRecord, String> {
    let http = Client::new();
    let mut form = vec![
        ("code", code.to_string()),
        ("client_id", client.client_id.clone()),
        ("code_verifier", code_verifier.to_string()),
        ("grant_type", "authorization_code".to_string()),
        ("redirect_uri", redirect_uri.to_string()),
    ];
    if let Some(client_secret) = client.client_secret.clone() {
        form.push(("client_secret", client_secret));
    }

    let token = http
        .post(GOOGLE_TOKEN_URL)
        .form(&form)
        .send()
        .await
        .map_err(|error| format!("Google OAuth token exchange failed: {}", error))?;
    let status = token.status();
    let token_text = token
        .text()
        .await
        .map_err(|error| format!("Failed to read Google OAuth token response: {}", error))?;
    if !status.is_success() {
        return Err(format!(
            "Google OAuth token exchange failed with {}: {}",
            status, token_text
        ));
    }

    let token_response = serde_json::from_str::<GoogleTokenResponse>(&token_text)
        .map_err(|error| format!("Failed to parse Google OAuth token response: {}", error))?;
    let account_email = fetch_google_account_email(&http, &token_response.access_token).await?;

    Ok(build_auth_record_from_token(
        token_response,
        account_email,
        fallback_scopes,
    ))
}

fn token_storage_status() -> Result<Value, String> {
    let path = google_auth_storage_path()?;
    let source = if path.exists() {
        "local"
    } else if env_string(&[
        "GOOGLE_OAUTH_REFRESH_TOKEN",
        "GOOGLE_WORKSPACE_REFRESH_TOKEN",
        "GOOGLE_OAUTH_ACCESS_TOKEN",
        "GOOGLE_WORKSPACE_ACCESS_TOKEN",
    ])
    .is_some()
    {
        "env"
    } else {
        "none"
    };

    Ok(json!({
        "source": source,
        "storagePath": path.display().to_string(),
        "present": path.exists()
    }))
}

async fn refresh_google_access_token(
    client: &GoogleOauthClientConfig,
    record: &mut GoogleAuthRecord,
) -> Result<(), String> {
    let refresh_token = record
        .refresh_token
        .clone()
        .ok_or_else(|| "Google auth cannot be refreshed because no refresh token is stored.".to_string())?;
    let http = Client::new();
    let mut form = vec![
        ("refresh_token", refresh_token.clone()),
        ("client_id", client.client_id.clone()),
        ("grant_type", "refresh_token".to_string()),
    ];
    if let Some(client_secret) = client.client_secret.clone() {
        form.push(("client_secret", client_secret));
    }

    let token = http
        .post(GOOGLE_TOKEN_URL)
        .form(&form)
        .send()
        .await
        .map_err(|error| format!("Google OAuth refresh failed: {}", error))?;
    let status = token.status();
    let token_text = token
        .text()
        .await
        .map_err(|error| format!("Failed to read Google OAuth refresh response: {}", error))?;
    if !status.is_success() {
        return Err(format!(
            "Google OAuth refresh failed with {}: {}",
            status, token_text
        ));
    }

    let token_response = serde_json::from_str::<GoogleTokenResponse>(&token_text)
        .map_err(|error| format!("Failed to parse Google OAuth refresh response: {}", error))?;
    let account_email = if let Some(existing) = record.account_email.clone() {
        Some(existing)
    } else {
        fetch_google_account_email(&http, &token_response.access_token).await?
    };

    let refreshed = build_auth_record_from_token(
        GoogleTokenResponse {
            refresh_token: Some(refresh_token),
            ..token_response
        },
        account_email,
        record.granted_scopes.clone(),
    );
    *record = refreshed;
    Ok(())
}

fn build_auth_record_from_token(
    token: GoogleTokenResponse,
    account_email: Option<String>,
    fallback_scopes: Vec<String>,
) -> GoogleAuthRecord {
    let granted_scopes = token
        .scope
        .as_deref()
        .map(split_scope_string)
        .filter(|values| !values.is_empty())
        .unwrap_or(fallback_scopes);
    let expires_at_utc = token
        .expires_in
        .map(|seconds| format_rfc3339(OffsetDateTime::now_utc() + time::Duration::seconds(seconds)));

    GoogleAuthRecord {
        account_email,
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at_utc,
        granted_scopes,
        token_type: token.token_type.unwrap_or_else(default_token_type),
    }
}

async fn fetch_google_account_email(
    client: &Client,
    access_token: &str,
) -> Result<Option<String>, String> {
    let response = client
        .get(GOOGLE_USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|error| format!("Failed to fetch Google account profile: {}", error))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| format!("Failed to read Google account profile response: {}", error))?;
    if !status.is_success() {
        return Err(format!(
            "Failed to fetch Google account profile with {}: {}",
            status, body
        ));
    }
    let profile = serde_json::from_str::<GoogleUserInfo>(&body)
        .map_err(|error| format!("Failed to parse Google account profile: {}", error))?;
    Ok(profile.email)
}

fn wait_for_google_callback(
    listener: TcpListener,
    expected_state: &str,
    timeout_secs: u64,
) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                let mut buffer = [0_u8; 4096];
                let read = stream
                    .read(&mut buffer)
                    .map_err(|error| format!("Failed to read Google OAuth callback: {}", error))?;
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                let request_line = request
                    .lines()
                    .next()
                    .ok_or_else(|| "Google OAuth callback was empty.".to_string())?;
                let path = request_line
                    .split_whitespace()
                    .nth(1)
                    .ok_or_else(|| "Google OAuth callback request path was missing.".to_string())?;
                let callback_url = Url::parse(&format!("http://127.0.0.1{}", path))
                    .map_err(|error| format!("Failed to parse Google OAuth callback URL: {}", error))?;
                let state = callback_url
                    .query_pairs()
                    .find_map(|(key, value)| (key == "state").then(|| value.to_string()));
                let code = callback_url
                    .query_pairs()
                    .find_map(|(key, value)| (key == "code").then(|| value.to_string()));
                let error = callback_url
                    .query_pairs()
                    .find_map(|(key, value)| (key == "error").then(|| value.to_string()));

                if let Some(error) = error {
                    let _ = send_google_callback_response(
                        &mut stream,
                        "Google sign-in failed",
                        "You can close this window and return to Autopilot.",
                    );
                    return Err(format!("Google OAuth authorization failed: {}", error));
                }

                if state.as_deref() != Some(expected_state) {
                    let _ = send_google_callback_response(
                        &mut stream,
                        "Google sign-in failed",
                        "The Google OAuth state did not match. You can close this window.",
                    );
                    return Err("Google OAuth state mismatch.".to_string());
                }

                let Some(code) = code else {
                    let _ = send_google_callback_response(
                        &mut stream,
                        "Google sign-in failed",
                        "No authorization code was returned. You can close this window.",
                    );
                    return Err("Google OAuth callback did not include an authorization code.".to_string());
                };

                let _ = send_google_callback_response(
                    &mut stream,
                    "Google authorization received",
                    "Google returned an authorization code. You can close this window and return to Autopilot while sign-in finishes locally.",
                );
                return Ok(code);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("Timed out waiting for Google OAuth callback.".to_string());
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            Err(error) => {
                return Err(format!("Google OAuth callback listener failed: {}", error));
            }
        }
    }
}

fn send_google_callback_response(
    stream: &mut std::net::TcpStream,
    title: &str,
    message: &str,
) -> Result<(), String> {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{}</title></head><body><h1>{}</h1><p>{}</p></body></html>",
        html_escape(title),
        html_escape(title),
        html_escape(message)
    );
    let payload = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    stream
        .write_all(payload.as_bytes())
        .map_err(|error| format!("Failed to write Google OAuth callback response: {}", error))
}

fn build_google_auth_url(
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
    scopes: &[String],
) -> Result<String, String> {
    let mut url = Url::parse(GOOGLE_AUTH_URL)
        .map_err(|error| format!("Failed to build Google OAuth URL: {}", error))?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("access_type", "offline")
        .append_pair("include_granted_scopes", "true")
        .append_pair("prompt", "consent select_account")
        .append_pair("state", state)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("scope", &scopes.join(" "));
    Ok(url.to_string())
}

fn open_url_in_browser(url: &str) -> Result<(), String> {
    let status = if cfg!(target_os = "macos") {
        Command::new("open").arg(url).status()
    } else if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", "start", "", url]).status()
    } else {
        Command::new("xdg-open").arg(url).status()
    }
    .map_err(|error| format!("Failed to open browser for Google OAuth: {}", error))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "Failed to open browser for Google OAuth. Exit status: {}",
            status
        ))
    }
}

fn split_scope_string(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn pkce_code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn random_url_safe_token(byte_len: usize) -> String {
    let mut bytes = vec![0_u8; byte_len];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn env_string(keys: &[&str]) -> Option<String> {
    load_local_google_env_defaults();
    keys.iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn load_local_google_env_defaults() {
    let Ok(mut loaded) = GOOGLE_LOCAL_ENV_LOADED.lock() else {
        return;
    };
    if *loaded {
        return;
    }
    *loaded = true;

    let mut candidate_roots = Vec::new();
    if let Ok(current_dir) = std::env::current_dir() {
        candidate_roots.extend(ancestor_paths(&current_dir));
    }
    candidate_roots.extend(ancestor_paths(&PathBuf::from(env!("CARGO_MANIFEST_DIR"))));
    candidate_roots.sort();
    candidate_roots.dedup();

    for root in candidate_roots {
        let candidate = root.join(".env.google-e2e.local");
        if !candidate.exists() {
            continue;
        }
        if let Ok(iter) = from_path_iter(&candidate) {
            for entry in iter.flatten() {
                if std::env::var_os(&entry.0).is_none() {
                    std::env::set_var(&entry.0, entry.1);
                }
            }
            break;
        }
    }
}

fn ancestor_paths(path: &PathBuf) -> Vec<PathBuf> {
    let mut next = Vec::new();
    for ancestor in path.ancestors() {
        next.push(ancestor.to_path_buf());
    }
    next
}

fn google_client_storage_path() -> Result<PathBuf, String> {
    if let Some(path) = env_string(&["IOI_GOOGLE_CLIENT_CONFIG_PATH"]) {
        return Ok(PathBuf::from(path));
    }

    let auth_path = google_auth_storage_path()?;
    let base_dir = auth_path.parent().map(PathBuf::from).ok_or_else(|| {
        "Unable to resolve Google OAuth client config directory.".to_string()
    })?;
    Ok(base_dir.join(GOOGLE_CLIENT_FILE_NAME))
}

fn mask_client_id(client_id: &str) -> String {
    let trimmed = client_id.trim();
    if trimmed.len() <= 18 {
        return trimmed.to_string();
    }
    let prefix = &trimmed[..8];
    let suffix = &trimmed[trimmed.len() - 10..];
    format!("{}...{}", prefix, suffix)
}

fn parse_rfc3339(raw: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(raw, &Rfc3339).ok()
}

fn format_rfc3339(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn html_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        expand_google_scope, missing_required_scopes, resolve_requested_google_oauth_scopes,
        split_scope_string,
    };

    #[test]
    fn expands_google_scopes() {
        assert_eq!(
            expand_google_scope("gmail.modify"),
            vec!["https://www.googleapis.com/auth/gmail.modify".to_string()]
        );
        assert_eq!(
            expand_google_scope("https://www.googleapis.com/auth/drive"),
            vec!["https://www.googleapis.com/auth/drive".to_string()]
        );
    }

    #[test]
    fn detects_missing_scopes_by_alias() {
        let granted = vec![
            "https://www.googleapis.com/auth/gmail.modify".to_string(),
            "https://www.googleapis.com/auth/calendar".to_string(),
        ];
        let missing = missing_required_scopes(&granted, &["gmail.modify", "spreadsheets"]);
        assert_eq!(missing, vec!["spreadsheets".to_string()]);
    }

    #[test]
    fn broader_google_scopes_cover_readonly_requirements() {
        let granted = vec![
            "https://www.googleapis.com/auth/gmail.modify".to_string(),
            "https://www.googleapis.com/auth/calendar".to_string(),
            "https://www.googleapis.com/auth/tasks".to_string(),
            "https://www.googleapis.com/auth/drive".to_string(),
        ];
        let missing = missing_required_scopes(
            &granted,
            &["gmail.readonly", "calendar.readonly", "tasks.readonly", "drive.readonly"],
        );
        assert!(missing.is_empty());
    }

    #[test]
    fn splits_scope_strings() {
        assert_eq!(
            split_scope_string("a b  c"),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn requested_google_scopes_include_identity_and_selected_bundles() {
        let scopes = resolve_requested_google_oauth_scopes(Some(vec![
            "gmail.modify".to_string(),
            "calendar".to_string(),
        ]))
        .expect("requested scopes should resolve");

        assert!(scopes.iter().any(|scope| scope == "openid"));
        assert!(scopes.iter().any(|scope| scope == "email"));
        assert!(
            scopes
                .iter()
                .any(|scope| scope == "https://www.googleapis.com/auth/gmail.modify")
        );
        assert!(
            scopes
                .iter()
                .any(|scope| scope == "https://www.googleapis.com/auth/calendar")
        );
    }
}
