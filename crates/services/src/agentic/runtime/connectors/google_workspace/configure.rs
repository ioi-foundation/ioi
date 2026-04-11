use super::{google_api, google_auth};
use super::{
    matches_google_connector_id, now_rfc3339, optional_string, required_string,
    ConnectorConfigureResult, GOOGLE_CONNECTOR_ID, GOOGLE_CONNECTOR_PROVIDER,
};
use serde_json::Value;

pub async fn connector_configure(
    connector_id: &str,
    input: Value,
) -> Result<ConnectorConfigureResult, String> {
    if !matches_google_connector_id(connector_id) {
        return Err(format!("Unsupported connector '{}'", connector_id));
    }

    let mode = optional_string(&input, "mode").unwrap_or_else(|| "status".to_string());
    match mode.as_str() {
        "login" | "connect" => configure_google_login(&input).await,
        "cancel_login" | "cancel_pending_auth" | "abort_login" => {
            configure_google_cancel_login().await
        }
        "save_oauth_client" | "set_oauth_client" => {
            configure_google_save_oauth_client(&input).await
        }
        "clear_oauth_client" => configure_google_clear_oauth_client().await,
        "logout" | "disconnect" => configure_google_logout().await,
        _ => configure_google_status().await,
    }
}

async fn configure_google_status() -> Result<ConnectorConfigureResult, String> {
    let auth = google_auth::status().await?;
    let mut data = auth.data;

    if auth.status == "connected" {
        let bootstrap = google_api::bootstrap_workspace_profile().await.ok();
        if let Some(bootstrap) = bootstrap {
            if let Value::Object(ref mut map) = data {
                map.insert("bootstrap".to_string(), bootstrap);
            }
        }
    }

    Ok(ConnectorConfigureResult {
        connector_id: GOOGLE_CONNECTOR_ID.to_string(),
        provider: GOOGLE_CONNECTOR_PROVIDER.to_string(),
        status: auth.status,
        summary: auth.summary,
        data: Some(data),
        executed_at_utc: now_rfc3339(),
    })
}

async fn configure_google_login(input: &Value) -> Result<ConnectorConfigureResult, String> {
    let requested_scopes = input
        .get("requestedScopes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        });
    let auth = google_auth::login(requested_scopes).await?;

    Ok(ConnectorConfigureResult {
        connector_id: GOOGLE_CONNECTOR_ID.to_string(),
        provider: GOOGLE_CONNECTOR_PROVIDER.to_string(),
        status: auth.status,
        summary: auth.summary,
        data: Some(auth.data),
        executed_at_utc: now_rfc3339(),
    })
}

async fn configure_google_save_oauth_client(
    input: &Value,
) -> Result<ConnectorConfigureResult, String> {
    google_auth::save_oauth_client(
        required_string(input, "clientId")?,
        super::optional_string(input, "clientSecret"),
    )?;

    let mut result = configure_google_status().await?;
    result.summary = "Saved local Google OAuth client configuration.".to_string();
    Ok(result)
}

async fn configure_google_clear_oauth_client() -> Result<ConnectorConfigureResult, String> {
    google_auth::clear_oauth_client()?;

    let mut result = configure_google_status().await?;
    result.summary = "Cleared local Google OAuth client configuration.".to_string();
    Ok(result)
}

async fn configure_google_cancel_login() -> Result<ConnectorConfigureResult, String> {
    let auth = google_auth::cancel_pending_login().await?;

    Ok(ConnectorConfigureResult {
        connector_id: GOOGLE_CONNECTOR_ID.to_string(),
        provider: GOOGLE_CONNECTOR_PROVIDER.to_string(),
        status: auth.status,
        summary: auth.summary,
        data: Some(auth.data),
        executed_at_utc: now_rfc3339(),
    })
}

async fn configure_google_logout() -> Result<ConnectorConfigureResult, String> {
    let auth = google_auth::logout().await?;

    Ok(ConnectorConfigureResult {
        connector_id: GOOGLE_CONNECTOR_ID.to_string(),
        provider: GOOGLE_CONNECTOR_PROVIDER.to_string(),
        status: auth.status,
        summary: auth.summary,
        data: Some(auth.data),
        executed_at_utc: now_rfc3339(),
    })
}
