use anyhow::{anyhow, Context, Result};
use reqwest::Method;
use serde_json::Value;
use std::time::Duration;

pub async fn daemon_request(
    endpoint: Option<&str>,
    token: Option<&str>,
    method: Method,
    route: &str,
    body: Option<Value>,
) -> Result<Value> {
    let endpoint = endpoint
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("IOI_DAEMON_ENDPOINT").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8765".to_string());
    let url = format!(
        "{}/{}",
        endpoint.trim_end_matches('/'),
        route.trim_start_matches('/')
    );
    let token = token
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("IOI_DAEMON_TOKEN").ok());

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build local IOI daemon HTTP client")?;
    let mut request = client
        .request(method, &url)
        .header("accept", "application/json");
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("failed to call local IOI daemon at {url}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .with_context(|| format!("failed to read local IOI daemon response from {url}"))?;
    let value = if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).with_context(|| {
            format!("local IOI daemon returned non-JSON response from {url}: {text}")
        })?
    };
    if !status.is_success() {
        return Err(anyhow!(
            "local IOI daemon request failed: {} {} -> {} {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("error"),
            url,
            value
        ));
    }
    Ok(value)
}

pub fn print_value(value: &Value, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}
