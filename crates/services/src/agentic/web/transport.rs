use anyhow::{anyhow, Result};
use ioi_drivers::browser::BrowserDriver;
use reqwest::{redirect, Client};
use std::time::Duration;
use tokio::time::timeout;

#[cfg(test)]
use std::future::Future;

use super::constants::{BROWSER_RETRIEVAL_TIMEOUT_SECS, HTTP_FALLBACK_TIMEOUT_SECS};
use super::util::env_flag_enabled;

const DEFAULT_HTTP_USER_AGENT: &str = "ioi-web-retrieve/1.0";
const STANDARD_WEB_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

pub(crate) fn record_challenge(
    challenge_reason: &mut Option<String>,
    challenge_url: &mut Option<String>,
    url: &str,
    reason: Option<&'static str>,
) {
    let Some(reason) = reason else {
        return;
    };
    if challenge_reason.is_none() {
        *challenge_reason = Some(reason.to_string());
        *challenge_url = Some(url.to_string());
    }
}

pub(crate) fn detect_human_challenge(url: &str, content: &str) -> Option<&'static str> {
    let url_lc = url.to_ascii_lowercase();
    let content_lc = content.to_ascii_lowercase();

    // Generic bot-check markers.
    if url_lc.contains("/sorry/") || content_lc.contains("/sorry/") {
        return Some("challenge redirect (/sorry/) detected");
    }
    if content_lc.contains("recaptcha") || content_lc.contains("g-recaptcha") {
        return Some("reCAPTCHA challenge marker detected");
    }
    if content_lc.contains("i'm not a robot") || content_lc.contains("i am not a robot") {
        return Some("robot-verification checkbox detected");
    }
    if content_lc.contains("verify you are human")
        || content_lc.contains("human verification")
        || content_lc.contains("please verify you are a human")
    {
        return Some("human-verification challenge detected");
    }

    // Cloudflare challenge flows.
    let cloudflare_surface = content_lc.contains("cloudflare")
        || content_lc.contains("cf-ray")
        || content_lc.contains("ray id")
        || content_lc.contains("__cf_chl")
        || content_lc.contains("cf_chl");
    if cloudflare_surface
        && (content_lc.contains("just a moment")
            || content_lc.contains("checking your browser before accessing")
            || content_lc.contains("please enable javascript and cookies to continue")
            || content_lc.contains("attention required"))
    {
        return Some("cloudflare challenge detected");
    }

    // DuckDuckGo anomaly / bot-check flows.
    if content_lc.contains("anomaly")
        && (url_lc.contains("duckduckgo") || content_lc.contains("duckduckgo"))
    {
        return Some("duckduckgo anomaly/bot-check detected");
    }
    if content_lc.contains("challenge-form") && url_lc.contains("duckduckgo") {
        return Some("duckduckgo challenge form detected");
    }

    None
}

fn is_timeout_or_hang_message(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("request timed out")
        || lower.contains("deadline")
        || lower.contains("hang")
}

#[cfg(test)]
fn is_browser_unavailable_message(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("browser is cold")
        || lower.contains("no lease")
        || lower.contains("set_lease(true)")
}

#[cfg(test)]
fn should_attempt_http_fallback(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    is_timeout_or_hang_message(&msg) || is_browser_unavailable_message(&msg)
}

pub(crate) async fn navigate_browser_retrieval(
    browser: &BrowserDriver,
    url: &str,
) -> Result<String> {
    if env_flag_enabled("IOI_WEB_TEST_FORCE_BROWSER_TIMEOUT") {
        return Err(anyhow!(
            "ERROR_CLASS=TimeoutOrHang browser retrieval timed out after {}s: {} (forced)",
            BROWSER_RETRIEVAL_TIMEOUT_SECS,
            url
        ));
    }

    let retrieval = timeout(
        Duration::from_secs(BROWSER_RETRIEVAL_TIMEOUT_SECS),
        browser.navigate_retrieval(url),
    )
    .await;

    match retrieval {
        Ok(Ok(html)) => Ok(html),
        Ok(Err(e)) => {
            let msg = format!("browser retrieval navigate failed: {}", e);
            if is_timeout_or_hang_message(&msg) {
                return Err(anyhow!("ERROR_CLASS=TimeoutOrHang {}", msg));
            }
            Err(anyhow!("{}", msg))
        }
        Err(_) => Err(anyhow!(
            "ERROR_CLASS=TimeoutOrHang browser retrieval timed out after {}s: {}",
            BROWSER_RETRIEVAL_TIMEOUT_SECS,
            url
        )),
    }
}

async fn fetch_html_http_fallback_with_user_agent(url: &str, user_agent: &str) -> Result<String> {
    if env_flag_enabled("IOI_WEB_TEST_FORCE_HTTP_TIMEOUT") {
        return Err(anyhow!("HTTP fallback request timed out (forced): {}", url));
    }
    if let Ok(html) = std::env::var("IOI_WEB_TEST_HTTP_FALLBACK_HTML") {
        return Ok(html);
    }

    let client = Client::builder()
        .redirect(redirect::Policy::limited(5))
        .timeout(Duration::from_secs(HTTP_FALLBACK_TIMEOUT_SECS))
        .user_agent(user_agent)
        .build()
        .map_err(|e| anyhow!("HTTP fallback client init failed: {}", e))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("HTTP fallback request failed: {}", e))?;

    response
        .text()
        .await
        .map_err(|e| anyhow!("HTTP fallback body read failed: {}", e))
}

pub(crate) async fn fetch_html_http_fallback(url: &str) -> Result<String> {
    fetch_html_http_fallback_with_user_agent(url, DEFAULT_HTTP_USER_AGENT).await
}

pub(crate) async fn fetch_html_http_fallback_browser_ua(url: &str) -> Result<String> {
    fetch_html_http_fallback_with_user_agent(url, STANDARD_WEB_USER_AGENT).await
}

#[cfg(test)]
pub(crate) async fn retrieve_html_with_fallback<FFut, F>(
    url: &str,
    primary: Result<String>,
    fallback_fetch: F,
) -> Result<String>
where
    F: FnOnce() -> FFut,
    FFut: Future<Output = Result<String>>,
{
    match primary {
        Ok(html) => Ok(html),
        Err(primary_err) => {
            if !should_attempt_http_fallback(&primary_err) {
                return Err(primary_err);
            }

            match fallback_fetch().await {
                Ok(html) => Ok(html),
                Err(fallback_err) => Err(anyhow!(
                    "ERROR_CLASS=TimeoutOrHang web retrieval timeout exhaustion for {}. primary_error={} fallback_error={}",
                    url,
                    primary_err,
                    fallback_err
                )),
            }
        }
    }
}
