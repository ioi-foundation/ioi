use crate::models::ChatOutcomeRequest;
use ioi_api::runtime_harness::ChatIntentContext;
use std::time::Duration;
use url::Url;

pub(super) fn extract_weather_scopes(intent: &str) -> Vec<String> {
    ChatIntentContext::new(intent).extract_weather_scopes()
}

fn trailing_measurement(tokens: &[&str], units: &[&str]) -> Option<String> {
    let unit_index = tokens
        .iter()
        .position(|token| units.iter().any(|unit| token.eq(unit)))?;
    if unit_index == 0 {
        return None;
    }
    Some(format!("{} {}", tokens[unit_index - 1], tokens[unit_index]))
}

fn trailing_wind_measurement(tokens: &[&str]) -> Option<String> {
    let wind = trailing_measurement(tokens, &["mph", "km/h"])?;
    let speed_index = tokens
        .iter()
        .position(|token| *token == "mph" || *token == "km/h")?;
    if speed_index < 2 {
        return Some(wind);
    }

    let direction = tokens[speed_index - 2];
    let has_arrow = direction
        .chars()
        .any(|character| matches!(character, '↑' | '↓' | '←' | '→' | '↖' | '↗' | '↘' | '↙'));
    if has_arrow {
        Some(format!("{direction} {wind}"))
    } else {
        Some(wind)
    }
}

pub(super) fn parse_weather_report_fallback(scope: &str, body: &str) -> Option<String> {
    let mut condition = None;
    let mut temperature = None;
    let mut wind = None;
    let mut visibility = None;
    let mut precipitation = None;

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if condition.is_none()
            && !trimmed.contains('_')
            && !trimmed.contains("°")
            && !trimmed.contains("mph")
            && !trimmed.contains("km/h")
            && !trimmed.contains(" mi")
            && !trimmed.contains(" km")
            && !trimmed.contains(" in")
            && !trimmed.contains(" mm")
            && !trimmed.starts_with("Weather report:")
        {
            condition = Some(trimmed.to_string());
            continue;
        }

        let tokens = trimmed.split_whitespace().collect::<Vec<_>>();
        if temperature.is_none() {
            temperature = trailing_measurement(&tokens, &["°F", "°C"]);
        }
        if wind.is_none() {
            wind = trailing_wind_measurement(&tokens);
        }
        if visibility.is_none() {
            visibility = trailing_measurement(&tokens, &["mi", "km"]);
        }
        if precipitation.is_none() {
            precipitation = trailing_measurement(&tokens, &["in", "mm"]);
        }
    }

    let mut parts = Vec::new();
    if let Some(summary) = condition {
        parts.push(summary);
    }
    if let Some(summary) = temperature {
        parts.push(summary);
    }
    if let Some(summary) = wind {
        parts.push(format!("wind {summary}"));
    }
    if let Some(summary) = visibility {
        parts.push(format!("visibility {summary}"));
    }
    if let Some(summary) = precipitation {
        parts.push(format!("precipitation {summary}"));
    }

    if parts.is_empty() {
        None
    } else {
        Some(format!("{}: {}.", scope.trim(), parts.join(" ")))
    }
}

fn fetch_weather_scope_summary(scope: &str) -> Result<String, String> {
    let client = super::places::chat_surface_http_client()?;
    let formats = [
        "%l: temp %t humidity %h wind %w pressure %P as of %T",
        "%l: %t %C",
    ];
    let mut last_error = None;

    for format in formats {
        for attempt in 0..3 {
            let mut url = Url::parse("https://wttr.in/").expect("static wttr base URL parses");
            url.set_path(&format!("/{}", scope));
            url.query_pairs_mut().append_pair("format", format);

            match client
                .get(url)
                .send()
                .and_then(reqwest::blocking::Response::error_for_status)
            {
                Ok(response) => {
                    let body = response.text().map_err(|error| {
                        format!("Chat weather surface could not read current conditions: {error}")
                    })?;
                    let cleaned = body.split_whitespace().collect::<Vec<_>>().join(" ");
                    if cleaned.is_empty() {
                        last_error = Some(
                            "Chat weather surface returned an empty conditions summary."
                                .to_string(),
                        );
                    } else if cleaned.to_ascii_lowercase().contains("unknown location") {
                        return Err(format!("Chat weather surface could not locate '{scope}'.",));
                    } else {
                        return Ok(cleaned.trim_end_matches('.').to_string() + ".");
                    }
                }
                Err(error) => {
                    last_error = Some(format!(
                        "Chat weather surface could not fetch current conditions: {error}"
                    ));
                }
            }

            if attempt < 2 {
                std::thread::sleep(Duration::from_millis(350));
            }
        }
    }

    for attempt in 0..3 {
        let mut url = Url::parse("https://wttr.in/").expect("static wttr base URL parses");
        url.set_path(&format!("/{}", scope));
        url.set_query(Some("0T"));

        match client
            .get(url)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
        {
            Ok(response) => {
                let body = response.text().map_err(|error| {
                    format!("Chat weather surface could not read current conditions: {error}")
                })?;
                if body.to_ascii_lowercase().contains("unknown location") {
                    return Err(format!("Chat weather surface could not locate '{scope}'.",));
                }
                if let Some(summary) = parse_weather_report_fallback(scope, &body) {
                    return Ok(summary);
                }
                last_error = Some(
                    "Chat weather surface returned an unreadable fallback weather report."
                        .to_string(),
                );
            }
            Err(error) => {
                last_error = Some(format!(
                    "Chat weather surface could not fetch current conditions: {error}"
                ));
            }
        }

        if attempt < 2 {
            std::thread::sleep(Duration::from_millis(350));
        }
    }

    Err(last_error
        .unwrap_or_else(|| "Chat weather surface could not fetch current conditions.".to_string()))
}

pub(super) fn weather_scopes_for_tool_widget(
    intent: &str,
    outcome_request: &ChatOutcomeRequest,
) -> Vec<String> {
    let scopes = extract_weather_scopes(intent);
    if !scopes.is_empty() {
        return scopes;
    }

    match outcome_request.normalized_request.as_ref() {
        Some(ioi_types::app::chat::ChatNormalizedRequest::Weather(frame)) => {
            let mut retained = frame.inferred_locations.clone();
            if let Some(location) = frame.assumed_location.as_ref() {
                if !retained
                    .iter()
                    .any(|entry| entry.eq_ignore_ascii_case(location))
                {
                    retained.push(location.clone());
                }
            }
            retained
        }
        _ => Vec::new(),
    }
}

pub(super) fn fetch_weather_tool_widget_reply(
    intent: &str,
    outcome_request: &ChatOutcomeRequest,
) -> Result<String, String> {
    let scopes = weather_scopes_for_tool_widget(intent, outcome_request);
    if scopes.is_empty() {
        return Err(
            "Chat could not determine which location to use for the weather request.".to_string(),
        );
    }
    if scopes.len() == 1 {
        return fetch_weather_scope_summary(&scopes[0]);
    }

    let mut lines = vec!["Current weather comparison:".to_string()];
    for scope in scopes {
        lines.push(format!("- {}", fetch_weather_scope_summary(&scope)?));
    }
    Ok(lines.join("\n"))
}
