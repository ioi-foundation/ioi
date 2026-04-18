use super::content_session::attach_non_artifact_studio_session;
use super::revisions::persist_studio_artifact_exemplar;
use super::*;
use crate::models::ChatMessage;
use ioi_api::execution::{ExecutionEnvelope, ExecutionStage};
use ioi_api::studio::{
    resolve_runtime_locality_placeholder, StudioArtifactExemplar, StudioArtifactGenerationProgress,
    StudioArtifactMergeReceipt, StudioArtifactPatchReceipt, StudioArtifactRuntimeEventStatus,
    StudioArtifactRuntimeEventType, StudioArtifactRuntimeNarrationEvent,
    StudioArtifactRuntimeStepId, StudioArtifactSwarmExecutionSummary, StudioArtifactSwarmPlan,
    StudioArtifactVerificationReceipt, StudioArtifactWorkerReceipt, StudioIntentContext,
};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::StudioExecutionStrategy;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

fn publish_current_task_progress(
    app: &AppHandle,
    task: &mut AgentTask,
    current_step: impl Into<String>,
) {
    task.phase = AgentPhase::Running;
    task.current_step = current_step.into();
    publish_current_task_snapshot(app, task);
}

fn publish_current_task_snapshot(app: &AppHandle, task: &AgentTask) {
    let task_id = task.id.clone();
    let task_snapshot = task.clone();
    let state = app.state::<Mutex<AppState>>();
    let mut memory_runtime = None;
    let mut replaced_current_task = false;

    if let Ok(mut guard) = state.lock() {
        memory_runtime = guard.memory_runtime.clone();
        if let Some(current_task) = guard.current_task.as_mut() {
            if current_task.id == task_id {
                *current_task = task_snapshot.clone();
                replaced_current_task = true;
            }
        }
    }

    if !replaced_current_task {
        return;
    }

    if let Some(memory_runtime) = memory_runtime.as_ref() {
        orchestrator::save_local_task_state(memory_runtime, &task_snapshot);
    }

    let _ = app.emit("task-updated", &task_snapshot);
    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        crate::kernel::session::emit_session_projection_update(&app_clone, false).await;
    });
}

fn build_direct_inline_conversation_prompt(intent: &str) -> String {
    format!(
        "You are Autopilot Studio's direct inline reply path.\n\
Answer the user's request directly.\n\
Constraints:\n\
- Answer in plain prose with no preamble about tools, routing, or process.\n\
- Do not mention unavailable tools or system internals.\n\
- Avoid markdown headings unless the user explicitly asked for structure.\n\
- Keep the answer compact but complete for a normal chat turn.\n\
- If the request truly cannot be answered safely without fresh external information, say that briefly instead of inventing details.\n\
\n\
User request:\n{intent}\n"
    )
}

fn tool_widget_family_hint(outcome_request: &StudioOutcomeRequest) -> Option<&str> {
    outcome_request
        .routing_hints
        .iter()
        .find_map(|hint| hint.strip_prefix("tool_widget:"))
}

#[derive(Clone, Copy)]
struct SportsTeamTarget {
    aliases: &'static [&'static str],
    display_name: &'static str,
    sport_path: &'static str,
    team_id: &'static str,
}

const SPORTS_TEAM_TARGETS: &[SportsTeamTarget] = &[
    SportsTeamTarget {
        aliases: &["lakers", "los angeles lakers"],
        display_name: "Los Angeles Lakers",
        sport_path: "basketball/nba",
        team_id: "13",
    },
    SportsTeamTarget {
        aliases: &["celtics", "boston celtics"],
        display_name: "Boston Celtics",
        sport_path: "basketball/nba",
        team_id: "2",
    },
    SportsTeamTarget {
        aliases: &["warriors", "golden state warriors"],
        display_name: "Golden State Warriors",
        sport_path: "basketball/nba",
        team_id: "9",
    },
    SportsTeamTarget {
        aliases: &["knicks", "new york knicks"],
        display_name: "New York Knicks",
        sport_path: "basketball/nba",
        team_id: "18",
    },
    SportsTeamTarget {
        aliases: &["yankees", "new york yankees"],
        display_name: "New York Yankees",
        sport_path: "baseball/mlb",
        team_id: "10",
    },
    SportsTeamTarget {
        aliases: &["dodgers", "los angeles dodgers"],
        display_name: "Los Angeles Dodgers",
        sport_path: "baseball/mlb",
        team_id: "19",
    },
    SportsTeamTarget {
        aliases: &["chiefs", "kansas city chiefs"],
        display_name: "Kansas City Chiefs",
        sport_path: "football/nfl",
        team_id: "12",
    },
    SportsTeamTarget {
        aliases: &["cowboys", "dallas cowboys"],
        display_name: "Dallas Cowboys",
        sport_path: "football/nfl",
        team_id: "6",
    },
    SportsTeamTarget {
        aliases: &["packers", "green bay packers"],
        display_name: "Green Bay Packers",
        sport_path: "football/nfl",
        team_id: "9",
    },
    SportsTeamTarget {
        aliases: &["steelers", "pittsburgh steelers"],
        display_name: "Pittsburgh Steelers",
        sport_path: "football/nfl",
        team_id: "23",
    },
    SportsTeamTarget {
        aliases: &["eagles", "philadelphia eagles"],
        display_name: "Philadelphia Eagles",
        sport_path: "football/nfl",
        team_id: "21",
    },
];

#[derive(Clone, Copy)]
struct PlacesCategoryTarget {
    amenity: &'static str,
    label: &'static str,
}

#[derive(Clone)]
struct ParsedPlacesRequest {
    anchor_phrase: String,
    category: PlacesCategoryTarget,
}

#[derive(Clone)]
struct PlaceCandidate {
    name: String,
    address_line: String,
    distance_miles: f64,
}

#[derive(Deserialize)]
struct NominatimSearchResult {
    lat: String,
    lon: String,
    display_name: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    address: Option<NominatimAddress>,
}

#[derive(Default, Deserialize)]
struct NominatimAddress {
    #[serde(default)]
    amenity: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    town: Option<String>,
    #[serde(default)]
    village: Option<String>,
    #[serde(default)]
    municipality: Option<String>,
    #[serde(default)]
    county: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

#[derive(Deserialize)]
struct OverpassResponse {
    #[serde(default)]
    elements: Vec<OverpassElement>,
}

#[derive(Deserialize)]
struct OverpassElement {
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    center: Option<OverpassCenter>,
    #[serde(default)]
    tags: HashMap<String, String>,
}

#[derive(Deserialize)]
struct OverpassCenter {
    lat: f64,
    lon: f64,
}

#[derive(Deserialize)]
struct EspnTeamEnvelope {
    team: EspnTeamSummary,
}

#[derive(Deserialize)]
struct EspnTeamSummary {
    #[serde(rename = "displayName", default)]
    display_name: Option<String>,
    #[serde(rename = "standingSummary", default)]
    standing_summary: Option<String>,
    #[serde(default)]
    record: Option<EspnRecord>,
    #[serde(rename = "nextEvent", default)]
    next_event: Vec<EspnEvent>,
}

#[derive(Deserialize)]
struct EspnRecord {
    #[serde(default)]
    items: Vec<EspnRecordItem>,
}

#[derive(Deserialize)]
struct EspnRecordItem {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    summary: Option<String>,
}

#[derive(Deserialize)]
struct EspnEvent {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct EspnNewsEnvelope {
    #[serde(default)]
    articles: Vec<EspnNewsArticle>,
}

#[derive(Deserialize)]
struct EspnNewsArticle {
    #[serde(default)]
    headline: Option<String>,
}

fn studio_surface_http_client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("ioi-autopilot-studio/0.1")
        .build()
        .map_err(|error| format!("Studio surface could not build its client: {error}"))
}

fn place_category_for_intent(intent: &str) -> Option<PlacesCategoryTarget> {
    place_category_target_from_label(StudioIntentContext::new(intent).places_category_label()?)
}

fn place_category_target_from_label(label: &str) -> Option<PlacesCategoryTarget> {
    match label.trim().to_ascii_lowercase().as_str() {
        "coffee shops" => Some(PlacesCategoryTarget {
            amenity: "cafe",
            label: "coffee shops",
        }),
        "restaurants" => Some(PlacesCategoryTarget {
            amenity: "restaurant",
            label: "restaurants",
        }),
        "bars" => Some(PlacesCategoryTarget {
            amenity: "bar",
            label: "bars",
        }),
        _ => None,
    }
}

fn anchor_phrase_for_places_intent(intent: &str) -> Option<String> {
    StudioIntentContext::new(intent).places_anchor_phrase()
}

fn parse_places_request(intent: &str) -> Option<ParsedPlacesRequest> {
    Some(ParsedPlacesRequest {
        anchor_phrase: anchor_phrase_for_places_intent(intent)?,
        category: place_category_for_intent(intent)?,
    })
}

fn places_request_for_tool_widget(
    intent: &str,
    outcome_request: &StudioOutcomeRequest,
) -> Option<ParsedPlacesRequest> {
    match outcome_request.request_frame.as_ref() {
        Some(ioi_types::app::studio::StudioNormalizedRequestFrame::Places(frame)) => {
            let category = frame
                .category
                .as_deref()
                .and_then(place_category_target_from_label);
            let anchor_phrase = frame
                .search_anchor
                .clone()
                .or_else(|| frame.location_scope.clone())
                .filter(|scope| !scope.trim().is_empty())
                .and_then(|scope| resolve_runtime_locality_placeholder(&scope));
            if let (Some(anchor_phrase), Some(category)) = (anchor_phrase, category) {
                return Some(ParsedPlacesRequest {
                    anchor_phrase,
                    category,
                });
            }
        }
        _ => {}
    }

    parse_places_request(intent)
}

fn parse_lat_lon_pair(lat: &str, lon: &str) -> Option<(f64, f64)> {
    Some((lat.parse().ok()?, lon.parse().ok()?))
}

fn haversine_distance_miles(start: (f64, f64), end: (f64, f64)) -> f64 {
    let earth_radius_miles = 3958.8_f64;
    let lat1 = start.0.to_radians();
    let lat2 = end.0.to_radians();
    let dlat = (end.0 - start.0).to_radians();
    let dlon = (end.1 - start.1).to_radians();
    let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    earth_radius_miles * c
}

fn nominatim_city(address: &NominatimAddress) -> Option<&str> {
    address
        .city
        .as_deref()
        .or(address.town.as_deref())
        .or(address.village.as_deref())
        .or(address.municipality.as_deref())
        .or(address.county.as_deref())
}

fn short_place_name(result: &NominatimSearchResult) -> String {
    result
        .name
        .as_deref()
        .or_else(|| {
            result
                .address
                .as_ref()
                .and_then(|address| address.amenity.as_deref())
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            result
                .display_name
                .split(',')
                .next()
                .unwrap_or("Nearby place")
                .trim()
                .to_string()
        })
}

fn short_place_address(result: &NominatimSearchResult) -> String {
    let segments: Vec<&str> = result
        .display_name
        .split(',')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.len() <= 1 {
        return result.display_name.trim().to_string();
    }
    segments
        .iter()
        .skip(1)
        .take(3)
        .copied()
        .collect::<Vec<_>>()
        .join(", ")
}

fn overpass_element_coords(element: &OverpassElement) -> Option<(f64, f64)> {
    match (element.lat, element.lon) {
        (Some(lat), Some(lon)) => Some((lat, lon)),
        _ => element
            .center
            .as_ref()
            .map(|center| (center.lat, center.lon)),
    }
}

fn short_overpass_place_name(element: &OverpassElement) -> String {
    element
        .tags
        .get("name")
        .map(String::as_str)
        .or_else(|| element.tags.get("amenity").map(String::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "Nearby place".to_string())
}

fn short_overpass_place_address(element: &OverpassElement) -> String {
    let mut segments = Vec::new();
    if let Some(house_number) = element.tags.get("addr:housenumber") {
        segments.push(house_number.trim().to_string());
    }
    if let Some(street) = element.tags.get("addr:street") {
        if segments.is_empty() {
            segments.push(street.trim().to_string());
        } else if let Some(first) = segments.first_mut() {
            *first = format!("{first} {}", street.trim());
        }
    }
    for key in ["addr:neighbourhood", "addr:suburb", "addr:city"] {
        if let Some(value) = element.tags.get(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                segments.push(trimmed.to_string());
            }
        }
    }
    if segments.is_empty() {
        return "Address unavailable".to_string();
    }
    segments.join(", ")
}

fn geocode_anchor_result(
    client: &Client,
    anchor_phrase: &str,
) -> Result<NominatimSearchResult, String> {
    let mut url = Url::parse("https://nominatim.openstreetmap.org/search")
        .expect("static nominatim search URL parses");
    url.query_pairs_mut()
        .append_pair("format", "jsonv2")
        .append_pair("limit", "1")
        .append_pair("addressdetails", "1")
        .append_pair("q", anchor_phrase);
    let results = client
        .get(url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|error| {
            format!("Studio places surface could not geocode '{anchor_phrase}': {error}")
        })?
        .json::<Vec<NominatimSearchResult>>()
        .map_err(|error| {
            format!("Studio places surface could not read its geocoder response: {error}")
        })?;
    results
        .into_iter()
        .next()
        .ok_or_else(|| format!("Studio places surface could not locate '{anchor_phrase}'."))
}

fn nearby_place_subset(mut candidates: Vec<PlaceCandidate>) -> Vec<PlaceCandidate> {
    candidates.sort_by(|left, right| left.distance_miles.total_cmp(&right.distance_miles));
    candidates.dedup_by(|left, right| left.name.eq_ignore_ascii_case(&right.name));
    candidates
        .into_iter()
        .filter(|candidate| candidate.distance_miles <= 3.0)
        .take(5)
        .collect()
}

fn nearby_places_from_overpass(
    overpass: OverpassResponse,
    anchor_coords: (f64, f64),
) -> Vec<PlaceCandidate> {
    let candidates = overpass
        .elements
        .into_iter()
        .filter_map(|element| {
            let coords = overpass_element_coords(&element)?;
            Some(PlaceCandidate {
                name: short_overpass_place_name(&element),
                address_line: short_overpass_place_address(&element),
                distance_miles: haversine_distance_miles(anchor_coords, coords),
            })
        })
        .collect::<Vec<_>>();
    nearby_place_subset(candidates)
}

fn nearby_places_from_nominatim(
    results: Vec<NominatimSearchResult>,
    anchor_coords: (f64, f64),
) -> Vec<PlaceCandidate> {
    let candidates = results
        .into_iter()
        .filter_map(|result| {
            let coords = parse_lat_lon_pair(&result.lat, &result.lon)?;
            Some(PlaceCandidate {
                name: short_place_name(&result),
                address_line: short_place_address(&result),
                distance_miles: haversine_distance_miles(anchor_coords, coords),
            })
        })
        .collect::<Vec<_>>();
    nearby_place_subset(candidates)
}

fn search_places_with_overpass(
    client: &Client,
    request: &ParsedPlacesRequest,
    anchor_coords: (f64, f64),
) -> Result<Vec<PlaceCandidate>, String> {
    let overpass_query = format!(
        "[out:json][timeout:25];(node(around:5000,{lat},{lon})[amenity={amenity}];way(around:5000,{lat},{lon})[amenity={amenity}];relation(around:5000,{lat},{lon})[amenity={amenity}];);out center tags;",
        lat = anchor_coords.0,
        lon = anchor_coords.1,
        amenity = request.category.amenity,
    );
    let mut last_error = None;
    for endpoint in [
        "https://overpass-api.de/api/interpreter",
        "https://overpass.kumi.systems/api/interpreter",
    ] {
        match client
            .post(endpoint)
            .form(&[("data", overpass_query.clone())])
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
        {
            Ok(response) => match response.json::<OverpassResponse>() {
                Ok(overpass) => {
                    let nearby = nearby_places_from_overpass(overpass, anchor_coords);
                    if !nearby.is_empty() {
                        return Ok(nearby);
                    }
                    last_error = Some(format!(
                        "Studio places surface found no {} near {} via {}.",
                        request.category.label, request.anchor_phrase, endpoint
                    ));
                }
                Err(error) => {
                    last_error = Some(format!(
                        "Studio places surface could not read nearby places from {}: {}",
                        endpoint, error
                    ));
                }
            },
            Err(error) => {
                last_error = Some(format!(
                    "Studio places surface could not search nearby places via {}: {}",
                    endpoint, error
                ));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        format!(
            "Studio places surface could not find {} near {}.",
            request.category.label, request.anchor_phrase
        )
    }))
}

fn search_places_with_nominatim(
    client: &Client,
    request: &ParsedPlacesRequest,
    anchor_coords: (f64, f64),
) -> Result<Vec<PlaceCandidate>, String> {
    let mut url = Url::parse("https://nominatim.openstreetmap.org/search")
        .expect("static nominatim search URL parses");
    let query = format!("{} near {}", request.category.label, request.anchor_phrase);
    url.query_pairs_mut()
        .append_pair("format", "jsonv2")
        .append_pair("limit", "10")
        .append_pair("addressdetails", "1")
        .append_pair("q", &query);
    let results = client
        .get(url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|error| {
            format!("Studio places surface could not query fallback place search: {error}")
        })?
        .json::<Vec<NominatimSearchResult>>()
        .map_err(|error| {
            format!("Studio places surface could not read fallback place search: {error}")
        })?;
    let nearby = nearby_places_from_nominatim(results, anchor_coords);
    if nearby.is_empty() {
        return Err(format!(
            "Studio places surface could not find {} near {}.",
            request.category.label, request.anchor_phrase
        ));
    }
    Ok(nearby)
}

fn fetch_places_candidates(
    client: &Client,
    intent: &str,
    outcome_request: &StudioOutcomeRequest,
) -> Result<(ParsedPlacesRequest, Vec<PlaceCandidate>), String> {
    let request = places_request_for_tool_widget(intent, outcome_request).ok_or_else(|| {
        "Studio could not determine which type of place and anchor location to use.".to_string()
    })?;
    let anchor = geocode_anchor_result(client, &request.anchor_phrase)?;
    let anchor_coords = parse_lat_lon_pair(&anchor.lat, &anchor.lon).ok_or_else(|| {
        format!(
            "Studio places surface could not interpret coordinates for '{}'.",
            request.anchor_phrase
        )
    })?;
    match search_places_with_overpass(client, &request, anchor_coords) {
        Ok(nearby) => Ok((request, nearby)),
        Err(overpass_error) => {
            match search_places_with_nominatim(client, &request, anchor_coords) {
                Ok(nearby) => Ok((request, nearby)),
                Err(nominatim_error) => Err(format!(
                    "{overpass_error} Fallback search also failed: {nominatim_error}"
                )),
            }
        }
    }
}

fn format_places_tool_widget_reply(
    intent: &str,
    outcome_request: &StudioOutcomeRequest,
) -> Result<String, String> {
    let client = studio_surface_http_client()?;
    let (request, candidates) = fetch_places_candidates(&client, intent, outcome_request)?;
    let mut lines = vec![format!(
        "Here are a few {} near {}:",
        request.category.label, request.anchor_phrase
    )];
    for candidate in candidates {
        lines.push(format!(
            "- {} — {} ({:.1} mi away)",
            candidate.name, candidate.address_line, candidate.distance_miles
        ));
    }
    Ok(lines.join("\n"))
}

fn sports_team_target_for_intent(intent: &str) -> Option<SportsTeamTarget> {
    let lowered = StudioIntentContext::new(intent)
        .sports_team_target()
        .map(|target| target.to_ascii_lowercase())
        .unwrap_or_else(|| intent.to_ascii_lowercase());
    SPORTS_TEAM_TARGETS
        .iter()
        .copied()
        .find(|target| target.aliases.iter().any(|alias| lowered.contains(alias)))
}

fn record_summary_for_description(record: &EspnRecord, description: &str) -> Option<String> {
    record.items.iter().find_map(|item| {
        let item_description = item.description.as_deref()?.trim();
        if item_description.eq_ignore_ascii_case(description) {
            item.summary
                .as_deref()
                .map(str::trim)
                .filter(|summary| !summary.is_empty())
                .map(ToOwned::to_owned)
        } else {
            None
        }
    })
}

fn fetch_sports_tool_widget_reply(intent: &str) -> Result<String, String> {
    let team = sports_team_target_for_intent(intent).ok_or_else(|| {
        "Studio could not determine which team to use for the sports request.".to_string()
    })?;
    let client = studio_surface_http_client()?;

    let team_url = format!(
        "https://site.api.espn.com/apis/site/v2/sports/{}/teams/{}",
        team.sport_path, team.team_id
    );
    let team_data = client
        .get(&team_url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|error| format!("Studio sports surface could not fetch team data: {error}"))?
        .json::<EspnTeamEnvelope>()
        .map_err(|error| format!("Studio sports surface could not read team data: {error}"))?;

    let news_url = format!(
        "https://site.api.espn.com/apis/site/v2/sports/{}/news?team={}",
        team.sport_path, team.team_id
    );
    let news_data = client
        .get(&news_url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|error| format!("Studio sports surface could not fetch team headlines: {error}"))?
        .json::<EspnNewsEnvelope>()
        .map_err(|error| format!("Studio sports surface could not read team headlines: {error}"))?;

    let team_summary = team_data.team;
    let team_name = team_summary
        .display_name
        .as_deref()
        .unwrap_or(team.display_name);
    let overall = team_summary
        .record
        .as_ref()
        .and_then(|record| record_summary_for_description(record, "Overall Record"))
        .unwrap_or_else(|| "their current record was unavailable".to_string());
    let standing = team_summary
        .standing_summary
        .as_deref()
        .unwrap_or("their current standing was unavailable");
    let mut lines = vec![format!(
        "{team_name} are {overall} and ESPN currently lists them as {standing}."
    )];

    if let Some(record) = team_summary.record.as_ref() {
        let home = record_summary_for_description(record, "Home Record");
        let away = record_summary_for_description(record, "Away Record");
        if home.is_some() || away.is_some() {
            lines.push(format!(
                "Split: {} at home and {} away.",
                home.unwrap_or_else(|| "record unavailable".to_string()),
                away.unwrap_or_else(|| "record unavailable".to_string())
            ));
        }
    }

    if let Some(next_event) = team_summary
        .next_event
        .iter()
        .find_map(|event| event.name.as_deref())
    {
        lines.push(format!("Next listed game: {next_event}."));
    }

    let headlines = news_data
        .articles
        .iter()
        .filter_map(|article| article.headline.as_deref())
        .take(3)
        .collect::<Vec<_>>();
    if !headlines.is_empty() {
        lines.push("Recent headlines:".to_string());
        for headline in headlines {
            lines.push(format!("- {headline}"));
        }
    }

    Ok(lines.join("\n"))
}

pub(super) fn extract_weather_scopes(intent: &str) -> Vec<String> {
    StudioIntentContext::new(intent).extract_weather_scopes()
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
    let client = studio_surface_http_client()?;
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
                        format!("Studio weather surface could not read current conditions: {error}")
                    })?;
                    let cleaned = body.split_whitespace().collect::<Vec<_>>().join(" ");
                    if cleaned.is_empty() {
                        last_error = Some(
                            "Studio weather surface returned an empty conditions summary."
                                .to_string(),
                        );
                    } else if cleaned.to_ascii_lowercase().contains("unknown location") {
                        return Err(format!(
                            "Studio weather surface could not locate '{scope}'.",
                        ));
                    } else {
                        return Ok(cleaned.trim_end_matches('.').to_string() + ".");
                    }
                }
                Err(error) => {
                    last_error = Some(format!(
                        "Studio weather surface could not fetch current conditions: {error}"
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
                    format!("Studio weather surface could not read current conditions: {error}")
                })?;
                if body.to_ascii_lowercase().contains("unknown location") {
                    return Err(format!(
                        "Studio weather surface could not locate '{scope}'.",
                    ));
                }
                if let Some(summary) = parse_weather_report_fallback(scope, &body) {
                    return Ok(summary);
                }
                last_error = Some(
                    "Studio weather surface returned an unreadable fallback weather report."
                        .to_string(),
                );
            }
            Err(error) => {
                last_error = Some(format!(
                    "Studio weather surface could not fetch current conditions: {error}"
                ));
            }
        }

        if attempt < 2 {
            std::thread::sleep(Duration::from_millis(350));
        }
    }

    Err(last_error.unwrap_or_else(|| {
        "Studio weather surface could not fetch current conditions.".to_string()
    }))
}

pub(super) fn weather_scopes_for_tool_widget(
    intent: &str,
    outcome_request: &StudioOutcomeRequest,
) -> Vec<String> {
    let scopes = extract_weather_scopes(intent);
    if !scopes.is_empty() {
        return scopes;
    }

    match outcome_request.request_frame.as_ref() {
        Some(ioi_types::app::studio::StudioNormalizedRequestFrame::Weather(frame)) => {
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

fn fetch_weather_tool_widget_reply(
    intent: &str,
    outcome_request: &StudioOutcomeRequest,
) -> Result<String, String> {
    let scopes = weather_scopes_for_tool_widget(intent, outcome_request);
    if scopes.is_empty() {
        return Err(
            "Studio could not determine which location to use for the weather request.".to_string(),
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

fn build_recipe_tool_widget_prompt(intent: &str) -> String {
    format!(
        "You are Autopilot Studio's recipe reply path.\n\
Answer the user's recipe request directly.\n\
Constraints:\n\
- Give a practical recipe sized to the user's request.\n\
- Include ingredients and concise numbered steps.\n\
- Keep the answer compact and kitchen-usable.\n\
- Do not mention tools, routing, or system internals.\n\
\n\
User request:\n{intent}\n"
    )
}

fn build_visualizer_reply_prompt(intent: &str) -> String {
    format!(
        "You are Autopilot Studio's inline visualizer reply path.\n\
Return only a mermaid fenced code block that satisfies the user's request.\n\
Constraints:\n\
- Start with ```mermaid and end with ```.\n\
- Keep the diagram compact, readable, and semantically correct.\n\
- Do not add prose before or after the fenced block.\n\
\n\
User request:\n{intent}\n"
    )
}

fn complete_recipe_tool_widget_reply(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
) -> Result<String, String> {
    let runtime = app_inference_runtime(app)
        .or_else(|| app_studio_routing_inference_runtime(app))
        .ok_or_else(|| {
            "Studio recipe reply is unavailable because inference is missing.".to_string()
        })?;

    publish_current_task_progress(app, task, "Drafting the recipe...");
    let prompt = build_recipe_tool_widget_prompt(intent);
    let options = InferenceOptions {
        temperature: 0.2,
        json_mode: false,
        max_tokens: 1024,
        ..Default::default()
    };

    let bytes = tauri::async_runtime::block_on(runtime.execute_inference(
        [0u8; 32],
        prompt.as_bytes(),
        options,
    ))
    .map_err(|error| format!("Studio recipe reply inference failed: {error}"))?;
    let reply = match String::from_utf8(bytes.clone()) {
        Ok(value) => value,
        Err(_) => String::from_utf8_lossy(&bytes).to_string(),
    };
    let cleaned = reply.trim().to_string();
    if cleaned.is_empty() {
        return Err("Studio recipe reply returned empty output.".to_string());
    }
    Ok(cleaned)
}

fn complete_visualizer_reply(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
) -> Result<String, String> {
    let runtime = app_inference_runtime(app)
        .or_else(|| app_studio_routing_inference_runtime(app))
        .ok_or_else(|| {
            "Studio visualizer reply is unavailable because inference is missing.".to_string()
        })?;

    publish_current_task_progress(app, task, "Drafting the inline visualizer...");
    let prompt = build_visualizer_reply_prompt(intent);
    let options = InferenceOptions {
        temperature: 0.1,
        json_mode: false,
        max_tokens: 768,
        ..Default::default()
    };

    let bytes = tauri::async_runtime::block_on(runtime.execute_inference(
        [0u8; 32],
        prompt.as_bytes(),
        options,
    ))
    .map_err(|error| format!("Studio visualizer inference failed: {error}"))?;
    let reply = match String::from_utf8(bytes.clone()) {
        Ok(value) => value,
        Err(_) => String::from_utf8_lossy(&bytes).to_string(),
    };
    let cleaned = reply.trim().to_string();
    if cleaned.is_empty() {
        return Err("Studio visualizer reply returned empty output.".to_string());
    }
    if cleaned.starts_with("```mermaid") {
        return Ok(cleaned);
    }
    Ok(format!("```mermaid\n{}\n```", cleaned))
}

fn finalize_studio_primary_non_artifact_reply(
    app: &AppHandle,
    task: &mut AgentTask,
    outcome_request: &StudioOutcomeRequest,
    reply: String,
    route_execution_evidence: &str,
    completion_summary: &str,
) {
    let timestamp = crate::kernel::state::now();

    if let Some(studio_session) = task.studio_session.as_mut() {
        studio_session.summary = reply.clone();
        studio_session.lifecycle_state = StudioArtifactLifecycleState::Ready;
        studio_session.status = "ready".to_string();
        studio_session.updated_at = now_iso();
        studio_session.verified_reply.status = StudioArtifactVerificationStatus::Ready;
        studio_session.verified_reply.lifecycle_state = StudioArtifactLifecycleState::Ready;
        studio_session.verified_reply.summary = reply.clone();
        if !studio_session
            .verified_reply
            .evidence
            .iter()
            .any(|entry| entry == route_execution_evidence)
        {
            studio_session
                .verified_reply
                .evidence
                .push(route_execution_evidence.to_string());
        }
        studio_session.verified_reply.updated_at = studio_session.updated_at.clone();
        super::content_session::refresh_non_artifact_studio_surface(studio_session);
    }

    task.phase = AgentPhase::Complete;
    task.progress = task.total_steps.max(1);
    task.total_steps = task.total_steps.max(1);
    task.current_step = "Ready for input".to_string();
    task.history.push(ChatMessage {
        role: "agent".to_string(),
        text: reply,
        timestamp,
    });
    super::content_session::append_route_contract_event(
        task,
        outcome_request,
        "Studio reply completed",
        completion_summary,
        true,
    );
    publish_current_task_snapshot(app, task);
}

fn complete_direct_inline_conversation_reply(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
) -> Result<String, String> {
    let runtime = app_inference_runtime(app)
        .or_else(|| app_studio_routing_inference_runtime(app))
        .ok_or_else(|| {
            "Studio direct inline reply is unavailable because inference is missing.".to_string()
        })?;

    publish_current_task_progress(app, task, "Drafting the direct answer...");
    let prompt = build_direct_inline_conversation_prompt(intent);
    let options = InferenceOptions {
        temperature: 0.2,
        json_mode: false,
        max_tokens: 1024,
        ..Default::default()
    };

    let bytes = tauri::async_runtime::block_on(runtime.execute_inference(
        [0u8; 32],
        prompt.as_bytes(),
        options,
    ))
    .map_err(|error| format!("Studio direct inline reply inference failed: {error}"))?;
    let reply = match String::from_utf8(bytes.clone()) {
        Ok(value) => value,
        Err(_) => String::from_utf8_lossy(&bytes).to_string(),
    };
    let cleaned = reply.trim().to_string();
    if cleaned.is_empty() {
        return Err("Studio direct inline reply returned empty output.".to_string());
    }
    Ok(cleaned)
}

pub(super) fn maybe_execute_studio_primary_non_artifact_reply(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
    outcome_request: &StudioOutcomeRequest,
) -> Result<bool, String> {
    let (reply, route_execution_evidence, completion_summary) =
        if super::task_state::non_artifact_single_pass_reply_stays_studio_primary(outcome_request) {
            (
                complete_direct_inline_conversation_reply(app, task, intent)?,
                "route_execution:studio_direct_inline",
                "Studio completed the direct inline route and preserved the final route contract.",
            )
        } else if super::task_state::tool_widget_route_stays_studio_primary(outcome_request) {
            match tool_widget_family_hint(outcome_request) {
                Some("weather") => {
                    publish_current_task_progress(app, task, "Fetching the current weather...");
                    (
                        fetch_weather_tool_widget_reply(intent, outcome_request)?,
                        "route_execution:studio_tool_widget_weather",
                        "Studio completed the weather tool-widget route directly and preserved the final route contract.",
                    )
                }
                Some("recipe") => (
                    complete_recipe_tool_widget_reply(app, task, intent)?,
                    "route_execution:studio_tool_widget_recipe",
                    "Studio completed the recipe tool-widget route directly and preserved the final route contract.",
                ),
                Some("sports") => {
                    publish_current_task_progress(app, task, "Checking the latest team data...");
                    (
                        fetch_sports_tool_widget_reply(intent)?,
                        "route_execution:studio_tool_widget_sports",
                        "Studio completed the sports tool-widget route directly and preserved the final route contract.",
                    )
                }
                Some("places") => {
                    publish_current_task_progress(app, task, "Finding nearby places...");
                    (
                        format_places_tool_widget_reply(intent, outcome_request)?,
                        "route_execution:studio_tool_widget_places",
                        "Studio completed the places tool-widget route directly and preserved the final route contract.",
                    )
                }
                _ => return Ok(false),
            }
        } else if super::task_state::visualizer_route_stays_studio_primary(outcome_request) {
            (
                complete_visualizer_reply(app, task, intent)?,
                "route_execution:studio_visualizer_inline",
                "Studio completed the inline visualizer route directly and preserved the final route contract.",
            )
        } else {
            return Ok(false);
        };

    finalize_studio_primary_non_artifact_reply(
        app,
        task,
        outcome_request,
        reply,
        route_execution_evidence,
        completion_summary,
    );
    Ok(true)
}

fn lifecycle_state_for_generation_progress(
    progress: &StudioArtifactGenerationProgress,
) -> StudioArtifactLifecycleState {
    let stage = progress
        .execution_envelope
        .as_ref()
        .and_then(|envelope| envelope.execution_summary.as_ref())
        .and_then(|summary| summary.execution_stage);
    match stage {
        Some(ExecutionStage::Plan) | Some(ExecutionStage::Dispatch) => {
            StudioArtifactLifecycleState::Materializing
        }
        Some(ExecutionStage::Work) | Some(ExecutionStage::Mutate) | Some(ExecutionStage::Merge) => {
            StudioArtifactLifecycleState::Implementing
        }
        Some(ExecutionStage::Verify) | Some(ExecutionStage::Finalize) => {
            StudioArtifactLifecycleState::Verifying
        }
        None => StudioArtifactLifecycleState::Materializing,
    }
}

fn latest_user_request_event_id(task: &AgentTask) -> Option<String> {
    task.events.iter().rev().find_map(|event| {
        let is_user_input = event
            .details
            .get("kind")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("user_input"));
        is_user_input.then(|| event.event_id.clone())
    })
}

fn initial_understand_request_event(
    _outcome_request: &StudioOutcomeRequest,
) -> StudioArtifactRuntimeNarrationEvent {
    StudioArtifactRuntimeNarrationEvent::new(
        StudioArtifactRuntimeEventType::UnderstandRequest,
        StudioArtifactRuntimeStepId::UnderstandRequest,
        "Understand request",
        "Studio captured the request and established the active artifact context.",
        StudioArtifactRuntimeEventStatus::Complete,
    )
}

fn artifact_route_committed_event(
    outcome_request: &StudioOutcomeRequest,
) -> StudioArtifactRuntimeNarrationEvent {
    let route_detail = outcome_request
        .artifact
        .as_ref()
        .map(|artifact| {
            format!(
                "Studio committed the request to the artifact route for a {:?} renderer.",
                artifact.renderer
            )
        })
        .unwrap_or_else(|| "Studio committed the request to the artifact route.".to_string());
    StudioArtifactRuntimeNarrationEvent::new(
        StudioArtifactRuntimeEventType::ArtifactRouteCommitted,
        StudioArtifactRuntimeStepId::ArtifactRouteCommitted,
        "Route to artifact",
        route_detail,
        StudioArtifactRuntimeEventStatus::Complete,
    )
}

fn publish_current_task_generation_progress(
    app: &AppHandle,
    task_id: &str,
    progress: &StudioArtifactGenerationProgress,
) {
    let task_snapshot = {
        let state = app.state::<Mutex<AppState>>();
        let Ok(mut guard) = state.lock() else {
            return;
        };
        let Some(task) = guard.current_task.as_mut() else {
            return;
        };
        if task.id != task_id {
            return;
        }

        task.phase = AgentPhase::Running;
        task.current_step = progress.current_step.clone();
        if let Some(session) = task.studio_session.as_mut() {
            let session_origin_prompt_event_id = session.origin_prompt_event_id.clone();
            assign_studio_session_turn_ownership(
                session,
                session_origin_prompt_event_id.as_deref(),
            );
            if progress.artifact_brief.is_some()
                || progress.preparation_needs.is_some()
                || progress.prepared_context_resolution.is_some()
                || progress.skill_discovery_resolution.is_some()
                || progress.blueprint.is_some()
                || progress.artifact_ir.is_some()
                || !progress.selected_skills.is_empty()
                || !progress.retrieved_exemplars.is_empty()
            {
                session.materialization.artifact_brief = progress.artifact_brief.clone();
                session.materialization.preparation_needs = progress.preparation_needs.clone();
                session.materialization.prepared_context_resolution =
                    progress.prepared_context_resolution.clone();
                session.materialization.skill_discovery_resolution =
                    progress.skill_discovery_resolution.clone();
                session.materialization.blueprint = progress.blueprint.clone();
                session.materialization.artifact_ir = progress.artifact_ir.clone();
                session.materialization.selected_skills = progress.selected_skills.clone();
                session.materialization.retrieved_exemplars = progress.retrieved_exemplars.clone();
            }
            session.materialization.execution_envelope = progress.execution_envelope.clone();
            session.materialization.swarm_plan = progress.swarm_plan.clone();
            session.materialization.swarm_execution = progress.swarm_execution.clone();
            session.materialization.swarm_worker_receipts = progress.swarm_worker_receipts.clone();
            session.materialization.swarm_change_receipts = progress.swarm_change_receipts.clone();
            session.materialization.swarm_merge_receipts = progress.swarm_merge_receipts.clone();
            session.materialization.swarm_verification_receipts =
                progress.swarm_verification_receipts.clone();
            if progress.render_evaluation.is_some() {
                session.materialization.render_evaluation = progress.render_evaluation.clone();
            }
            if progress.validation.is_some() {
                session.materialization.validation = progress.validation.clone();
            }
            let mut progress_runtime_narration_events = progress.runtime_narration_events.clone();
            assign_runtime_narration_events_origin(
                &mut progress_runtime_narration_events,
                session_origin_prompt_event_id.as_deref(),
            );
            merge_runtime_narration_events(
                &mut session.materialization.runtime_narration_events,
                &progress_runtime_narration_events,
            );
            session.lifecycle_state = lifecycle_state_for_generation_progress(progress);
            session.status = lifecycle_state_label(session.lifecycle_state).to_string();
            session.updated_at = now_iso();
            session.artifact_manifest.verification.summary = progress.current_step.clone();
            session.verified_reply.summary = progress.current_step.clone();
            refresh_pipeline_steps(session, None);
        }

        task.clone()
    };

    publish_current_task_snapshot(app, &task_snapshot);
}

pub(super) fn provisional_non_workspace_studio_session(
    thread_id: &str,
    studio_session_id: &str,
    title: &str,
    summary: &str,
    created_at: &str,
    outcome_request: &StudioOutcomeRequest,
    origin_prompt_event_id: Option<&str>,
    mut materialization: StudioArtifactMaterializationContract,
) -> Result<StudioArtifactSession, String> {
    let artifact_request = outcome_request
        .artifact
        .as_ref()
        .ok_or_else(|| "Studio artifact outcome missing artifact request".to_string())?;
    let lifecycle_state = StudioArtifactLifecycleState::Materializing;
    let mut artifact_manifest =
        artifact_manifest_for_request(title, artifact_request, &[], None, None, lifecycle_state);
    artifact_manifest.verification.summary = materialization
        .blueprint
        .as_ref()
        .map(|blueprint| format!("Preparing the {} artifact plan.", blueprint.scaffold_family))
        .unwrap_or_else(|| "Preparing the artifact plan.".to_string());
    artifact_manifest.verification.production_provenance =
        materialization.production_provenance.clone();
    artifact_manifest.verification.acceptance_provenance =
        materialization.acceptance_provenance.clone();
    let retrieved_exemplars = materialization.retrieved_exemplars.clone();
    merge_runtime_narration_events(
        &mut materialization.runtime_narration_events,
        &[
            initial_understand_request_event(outcome_request),
            artifact_route_committed_event(outcome_request),
        ],
    );
    assign_runtime_narration_events_origin(
        &mut materialization.runtime_narration_events,
        origin_prompt_event_id,
    );

    let mut studio_session = StudioArtifactSession {
        session_id: studio_session_id.to_string(),
        thread_id: thread_id.to_string(),
        artifact_id: artifact_manifest.artifact_id.clone(),
        origin_prompt_event_id: origin_prompt_event_id.map(ToOwned::to_owned),
        title: title.to_string(),
        summary: summary.to_string(),
        current_lens: artifact_manifest.primary_tab.clone(),
        navigator_backing_mode: "logical".to_string(),
        navigator_nodes: navigator_nodes_for_manifest(&artifact_manifest),
        attached_artifact_ids: Vec::new(),
        available_lenses: artifact_manifest
            .tabs
            .iter()
            .map(|tab| tab.id.clone())
            .collect(),
        materialization,
        outcome_request: outcome_request.clone(),
        artifact_manifest: artifact_manifest.clone(),
        verified_reply: verified_reply_from_manifest(title, &artifact_manifest),
        lifecycle_state,
        status: lifecycle_state_label(lifecycle_state).to_string(),
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory: None,
        retrieved_exemplars,
        selected_targets: Vec::new(),
        widget_state: None,
        ux_lifecycle: None,
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        build_session_id: None,
        workspace_root: None,
        renderer_session_id: None,
    };
    assign_studio_session_turn_ownership(&mut studio_session, origin_prompt_event_id);
    refresh_pipeline_steps(&mut studio_session, None);
    Ok(studio_session)
}

pub(super) fn seed_provisional_artifact_route_state(
    task: &mut AgentTask,
    outcome_request: &StudioOutcomeRequest,
    summary: &str,
    studio_session: StudioArtifactSession,
    build_session: Option<BuildArtifactSession>,
    renderer_session: Option<StudioRendererSession>,
) {
    task.studio_outcome = Some(outcome_request.clone());
    task.studio_session = Some(studio_session);
    task.build_session = build_session;
    task.renderer_session = renderer_session;
    super::content_session::append_route_contract_event(
        task,
        outcome_request,
        "Studio route decision",
        summary,
        false,
    );
}

pub fn maybe_prepare_task_for_studio(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
) -> Result<(), String> {
    publish_current_task_progress(app, task, "Routing the request...");
    let active_artifact_id = task
        .studio_session
        .as_ref()
        .map(|session| session.artifact_id.clone());
    let active_refinement = task.studio_session.as_ref().and_then(|session| {
        app.state::<Mutex<AppState>>()
            .lock()
            .ok()
            .and_then(|state| {
                state
                    .memory_runtime
                    .as_ref()
                    .map(|runtime| studio_refinement_context_for_session(runtime, session))
            })
    });
    let active_widget_state = task
        .studio_session
        .as_ref()
        .and_then(|session| session.widget_state.as_ref());
    if let Some(runtime) = app_studio_routing_inference_runtime(app) {
        if runtime.studio_runtime_provenance().kind
            == crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable
        {
            let failure = StudioArtifactFailure {
                kind: StudioArtifactFailureKind::InferenceUnavailable,
                code: "inference_unavailable".to_string(),
                message:
                    "Studio cannot route or materialize artifacts because inference is unavailable."
                        .to_string(),
            };
            attach_blocked_studio_failure_session(
                task,
                intent,
                active_artifact_id,
                runtime.studio_runtime_provenance(),
                failure,
            );
            return Ok(());
        }
    } else {
        attach_blocked_studio_failure_session(
            task,
            intent,
            active_artifact_id,
            crate::models::StudioRuntimeProvenance {
                kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            },
            StudioArtifactFailure {
                kind: StudioArtifactFailureKind::InferenceUnavailable,
                code: "inference_unavailable".to_string(),
                message: "Studio cannot route or materialize artifacts because inference runtime is unavailable."
                    .to_string(),
            },
        );
        return Ok(());
    }
    let outcome_request = match studio_outcome_request(
        app,
        intent,
        active_artifact_id.clone(),
        active_refinement.as_ref(),
        active_widget_state,
    ) {
        Ok(outcome_request) => outcome_request,
        Err(error) => {
            let provenance = app_studio_routing_inference_runtime(app)
                .map(|runtime| runtime.studio_runtime_provenance())
                .unwrap_or(crate::models::StudioRuntimeProvenance {
                    kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
                    label: "inference unavailable".to_string(),
                    model: None,
                    endpoint: None,
                });
            attach_blocked_studio_failure_session(
                task,
                intent,
                active_artifact_id,
                provenance,
                StudioArtifactFailure {
                    kind: StudioArtifactFailureKind::RoutingFailure,
                    code: "routing_failure".to_string(),
                    message: error,
                },
            );
            return Ok(());
        }
    };
    task.studio_outcome = Some(outcome_request.clone());

    if outcome_request.needs_clarification {
        let provenance = app_studio_routing_inference_runtime(app)
            .map(|runtime| runtime.studio_runtime_provenance())
            .unwrap_or(crate::models::StudioRuntimeProvenance {
                kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            });
        attach_non_artifact_studio_session(task, intent, provenance, &outcome_request);
        apply_non_artifact_route_state(task, &outcome_request);
        publish_current_task_snapshot(app, task);
        return Ok(());
    }

    if outcome_request.outcome_kind != StudioOutcomeKind::Artifact {
        let provenance = app_studio_routing_inference_runtime(app)
            .map(|runtime| runtime.studio_runtime_provenance())
            .unwrap_or(crate::models::StudioRuntimeProvenance {
                kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            });
        attach_non_artifact_studio_session(task, intent, provenance, &outcome_request);
        apply_non_artifact_route_state(task, &outcome_request);
        if maybe_execute_studio_primary_non_artifact_reply(app, task, intent, &outcome_request)? {
            return Ok(());
        }
        if task_requires_studio_primary_execution(task) {
            apply_studio_authoritative_status(task, None);
        }
        publish_current_task_snapshot(app, task);
        return Ok(());
    }

    maybe_prepare_task_for_studio_with_request(app, task, intent, outcome_request)
}

fn maybe_prepare_task_for_studio_with_request(
    app: &AppHandle,
    task: &mut AgentTask,
    intent: &str,
    outcome_request: StudioOutcomeRequest,
) -> Result<(), String> {
    let origin_prompt_event_id = latest_user_request_event_id(task);
    let artifact_request = outcome_request
        .artifact
        .clone()
        .ok_or_else(|| "Studio artifact outcome missing artifact request".to_string())?;
    let renderer_kind = artifact_request.renderer;
    let thread_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
    let title = derive_artifact_title(intent);
    let summary = summary_for_request(&artifact_request, &title);
    let studio_session_id = Uuid::new_v4().to_string();
    let created_at = now_iso();
    let mut attached_artifact_ids = Vec::new();
    let mut manifest_files: Vec<StudioArtifactManifestFile> = Vec::new();
    let mut materialization = materialization_contract_for_request(
        intent,
        &artifact_request,
        &summary,
        outcome_request.execution_mode_decision.clone(),
        outcome_request.execution_strategy,
    );
    let workspace_root = if renderer_kind == StudioRendererKind::WorkspaceSurface {
        Some(workspace_root_for(app, &studio_session_id))
    } else {
        None
    };
    let mut initial_lifecycle_state = if renderer_kind == StudioRendererKind::WorkspaceSurface {
        StudioArtifactLifecycleState::Materializing
    } else {
        StudioArtifactLifecycleState::Ready
    };
    let mut non_workspace_verification_summary: Option<String> = None;
    let mut artifact_brief: Option<StudioArtifactBrief> = None;
    let mut edit_intent: Option<StudioArtifactEditIntent> = None;
    let mut candidate_summaries = Vec::<StudioArtifactCandidateSummary>::new();
    let mut winning_candidate_id: Option<String> = None;
    let mut winning_candidate_rationale: Option<String> = None;
    let mut execution_envelope: Option<ExecutionEnvelope> = None;
    let mut swarm_plan: Option<StudioArtifactSwarmPlan> = None;
    let mut swarm_execution: Option<StudioArtifactSwarmExecutionSummary> = None;
    let mut swarm_worker_receipts = Vec::<StudioArtifactWorkerReceipt>::new();
    let mut swarm_change_receipts = Vec::<StudioArtifactPatchReceipt>::new();
    let mut swarm_merge_receipts = Vec::<StudioArtifactMergeReceipt>::new();
    let mut swarm_verification_receipts = Vec::<StudioArtifactVerificationReceipt>::new();
    let mut render_evaluation: Option<ioi_api::studio::StudioArtifactRenderEvaluation> = None;
    let mut validation: Option<StudioArtifactValidationResult> = None;
    let mut output_origin: Option<StudioArtifactOutputOrigin> = None;
    let mut production_provenance: Option<crate::models::StudioRuntimeProvenance> = None;
    let mut acceptance_provenance: Option<crate::models::StudioRuntimeProvenance> = None;
    let mut fallback_used = false;
    let mut ux_lifecycle: Option<StudioArtifactUxLifecycle> = None;
    let mut failure: Option<crate::models::StudioArtifactFailure> = None;
    let mut taste_memory: Option<StudioArtifactTasteMemory> = None;
    let mut retrieved_exemplars = Vec::<StudioArtifactExemplar>::new();
    let mut selected_targets = Vec::<StudioArtifactSelectionTarget>::new();
    let mut final_materialized_artifact: Option<
        super::content_session::MaterializedContentArtifact,
    > = None;
    let app_runtime_provenance =
        app_inference_runtime(app).map(|runtime| runtime.studio_runtime_provenance());
    let app_acceptance_runtime_provenance =
        app_acceptance_inference_runtime(app).map(|runtime| runtime.studio_runtime_provenance());

    if renderer_kind == StudioRendererKind::WorkspaceSurface {
        production_provenance = Some(app_runtime_provenance.clone().unwrap_or(
            crate::models::StudioRuntimeProvenance {
                kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            },
        ));
        acceptance_provenance = Some(app_acceptance_runtime_provenance.clone().unwrap_or(
            crate::models::StudioRuntimeProvenance {
                kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            },
        ));
        output_origin = production_provenance
            .as_ref()
            .map(output_origin_from_runtime_provenance);
    }

    let mut build_session = if let Some(root) = workspace_root.as_ref() {
        let recipe = select_workspace_recipe(&artifact_request);
        let package_name = package_name_for_title(&title);
        let scaffold = scaffold_workspace(
            recipe,
            artifact_request
                .presentation_variant_id
                .as_deref()
                .and_then(parse_static_html_archetype_id),
            root,
            &title,
            &package_name,
        )?;
        materialization.file_writes = scaffold.file_writes.clone();
        materialization.command_intents = build_command_intents();
        materialization.preview_intent = Some(StudioArtifactMaterializationPreviewIntent {
            label: "Preview lane".to_string(),
            url: None,
            status: "pending".to_string(),
        });
        materialization.verification_steps = vec![
            verification_step("scaffold", "Scaffold workspace", "success"),
            verification_step("install", "Install dependencies", "pending"),
            verification_step("validation", "Validate build", "pending"),
            verification_step("preview", "Verify preview", "pending"),
        ];
        Some(BuildArtifactSession {
            session_id: Uuid::new_v4().to_string(),
            studio_session_id: studio_session_id.clone(),
            workspace_root: root.to_string_lossy().to_string(),
            entry_document: recipe.entry_document().to_string(),
            preview_url: None,
            preview_process_id: None,
            scaffold_recipe_id: recipe.id().to_string(),
            presentation_variant_id: artifact_request.presentation_variant_id.clone(),
            package_manager: "npm".to_string(),
            build_status: "scaffolded".to_string(),
            verification_status: "pending".to_string(),
            receipts: vec![StudioBuildReceipt {
                receipt_id: Uuid::new_v4().to_string(),
                kind: "scaffold".to_string(),
                title: format!("Scaffolded {} workspace", recipe.label()),
                status: "success".to_string(),
                summary: format!(
                    "Materialized {} starter files in {} using the {} recipe.",
                    scaffold.file_writes.len(),
                    root.display(),
                    recipe.label()
                ),
                started_at: created_at.clone(),
                finished_at: Some(now_iso()),
                artifact_ids: Vec::new(),
                command: None,
                exit_code: Some(0),
                duration_ms: Some(0),
                failure_class: None,
                replay_classification: Some("replay_safe".to_string()),
            }],
            current_worker_execution: StudioCodeWorkerLease {
                backend: "hosted-fallback".to_string(),
                planner_authority: "kernel".to_string(),
                allowed_mutation_scope: mutation_scope_for_recipe(root, recipe),
                allowed_command_classes: vec![
                    "install".to_string(),
                    "build".to_string(),
                    "preview".to_string(),
                    "repair".to_string(),
                ],
                execution_state: "preparing".to_string(),
                retry_classification: Some("retry_required".to_string()),
                last_summary: Some(format!(
                    "Kernel owns routing. Studio materialized a {} workspace so the artifact can open real code and preview lenses under bounded supervision.",
                    recipe.label()
                )),
            },
            current_lens: "code".to_string(),
            available_lenses: BUILD_LENSES_IN_PROGRESS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            ready_lenses: vec!["code".to_string()],
            retry_count: 0,
            last_failure_summary: None,
        })
    } else {
        None
    };

    let renderer_session = build_session
        .as_ref()
        .map(build_session_to_renderer_session);

    if build_session.is_some() {
        publish_current_task_progress(app, task, "Selecting workspace scaffold...");
        let mut provisional_session = provisional_non_workspace_studio_session(
            &thread_id,
            &studio_session_id,
            &title,
            &summary,
            &created_at,
            &outcome_request,
            origin_prompt_event_id.as_deref(),
            materialization.clone(),
        )?;
        provisional_session.navigator_backing_mode = "workspace".to_string();
        provisional_session.workspace_root = workspace_root
            .as_ref()
            .map(|root| root.to_string_lossy().to_string());
        provisional_session.build_session_id = build_session
            .as_ref()
            .map(|session| session.session_id.clone());
        seed_provisional_artifact_route_state(
            task,
            &outcome_request,
            &summary,
            provisional_session,
            build_session.clone(),
            renderer_session.clone(),
        );
        publish_current_task_snapshot(app, task);
    } else {
        publish_current_task_progress(
            app,
            task,
            if outcome_request.execution_strategy == StudioExecutionStrategy::DirectAuthor {
                "Understanding the artifact request..."
            } else {
                "Planning artifact blueprint..."
            },
        );
        materialization.production_provenance = app_runtime_provenance.clone();
        materialization.acceptance_provenance = app_acceptance_runtime_provenance
            .clone()
            .or_else(|| app_runtime_provenance.clone());
        task.studio_session = Some(provisional_non_workspace_studio_session(
            &thread_id,
            &studio_session_id,
            &title,
            &summary,
            &created_at,
            &outcome_request,
            origin_prompt_event_id.as_deref(),
            materialization.clone(),
        )?);
        super::content_session::append_route_contract_event(
            task,
            &outcome_request,
            "Studio route decision",
            &summary,
            false,
        );
        publish_current_task_snapshot(app, task);
        let progress_app = app.clone();
        let progress_task_id = task.id.clone();
        let progress_observer =
            std::sync::Arc::new(move |progress: StudioArtifactGenerationProgress| {
                publish_current_task_generation_progress(
                    &progress_app,
                    &progress_task_id,
                    &progress,
                );
            });
        let materialized_artifact =
            materialize_non_workspace_artifact_with_execution_strategy_and_progress_observer(
                app,
                &thread_id,
                &title,
                intent,
                &artifact_request,
                None,
                outcome_request.execution_strategy,
                Some(progress_observer),
            )?;
        publish_current_task_progress(
            app,
            task,
            if outcome_request.execution_strategy == StudioExecutionStrategy::DirectAuthor {
                "Evaluating rendered artifact...".to_string()
            } else if let Some(blueprint) = materialized_artifact.blueprint.as_ref() {
                format!(
                    "Running static audits and render sanity for the {} scaffold...",
                    blueprint.scaffold_family
                )
            } else {
                "Running static audits and render sanity...".to_string()
            },
        );
        initial_lifecycle_state = materialized_artifact.lifecycle_state;
        non_workspace_verification_summary =
            Some(materialized_artifact.verification_summary.clone());
        artifact_brief = Some(materialized_artifact.brief.clone());
        edit_intent = materialized_artifact.edit_intent.clone();
        candidate_summaries = materialized_artifact.candidate_summaries.clone();
        winning_candidate_id = materialized_artifact.winning_candidate_id.clone();
        winning_candidate_rationale = materialized_artifact.winning_candidate_rationale.clone();
        execution_envelope = materialized_artifact.execution_envelope.clone();
        swarm_plan = materialized_artifact.swarm_plan.clone();
        swarm_execution = materialized_artifact.swarm_execution.clone();
        swarm_worker_receipts = materialized_artifact.swarm_worker_receipts.clone();
        swarm_change_receipts = materialized_artifact.swarm_change_receipts.clone();
        swarm_merge_receipts = materialized_artifact.swarm_merge_receipts.clone();
        swarm_verification_receipts = materialized_artifact.swarm_verification_receipts.clone();
        render_evaluation = materialized_artifact.render_evaluation.clone();
        validation = materialized_artifact.validation.clone();
        output_origin = Some(materialized_artifact.output_origin);
        production_provenance = materialized_artifact.production_provenance.clone();
        acceptance_provenance = materialized_artifact.acceptance_provenance.clone();
        fallback_used = materialized_artifact.fallback_used;
        ux_lifecycle = Some(materialized_artifact.ux_lifecycle);
        failure = materialized_artifact.failure.clone();
        taste_memory = materialized_artifact.taste_memory.clone();
        retrieved_exemplars = materialized_artifact.retrieved_exemplars.clone();
        selected_targets = materialized_artifact.selected_targets.clone();
        attached_artifact_ids.extend(
            materialized_artifact
                .artifacts
                .iter()
                .map(|artifact| artifact.artifact_id.clone()),
        );
        task.artifacts
            .extend(materialized_artifact.artifacts.clone());
        manifest_files = materialized_artifact.files.clone();
        materialization
            .file_writes
            .extend(materialized_artifact.file_writes.clone());
        materialization
            .notes
            .extend(materialized_artifact.notes.clone());
        final_materialized_artifact = Some(materialized_artifact);
    }

    publish_current_task_progress(app, task, "Finalizing artifact session...");
    let mut artifact_manifest = artifact_manifest_for_request(
        &title,
        &artifact_request,
        &attached_artifact_ids,
        build_session.as_ref(),
        renderer_session.as_ref(),
        initial_lifecycle_state,
    );

    if let Some(build) = build_session.as_mut() {
        if let Some(receipt_artifact) =
            create_receipt_report_artifact(app, &thread_id, &title, &build.receipts[0])
        {
            build.receipts[0]
                .artifact_ids
                .push(receipt_artifact.artifact_id.clone());
            attached_artifact_ids.push(receipt_artifact.artifact_id.clone());
            task.artifacts.push(receipt_artifact);
        }
    }

    if let Some(materialized_artifact) = final_materialized_artifact.as_ref() {
        super::content_session::apply_materialized_artifact_to_contract(
            &mut materialization,
            &artifact_request,
            materialized_artifact,
            outcome_request.execution_mode_decision.clone(),
            outcome_request.execution_strategy,
        );
        assign_runtime_narration_events_origin(
            &mut materialization.runtime_narration_events,
            origin_prompt_event_id.as_deref(),
        );
    } else {
        materialization.artifact_brief = artifact_brief.clone();
        materialization.edit_intent = edit_intent.clone();
        materialization.candidate_summaries = candidate_summaries.clone();
        materialization.winning_candidate_id = winning_candidate_id.clone();
        materialization.winning_candidate_rationale = winning_candidate_rationale.clone();
        materialization.swarm_plan = swarm_plan.clone();
        materialization.swarm_execution = swarm_execution.clone();
        materialization.swarm_worker_receipts = swarm_worker_receipts.clone();
        materialization.swarm_change_receipts = swarm_change_receipts.clone();
        materialization.swarm_merge_receipts = swarm_merge_receipts.clone();
        materialization.swarm_verification_receipts = swarm_verification_receipts.clone();
        materialization.execution_envelope = execution_envelope.clone().or_else(|| {
            super::content_session::artifact_execution_envelope_for_contract(
                outcome_request.execution_mode_decision.clone(),
                outcome_request.execution_strategy,
                &materialization,
            )
        });
        materialization.render_evaluation = render_evaluation;
        materialization.validation = validation.clone();
        materialization.output_origin = output_origin;
        materialization.production_provenance = production_provenance.clone();
        materialization.acceptance_provenance = acceptance_provenance.clone();
        materialization.fallback_used = fallback_used;
        materialization.ux_lifecycle = ux_lifecycle;
        materialization.failure = failure.clone();
        materialization.retrieved_exemplars = retrieved_exemplars.clone();
        assign_runtime_narration_events_origin(
            &mut materialization.runtime_narration_events,
            origin_prompt_event_id.as_deref(),
        );
    }

    if let Some(artifact) = create_contract_artifact(app, &thread_id, &title, &materialization) {
        attached_artifact_ids.push(artifact.artifact_id.clone());
        task.artifacts.push(artifact);
    }

    artifact_manifest.artifact_id = attached_artifact_ids
        .first()
        .cloned()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    artifact_manifest.files = if manifest_files.is_empty() {
        manifest_files_for_request(&artifact_request, build_session.as_ref())
    } else {
        manifest_files
    };
    if let Some(summary) = non_workspace_verification_summary {
        artifact_manifest.verification = StudioArtifactManifestVerification {
            status: verification_status_for_lifecycle(initial_lifecycle_state),
            lifecycle_state: initial_lifecycle_state,
            summary,
            production_provenance: production_provenance.clone(),
            acceptance_provenance: acceptance_provenance.clone(),
            failure: failure.clone(),
        };
    }
    materialization.navigator_nodes = navigator_nodes_for_manifest(&artifact_manifest);
    let verified_reply = verified_reply_from_manifest(&title, &artifact_manifest);

    let mut studio_session = StudioArtifactSession {
        session_id: studio_session_id.clone(),
        thread_id: thread_id.clone(),
        artifact_id: attached_artifact_ids
            .first()
            .cloned()
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        origin_prompt_event_id: origin_prompt_event_id.clone(),
        title,
        summary,
        current_lens: artifact_manifest.primary_tab.clone(),
        navigator_backing_mode: if renderer_kind == StudioRendererKind::WorkspaceSurface {
            "workspace".to_string()
        } else {
            "logical".to_string()
        },
        navigator_nodes: navigator_nodes_for_manifest(&artifact_manifest),
        attached_artifact_ids,
        available_lenses: artifact_manifest
            .tabs
            .iter()
            .map(|tab| tab.id.clone())
            .collect(),
        materialization,
        outcome_request: outcome_request.clone(),
        artifact_manifest,
        verified_reply,
        lifecycle_state: initial_lifecycle_state,
        status: lifecycle_state_label(initial_lifecycle_state).to_string(),
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory,
        retrieved_exemplars,
        selected_targets,
        widget_state: None,
        ux_lifecycle,
        created_at: created_at.clone(),
        updated_at: created_at,
        build_session_id: build_session
            .as_ref()
            .map(|session| session.session_id.clone()),
        workspace_root: workspace_root
            .as_ref()
            .map(|root| root.to_string_lossy().to_string()),
        renderer_session_id: renderer_session
            .as_ref()
            .map(|session| session.session_id.clone()),
    };
    assign_studio_session_turn_ownership(&mut studio_session, origin_prompt_event_id.as_deref());
    refresh_pipeline_steps(&mut studio_session, build_session.as_ref());
    let initial_revision = initial_revision_for_session(&studio_session, intent);
    studio_session.active_revision_id = Some(initial_revision.revision_id.clone());
    studio_session.revisions = vec![initial_revision];
    if let Some(initial_revision) = studio_session.revisions.first().cloned() {
        if let Some(memory_runtime) = app
            .state::<Mutex<AppState>>()
            .lock()
            .ok()
            .and_then(|state| state.memory_runtime.clone())
        {
            match persist_studio_artifact_exemplar(
                &memory_runtime,
                app_inference_runtime(app),
                &studio_session,
                &initial_revision,
            ) {
                Ok(Some(exemplar)) => studio_session.materialization.notes.push(format!(
                    "Archived exemplar {} for {} / {}.",
                    exemplar.record_id,
                    renderer_kind_id(exemplar.renderer),
                    exemplar.scaffold_family
                )),
                Ok(None) => {}
                Err(error) => studio_session
                    .materialization
                    .notes
                    .push(format!("Exemplar archival skipped: {error}")),
            }
        }
    }
    sync_workspace_manifest_file(&studio_session);

    let artifact_refs = task
        .artifacts
        .iter()
        .map(|artifact| ArtifactRef {
            artifact_id: artifact.artifact_id.clone(),
            artifact_type: artifact.artifact_type.clone(),
        })
        .collect::<Vec<_>>();

    task.events.push(build_event(
        &thread_id,
        task.progress,
        EventType::Receipt,
        format!("Studio created {}", studio_session.title),
        json!({
            "artifact_class": artifact_class_id_for_request(&artifact_request),
            "navigator_backing_mode": studio_session.navigator_backing_mode,
            "build_session_id": studio_session.build_session_id,
            "selected_route": super::content_session::build_route_contract_payload(
                &outcome_request,
                false,
            )
            .get("selected_route")
            .cloned()
            .unwrap_or_else(|| json!("artifact")),
            "route_family": super::content_session::build_route_contract_payload(
                &outcome_request,
                false,
            )
            .get("route_family")
            .cloned()
            .unwrap_or_else(|| json!("artifacts")),
            "topology": super::content_session::build_route_contract_payload(
                &outcome_request,
                false,
            )
            .get("topology")
            .cloned()
            .unwrap_or_else(|| json!("planner_specialist")),
            "planner_authority": "kernel",
            "verifier_state": super::content_session::build_route_contract_payload(
                &outcome_request,
                false,
            )
            .get("verifier_state")
            .cloned()
            .unwrap_or_else(|| json!("active")),
            "route_decision": super::content_session::build_route_contract_payload(
                &outcome_request,
                false,
            )
            .get("route_decision")
            .cloned()
            .unwrap_or_else(|| json!({})),
        }),
        {
            let mut details = serde_json::to_value(&studio_session).unwrap_or_else(|_| json!({}));
            if let Some(details_object) = details.as_object_mut() {
                let payload =
                    super::content_session::build_route_contract_payload(&outcome_request, false);
                details_object.insert(
                    "selected_route".to_string(),
                    payload["selected_route"].clone(),
                );
                details_object.insert("route_family".to_string(), payload["route_family"].clone());
                details_object.insert("topology".to_string(), payload["topology"].clone());
                details_object.insert(
                    "planner_authority".to_string(),
                    payload["planner_authority"].clone(),
                );
                details_object.insert(
                    "verifier_state".to_string(),
                    payload["verifier_state"].clone(),
                );
                details_object.insert(
                    "verifier_outcome".to_string(),
                    payload["verifier_outcome"].clone(),
                );
                details_object.insert(
                    "route_decision".to_string(),
                    payload["route_decision"].clone(),
                );
            }
            details
        },
        EventStatus::Success,
        artifact_refs,
        None,
        Vec::new(),
        Some(0),
    ));

    task.studio_session = Some(studio_session.clone());
    task.renderer_session = renderer_session.clone();
    task.build_session = build_session.clone();

    if let Some(build_session) = build_session {
        spawn_build_supervisor(app.clone(), studio_session, build_session);
    }

    Ok(())
}

pub fn maybe_prepare_current_task_for_studio_turn(
    app: &AppHandle,
    intent: &str,
) -> Result<(), String> {
    println!(
        "[Autopilot][StudioContinue] maybe_prepare_current_task_for_studio_turn intent={}",
        intent
    );
    let state = app.state::<Mutex<AppState>>();
    let (mut task, memory_runtime) = {
        let guard = state
            .lock()
            .map_err(|_| "Failed to lock app state".to_string())?;
        let Some(task) = guard.current_task.clone() else {
            return Ok(());
        };
        (task, guard.memory_runtime.clone())
    };
    let origin_prompt_event_id = latest_user_request_event_id(&task);
    let current_artifact_id = task
        .studio_session
        .as_ref()
        .map(|session| session.artifact_id.clone());
    let active_refinement = task.studio_session.as_ref().and_then(|session| {
        memory_runtime
            .as_ref()
            .map(|runtime| studio_refinement_context_for_session(runtime, session))
    });
    let active_widget_state = task
        .studio_session
        .as_ref()
        .and_then(|session| session.widget_state.as_ref());
    let outcome_request = studio_outcome_request(
        app,
        intent,
        current_artifact_id,
        active_refinement.as_ref(),
        active_widget_state,
    )?;
    println!(
        "[Autopilot][StudioContinue] routed follow-up outcome_kind={:?} hints={:?}",
        outcome_request.outcome_kind, outcome_request.routing_hints
    );

    task.studio_outcome = Some(outcome_request.clone());

    let previous_build_session_id = task
        .build_session
        .as_ref()
        .map(|session| session.session_id.clone());
    let previous_studio_session_id = task
        .studio_session
        .as_ref()
        .map(|session| session.session_id.clone());
    let previous_artifact_count = task.artifacts.len();
    let previous_phase = task.phase.clone();
    let previous_current_step = task.current_step.clone();
    let previous_outcome_request_id = task
        .studio_outcome
        .as_ref()
        .map(|request| request.request_id.clone());
    let previous_studio_lifecycle = task
        .studio_session
        .as_ref()
        .map(|session| session.lifecycle_state);
    let previous_revision_count = task
        .studio_session
        .as_ref()
        .map(|session| session.revisions.len());
    let previous_file_count = task
        .studio_session
        .as_ref()
        .map(|session| session.artifact_manifest.files.len());

    if outcome_request.outcome_kind == StudioOutcomeKind::Artifact
        && !outcome_request.needs_clarification
    {
        if !maybe_refine_current_non_workspace_artifact_turn(
            app,
            &mut task,
            intent,
            outcome_request.clone(),
        )? {
            maybe_prepare_task_for_studio_with_request(app, &mut task, intent, outcome_request)?;
        }
    } else {
        if outcome_request.outcome_kind != StudioOutcomeKind::Artifact {
            let provenance = app_studio_routing_inference_runtime(app)
                .map(|runtime| runtime.studio_runtime_provenance())
                .unwrap_or(crate::models::StudioRuntimeProvenance {
                    kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
                    label: "inference unavailable".to_string(),
                    model: None,
                    endpoint: None,
                });
            attach_non_artifact_studio_session(&mut task, intent, provenance, &outcome_request);
        }
        apply_non_artifact_route_state(&mut task, &outcome_request);
        maybe_execute_studio_primary_non_artifact_reply(app, &mut task, intent, &outcome_request)?;
    }

    if let Some(session) = task.studio_session.as_mut() {
        assign_studio_session_turn_ownership(session, origin_prompt_event_id.as_deref());
    }

    if task_requires_studio_primary_execution(&task) {
        apply_studio_authoritative_status(&mut task, None);
    }

    let studio_changed = previous_studio_session_id
        != task
            .studio_session
            .as_ref()
            .map(|session| session.session_id.clone());
    let build_changed = previous_build_session_id
        != task
            .build_session
            .as_ref()
            .map(|session| session.session_id.clone());
    let artifacts_changed = previous_artifact_count != task.artifacts.len();
    let phase_changed = previous_phase != task.phase;
    let current_step_changed = previous_current_step != task.current_step;
    let outcome_changed = previous_outcome_request_id
        != task
            .studio_outcome
            .as_ref()
            .map(|request| request.request_id.clone());
    let lifecycle_changed = previous_studio_lifecycle
        != task
            .studio_session
            .as_ref()
            .map(|session| session.lifecycle_state);
    let revision_count_changed = previous_revision_count
        != task
            .studio_session
            .as_ref()
            .map(|session| session.revisions.len());
    let file_count_changed = previous_file_count
        != task
            .studio_session
            .as_ref()
            .map(|session| session.artifact_manifest.files.len());

    if !studio_changed
        && !build_changed
        && !artifacts_changed
        && !phase_changed
        && !current_step_changed
        && !outcome_changed
        && !lifecycle_changed
        && !revision_count_changed
        && !file_count_changed
    {
        println!("[Autopilot][StudioContinue] follow-up produced no material task change");
        return Ok(());
    }

    if let Some(previous_build_session_id) = previous_build_session_id {
        if task
            .build_session
            .as_ref()
            .is_none_or(|session| session.session_id != previous_build_session_id)
        {
            kill_preview_process(&previous_build_session_id);
        }
    }

    {
        let mut guard = state
            .lock()
            .map_err(|_| "Failed to lock app state".to_string())?;
        if let Some(current_task) = guard.current_task.as_mut() {
            *current_task = task.clone();
        }
    }

    if let Some(memory_runtime) = memory_runtime.as_ref() {
        orchestrator::save_local_task_state(memory_runtime, &task);
    }

    let _ = app.emit("task-updated", &task);
    println!(
        "[Autopilot][StudioContinue] follow-up task updated phase={:?} current_step={}",
        task.phase, task.current_step
    );
    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        crate::kernel::session::emit_session_projection_update(&app_clone, false).await;
    });
    Ok(())
}

pub(super) fn apply_non_artifact_route_state(
    task: &mut AgentTask,
    outcome_request: &StudioOutcomeRequest,
) {
    task.current_step = if outcome_request.outcome_kind == StudioOutcomeKind::Artifact {
        task.current_step.clone()
    } else {
        super::content_session::non_artifact_route_status_message(outcome_request)
    };
}

#[cfg(test)]
mod tests {
    use super::places_request_for_tool_widget;
    use crate::models::StudioOutcomeRequest;
    use ioi_types::app::studio::{
        StudioNormalizedRequestFrame, StudioOutcomeKind, StudioPlacesRequestFrame,
    };
    use ioi_types::app::StudioExecutionStrategy;

    fn places_outcome_request(frame: Option<StudioPlacesRequestFrame>) -> StudioOutcomeRequest {
        StudioOutcomeRequest {
            request_id: "places-request".to_string(),
            raw_prompt: "Find coffee shops open now.".to_string(),
            active_artifact_id: None,
            outcome_kind: StudioOutcomeKind::ToolWidget,
            execution_strategy: StudioExecutionStrategy::PlanExecute,
            execution_mode_decision: None,
            confidence: 0.92,
            needs_clarification: false,
            clarification_questions: Vec::new(),
            routing_hints: vec!["tool_widget:places".to_string()],
            lane_frame: None,
            request_frame: frame.map(StudioNormalizedRequestFrame::Places),
            source_selection: None,
            retained_lane_state: None,
            lane_transitions: Vec::new(),
            orchestration_state: None,
            artifact: None,
        }
    }

    #[test]
    fn places_request_for_tool_widget_prefers_request_frame_state() {
        let outcome_request = places_outcome_request(Some(StudioPlacesRequestFrame {
            search_anchor: None,
            category: Some("coffee shops".to_string()),
            location_scope: Some("Williamsburg, Brooklyn".to_string()),
            missing_slots: Vec::new(),
            clarification_required_slots: Vec::new(),
        }));

        let parsed =
            places_request_for_tool_widget("Near Williamsburg, Brooklyn.", &outcome_request)
                .expect("retained places request");

        assert_eq!(parsed.category.label, "coffee shops");
        assert_eq!(parsed.category.amenity, "cafe");
        assert_eq!(parsed.anchor_phrase, "Williamsburg, Brooklyn");
    }
}
