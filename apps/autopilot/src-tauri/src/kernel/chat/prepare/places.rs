use super::*;
use ioi_api::runtime_harness::{resolve_runtime_locality_placeholder, ChatIntentContext};
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

#[derive(Clone, Copy)]
pub(super) struct PlacesCategoryTarget {
    pub(super) amenity: &'static str,
    pub(super) label: &'static str,
}

#[derive(Clone)]
pub(super) struct ParsedPlacesRequest {
    pub(super) anchor_phrase: String,
    pub(super) category: PlacesCategoryTarget,
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

pub(super) fn chat_surface_http_client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("ioi-autopilot-chat/0.1")
        .build()
        .map_err(|error| format!("Chat surface could not build its client: {error}"))
}

fn place_category_for_intent(intent: &str) -> Option<PlacesCategoryTarget> {
    place_category_target_from_label(ChatIntentContext::new(intent).places_category_label()?)
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
    ChatIntentContext::new(intent).places_anchor_phrase()
}

fn parse_places_request(intent: &str) -> Option<ParsedPlacesRequest> {
    Some(ParsedPlacesRequest {
        anchor_phrase: anchor_phrase_for_places_intent(intent)?,
        category: place_category_for_intent(intent)?,
    })
}

pub(super) fn places_request_for_tool_widget(
    intent: &str,
    outcome_request: &ChatOutcomeRequest,
) -> Option<ParsedPlacesRequest> {
    if let Some(ioi_types::app::chat::ChatNormalizedRequest::Places(frame)) =
        outcome_request.normalized_request.as_ref()
    {
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
            format!("Chat places surface could not geocode '{anchor_phrase}': {error}")
        })?
        .json::<Vec<NominatimSearchResult>>()
        .map_err(|error| {
            format!("Chat places surface could not read its geocoder response: {error}")
        })?;
    results
        .into_iter()
        .next()
        .ok_or_else(|| format!("Chat places surface could not locate '{anchor_phrase}'."))
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
                        "Chat places surface found no {} near {} via {}.",
                        request.category.label, request.anchor_phrase, endpoint
                    ));
                }
                Err(error) => {
                    last_error = Some(format!(
                        "Chat places surface could not read nearby places from {}: {}",
                        endpoint, error
                    ));
                }
            },
            Err(error) => {
                last_error = Some(format!(
                    "Chat places surface could not search nearby places via {}: {}",
                    endpoint, error
                ));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        format!(
            "Chat places surface could not find {} near {}.",
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
            format!("Chat places surface could not query fallback place search: {error}")
        })?
        .json::<Vec<NominatimSearchResult>>()
        .map_err(|error| {
            format!("Chat places surface could not read fallback place search: {error}")
        })?;
    let nearby = nearby_places_from_nominatim(results, anchor_coords);
    if nearby.is_empty() {
        return Err(format!(
            "Chat places surface could not find {} near {}.",
            request.category.label, request.anchor_phrase
        ));
    }
    Ok(nearby)
}

fn fetch_places_candidates(
    client: &Client,
    intent: &str,
    outcome_request: &ChatOutcomeRequest,
) -> Result<(ParsedPlacesRequest, Vec<PlaceCandidate>), String> {
    let request = places_request_for_tool_widget(intent, outcome_request).ok_or_else(|| {
        "Chat could not determine which type of place and anchor location to use.".to_string()
    })?;
    let anchor = geocode_anchor_result(client, &request.anchor_phrase)?;
    let anchor_coords = parse_lat_lon_pair(&anchor.lat, &anchor.lon).ok_or_else(|| {
        format!(
            "Chat places surface could not interpret coordinates for '{}'.",
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

pub(super) fn format_places_tool_widget_reply(
    intent: &str,
    outcome_request: &ChatOutcomeRequest,
) -> Result<String, String> {
    let client = chat_surface_http_client()?;
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
