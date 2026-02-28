use super::util::{marker_hits, normalize_marker_text};
use crate::agentic::desktop::service::step::text_tokens::{
    is_iso_date_token, looks_like_clock_time, token_has_numeric_payload,
};
use std::collections::BTreeSet;

const METRIC_AXIS_TEMPERATURE_MARKERS: [&str; 5] = [
    "temperature",
    "temp",
    "feels like",
    "dew point",
    "heat index",
];
const METRIC_AXIS_HUMIDITY_MARKERS: [&str; 3] = ["humidity", "relative humidity", "humid"];
const METRIC_AXIS_WIND_MARKERS: [&str; 4] = ["wind", "gust", "breeze", "mph"];
const METRIC_AXIS_PRESSURE_MARKERS: [&str; 4] = ["pressure", "barometric", "hpa", "inhg"];
const METRIC_AXIS_VISIBILITY_MARKERS: [&str; 2] = ["visibility", "vis "];
const METRIC_AXIS_AIR_QUALITY_MARKERS: [&str; 4] = ["aqi", "air quality", "pm2.5", "uv index"];
const METRIC_AXIS_PRECIPITATION_MARKERS: [&str; 5] = [
    "precipitation",
    "rain",
    "snow",
    "chance of rain",
    "chance of snow",
];
const METRIC_AXIS_PRICE_MARKERS: [&str; 8] = [
    "price",
    "cost",
    "quote",
    "market cap",
    "valuation",
    "usd",
    "eur",
    "gbp",
];
const METRIC_AXIS_RATE_STRONG_MARKERS: [&str; 4] =
    ["exchange rate", "interest rate", "rate", "yield"];
const METRIC_AXIS_RATE_WEAK_MARKERS: [&str; 2] = ["apr", "apy"];
const METRIC_AXIS_SCORE_MARKERS: [&str; 5] = ["score", "points", "standing", "ranking", "rank"];
const METRIC_AXIS_DURATION_MARKERS: [&str; 7] = [
    "minutes",
    "minute",
    "hours",
    "hour",
    "duration",
    "delay",
    "wait time",
];
const METRIC_OBSERVATION_MARKERS: [&str; 6] = [
    " current ",
    " currently ",
    " right now ",
    " as of ",
    " observed ",
    " live ",
];
const METRIC_HORIZON_MARKERS: [&str; 10] = [
    " forecast ",
    " outlook ",
    " tomorrow ",
    " next ",
    " weekly ",
    " monthly ",
    " annual ",
    " yearly ",
    " seasonal ",
    " future ",
];
const METRIC_RANGE_MARKERS: [&str; 8] = [
    " high ",
    " low ",
    " min ",
    " max ",
    " range ",
    " avg ",
    " average ",
    " median ",
];
const METRIC_UNIT_MARKERS: [&str; 17] = [
    "f",
    "c",
    "fahrenheit",
    "celsius",
    "mph",
    "km/h",
    "kph",
    "m/s",
    "hpa",
    "mb",
    "inhg",
    "aqi",
    "uv",
    "mm",
    "cm",
    "percent",
    "pct",
];
const METRIC_CURRENCY_MARKERS: [&str; 8] =
    ["$", " usd", " eur", " gbp", " jpy", " cad", " aud", " chf"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MetricAxis {
    Temperature,
    Humidity,
    Wind,
    Pressure,
    Visibility,
    AirQuality,
    Precipitation,
    Price,
    Rate,
    Score,
    Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricSchemaProfile {
    pub axis_hits: BTreeSet<MetricAxis>,
    pub numeric_token_hits: usize,
    pub unit_hits: usize,
    pub currency_hits: usize,
    pub timestamp_hits: usize,
    pub observation_hits: usize,
    pub horizon_hits: usize,
    pub range_hits: usize,
}

impl MetricSchemaProfile {
    pub fn has_metric_payload(&self) -> bool {
        if self.numeric_token_hits == 0 {
            return false;
        }
        self.unit_hits > 0
            || self.currency_hits > 0
            || !self.axis_hits.is_empty()
            || self.range_hits > 0
            || self.timestamp_hits > 0
    }

    pub fn has_current_observation_payload(&self) -> bool {
        if !self.has_metric_payload() {
            return false;
        }
        let observation_strength = self.observation_hits + self.timestamp_hits;
        let horizon_pressure = self.horizon_hits + self.range_hits;
        if observation_strength == 0 && !self.axis_hits.is_empty() {
            return horizon_pressure == 0;
        }
        if self.range_hits > 0 && observation_strength <= 1 && self.timestamp_hits == 0 {
            return false;
        }
        observation_strength > horizon_pressure
    }

    pub fn axis_overlap_score(&self, required: &BTreeSet<MetricAxis>) -> usize {
        if required.is_empty() {
            return usize::from(!self.axis_hits.is_empty());
        }
        self.axis_hits.intersection(required).count()
    }
}

fn metric_marker_hits(lower_text: &str, markers: &[&str]) -> usize {
    let tokens = lower_text.split_whitespace().collect::<Vec<_>>();
    markers
        .iter()
        .filter(|marker| {
            let normalized = marker.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                return false;
            }
            if normalized.contains(' ') {
                let phrase = format!(" {} ", normalized);
                lower_text.contains(&phrase)
            } else {
                tokens.iter().any(|token| **token == normalized)
            }
        })
        .count()
}

fn metric_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| {
        !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '%' | '/' | '-' | '+' | ',' | '$' | ':'))
    })
    .filter(|token| !token.is_empty())
    .map(|token| token.to_ascii_lowercase())
    .collect()
}

fn axis_hits(lower: &str) -> BTreeSet<MetricAxis> {
    let mut out = BTreeSet::new();
    if metric_marker_hits(lower, &METRIC_AXIS_TEMPERATURE_MARKERS) > 0 {
        out.insert(MetricAxis::Temperature);
    }
    if metric_marker_hits(lower, &METRIC_AXIS_HUMIDITY_MARKERS) > 0 {
        out.insert(MetricAxis::Humidity);
    }
    if metric_marker_hits(lower, &METRIC_AXIS_WIND_MARKERS) > 0 {
        out.insert(MetricAxis::Wind);
    }
    if metric_marker_hits(lower, &METRIC_AXIS_PRESSURE_MARKERS) > 0 {
        out.insert(MetricAxis::Pressure);
    }
    if metric_marker_hits(lower, &METRIC_AXIS_VISIBILITY_MARKERS) > 0 {
        out.insert(MetricAxis::Visibility);
    }
    if metric_marker_hits(lower, &METRIC_AXIS_AIR_QUALITY_MARKERS) > 0 {
        out.insert(MetricAxis::AirQuality);
    }
    if metric_marker_hits(lower, &METRIC_AXIS_PRECIPITATION_MARKERS) > 0 {
        out.insert(MetricAxis::Precipitation);
    }
    if metric_marker_hits(lower, &METRIC_AXIS_PRICE_MARKERS) > 0 {
        out.insert(MetricAxis::Price);
    }
    let has_rate_strong_marker = metric_marker_hits(lower, &METRIC_AXIS_RATE_STRONG_MARKERS) > 0;
    let has_rate_weak_marker = metric_marker_hits(lower, &METRIC_AXIS_RATE_WEAK_MARKERS) > 0;
    let has_rate_disambiguation_context =
        lower.contains('%') || lower.contains(" percent ") || lower.contains(" pct ");
    if has_rate_strong_marker || (has_rate_weak_marker && has_rate_disambiguation_context) {
        out.insert(MetricAxis::Rate);
    }
    if metric_marker_hits(lower, &METRIC_AXIS_SCORE_MARKERS) > 0 {
        out.insert(MetricAxis::Score);
    }
    if metric_marker_hits(lower, &METRIC_AXIS_DURATION_MARKERS) > 0 {
        out.insert(MetricAxis::Duration);
    }
    out
}

pub fn analyze_metric_schema(text: &str) -> MetricSchemaProfile {
    let raw_lower = format!(" {} ", text.to_ascii_lowercase());
    if raw_lower.trim().is_empty() {
        return MetricSchemaProfile::default();
    }
    let normalized_lower = normalize_marker_text(text);

    let tokens = metric_tokens(&raw_lower);
    let numeric_token_hits = tokens
        .iter()
        .filter(|token| token_has_numeric_payload(token.as_str()))
        .count();
    let unit_hits = tokens
        .iter()
        .enumerate()
        .filter(|(idx, token)| {
            METRIC_UNIT_MARKERS.iter().any(|unit| unit == token)
                && (*idx > 0 || *token == "uv" || *token == "aqi")
        })
        .count()
        + usize::from(raw_lower.contains('°'))
        + usize::from(raw_lower.contains('%'));
    let currency_hits = METRIC_CURRENCY_MARKERS
        .iter()
        .filter(|marker| raw_lower.contains(**marker))
        .count();
    let timestamp_hits = tokens
        .iter()
        .filter(|token| looks_like_clock_time(token) || is_iso_date_token(token))
        .count();
    let observation_hits = marker_hits(&normalized_lower, &METRIC_OBSERVATION_MARKERS);
    let horizon_hits = marker_hits(&normalized_lower, &METRIC_HORIZON_MARKERS);
    let range_hits = marker_hits(&normalized_lower, &METRIC_RANGE_MARKERS);

    let mut detected_axes = axis_hits(&normalized_lower);
    let has_temperature_unit_signal = raw_lower.contains('°')
        || tokens
            .iter()
            .any(|token| matches!(token.as_str(), "f" | "c" | "fahrenheit" | "celsius"));
    if !detected_axes.contains(&MetricAxis::Temperature)
        && numeric_token_hits > 0
        && unit_hits > 0
        && has_temperature_unit_signal
    {
        detected_axes.insert(MetricAxis::Temperature);
    }

    MetricSchemaProfile {
        axis_hits: detected_axes,
        numeric_token_hits,
        unit_hits,
        currency_hits,
        timestamp_hits,
        observation_hits,
        horizon_hits,
        range_hits,
    }
}
