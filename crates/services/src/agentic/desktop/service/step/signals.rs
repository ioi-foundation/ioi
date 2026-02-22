use crate::agentic::desktop::types::InteractionTarget;
use std::collections::BTreeSet;
use url::Url;

pub const ONTOLOGY_SIGNAL_VERSION: &str = "ontology_signals_v3";
pub const LIVE_EXTERNAL_RESEARCH_SIGNAL_VERSION: &str = ONTOLOGY_SIGNAL_VERSION;
pub const WEB_EVIDENCE_SIGNAL_VERSION: &str = "web_evidence_signals_v3";

const RECENCY_MARKERS: [&str; 15] = [
    "as of",
    "as-of",
    "now",
    "current",
    "currently",
    "latest",
    "today",
    "this hour",
    "last hour",
    "past hour",
    "right now",
    "utc",
    "live",
    "recent",
    "most recent",
];

const PROVENANCE_MARKERS: [&str; 18] = [
    "citation",
    "citations",
    "source",
    "sources",
    "timestamp",
    "timestamps",
    "link",
    "links",
    "url",
    "urls",
    "reference",
    "references",
    "official",
    "evidence",
    "grounded",
    "grounding",
    "verify",
    "proof",
];

const EXTERNAL_KNOWLEDGE_MARKERS: [&str; 20] = [
    "web",
    "internet",
    "online",
    "news",
    "status",
    "status page",
    "status dashboard",
    "service health",
    "incident",
    "outage",
    "degraded",
    "degradation",
    "availability",
    "downtime",
    "uptime",
    "provider",
    "public report",
    "public update",
    "market update",
    "release note",
];

const PUBLIC_FACT_MARKERS: [&str; 24] = [
    "weather",
    "forecast",
    "temperature",
    "feels like",
    "humidity",
    "dew point",
    "wind",
    "precipitation",
    "rain",
    "snow",
    "air quality",
    "aqi",
    "uv index",
    "pollen",
    "visibility",
    "stock price",
    "market price",
    "exchange rate",
    "price of",
    "score",
    "traffic",
    "wait time",
    "travel time",
    "arrival time",
];

const WORKSPACE_MARKERS: [&str; 24] = [
    "repo",
    "repository",
    "workspace",
    "codebase",
    "source code",
    "file",
    "files",
    "folder",
    "directory",
    "crate",
    "module",
    "function",
    "class",
    "test",
    "tests",
    "cargo",
    "rust",
    "typescript",
    "javascript",
    "commit",
    "branch",
    "pull request",
    "patch",
    "diff",
];

const LAUNCH_MARKERS: [&str; 4] = ["open ", "launch ", "start ", "run "];
const FOLLOW_UP_ACTION_MARKERS: [&str; 19] = [
    " click ",
    " type ",
    " enter ",
    " compute ",
    " calculate ",
    " solve ",
    " search ",
    " browse ",
    " navigate ",
    " extract ",
    " summarize ",
    " read ",
    " write ",
    " edit ",
    " create ",
    " delete ",
    " screenshot ",
    " test ",
    " run tests",
];

const CONVERSATION_MARKERS: [&str; 8] = [
    "ask",
    "explain",
    "summarize",
    "draft",
    "rewrite",
    "clarify",
    "answer",
    "respond",
];

const DELEGATION_MARKERS: [&str; 3] = ["delegate", "handoff", "sub-agent"];

const UI_MARKERS: [&str; 9] = [
    "click",
    "type",
    "press",
    "drag",
    "scroll",
    "button",
    "input field",
    "window",
    "dialog",
];

const FILESYSTEM_MARKERS: [&str; 12] = [
    "file",
    "directory",
    "folder",
    "path",
    "repo",
    "repository",
    "workspace",
    "read file",
    "write file",
    "patch",
    "diff",
    "module",
];

const INSTALL_MARKERS: [&str; 6] = ["install", "dependency", "package", "apt", "brew", "yum"];

const BROWSER_MARKERS: [&str; 8] = [
    "browser",
    "web",
    "search",
    "http://",
    "https://",
    "url",
    "website",
    "status page",
];

const COMMAND_MARKERS: [&str; 9] = [
    "terminal",
    "shell",
    "command",
    "cli",
    "bash",
    "zsh",
    "powershell",
    "run command",
    "execute",
];

const MAILBOX_DOMAIN_MARKERS: [&str; 11] = [
    " email ",
    " e-mail ",
    " inbox ",
    " mailbox ",
    " message ",
    " messages ",
    " spam ",
    " junk ",
    " unread ",
    " sender ",
    " subject ",
];

const MAILBOX_PERSONAL_SCOPE_MARKERS: [&str; 9] = [
    " my ",
    " me ",
    " i ",
    " i've ",
    " i have ",
    " received ",
    " arrived ",
    " sent ",
    " my inbox ",
];

const MAILBOX_ACTION_MARKERS: [&str; 13] = [
    " read ",
    " list ",
    " check ",
    " latest ",
    " recent ",
    " newest ",
    " most recent ",
    " delete ",
    " remove ",
    " reply ",
    " respond ",
    " summarize ",
    " summarise ",
];

const REPORT_CHANGE_MARKERS: [&str; 8] = [
    "change",
    "changed",
    "delta",
    "update",
    "new since",
    "recently",
    "what changed",
    "what is new",
];

const REPORT_HOURLY_SCOPE_MARKERS: [&str; 6] = [
    "last hour",
    "last-hour",
    "past hour",
    "past-hour",
    "this hour",
    "this-hour",
];

const REPORT_SIGNIFICANCE_MARKERS: [&str; 4] = [
    "why it matters",
    "why this matters",
    "importance",
    "implication",
];

const REPORT_IMPACT_MARKERS: [&str; 8] = [
    "impact",
    "impacts",
    "affected",
    "effect",
    "customer impact",
    "user impact",
    "blast radius",
    "who is affected",
];

const REPORT_MITIGATION_MARKERS: [&str; 7] = [
    "workaround",
    "mitigation",
    "temporary fix",
    "fallback",
    "remediation",
    "how to mitigate",
    "next steps",
];

const REPORT_TIMELINE_MARKERS: [&str; 8] = [
    "eta",
    "confidence",
    "expected",
    "timeline",
    "restoration",
    "resolution",
    "when",
    "next update",
];

const REPORT_CAVEAT_MARKERS: [&str; 4] = ["caveat", "limitation", "uncertainty", "unknown"];

const SOURCE_LOW_PRIORITY_MARKERS: [&str; 16] = [
    "fact sheet",
    "news websites",
    "trust in media",
    "which news sources",
    "opinion",
    "analysis",
    "liveblog",
    "live blog",
    "roundup",
    "watch live",
    "video recap",
    "how to watch",
    "schedules and results",
    "news, schedules, results",
    "advertisement",
    "sponsored",
];

const SOURCE_PRIMARY_EVENT_MARKERS: [&str; 28] = [
    "incident",
    "outage",
    "degraded",
    "degradation",
    "service disruption",
    "unavailable",
    "downtime",
    "latency",
    "error rate",
    "elevated errors",
    "packet loss",
    "availability",
    "investigating",
    "identified",
    "monitoring",
    "mitigation",
    "mitigated",
    "restored",
    "status page",
    "service health",
    "impacted",
    "affected",
    "authentication",
    "login",
    "api",
    "dashboard",
    "control plane",
    "data plane",
];

const SOURCE_PROVENANCE_MARKERS: [&str; 12] = [
    "status.",
    "statuspage",
    "service health",
    "status page",
    "status dashboard",
    "official update",
    "official status",
    "incident history",
    "postmortem",
    "publish date",
    "updated at",
    "reported at",
];

const SOURCE_PRIMARY_STATUS_SURFACE_MARKERS: [&str; 15] = [
    "status.",
    "statuspage.io",
    "/status",
    "/status/",
    "/incidents",
    "/incident",
    "/incident-history",
    "/service-health",
    "/service_health",
    "/health-status",
    "status page",
    "status dashboard",
    "service health",
    "official status",
    "incident history",
];

const SOURCE_SECONDARY_COVERAGE_MARKERS: [&str; 27] = [
    "aggregator",
    "aggregate",
    "monitor 100",
    "monitor 1000",
    "monitor 5,",
    "tracker",
    "tracking",
    "across providers",
    "across vendors",
    "across services",
    "multiple services",
    "multi-service",
    "industry incidents",
    "industry outages",
    "crowdsourced",
    "community reports",
    "user reports",
    "watch live",
    "research report",
    "annual report",
    "state of",
    "retrospective",
    "high-profile",
    "lessons",
    "breaches",
    "2023 ",
    "2024 ",
];

const SOURCE_OFFICIAL_STATUS_HOST_MARKERS: [&str; 8] = [
    "status",
    "statuspage",
    "servicehealth",
    "service-health",
    "health",
    "uptime",
    "trust",
    "availability",
];

const SOURCE_OFFICIAL_STATUS_PATH_MARKERS: [&str; 10] = [
    "/status",
    "/status/",
    "/incidents",
    "/incident",
    "/incident-history",
    "/service-health",
    "/service_health",
    "/health-status",
    "/health/",
    "/uptime",
];

const SOURCE_SECONDARY_AGGREGATION_HOST_MARKERS: [&str; 11] = [
    "monitor",
    "tracker",
    "aggregator",
    "outage",
    "watch",
    "radar",
    "reports",
    "insights",
    "analytics",
    "signals",
    "intel",
];

const SOURCE_SECONDARY_AGGREGATION_PATH_MARKERS: [&str; 9] = [
    "/all-services",
    "/all-providers",
    "/across-providers",
    "/industry",
    "/outages",
    "/reports",
    "/analysis",
    "/analytics",
    "/statistics",
];

const SOURCE_DOCUMENTATION_SURFACE_HOST_MARKERS: [&str; 8] = [
    "docs",
    "doc",
    "learn",
    "developer",
    "developers",
    "knowledge",
    "support",
    "help",
];

const SOURCE_DOCUMENTATION_SURFACE_PATH_MARKERS: [&str; 7] = [
    "/docs",
    "/documentation",
    "/learn",
    "/knowledge",
    "/help",
    "/guide",
    "/guides",
];

const SOURCE_IMPACT_MARKERS: [&str; 10] = [
    "u.s.",
    "united states",
    "north america",
    "region",
    "regional",
    "tenant",
    "customer impact",
    "user impact",
    "customers",
    "users",
];

const SOURCE_MITIGATION_MARKERS: [&str; 11] = [
    "workaround",
    "mitigation",
    "temporary fix",
    "retry",
    "failover",
    "fallback",
    "manual workaround",
    "switch region",
    "use another region",
    "alternate endpoint",
    "remediation",
];

const SOURCE_TIMELINE_MARKERS: [&str; 12] = [
    "eta",
    "estimated",
    "expected by",
    "expected resolution",
    "next update",
    "update at",
    "within",
    "minutes",
    "hours",
    "time to resolve",
    "resolution time",
    "restoration timeline",
];

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

const BROWSER_SURFACE_MARKERS: [&str; 8] = [
    "chrome", "chromium", "brave", "firefox", "edge", "safari", "arc", "browser",
];

const SYSTEM_SURFACE_MARKERS: [&str; 8] = [
    "finder",
    "explorer",
    "dock",
    "shell",
    "launcher",
    "desktop",
    "taskbar",
    "autopilot",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoalSignalProfile {
    pub recency_hits: usize,
    pub provenance_hits: usize,
    pub external_hits: usize,
    pub public_fact_hits: usize,
    pub workspace_hits: usize,
    pub launch_hits: usize,
    pub follow_up_hits: usize,
    pub conversation_hits: usize,
    pub delegation_hits: usize,
    pub ui_hits: usize,
    pub filesystem_hits: usize,
    pub install_hits: usize,
    pub browser_hits: usize,
    pub command_hits: usize,
    pub explicit_url_hits: usize,
    pub mailbox_domain_hits: usize,
    pub mailbox_personal_scope_hits: usize,
    pub mailbox_action_hits: usize,
}

impl GoalSignalProfile {
    pub fn workspace_dominant(&self) -> bool {
        self.workspace_hits >= 2 && self.external_hits <= 1
    }

    pub fn prefers_live_external_research(&self) -> bool {
        if self.prefers_mailbox_connector_flow() {
            return false;
        }
        if self.workspace_dominant() {
            return false;
        }

        let has_live_grounding_request = self.recency_hits >= 1 && self.provenance_hits >= 1;
        let has_external_surface =
            self.external_hits >= 2 || (self.external_hits >= 1 && has_live_grounding_request);
        let has_provenance_pressure = self.provenance_hits >= 2 || self.explicit_url_hits > 0;
        let has_time_sensitive_public_fact_lookup = self.recency_hits >= 1
            && self.public_fact_hits >= 1
            && self.workspace_hits == 0
            && self.filesystem_hits == 0
            && self.command_hits == 0
            && self.install_hits == 0;

        (has_live_grounding_request && has_external_surface)
            || (has_external_surface && has_provenance_pressure)
            || has_time_sensitive_public_fact_lookup
    }

    pub fn prefers_mailbox_connector_flow(&self) -> bool {
        let has_mailbox_domain = self.mailbox_domain_hits > 0;
        let has_personal_anchor = self.mailbox_personal_scope_hits > 0;
        let has_mailbox_action = self.mailbox_action_hits > 0;
        has_mailbox_domain && (has_personal_anchor || has_mailbox_action)
    }
}

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryFacetProfile {
    pub goal: GoalSignalProfile,
    pub metric_schema: MetricSchemaProfile,
    pub time_sensitive_public_fact: bool,
    pub locality_sensitive_public_fact: bool,
    pub grounded_external_required: bool,
    pub workspace_constrained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentSurface {
    AppLaunch,
    CommandExecution,
    Conversation,
    Delegation,
    DependencyInstall,
    UiInteraction,
    WebResearch,
    WorkspaceOps,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReportSectionKind {
    Summary,
    RecentChange,
    Significance,
    UserImpact,
    Mitigation,
    EtaConfidence,
    Caveat,
    Evidence,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SourceSignalProfile {
    pub primary_event_hits: usize,
    pub provenance_hits: usize,
    pub primary_status_surface_hits: usize,
    pub official_status_host_hits: usize,
    pub secondary_coverage_hits: usize,
    pub documentation_surface_hits: usize,
    pub impact_hits: usize,
    pub mitigation_hits: usize,
    pub timeline_hits: usize,
    pub low_priority_hits: usize,
}

impl SourceSignalProfile {
    const PRIMARY_EVENT_WEIGHT: usize = 5;
    const PROVENANCE_WEIGHT: usize = 4;
    const PRIMARY_STATUS_SURFACE_WEIGHT: usize = 6;
    const OFFICIAL_STATUS_HOST_WEIGHT: usize = 8;
    const IMPACT_WEIGHT: usize = 3;
    const MITIGATION_WEIGHT: usize = 2;
    const TIMELINE_WEIGHT: usize = 2;
    const SUCCESSFUL_READ_BONUS: usize = 4;
    const SECONDARY_COVERAGE_PENALTY: usize = 5;
    const DOCUMENTATION_SURFACE_PENALTY: usize = 4;
    const SCORE_FLOOR: usize = 1;

    pub fn relevance_score(self, from_successful_read: bool) -> usize {
        let successful_read_bonus = if from_successful_read {
            Self::SUCCESSFUL_READ_BONUS
        } else {
            0
        };
        let score = self.primary_event_hits * Self::PRIMARY_EVENT_WEIGHT
            + self.provenance_hits * Self::PROVENANCE_WEIGHT
            + self.primary_status_surface_hits * Self::PRIMARY_STATUS_SURFACE_WEIGHT
            + self.official_status_host_hits * Self::OFFICIAL_STATUS_HOST_WEIGHT
            + self.impact_hits * Self::IMPACT_WEIGHT
            + self.mitigation_hits * Self::MITIGATION_WEIGHT
            + self.timeline_hits * Self::TIMELINE_WEIGHT
            + successful_read_bonus;
        let score =
            score.saturating_sub(self.secondary_coverage_hits * Self::SECONDARY_COVERAGE_PENALTY);
        let score = score
            .saturating_sub(self.documentation_surface_hits * Self::DOCUMENTATION_SURFACE_PENALTY);
        score + Self::SCORE_FLOOR
    }

    pub fn low_priority_dominates(self) -> bool {
        let low_signal =
            self.low_priority_hits + self.secondary_coverage_hits + self.documentation_surface_hits;
        let high_signal = self.primary_event_hits
            + self.primary_status_surface_hits
            + self.official_status_host_hits;
        low_signal > high_signal
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct SourceUrlSignalProfile {
    official_status_host_hits: usize,
    secondary_aggregation_hits: usize,
    documentation_surface_hits: usize,
}

fn marker_hits(lower_text: &str, markers: &[&str]) -> usize {
    markers
        .iter()
        .filter(|marker| lower_text.contains(**marker))
        .count()
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

fn normalize_marker_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push(' ');
    let mut last_was_space = true;
    for ch in text.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            out.push(lower);
            last_was_space = false;
            continue;
        }
        if !last_was_space {
            out.push(' ');
            last_was_space = true;
        }
    }
    if !out.ends_with(' ') {
        out.push(' ');
    }
    out
}

fn metric_tokens(text: &str) -> Vec<String> {
    text.split(|ch: char| {
        !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '%' | '/' | '-' | '+' | ',' | '$' | ':'))
    })
    .filter(|token| !token.is_empty())
    .map(|token| token.to_ascii_lowercase())
    .collect()
}

fn token_has_numeric_payload(token: &str) -> bool {
    let mut digits = 0usize;
    for ch in token.chars() {
        if ch.is_ascii_digit() {
            digits += 1;
            continue;
        }
        if ch.is_ascii_alphabetic() {
            return false;
        }
        if matches!(ch, '.' | '%' | '/' | '-' | '+' | ',' | '$' | ':') {
            continue;
        }
        return false;
    }
    digits > 0
}

fn has_iso_date_token(token: &str) -> bool {
    let bytes = token.as_bytes();
    if bytes.len() != 10 {
        return false;
    }
    bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
        && bytes[4] == b'-'
        && bytes[5].is_ascii_digit()
        && bytes[6].is_ascii_digit()
        && bytes[7] == b'-'
        && bytes[8].is_ascii_digit()
        && bytes[9].is_ascii_digit()
}

fn has_clock_token(token: &str) -> bool {
    let cleaned = token.trim_matches(|ch: char| !ch.is_ascii_digit() && ch != ':');
    let mut parts = cleaned.split(':');
    let Some(hours) = parts.next() else {
        return false;
    };
    let Some(minutes) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    !hours.is_empty()
        && minutes.len() == 2
        && hours.chars().all(|ch| ch.is_ascii_digit())
        && minutes.chars().all(|ch| ch.is_ascii_digit())
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
        .filter(|token| has_clock_token(token) || has_iso_date_token(token))
        .count();
    let observation_hits = marker_hits(&normalized_lower, &METRIC_OBSERVATION_MARKERS);
    let horizon_hits = marker_hits(&normalized_lower, &METRIC_HORIZON_MARKERS);
    let range_hits = marker_hits(&normalized_lower, &METRIC_RANGE_MARKERS);

    MetricSchemaProfile {
        axis_hits: axis_hits(&normalized_lower),
        numeric_token_hits,
        unit_hits,
        currency_hits,
        timestamp_hits,
        observation_hits,
        horizon_hits,
        range_hits,
    }
}

pub fn analyze_query_facets(query: &str) -> QueryFacetProfile {
    let goal = analyze_goal_signals(query);
    let metric_schema = analyze_metric_schema(query);
    let workspace_constrained = goal.workspace_dominant()
        || goal.filesystem_hits > 0
        || goal.command_hits > 0
        || goal.install_hits > 0;
    let time_sensitive_public_fact = goal.recency_hits > 0 && goal.public_fact_hits > 0;
    let metric_locality_sensitive = metric_schema.axis_hits.iter().any(|axis| {
        matches!(
            axis,
            MetricAxis::Temperature
                | MetricAxis::Humidity
                | MetricAxis::Wind
                | MetricAxis::Pressure
                | MetricAxis::Visibility
                | MetricAxis::AirQuality
                | MetricAxis::Precipitation
                | MetricAxis::Duration
        )
    });
    let implicit_locality_shape =
        goal.public_fact_hits > 0 && goal.external_hits == 0 && metric_schema.axis_hits.is_empty();
    let locality_sensitive_public_fact =
        time_sensitive_public_fact && (metric_locality_sensitive || implicit_locality_shape);
    let grounded_external_required = goal.prefers_live_external_research()
        || (time_sensitive_public_fact && !workspace_constrained);

    QueryFacetProfile {
        goal,
        metric_schema,
        time_sensitive_public_fact,
        locality_sensitive_public_fact,
        grounded_external_required,
        workspace_constrained,
    }
}

fn canonical_tool_name(root_tool_name: &str) -> String {
    root_tool_name
        .trim()
        .to_ascii_lowercase()
        .replace("::", "__")
}

pub fn analyze_goal_signals(goal: &str) -> GoalSignalProfile {
    let goal_lc = goal.to_ascii_lowercase();
    if goal_lc.trim().is_empty() {
        return GoalSignalProfile::default();
    }
    let padded_goal = format!(" {} ", goal_lc);

    GoalSignalProfile {
        recency_hits: marker_hits(&padded_goal, &RECENCY_MARKERS),
        provenance_hits: marker_hits(&padded_goal, &PROVENANCE_MARKERS),
        external_hits: marker_hits(&padded_goal, &EXTERNAL_KNOWLEDGE_MARKERS),
        public_fact_hits: marker_hits(&padded_goal, &PUBLIC_FACT_MARKERS),
        workspace_hits: marker_hits(&padded_goal, &WORKSPACE_MARKERS),
        launch_hits: marker_hits(&padded_goal, &LAUNCH_MARKERS),
        follow_up_hits: marker_hits(&padded_goal, &FOLLOW_UP_ACTION_MARKERS),
        conversation_hits: marker_hits(&padded_goal, &CONVERSATION_MARKERS),
        delegation_hits: marker_hits(&padded_goal, &DELEGATION_MARKERS),
        ui_hits: marker_hits(&padded_goal, &UI_MARKERS),
        filesystem_hits: marker_hits(&padded_goal, &FILESYSTEM_MARKERS),
        install_hits: marker_hits(&padded_goal, &INSTALL_MARKERS),
        browser_hits: marker_hits(&padded_goal, &BROWSER_MARKERS),
        command_hits: marker_hits(&padded_goal, &COMMAND_MARKERS),
        explicit_url_hits: marker_hits(&padded_goal, &["http://", "https://"]),
        mailbox_domain_hits: marker_hits(&padded_goal, &MAILBOX_DOMAIN_MARKERS),
        mailbox_personal_scope_hits: marker_hits(&padded_goal, &MAILBOX_PERSONAL_SCOPE_MARKERS),
        mailbox_action_hits: marker_hits(&padded_goal, &MAILBOX_ACTION_MARKERS),
    }
}

fn marker_lexeme_tokens(markers: &[&str]) -> BTreeSet<String> {
    markers
        .iter()
        .flat_map(|marker| marker.split(|ch: char| !ch.is_ascii_alphanumeric()))
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < 3 {
                return None;
            }
            if normalized.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

fn goal_structural_directive_tokens(goal: &GoalSignalProfile) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    if goal.recency_hits > 0 {
        tokens.extend(marker_lexeme_tokens(&RECENCY_MARKERS));
    }
    if goal.provenance_hits > 0 {
        tokens.extend(marker_lexeme_tokens(&PROVENANCE_MARKERS));
    }
    if goal.follow_up_hits > 0 {
        tokens.extend(marker_lexeme_tokens(&FOLLOW_UP_ACTION_MARKERS));
    }
    if goal.conversation_hits > 0 {
        tokens.extend(marker_lexeme_tokens(&CONVERSATION_MARKERS));
    }
    if goal.delegation_hits > 0 {
        tokens.extend(marker_lexeme_tokens(&DELEGATION_MARKERS));
    }
    if goal.launch_hits > 0 {
        tokens.extend(marker_lexeme_tokens(&LAUNCH_MARKERS));
    }
    tokens
}

pub fn query_structural_directive_tokens(query: &str) -> BTreeSet<String> {
    let goal = analyze_goal_signals(query);
    goal_structural_directive_tokens(&goal)
}

pub fn query_semantic_anchor_tokens(query: &str) -> BTreeSet<String> {
    let normalized = normalize_marker_text(query);
    if normalized.trim().is_empty() {
        return BTreeSet::new();
    }

    let base_tokens = normalized
        .split_whitespace()
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < 3 {
                return None;
            }
            if normalized.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            Some(normalized)
        })
        .collect::<BTreeSet<_>>();

    if base_tokens.is_empty() {
        return base_tokens;
    }

    let structural_tokens = query_structural_directive_tokens(query);
    let semantic_tokens = base_tokens
        .iter()
        .filter(|token| !structural_tokens.contains(*token))
        .cloned()
        .collect::<BTreeSet<_>>();

    if semantic_tokens.is_empty() {
        base_tokens
    } else {
        semantic_tokens
    }
}

pub fn is_live_external_research_goal(goal: &str) -> bool {
    analyze_goal_signals(goal).prefers_live_external_research()
}

pub fn is_mailbox_connector_intent(goal: &str) -> bool {
    analyze_goal_signals(goal).prefers_mailbox_connector_flow()
}

pub fn is_mail_connector_tool_name(tool_name: &str) -> bool {
    let normalized = tool_name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    normalized.starts_with("wallet_network__mail_")
        || normalized.starts_with("wallet_mail_")
        || normalized.starts_with("mail__")
}

pub fn infer_interaction_target(goal: &str) -> Option<InteractionTarget> {
    let profile = analyze_goal_signals(goal);
    if profile.launch_hits == 0 {
        return None;
    }

    let goal_lc = goal.to_ascii_lowercase();
    let app_hint = [
        ("calculator", &["calculator", "calc"] as &[_]),
        (
            "code",
            &["vscode", "visual studio code", "code editor", "code"],
        ),
        (
            "terminal",
            &["terminal", "shell", "command prompt", "powershell", "iterm"],
        ),
        ("browser", &["browser", "chrome", "firefox", "safari"]),
    ]
    .iter()
    .find_map(|(hint, aliases)| {
        aliases
            .iter()
            .any(|alias| goal_lc.contains(alias))
            .then_some((*hint).to_string())
    })?;

    Some(InteractionTarget {
        app_hint: Some(app_hint),
        title_pattern: None,
    })
}

pub fn infer_intent_surface(
    goal: &str,
    root_tool_name: &str,
    target_hint: Option<&str>,
) -> IntentSurface {
    let tool = canonical_tool_name(root_tool_name);

    if tool.contains("agent__delegate") {
        return IntentSurface::Delegation;
    }
    if tool.contains("chat__reply") {
        return IntentSurface::Conversation;
    }
    if tool.contains("os__launch_app") {
        return IntentSurface::AppLaunch;
    }
    if tool.contains("sys__install_package") || tool.ends_with("install_package") {
        return IntentSurface::DependencyInstall;
    }
    if tool.starts_with("web__") || tool.starts_with("browser__") {
        return IntentSurface::WebResearch;
    }
    if tool.starts_with("filesystem__") || tool.starts_with("fs__") {
        return IntentSurface::WorkspaceOps;
    }
    if tool.starts_with("gui__") || tool.contains("computer") {
        return IntentSurface::UiInteraction;
    }
    if tool.starts_with("sys__exec") || tool.starts_with("sys__change_directory") {
        return IntentSurface::CommandExecution;
    }

    if target_hint.is_some_and(|hint| !hint.trim().is_empty()) {
        return IntentSurface::AppLaunch;
    }

    let profile = analyze_goal_signals(goal);

    if profile.delegation_hits > 0 {
        return IntentSurface::Delegation;
    }
    if profile.install_hits > 0 {
        return IntentSurface::DependencyInstall;
    }
    if profile.launch_hits > 0 {
        return IntentSurface::AppLaunch;
    }
    if profile.filesystem_hits > 0 {
        return IntentSurface::WorkspaceOps;
    }
    if profile.ui_hits > 0 {
        return IntentSurface::UiInteraction;
    }
    if profile.browser_hits > 0 || profile.prefers_live_external_research() {
        return IntentSurface::WebResearch;
    }
    if profile.command_hits > 0 {
        return IntentSurface::CommandExecution;
    }

    if profile.conversation_hits > 0 {
        return IntentSurface::Conversation;
    }

    IntentSurface::Unknown
}

pub fn infer_report_sections(query: &str) -> Vec<ReportSectionKind> {
    let query_lc = query.to_ascii_lowercase();
    let mut sections = vec![ReportSectionKind::Summary];

    if marker_hits(&query_lc, &REPORT_CHANGE_MARKERS) > 0 {
        sections.push(ReportSectionKind::RecentChange);
    }
    if marker_hits(&query_lc, &REPORT_SIGNIFICANCE_MARKERS) > 0 {
        sections.push(ReportSectionKind::Significance);
    }
    if marker_hits(&query_lc, &REPORT_IMPACT_MARKERS) > 0 {
        sections.push(ReportSectionKind::UserImpact);
    }
    if marker_hits(&query_lc, &REPORT_MITIGATION_MARKERS) > 0 {
        sections.push(ReportSectionKind::Mitigation);
    }
    if marker_hits(&query_lc, &REPORT_TIMELINE_MARKERS) > 0 {
        sections.push(ReportSectionKind::EtaConfidence);
    }
    if marker_hits(&query_lc, &REPORT_CAVEAT_MARKERS) > 0 {
        sections.push(ReportSectionKind::Caveat);
    }

    // If the user explicitly asks for grounded output, request an evidence section.
    if marker_hits(&query_lc, &PROVENANCE_MARKERS) > 0 {
        sections.push(ReportSectionKind::Evidence);
    }

    if sections.len() == 1 {
        sections.push(ReportSectionKind::Evidence);
    }

    sections.sort();
    sections.dedup();
    sections
}

pub fn report_section_label(kind: ReportSectionKind, query: &str) -> String {
    match kind {
        ReportSectionKind::Summary => "What happened".to_string(),
        ReportSectionKind::RecentChange => {
            let query_lc = query.to_ascii_lowercase();
            if marker_hits(&query_lc, &REPORT_HOURLY_SCOPE_MARKERS) > 0 {
                "What changed in the last hour".to_string()
            } else {
                "What changed recently".to_string()
            }
        }
        ReportSectionKind::Significance => "Why it matters".to_string(),
        ReportSectionKind::UserImpact => "User impact".to_string(),
        ReportSectionKind::Mitigation => "Workaround".to_string(),
        ReportSectionKind::EtaConfidence => "ETA confidence".to_string(),
        ReportSectionKind::Caveat => "Caveat".to_string(),
        ReportSectionKind::Evidence => "Key evidence".to_string(),
    }
}

pub fn report_section_key(kind: ReportSectionKind) -> &'static str {
    match kind {
        ReportSectionKind::Summary => "what_happened",
        ReportSectionKind::RecentChange => "recent_change",
        ReportSectionKind::Significance => "significance",
        ReportSectionKind::UserImpact => "user_impact",
        ReportSectionKind::Mitigation => "mitigation",
        ReportSectionKind::EtaConfidence => "eta_confidence",
        ReportSectionKind::Caveat => "caveat",
        ReportSectionKind::Evidence => "key_evidence",
    }
}

pub fn report_section_aliases(kind: ReportSectionKind) -> &'static [&'static str] {
    match kind {
        ReportSectionKind::Summary => &[
            "what_happened",
            "summary",
            "overview",
            "key_evidence",
            "evidence",
        ],
        ReportSectionKind::RecentChange => &[
            "what_changed_in_the_last_hour",
            "what_changed_recently",
            "recent_change",
            "changes",
            "recent_changes",
            "delta",
        ],
        ReportSectionKind::Significance => &[
            "why_it_matters",
            "why_this_matters",
            "importance",
            "significance",
            "why_it_is_important",
        ],
        ReportSectionKind::UserImpact => &["user_impact", "impact", "customer_impact"],
        ReportSectionKind::Mitigation => &["workaround", "mitigation", "temporary_fix", "fallback"],
        ReportSectionKind::EtaConfidence => &[
            "eta_confidence",
            "eta",
            "resolution_confidence",
            "restoration_confidence",
            "confidence",
        ],
        ReportSectionKind::Caveat => &["caveat", "limitation", "uncertainty"],
        ReportSectionKind::Evidence => &["key_evidence", "evidence", "supporting_evidence"],
    }
}

pub fn analyze_source_text_signals(text: &str) -> SourceSignalProfile {
    let lower = text.to_ascii_lowercase();
    SourceSignalProfile {
        primary_event_hits: marker_hits(&lower, &SOURCE_PRIMARY_EVENT_MARKERS),
        provenance_hits: marker_hits(&lower, &SOURCE_PROVENANCE_MARKERS),
        primary_status_surface_hits: marker_hits(&lower, &SOURCE_PRIMARY_STATUS_SURFACE_MARKERS),
        official_status_host_hits: 0,
        secondary_coverage_hits: marker_hits(&lower, &SOURCE_SECONDARY_COVERAGE_MARKERS),
        documentation_surface_hits: 0,
        impact_hits: marker_hits(&lower, &SOURCE_IMPACT_MARKERS),
        mitigation_hits: marker_hits(&lower, &SOURCE_MITIGATION_MARKERS),
        timeline_hits: marker_hits(&lower, &SOURCE_TIMELINE_MARKERS),
        low_priority_hits: marker_hits(&lower, &SOURCE_LOW_PRIORITY_MARKERS),
    }
}

fn analyze_source_url_signals(url: &str) -> SourceUrlSignalProfile {
    let parsed = match Url::parse(url.trim()) {
        Ok(parsed) => parsed,
        Err(_) => return SourceUrlSignalProfile::default(),
    };
    let host = parsed
        .host_str()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let path = parsed.path().to_ascii_lowercase();

    if host.trim().is_empty() {
        return SourceUrlSignalProfile::default();
    }

    let mut official_status_host_hits = 0;
    if host.starts_with("status.")
        || host.contains(".status.")
        || host.starts_with("health.")
        || host.contains(".health.")
        || host.starts_with("trust.")
        || host.contains(".trust.")
    {
        official_status_host_hits += 2;
    }
    official_status_host_hits += marker_hits(&host, &SOURCE_OFFICIAL_STATUS_HOST_MARKERS);
    official_status_host_hits += marker_hits(&path, &SOURCE_OFFICIAL_STATUS_PATH_MARKERS);
    official_status_host_hits = official_status_host_hits.min(6);

    let mut secondary_aggregation_hits =
        marker_hits(&host, &SOURCE_SECONDARY_AGGREGATION_HOST_MARKERS)
            + marker_hits(&path, &SOURCE_SECONDARY_AGGREGATION_PATH_MARKERS);
    if official_status_host_hits > 0 && path.contains("/incidents") {
        secondary_aggregation_hits = secondary_aggregation_hits.saturating_sub(1);
    }
    secondary_aggregation_hits = secondary_aggregation_hits.min(4);

    let documentation_surface_hits =
        (marker_hits(&host, &SOURCE_DOCUMENTATION_SURFACE_HOST_MARKERS)
            + marker_hits(&path, &SOURCE_DOCUMENTATION_SURFACE_PATH_MARKERS))
        .min(4);

    SourceUrlSignalProfile {
        official_status_host_hits,
        secondary_aggregation_hits,
        documentation_surface_hits,
    }
}

pub fn analyze_source_record_signals(url: &str, title: &str, excerpt: &str) -> SourceSignalProfile {
    let normalized_url = url.trim().to_ascii_lowercase();
    let combined = format!("{} {} {}", title, excerpt, normalized_url);
    let mut profile = analyze_source_text_signals(&combined);
    let url_profile = analyze_source_url_signals(url);

    profile.provenance_hits = profile
        .provenance_hits
        .saturating_add(url_profile.official_status_host_hits.min(2));
    profile.primary_status_surface_hits = profile
        .primary_status_surface_hits
        .saturating_add(url_profile.official_status_host_hits);
    profile.official_status_host_hits = url_profile.official_status_host_hits;
    profile.secondary_coverage_hits = profile
        .secondary_coverage_hits
        .saturating_add(url_profile.secondary_aggregation_hits);
    profile.documentation_surface_hits = url_profile.documentation_surface_hits;
    profile.low_priority_hits = profile
        .low_priority_hits
        .saturating_add(url_profile.documentation_surface_hits);

    profile
}

pub fn is_browser_surface(app_name: &str, title: &str) -> bool {
    let app_lc = app_name.to_ascii_lowercase();
    let title_lc = title.to_ascii_lowercase();

    BROWSER_SURFACE_MARKERS
        .iter()
        .any(|marker| app_lc.contains(marker) || title_lc.contains(marker))
}

pub fn is_system_surface(app_name: &str, title: &str) -> bool {
    let app_lc = app_name.to_ascii_lowercase();
    let title_lc = title.to_ascii_lowercase();

    SYSTEM_SURFACE_MARKERS
        .iter()
        .any(|marker| app_lc.contains(marker) || title_lc.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::{
        analyze_goal_signals, analyze_metric_schema, analyze_query_facets,
        analyze_source_record_signals, analyze_source_text_signals, infer_interaction_target,
        infer_report_sections, is_live_external_research_goal, is_mail_connector_tool_name,
        is_mailbox_connector_intent, query_semantic_anchor_tokens,
        query_structural_directive_tokens, report_section_label, GoalSignalProfile, MetricAxis,
        ReportSectionKind,
    };

    #[test]
    fn live_external_research_signal_ignores_workspace_local_prompts() {
        assert!(is_live_external_research_goal(
            "As of now (UTC), summarize active provider incidents with citations"
        ));
        assert!(!is_live_external_research_goal(
            "As of now, search this repository for incident handler changes and cite files"
        ));
    }

    #[test]
    fn infers_interaction_target_from_launch_goal() {
        let target = infer_interaction_target("Launch Visual Studio Code and open this folder")
            .expect("target should be inferred");
        assert_eq!(target.app_hint.as_deref(), Some("code"));
    }

    #[test]
    fn infers_report_sections_from_query_signals() {
        let sections = infer_report_sections(
            "top incidents, what changed in last hour, user impact, workaround, eta confidence, citations",
        );
        assert!(sections.contains(&ReportSectionKind::Summary));
        assert!(sections.contains(&ReportSectionKind::RecentChange));
        assert!(sections.contains(&ReportSectionKind::UserImpact));
        assert!(sections.contains(&ReportSectionKind::Mitigation));
        assert!(sections.contains(&ReportSectionKind::EtaConfidence));
        assert!(sections.contains(&ReportSectionKind::Evidence));
        assert_eq!(
            report_section_label(ReportSectionKind::RecentChange, "what changed in last hour"),
            "What changed in the last hour"
        );
        assert_eq!(
            report_section_label(ReportSectionKind::RecentChange, "include last-hour change"),
            "What changed in the last hour"
        );
    }

    #[test]
    fn source_signals_rank_operational_updates_above_roundups() {
        let status = analyze_source_text_signals(
            "Provider status page: investigating API outage, mitigation in progress, next update in 30 minutes.",
        );
        let roundup = analyze_source_text_signals("Weekly roundup and opinion analysis.");
        assert!(status.relevance_score(false) > roundup.relevance_score(false));
        assert!(roundup.low_priority_dominates());
    }

    #[test]
    fn source_signals_prefer_primary_status_surface_over_secondary_aggregation() {
        let primary = analyze_source_record_signals(
            "https://status.vendor-a.com/incidents/12345",
            "Service health incident",
            "Investigating elevated API errors; next update in 30 minutes.",
        );
        let secondary = analyze_source_record_signals(
            "https://example-monitor.com/cloud/incidents",
            "Cloud status page aggregator",
            "Track incidents across providers with community outage reports.",
        );
        assert!(primary.primary_status_surface_hits > 0);
        assert!(primary.official_status_host_hits > 0);
        assert!(secondary.secondary_coverage_hits > 0);
        assert!(primary.relevance_score(false) > secondary.relevance_score(false));
    }

    #[test]
    fn source_signals_demote_documentation_surface_vs_operational_status_host() {
        let status_host = analyze_source_record_signals(
            "https://status.vendor-a.com/incidents/12345",
            "Provider status incident",
            "Investigating elevated API errors with mitigation in progress.",
        );
        let docs_surface = analyze_source_record_signals(
            "https://learn.vendor-a.com/service-health/overview",
            "Service health overview",
            "Documentation overview for service health capabilities and guidance.",
        );

        assert!(status_host.official_status_host_hits > docs_surface.official_status_host_hits);
        assert!(docs_surface.documentation_surface_hits > 0);
        assert!(status_host.relevance_score(false) > docs_surface.relevance_score(false));
    }

    #[test]
    fn goal_profile_handles_empty_input() {
        assert_eq!(analyze_goal_signals(""), GoalSignalProfile::default());
    }

    #[test]
    fn mailbox_connector_signal_detects_personal_mailbox_intent() {
        assert!(is_mailbox_connector_intent(
            "Read me the latest email in my inbox"
        ));
        assert!(!is_live_external_research_goal(
            "Read me the latest email in my inbox"
        ));
    }

    #[test]
    fn mailbox_connector_signal_ignores_general_web_queries() {
        assert!(!is_mailbox_connector_intent(
            "Find the latest cloud outage updates with citations"
        ));
        assert!(is_live_external_research_goal(
            "Find the latest cloud outage updates with citations"
        ));
    }

    #[test]
    fn live_external_research_detects_time_sensitive_public_fact_lookups() {
        assert!(is_live_external_research_goal(
            "What's the weather right now in Anderson, SC?"
        ));
        assert!(is_live_external_research_goal(
            "Current USD to EUR exchange rate right now."
        ));
        assert!(!is_live_external_research_goal(
            "In this repository, what's the current weather parser logic?"
        ));
    }

    #[test]
    fn mailbox_tool_name_signal_matches_connector_prefixes() {
        assert!(is_mail_connector_tool_name(
            "wallet_network__mail_read_latest"
        ));
        assert!(is_mail_connector_tool_name("wallet_mail_handle_intent"));
        assert!(!is_mail_connector_tool_name("web__search"));
    }

    #[test]
    fn metric_schema_distinguishes_current_observation_from_forecast_horizon() {
        let current = analyze_metric_schema(
            "Current conditions as of 10:35 AM: temperature 62F, humidity 42%, wind 4 mph.",
        );
        let forecast =
            analyze_metric_schema("Tomorrow forecast: high 65, low 49, rain chance 60%.");
        assert!(current.has_metric_payload());
        assert!(current.has_current_observation_payload());
        assert!(forecast.has_metric_payload());
        assert!(!forecast.has_current_observation_payload());
        assert!(current.axis_hits.contains(&MetricAxis::Temperature));
        assert!(current.axis_hits.contains(&MetricAxis::Humidity));
        assert!(forecast.axis_hits.contains(&MetricAxis::Precipitation));
    }

    #[test]
    fn query_facets_capture_time_sensitive_public_fact_contract() {
        let facets = analyze_query_facets("What's the weather right now with UTC timestamp?");
        assert!(facets.time_sensitive_public_fact);
        assert!(facets.locality_sensitive_public_fact);
        assert!(facets.grounded_external_required);
        assert!(!facets.workspace_constrained);

        let rate_facets =
            analyze_query_facets("Current USD to EUR exchange rate right now with sources.");
        assert!(rate_facets.time_sensitive_public_fact);
        assert!(!rate_facets.locality_sensitive_public_fact);
    }

    #[test]
    fn semantic_anchor_tokens_exclude_structural_directives() {
        let query = "Current weather in Anderson, SC right now with sources and UTC timestamp.";
        let structural = query_structural_directive_tokens(query);
        assert!(structural.contains("sources"));
        assert!(structural.contains("utc"));
        assert!(structural.contains("timestamp"));

        let semantic = query_semantic_anchor_tokens(query);
        assert!(semantic.contains("weather"));
        assert!(semantic.contains("anderson"));
        assert!(!semantic.contains("sources"));
        assert!(!semantic.contains("utc"));
        assert!(!semantic.contains("timestamp"));
    }
}
