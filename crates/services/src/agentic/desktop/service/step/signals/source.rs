use super::util::marker_hits;
use url::Url;

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
