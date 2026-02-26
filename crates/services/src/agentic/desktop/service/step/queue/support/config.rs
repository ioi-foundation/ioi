//! Queue web-pipeline configuration and policy constants.
pub(crate) const MAX_SEARCH_EXTRACT_CHARS: usize = 8_000;
pub(crate) const QUEUE_TOOL_NAME_KEY: &str = "__ioi_tool_name";
pub(crate) const WEB_PIPELINE_EXCERPT_CHARS: usize = 220;
pub(crate) const WEB_PIPELINE_BUDGET_MS: u64 = 45_000;
pub(crate) const WEB_PIPELINE_DEFAULT_MIN_SOURCES: u32 = 1;
pub(crate) const WEB_PIPELINE_SEARCH_LIMIT: u32 = 10;
pub(crate) const WEB_PIPELINE_REQUIRED_STORIES: usize = 3;
pub(crate) const WEB_PIPELINE_CITATIONS_PER_STORY: usize = 2;
pub(crate) const WEIGHTED_INSIGHT_SIGNAL_VERSION: &str = "weighted_insight_v1";
pub(crate) const WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MIN: u32 = 4;
pub(crate) const WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX: u32 = 8;
pub(crate) const WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MULTIPLIER: u32 = 3;

pub(crate) const WEB_PIPELINE_STORY_TITLE_CHARS: usize = 140;
pub(crate) const WEB_PIPELINE_HYBRID_MAX_TOKENS: u32 = 1_200;
pub(crate) const WEB_PIPELINE_HYBRID_BUDGET_GUARD_MS: u64 = 45_000;
pub(crate) const WEB_PIPELINE_ACTIONABLE_EXCERPT_CHARS: usize = 140;
pub(crate) const WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_INITIAL_READ: u64 = 20_000;
pub(crate) const WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE: u64 = 20_000;
pub(crate) const WEB_PIPELINE_LATENCY_ELEVATED_BUFFER_MS: u64 = 6_000;
pub(crate) const WEB_PIPELINE_LATENCY_READ_GUARD_MS: u64 = 8_000;
pub(crate) const WEB_PIPELINE_LATENCY_PROBE_GUARD_MS: u64 = 10_000;
pub(crate) const CITATION_SOURCE_URL_MATCH_BONUS: usize = 1_000;
pub(crate) const CITATION_PRIMARY_STATUS_BONUS: usize = 16;
pub(crate) const CITATION_OFFICIAL_STATUS_HOST_BONUS: usize = 24;
pub(crate) const CITATION_SECONDARY_COVERAGE_PENALTY: usize = 8;
pub(crate) const CITATION_DOCUMENTATION_SURFACE_PENALTY: usize = 10;
pub(crate) const SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES: usize = 1;
pub(crate) const SINGLE_SNAPSHOT_MAX_EXPLORATORY_READS_WITHOUT_COMPATIBILITY: usize = 2;
pub(crate) const SINGLE_SNAPSHOT_MIN_REMAINING_BUDGET_MS_FOR_PROBE: u64 = 35_000;
pub(crate) const QUERY_COMPATIBILITY_MIN_TOKEN_CHARS: usize = 3;
pub(crate) const QUERY_COMPATIBILITY_MIN_ANCHOR_OVERLAP: usize = 1;
pub(crate) const QUERY_COMPATIBILITY_MIN_GROUNDED_MULTI_ANCHOR_OVERLAP: usize = 2;
pub(crate) const QUERY_COMPATIBILITY_STRONG_COVERAGE_NUMERATOR: usize = 1;
pub(crate) const QUERY_COMPATIBILITY_STRONG_COVERAGE_DENOMINATOR: usize = 3;
pub(crate) const QUERY_COMPATIBILITY_ANCHOR_WEIGHT: usize = 8;
pub(crate) const QUERY_COMPATIBILITY_NATIVE_ANCHOR_WEIGHT: usize = 12;
pub(crate) const QUERY_COMPATIBILITY_STRONG_COVERAGE_BONUS: usize = 10;
pub(crate) const QUERY_COMPATIBILITY_AXIS_OVERLAP_WEIGHT: usize = 10;
pub(crate) const QUERY_COMPATIBILITY_CURRENT_OBSERVATION_BONUS: usize = 8;
pub(crate) const QUERY_COMPATIBILITY_GROUNDED_EXTERNAL_BONUS: usize = 6;
pub(crate) const QUERY_COMPATIBILITY_SEARCH_HUB_PENALTY: usize = 24;
pub(crate) const QUERY_COMPATIBILITY_NO_RESOLVABLE_PAYLOAD_PENALTY: usize = 6;
pub(crate) const QUERY_COMPATIBILITY_LOCALITY_OVERLAP_WEIGHT: usize = 14;
pub(crate) const QUERY_COMPATIBILITY_MIN_LOCALITY_OVERLAP: usize = 1;
pub(crate) const TIME_SENSITIVE_RESOLVABLE_SURFACE_MIN_AXIS: usize = 2;
pub(crate) const QUERY_PROBE_HINT_MAX_CANDIDATES: usize = 4;
pub(crate) const QUERY_PROBE_HINT_MAX_TOKENS: usize = 3;
pub(crate) const QUERY_PROBE_HINT_MIN_SHARED_TOKEN_HITS: usize = 2;
pub(crate) const QUERY_PROBE_ESCALATION_MAX_CONFLICT_TERMS: usize = 3;
pub(crate) const QUERY_PROBE_ESCALATION_MIN_CONFLICT_HITS: usize = 1;
pub(crate) const QUERY_PROBE_ESCALATION_MAX_HOST_EXCLUSION_TERMS: usize = 2;
pub(crate) const QUERY_PROBE_LOCALITY_METRIC_ESCALATION_PHRASE: &str = "current conditions";
pub(crate) const ACTIONABLE_EXCERPT_MIN_SCORE: usize = 4;
pub(crate) const ACTIONABLE_EXCERPT_SEGMENT_MIN_CHARS: usize = 28;
pub(crate) const ACTIONABLE_EXCERPT_CLAIM_BASE_BONUS: usize = 3;
pub(crate) const INFERRED_SCOPE_FALLBACK_CANDIDATE_COUNT: usize = 2;
pub(crate) const TIME_SENSITIVE_RESOLUTION_MIN_FACET_NUMERATOR: usize = 1;
pub(crate) const TIME_SENSITIVE_RESOLUTION_MIN_FACET_DENOMINATOR: usize = 2;
pub(crate) const LOCALITY_SCOPE_MAX_CHARS: usize = 96;
pub(crate) const LOCALITY_SCOPE_TOKEN_MAX_CHARS: usize = 24;
pub(crate) const LOCALITY_INFERENCE_MIN_SUPPORT: usize = 2;
pub(crate) const LOCALITY_INFERENCE_MAX_TOKENS: usize = 4;
pub(crate) const QUERY_COMPATIBILITY_STOPWORDS: [&str; 50] = [
    "a",
    "an",
    "the",
    "and",
    "or",
    "to",
    "of",
    "for",
    "with",
    "in",
    "on",
    "at",
    "by",
    "from",
    "into",
    "over",
    "under",
    "what",
    "whats",
    "is",
    "are",
    "was",
    "were",
    "right",
    "now",
    "top",
    "active",
    "current",
    "currently",
    "like",
    "latest",
    "today",
    "change",
    "changed",
    "give",
    "include",
    "including",
    "each",
    "confidence",
    "eta",
    "user",
    "users",
    "last",
    "hour",
    "major",
    "page",
    "pages",
    "impact",
    "impacting",
    "relevant",
];
pub(crate) const LOCALITY_SCOPE_NOISE_TOKENS: [&str; 21] = [
    "http", "https", "www", "com", "org", "net", "news", "google", "search", "query", "update",
    "source", "sources", "rss", "article", "articles", "read", "feed", "story", "stories", "oc",
];
pub(crate) const TRUSTED_LOCALITY_ENV_KEYS: [&str; 8] = [
    "IOI_SESSION_LOCALITY",
    "IOI_DEVICE_LOCALITY",
    "IOI_USER_LOCALITY",
    "IOI_LOCALITY",
    "SESSION_LOCALITY",
    "DEVICE_LOCALITY",
    "USER_LOCALITY",
    "LOCALITY",
];
