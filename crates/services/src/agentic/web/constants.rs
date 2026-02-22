pub(crate) const BROWSER_RETRIEVAL_TIMEOUT_SECS: u64 = 8;
pub(crate) const HTTP_FALLBACK_TIMEOUT_SECS: u64 = 4;
pub(crate) const EDGE_WEB_SEARCH_TOTAL_BUDGET_MS: u64 = 14_000;
pub(crate) const READ_BLOCK_LOW_SIGNAL_CHAR_THRESHOLD: usize = 320;
pub(crate) const READ_BLOCK_SUPPLEMENTAL_MAX: usize = 40;
pub(crate) const READ_BLOCK_STRUCTURED_SCRIPT_MAX: usize = 12;
pub(crate) const READ_BLOCK_STRUCTURED_SCRIPT_TOKEN_LIMIT: usize = 3_000;
pub(crate) const READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_TOKENS: usize = 36;
pub(crate) const READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_STEP: usize = 12;
pub(crate) const READ_BLOCK_STRUCTURED_SCRIPT_MAX_SCRIPT_CHARS: usize = 40_000;
pub(crate) const READ_BLOCK_STRUCTURED_SCRIPT_MIN_SCORE: usize = 6;
pub(crate) const SEARCH_ANCHOR_MIN_TOKEN_CHARS: usize = 3;
pub(crate) const SEARCH_ANCHOR_REQUIRED_OVERLAP_RATIO_DENOMINATOR: usize = 3;
pub(crate) const SEARCH_ANCHOR_REQUIRED_OVERLAP_CAP: usize = 4;
pub(crate) const SEARCH_ANCHOR_GROUNDED_MIN_OVERLAP: usize = 2;
pub(crate) const SEARCH_ANCHOR_TIME_SENSITIVE_MIN_OVERLAP: usize = 2;
pub(crate) const SEARCH_ANCHOR_LOCALITY_MIN_OVERLAP: usize = 1;
pub(crate) const SEARCH_ANCHOR_SEMANTIC_MIN_OVERLAP: usize = 1;
pub(crate) const SEARCH_ANCHOR_STOPWORDS: [&str; 30] = [
    "a", "an", "the", "and", "or", "to", "of", "for", "with", "in", "on", "at", "by", "from",
    "into", "over", "under", "near", "around", "what", "whats", "is", "are", "was", "were",
    "right", "now", "current", "latest", "today",
];
pub(crate) const QUERY_SCOPE_MARKERS: [&str; 4] = [" in ", " near ", " around ", " at "];
