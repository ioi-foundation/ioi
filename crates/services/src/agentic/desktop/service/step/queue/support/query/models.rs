use super::*;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PreReadCandidatePlan {
    pub candidate_urls: Vec<String>,
    pub candidate_source_hints: Vec<PendingSearchReadSummary>,
    pub probe_source_hints: Vec<PendingSearchReadSummary>,
    pub total_candidates: usize,
    pub pruned_candidates: usize,
    pub resolvable_candidates: usize,
    pub scoreable_candidates: usize,
    pub requires_constraint_search_probe: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebPipelineCompletionReason {
    MinSourcesReached,
    ExhaustedCandidates,
    DeadlineReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebPipelineLatencyPressure {
    Nominal,
    Elevated,
    Critical,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CandidateConstraintCompatibility {
    pub(crate) compatibility_score: usize,
    pub(crate) is_compatible: bool,
    pub(crate) locality_compatible: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct QueryConstraintProjection {
    pub(crate) constraints: ConstraintSet,
    pub(crate) query_facets: QueryFacetProfile,
    pub(crate) query_native_tokens: BTreeSet<String>,
    pub(crate) query_native_tokens_ordered: Vec<String>,
    pub(crate) query_tokens: BTreeSet<String>,
    pub(crate) locality_scope: Option<String>,
    pub(crate) locality_scope_inferred: bool,
    pub(crate) locality_tokens: BTreeSet<String>,
}

impl QueryConstraintProjection {
    pub(crate) fn enforce_grounded_compatibility(&self) -> bool {
        self.constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            || (self.query_facets.grounded_external_required
                && !self.query_native_tokens.is_empty())
    }

    pub(crate) fn strict_grounded_compatibility(&self) -> bool {
        self.constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            && self.enforce_grounded_compatibility()
            && !self.locality_scope_inferred
            && self.query_native_tokens.len()
                >= QUERY_COMPATIBILITY_MIN_GROUNDED_MULTI_ANCHOR_OVERLAP
    }

    pub(crate) fn has_constraint_objective(&self) -> bool {
        self.constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            || self.query_facets.grounded_external_required
            || !self.constraints.required_facets.is_empty()
            || !self.query_tokens.is_empty()
    }

    pub(crate) fn reject_search_hub_candidates(&self) -> bool {
        self.constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            || self.query_facets.grounded_external_required
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RankedAcquisitionCandidate {
    pub(crate) idx: usize,
    pub(crate) hint: PendingSearchReadSummary,
    pub(crate) envelope_score: CandidateEvidenceScore,
    pub(crate) resolves_constraint: bool,
    pub(crate) time_sensitive_resolvable_payload: bool,
    pub(crate) compatibility: CandidateConstraintCompatibility,
    pub(crate) source_relevance_score: usize,
    pub(crate) headline_low_quality: bool,
    pub(crate) headline_actionable: bool,
}
