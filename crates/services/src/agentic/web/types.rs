#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SearchBackendProfile {
    ConstraintGroundedTimeSensitive,
    ConstraintGroundedExternal,
    General,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SearchProviderStage {
    DdgHttp,
    DdgBrowser,
    BingHttp,
    GoogleHttp,
    GoogleNewsRss,
}
