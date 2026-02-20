use crate::agentic::desktop::types::InteractionTarget;
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

const PROVENANCE_MARKERS: [&str; 16] = [
    "citation",
    "citations",
    "source",
    "sources",
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

        (has_live_grounding_request && has_external_surface)
            || (has_external_surface && has_provenance_pressure)
    }

    pub fn prefers_mailbox_connector_flow(&self) -> bool {
        let has_mailbox_domain = self.mailbox_domain_hits > 0;
        let has_personal_anchor = self.mailbox_personal_scope_hits > 0;
        let has_mailbox_action = self.mailbox_action_hits > 0;
        has_mailbox_domain && (has_personal_anchor || has_mailbox_action)
    }
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
        analyze_goal_signals, analyze_source_record_signals, analyze_source_text_signals,
        infer_interaction_target, infer_report_sections, is_live_external_research_goal,
        is_mail_connector_tool_name, is_mailbox_connector_intent, report_section_label,
        GoalSignalProfile, ReportSectionKind,
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
    fn mailbox_tool_name_signal_matches_connector_prefixes() {
        assert!(is_mail_connector_tool_name(
            "wallet_network__mail_read_latest"
        ));
        assert!(is_mail_connector_tool_name("wallet_mail_handle_intent"));
        assert!(!is_mail_connector_tool_name("web__search"));
    }
}
