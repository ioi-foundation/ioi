use super::util::{marker_hits, normalize_marker_text};
use crate::agentic::desktop::types::InteractionTarget;
use std::collections::BTreeSet;

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

fn canonical_tool_name(root_tool_name: &str) -> String {
    root_tool_name
        .trim()
        .to_ascii_lowercase()
        .replace("::", "__")
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

pub(crate) fn provenance_marker_hits(text: &str) -> usize {
    marker_hits(text, &PROVENANCE_MARKERS)
}
