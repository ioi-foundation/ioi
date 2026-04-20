#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TerminalChatReplyLayoutProfile {
    SingleSnapshot,
    DocumentBriefing,
    StoryCollection,
    Other,
}

impl TerminalChatReplyLayoutProfile {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::SingleSnapshot => "single_snapshot",
            Self::DocumentBriefing => "document_briefing",
            Self::StoryCollection => "story_collection",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct TerminalChatReplyShapeFacts {
    pub heading_present: bool,
    pub single_snapshot_heading_present: bool,
    pub story_header_count: usize,
    pub comparison_label_count: usize,
    pub run_date_present: bool,
    pub run_timestamp_present: bool,
    pub overall_confidence_present: bool,
}

pub(super) fn observe_terminal_chat_reply_shape(summary: &str) -> TerminalChatReplyShapeFacts {
    let lines = summary
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let heading_present = lines.first().is_some_and(|line| {
        line.starts_with("Briefing for '") || line.starts_with("Web briefing (as of ")
    });
    let single_snapshot_heading_present = lines.first().is_some_and(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("right now") && lower.contains("as of ")
    });
    let story_header_count = lines
        .iter()
        .filter(|line| {
            line.strip_prefix("Story ")
                .and_then(|rest| rest.split_once(':'))
                .is_some()
        })
        .count();
    let comparison_label_count = lines
        .iter()
        .filter(|line| line.eq_ignore_ascii_case("Comparison:"))
        .count();
    let run_date_present = lines.iter().any(|line| {
        line.starts_with("Run date (UTC):") && !line["Run date (UTC):".len()..].trim().is_empty()
    });
    let run_timestamp_present = lines.iter().any(|line| {
        line.starts_with("Run timestamp (UTC):")
            && !line["Run timestamp (UTC):".len()..].trim().is_empty()
    });
    let overall_confidence_present = lines.iter().any(|line| {
        line.starts_with("Overall confidence:")
            && !line["Overall confidence:".len()..].trim().is_empty()
    });

    TerminalChatReplyShapeFacts {
        heading_present,
        single_snapshot_heading_present,
        story_header_count,
        comparison_label_count,
        run_date_present,
        run_timestamp_present,
        overall_confidence_present,
    }
}

pub(super) fn is_absorbed_pending_web_read_gate(tool_name: &str, output: Option<&str>) -> bool {
    tool_name == "web__read"
        && output
            .map(|value| {
                value.starts_with("Recorded gated source in fixed payload (no approval retries): ")
            })
            .unwrap_or(false)
}

pub(super) fn terminal_chat_reply_layout_profile(
    facts: &TerminalChatReplyShapeFacts,
) -> TerminalChatReplyLayoutProfile {
    if facts.heading_present && facts.story_header_count == 0 && facts.comparison_label_count == 0 {
        return TerminalChatReplyLayoutProfile::DocumentBriefing;
    }
    if facts.story_header_count > 0 || facts.comparison_label_count > 0 {
        return TerminalChatReplyLayoutProfile::StoryCollection;
    }
    if facts.single_snapshot_heading_present {
        return TerminalChatReplyLayoutProfile::SingleSnapshot;
    }
    TerminalChatReplyLayoutProfile::Other
}

#[cfg(test)]
#[path = "terminal_reply/tests.rs"]
mod tests;
