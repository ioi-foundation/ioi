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
mod tests {
    use super::{
        observe_terminal_chat_reply_shape, terminal_chat_reply_layout_profile,
        TerminalChatReplyLayoutProfile,
    };

    #[test]
    fn terminal_chat_reply_shape_detects_story_collection_output() {
        let output = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nComparison:\nExample.\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: high";
        let facts = observe_terminal_chat_reply_shape(output);

        assert!(!facts.heading_present);
        assert_eq!(facts.story_header_count, 1);
        assert_eq!(facts.comparison_label_count, 1);
        assert_eq!(
            terminal_chat_reply_layout_profile(&facts),
            TerminalChatReplyLayoutProfile::StoryCollection
        );
    }

    #[test]
    fn terminal_chat_reply_shape_detects_document_briefing_output() {
        let output = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nWhat happened:\n- NIST finalized FIPS 203, FIPS 204, and FIPS 205.\n\nKey evidence:\n- NIST states the standards are mandatory for federal systems.\n\nCitations:\n- Post-quantum cryptography | NIST | https://www.nist.gov/pqc | 2026-03-10T12:19:24Z | retrieved_utc\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: high";
        let facts = observe_terminal_chat_reply_shape(output);

        assert!(facts.heading_present);
        assert_eq!(facts.story_header_count, 0);
        assert_eq!(facts.comparison_label_count, 0);
        assert!(facts.run_date_present);
        assert!(facts.run_timestamp_present);
        assert!(facts.overall_confidence_present);
        assert_eq!(
            terminal_chat_reply_layout_profile(&facts),
            TerminalChatReplyLayoutProfile::DocumentBriefing
        );
    }

    #[test]
    fn terminal_chat_reply_shape_detects_single_snapshot_output() {
        let output = "Right now (as of 2026-03-11T13:42:57Z UTC):\n\nCurrent conditions from cited source text: Bitcoin price right now: $86,743.63 USD.\n\nCitations:\n- Bitcoin price | index, chart and news | WorldCoinIndex | https://www.worldcoinindex.com/coin/bitcoin | 2026-03-11T13:42:57Z | retrieved_utc\n\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T13:42:57Z\nOverall confidence: high";
        let facts = observe_terminal_chat_reply_shape(output);

        assert!(!facts.heading_present);
        assert!(facts.single_snapshot_heading_present);
        assert_eq!(facts.story_header_count, 0);
        assert_eq!(facts.comparison_label_count, 0);
        assert!(facts.run_date_present);
        assert!(facts.run_timestamp_present);
        assert!(facts.overall_confidence_present);
        assert_eq!(
            terminal_chat_reply_layout_profile(&facts),
            TerminalChatReplyLayoutProfile::SingleSnapshot
        );
    }
}
