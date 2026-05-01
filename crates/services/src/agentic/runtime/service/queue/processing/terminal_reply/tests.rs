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
