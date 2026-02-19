use super::support::{
    append_pending_web_success_fallback, candidate_source_hints_from_bundle,
    candidate_urls_from_bundle, fallback_search_summary, queue_action_request_to_tool,
    summarize_search_results, synthesize_web_pipeline_reply, web_pipeline_completion_reason,
    WebPipelineCompletionReason,
};
use crate::agentic::desktop::types::PendingSearchCompletion;
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use ioi_types::app::agentic::{WebEvidenceBundle, WebSource};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use std::collections::BTreeSet;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn build_request(target: ActionTarget, nonce: u64, args: serde_json::Value) -> ActionRequest {
    ActionRequest {
        target,
        params: serde_json::to_vec(&args).expect("params should serialize"),
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce,
    }
}

fn build_fs_read_request(args: serde_json::Value) -> ActionRequest {
    build_request(ActionTarget::FsRead, 7, args)
}

fn build_fs_write_request(args: serde_json::Value) -> ActionRequest {
    build_request(ActionTarget::FsWrite, 11, args)
}

fn build_custom_request(name: &str, nonce: u64, args: serde_json::Value) -> ActionRequest {
    build_request(ActionTarget::Custom(name.to_string()), nonce, args)
}

fn build_sys_exec_request(args: serde_json::Value) -> ActionRequest {
    build_request(ActionTarget::SysExec, 13, args)
}

fn extract_urls(text: &str) -> BTreeSet<String> {
    text.split_whitespace()
        .filter_map(|token| {
            let trimmed = token
                .trim_matches(|ch: char| ",.;:!?()[]{}\"'|".contains(ch))
                .trim();
            if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn extract_story_titles(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.strip_prefix("Story "))
        .map(|line| {
            line.split_once(':')
                .map(|(_, title)| title.trim().to_string())
                .expect("story lines should contain ':' separators")
        })
        .collect()
}

#[test]
fn summary_contains_topic_and_refinement_hint() {
    let summary = summarize_search_results(
        "internet of intelligence",
        "https://duckduckgo.com/?q=internet+of+intelligence",
        "<html><body><a href=\"https://example.com/a\">A</a>\nThe Internet of Intelligence explores decentralized agent coordination.\nOpen protocols enable verifiable execution and policy enforcement.</body></html>",
    );
    assert!(summary.contains("Search summary for 'internet of intelligence'"));
    assert!(summary.contains("Source URL: https://duckduckgo.com/?q=internet+of+intelligence"));
    assert!(summary.contains("Next refinement:"));
}

#[test]
fn fallback_summary_is_deterministic() {
    let msg = fallback_search_summary(
        "internet of intelligence",
        "https://duckduckgo.com/?q=internet+of+intelligence",
    );
    assert_eq!(
        msg,
        "Searched 'internet of intelligence' at https://duckduckgo.com/?q=internet+of+intelligence, but structured extraction failed. Retry refinement if needed."
    );
}

#[test]
fn web_pipeline_candidate_urls_preserve_rank_order() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("latest news".to_string()),
        url: Some("https://duckduckgo.com/?q=latest+news".to_string()),
        sources: vec![
            WebSource {
                source_id: "b".to_string(),
                rank: Some(2),
                url: "https://b.example.com".to_string(),
                title: Some("B".to_string()),
                snippet: None,
                domain: Some("b.example.com".to_string()),
            },
            WebSource {
                source_id: "a".to_string(),
                rank: Some(1),
                url: "https://a.example.com".to_string(),
                title: Some("A".to_string()),
                snippet: None,
                domain: Some("a.example.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let urls = candidate_urls_from_bundle(&bundle);
    assert_eq!(
        urls,
        vec![
            "https://a.example.com".to_string(),
            "https://b.example.com".to_string()
        ]
    );
}

#[test]
fn web_pipeline_source_hints_preserve_rank_order() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("latest news".to_string()),
        url: Some("https://duckduckgo.com/?q=latest+news".to_string()),
        sources: vec![
            WebSource {
                source_id: "b".to_string(),
                rank: Some(2),
                url: "https://b.example.com".to_string(),
                title: Some("Headline B".to_string()),
                snippet: Some("Summary B".to_string()),
                domain: Some("b.example.com".to_string()),
            },
            WebSource {
                source_id: "a".to_string(),
                rank: Some(1),
                url: "https://a.example.com".to_string(),
                title: Some("Headline A".to_string()),
                snippet: Some("Summary A".to_string()),
                domain: Some("a.example.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let hints = candidate_source_hints_from_bundle(&bundle);
    assert_eq!(hints.len(), 2);
    assert_eq!(hints[0].url, "https://a.example.com");
    assert_eq!(hints[0].title.as_deref(), Some("Headline A"));
    assert_eq!(hints[1].url, "https://b.example.com");
    assert_eq!(hints[1].title.as_deref(), Some("Headline B"));
}

#[test]
fn web_pipeline_uses_source_hints_when_read_output_is_low_signal() {
    let mut pending = PendingSearchCompletion {
        query: "latest breaking news".to_string(),
        url: "https://news.google.com/rss/search?q=latest+breaking+news".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec!["https://news.google.com/rss/articles/abc".to_string()],
        candidate_source_hints: vec![crate::agentic::desktop::types::PendingSearchReadSummary {
            url: "https://news.google.com/rss/articles/abc".to_string(),
            title: Some("Major storm causes widespread flight delays".to_string()),
            excerpt: "Airports across the U.S. reported cancellations and delays overnight."
                .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 1,
    };

    append_pending_web_success_fallback(
        &mut pending,
        "https://news.google.com/rss/articles/abc",
        Some("Google News"),
    );
    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(reply.contains("Major storm causes widespread flight delays"));
    assert!(reply.contains("Airports across the U.S."));
}

#[test]
fn web_pipeline_completion_deadline_produces_partial_low_confidence() {
    let pending = PendingSearchCompletion {
        query: "latest news".to_string(),
        url: "https://duckduckgo.com/?q=latest+news".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 160,
        candidate_urls: vec!["https://a.example.com".to_string()],
        candidate_source_hints: vec![],
        attempted_urls: vec!["https://a.example.com".to_string()],
        blocked_urls: vec!["https://blocked.example.com".to_string()],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 200)
        .expect("deadline should produce completion reason");
    assert_eq!(reason, WebPipelineCompletionReason::DeadlineReached);

    let reply = synthesize_web_pipeline_reply(&pending, reason);
    assert!(reply.contains("Partial evidence"));
    assert!(reply.contains("Blocked sources requiring human challenge"));
    assert!(reply.contains("Run date (UTC): "));
    assert!(reply.contains("Run timestamp (UTC): "));
    assert!(reply.contains("Overall confidence: low"));
}

#[test]
fn web_pipeline_reply_enforces_three_story_structure_with_citations_and_timestamps() {
    let pending = PendingSearchCompletion {
        query: "As of now (UTC), what are the top 3 U.S. breaking stories from the last 6 hours?"
            .to_string(),
        url: "https://duckduckgo.com/?q=us+breaking+news".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://a.example.com/story-1".to_string(),
            "https://b.example.com/story-2".to_string(),
            "https://c.example.com/story-3".to_string(),
            "https://d.example.com/story-4".to_string(),
            "https://e.example.com/story-5".to_string(),
            "https://f.example.com/story-6".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://a.example.com/story-1".to_string(),
                title: Some("Federal agency issues emergency advisory".to_string()),
                excerpt: "Officials confirmed a rapidly developing advisory affecting multiple U.S. states.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://b.example.com/story-2".to_string(),
                title: Some("Court hearing drives immediate policy response".to_string()),
                excerpt: "A late-day hearing prompted new guidance and federal statements.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://c.example.com/story-3".to_string(),
                title: Some("Major weather disruption impacts transit corridors".to_string()),
                excerpt: "Flight and rail schedules changed as severe weather moved east.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://d.example.com/story-4".to_string(),
                title: Some("Market reaction follows latest federal filing".to_string()),
                excerpt: "Risk assets and yields moved after publication of new documents.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(reply.contains("Story 1:"));
    assert!(reply.contains("Story 2:"));
    assert!(reply.contains("Story 3:"));
    assert_eq!(reply.matches("What happened:").count(), 3);
    assert_eq!(reply.matches("What changed in the last hour:").count(), 3);
    assert_eq!(reply.matches("Why it matters:").count(), 3);
    assert_eq!(reply.matches("Citations:").count(), 3);
    assert!(reply.contains("T") && reply.contains("Z"));
    let urls = extract_urls(&reply);
    assert!(
        urls.len() >= 6,
        "expected >= 6 distinct urls, got {}",
        urls.len()
    );
}

#[test]
fn web_pipeline_dedupes_near_duplicate_story_titles() {
    let pending = PendingSearchCompletion {
        query: "top breaking stories".to_string(),
        url: "https://duckduckgo.com/?q=top+breaking+stories".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://news1.example.com/a".to_string(),
            "https://news2.example.com/b".to_string(),
            "https://news3.example.com/c".to_string(),
            "https://news4.example.com/d".to_string(),
            "https://news5.example.com/e".to_string(),
            "https://news6.example.com/f".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news1.example.com/a".to_string(),
                title: Some("Senate passes emergency funding package".to_string()),
                excerpt: "An emergency package advanced after a late-session vote.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news2.example.com/b".to_string(),
                title: Some("Emergency funding package passes in Senate vote".to_string()),
                excerpt: "Lawmakers approved stopgap funding in an overnight session.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news3.example.com/c".to_string(),
                title: Some("Wildfire response expands across western states".to_string()),
                excerpt: "Federal and state teams expanded response coverage overnight."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news4.example.com/d".to_string(),
                title: Some("DOJ files updated brief in high-profile case".to_string()),
                excerpt: "New filings add detail to the government legal position.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let story_titles = extract_story_titles(&reply);
    let unique_titles = story_titles.iter().collect::<BTreeSet<_>>();
    assert_eq!(unique_titles.len(), story_titles.len());
}

#[test]
fn web_pipeline_deprioritizes_news_about_news_when_event_stories_exist() {
    let pending = PendingSearchCompletion {
        query: "top US breaking news last 6 hours".to_string(),
        url: "https://news.google.com/rss/search?q=top+US+breaking+news+last+6+hours".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://news.google.com/rss/articles/a".to_string(),
            "https://news.google.com/rss/articles/b".to_string(),
            "https://news.google.com/rss/articles/c".to_string(),
            "https://news.google.com/rss/articles/d".to_string(),
            "https://news.google.com/rss/articles/e".to_string(),
            "https://news.google.com/rss/articles/f".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news.google.com/rss/articles/a".to_string(),
                title: Some(
                    "Top 50 US news websites: Minnesota Star Tribune traffic boosted by ICE coverage"
                        .to_string(),
                ),
                excerpt: "Press Gazette".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news.google.com/rss/articles/b".to_string(),
                title: Some("Social Media and News Fact Sheet - Pew Research Center".to_string()),
                excerpt: "Pew analysis of news habits.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news.google.com/rss/articles/c".to_string(),
                title: Some("Federal court issues emergency injunction in border case".to_string()),
                excerpt: "The order immediately changes enforcement guidance.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news.google.com/rss/articles/d".to_string(),
                title: Some("Severe storm system triggers evacuations across Gulf Coast".to_string()),
                excerpt: "State officials issued new evacuation zones in the last hour.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news.google.com/rss/articles/e".to_string(),
                title: Some("Senate advances emergency funding bill after late vote".to_string()),
                excerpt: "Leaders confirmed immediate procedural next steps.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let story_titles = extract_story_titles(&reply);
    assert_eq!(story_titles.len(), 3);
    let story_titles_lc = story_titles
        .iter()
        .map(|title| title.to_ascii_lowercase())
        .collect::<Vec<_>>();
    assert!(
        story_titles_lc
            .iter()
            .all(|title| !title.contains("news websites") && !title.contains("fact sheet")),
        "expected event-driven stories to outrank meta-news titles, got {:?}",
        story_titles
    );
}

#[test]
fn queue_maps_browser_click_element_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        21,
        serde_json::json!({
            "id": "btn_submit"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserClickElement { id } => {
            assert_eq!(id, "btn_submit");
        }
        other => panic!("expected BrowserClickElement, got {:?}", other),
    }
}

#[test]
fn queue_maps_net_fetch_target_to_typed_net_fetch_tool() {
    let request = build_request(
        ActionTarget::NetFetch,
        25,
        serde_json::json!({
            "url": "https://example.com",
            "max_chars": 123
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::NetFetch { url, max_chars } => {
            assert_eq!(url, "https://example.com");
            assert_eq!(max_chars, Some(123));
        }
        other => panic!("expected NetFetch, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_search_from_fsread_target() {
    let request = build_fs_read_request(serde_json::json!({
        "path": "/tmp/workspace",
        "regex": "TODO",
        "file_pattern": "*.rs"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsSearch {
            path,
            regex,
            file_pattern,
        } => {
            assert_eq!(path, "/tmp/workspace");
            assert_eq!(regex, "TODO");
            assert_eq!(file_pattern.as_deref(), Some("*.rs"));
        }
        other => panic!("expected FsSearch, got {:?}", other),
    }
}

#[test]
fn queue_infers_list_directory_for_existing_directory_path() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ioi_queue_fs_list_{}", unique));
    fs::create_dir_all(&dir).expect("temp directory should be created");
    let request = build_fs_read_request(serde_json::json!({
        "path": dir.to_string_lossy()
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsList { path } => {
            assert_eq!(path, dir.to_string_lossy());
        }
        other => panic!("expected FsList, got {:?}", other),
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn queue_uses_explicit_fsread_tool_name_override() {
    let request = build_fs_read_request(serde_json::json!({
        "path": "/tmp/not-a-real-directory",
        "__ioi_tool_name": "filesystem__list_directory"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsList { path } => {
            assert_eq!(path, "/tmp/not-a-real-directory");
        }
        other => panic!("expected FsList, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_fsread_tool_name_override_for_custom_alias_target() {
    let request = build_custom_request(
        "fs::read",
        8,
        serde_json::json!({
            "path": "/tmp/not-a-real-directory",
            "__ioi_tool_name": "filesystem__list_directory"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsList { path } => {
            assert_eq!(path, "/tmp/not-a-real-directory");
        }
        other => panic!("expected FsList, got {:?}", other),
    }
}

#[test]
fn queue_rejects_incompatible_explicit_tool_name_for_target() {
    let request = build_fs_read_request(serde_json::json!({
        "path": "/tmp/demo.txt",
        "__ioi_tool_name": "filesystem__write_file"
    }));

    let err = queue_action_request_to_tool(&request)
        .expect_err("queue mapping should fail for incompatible explicit tool name");
    assert!(err.to_string().contains("incompatible"));
}

#[test]
fn queue_rejects_ambiguous_fswrite_transfer_without_explicit_tool_name() {
    let request = build_fs_write_request(serde_json::json!({
        "source_path": "/tmp/source.txt",
        "destination_path": "/tmp/destination.txt"
    }));

    let err = queue_action_request_to_tool(&request)
        .expect_err("queue mapping should fail for ambiguous transfer without explicit tool name");
    assert!(err.to_string().contains("__ioi_tool_name"));
    assert!(err.to_string().contains("filesystem__copy_path"));
}

#[test]
fn queue_rejects_ambiguous_fswrite_transfer_without_explicit_tool_name_for_custom_alias_target() {
    let request = build_custom_request(
        "fs::write",
        9,
        serde_json::json!({
            "source_path": "/tmp/source.txt",
            "destination_path": "/tmp/destination.txt"
        }),
    );

    let err = queue_action_request_to_tool(&request)
        .expect_err("queue mapping should fail for ambiguous transfer without explicit tool name");
    assert!(err.to_string().contains("__ioi_tool_name"));
    assert!(err.to_string().contains("filesystem__move_path"));
}

#[test]
fn queue_defaults_to_read_file_when_not_search_or_directory() {
    let request = build_fs_read_request(serde_json::json!({
        "path": "/tmp/not-a-real-file.txt"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsRead { path } => {
            assert_eq!(path, "/tmp/not-a-real-file.txt");
        }
        other => panic!("expected FsRead, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_patch_from_fswrite_target() {
    let request = build_fs_write_request(serde_json::json!({
        "path": "/tmp/demo.txt",
        "search": "alpha",
        "replace": "beta"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsPatch {
            path,
            search,
            replace,
        } => {
            assert_eq!(path, "/tmp/demo.txt");
            assert_eq!(search, "alpha");
            assert_eq!(replace, "beta");
        }
        other => panic!("expected FsPatch, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_delete_from_fswrite_target() {
    let request = build_fs_write_request(serde_json::json!({
        "path": "/tmp/demo.txt",
        "recursive": false,
        "ignore_missing": true
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsDelete {
            path,
            recursive,
            ignore_missing,
        } => {
            assert_eq!(path, "/tmp/demo.txt");
            assert!(!recursive);
            assert!(ignore_missing);
        }
        other => panic!("expected FsDelete, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_delete_from_fswrite_target_when_recursive() {
    let request = build_fs_write_request(serde_json::json!({
        "path": "/tmp/demo-dir",
        "recursive": true,
        "ignore_missing": false
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsDelete {
            path,
            recursive,
            ignore_missing,
        } => {
            assert_eq!(path, "/tmp/demo-dir");
            assert!(recursive);
            assert!(!ignore_missing);
        }
        other => panic!("expected FsDelete, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_create_directory_from_fswrite_target() {
    let request = build_fs_write_request(serde_json::json!({
        "path": "/tmp/new-dir",
        "recursive": true
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsCreateDirectory { path, recursive } => {
            assert_eq!(path, "/tmp/new-dir");
            assert!(recursive);
        }
        other => panic!("expected FsCreateDirectory, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_fswrite_tool_name_override_for_copy_path() {
    let request = build_fs_write_request(serde_json::json!({
        "source_path": "/tmp/source.txt",
        "destination_path": "/tmp/destination.txt",
        "overwrite": true,
        "__ioi_tool_name": "filesystem__copy_path"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsCopy {
            source_path,
            destination_path,
            overwrite,
        } => {
            assert_eq!(source_path, "/tmp/source.txt");
            assert_eq!(destination_path, "/tmp/destination.txt");
            assert!(overwrite);
        }
        other => panic!("expected FsCopy, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_fswrite_tool_name_override_for_move_path() {
    let request = build_fs_write_request(serde_json::json!({
        "source_path": "/tmp/source.txt",
        "destination_path": "/tmp/destination.txt",
        "overwrite": false,
        "__ioi_tool_name": "filesystem__move_path"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsMove {
            source_path,
            destination_path,
            overwrite,
        } => {
            assert_eq!(source_path, "/tmp/source.txt");
            assert_eq!(destination_path, "/tmp/destination.txt");
            assert!(!overwrite);
        }
        other => panic!("expected FsMove, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_fswrite_tool_name_override_for_custom_alias_target() {
    let request = build_custom_request(
        "fs::write",
        17,
        serde_json::json!({
            "source_path": "/tmp/source.txt",
            "destination_path": "/tmp/destination.txt",
            "__ioi_tool_name": "filesystem__move_path"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsMove {
            source_path,
            destination_path,
            overwrite,
        } => {
            assert_eq!(source_path, "/tmp/source.txt");
            assert_eq!(destination_path, "/tmp/destination.txt");
            assert!(!overwrite);
        }
        other => panic!("expected FsMove, got {:?}", other),
    }
}

#[test]
fn queue_preserves_launch_app_for_sys_exec_target_with_app_name() {
    let request = build_sys_exec_request(serde_json::json!({
        "app_name": "calculator"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::OsLaunchApp { app_name } => {
            assert_eq!(app_name, "calculator");
        }
        other => panic!("expected OsLaunchApp, got {:?}", other),
    }
}

#[test]
fn queue_does_not_allow_metadata_override_for_sys_exec_target() {
    let request = build_sys_exec_request(serde_json::json!({
        "app_name": "calculator",
        "__ioi_tool_name": "os__launch_app"
    }));

    let err = queue_action_request_to_tool(&request).expect_err("expected schema error");
    assert!(err.to_string().contains("__ioi_tool_name"));
}

#[test]
fn queue_does_not_allow_metadata_to_override_non_fs_target_inference() {
    let request = build_sys_exec_request(serde_json::json!({
        "command": "echo",
        "args": ["ok"],
        "__ioi_tool_name": "os__launch_app"
    }));

    let err = queue_action_request_to_tool(&request).expect_err("expected schema error");
    assert!(err.to_string().contains("__ioi_tool_name"));
}

#[test]
fn queue_uses_explicit_sys_exec_tool_name_override_for_exec_session() {
    let request = build_sys_exec_request(serde_json::json!({
        "command": "echo",
        "args": ["ok"],
        "__ioi_tool_name": "sys__exec_session"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::SysExecSession { command, args, .. } => {
            assert_eq!(command, "echo");
            assert_eq!(args, vec!["ok".to_string()]);
        }
        other => panic!("expected SysExecSession, got {:?}", other),
    }
}

#[test]
fn queue_maps_sys_exec_session_custom_alias() {
    let request = build_custom_request(
        "sys::exec_session",
        151,
        serde_json::json!({
            "command": "bash",
            "args": ["-lc", "echo ok"]
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::SysExecSession { command, args, .. } => {
            assert_eq!(command, "bash");
            assert_eq!(args, vec!["-lc".to_string(), "echo ok".to_string()]);
        }
        other => panic!("expected SysExecSession, got {:?}", other),
    }
}

#[test]
fn queue_maps_sys_exec_session_reset_custom_alias() {
    let request = build_custom_request("sys::exec_session_reset", 152, serde_json::json!({}));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::SysExecSessionReset {} => {}
        other => panic!("expected SysExecSessionReset, got {:?}", other),
    }
}

#[test]
fn queue_preserves_computer_left_click_payload_for_guiclick_target() {
    let request = build_request(
        ActionTarget::GuiClick,
        31,
        serde_json::json!({
            "action": "left_click",
            "coordinate": [120, 240]
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::Computer(ComputerAction::LeftClick { coordinate }) => {
            assert_eq!(coordinate, Some([120, 240]));
        }
        other => panic!("expected Computer LeftClick, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_guiclick_tool_name_override_for_click_element() {
    let request = build_request(
        ActionTarget::GuiClick,
        32,
        serde_json::json!({
            "id": "btn_submit",
            "__ioi_tool_name": "gui__click_element"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::GuiClickElement { id } => {
            assert_eq!(id, "btn_submit");
        }
        other => panic!("expected GuiClickElement, got {:?}", other),
    }
}

#[test]
fn queue_maps_guimousemove_target_to_computer_tool() {
    let request = build_request(
        ActionTarget::GuiMouseMove,
        33,
        serde_json::json!({
            "coordinate": [55, 89]
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::Computer(ComputerAction::MouseMove { coordinate }) => {
            assert_eq!(coordinate, [55, 89]);
        }
        other => panic!("expected Computer MouseMove, got {:?}", other),
    }
}

#[test]
fn queue_maps_guiscreenshot_target_to_computer_tool() {
    let request = build_request(ActionTarget::GuiScreenshot, 35, serde_json::json!({}));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::Computer(ComputerAction::Screenshot) => {}
        other => panic!("expected Computer Screenshot, got {:?}", other),
    }
}

#[test]
fn queue_maps_custom_computer_cursor_alias_to_computer_tool() {
    let request = build_custom_request(
        "computer::cursor",
        37,
        serde_json::json!({
            "action": "cursor_position"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::Computer(ComputerAction::CursorPosition) => {}
        other => panic!("expected Computer CursorPosition, got {:?}", other),
    }
}
