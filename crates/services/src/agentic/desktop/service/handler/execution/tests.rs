use super::approvals::is_runtime_secret_install_retry_approved;
use super::execution_request_nonce;
use super::focus::is_focus_sensitive_tool;
use super::query_active_window_with_timeout;
use super::target_requires_window_binding;
use super::{normalize_web_research_tool_call, reconcile_pending_web_research_tool_call};
use crate::agentic::desktop::runtime_secret;
use crate::agentic::desktop::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, PendingSearchCompletion,
    PendingSearchReadSummary,
};
use async_trait::async_trait;
use ioi_api::state::StateScanIter;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_types::app::agentic::{
    AgentTool, ComputerAction, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    WebRetrievalContract,
};
use ioi_types::app::{AccountId, ActionTarget, ChainId, NetMode, RuntimeTarget};
use ioi_types::error::StateError;
use ioi_types::error::VmError;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::{sleep, Duration, Instant};

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0u8; 32],
        goal: "test".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 8,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 1,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: vec![],
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: vec![],
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target: None,
        resolved_intent: None,

        awaiting_intent_clarification: false,

        working_directory: ".".to_string(),
        active_lens: None,
        pending_search_completion: None,
        planner_state: None,
        command_history: Default::default(),
    }
}

#[test]
fn right_click_variants_require_focus_recovery() {
    assert!(is_focus_sensitive_tool(&AgentTool::Computer(
        ComputerAction::RightClick {
            coordinate: Some([10, 20]),
        },
    )));
    assert!(is_focus_sensitive_tool(&AgentTool::Computer(
        ComputerAction::RightClickId { id: 12 },
    )));
    assert!(is_focus_sensitive_tool(&AgentTool::Computer(
        ComputerAction::RightClickElement {
            id: "file_row".to_string(),
        },
    )));
}

#[test]
fn browser_click_tools_do_not_require_native_focus_recovery() {
    assert!(!is_focus_sensitive_tool(&AgentTool::BrowserClick {
        selector: "#submit".to_string(),
    }));
    assert!(!is_focus_sensitive_tool(&AgentTool::BrowserClickElement {
        id: Some("btn_submit".to_string()),
        ids: Vec::new(),
        delay_ms_between_ids: None,
        continue_with: None,
    }));
    assert!(!is_focus_sensitive_tool(
        &AgentTool::BrowserSyntheticClick {
            x: 20.0,
            y: 30.0,
            continue_with: None,
        }
    ));
}

#[test]
fn desktop_screenshot_does_not_require_window_binding() {
    assert!(
        !target_requires_window_binding(&ActionTarget::GuiScreenshot),
        "full-display screenshot capture should not depend on a foreground-window binding"
    );
    assert!(
        target_requires_window_binding(&ActionTarget::GuiClick),
        "interactive GUI clicks should remain window-bound"
    );
}

struct SlowWindowOsDriver;

#[async_trait]
impl OsDriver for SlowWindowOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(None)
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        sleep(Duration::from_secs(5)).await;
        Ok(None)
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(false)
    }

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
    }
}

#[tokio::test]
async fn active_window_query_timeout_returns_none_without_blocking() {
    let os_driver: Arc<dyn OsDriver> = Arc::new(SlowWindowOsDriver);
    let started = Instant::now();
    let result = query_active_window_with_timeout(&os_driver, [0u8; 32], "test").await;
    let elapsed = started.elapsed();

    assert!(result.is_none());
    assert!(
        elapsed < Duration::from_secs(2),
        "active window timeout guard took too long: {:?}",
        elapsed
    );
}

#[test]
fn runtime_secret_retry_is_approved_only_for_matching_pending_install() {
    let session_id = [9u8; 32];
    let session_hex = hex::encode(session_id);
    runtime_secret::set_secret(&session_hex, "sudo_password", "pw".to_string(), true, 60)
        .expect("set runtime sudo secret");

    let mut state = test_agent_state();
    let hash = [7u8; 32];
    state.pending_tool_hash = Some(hash);

    let install_tool = AgentTool::SysInstallPackage {
        package: "gnome-calculator".to_string(),
        manager: Some("apt-get".to_string()),
    };
    assert!(is_runtime_secret_install_retry_approved(
        &install_tool,
        hash,
        session_id,
        &state
    ));

    assert!(!is_runtime_secret_install_retry_approved(
        &install_tool,
        [8u8; 32],
        session_id,
        &state
    ));

    let non_install = AgentTool::SysExec {
        command: "echo".to_string(),
        args: vec!["ok".to_string()],
        stdin: None,
        detach: false,
    };
    assert!(!is_runtime_secret_install_retry_approved(
        &non_install,
        hash,
        session_id,
        &state
    ));
}

#[test]
fn pending_request_nonce_is_reused_for_canonical_resume() {
    let mut state = test_agent_state();
    state.pending_request_nonce = Some(7);

    assert_eq!(execution_request_nonce(&state, 11), 7);

    state.pending_request_nonce = None;
    assert_eq!(execution_request_nonce(&state, 11), 11);
}

fn resolved(scope: IntentScopeProfile) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "test".to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [0u8; 32],
        receipt_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

#[test]
fn rewrites_search_navigation_to_web_search_for_web_research_scope() {
    let mut tool = AgentTool::BrowserNavigate {
        url: "https://duckduckgo.com/?q=latest+news".to_string(),
    };
    let intent = resolved(IntentScopeProfile::WebResearch);

    normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback query");

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            assert_eq!(query, "latest news");
            assert_eq!(query_contract.as_deref(), Some("fallback query"));
            assert!(retrieval_contract.is_none());
            assert_eq!(
                    limit,
                    Some(crate::agentic::desktop::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
                );
            let expected = crate::agentic::web::build_default_search_url("latest news");
            assert_eq!(url.as_deref(), Some(expected.as_str()));
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn rewrites_direct_navigation_to_web_read_for_web_research_scope() {
    let mut tool = AgentTool::BrowserNavigate {
        url: "https://example.com/news".to_string(),
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback query");

    match tool {
        AgentTool::WebRead {
            url,
            max_chars,
            allow_browser_fallback,
        } => {
            assert_eq!(url, "https://example.com/news");
            assert_eq!(max_chars, None);
            assert_eq!(allow_browser_fallback, None);
        }
        other => panic!("expected WebRead, got {:?}", other),
    }
}

#[test]
fn rewrites_browser_snapshot_to_web_search_for_web_research_scope() {
    let mut tool = AgentTool::BrowserSnapshot {};
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(
        &mut tool,
        Some(&intent),
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
    );

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            assert_eq!(query, "italian menus");
            assert_eq!(
                query_contract.as_deref(),
                Some(
                    "Find the three best-reviewed Italian restaurants near me and compare their menus."
                )
            );
            assert!(retrieval_contract.is_none());
            assert_eq!(
                limit,
                Some(crate::agentic::desktop::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
            );
            let expected = crate::agentic::web::build_default_search_url("italian menus");
            assert_eq!(url.as_deref(), Some(expected.as_str()));
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn does_not_rewrite_non_search_navigation_or_non_web_scope() {
    let mut scoped_tool = AgentTool::BrowserNavigate {
        url: "https://duckduckgo.com/?q=latest+news".to_string(),
    };
    let non_web_intent = resolved(IntentScopeProfile::Conversation);
    normalize_web_research_tool_call(&mut scoped_tool, Some(&non_web_intent), "fallback");
    assert!(matches!(scoped_tool, AgentTool::BrowserNavigate { .. }));

    let mut non_http_tool = AgentTool::BrowserNavigate {
        url: "about:blank".to_string(),
    };
    let web_intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(&mut non_http_tool, Some(&web_intent), "fallback");
    assert!(matches!(non_http_tool, AgentTool::BrowserNavigate { .. }));
}

#[test]
fn does_not_rewrite_browser_actions_when_goal_explicitly_forbids_web_retrieval() {
    let mut tool = AgentTool::BrowserType {
        text: "dispatch.agent".to_string(),
        selector: Some("#username".to_string()),
    };
    let intent = resolved(IntentScopeProfile::UiInteraction);

    normalize_web_research_tool_call(
        &mut tool,
        Some(&intent),
        "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Search the queue for fiber, switch the sort to Recently Updated, and verify the saved dispatch update was not persisted.",
    );

    match tool {
        AgentTool::BrowserType { text, selector } => {
            assert_eq!(text, "dispatch.agent");
            assert_eq!(selector.as_deref(), Some("#username"));
        }
        other => panic!("expected BrowserType, got {:?}", other),
    }
}

#[test]
fn redirects_exhausted_pending_web_read_to_next_grounded_candidate() {
    let exhausted_url = "https://example.com/archive";
    let replacement_url = "https://example.com/latest";
    let mut tool = AgentTool::WebRead {
        url: exhausted_url.to_string(),
        max_chars: None,
        allow_browser_fallback: None,
    };
    let pending = PendingSearchCompletion {
        query: "Read the latest incident report updates.".to_string(),
        query_contract: "Read the latest incident report updates.".to_string(),
        retrieval_contract: None,
        url: "https://www.google.com/search?q=incident+report+updates".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![exhausted_url.to_string(), replacement_url.to_string()],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: exhausted_url.to_string(),
                title: Some("Older update".to_string()),
                excerpt: "Outdated incident report.".to_string(),
            },
            PendingSearchReadSummary {
                url: replacement_url.to_string(),
                title: Some("Current update".to_string()),
                excerpt: "Current incident report.".to_string(),
            },
        ],
        attempted_urls: vec![exhausted_url.to_string()],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };

    let replacement = reconcile_pending_web_research_tool_call(&mut tool, Some(&pending));

    assert_eq!(
        replacement,
        Some((exhausted_url.to_string(), replacement_url.to_string()))
    );
    match tool {
        AgentTool::WebRead { url, .. } => assert_eq!(url, replacement_url),
        other => panic!("expected WebRead, got {:?}", other),
    }
}

#[test]
fn does_not_redirect_exhausted_pending_web_read_when_query_contract_disallows_fallback() {
    let exhausted_url = "https://csrc.nist.gov/projects/post-quantum-cryptography";
    let replacement_url = "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption";
    let mut tool = AgentTool::WebRead {
        url: exhausted_url.to_string(),
        max_chars: None,
        allow_browser_fallback: None,
    };
    let pending = PendingSearchCompletion {
        query:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(ioi_types::app::agentic::WebRetrievalContract {
            contract_version: "web_retrieval_contract.v1".to_string(),
            browser_fallback_allowed: false,
            ..Default::default()
        }),
        url: "https://www.google.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![exhausted_url.to_string(), replacement_url.to_string()],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: exhausted_url.to_string(),
                title: Some("Post-Quantum Cryptography".to_string()),
                excerpt: "NIST project page for post-quantum cryptography.".to_string(),
            },
            PendingSearchReadSummary {
                url: replacement_url.to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                        .to_string(),
                ),
                excerpt:
                    "NIST selected HQC in March 2025 as the fifth post-quantum encryption algorithm."
                        .to_string(),
            },
        ],
        attempted_urls: vec![exhausted_url.to_string()],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };

    let replacement = reconcile_pending_web_research_tool_call(&mut tool, Some(&pending));

    assert_eq!(replacement, None);
    match tool {
        AgentTool::WebRead { url, .. } => assert_eq!(url, exhausted_url),
        other => panic!("expected WebRead, got {:?}", other),
    }
}

#[test]
fn leaves_fresh_pending_web_read_unchanged() {
    let fresh_url = "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";
    let mut tool = AgentTool::WebRead {
        url: fresh_url.to_string(),
        max_chars: None,
        allow_browser_fallback: None,
    };
    let pending = PendingSearchCompletion {
        query:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: None,
        url: "https://www.google.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![fresh_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: fresh_url.to_string(),
            title: Some(
                "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
            ),
            excerpt: "NIST finalized ML-KEM, ML-DSA and SLH-DSA in August 2024.".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };

    assert_eq!(
        reconcile_pending_web_research_tool_call(&mut tool, Some(&pending)),
        None
    );
    match tool {
        AgentTool::WebRead { url, .. } => assert_eq!(url, fresh_url),
        other => panic!("expected WebRead, got {:?}", other),
    }
}

#[test]
fn normalizes_direct_web_search_limit_for_web_research_scope() {
    let mut tool = AgentTool::WebSearch {
        query: "top US breaking news last 6 hours".to_string(),
        query_contract: None,
        retrieval_contract: None,
        limit: Some(3),
        url: None,
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback");

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            assert_eq!(query, "top US breaking news last 6 hours");
            assert_eq!(query_contract.as_deref(), Some("fallback"));
            assert!(retrieval_contract.is_none());
            assert_eq!(
                    limit,
                    Some(crate::agentic::desktop::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
                );
            let expected =
                crate::agentic::web::build_default_search_url("top US breaking news last 6 hours");
            assert_eq!(url.as_deref(), Some(expected.as_str()));
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn normalizes_web_search_query_contract_from_resolved_locality_query() {
    let mut tool = AgentTool::WebSearch {
        query: "best-reviewed Italian restaurants in Anderson, SC".to_string(),
        query_contract: None,
        retrieval_contract: None,
        limit: Some(3),
        url: None,
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(
        &mut tool,
        Some(&intent),
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
    );

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            assert_eq!(query, "best-reviewed Italian restaurants in Anderson, SC");
            assert_eq!(
                query_contract.as_deref(),
                Some(
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
                )
            );
            assert!(retrieval_contract.is_none());
            assert_eq!(
                limit,
                Some(crate::agentic::desktop::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
            );
            let expected = crate::agentic::web::build_default_search_url(
                "best-reviewed Italian restaurants in Anderson, SC",
            );
            assert_eq!(url.as_deref(), Some(expected.as_str()));
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn preserves_precomputed_web_search_retrieval_contract_when_query_contract_is_present() {
    let mut tool = AgentTool::WebSearch {
        query: "best-reviewed Italian restaurants in Anderson, SC".to_string(),
        query_contract: Some(
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
                .to_string(),
        ),
        retrieval_contract: Some(WebRetrievalContract {
            contract_version: "test.v1".to_string(),
            entity_cardinality_min: 3,
            comparison_required: true,
            currentness_required: true,
            runtime_locality_required: true,
            source_independence_min: 3,
            citation_count_min: 1,
            structured_record_preferred: false,
            ordered_collection_preferred: false,
            link_collection_preferred: true,
            canonical_link_out_preferred: true,
            geo_scoped_detail_required: true,
            discovery_surface_required: true,
            entity_diversity_required: true,
            scalar_measure_required: false,
            browser_fallback_allowed: true,
        }),
        limit: Some(3),
        url: None,
    };
    let intent = resolved(IntentScopeProfile::WebResearch);

    normalize_web_research_tool_call(
        &mut tool,
        Some(&intent),
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
    );

    match tool {
        AgentTool::WebSearch {
            retrieval_contract, ..
        } => {
            assert!(retrieval_contract.is_some());
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn rewrites_memory_search_to_web_search_for_web_research_scope() {
    let mut tool = AgentTool::MemorySearch {
        query: "active cloud incidents us impact".to_string(),
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback");

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            assert_eq!(query, "active cloud incidents us impact");
            assert_eq!(query_contract.as_deref(), Some("fallback"));
            assert!(retrieval_contract.is_none());
            assert_eq!(
                    limit,
                    Some(crate::agentic::desktop::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
                );
            let expected =
                crate::agentic::web::build_default_search_url("active cloud incidents us impact");
            assert_eq!(url.as_deref(), Some(expected.as_str()));
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn rewrites_empty_memory_search_with_fallback_for_web_research_scope() {
    let mut tool = AgentTool::MemorySearch {
        query: "   ".to_string(),
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(
        &mut tool,
        Some(&intent),
        "as of now top active us cloud incidents",
    );

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            assert_eq!(query, "as of now top active us cloud incidents");
            assert_eq!(
                query_contract.as_deref(),
                Some("as of now top active us cloud incidents")
            );
            assert!(retrieval_contract.is_none());
            assert_eq!(
                    limit,
                    Some(crate::agentic::desktop::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
                );
            let expected = crate::agentic::web::build_default_search_url(
                "as of now top active us cloud incidents",
            );
            assert_eq!(url.as_deref(), Some(expected.as_str()));
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn rewrites_memory_search_when_goal_is_live_external_even_if_scope_is_not_web() {
    let mut tool = AgentTool::MemorySearch {
        query: "active cloud incidents us impact".to_string(),
    };
    let workspace_intent = resolved(IntentScopeProfile::WorkspaceOps);
    normalize_web_research_tool_call(
        &mut tool,
        Some(&workspace_intent),
        "As of now (UTC), top active cloud incidents with citations",
    );

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            ..
        } => {
            assert_eq!(query, "active cloud incidents us impact");
            assert_eq!(
                query_contract.as_deref(),
                Some("As of now (UTC), top active cloud incidents with citations")
            );
            assert!(retrieval_contract.is_none());
            assert_eq!(
                limit,
                Some(crate::agentic::desktop::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
            );
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn normalizes_live_external_restaurant_search_even_if_scope_is_not_web() {
    let mut tool = AgentTool::WebSearch {
        query: "italian restaurants menus in Anderson, SC \"italian restaurants menus\" \"Anderson, SC\""
            .to_string(),
        query_contract: None,
        retrieval_contract: None,
        limit: Some(3),
        url: None,
    };
    let workspace_intent = resolved(IntentScopeProfile::WorkspaceOps);

    normalize_web_research_tool_call(
        &mut tool,
        Some(&workspace_intent),
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
    );

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            ..
        } => {
            let normalized = query.to_ascii_lowercase();
            assert!(
                normalized.contains("italian restaurants in anderson")
                    || normalized.contains("restaurants in anderson"),
                "query={query}"
            );
            assert!(!normalized.contains("compare"), "query={query}");
            assert!(
                !normalized.contains("\"italian restaurants menus\""),
                "query={query}"
            );
            assert_eq!(
                query_contract.as_deref(),
                Some(
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
                )
            );
            assert!(retrieval_contract.is_none());
            assert_eq!(
                limit,
                Some(crate::agentic::desktop::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
            );
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn does_not_rewrite_memory_search_for_workspace_local_goal() {
    let mut tool = AgentTool::MemorySearch {
        query: "intent resolver".to_string(),
    };
    let workspace_intent = resolved(IntentScopeProfile::WorkspaceOps);
    normalize_web_research_tool_call(
        &mut tool,
        Some(&workspace_intent),
        "Search the repository for intent resolver code and patch tests",
    );

    assert!(matches!(tool, AgentTool::MemorySearch { .. }));
}

#[derive(Default)]
struct MockState {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl ioi_api::state::StateAccess for MockState {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        keys.iter().map(|key| self.get(key)).collect()
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        for key in deletes {
            self.delete(key)?;
        }
        for (key, value) in inserts {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let rows: Vec<_> = self
            .data
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
            .collect();
        Ok(Box::new(rows.into_iter()))
    }
}

#[test]
fn firewall_attestation_signatures_are_real_and_verifiable() {
    let mut state = MockState::default();
    let attestation = b"firewall.attestation.payload";
    let ctx = Some((ChainId(7), AccountId([9u8; 32])));

    let sig = super::sign_firewall_attestation(&mut state, ctx, attestation)
        .expect("signature envelope should be generated");
    super::verify_firewall_attestation_signature(attestation, &sig)
        .expect("signature envelope should verify");
}

#[test]
fn firewall_attestation_signature_is_deterministic_for_same_signer_and_payload() {
    let mut state = MockState::default();
    let attestation = b"deterministic.payload";
    let ctx = Some((ChainId(1), AccountId([3u8; 32])));

    let first =
        super::sign_firewall_attestation(&mut state, ctx, attestation).expect("first signature");
    let second =
        super::sign_firewall_attestation(&mut state, ctx, attestation).expect("second signature");

    assert_eq!(first, second);
}

#[test]
fn runtime_target_maps_dynamic_tools_to_adapter() {
    let tool = AgentTool::Dynamic(serde_json::json!({
        "name": "filesystem__read_file",
        "arguments": { "path": "README.md" }
    }));
    assert_eq!(
        super::runtime_target_for_tool(&tool),
        RuntimeTarget::Adapter
    );
}

#[test]
fn runtime_target_maps_google_connector_dynamic_tools_to_adapter() {
    let tool = AgentTool::Dynamic(serde_json::json!({
        "name": "connector__google__gmail_read_emails",
        "arguments": { "query": "is:unread" }
    }));
    assert_eq!(
        super::runtime_target_for_tool(&tool),
        RuntimeTarget::Adapter
    );
}

#[test]
fn build_workload_spec_binds_domain_and_allowlisted_net_mode_for_net_fetch() {
    let tool = AgentTool::NetFetch {
        url: "https://api.example.com/v1/status".to_string(),
        max_chars: Some(256),
    };
    let (spec, observed_domain) =
        super::build_workload_spec(&tool, &ActionTarget::NetFetch, [5u8; 32], None, None, 2_000);

    assert_eq!(spec.runtime_target, RuntimeTarget::Network);
    assert_eq!(spec.net_mode, NetMode::AllowListed);
    assert_eq!(observed_domain.as_deref(), Some("api.example.com"));

    let lease = spec
        .capability_lease
        .as_ref()
        .expect("net fetch should mint capability lease");
    assert!(lease.allows_capability("net::fetch"));
    assert!(lease.allows_domain("status.api.example.com"));
}

#[test]
fn workload_spec_check_fails_closed_when_capability_lease_missing() {
    let tool = AgentTool::FsRead {
        path: "README.md".to_string(),
    };
    let (mut spec, _) =
        super::build_workload_spec(&tool, &ActionTarget::FsRead, [8u8; 32], None, None, 1_000);
    spec.capability_lease = None;

    let check = spec.evaluate_lease(&ActionTarget::FsRead, None, 1_100);
    assert!(!check.satisfied);
    assert_eq!(check.reason.as_deref(), Some("missing_capability_lease"));
}
