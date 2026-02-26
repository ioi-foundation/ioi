use super::approvals::is_runtime_secret_install_retry_approved;
use super::focus::is_focus_sensitive_tool;
use super::normalize_web_research_tool_call;
use super::query_active_window_with_timeout;
use crate::agentic::desktop::runtime_secret;
use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
use async_trait::async_trait;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_types::app::agentic::{
    AgentTool, ComputerAction, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
};
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
        id: "btn_submit".to_string(),
    }));
    assert!(!is_focus_sensitive_tool(
        &AgentTool::BrowserSyntheticClick { x: 20, y: 30 }
    ));
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

fn resolved(scope: IntentScopeProfile) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "test".to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![],
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
        AgentTool::WebSearch { query, limit, url } => {
            assert_eq!(query, "latest news");
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
fn does_not_rewrite_non_search_navigation_or_non_web_scope() {
    let mut tool = AgentTool::BrowserNavigate {
        url: "https://example.com/news".to_string(),
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback query");
    assert!(matches!(tool, AgentTool::BrowserNavigate { .. }));

    let mut scoped_tool = AgentTool::BrowserNavigate {
        url: "https://duckduckgo.com/?q=latest+news".to_string(),
    };
    let non_web_intent = resolved(IntentScopeProfile::Conversation);
    normalize_web_research_tool_call(&mut scoped_tool, Some(&non_web_intent), "fallback");
    assert!(matches!(scoped_tool, AgentTool::BrowserNavigate { .. }));
}

#[test]
fn normalizes_direct_web_search_limit_for_web_research_scope() {
    let mut tool = AgentTool::WebSearch {
        query: "top US breaking news last 6 hours".to_string(),
        limit: Some(3),
        url: None,
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback");

    match tool {
        AgentTool::WebSearch { query, limit, url } => {
            assert_eq!(query, "top US breaking news last 6 hours");
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
fn rewrites_memory_search_to_web_search_for_web_research_scope() {
    let mut tool = AgentTool::MemorySearch {
        query: "active cloud incidents us impact".to_string(),
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback");

    match tool {
        AgentTool::WebSearch { query, limit, url } => {
            assert_eq!(query, "active cloud incidents us impact");
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
        AgentTool::WebSearch { query, limit, url } => {
            assert_eq!(query, "as of now top active us cloud incidents");
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
fn does_not_rewrite_memory_search_when_goal_is_live_external_but_scope_is_not_web() {
    let mut tool = AgentTool::MemorySearch {
        query: "active cloud incidents us impact".to_string(),
    };
    let workspace_intent = resolved(IntentScopeProfile::WorkspaceOps);
    normalize_web_research_tool_call(
        &mut tool,
        Some(&workspace_intent),
        "As of now (UTC), top active cloud incidents with citations",
    );

    assert!(matches!(tool, AgentTool::MemorySearch { .. }));
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
