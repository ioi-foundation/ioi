// Path: crates/services/src/agentic/desktop/service/mod.rs

//! The core service definition for the Desktop Agent.

pub mod actions;
pub mod builder;
pub mod lifecycle;
pub mod step;

// [NEW] Submodules for refactored logic
pub mod handler;
pub mod memory;
pub mod skills;
pub mod visual;
pub mod utility {
    // [FIX] Correct re-export path.
    // Since 'handler' is a sibling module of 'utility' in this file,
    // we access it via 'super::handler'.
    pub use super::handler::select_runtime;
}

// [FIX] Middleware is in parent `desktop` module, not here.
// Removed `pub mod middleware;`

use async_trait::async_trait;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::GuiDriver;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::SovereignContextStore;
use ioi_types::app::KernelEvent;
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use ioi_types::service_configs::Capabilities;
use std::any::Any;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

use crate::agentic::fitness::Evaluator;
use crate::agentic::optimizer::OptimizerService;
use crate::agentic::pii_scrubber::PiiScrubber;
use ioi_api::ibc::AgentZkVerifier;
use ioi_api::vm::drivers::os::OsDriver;

use self::lifecycle::{handle_delete_session, handle_post_message, handle_resume, handle_start};
use self::step::handle_step;
use crate::agentic::desktop::types::{PostMessageParams, StepAgentParams};

use ioi_drivers::gui::accessibility::AccessibilityNode;
use ioi_drivers::gui::lenses::LensRegistry;

// Use the new VisualContextCache from the submodule
pub use self::visual::VisualContextCache;

/// The Desktop Agent Service.
pub struct DesktopAgentService {
    /// Driver for GUI automation (screenshot, click, type).
    pub(crate) gui: Arc<dyn GuiDriver>,
    /// Driver for terminal execution.
    pub(crate) terminal: Arc<TerminalDriver>,
    /// Driver for browser automation (CDP).
    pub(crate) browser: Arc<BrowserDriver>,
    /// Manager for Model Context Protocol (MCP) servers.
    pub(crate) mcp: Option<Arc<McpManager>>,
    /// Fast/Cheap inference runtime (System 1).
    pub(crate) fast_inference: Arc<dyn InferenceRuntime>,
    /// Reasoning/Expensive inference runtime (System 2).
    pub(crate) reasoning_inference: Arc<dyn InferenceRuntime>,
    /// Scrubber for redacting PII from logs/context.
    pub(crate) scrubber: PiiScrubber,

    /// Optional evaluator for measuring agent performance (RSI).
    pub(crate) evaluator: Option<Arc<dyn Evaluator>>,
    /// Optional optimizer for self-improvement.
    pub(crate) optimizer: Option<Arc<OptimizerService>>,

    /// Optional ZK verifier for proof checking.
    pub(crate) zk_verifier: Option<Arc<dyn AgentZkVerifier>>,
    /// Optional handle to the Sovereign Context Store (SCS) for long-term memory.
    pub(crate) scs: Option<Arc<Mutex<SovereignContextStore>>>,
    /// Sender for broadcasting kernel events to the UI.
    pub(crate) event_sender: Option<tokio::sync::broadcast::Sender<KernelEvent>>,
    /// Driver for OS-level operations (window management, clipboard).
    pub(crate) os_driver: Option<Arc<dyn OsDriver>>,
    /// Path to the local workspace/sandbox.
    pub(crate) workspace_path: String,
    /// Whether Set-of-Marks (SoM) visual grounding is enabled.
    pub(crate) enable_som: bool,

    /// Async RwLock + LRU Cache Wrapper.
    /// Stores recent visual contexts to allow robust resumption of actions after approval.
    pub(crate) som_history: Arc<RwLock<VisualContextCache>>,

    /// Cached accessibility tree from the most recent perception step.
    pub(crate) last_accessibility_tree: Arc<RwLock<Option<AccessibilityNode>>>,

    /// Lens Registry for Application Lenses ("LiDAR")
    pub(crate) lens_registry: Arc<LensRegistry>,
}

#[async_trait]
impl UpgradableService for DesktopAgentService {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[async_trait]
impl BlockchainService for DesktopAgentService {
    fn id(&self) -> &str {
        "desktop_agent"
    }
    fn abi_version(&self) -> u32 {
        1
    }
    fn state_schema(&self) -> &str {
        "v1"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "start@v1" => {
                let p = codec::from_bytes_canonical(params)?;
                handle_start(self, state, p).await
            }
            "resume@v1" => {
                let p = codec::from_bytes_canonical(params)?;
                handle_resume(self, state, p).await
            }
            "step@v1" => {
                let p: StepAgentParams = codec::from_bytes_canonical(params)?;
                handle_step(self, state, p, ctx).await
            }
            "post_message@v1" => {
                let p: PostMessageParams = codec::from_bytes_canonical(params)?;
                handle_post_message(self, state, p, ctx).await
            }
            "delete_session@v1" => handle_delete_session(self, state, params).await,
            _ => Err(TransactionError::Unsupported(method.into())),
        }
    }
}

// Forwarding methods to new submodules
impl DesktopAgentService {
    pub async fn fetch_swarm_manifest(
        &self,
        hash: [u8; 32],
    ) -> Option<ioi_types::app::agentic::SwarmManifest> {
        self::memory::fetch_swarm_manifest(self, hash).await
    }

    pub async fn restore_visual_context(
        &self,
        visual_hash: [u8; 32],
    ) -> Result<(), TransactionError> {
        self::visual::restore_visual_context(self, visual_hash).await
    }

    pub(crate) async fn handle_action_execution(
        &self,
        tool: ioi_types::app::agentic::AgentTool,
        session_id: [u8; 32],
        step_index: u32,
        visual_phash: [u8; 32],
        rules: &crate::agentic::rules::ActionRules,
        agent_state: &crate::agentic::desktop::types::AgentState,
        os_driver: &Arc<dyn OsDriver>,
        scoped_exception_hash: Option<[u8; 32]>,
    ) -> Result<(bool, Option<String>, Option<String>), TransactionError> {
        self::handler::handle_action_execution(
            self,
            tool,
            session_id,
            step_index,
            visual_phash,
            rules,
            agent_state,
            os_driver,
            scoped_exception_hash,
        )
        .await
    }

    pub(crate) async fn recall_skills(
        &self,
        state: &dyn StateAccess,
        goal: &str,
    ) -> Result<Vec<ioi_types::app::agentic::AgentSkill>, TransactionError> {
        self::skills::recall_skills(self, state, goal).await
    }

    pub async fn retrieve_context_hybrid(
        &self,
        query: &str,
        visual_phash: Option<[u8; 32]>,
    ) -> String {
        self::memory::retrieve_context_hybrid(self, query, visual_phash).await
    }

    pub(crate) fn select_runtime(
        &self,
        state: &crate::agentic::desktop::types::AgentState,
    ) -> std::sync::Arc<dyn ioi_api::vm::inference::InferenceRuntime> {
        self::handler::select_runtime(self, state)
    }

    pub async fn append_chat_to_scs(
        &self,
        session_id: [u8; 32],
        msg: &ioi_types::app::agentic::ChatMessage,
        block_height: u64,
    ) -> Result<[u8; 32], TransactionError> {
        self::memory::append_chat_to_scs(self, session_id, msg, block_height).await
    }

    pub fn hydrate_session_history(
        &self,
        session_id: [u8; 32],
    ) -> Result<Vec<ioi_types::app::agentic::ChatMessage>, TransactionError> {
        self::memory::hydrate_session_history(self, session_id)
    }

    pub fn hydrate_session_history_raw(
        &self,
        session_id: [u8; 32],
    ) -> Result<Vec<ioi_types::app::agentic::ChatMessage>, TransactionError> {
        self::memory::hydrate_session_history_raw(self, session_id)
    }

    pub(crate) fn fetch_failure_context(
        &self,
        session_id: [u8; 32],
    ) -> Result<Vec<ioi_types::app::agentic::StepTrace>, TransactionError> {
        self::memory::fetch_failure_context(self, session_id)
    }

    pub(crate) fn fetch_skill_macro(
        &self,
        tool_name: &str,
    ) -> Option<(ioi_types::app::agentic::AgentMacro, [u8; 32])> {
        self::skills::fetch_skill_macro(self, tool_name)
    }

    pub(crate) fn expand_macro(
        &self,
        skill: &ioi_types::app::agentic::AgentMacro,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Vec<ioi_types::app::ActionRequest>, TransactionError> {
        self::skills::expand_macro(self, skill, args)
    }

    pub(crate) async fn update_skill_reputation(
        &self,
        state: &mut dyn StateAccess,
        session_id: [u8; 32],
        session_success: bool,
        block_height: u64,
    ) -> Result<(), TransactionError> {
        self::skills::update_skill_reputation(
            self,
            state,
            session_id,
            session_success,
            block_height,
        )
        .await
    }

    pub(crate) async fn inspect_frame(&self, frame_id: u64) -> Result<String, TransactionError> {
        self::memory::inspect_frame(self, frame_id).await
    }

    pub(crate) async fn prepare_cloud_inference_input(
        &self,
        session_id: Option<[u8; 32]>,
        provider: &str,
        model: &str,
        input: &[u8],
    ) -> Result<Vec<u8>, TransactionError> {
        crate::agentic::desktop::cloud_airlock::prepare_cloud_inference_input(
            &self.scrubber,
            self.event_sender.as_ref(),
            session_id,
            provider,
            model,
            input,
        )
        .await
    }
}
