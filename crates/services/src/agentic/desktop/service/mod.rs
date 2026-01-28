// Path: crates/services/src/agentic/desktop/service/mod.rs
pub mod actions;
pub mod builder;
pub mod lifecycle;
pub mod step; 
pub mod utils;

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

use crate::agentic::scrubber::SemanticScrubber;
use ioi_api::ibc::AgentZkVerifier;
use ioi_api::vm::drivers::os::OsDriver;

use self::lifecycle::{handle_delete_session, handle_resume, handle_start};
// [MODIFIED] Import handle_step from the new module location
use self::step::handle_step;
use crate::agentic::desktop::types::StepAgentParams; 

pub struct DesktopAgentService {
    // Fields are pub(crate) so submodules can access them
    pub(crate) gui: Arc<dyn GuiDriver>,
    pub(crate) terminal: Arc<TerminalDriver>,
    pub(crate) browser: Arc<BrowserDriver>,
    pub(crate) mcp: Option<Arc<McpManager>>,
    pub(crate) fast_inference: Arc<dyn InferenceRuntime>,
    pub(crate) reasoning_inference: Arc<dyn InferenceRuntime>,
    pub(crate) scrubber: SemanticScrubber,
    pub(crate) zk_verifier: Option<Arc<dyn AgentZkVerifier>>,
    pub(crate) scs: Option<Arc<Mutex<SovereignContextStore>>>,
    pub(crate) event_sender: Option<tokio::sync::broadcast::Sender<KernelEvent>>,
    pub(crate) os_driver: Option<Arc<dyn OsDriver>>,
    pub(crate) workspace_path: String,
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
                // [FIX] Explicit type annotation to satisfy compiler inference and future compatibility
                let p: StepAgentParams = codec::from_bytes_canonical(params)?;
                handle_step(self, state, p, ctx).await
            }
            "delete_session@v1" => handle_delete_session(self, state, params).await,
            _ => Err(TransactionError::Unsupported(method.into())),
        }
    }
}