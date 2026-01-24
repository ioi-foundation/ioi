use super::DesktopAgentService;
use crate::agentic::scrub_adapter::RuntimeAsSafetyModel;
use crate::agentic::scrubber::SemanticScrubber;
use ioi_api::ibc::AgentZkVerifier;
use ioi_api::vm::drivers::gui::GuiDriver;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::SovereignContextStore;
use ioi_types::app::KernelEvent;
use std::sync::{Arc, Mutex};

impl DesktopAgentService {
    pub fn new(
        gui: Arc<dyn GuiDriver>,
        terminal: Arc<TerminalDriver>,
        browser: Arc<BrowserDriver>,
        inference: Arc<dyn InferenceRuntime>,
    ) -> Self {
        let safety_adapter = Arc::new(RuntimeAsSafetyModel::new(inference.clone()));
        let scrubber = SemanticScrubber::new(safety_adapter);

        Self {
            gui,
            terminal,
            browser,
            mcp: None,
            fast_inference: inference.clone(),
            reasoning_inference: inference,
            scrubber,
            zk_verifier: None,
            scs: None,
            event_sender: None,
            os_driver: None,
            workspace_path: "./ioi-data".to_string(),
        }
    }

    pub fn new_hybrid(
        gui: Arc<dyn GuiDriver>,
        terminal: Arc<TerminalDriver>,
        browser: Arc<BrowserDriver>,
        fast_inference: Arc<dyn InferenceRuntime>,
        reasoning_inference: Arc<dyn InferenceRuntime>,
    ) -> Self {
        let safety_adapter = Arc::new(RuntimeAsSafetyModel::new(fast_inference.clone()));
        let scrubber = SemanticScrubber::new(safety_adapter);

        Self {
            gui,
            terminal,
            browser,
            mcp: None,
            fast_inference,
            reasoning_inference,
            scrubber,
            zk_verifier: None,
            scs: None,
            event_sender: None,
            os_driver: None,
            workspace_path: "./ioi-data".to_string(),
        }
    }

    pub fn with_workspace_path(mut self, path: String) -> Self {
        self.workspace_path = path;
        self
    }

    pub fn with_mcp_manager(mut self, manager: Arc<McpManager>) -> Self {
        self.mcp = Some(manager);
        self
    }

    pub fn with_zk_verifier(mut self, verifier: Arc<dyn AgentZkVerifier>) -> Self {
        self.zk_verifier = Some(verifier);
        self
    }

    pub fn with_scs(mut self, scs: Arc<Mutex<SovereignContextStore>>) -> Self {
        self.scs = Some(scs);
        self
    }

    pub fn with_event_sender(
        mut self,
        sender: tokio::sync::broadcast::Sender<KernelEvent>,
    ) -> Self {
        self.event_sender = Some(sender);
        self
    }

    pub fn with_os_driver(mut self, driver: Arc<dyn OsDriver>) -> Self {
        self.os_driver = Some(driver);
        self
    }
}