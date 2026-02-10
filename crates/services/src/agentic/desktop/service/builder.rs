// Path: crates/services/src/agentic/desktop/service/builder.rs
use super::{DesktopAgentService, VisualContextCache};
use crate::agentic::scrub_adapter::RuntimeAsSafetyModel;
use crate::agentic::scrubber::SemanticScrubber;
use crate::agentic::fitness::LlmEvaluator;
use crate::agentic::optimizer::OptimizerService;

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
use tokio::sync::RwLock;

// [FIX] Import LensRegistry and ReactLens
use ioi_drivers::gui::lenses::{LensRegistry, react::ReactLens};

impl DesktopAgentService {
    pub fn new(
        gui: Arc<dyn GuiDriver>,
        terminal: Arc<TerminalDriver>,
        browser: Arc<BrowserDriver>,
        inference: Arc<dyn InferenceRuntime>,
    ) -> Self {
        let safety_adapter = Arc::new(RuntimeAsSafetyModel::new(inference.clone()));
        let scrubber = SemanticScrubber::new(safety_adapter);
        
        let evaluator = Arc::new(LlmEvaluator::new(inference.clone()));

        // [FIX] Initialize Lens Registry
        let mut lens_registry = LensRegistry::new();
        lens_registry.register(Box::new(ReactLens));
        // [FIX] Wrap in Arc to share with Executor
        let lens_registry_arc = Arc::new(lens_registry);

        Self {
            gui,
            terminal,
            browser,
            mcp: None,
            fast_inference: inference.clone(),
            reasoning_inference: inference,
            scrubber,
            evaluator: Some(evaluator),
            optimizer: None,
            zk_verifier: None,
            scs: None,
            event_sender: None,
            os_driver: None,
            workspace_path: "./ioi-data".to_string(),
            enable_som: false,
            // [FIX] Increased cache size from 5 to 100 to prevent eviction during human approval delays
            som_history: Arc::new(RwLock::new(VisualContextCache::new(100))),
            last_accessibility_tree: Arc::new(RwLock::new(None)),
            lens_registry: lens_registry_arc,
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

        let evaluator = Arc::new(LlmEvaluator::new(reasoning_inference.clone()));

        // [FIX] Initialize Lens Registry
        let mut lens_registry = LensRegistry::new();
        lens_registry.register(Box::new(ReactLens));
        // [FIX] Wrap in Arc to share with Executor
        let lens_registry_arc = Arc::new(lens_registry);

        Self {
            gui,
            terminal,
            browser,
            mcp: None,
            fast_inference,
            reasoning_inference,
            scrubber,
            evaluator: Some(evaluator),
            optimizer: None,
            zk_verifier: None,
            scs: None,
            event_sender: None,
            os_driver: None,
            workspace_path: "./ioi-data".to_string(),
            enable_som: false,
            // [FIX] Increased cache size from 5 to 100 to prevent eviction during human approval delays
            som_history: Arc::new(RwLock::new(VisualContextCache::new(100))),
            last_accessibility_tree: Arc::new(RwLock::new(None)),
            lens_registry: lens_registry_arc,
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
    
    pub fn with_optimizer(mut self, optimizer: Arc<OptimizerService>) -> Self {
        self.optimizer = Some(optimizer);
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
    
    pub fn with_som(mut self, enabled: bool) -> Self {
        self.enable_som = enabled;
        self
    }
}