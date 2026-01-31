// Path: crates/drivers/src/gui/mod.rs

pub mod accessibility;
pub mod operator;
pub mod platform;
pub mod vision;
pub mod som; // [NEW] Set-of-Marks module

use self::operator::NativeOperator;
use self::vision::NativeVision;
use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;

use self::accessibility::{MockSubstrateProvider, SovereignSubstrateProvider, Rect};
use self::platform::NativeSubstrateProvider;

use self::som::overlay_accessibility_tree;

use ioi_scs::SovereignContextStore;
use ioi_types::app::KernelEvent;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast::Sender;
use image::{load_from_memory, ImageFormat};
use std::io::Cursor;
use std::collections::HashMap;

/// The concrete implementation of the IOI GUI Driver.
/// This replaces the UI-TARS Electron app.
pub struct IoiGuiDriver {
    operator: NativeOperator,
    substrate: Box<dyn SovereignSubstrateProvider + Send + Sync>,
    // [NEW] Flag to enable visual grounding overlay
    enable_som: bool,
    // [NEW] Cache for SoM ID -> Rect mapping
    som_cache: Arc<Mutex<HashMap<u32, Rect>>>,
}

impl IoiGuiDriver {
    pub fn new() -> Self {
        // Default to Mock substrate.
        // The real provider requires the SCS handle, which must be injected.
        let substrate: Box<dyn SovereignSubstrateProvider + Send + Sync> =
            Box::new(MockSubstrateProvider);

        Self {
            operator: NativeOperator::new(),
            substrate,
            enable_som: false, // Disabled by default for clean screenshots
            som_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // [NEW] Builder method to inject event sender into operator
    pub fn with_event_sender(mut self, sender: Sender<KernelEvent>) -> Self {
        self.operator = self.operator.with_event_sender(sender);
        self
    }

    // [NEW] Builder method to inject SCS and switch to Native provider
    pub fn with_scs(mut self, scs: Arc<Mutex<SovereignContextStore>>) -> Self {
        self.substrate = Box::new(NativeSubstrateProvider::new(scs));
        self
    }
    
    // [NEW] Builder method to enable Set-of-Marks overlay
    pub fn with_som(mut self) -> Self {
        self.enable_som = true;
        self
    }
}

#[async_trait]
impl GuiDriver for IoiGuiDriver {
    async fn capture_screen(&self) -> Result<Vec<u8>, VmError> {
        let enable_som = self.enable_som;

        // 1. Capture Raw Screenshot (Blocking OS Call)
        // Offload to blocking thread when a Tokio runtime is available.
        let raw_bytes = if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle
                .spawn_blocking(|| {
                    NativeVision::capture_primary()
                        .map_err(|e| VmError::HostError(format!("Vision failure: {}", e)))
                })
                .await
                .map_err(|e| VmError::HostError(format!("Task join error: {}", e)))??
        } else {
            // Fallback for non-Tokio worker threads (e.g., parallel execution pool).
            NativeVision::capture_primary()
                .map_err(|e| VmError::HostError(format!("Vision failure: {}", e)))?
        };

        if !enable_som {
            return Ok(raw_bytes);
        }

        // 2. Fetch Accessibility Tree (Async)
        // [FIX] Correct module path: 'crate' refers to the root of 'ioi-drivers'
        // Since we are in 'gui/mod.rs', 'platform' is a submodule of 'gui'.
        // So we access it via `self::platform` or `crate::gui::platform`.
        let tree = self::platform::fetch_tree_direct().await
            .map_err(|e| VmError::HostError(format!("Failed to fetch tree for SoM: {}", e)))?;

        // 3. Render Overlay
        let mut img = load_from_memory(&raw_bytes)
            .map_err(|e| VmError::HostError(format!("Image decode failed: {}", e)))?
            .to_rgba8();

        // [NEW] Get map back from overlay function
        let map = overlay_accessibility_tree(&mut img, &tree);
        
        // [NEW] Update cache
        {
            let mut cache = self.som_cache.lock().unwrap();
            *cache = map;
        }

        // 4. Encode back to PNG
        let mut out_bytes: Vec<u8> = Vec::new();
        img.write_to(&mut Cursor::new(&mut out_bytes), ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("Image re-encoding failed: {}", e)))?;

        Ok(out_bytes)
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        // Legacy method: use a dummy intent to fetch the full tree via Substrate
        let dummy_intent = ActionRequest {
            target: ioi_types::app::ActionTarget::GuiScreenshot,
            params: vec![],
            context: ioi_types::app::ActionContext {
                agent_id: "legacy".into(),
                session_id: None,
                window_id: None,
            },
            nonce: 0,
        };

        let slice = self.capture_context(&dummy_intent).await?;
        
        let mut combined_data = Vec::new();
        for chunk in &slice.chunks {
            combined_data.extend_from_slice(chunk);
        }
        
        let tree_xml = String::from_utf8(combined_data)
            .map_err(|e| VmError::HostError(format!("Invalid UTF-8 in slice: {}", e)))?;
        Ok(tree_xml)
    }

    // Implementation of the Substrate access method
    async fn capture_context(&self, intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        // In a real implementation, we would determine the active monitor handle here.
        let monitor_handle = 0;

        self.substrate
            .get_intent_constrained_slice(intent, monitor_handle)
            .await 
            .map_err(|e| VmError::HostError(format!("Substrate error: {}", e)))
    }

    async fn inject_input(&self, event: InputEvent) -> Result<(), VmError> {
        // Offload input injection to blocking thread (Enigo is synchronous)
        let op = self.operator.inject(&event);

        match op {
            Ok(_) => Ok(()),
            Err(e) => Err(VmError::HostError(format!("Input injection failed: {}", e))),
        }
    }

    // [NEW] Implementation
    async fn get_element_center(&self, id: u32) -> Result<Option<(u32, u32)>, VmError> {
        let cache = self.som_cache.lock().unwrap();
        if let Some(rect) = cache.get(&id) {
            let cx = rect.x + (rect.width / 2);
            let cy = rect.y + (rect.height / 2);
            // Ensure non-negative
            Ok(Some((cx.max(0) as u32, cy.max(0) as u32)))
        } else {
            Ok(None)
        }
    }
}