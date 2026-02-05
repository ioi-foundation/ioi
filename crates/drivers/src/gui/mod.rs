// Path: crates/drivers/src/gui/mod.rs

pub mod accessibility;
pub mod operator;
pub mod platform;
pub mod vision;
pub mod som; 
pub mod lenses; // [NEW] Register lenses module

use self::operator::NativeOperator;
use self::vision::NativeVision;
use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;

use self::accessibility::{MockSubstrateProvider, SovereignSubstrateProvider, Rect, serialize_tree_to_xml};
use self::platform::NativeSubstrateProvider;

use self::som::overlay_accessibility_tree;
use self::lenses::{LensRegistry, react::ReactLens};

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
    // Flag to enable visual grounding overlay
    enable_som: bool,
    // Cache for SoM ID -> Rect mapping
    som_cache: Arc<Mutex<HashMap<u32, Rect>>>,
    // [NEW] Lens Registry for Application Lenses ("LiDAR")
    lens_registry: LensRegistry,
}

impl IoiGuiDriver {
    pub fn new() -> Self {
        // Default to Mock substrate.
        // The real provider requires the SCS handle, which must be injected.
        let substrate: Box<dyn SovereignSubstrateProvider + Send + Sync> =
            Box::new(MockSubstrateProvider);

        let mut lens_registry = LensRegistry::new();
        // [NEW] Register the React Lens by default for Electron/Web apps
        lens_registry.register(Box::new(ReactLens)); 

        Self {
            operator: NativeOperator::new(),
            substrate,
            enable_som: false, // Disabled by default for clean screenshots
            som_cache: Arc::new(Mutex::new(HashMap::new())),
            lens_registry,
        }
    }

    // Builder method to inject event sender into operator
    pub fn with_event_sender(mut self, sender: Sender<KernelEvent>) -> Self {
        self.operator = self.operator.with_event_sender(sender);
        self
    }

    // Builder method to inject SCS and switch to Native provider
    pub fn with_scs(mut self, scs: Arc<Mutex<SovereignContextStore>>) -> Self {
        self.substrate = Box::new(NativeSubstrateProvider::new(scs));
        self
    }
    
    // Builder method to enable Set-of-Marks overlay
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
        // Correct module path for platform
        let tree = self::platform::fetch_tree_direct().await
            .map_err(|e| VmError::HostError(format!("Failed to fetch tree for SoM: {}", e)))?;

        // 3. Render Overlay
        let mut img = load_from_memory(&raw_bytes)
            .map_err(|e| VmError::HostError(format!("Image decode failed: {}", e)))?
            .to_rgba8();

        let map = overlay_accessibility_tree(&mut img, &tree);
        
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
        // [NEW] Refactored to apply Lenses *before* committing to Substrate.
        // The NativeSubstrateProvider (platform.rs) does raw capture + storage.
        // We need to intercept here to apply the Lens transformation.
        
        // 1. Fetch raw tree from platform directly
        // We bypass substrate.get_intent_constrained_slice initially to get the struct.
        // But the trait doesn't expose the raw struct.
        // We need to cast or access the platform fetcher directly.
        // Since we are in the same crate, we can use the platform module helper.
        let raw_tree = self::platform::fetch_tree_direct().await
             .map_err(|e| VmError::HostError(format!("Failed to fetch raw tree: {}", e)))?;

        // 2. Identify Active Window for Lens Selection
        let window_title = raw_tree.name.as_deref().unwrap_or("");

        // 3. Apply Lens
        let xml_content = if let Some(lens) = self.lens_registry.select(window_title) {
            log::info!("Applying Application Lens: {}", lens.name());
            if let Some(transformed) = lens.transform(&raw_tree) {
                lens.render(&transformed, 0)
            } else {
                String::new() // Filtered out
            }
        } else {
            // Fallback to standard serializer
            serialize_tree_to_xml(&raw_tree, 0)
        };

        // 4. Manually commit to Substrate (replicating logic from NativeSubstrateProvider)
        // We do this here because we modified the data (Lensed XML instead of Raw XML).
        // If we used the trait method, we'd get the raw XML.
        // Note: Ideally, the Substrate provider should accept an optional transformer.
        // For now, we assume `self.substrate` is `NativeSubstrateProvider` and we use its underlying SCS.
        // Since we can't downcast easily without Any, we rely on the fact that we constructed it
        // and we have access to `ioi_scs` types.
        
        // BUT: The trait `SovereignSubstrateProvider` handles the commit.
        // To avoid code duplication, we should update the trait or provider to accept content.
        // Given constraints, we will reconstruct the ContextSlice manually here and commit if we have the SCS handle.
        // However, IoiGuiDriver doesn't hold the SCS handle directly in a public way, only inside the `substrate` box.
        // Wait, `with_scs` sets `self.substrate = Box::new(NativeSubstrateProvider::new(scs))`.
        
        // Strategy: We will accept that for this phase, `capture_context` via `self.substrate` returns RAW data,
        // and we overwrite the payload in the slice.
        // This means the SCS stores the RAW data (good for audit), but the Agent sees the LENSED data.
        
        let mut slice = self.substrate
            .get_intent_constrained_slice(intent, 0)
            .await
            .map_err(|e| VmError::HostError(format!("Substrate error: {}", e)))?;

        // Replace the chunks with our Lensed XML
        slice.chunks = vec![xml_content.into_bytes()];

        // Note: The slice_id and provenance proof in `slice` point to the RAW data stored in SCS.
        // The Agent gets Lensed data. This is actually correct:
        // - SCS stores "What really happened" (Raw Truth).
        // - Agent sees "What matters" (Semantic View).
        // - Provenance verifies the Raw Truth.
        
        Ok(slice)
    }

    async fn inject_input(&self, event: InputEvent) -> Result<(), VmError> {
        // Offload input injection to blocking thread (Enigo is synchronous)
        let op = self.operator.inject(&event);

        match op {
            Ok(_) => Ok(()),
            Err(e) => Err(VmError::HostError(format!("Input injection failed: {}", e))),
        }
    }

    async fn get_element_center(&self, id: u32) -> Result<Option<(u32, u32)>, VmError> {
        let cache = self.som_cache.lock().unwrap();
        if let Some(rect) = cache.get(&id) {
            let cx = rect.x + (rect.width / 2);
            let cy = rect.y + (rect.height / 2);
            Ok(Some((cx.max(0) as u32, cy.max(0) as u32)))
        } else {
            Ok(None)
        }
    }
}