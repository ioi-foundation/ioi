// Path: crates/drivers/src/gui/mod.rs

pub mod accessibility;
pub mod geometry;
pub mod lenses;
pub mod operator;
pub mod platform;
pub mod som;
pub mod vision;

use self::operator::NativeOperator;
use self::vision::NativeVision;
use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;

use self::accessibility::{
    serialize_tree_to_xml, MockSubstrateProvider, Rect, SovereignSubstrateProvider,
};
use self::platform::NativeSubstrateProvider;

use self::geometry::{CoordinateSpace, DisplayTransform, Point};
use self::lenses::{auto::AutoLens, react::ReactLens, AppLens, LensRegistry}; // [FIX] Import AutoLens
use self::som::{assign_som_ids, draw_som_overlay, redact_sensitive_regions};

use image::{load_from_memory, ImageFormat};
use ioi_scs::SovereignContextStore;
use ioi_types::app::KernelEvent;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast::Sender;

/// The concrete implementation of the IOI GUI Driver.
/// This acts as the "Eyes and Hands" of the agent, managing screen capture,
/// visual grounding (SoM), and input injection.
pub struct IoiGuiDriver {
    operator: NativeOperator,
    substrate: Box<dyn SovereignSubstrateProvider + Send + Sync>,
    // Flag to enable visual grounding overlay
    enable_som: bool,
    // Cache for SoM ID -> Rect mapping.
    // Shared with the ToolExecutor to resolve "Click #42" to coordinates.
    som_cache: Arc<Mutex<HashMap<u32, Rect>>>,
    // Lens Registry for Application Lenses ("LiDAR")
    lens_registry: LensRegistry,
}

impl IoiGuiDriver {
    pub fn new() -> Self {
        // Default to Mock substrate.
        // The real provider requires the SCS handle, which must be injected.
        let substrate: Box<dyn SovereignSubstrateProvider + Send + Sync> =
            Box::new(MockSubstrateProvider);

        let mut lens_registry = LensRegistry::new();
        // High-Priority: React/Electron apps
        lens_registry.register(Box::new(ReactLens));
        // Fallback: Universal Heuristic Lens
        lens_registry.register(Box::new(AutoLens));

        Self {
            operator: NativeOperator::new(),
            substrate,
            enable_som: false,
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
    pub fn with_som(mut self, enabled: bool) -> Self {
        self.enable_som = enabled;
        self
    }

    // [NEW] Public API to register custom lenses
    pub fn register_lens(&mut self, lens: Box<dyn AppLens>) {
        self.lens_registry.register(lens);
    }

    /// [NEW] Manually injects a Set-of-Marks mapping into the cache.
    /// This allows "Visual Background" mode (Tier 2) to register the locations of
    /// elements found in a Tab Screenshot, so the Executor can resolve IDs.
    pub fn register_som_overlay(&self, map: HashMap<u32, Rect>) {
        let mut cache = self.som_cache.lock().unwrap();
        // We extend the cache, allowing ID overrides if a new step re-uses numbers.
        // In practice, the agent usually refers to the latest snapshot.
        cache.clear();
        cache.extend(map);
    }
}

#[async_trait]
impl GuiDriver for IoiGuiDriver {
    async fn capture_screen(
        &self,
        crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        // [MODIFIED] Use the raw capture logic, then apply processing
        let raw_bytes = self.capture_raw_screen().await?;

        // Load image to handle potential cropping or overlay
        let mut img = load_from_memory(&raw_bytes)
            .map_err(|e| VmError::HostError(format!("Image decode failed: {}", e)))?
            .to_rgba8();

        let mut offset = (0, 0);

        // Apply Crop if requested
        if let Some((x, y, w, h)) = crop_rect {
            let img_w = img.width();
            let img_h = img.height();

            // Coordinate validation
            // Treat negative coords as valid (multi-monitor), but for image slicing we rely on
            // visual/os driver alignment. For simplicity here, we clamp to image bounds if coords are positive.
            let cx = x.max(0) as u32;
            let cy = y.max(0) as u32;

            // Ensure crop area is valid
            if cx < img_w && cy < img_h {
                let cw = w.min(img_w - cx);
                let ch = h.min(img_h - cy);

                if cw > 0 && ch > 0 {
                    use image::imageops::crop;
                    // Crop creates a SubImage, convert back to RgbaImage
                    img = crop(&mut img, cx, cy, cw, ch).to_image();
                    // Set offset so SoM knows where this crop came from relative to global coords
                    offset = (x, y);
                }
            }
        }

        // Apply Redaction and SoM if enabled
        if self.enable_som {
            // Fetch Accessibility Tree (Async)
            if let Ok(tree) = self::platform::fetch_tree_direct().await {
                // Redact Sensitive Regions (Passwords/PII)
                redact_sensitive_regions(&mut img, &tree, offset);

                let base = NativeOperator::current_display_transform();
                let transform = DisplayTransform::new(
                    base.scale_factor,
                    Point::new(0.0, 0.0, CoordinateSpace::ScreenLogical),
                    Point::new(
                        offset.0 as f64 * base.scale_factor,
                        offset.1 as f64 * base.scale_factor,
                        CoordinateSpace::ImagePhysical,
                    ),
                    img.width(),
                    img.height(),
                );

                let mut grounded_tree = tree.clone();
                let mut map = HashMap::new();
                let mut counter = 1;
                assign_som_ids(&mut grounded_tree, &transform, &mut counter, &mut map);
                draw_som_overlay(&mut img, &grounded_tree, &transform);

                {
                    let mut cache = self.som_cache.lock().unwrap();
                    *cache = map;
                }
            } else {
                log::warn!("Failed to fetch accessibility tree for SoM/Redaction");
            }
        }

        // Encode back to PNG
        let mut out_bytes: Vec<u8> = Vec::new();
        img.write_to(&mut Cursor::new(&mut out_bytes), ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("Image re-encoding failed: {}", e)))?;

        Ok(out_bytes)
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        // Offload input injection to blocking thread (xcap is synchronous)
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            // [FIX] Wrap success in Ok(), use single ? on join handle result
            let bytes = handle
                .spawn_blocking(|| {
                    NativeVision::capture_primary()
                        .map_err(|e| VmError::HostError(format!("Vision failure: {}", e)))
                })
                .await
                .map_err(|e| VmError::HostError(format!("Task join error: {}", e)))??; // Double ?? unwraps Join and Vision Result

            Ok(bytes)
        } else {
            // [FIX] Wrap in Ok()
            let bytes = NativeVision::capture_primary()
                .map_err(|e| VmError::HostError(format!("Vision failure: {}", e)))?;
            Ok(bytes)
        }
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
        // 1. Fetch raw tree from platform directly
        let raw_tree = self::platform::fetch_tree_direct()
            .await
            .map_err(|e| VmError::HostError(format!("Failed to fetch raw tree: {}", e)))?;

        // 2. Identify Active Window for Lens Selection
        let window_title = raw_tree.name.as_deref().unwrap_or("");

        // 3. Apply Lens (Filter "Div Soup") with ROBUST FALLBACK
        let mut xml_content = String::new();
        let mut lens_applied = false;

        // Try specific lens first
        if let Some(lens) = self.lens_registry.select(window_title) {
            log::info!("Applying Application Lens: {}", lens.name());
            if let Some(transformed) = lens.transform(&raw_tree) {
                let rendered = lens.render(&transformed, 0);
                if !rendered.trim().is_empty() {
                    xml_content = rendered;
                    lens_applied = true;
                }
            }
        }

        // If specific lens failed or returned empty (e.g. Electron app structure changed),
        // FORCE the AutoLens (Universal Heuristic).
        if !lens_applied {
            log::warn!("Primary lens failed or returned empty. Falling back to AutoLens (Unstoppable Mode).");
            // [FIX] Directly instantiate AutoLens to ensure we always have it
            let auto = self::lenses::auto::AutoLens;
            if let Some(transformed) = auto.transform(&raw_tree) {
                xml_content = auto.render(&transformed, 0);
            }
        }

        // If STILL empty, it means the OS tree itself is empty or invisible.
        // We return raw XML of the root as a last resort diagnostics.
        if xml_content.trim().is_empty() {
            log::warn!("AutoLens returned empty. Returning raw OS root for diagnostics.");
            xml_content = serialize_tree_to_xml(&raw_tree, 0);
        }

        // 4. Manually commit to Substrate (Active Observation)
        // We use the substrate provider to handle the storage framing,
        // but we inject our "Lensed" XML as the content.
        let mut slice = self
            .substrate
            .get_intent_constrained_slice(intent, 0)
            .await
            .map_err(|e| VmError::HostError(format!("Substrate error: {}", e)))?;

        // Replace the chunks with our Lensed XML
        slice.chunks = vec![xml_content.into_bytes()];

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

    // [UPDATED] Implement the trait method
    async fn register_som_overlay(
        &self,
        map: HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        let mut cache = self.som_cache.lock().unwrap();
        cache.clear();

        for (id, (x, y, w, h)) in map {
            cache.insert(
                id,
                Rect {
                    x,
                    y,
                    width: w,
                    height: h,
                },
            );
        }
        Ok(())
    }
}
