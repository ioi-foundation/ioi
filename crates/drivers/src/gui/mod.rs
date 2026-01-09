// Path: crates/drivers/src/gui/mod.rs

pub mod operator;
pub mod vision;
pub mod accessibility; // [NEW]

use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_types::error::VmError;
use self::operator::NativeOperator;
use self::vision::NativeVision;
use self::accessibility::{AccessibilityProvider, MockAccessibilityProvider, serialize_tree_to_xml}; // [NEW]

/// The concrete implementation of the IOI GUI Driver.
/// This replaces the UI-TARS Electron app.
pub struct IoiGuiDriver {
    operator: NativeOperator,
    a11y: Box<dyn AccessibilityProvider + Send + Sync>, // [NEW]
}

impl IoiGuiDriver {
    pub fn new() -> Self {
        Self {
            operator: NativeOperator::new(),
            // In a real build, we would conditionally instantiate platform-specific providers here.
            a11y: Box::new(MockAccessibilityProvider), 
        }
    }
}

#[async_trait]
impl GuiDriver for IoiGuiDriver {
    async fn capture_screen(&self) -> Result<Vec<u8>, VmError> {
        // Offload to blocking thread as screen capture is CPU intensive IO
        tokio::task::spawn_blocking(|| {
            NativeVision::capture_primary()
                .map_err(|e| VmError::HostError(format!("Vision failure: {}", e)))
        })
        .await
        .map_err(|e| VmError::HostError(format!("Task join error: {}", e)))?
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        // [NEW] Implementation
        // 1. Fetch the raw tree structure from the OS provider
        let root_node = self.a11y.get_active_window_tree()
            .map_err(|e| VmError::HostError(format!("Accessibility error: {}", e)))?;
            
        // 2. Serialize to VLM-friendly XML
        let xml_tree = serialize_tree_to_xml(&root_node, 0);
        
        Ok(xml_tree)
    }

    async fn inject_input(&self, event: InputEvent) -> Result<(), VmError> {
        // Offload input injection to blocking thread (Enigo is synchronous)
        let op = self.operator.inject(&event);
        
        match op {
            Ok(_) => Ok(()),
            Err(e) => Err(VmError::HostError(format!("Input injection failed: {}", e))),
        }
    }
}