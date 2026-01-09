// Path: crates/drivers/src/gui/mod.rs

pub mod accessibility;
pub mod operator;
pub mod vision; // [NEW]

use self::operator::NativeOperator;
use self::vision::NativeVision;
use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
// [FIX] Updated imports to match the SCS rebrand, removed unused `serialize_tree_to_xml`
use self::accessibility::{MockSubstrateProvider, SovereignSubstrateProvider};

/// The concrete implementation of the IOI GUI Driver.
/// This replaces the UI-TARS Electron app.
pub struct IoiGuiDriver {
    operator: NativeOperator,
    // [FIX] Updated trait bound
    substrate: Box<dyn SovereignSubstrateProvider + Send + Sync>,
}

impl IoiGuiDriver {
    pub fn new() -> Self {
        Self {
            operator: NativeOperator::new(),
            // In a real build, we would conditionally instantiate platform-specific providers here.
            // [FIX] Updated struct name
            substrate: Box::new(MockSubstrateProvider),
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
        let tree_xml = String::from_utf8(slice.data)
            .map_err(|e| VmError::HostError(format!("Invalid UTF-8 in slice: {}", e)))?;
        Ok(tree_xml)
    }

    // [NEW] Implementation of the Substrate access method
    async fn capture_context(&self, intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        // In a real implementation, we would determine the active monitor handle here.
        let monitor_handle = 0;

        self.substrate
            .get_intent_constrained_slice(intent, monitor_handle)
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
}
