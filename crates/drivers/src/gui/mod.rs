// Path: crates/drivers/src/gui/mod.rs

pub mod accessibility;
pub mod operator;
pub mod platform;
pub mod vision; // [NEW] Module for native provider

use self::operator::NativeOperator;
use self::vision::NativeVision;
use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;

use self::accessibility::{MockSubstrateProvider, SovereignSubstrateProvider};
use self::platform::NativeSubstrateProvider; // [NEW] Import Native Provider

/// The concrete implementation of the IOI GUI Driver.
/// This replaces the UI-TARS Electron app.
pub struct IoiGuiDriver {
    operator: NativeOperator,
    substrate: Box<dyn SovereignSubstrateProvider + Send + Sync>,
}

impl IoiGuiDriver {
    pub fn new() -> Self {
        // [FIX] Conditionally use Native provider in non-test builds, or based on a feature flag.
        // For now, we default to the Native provider (which currently has a mock impl inside)
        // to exercise the new code paths. In production, this would switch based on `cfg!(target_os)`.
        let substrate: Box<dyn SovereignSubstrateProvider + Send + Sync> = if cfg!(test) {
            Box::new(MockSubstrateProvider)
        } else {
            Box::new(NativeSubstrateProvider::new())
        };

        Self {
            operator: NativeOperator::new(),
            substrate,
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

    // Implementation of the Substrate access method
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
