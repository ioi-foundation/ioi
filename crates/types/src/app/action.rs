// Path: crates/types/src/app/action.rs

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
// [FIX] Import HashFunction trait so Sha256::digest is available
use dcrypt::algorithms::hash::HashFunction;

/// The target capability domain of an action.
/// This enum maps directly to the `cap:*` scopes defined in the Agency Firewall policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum ActionTarget {
    /// Perform an outbound network request (HTTP, etc.).
    #[serde(rename = "net::fetch")]
    NetFetch,
    /// Write to the local filesystem (subject to sandbox restrictions).
    #[serde(rename = "fs::write")]
    FsWrite,
    /// Read from the local filesystem.
    #[serde(rename = "fs::read")]
    FsRead,
    /// Simulate a UI click event.
    #[serde(rename = "ui::click")]
    UiClick,
    /// Simulate keyboard input.
    #[serde(rename = "ui::type")]
    UiType,
    /// Execute a system command (highly restricted).
    #[serde(rename = "sys::exec")]
    SysExec,
    /// Request a signature from the user's wallet.
    #[serde(rename = "wallet::sign")]
    WalletSign,
    /// Request a transaction send from the user's wallet.
    #[serde(rename = "wallet::send")]
    WalletSend,

    // --- New GUI Primitives (UI-TARS Port) ---
    /// Move the mouse cursor to specific coordinates.
    #[serde(rename = "gui::mouse_move")]
    GuiMouseMove,
    /// Perform a mouse click operation.
    #[serde(rename = "gui::click")]
    GuiClick,
    /// Simulate typing text on the keyboard.
    #[serde(rename = "gui::type")]
    GuiType,
    /// Capture a screenshot of the current display.
    #[serde(rename = "gui::screenshot")]
    GuiScreenshot,
    /// Scroll the active window or element.
    #[serde(rename = "gui::scroll")]
    GuiScroll,

    // --- New Browser Primitives (CDP) ---
    /// Navigate the controlled browser to a specific URL.
    #[serde(rename = "browser::navigate")]
    BrowserNavigate,
    /// Extract the DOM or accessibility tree from the current browser page.
    #[serde(rename = "browser::extract")]
    BrowserExtract,

    /// Catch-all for application-specific or plugin-defined actions.
    Custom(String),
}

/// Context binding an action to a specific execution scope.
/// Ensures that an action cannot be replayed outside its intended session or agent context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ActionContext {
    /// The unique identifier of the agent initiating the action.
    pub agent_id: String,
    /// The session ID this action belongs to (if bursting/remote).
    pub session_id: Option<[u8; 32]>,
    /// The UI window ID this action targets (if applicable).
    pub window_id: Option<u64>,
}

/// A normalized, schema-validated description of an externally effectful operation.
/// This is the primary input to the Agency Firewall policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ActionRequest {
    /// The type of action being requested.
    pub target: ActionTarget,
    /// Canonical JSON payload (RFC 8785) defining the parameters.
    /// This must be a deterministic byte representation to ensure the policy hash is stable.
    pub params: Vec<u8>,
    /// The execution context binding.
    pub context: ActionContext,
    /// Anti-replay nonce within the context.
    pub nonce: u64,
}

impl ActionRequest {
    /// Creates a deterministic hash of the action request for signing or logging.
    pub fn hash(&self) -> [u8; 32] {
        use dcrypt::algorithms::hash::Sha256;

        let mut data = Vec::new();
        // Naive serialization for hashing placeholder
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.extend_from_slice(&self.params);
        if let Some(sid) = self.context.session_id {
            data.extend_from_slice(&sid);
        }

        let digest = Sha256::digest(&data).expect("Sha256 failed");
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }
}
