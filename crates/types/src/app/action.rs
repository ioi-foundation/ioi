// Path: crates/types/src/app/action.rs

use crate::app::agentic::PiiScopedException;
use crate::app::SignatureSuite;
use dcrypt::algorithms::hash::HashFunction;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// The target capability domain of an action.
/// This enum maps directly to the `cap:*` scopes defined in the Agency Firewall policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum ActionTarget {
    /// Perform an outbound network request (HTTP, etc.).
    #[serde(rename = "net::fetch")]
    NetFetch,
    /// Deterministic web retrieval (search/read) producing provenance-tracked evidence.
    #[serde(rename = "web::retrieve")]
    WebRetrieve,
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
    /// Install a package through deterministic manager adapters.
    #[serde(rename = "sys::install_package")]
    SysInstallPackage,
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

    /// Execute a composite input sequence (e.g. Drag, Key Chord).
    /// This targets batch operations for atomic execution.
    #[serde(rename = "gui::sequence")]
    GuiSequence,

    // --- Browser Intent Buckets ---
    /// Interact with the hermetic browser (navigate/click/type/scroll/etc.).
    #[serde(rename = "browser::interact")]
    BrowserInteract,

    /// Inspect the current browser page (DOM/a11y snapshot) without interaction.
    #[serde(rename = "browser::inspect")]
    BrowserInspect,

    // --- New Commerce Primitives (UCP) ---
    /// Discovery phase: Fetch /.well-known/ucp to see what a merchant supports.
    /// Typically low-risk, often allowed by default.
    #[serde(rename = "ucp::discovery")]
    CommerceDiscovery,

    /// Checkout phase: Execute a purchase via UCP.
    /// High-risk: involves injecting payment tokens. Firewall MUST enforce spend limits.
    #[serde(rename = "ucp::checkout")]
    CommerceCheckout,

    // --- OS Control Primitives ---
    /// Focus a window by title.
    #[serde(rename = "os::focus")]
    WindowFocus,
    /// Read from the system clipboard.
    #[serde(rename = "clipboard::read")]
    ClipboardRead,
    /// Write to the system clipboard.
    #[serde(rename = "clipboard::write")]
    ClipboardWrite,

    /// Catch-all for application-specific or plugin-defined actions.
    Custom(String),
}

impl ActionTarget {
    /// Returns the canonical deterministic label for this target.
    pub fn canonical_label(&self) -> String {
        match self {
            ActionTarget::NetFetch => "net::fetch".to_string(),
            ActionTarget::WebRetrieve => "web::retrieve".to_string(),
            ActionTarget::FsWrite => "fs::write".to_string(),
            ActionTarget::FsRead => "fs::read".to_string(),
            ActionTarget::UiClick => "ui::click".to_string(),
            ActionTarget::UiType => "ui::type".to_string(),
            ActionTarget::SysExec => "sys::exec".to_string(),
            ActionTarget::SysInstallPackage => "sys::install_package".to_string(),
            ActionTarget::WalletSign => "wallet::sign".to_string(),
            ActionTarget::WalletSend => "wallet::send".to_string(),
            ActionTarget::GuiMouseMove => "gui::mouse_move".to_string(),
            ActionTarget::GuiClick => "gui::click".to_string(),
            ActionTarget::GuiType => "gui::type".to_string(),
            ActionTarget::GuiScreenshot => "gui::screenshot".to_string(),
            ActionTarget::GuiScroll => "gui::scroll".to_string(),
            ActionTarget::GuiSequence => "gui::sequence".to_string(),
            ActionTarget::BrowserInteract => "browser::interact".to_string(),
            ActionTarget::BrowserInspect => "browser::inspect".to_string(),
            ActionTarget::CommerceDiscovery => "ucp::discovery".to_string(),
            ActionTarget::CommerceCheckout => "ucp::checkout".to_string(),
            ActionTarget::WindowFocus => "os::focus".to_string(),
            ActionTarget::ClipboardRead => "clipboard::read".to_string(),
            ActionTarget::ClipboardWrite => "clipboard::write".to_string(),
            ActionTarget::Custom(name) => name.clone(),
        }
    }
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

        // Include Target in hash to prevent semantic aliasing
        // We use the JSON serialization of the target enum to ensure unique representation
        if let Ok(target_bytes) = serde_json::to_vec(&self.target) {
            data.extend_from_slice(&target_bytes);
        }

        // Include Agent ID to prevent cross-agent replay
        data.extend_from_slice(self.context.agent_id.as_bytes());

        let digest = Sha256::digest(&data).expect("Sha256 failed");
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }
}

// -----------------------------------------------------------------------------
// Agency Firewall Artifacts
// -----------------------------------------------------------------------------

/// Constraints on a user approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct ApprovalScope {
    /// UNIX timestamp when this approval expires.
    pub expires_at: u64,
    /// Optional: Usage count remaining (for session approvals).
    pub max_usages: Option<u32>,
}

/// Deterministic action selected for a PII review approval flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum PiiApprovalAction {
    /// Approve deterministic transform for this decision.
    ApproveTransform,
    /// Deny the pending PII decision.
    Deny,
    /// Grant a scoped low-severity raw exception.
    GrantScopedException,
}

/// A scoped, time-bounded authorization for an ActionRequest (User Consent).
/// Acts as a "2FA Token" for high-risk actions blocked by default policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ApprovalToken {
    /// Hash of the specific ActionRequest being approved.
    pub request_hash: [u8; 32],
    /// Constraints on the approval (e.g., max times usage, expiration).
    pub scope: ApprovalScope,

    /// [NEW] The hash of the visual context (screenshot) the user saw when approving.
    /// Used to restore the correct Set-of-Marks mapping.
    pub visual_hash: Option<[u8; 32]>,

    /// Optional PII review action attached to this approval.
    #[serde(default)]
    pub pii_action: Option<PiiApprovalAction>,

    /// Optional scoped exception attached for deterministic raw override.
    #[serde(default)]
    pub scoped_exception: Option<PiiScopedException>,

    /// Signature by the user's Local DID (Device Key).
    pub approver_sig: Vec<u8>,
    /// The cryptographic suite used for the signature.
    pub approver_suite: SignatureSuite,
}

/// The verdict rendered by the firewall policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum PolicyVerdict {
    /// Action matches an ALLOW rule.
    Allow,
    /// Action matches a BLOCK rule or Default Deny. Contains reason.
    Block(String),
    /// Action matches a REQUIRE_APPROVAL rule and a valid token was provided.
    /// Contains the hash of the ApprovalToken used.
    Approved([u8; 32]),
}

/// A Guardian-attested record of the firewall's decision.
/// This serves as the "Audit Log" or "Black Box" evidence in case of disputes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct FirewallDecisionReceipt {
    /// Hash of the canonical ActionRequest.
    pub request_hash: [u8; 32],
    /// Hash of the active policy ruleset used for evaluation.
    pub policy_hash: [u8; 32],
    /// The verdict rendered.
    pub verdict: PolicyVerdict,
    /// Monotonic sequence number for the local audit chain.
    pub seq: u64,
    /// Hash link to the previous receipt (Tamper-evident log).
    pub prev_receipt_hash: [u8; 32],
    /// Guardian attestation over the fields above.
    pub guardian_sig: Vec<u8>,
}
