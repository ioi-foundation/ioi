// Path: crates/types/src/app/action.rs

use crate::app::agentic::PiiScopedException;
use crate::app::SignatureSuite;
use dcrypt::algorithms::hash::HashFunction;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

    /// Inspect the current UI state without pixel capture (e.g., accessibility tree snapshot).
    #[serde(rename = "gui::inspect")]
    GuiInspect,
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
            ActionTarget::GuiInspect => "gui::inspect".to_string(),
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

/// Errors returned while canonicalizing or hashing an [`ActionRequest`].
#[derive(Debug, Error)]
pub enum ActionHashError {
    /// `params` bytes were not valid JSON and could not be normalized.
    #[error("action params must be valid JSON: {0}")]
    InvalidParamsJson(String),
    /// RFC 8785 JCS canonicalization failed.
    #[error("action request canonicalization failed: {0}")]
    Canonicalization(String),
    /// SHA-256 hashing failed.
    #[error("action request hashing failed: {0}")]
    Hash(String),
}

#[derive(Debug, Serialize)]
struct ActionContextHashMaterial<'a> {
    agent_id: &'a str,
    session_id: Option<[u8; 32]>,
    window_id: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ActionRequestHashMaterial<'a> {
    target: String,
    params: serde_json::Value,
    context: ActionContextHashMaterial<'a>,
    nonce: u64,
}

impl ActionRequest {
    /// Returns deterministic RFC 8785 JCS bytes for this request.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ActionHashError> {
        let params_value = serde_json::from_slice(&self.params)
            .map_err(|e| ActionHashError::InvalidParamsJson(e.to_string()))?;

        let material = ActionRequestHashMaterial {
            target: self.target.canonical_label(),
            params: params_value,
            context: ActionContextHashMaterial {
                agent_id: &self.context.agent_id,
                session_id: self.context.session_id,
                window_id: self.context.window_id,
            },
            nonce: self.nonce,
        };

        serde_jcs::to_vec(&material).map_err(|e| ActionHashError::Canonicalization(e.to_string()))
    }

    /// Creates a deterministic hash of the action request for signing or logging.
    /// Hashing is fail-closed: invalid/canonicalization failures are returned as errors.
    pub fn try_hash(&self) -> Result<[u8; 32], ActionHashError> {
        use dcrypt::algorithms::hash::Sha256;

        let canonical = self.canonical_bytes()?;
        let digest =
            Sha256::digest(&canonical).map_err(|e| ActionHashError::Hash(e.to_string()))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        Ok(out)
    }

    /// Creates a deterministic hash of the action request.
    /// For call sites that cannot fail yet, this panics on invalid/non-canonical inputs.
    pub fn hash(&self) -> [u8; 32] {
        self.try_hash()
            .expect("ActionRequest::hash failed: request must be JSON and JCS canonicalizable")
    }
}

fn default_committed_action_schema_version() -> u16 {
    1
}

/// State key prefix for persisted deterministic commit artifacts.
pub const DETERMINISM_COMMIT_STATE_PREFIX: &[u8] = b"agentic:determinism:commit:v1:";
/// State key prefix for persisted deterministic verification evidence bundles.
pub const DETERMINISM_EVIDENCE_STATE_PREFIX: &[u8] = b"agentic:determinism:evidence:v1:";
/// State key prefix for persisted deterministic step contract evidence bundles.
pub const DETERMINISM_STEP_CONTRACT_STATE_PREFIX: &[u8] = b"agentic:determinism:contract:v1:";

/// Errors returned while creating or verifying a [`CommittedAction`].
#[derive(Debug, Error)]
pub enum CommittedActionError {
    /// Failed to hash the bound action request.
    #[error(transparent)]
    RequestHash(#[from] ActionHashError),
    /// RFC 8785 JCS canonicalization failed for commitment material.
    #[error("committed action canonicalization failed: {0}")]
    Canonicalization(String),
    /// SHA-256 hashing failed for commitment material.
    #[error("committed action hashing failed: {0}")]
    Hash(String),
    /// Schema version mismatch while verifying a committed action.
    #[error("committed action schema mismatch: expected {expected}, found {found}")]
    SchemaMismatch {
        /// Expected schema version.
        expected: u16,
        /// Found schema version in the artifact.
        found: u16,
    },
    /// The bound action request hash does not match the committed hash.
    #[error("committed action request hash mismatch")]
    RequestHashMismatch,
    /// The bound policy hash does not match the expected active policy hash.
    #[error("committed action policy hash mismatch")]
    PolicyHashMismatch,
    /// The bound window context does not match the request context.
    #[error("committed action window binding mismatch")]
    WindowBindingMismatch,
    /// The approval reference does not match expected approval linkage.
    #[error("committed action approval reference mismatch")]
    ApprovalRefMismatch,
    /// The commitment hash does not match recomputed commitment material.
    #[error("committed action commitment hash mismatch")]
    CommitmentHashMismatch,
}

#[derive(Debug, Serialize)]
struct CommittedActionHashMaterial {
    schema_version: u16,
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    window_id: Option<u64>,
    approval_ref: Option<[u8; 32]>,
}

/// Deterministic commit artifact that gates side effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct CommittedAction {
    /// Schema version for this commit artifact format.
    #[serde(default = "default_committed_action_schema_version")]
    pub schema_version: u16,
    /// Canonical hash of the bound [`ActionRequest`].
    pub request_hash: [u8; 32],
    /// Canonical hash of the active policy ruleset used for authorization.
    pub policy_hash: [u8; 32],
    /// Optional deterministic window binding used for UI/browser execution context.
    pub window_id: Option<u64>,
    /// Optional hash reference to the approval artifact authorizing this action.
    #[serde(default)]
    pub approval_ref: Option<[u8; 32]>,
    /// Canonical hash of the commitment material.
    pub commitment_hash: [u8; 32],
}

impl CommittedAction {
    /// Builds a deterministic commitment for an authorized action.
    pub fn commit(
        request: &ActionRequest,
        policy_hash: [u8; 32],
        approval_ref: Option<[u8; 32]>,
    ) -> Result<Self, CommittedActionError> {
        let request_hash = request.try_hash()?;
        let window_id = request.context.window_id;
        let commitment_hash =
            Self::compute_commitment_hash(request_hash, policy_hash, window_id, approval_ref)?;

        Ok(Self {
            schema_version: default_committed_action_schema_version(),
            request_hash,
            policy_hash,
            window_id,
            approval_ref,
            commitment_hash,
        })
    }

    /// Verifies the commitment against the request, expected policy hash, and approval reference.
    pub fn verify(
        &self,
        request: &ActionRequest,
        expected_policy_hash: [u8; 32],
        expected_approval_ref: Option<[u8; 32]>,
    ) -> Result<(), CommittedActionError> {
        let expected_schema = default_committed_action_schema_version();
        if self.schema_version != expected_schema {
            return Err(CommittedActionError::SchemaMismatch {
                expected: expected_schema,
                found: self.schema_version,
            });
        }

        let request_hash = request.try_hash()?;
        if self.request_hash != request_hash {
            return Err(CommittedActionError::RequestHashMismatch);
        }
        if self.policy_hash != expected_policy_hash {
            return Err(CommittedActionError::PolicyHashMismatch);
        }

        let expected_window = request.context.window_id;
        if self.window_id != expected_window {
            return Err(CommittedActionError::WindowBindingMismatch);
        }
        if self.approval_ref != expected_approval_ref {
            return Err(CommittedActionError::ApprovalRefMismatch);
        }

        let expected_commitment = Self::compute_commitment_hash(
            self.request_hash,
            self.policy_hash,
            self.window_id,
            self.approval_ref,
        )?;
        if self.commitment_hash != expected_commitment {
            return Err(CommittedActionError::CommitmentHashMismatch);
        }

        Ok(())
    }

    fn compute_commitment_hash(
        request_hash: [u8; 32],
        policy_hash: [u8; 32],
        window_id: Option<u64>,
        approval_ref: Option<[u8; 32]>,
    ) -> Result<[u8; 32], CommittedActionError> {
        use dcrypt::algorithms::hash::Sha256;

        let material = CommittedActionHashMaterial {
            schema_version: default_committed_action_schema_version(),
            request_hash,
            policy_hash,
            window_id,
            approval_ref,
        };

        let canonical = serde_jcs::to_vec(&material)
            .map_err(|e| CommittedActionError::Canonicalization(e.to_string()))?;
        let digest =
            Sha256::digest(&canonical).map_err(|e| CommittedActionError::Hash(e.to_string()))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        Ok(out)
    }
}

fn default_determinism_evidence_schema_version() -> u16 {
    1
}

/// Deterministic evidence bundle persisted for public verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct DeterminismEvidence {
    /// Schema version for this evidence bundle.
    #[serde(default = "default_determinism_evidence_schema_version")]
    pub schema_version: u16,
    /// Canonical action request that was committed before side effects.
    pub request: ActionRequest,
    /// Committed action artifact bound to `request`.
    pub committed_action: CommittedAction,
    /// Whether this commit was recorded as a retry/recovery action.
    #[serde(default)]
    pub recovery_retry: bool,
    /// Optional machine-readable retry/recovery reason.
    #[serde(default)]
    pub recovery_reason: Option<String>,
}

impl DeterminismEvidence {
    /// Returns the expected schema version for deterministic evidence bundles.
    pub fn schema_version() -> u16 {
        default_determinism_evidence_schema_version()
    }
}

/// Constructs the canonical state key for a persisted committed action.
pub fn determinism_commit_state_key(session_id: [u8; 32], step_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        DETERMINISM_COMMIT_STATE_PREFIX.len() + session_id.len() + std::mem::size_of::<u32>(),
    );
    key.extend_from_slice(DETERMINISM_COMMIT_STATE_PREFIX);
    key.extend_from_slice(&session_id);
    key.extend_from_slice(&step_index.to_be_bytes());
    key
}

/// Constructs the canonical state key for a persisted determinism evidence bundle.
pub fn determinism_evidence_state_key(session_id: [u8; 32], step_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        DETERMINISM_EVIDENCE_STATE_PREFIX.len() + session_id.len() + std::mem::size_of::<u32>(),
    );
    key.extend_from_slice(DETERMINISM_EVIDENCE_STATE_PREFIX);
    key.extend_from_slice(&session_id);
    key.extend_from_slice(&step_index.to_be_bytes());
    key
}

fn default_determinism_step_contract_schema_version() -> u16 {
    1
}

/// Deterministic step-scoped completion evidence used to verify required receipt sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct DeterminismStepContractEvidence {
    /// Schema version for this step contract evidence format.
    #[serde(default = "default_determinism_step_contract_schema_version")]
    pub schema_version: u16,
    /// Resolved intent identifier associated with the completed step.
    pub intent_id: String,
    /// Receipts observed for this step.
    #[serde(default)]
    pub receipts: Vec<String>,
    /// Postconditions observed for this step.
    #[serde(default)]
    pub postconditions: Vec<String>,
    /// Whether the step was executed as an explicit retry/recovery action.
    #[serde(default)]
    pub recovery_retry: bool,
    /// Optional machine-readable recovery reason.
    #[serde(default)]
    pub recovery_reason: Option<String>,
}

impl DeterminismStepContractEvidence {
    /// Returns the expected schema version for step contract evidence bundles.
    pub fn schema_version() -> u16 {
        default_determinism_step_contract_schema_version()
    }
}

/// Constructs the canonical state key for step-scoped deterministic contract evidence.
pub fn determinism_step_contract_state_key(session_id: [u8; 32], step_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        DETERMINISM_STEP_CONTRACT_STATE_PREFIX.len()
            + session_id.len()
            + std::mem::size_of::<u32>(),
    );
    key.extend_from_slice(DETERMINISM_STEP_CONTRACT_STATE_PREFIX);
    key.extend_from_slice(&session_id);
    key.extend_from_slice(&step_index.to_be_bytes());
    key
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
    /// Approval token schema version.
    /// v2 introduces explicit audience/revocation/replay bindings.
    #[serde(default = "default_approval_token_schema_version")]
    pub schema_version: u16,
    /// Hash of the specific ActionRequest being approved.
    pub request_hash: [u8; 32],
    /// Audience identity this token is valid for (executor/guardian account id).
    #[serde(default)]
    pub audience: [u8; 32],
    /// Minimum active revocation epoch required for this token to remain valid.
    #[serde(default)]
    pub revocation_epoch: u64,
    /// Token replay nonce.
    #[serde(default)]
    pub nonce: [u8; 32],
    /// Monotonic token replay counter.
    #[serde(default)]
    pub counter: u64,
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

fn default_approval_token_schema_version() -> u16 {
    2
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

#[cfg(test)]
mod tests {
    use super::{
        ActionContext, ActionHashError, ActionRequest, ActionTarget, CommittedAction,
        CommittedActionError,
    };

    fn base_request(window_id: Option<u64>) -> ActionRequest {
        ActionRequest {
            target: ActionTarget::GuiClick,
            params: serde_jcs::to_vec(&serde_json::json!({
                "x": 10,
                "y": 20,
                "button": "left",
            }))
            .expect("params should canonicalize"),
            context: ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: Some([7u8; 32]),
                window_id,
            },
            nonce: 1,
        }
    }

    #[test]
    fn action_request_hash_changes_when_window_binding_changes() {
        let a = base_request(Some(111));
        let b = base_request(Some(222));

        assert_ne!(a.try_hash().expect("hash"), b.try_hash().expect("hash"));
    }

    #[test]
    fn action_request_try_hash_rejects_non_json_params() {
        let mut req = base_request(Some(5));
        req.params = vec![0xFF, 0xFE];

        let err = req.try_hash().expect_err("invalid json params should fail");
        assert!(matches!(err, ActionHashError::InvalidParamsJson(_)));
    }

    #[test]
    fn committed_action_verify_rejects_policy_hash_mismatch() {
        let req = base_request(Some(1));
        let committed = CommittedAction::commit(&req, [1u8; 32], None).expect("commit");

        let err = committed
            .verify(&req, [2u8; 32], None)
            .expect_err("policy mismatch should fail");
        assert!(matches!(err, CommittedActionError::PolicyHashMismatch));
    }
}
