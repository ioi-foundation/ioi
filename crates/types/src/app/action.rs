// Path: crates/types/src/app/action.rs

use crate::app::agentic::PiiScopedException;
use crate::app::{account_id_from_key_material, SignatureSuite};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
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
    /// Text-generation or responses-style model execution.
    #[serde(rename = "model::respond")]
    ModelRespond,
    /// Embedding generation over text, image, or similar inputs.
    #[serde(rename = "model::embed")]
    ModelEmbed,
    /// Candidate reranking over retrieval or planning results.
    #[serde(rename = "model::rerank")]
    ModelRerank,
    /// Transcript extraction from a media source with provenance.
    #[serde(rename = "media::extract_transcript")]
    MediaExtractTranscript,
    /// Multimodal media evidence extraction with provenance.
    #[serde(rename = "media::extract_multimodal_evidence")]
    MediaExtractMultimodalEvidence,
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
            ActionTarget::ModelRespond => "model::respond".to_string(),
            ActionTarget::ModelEmbed => "model::embed".to_string(),
            ActionTarget::ModelRerank => "model::rerank".to_string(),
            ActionTarget::MediaExtractTranscript => "media::extract_transcript".to_string(),
            ActionTarget::MediaExtractMultimodalEvidence => {
                "media::extract_multimodal_evidence".to_string()
            }
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
/// State key prefix for persisted policy decision records.
pub const POLICY_DECISION_STATE_PREFIX: &[u8] = b"agentic:policy:decision:v1:";
/// State key prefix for persisted settlement receipt bundles.
pub const SETTLEMENT_RECEIPT_BUNDLE_STATE_PREFIX: &[u8] = b"agentic:settlement:bundle:v1:";
/// State key prefix for persisted execution observation receipts.
pub const EXECUTION_OBSERVATION_RECEIPT_STATE_PREFIX: &[u8] =
    b"agentic:settlement:execution_receipt:v1:";
/// State key prefix for persisted postcondition proofs.
pub const POSTCONDITION_PROOF_STATE_PREFIX: &[u8] = b"agentic:settlement:postcondition:v1:";
/// State key prefix for persisted required receipt manifests.
pub const REQUIRED_RECEIPT_MANIFEST_STATE_PREFIX: &[u8] =
    b"agentic:settlement:manifest:v1:";

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

fn default_policy_decision_record_schema_version() -> u16 {
    1
}

#[derive(Debug, Serialize)]
struct PolicyDecisionHashMaterial<'a> {
    schema_version: u16,
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    verdict: &'a PolicyVerdict,
    matched_rules: &'a [String],
    default_policy: &'a str,
    lease_check_reason: Option<&'a str>,
    approval_required: bool,
}

/// Canonical authoritative record of the deterministic policy decision for an action request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PolicyDecisionRecord {
    /// Schema version for this policy decision format.
    #[serde(default = "default_policy_decision_record_schema_version")]
    pub schema_version: u16,
    /// Exact hash of the bound action request.
    pub request_hash: [u8; 32],
    /// Exact hash of the active policy ruleset used during evaluation.
    pub policy_hash: [u8; 32],
    /// Deterministically ordered identifiers for the rules that matched.
    #[serde(default)]
    pub matched_rules: Vec<String>,
    /// Default policy label used when no explicit rule matched.
    pub default_policy: String,
    /// Optional fail-closed lease denial reason observed during policy evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_check_reason: Option<String>,
    /// Whether this decision requires or consumed external approval.
    pub approval_required: bool,
    /// Final authoritative policy verdict for this request.
    pub verdict: PolicyVerdict,
    /// Canonical hash of this policy decision record.
    pub decision_hash: [u8; 32],
}

impl PolicyDecisionRecord {
    /// Builds a canonical policy decision record and computes its decision hash.
    pub fn build(
        request_hash: [u8; 32],
        policy_hash: [u8; 32],
        matched_rules: Vec<String>,
        default_policy: String,
        lease_check_reason: Option<String>,
        approval_required: bool,
        verdict: PolicyVerdict,
    ) -> Result<Self, ActionHashError> {
        let decision_hash = Self::compute_hash(
            request_hash,
            policy_hash,
            &matched_rules,
            &default_policy,
            lease_check_reason.as_deref(),
            approval_required,
            &verdict,
        )?;
        Ok(Self {
            schema_version: default_policy_decision_record_schema_version(),
            request_hash,
            policy_hash,
            matched_rules,
            default_policy,
            lease_check_reason,
            approval_required,
            verdict,
            decision_hash,
        })
    }

    /// Verifies that the stored decision hash matches the canonical decision material.
    pub fn verify(&self) -> Result<(), ActionHashError> {
        let expected = Self::compute_hash(
            self.request_hash,
            self.policy_hash,
            &self.matched_rules,
            &self.default_policy,
            self.lease_check_reason.as_deref(),
            self.approval_required,
            &self.verdict,
        )?;
        if self.decision_hash != expected {
            return Err(ActionHashError::Hash(
                "policy decision hash mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn compute_hash(
        request_hash: [u8; 32],
        policy_hash: [u8; 32],
        matched_rules: &[String],
        default_policy: &str,
        lease_check_reason: Option<&str>,
        approval_required: bool,
        verdict: &PolicyVerdict,
    ) -> Result<[u8; 32], ActionHashError> {
        use dcrypt::algorithms::hash::Sha256;

        let material = PolicyDecisionHashMaterial {
            schema_version: default_policy_decision_record_schema_version(),
            request_hash,
            policy_hash,
            verdict,
            matched_rules,
            default_policy,
            lease_check_reason,
            approval_required,
        };
        let canonical = serde_jcs::to_vec(&material)
            .map_err(|e| ActionHashError::Canonicalization(e.to_string()))?;
        let digest = Sha256::digest(&canonical).map_err(|e| ActionHashError::Hash(e.to_string()))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        Ok(out)
    }
}

/// Constructs the canonical state key for a persisted policy decision record.
pub fn policy_decision_state_key(session_id: [u8; 32], step_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        POLICY_DECISION_STATE_PREFIX.len() + session_id.len() + std::mem::size_of::<u32>(),
    );
    key.extend_from_slice(POLICY_DECISION_STATE_PREFIX);
    key.extend_from_slice(&session_id);
    key.extend_from_slice(&step_index.to_be_bytes());
    key
}

// -----------------------------------------------------------------------------
// Agency Firewall Artifacts
// -----------------------------------------------------------------------------

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

fn default_approval_grant_schema_version() -> u16 {
    1
}

fn default_approval_authority_schema_version() -> u16 {
    1
}

/// A registered approver identity that may issue [`ApprovalGrant`] artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ApprovalAuthority {
    /// Schema version for the authority registry artifact.
    #[serde(default = "default_approval_authority_schema_version")]
    pub schema_version: u16,
    /// Stable authority identifier derived from the public key.
    pub authority_id: [u8; 32],
    /// Public key used to verify approval grants from this authority.
    pub public_key: Vec<u8>,
    /// Signature suite used by this authority.
    pub signature_suite: SignatureSuite,
    /// Expiration timestamp in milliseconds for the authority registration.
    pub expires_at: u64,
    /// Whether this authority has been revoked.
    #[serde(default)]
    pub revoked: bool,
    /// Optional scope allowlist carried by the registry entry.
    #[serde(default)]
    pub scope_allowlist: Vec<String>,
}

impl ApprovalAuthority {
    /// Verifies structural integrity for a registered approval authority.
    pub fn verify(&self) -> Result<(), ActionHashError> {
        if self.schema_version != default_approval_authority_schema_version() {
            return Err(ActionHashError::Canonicalization(format!(
                "approval authority schema mismatch: expected {}, found {}",
                default_approval_authority_schema_version(),
                self.schema_version
            )));
        }
        if self.public_key.is_empty() {
            return Err(ActionHashError::Hash(
                "approval authority public key must not be empty".to_string(),
            ));
        }
        let derived_authority =
            account_id_from_key_material(self.signature_suite, &self.public_key)
                .map_err(|e| ActionHashError::Canonicalization(e.to_string()))?;
        if derived_authority != self.authority_id {
            return Err(ActionHashError::Hash(
                "approval authority_id does not match public key".to_string(),
            ));
        }
        if self.expires_at == 0 {
            return Err(ActionHashError::Hash(
                "approval authority expiry must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct ApprovalGrantSigningMaterial<'a> {
    schema_version: u16,
    authority_id: [u8; 32],
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    audience: [u8; 32],
    nonce: [u8; 32],
    counter: u64,
    expires_at: u64,
    max_usages: Option<u32>,
    window_id: Option<u64>,
    pii_action: &'a Option<PiiApprovalAction>,
    scoped_exception: &'a Option<PiiScopedException>,
    review_request_hash: Option<[u8; 32]>,
    approver_public_key: &'a [u8],
    approver_suite: SignatureSuite,
}

/// An externally signed approval artifact authorizing an exact action/policy binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ApprovalGrant {
    /// Schema version for approval grant verification rules.
    #[serde(default = "default_approval_grant_schema_version")]
    pub schema_version: u16,
    /// Stable authority identifier derived from the approver public key.
    pub authority_id: [u8; 32],
    /// Exact request hash this grant authorizes.
    pub request_hash: [u8; 32],
    /// Exact policy hash this grant authorizes under.
    pub policy_hash: [u8; 32],
    /// Audience identity this grant is valid for.
    pub audience: [u8; 32],
    /// Replay nonce for this grant.
    pub nonce: [u8; 32],
    /// Monotonic replay counter.
    pub counter: u64,
    /// Expiration timestamp in milliseconds.
    pub expires_at: u64,
    /// Optional bounded usage count for grant consumption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_usages: Option<u32>,
    /// Optional window binding for UI-scoped approvals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_id: Option<u64>,
    /// Optional PII review action bound to this approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii_action: Option<PiiApprovalAction>,
    /// Optional scoped exception bound to this approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped_exception: Option<PiiScopedException>,
    /// Optional review request hash when this grant answers a persisted review request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_request_hash: Option<[u8; 32]>,
    /// Approver public key used to verify the grant signature.
    pub approver_public_key: Vec<u8>,
    /// Signature over the canonical signing payload.
    pub approver_sig: Vec<u8>,
    /// Signature suite used by the approver.
    pub approver_suite: SignatureSuite,
}

impl ApprovalGrant {
    /// Returns canonical signing bytes for this grant excluding the signature itself.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ActionHashError> {
        let material = ApprovalGrantSigningMaterial {
            schema_version: self.schema_version,
            authority_id: self.authority_id,
            request_hash: self.request_hash,
            policy_hash: self.policy_hash,
            audience: self.audience,
            nonce: self.nonce,
            counter: self.counter,
            expires_at: self.expires_at,
            max_usages: self.max_usages,
            window_id: self.window_id,
            pii_action: &self.pii_action,
            scoped_exception: &self.scoped_exception,
            review_request_hash: self.review_request_hash,
            approver_public_key: &self.approver_public_key,
            approver_suite: self.approver_suite,
        };
        serde_jcs::to_vec(&material).map_err(|e| ActionHashError::Canonicalization(e.to_string()))
    }

    /// Returns a canonical content hash for this exact grant artifact.
    pub fn artifact_hash(&self) -> Result<[u8; 32], ActionHashError> {
        let canonical =
            serde_jcs::to_vec(self).map_err(|e| ActionHashError::Canonicalization(e.to_string()))?;
        let digest = Sha256::digest(&canonical).map_err(|e| ActionHashError::Hash(e.to_string()))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        Ok(out)
    }

    /// Verifies structural binding and signature validity for this approval grant.
    pub fn verify(&self) -> Result<(), ActionHashError> {
        if self.schema_version != default_approval_grant_schema_version() {
            return Err(ActionHashError::Canonicalization(format!(
                "approval grant schema mismatch: expected {}, found {}",
                default_approval_grant_schema_version(),
                self.schema_version
            )));
        }
        if self.request_hash == [0u8; 32] {
            return Err(ActionHashError::Hash(
                "approval grant request hash must not be zero".to_string(),
            ));
        }
        if self.policy_hash == [0u8; 32] {
            return Err(ActionHashError::Hash(
                "approval grant policy hash must not be zero".to_string(),
            ));
        }
        if self.audience == [0u8; 32] {
            return Err(ActionHashError::Hash(
                "approval grant audience must not be zero".to_string(),
            ));
        }
        if self.nonce == [0u8; 32] {
            return Err(ActionHashError::Hash(
                "approval grant nonce must not be zero".to_string(),
            ));
        }
        if self.counter == 0 {
            return Err(ActionHashError::Hash(
                "approval grant counter must be >= 1".to_string(),
            ));
        }
        if self.expires_at == 0 {
            return Err(ActionHashError::Hash(
                "approval grant expiry must be non-zero".to_string(),
            ));
        }
        if matches!(self.max_usages, Some(0)) {
            return Err(ActionHashError::Hash(
                "approval grant max_usages must be >= 1".to_string(),
            ));
        }
        if self.approver_public_key.is_empty() {
            return Err(ActionHashError::Hash(
                "approval grant public key must not be empty".to_string(),
            ));
        }
        if self.approver_sig.is_empty() {
            return Err(ActionHashError::Hash(
                "approval grant signature must not be empty".to_string(),
            ));
        }

        let derived_authority =
            account_id_from_key_material(self.approver_suite, &self.approver_public_key)
                .map_err(|e| ActionHashError::Canonicalization(e.to_string()))?;
        if derived_authority != self.authority_id {
            return Err(ActionHashError::Hash(
                "approval grant authority_id does not match public key".to_string(),
            ));
        }
        Ok(())
    }
}

fn default_settlement_receipt_bundle_schema_version() -> u16 {
    1
}

fn default_execution_observation_receipt_schema_version() -> u16 {
    1
}

fn default_postcondition_proof_schema_version() -> u16 {
    1
}

fn default_required_receipt_manifest_schema_version() -> u16 {
    1
}

#[derive(Debug, Serialize)]
struct ExecutionObservationHashMaterial<'a> {
    schema_version: u16,
    request_hash: [u8; 32],
    target: &'a str,
    observation_key: &'a str,
    success: bool,
    started_at_ms: u64,
    finished_at_ms: u64,
    history_entry: Option<&'a str>,
    error: Option<&'a str>,
    provider_id: Option<&'a str>,
    visual_artifact_hash: Option<[u8; 32]>,
}

/// Typed authoritative observation of an execution attempt and its terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ExecutionObservationReceipt {
    /// Schema version for this execution observation receipt format.
    #[serde(default = "default_execution_observation_receipt_schema_version")]
    pub schema_version: u16,
    /// Exact hash of the bound action request.
    pub request_hash: [u8; 32],
    /// Canonical action target label that produced this receipt.
    pub target: String,
    /// Stable receipt key describing the observation class.
    pub observation_key: String,
    /// Whether the observed execution reached a successful terminal state.
    pub success: bool,
    /// Start timestamp for the observed execution interval in milliseconds.
    pub started_at_ms: u64,
    /// End timestamp for the observed execution interval in milliseconds.
    pub finished_at_ms: u64,
    /// Optional execution history entry emitted by the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_entry: Option<String>,
    /// Optional terminal error emitted by the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Optional provider identifier when the execution was routed through a connector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// Optional persisted visual artifact hash associated with this execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visual_artifact_hash: Option<[u8; 32]>,
    /// Canonical hash of the full observation receipt artifact.
    pub receipt_hash: [u8; 32],
}

impl ExecutionObservationReceipt {
    /// Builds a canonical execution observation receipt and computes its receipt hash.
    pub fn build(
        request_hash: [u8; 32],
        target: String,
        observation_key: String,
        success: bool,
        started_at_ms: u64,
        finished_at_ms: u64,
        history_entry: Option<String>,
        error: Option<String>,
        provider_id: Option<String>,
        visual_artifact_hash: Option<[u8; 32]>,
    ) -> Result<Self, ActionHashError> {
        let receipt_hash = Self::compute_hash(
            request_hash,
            &target,
            &observation_key,
            success,
            started_at_ms,
            finished_at_ms,
            history_entry.as_deref(),
            error.as_deref(),
            provider_id.as_deref(),
            visual_artifact_hash,
        )?;
        Ok(Self {
            schema_version: default_execution_observation_receipt_schema_version(),
            request_hash,
            target,
            observation_key,
            success,
            started_at_ms,
            finished_at_ms,
            history_entry,
            error,
            provider_id,
            visual_artifact_hash,
            receipt_hash,
        })
    }

    /// Verifies that the stored receipt hash matches the canonical observation material.
    pub fn verify(&self) -> Result<(), ActionHashError> {
        let expected = Self::compute_hash(
            self.request_hash,
            &self.target,
            &self.observation_key,
            self.success,
            self.started_at_ms,
            self.finished_at_ms,
            self.history_entry.as_deref(),
            self.error.as_deref(),
            self.provider_id.as_deref(),
            self.visual_artifact_hash,
        )?;
        if self.receipt_hash != expected {
            return Err(ActionHashError::Hash(
                "execution observation receipt hash mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn compute_hash(
        request_hash: [u8; 32],
        target: &str,
        observation_key: &str,
        success: bool,
        started_at_ms: u64,
        finished_at_ms: u64,
        history_entry: Option<&str>,
        error: Option<&str>,
        provider_id: Option<&str>,
        visual_artifact_hash: Option<[u8; 32]>,
    ) -> Result<[u8; 32], ActionHashError> {
        let material = ExecutionObservationHashMaterial {
            schema_version: default_execution_observation_receipt_schema_version(),
            request_hash,
            target,
            observation_key,
            success,
            started_at_ms,
            finished_at_ms,
            history_entry,
            error,
            provider_id,
            visual_artifact_hash,
        };
        let canonical = serde_jcs::to_vec(&material)
            .map_err(|e| ActionHashError::Canonicalization(e.to_string()))?;
        let digest = Sha256::digest(&canonical).map_err(|e| ActionHashError::Hash(e.to_string()))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        Ok(out)
    }
}

#[derive(Debug, Serialize)]
struct PostconditionProofHashMaterial<'a> {
    schema_version: u16,
    request_hash: [u8; 32],
    proof_key: &'a str,
    satisfied: bool,
    observed_value: Option<&'a str>,
    evidence_type: Option<&'a str>,
    provider_id: Option<&'a str>,
    timestamp_ms: u64,
}

/// Typed authoritative postcondition proof bound to a request hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PostconditionProof {
    /// Schema version for this postcondition proof format.
    #[serde(default = "default_postcondition_proof_schema_version")]
    pub schema_version: u16,
    /// Exact hash of the bound action request.
    pub request_hash: [u8; 32],
    /// Stable proof key describing the postcondition this artifact covers.
    pub proof_key: String,
    /// Whether the postcondition was satisfied.
    pub satisfied: bool,
    /// Optional observed value captured while evaluating the postcondition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_value: Option<String>,
    /// Optional evidence type label describing the observation material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_type: Option<String>,
    /// Optional provider identifier when the postcondition came from a connector verifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// Timestamp in milliseconds when the proof was recorded.
    pub timestamp_ms: u64,
    /// Canonical hash of the full postcondition proof artifact.
    pub proof_hash: [u8; 32],
}

impl PostconditionProof {
    /// Builds a canonical postcondition proof and computes its proof hash.
    pub fn build(
        request_hash: [u8; 32],
        proof_key: String,
        satisfied: bool,
        observed_value: Option<String>,
        evidence_type: Option<String>,
        provider_id: Option<String>,
        timestamp_ms: u64,
    ) -> Result<Self, ActionHashError> {
        let proof_hash = Self::compute_hash(
            request_hash,
            &proof_key,
            satisfied,
            observed_value.as_deref(),
            evidence_type.as_deref(),
            provider_id.as_deref(),
            timestamp_ms,
        )?;
        Ok(Self {
            schema_version: default_postcondition_proof_schema_version(),
            request_hash,
            proof_key,
            satisfied,
            observed_value,
            evidence_type,
            provider_id,
            timestamp_ms,
            proof_hash,
        })
    }

    /// Verifies that the stored proof hash matches the canonical proof material.
    pub fn verify(&self) -> Result<(), ActionHashError> {
        let expected = Self::compute_hash(
            self.request_hash,
            &self.proof_key,
            self.satisfied,
            self.observed_value.as_deref(),
            self.evidence_type.as_deref(),
            self.provider_id.as_deref(),
            self.timestamp_ms,
        )?;
        if self.proof_hash != expected {
            return Err(ActionHashError::Hash(
                "postcondition proof hash mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn compute_hash(
        request_hash: [u8; 32],
        proof_key: &str,
        satisfied: bool,
        observed_value: Option<&str>,
        evidence_type: Option<&str>,
        provider_id: Option<&str>,
        timestamp_ms: u64,
    ) -> Result<[u8; 32], ActionHashError> {
        let material = PostconditionProofHashMaterial {
            schema_version: default_postcondition_proof_schema_version(),
            request_hash,
            proof_key,
            satisfied,
            observed_value,
            evidence_type,
            provider_id,
            timestamp_ms,
        };
        let canonical = serde_jcs::to_vec(&material)
            .map_err(|e| ActionHashError::Canonicalization(e.to_string()))?;
        let digest = Sha256::digest(&canonical).map_err(|e| ActionHashError::Hash(e.to_string()))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        Ok(out)
    }
}

#[derive(Debug, Serialize)]
struct RequiredReceiptManifestHashMaterial<'a> {
    schema_version: u16,
    target: &'a str,
    required_execution_receipt_keys: &'a [String],
    required_postcondition_keys: &'a [String],
}

/// Canonical manifest declaring the required receipt and proof set for a request target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct RequiredReceiptManifest {
    /// Schema version for this required receipt manifest format.
    #[serde(default = "default_required_receipt_manifest_schema_version")]
    pub schema_version: u16,
    /// Canonical action target label this manifest governs.
    pub target: String,
    /// Ordered list of required execution receipt keys for settlement completeness.
    #[serde(default)]
    pub required_execution_receipt_keys: Vec<String>,
    /// Ordered list of required postcondition proof keys for settlement completeness.
    #[serde(default)]
    pub required_postcondition_keys: Vec<String>,
    /// Canonical hash of the full required receipt manifest.
    pub manifest_hash: [u8; 32],
}

impl RequiredReceiptManifest {
    /// Builds a canonical required receipt manifest and computes its manifest hash.
    pub fn build(
        target: String,
        required_execution_receipt_keys: Vec<String>,
        required_postcondition_keys: Vec<String>,
    ) -> Result<Self, ActionHashError> {
        let manifest_hash = Self::compute_hash(
            &target,
            &required_execution_receipt_keys,
            &required_postcondition_keys,
        )?;
        Ok(Self {
            schema_version: default_required_receipt_manifest_schema_version(),
            target,
            required_execution_receipt_keys,
            required_postcondition_keys,
            manifest_hash,
        })
    }

    /// Verifies that the stored manifest hash matches the canonical manifest material.
    pub fn verify(&self) -> Result<(), ActionHashError> {
        let expected = Self::compute_hash(
            &self.target,
            &self.required_execution_receipt_keys,
            &self.required_postcondition_keys,
        )?;
        if self.manifest_hash != expected {
            return Err(ActionHashError::Hash(
                "required receipt manifest hash mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn compute_hash(
        target: &str,
        required_execution_receipt_keys: &[String],
        required_postcondition_keys: &[String],
    ) -> Result<[u8; 32], ActionHashError> {
        let material = RequiredReceiptManifestHashMaterial {
            schema_version: default_required_receipt_manifest_schema_version(),
            target,
            required_execution_receipt_keys,
            required_postcondition_keys,
        };
        let canonical = serde_jcs::to_vec(&material)
            .map_err(|e| ActionHashError::Canonicalization(e.to_string()))?;
        let digest = Sha256::digest(&canonical).map_err(|e| ActionHashError::Hash(e.to_string()))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        Ok(out)
    }
}

#[derive(Debug, Serialize)]
struct SettlementBundleHashMaterial<'a> {
    schema_version: u16,
    request_hash: [u8; 32],
    committed_action_hash: [u8; 32],
    policy_decision_hash: [u8; 32],
    approval_grant_hash: Option<[u8; 32]>,
    execution_receipt_hashes: &'a [[u8; 32]],
    postcondition_proof_hashes: &'a [[u8; 32]],
    required_receipt_manifest_hash: Option<[u8; 32]>,
    prev_bundle_hash: Option<[u8; 32]>,
    settlement_status: &'a str,
}

/// Minimal canonical settlement bundle tying together the authoritative execution artifact chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SettlementReceiptBundle {
    /// Schema version for this settlement bundle format.
    #[serde(default = "default_settlement_receipt_bundle_schema_version")]
    pub schema_version: u16,
    /// Exact hash of the bound action request.
    pub request_hash: [u8; 32],
    /// Canonical hash of the committed action artifact.
    pub committed_action_hash: [u8; 32],
    /// Canonical hash of the authoritative policy decision record.
    pub policy_decision_hash: [u8; 32],
    /// Optional hash of the approval artifact authorizing the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_grant_hash: Option<[u8; 32]>,
    /// Canonical hashes of execution observation receipts included in this bundle.
    #[serde(default)]
    pub execution_receipt_hashes: Vec<[u8; 32]>,
    /// Canonical hashes of postcondition proofs included in this bundle.
    #[serde(default)]
    pub postcondition_proof_hashes: Vec<[u8; 32]>,
    /// Optional hash of the manifest describing required receipts and proofs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_receipt_manifest_hash: Option<[u8; 32]>,
    /// Optional hash of the prior settlement bundle in this lineage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_bundle_hash: Option<[u8; 32]>,
    /// Machine-readable settlement status for this bundle.
    pub settlement_status: String,
    /// Canonical root hash over the bundle contents.
    pub artifact_root_hash: [u8; 32],
}

impl SettlementReceiptBundle {
    /// Builds a canonical settlement receipt bundle and computes its artifact root hash.
    pub fn build(
        request_hash: [u8; 32],
        committed_action_hash: [u8; 32],
        policy_decision_hash: [u8; 32],
        approval_grant_hash: Option<[u8; 32]>,
        execution_receipt_hashes: Vec<[u8; 32]>,
        postcondition_proof_hashes: Vec<[u8; 32]>,
        required_receipt_manifest_hash: Option<[u8; 32]>,
        prev_bundle_hash: Option<[u8; 32]>,
        settlement_status: String,
    ) -> Result<Self, ActionHashError> {
        let artifact_root_hash = Self::compute_hash(
            request_hash,
            committed_action_hash,
            policy_decision_hash,
            approval_grant_hash,
            &execution_receipt_hashes,
            &postcondition_proof_hashes,
            required_receipt_manifest_hash,
            prev_bundle_hash,
            &settlement_status,
        )?;
        Ok(Self {
            schema_version: default_settlement_receipt_bundle_schema_version(),
            request_hash,
            committed_action_hash,
            policy_decision_hash,
            approval_grant_hash,
            execution_receipt_hashes,
            postcondition_proof_hashes,
            required_receipt_manifest_hash,
            prev_bundle_hash,
            settlement_status,
            artifact_root_hash,
        })
    }

    /// Verifies that the stored artifact root hash matches the canonical bundle material.
    pub fn verify(&self) -> Result<(), ActionHashError> {
        let expected = Self::compute_hash(
            self.request_hash,
            self.committed_action_hash,
            self.policy_decision_hash,
            self.approval_grant_hash,
            &self.execution_receipt_hashes,
            &self.postcondition_proof_hashes,
            self.required_receipt_manifest_hash,
            self.prev_bundle_hash,
            &self.settlement_status,
        )?;
        if self.artifact_root_hash != expected {
            return Err(ActionHashError::Hash(
                "settlement receipt bundle hash mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn compute_hash(
        request_hash: [u8; 32],
        committed_action_hash: [u8; 32],
        policy_decision_hash: [u8; 32],
        approval_grant_hash: Option<[u8; 32]>,
        execution_receipt_hashes: &[[u8; 32]],
        postcondition_proof_hashes: &[[u8; 32]],
        required_receipt_manifest_hash: Option<[u8; 32]>,
        prev_bundle_hash: Option<[u8; 32]>,
        settlement_status: &str,
    ) -> Result<[u8; 32], ActionHashError> {
        use dcrypt::algorithms::hash::Sha256;

        let material = SettlementBundleHashMaterial {
            schema_version: default_settlement_receipt_bundle_schema_version(),
            request_hash,
            committed_action_hash,
            policy_decision_hash,
            approval_grant_hash,
            execution_receipt_hashes,
            postcondition_proof_hashes,
            required_receipt_manifest_hash,
            prev_bundle_hash,
            settlement_status,
        };
        let canonical = serde_jcs::to_vec(&material)
            .map_err(|e| ActionHashError::Canonicalization(e.to_string()))?;
        let digest = Sha256::digest(&canonical).map_err(|e| ActionHashError::Hash(e.to_string()))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        Ok(out)
    }
}

/// Constructs the canonical state key for a persisted settlement receipt bundle.
pub fn settlement_receipt_bundle_state_key(session_id: [u8; 32], step_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        SETTLEMENT_RECEIPT_BUNDLE_STATE_PREFIX.len()
            + session_id.len()
            + std::mem::size_of::<u32>(),
    );
    key.extend_from_slice(SETTLEMENT_RECEIPT_BUNDLE_STATE_PREFIX);
    key.extend_from_slice(&session_id);
    key.extend_from_slice(&step_index.to_be_bytes());
    key
}

/// Constructs the canonical state key for an execution observation receipt.
pub fn execution_observation_receipt_state_key(
    session_id: [u8; 32],
    step_index: u32,
    receipt_index: u16,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        EXECUTION_OBSERVATION_RECEIPT_STATE_PREFIX.len()
            + session_id.len()
            + std::mem::size_of::<u32>()
            + std::mem::size_of::<u16>(),
    );
    key.extend_from_slice(EXECUTION_OBSERVATION_RECEIPT_STATE_PREFIX);
    key.extend_from_slice(&session_id);
    key.extend_from_slice(&step_index.to_be_bytes());
    key.extend_from_slice(&receipt_index.to_be_bytes());
    key
}

/// Constructs the canonical state key for a postcondition proof.
pub fn postcondition_proof_state_key(
    session_id: [u8; 32],
    step_index: u32,
    proof_index: u16,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        POSTCONDITION_PROOF_STATE_PREFIX.len()
            + session_id.len()
            + std::mem::size_of::<u32>()
            + std::mem::size_of::<u16>(),
    );
    key.extend_from_slice(POSTCONDITION_PROOF_STATE_PREFIX);
    key.extend_from_slice(&session_id);
    key.extend_from_slice(&step_index.to_be_bytes());
    key.extend_from_slice(&proof_index.to_be_bytes());
    key
}

/// Constructs the canonical state key for a required receipt manifest.
pub fn required_receipt_manifest_state_key(session_id: [u8; 32], step_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        REQUIRED_RECEIPT_MANIFEST_STATE_PREFIX.len()
            + session_id.len()
            + std::mem::size_of::<u32>(),
    );
    key.extend_from_slice(REQUIRED_RECEIPT_MANIFEST_STATE_PREFIX);
    key.extend_from_slice(&session_id);
    key.extend_from_slice(&step_index.to_be_bytes());
    key
}

/// The verdict rendered by the firewall policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum PolicyVerdict {
    /// Action matches an ALLOW rule.
    Allow,
    /// Action matches a BLOCK rule or Default Deny. Contains reason.
    Block(String),
    /// Action matches a REQUIRE_APPROVAL rule and a valid grant was provided.
    /// Contains the hash of the ApprovalGrant used.
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
#[path = "action/tests.rs"]
mod tests;
