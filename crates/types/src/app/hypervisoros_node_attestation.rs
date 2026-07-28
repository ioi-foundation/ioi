//! HypervisorOS node-attestation plane (M2): the node-side trust ladder the
//! membership plane's admission evidence hangs from.
//!
//! Desired boot posture (`HypervisorOSBootProfile`) and declared freshness
//! policy (`TemporalVerificationProfile`) are owner-authorized records with
//! their own content roots; the observed side (`HypervisorOSNode` records and
//! `HypervisorOSBootReceipt`s) compiles as strict compare-and-swap steps over
//! the durable node record set. Every admission input is resolved from trusted
//! server truth, never asserted by the caller (`INV-37`): the boot-receipt
//! observation, the temporal validity evaluation, and any enforcement-coverage
//! declarations arrive as durable resolved values.
//!
//! A boot receipt compiles to `verified` only when, jointly: the observed
//! measurements equal the declared profile floors, the effective posture
//! satisfies the required posture, the appraisal passed with a consumed
//! single-use nonce and current revocation state, the observed rollback
//! counter is at or above the declared floor (and never below a previously
//! verified counter, with a strictly advancing boot epoch), the node identity
//! signature chain validates against the admitted sealed-identity public
//! binding, and the resolved `TemporalValidityEvaluation` establishes every
//! claim the declared temporal profile requires with an `online_fresh`
//! posture. Node readiness is derivable only from a bound verified receipt:
//! ready-before-proof is structurally impossible. Sealed identity material
//! never appears here — records carry only the public key, a recomputable
//! commitment, and the wallet.network sealing alias reference.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::generated::architecture_contracts::validate_architecture_contract;

use super::system_activation::{jcs_hash, required_string};

/// Registered HypervisorOS node identity record contract.
pub const HYPERVISOROS_NODE_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/hypervisoros-node/v1";
/// Registered DESIRED boot posture contract.
pub const BOOT_PROFILE_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/hypervisoros-boot-profile/v1";
/// Registered OBSERVED measured-boot receipt contract.
pub const BOOT_RECEIPT_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/hypervisoros-boot-receipt/v1";
/// Registered declared freshness-policy contract.
pub const TEMPORAL_PROFILE_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/temporal-verification-profile/v1";
/// Registered per-claim temporal evaluation contract.
pub const TEMPORAL_EVALUATION_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/temporal-validity-evaluation/v1";
/// Already-registered enforcement-coverage substrate this plane integrates.
pub const ENFORCEMENT_COVERAGE_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/enforcement-coverage-declaration/v1";

/// Content root domain of one timeless node record revision.
pub const NODE_RECORD_HASH_PROFILE: &str = "ioi.hypervisoros-node-record-jcs-sha256.v1";
/// Content root domain of the live node record set.
pub const NODE_SET_HASH_PROFILE: &str = "ioi.hypervisoros-node-set-jcs-sha256.v1";
/// Content root domain of one declared boot profile.
pub const BOOT_PROFILE_HASH_PROFILE: &str = "ioi.hypervisoros-boot-profile-jcs-sha256.v1";
/// Content root domain of one declared temporal-verification-profile record.
pub const TEMPORAL_PROFILE_HASH_PROFILE: &str =
    "ioi.temporal-verification-profile-record-jcs-sha256.v1";
/// Content root domain of one timeless committed boot receipt.
pub const BOOT_RECEIPT_HASH_PROFILE: &str = "ioi.hypervisoros-boot-receipt-jcs-sha256.v1";
/// Operation commitment domain over the closed governed effect.
pub const NODE_OPERATION_HASH_PROFILE: &str =
    "ioi.hypervisoros-node-operation-commitment-jcs-sha256.v1";
/// Public identity-key commitment domain (public binding only, never material).
pub const IDENTITY_COMMITMENT_HASH_PROFILE: &str =
    "ioi.hypervisoros-node-identity-commitment-jcs-sha256.v1";
/// Signed-material domain: receipt identity plus complete observation only.
pub const SIGNED_MATERIAL_HASH_PROFILE: &str =
    "ioi.hypervisoros-boot-receipt-signed-material-jcs-sha256.v1";

const WORKER_SUBSTRATES: [&str; 5] = ["vm", "microvm", "container", "wasm", "model_server"];
const MOUNT_PROFILES: [&str; 4] = [
    "public_mount",
    "redacted_mount",
    "plaintext_free_model_mount",
    "ctee_private_workspace",
];
const FORBIDDEN_BYPASSES: [&str; 5] = [
    "direct_plaintext_private_mount",
    "unreceipted_tool_execution",
    "raw_secret_env_injection",
    "daemonless_model_server",
    "unscoped_network_egress",
];
const RECEIPTS_REQUIRED: [&str; 7] = [
    "HypervisorOSBootReceipt",
    "NodeMeasurementReceipt",
    "ModelMountReceipt",
    "PrivateInferenceReceipt",
    "CapabilityExitReceipt",
    "ExecutableDeniedReceipt",
    "EgressDetectionReceipt",
];
const SEALED_IDENTITY_FIELDS: [&str; 5] = [
    "key_suite",
    "identity_public_key",
    "identity_key_commitment",
    "sealed_identity_alias",
    "sealing_receipt_ref",
];

/// Injected signature verifier: `(key_suite, public_key, message, signature)`.
/// The types crate stays crypto-agnostic; callers bind a real Ed25519
/// verifier (routes use ioi-crypto), tests exercise real keys.
pub type SignatureVerifier<'a> = &'a dyn Fn(&str, &[u8], &[u8], &[u8]) -> Result<(), String>;

/// Named node-attestation operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeAttestationOp {
    /// Admit one node identity with its public sealed-identity binding.
    AdmitNodeIdentity,
    /// Verify one observed measured-boot receipt against the declared floors.
    SubmitBootReceipt,
    /// Derive readiness from the bound verified receipt under fresh evidence.
    MarkNodeReady,
}

impl NodeAttestationOp {
    /// Every node-attestation operation in stable order.
    pub const ALL: [Self; 3] = [
        Self::AdmitNodeIdentity,
        Self::SubmitBootReceipt,
        Self::MarkNodeReady,
    ];

    /// Stable wire operation name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdmitNodeIdentity => "admit_node_identity",
            Self::SubmitBootReceipt => "submit_boot_receipt",
            Self::MarkNodeReady => "mark_node_ready",
        }
    }

    /// Parse a stable wire operation name.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.as_str() == value)
    }

    /// Exact one-operation wallet scope; never a membership, continuity, or
    /// lifecycle scope, and never a wildcard.
    pub fn required_scope(self) -> &'static str {
        match self {
            Self::AdmitNodeIdentity => "scope:hypervisoros.node.admit_node_identity",
            Self::SubmitBootReceipt => "scope:hypervisoros.node.submit_boot_receipt",
            Self::MarkNodeReady => "scope:hypervisoros.node.mark_node_ready",
        }
    }

    fn admits_predecessor(self, predecessor: Option<&str>) -> bool {
        match self {
            Self::AdmitNodeIdentity => predecessor.is_none(),
            // A later verified receipt supersedes the earlier one; readiness
            // must be re-derived against the new verified evidence.
            Self::SubmitBootReceipt => {
                matches!(predecessor, Some("candidate" | "measured" | "ready"))
            }
            Self::MarkNodeReady => predecessor == Some("measured"),
        }
    }
}

/// Closed caller declaration. Fields irrelevant to the named operation are
/// rejected rather than ignored, so one operation cannot smuggle another
/// operation's evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAttestationDeclaration {
    /// Exact node identity inside the estate namespace.
    pub node_id: String,
    /// Caller's compare-and-swap view of the current node set root.
    pub expected_node_set_root: String,
    /// Per-transition evidence refs.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Admitting owner principal (admission only).
    #[serde(default)]
    pub node_owner_ref: Option<String>,
    /// Public sealed-identity binding (admission only): suite, public key,
    /// commitment, sealing alias/receipt references. Never private material.
    #[serde(default)]
    pub sealed_identity: Option<Value>,
    /// Declared node enforcement profile (admission only).
    #[serde(default)]
    pub node_enforcement_profile_ref: Option<String>,
    /// Declared measurement policy (admission only).
    #[serde(default)]
    pub measurement_policy_ref: Option<String>,
    /// Declared cTEE policy (admission only).
    #[serde(default)]
    pub ctee_policy_ref: Option<String>,
    /// Declared worker substrates (admission only).
    #[serde(default)]
    pub supported_worker_substrates: Vec<String>,
    /// Declared mount profiles (admission only).
    #[serde(default)]
    pub supported_mount_profiles: Vec<String>,
    /// Ref of the server-resolved observed boot receipt (submit only).
    #[serde(default)]
    pub boot_receipt_ref: Option<String>,
    /// Ref of the server-resolved temporal validity evaluation
    /// (submit and ready).
    #[serde(default)]
    pub temporal_validity_evaluation_ref: Option<String>,
}

/// Exact durable estate coordinates resolved by the server, never the caller.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeEstateBinding {
    /// Estate namespace all admissible node identities live inside.
    pub estate_namespace: String,
    /// The daemon that is node root for this estate.
    pub daemon_ref: String,
    /// Admitted operational-truth domain.
    pub agentgres_domain_ref: String,
}

/// Durable node-attestation log head resolved from committed transitions only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeAttestationLogHead {
    /// Last committed sequence; zero before the first admission.
    pub sequence: u64,
    /// Current node set root derived from durable records.
    pub node_set_root: String,
}

/// Pure server-derived plan for one named node-attestation transition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledNodeAttestationPlan {
    /// Named operation.
    pub op: NodeAttestationOp,
    /// Monotonic plane sequence.
    pub sequence: u64,
    /// Exact node identity.
    pub node_id: String,
    /// Exact node record identity.
    pub node_record_ref: String,
    /// Predecessor record status, absent only at admission.
    pub predecessor_status: Option<String>,
    /// Derived resulting record status.
    pub resulting_status: String,
    /// Compare-and-swap predecessor node set root.
    pub predecessor_node_set_root: String,
    /// Derived resulting node set root.
    pub resulting_node_set_root: String,
    /// Predecessor record revision root, absent only at admission.
    pub predecessor_record_root: Option<String>,
    /// Derived resulting record revision root.
    pub resulting_record_root: String,
    /// Timeless resulting record body (volatile time fields null).
    pub resulting_record: Value,
    /// Timeless committed boot receipt (submit only).
    pub committed_boot_receipt: Option<Value>,
    /// Timeless committed boot-receipt root (submit only).
    pub committed_boot_receipt_root: Option<String>,
    /// Closed effect authorized by wallet.network.
    pub authority_effect: Value,
}

fn canonical_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|tail| {
        tail.len() == 64
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn canonical_ref(value: &str, prefixes: &[&str]) -> bool {
    !value.chars().any(char::is_whitespace)
        && value.len() <= 256
        && prefixes.iter().any(|prefix| value.starts_with(prefix))
}

fn ensure_distinct(values: &[String], label: &str) -> Result<(), String> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != values.len() {
        return Err(format!("{label} contains duplicate entries"));
    }
    Ok(())
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} is not canonical lowercase hex"));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(format!("{label} is not canonical lowercase hex"));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| format!("{label} is not canonical lowercase hex"))
        })
        .collect()
}

/// Timeless material of one node record revision.
pub fn node_record_root(record: &Value) -> Result<String, String> {
    let mut timeless = record.clone();
    timeless["attestation"]["verified_at"] = Value::Null;
    timeless["last_transition_at"] = Value::Null;
    jcs_hash(&json!({
        "domain": NODE_RECORD_HASH_PROFILE,
        "record": timeless,
    }))
}

/// Set root over the exact live node records, sorted by node identity.
pub fn node_set_root(estate_namespace: &str, records: &[Value]) -> Result<String, String> {
    let mut members = Vec::with_capacity(records.len());
    for record in records {
        members.push((
            required_string(record, "/node_id")?.to_owned(),
            node_record_root(record)?,
        ));
    }
    members.sort();
    let members: Vec<Value> = members
        .into_iter()
        .map(|(node_id, record_root)| json!({"node_id": node_id, "record_root": record_root}))
        .collect();
    jcs_hash(&json!({
        "domain": NODE_SET_HASH_PROFILE,
        "estate_namespace": estate_namespace,
        "members": members,
    }))
}

/// Content root of one declared boot profile.
pub fn boot_profile_root(profile: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": BOOT_PROFILE_HASH_PROFILE,
        "profile": profile,
    }))
}

/// Content root of one declared temporal-verification-profile record.
pub fn temporal_profile_root(profile: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": TEMPORAL_PROFILE_HASH_PROFILE,
        "profile": profile,
    }))
}

/// Timeless content root of one committed boot receipt.
pub fn boot_receipt_root(receipt: &Value) -> Result<String, String> {
    let mut timeless = receipt.clone();
    timeless["verification"]["verified_at"] = Value::Null;
    jcs_hash(&json!({
        "domain": BOOT_RECEIPT_HASH_PROFILE,
        "receipt": timeless,
    }))
}

/// Public identity-key commitment over suite and public key only.
pub fn identity_key_commitment(
    key_suite: &str,
    identity_public_key: &str,
) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": IDENTITY_COMMITMENT_HASH_PROFILE,
        "key_suite": key_suite,
        "identity_public_key": identity_public_key,
    }))
}

/// Signed-material hash: receipt identity plus complete observation. The
/// verdict and the signature itself stay outside the signed material.
pub fn boot_receipt_signed_material_hash(receipt: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": SIGNED_MATERIAL_HASH_PROFILE,
        "receipt_id": required_string(receipt, "/receipt_id")?,
        "node_id": required_string(receipt, "/node_id")?,
        "node_record_ref": required_string(receipt, "/node_record_ref")?,
        "observation": receipt.get("observation").cloned().ok_or("receipt lacks its observation")?,
    }))
}

/// Deterministic posture admission: the effective posture must satisfy the
/// required minimum. CPU-TEE and GPU confidential compute are distinct
/// branches — neither implies the other; only the combined posture satisfies
/// the combined requirement. `unverified` satisfies nothing.
pub fn posture_satisfies(effective: &str, required: &str) -> bool {
    fn base_rank(posture: &str) -> Option<u8> {
        Some(match posture {
            "trusted_operator" => 1,
            "software_only" => 2,
            "measured_boot" => 3,
            "secure_element" => 4,
            "cpu_tee" | "gpu_confidential_compute" => 5,
            "cpu_tee_and_gpu_confidential_compute" => 6,
            _ => return None,
        })
    }
    match required {
        "cpu_tee" => matches!(
            effective,
            "cpu_tee" | "cpu_tee_and_gpu_confidential_compute"
        ),
        "gpu_confidential_compute" => matches!(
            effective,
            "gpu_confidential_compute" | "cpu_tee_and_gpu_confidential_compute"
        ),
        "cpu_tee_and_gpu_confidential_compute" => {
            effective == "cpu_tee_and_gpu_confidential_compute"
        }
        _ => match (base_rank(effective), base_rank(required)) {
            (Some(effective_rank), Some(required_rank)) => effective_rank >= required_rank,
            _ => false,
        },
    }
}

fn validate_declaration(
    op: NodeAttestationOp,
    declaration: &NodeAttestationDeclaration,
) -> Result<(), String> {
    ensure_distinct(&declaration.evidence_refs, "transition evidence")?;
    ensure_distinct(
        &declaration.supported_worker_substrates,
        "declared worker substrates",
    )?;
    ensure_distinct(
        &declaration.supported_mount_profiles,
        "declared mount profiles",
    )?;
    let evidence_prefixes = &["evidence://", "receipt://", "artifact://", "attestation://"][..];
    if declaration
        .evidence_refs
        .iter()
        .any(|value| !canonical_ref(value, evidence_prefixes))
    {
        return Err("transition evidence contains a non-canonical ref".to_owned());
    }
    if !canonical_hash(&declaration.expected_node_set_root) {
        return Err("expected node set root is not canonical".to_owned());
    }

    let only = |allowed: &[&str]| {
        let present = [
            ("node_owner_ref", declaration.node_owner_ref.is_some()),
            ("sealed_identity", declaration.sealed_identity.is_some()),
            (
                "node_enforcement_profile_ref",
                declaration.node_enforcement_profile_ref.is_some(),
            ),
            (
                "measurement_policy_ref",
                declaration.measurement_policy_ref.is_some(),
            ),
            ("ctee_policy_ref", declaration.ctee_policy_ref.is_some()),
            (
                "supported_worker_substrates",
                !declaration.supported_worker_substrates.is_empty(),
            ),
            (
                "supported_mount_profiles",
                !declaration.supported_mount_profiles.is_empty(),
            ),
            ("boot_receipt_ref", declaration.boot_receipt_ref.is_some()),
            (
                "temporal_validity_evaluation_ref",
                declaration.temporal_validity_evaluation_ref.is_some(),
            ),
        ];
        present
            .into_iter()
            .find(|(name, set)| *set && !allowed.contains(name))
            .map(|(name, _)| name)
    };
    let allowed = match op {
        NodeAttestationOp::AdmitNodeIdentity => &[
            "node_owner_ref",
            "sealed_identity",
            "node_enforcement_profile_ref",
            "measurement_policy_ref",
            "ctee_policy_ref",
            "supported_worker_substrates",
            "supported_mount_profiles",
        ][..],
        NodeAttestationOp::SubmitBootReceipt => {
            &["boot_receipt_ref", "temporal_validity_evaluation_ref"][..]
        }
        NodeAttestationOp::MarkNodeReady => &["temporal_validity_evaluation_ref"][..],
    };
    if let Some(field) = only(allowed) {
        return Err(format!("{field} is not admitted for {}", op.as_str()));
    }
    match op {
        NodeAttestationOp::AdmitNodeIdentity => {
            let owner_ok = declaration
                .node_owner_ref
                .as_deref()
                .is_some_and(|value| canonical_ref(value, &["wallet://", "provider://", "org://"]));
            if !owner_ok {
                return Err("admission requires a canonical node owner".to_owned());
            }
            let measurement_ok = declaration
                .measurement_policy_ref
                .as_deref()
                .is_some_and(|value| canonical_ref(value, &["measurement-policy://"]));
            let ctee_ok = declaration
                .ctee_policy_ref
                .as_deref()
                .is_some_and(|value| canonical_ref(value, &["policy://"]));
            if !measurement_ok || !ctee_ok {
                return Err(
                    "admission requires canonical measurement and cTEE policy refs".to_owned(),
                );
            }
            if let Some(reference) = declaration.node_enforcement_profile_ref.as_deref() {
                if !canonical_ref(reference, &["node-enforcement://"]) {
                    return Err("node enforcement profile ref is not canonical".to_owned());
                }
            }
            if declaration.supported_worker_substrates.is_empty()
                || declaration
                    .supported_worker_substrates
                    .iter()
                    .any(|value| !WORKER_SUBSTRATES.contains(&value.as_str()))
            {
                return Err("admission requires worker substrates from the closed enum".to_owned());
            }
            if declaration.supported_mount_profiles.is_empty()
                || declaration
                    .supported_mount_profiles
                    .iter()
                    .any(|value| !MOUNT_PROFILES.contains(&value.as_str()))
            {
                return Err("admission requires mount profiles from the closed enum".to_owned());
            }
            validate_sealed_identity_binding(
                declaration
                    .sealed_identity
                    .as_ref()
                    .ok_or("admission requires the public sealed-identity binding")?,
            )?;
        }
        NodeAttestationOp::SubmitBootReceipt => {
            if declaration
                .boot_receipt_ref
                .as_deref()
                .is_none_or(|value| !canonical_ref(value, &["receipt://"]))
            {
                return Err("submission requires one canonical boot receipt ref".to_owned());
            }
            if declaration
                .temporal_validity_evaluation_ref
                .as_deref()
                .is_none_or(|value| canonical_temporal_evaluation_ref(value).is_err())
            {
                return Err("submission requires one canonical temporal evaluation ref".to_owned());
            }
        }
        NodeAttestationOp::MarkNodeReady => {
            if declaration
                .temporal_validity_evaluation_ref
                .as_deref()
                .is_none_or(|value| canonical_temporal_evaluation_ref(value).is_err())
            {
                return Err("readiness requires one canonical temporal evaluation ref".to_owned());
            }
        }
    }
    Ok(())
}

fn canonical_temporal_evaluation_ref(value: &str) -> Result<(), String> {
    if canonical_ref(
        value,
        &["temporal-evaluation://", "evidence://", "receipt://"],
    ) {
        Ok(())
    } else {
        Err("temporal evaluation ref is not canonical".to_owned())
    }
}

/// The public sealed-identity binding is a closed shape: exactly the public
/// key, its suite, its recomputable commitment, and sealing references. Any
/// other field — in particular any private or seed material — is refused
/// before contract validation ever sees it.
fn validate_sealed_identity_binding(binding: &Value) -> Result<(), String> {
    let object = binding
        .as_object()
        .ok_or("sealed identity binding must be one object")?;
    if let Some(key) = object
        .keys()
        .find(|key| !SEALED_IDENTITY_FIELDS.contains(&key.as_str()))
    {
        return Err(format!(
            "sealed identity binding carries undeclared field '{key}'; only the public binding is admissible"
        ));
    }
    if binding.get("key_suite").and_then(Value::as_str) != Some("ed25519") {
        return Err("sealed identity key suite must be ed25519".to_owned());
    }
    let public_key = binding
        .get("identity_public_key")
        .and_then(Value::as_str)
        .ok_or("sealed identity binding lacks its public key")?;
    if public_key.len() != 64 || decode_hex(public_key, "identity public key").is_err() {
        return Err("identity public key is not 32 canonical hex bytes".to_owned());
    }
    let commitment = binding
        .get("identity_key_commitment")
        .and_then(Value::as_str)
        .ok_or("sealed identity binding lacks its key commitment")?;
    if identity_key_commitment("ed25519", public_key)? != commitment {
        return Err(
            "identity key commitment does not recompute from the public binding".to_owned(),
        );
    }
    let alias_ok = binding
        .get("sealed_identity_alias")
        .and_then(Value::as_str)
        .is_some_and(|value| canonical_ref(value, &["vault://"]));
    if !alias_ok {
        return Err("sealed identity alias must be one vault:// reference".to_owned());
    }
    match binding.get("sealing_receipt_ref") {
        None | Some(Value::Null) => {}
        Some(Value::String(reference)) if canonical_ref(reference, &["receipt://"]) => {}
        Some(_) => return Err("sealing receipt ref is not canonical".to_owned()),
    }
    Ok(())
}

fn validate_boot_profile(profile: &Value, label: &str) -> Result<String, String> {
    validate_architecture_contract(BOOT_PROFILE_CONTRACT, profile)
        .map_err(|error| format!("{label} is invalid: {error}"))?;
    if profile.get("status").and_then(Value::as_str) != Some("declared") {
        return Err(format!("{label} is not the declared record"));
    }
    boot_profile_root(profile)
}

fn validate_temporal_profile(profile: &Value, label: &str) -> Result<String, String> {
    validate_architecture_contract(TEMPORAL_PROFILE_CONTRACT, profile)
        .map_err(|error| format!("{label} is invalid: {error}"))?;
    if profile.get("status").and_then(Value::as_str) != Some("declared") {
        return Err(format!("{label} is not the declared record"));
    }
    temporal_profile_root(profile)
}

fn validate_current_records(records: &[Value], node_namespace_prefix: &str) -> Result<(), String> {
    let mut seen = Vec::new();
    for record in records {
        validate_architecture_contract(HYPERVISOROS_NODE_CONTRACT, record)
            .map_err(|error| format!("durable node record is invalid: {error}"))?;
        let node_id = required_string(record, "/node_id")?;
        if !node_id.starts_with(node_namespace_prefix) {
            return Err("durable node record names a foreign node".to_owned());
        }
        if required_string(record, "/status")? == "retired" {
            return Err("durable live set retains a retired node record".to_owned());
        }
        seen.push(node_id.to_owned());
    }
    let count = seen.len();
    seen.sort();
    seen.dedup();
    if seen.len() != count {
        return Err("durable live set holds duplicate node identities".to_owned());
    }
    Ok(())
}

fn node_record<'a>(records: &'a [Value], node_id: &str) -> Option<&'a Value> {
    records
        .iter()
        .find(|record| record.get("node_id").and_then(Value::as_str) == Some(node_id))
}

/// Validate the resolved boot-receipt signature chain against the admitted
/// node record: the signer must be the node's sealed-identity public key
/// under its declared suite, the public commitment must recompute, the signed
/// material hash must recompute from the observation, and the signature must
/// verify over the signed material hash bytes.
fn validate_signature_chain(
    receipt: &Value,
    node: &Value,
    verify_signature: SignatureVerifier<'_>,
) -> Result<String, String> {
    let suite = required_string(receipt, "/signature/key_suite")?;
    let signer = required_string(receipt, "/signature/signer_public_key")?;
    let node_suite = required_string(node, "/sealed_identity/key_suite")?;
    let node_key = required_string(node, "/sealed_identity/identity_public_key")?;
    let commitment = required_string(node, "/sealed_identity/identity_key_commitment")?;
    if identity_key_commitment(node_suite, node_key)? != commitment {
        return Err(
            "admitted identity commitment does not recompute from the public binding".to_owned(),
        );
    }
    if suite != node_suite || signer != node_key {
        return Err(
            "boot receipt signer chain does not terminate at the admitted node identity".to_owned(),
        );
    }
    let signed_material = boot_receipt_signed_material_hash(receipt)?;
    if required_string(receipt, "/signature/signed_material_hash")? != signed_material {
        return Err("boot receipt signed material hash does not recompute".to_owned());
    }
    let signature = required_string(receipt, "/signature/signature")?;
    let public_key = decode_hex(signer, "boot receipt signer public key")?;
    let signature_bytes = decode_hex(signature, "boot receipt signature")?;
    verify_signature(
        suite,
        &public_key,
        signed_material.as_bytes(),
        &signature_bytes,
    )
    .map_err(|error| format!("boot receipt signature is forged or invalid ({error})"))?;
    Ok(signed_material)
}

/// Validate the resolved temporal validity evaluation against the declared
/// temporal profile and the exact subject: every claim the profile requires
/// must be `established`, the posture must be `online_fresh`, and the
/// evaluation must bind the exact profile hash, subject ref, and subject
/// hash. A stale, indeterminate, or unavailable claim fails closed.
fn validate_fresh_evaluation(
    evaluation: &Value,
    temporal_profile: &Value,
    declared_ref: &str,
    subject_ref: &str,
    subject_hash: &str,
) -> Result<String, String> {
    validate_architecture_contract(TEMPORAL_EVALUATION_CONTRACT, evaluation)
        .map_err(|error| format!("temporal validity evaluation is invalid: {error}"))?;
    if required_string(evaluation, "/evaluation_id")? != declared_ref {
        return Err(
            "resolved temporal evaluation does not match the declared evaluation ref".to_owned(),
        );
    }
    if required_string(evaluation, "/profile_ref")?
        != required_string(temporal_profile, "/profile_ref")?
        || required_string(evaluation, "/profile_hash")?
            != required_string(temporal_profile, "/profile_hash")?
    {
        return Err("temporal evaluation is not bound to the declared temporal profile".to_owned());
    }
    if required_string(evaluation, "/subject_ref")? != subject_ref
        || required_string(evaluation, "/subject_hash")? != subject_hash
    {
        return Err("temporal evaluation is not bound to this exact subject".to_owned());
    }
    if required_string(evaluation, "/temporal_posture")? != "online_fresh" {
        return Err(
            "temporal evaluation posture is not online_fresh; stale evidence cannot verify a boot"
                .to_owned(),
        );
    }
    let required_claims: Vec<&str> = temporal_profile
        .pointer("/declaration/required_claims")
        .and_then(Value::as_array)
        .map(|claims| claims.iter().filter_map(Value::as_str).collect())
        .ok_or("temporal profile lacks its required claims")?;
    let claims = evaluation
        .get("claims")
        .and_then(Value::as_array)
        .ok_or("temporal evaluation lacks its claims")?;
    for required in required_claims {
        let status = claims
            .iter()
            .find(|claim| claim.get("kind").and_then(Value::as_str) == Some(required))
            .and_then(|claim| claim.get("status"))
            .and_then(Value::as_str);
        if status != Some("established") {
            return Err(format!(
                "required temporal claim '{required}' is not established ({})",
                status.unwrap_or("absent")
            ));
        }
    }
    required_string(evaluation, "/evaluation_hash").map(str::to_owned)
}

fn validate_enforcement_declarations(
    declarations: &[Value],
    node_enforcement_profile_ref: Option<&str>,
) -> Result<Vec<Value>, String> {
    let Some(profile_ref) = node_enforcement_profile_ref else {
        if declarations.is_empty() {
            return Ok(Vec::new());
        }
        return Err(
            "enforcement declarations were resolved without a declared enforcement profile"
                .to_owned(),
        );
    };
    let mut refs = Vec::new();
    for declaration in declarations {
        validate_architecture_contract(ENFORCEMENT_COVERAGE_CONTRACT, declaration)
            .map_err(|error| format!("enforcement coverage declaration is invalid: {error}"))?;
        if declaration.pointer("/subject/kind").and_then(Value::as_str)
            != Some("node_enforcement_profile")
            || declaration
                .pointer("/subject/profile_or_adapter_ref")
                .and_then(Value::as_str)
                != Some(profile_ref)
        {
            return Err(
                "enforcement coverage declaration covers a foreign enforcement profile".to_owned(),
            );
        }
        // Only verified-current declarations may be relied on (owner rule):
        // in the registered wire shape that is status `verified` with a
        // `current` verification freshness.
        if declaration.get("status").and_then(Value::as_str) != Some("verified")
            || declaration
                .pointer("/verification/freshness_status")
                .and_then(Value::as_str)
                != Some("current")
        {
            return Err(
                "only verified, freshness-current enforcement coverage declarations are admissible"
                    .to_owned(),
            );
        }
        refs.push(json!(required_string(declaration, "/declaration_id")?));
    }
    let mut sorted: Vec<String> = refs
        .iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != refs.len() {
        return Err("enforcement coverage declarations are not distinct".to_owned());
    }
    Ok(refs)
}

/// Node readiness is derivable only from a bound verified boot receipt: the
/// record must have reached `measured` (or already be `ready`), the resolved
/// committed receipt must recompute to the exact bound root, and its verdict
/// must be `verified`. Everything else refuses.
pub fn derive_node_readiness(
    record: &Value,
    committed_boot_receipt: Option<&Value>,
) -> Result<&'static str, String> {
    let status = required_string(record, "/status")?;
    if !matches!(status, "measured" | "ready") {
        return Err(format!(
            "readiness is not derivable from status '{status}' without a verified boot receipt"
        ));
    }
    let bound_root = record
        .pointer("/attestation/boot_receipt_root")
        .and_then(Value::as_str)
        .ok_or("readiness is not derivable: the record binds no boot receipt")?;
    let receipt = committed_boot_receipt
        .ok_or("readiness is not derivable: the bound boot receipt is not resolvable")?;
    if boot_receipt_root(receipt)? != bound_root {
        return Err(
            "readiness is not derivable: the resolved receipt is not the bound receipt".to_owned(),
        );
    }
    if required_string(receipt, "/verification/verdict")? != "verified" {
        return Err("readiness is not derivable from an unverified boot receipt".to_owned());
    }
    Ok("ready_derivable")
}

/// Compile one named node-attestation operation from exact durable owner
/// inputs. Every trusted input is server-resolved (`INV-37`).
#[allow(clippy::too_many_arguments)]
pub fn compile_node_attestation_plan(
    op: NodeAttestationOp,
    binding: &NodeEstateBinding,
    boot_profile: &Value,
    temporal_profile: &Value,
    current_records: &[Value],
    head: &NodeAttestationLogHead,
    declaration: &NodeAttestationDeclaration,
    trusted_boot_receipt: Option<&Value>,
    trusted_temporal_evaluation: Option<&Value>,
    trusted_enforcement_declarations: &[Value],
    verify_signature: SignatureVerifier<'_>,
) -> Result<CompiledNodeAttestationPlan, String> {
    let ns = &binding.estate_namespace;
    if ns.is_empty()
        || ns.len() > 128
        || !ns
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '/'))
    {
        return Err("estate namespace is not canonical".to_owned());
    }
    validate_declaration(op, declaration)?;
    let declared_boot_profile_root = validate_boot_profile(boot_profile, "declared boot profile")?;
    let declared_temporal_root =
        validate_temporal_profile(temporal_profile, "declared temporal profile")?;
    if boot_profile
        .get("temporal_verification_profile_ref")
        .and_then(Value::as_str)
        != temporal_profile.get("profile_ref").and_then(Value::as_str)
        || boot_profile
            .get("temporal_verification_profile_hash")
            .and_then(Value::as_str)
            != temporal_profile.get("profile_hash").and_then(Value::as_str)
    {
        return Err(
            "declared boot profile is not bound to the declared temporal profile".to_owned(),
        );
    }
    let node_prefix = format!("runtime://{ns}/");
    validate_current_records(current_records, &node_prefix)?;

    // Branch — foreign node: identity outside the estate namespace.
    let node_tail = declaration
        .node_id
        .strip_prefix(node_prefix.as_str())
        .filter(|tail| {
            !tail.is_empty() && tail.len() <= 128 && !tail.chars().any(char::is_whitespace)
        })
        .ok_or("node identity is outside the estate namespace")?;

    // Strict CAS over the exact derived durable set root.
    let derived_root = node_set_root(ns, current_records)?;
    if derived_root != head.node_set_root {
        return Err("durable node truth does not recompute to its committed root".to_owned());
    }
    if declaration.expected_node_set_root != derived_root {
        return Err("stale predecessor node set root".to_owned());
    }

    if trusted_boot_receipt.is_some()
        && !matches!(
            op,
            NodeAttestationOp::SubmitBootReceipt | NodeAttestationOp::MarkNodeReady
        )
    {
        return Err("a boot receipt was supplied to a non-attestation operation".to_owned());
    }
    if trusted_temporal_evaluation.is_some() && op == NodeAttestationOp::AdmitNodeIdentity {
        return Err("a temporal evaluation was supplied to admission".to_owned());
    }
    if !trusted_enforcement_declarations.is_empty() && op != NodeAttestationOp::AdmitNodeIdentity {
        return Err("enforcement declarations are admission inputs only".to_owned());
    }

    let current = node_record(current_records, &declaration.node_id);
    let predecessor_status = current
        .map(|record| required_string(record, "/status").map(str::to_owned))
        .transpose()?;
    if !op.admits_predecessor(predecessor_status.as_deref()) {
        return Err(match &predecessor_status {
            Some(status) => format!("{} cannot lawfully leave {status}", op.as_str()),
            None => format!("{} requires an admitted node identity", op.as_str()),
        });
    }
    let predecessor_record_root = current.map(node_record_root).transpose()?;
    let sequence = head.sequence.checked_add(1).ok_or("sequence overflow")?;
    let node_record_ref = format!("hypervisoros-node://{ns}/node/{node_tail}");

    let mut committed_boot_receipt: Option<Value> = None;
    let mut committed_boot_receipt_root: Option<String> = None;
    let mut bound_evaluation_hash: Option<String> = None;

    let resulting_record = match op {
        NodeAttestationOp::AdmitNodeIdentity => {
            let enforcement_refs = validate_enforcement_declarations(
                trusted_enforcement_declarations,
                declaration.node_enforcement_profile_ref.as_deref(),
            )?;
            json!({
                "schema_version": "ioi.components.daemon-runtime.hypervisoros-node.v1",
                "node_record_id": node_record_ref,
                "node_id": declaration.node_id,
                "profile": "hypervisoros_bare_metal",
                "owner_ref": declaration.node_owner_ref,
                "daemon_ref": binding.daemon_ref,
                "boot_profile_ref": boot_profile["boot_profile_id"],
                "boot_profile_root": declared_boot_profile_root,
                "measurement_policy_ref": declaration.measurement_policy_ref,
                "ctee_policy_ref": declaration.ctee_policy_ref,
                "node_enforcement_profile_ref": declaration.node_enforcement_profile_ref,
                "enforcement_coverage_declaration_refs": enforcement_refs,
                "agentgres_domain_ref": binding.agentgres_domain_ref,
                "supported_worker_substrates": declaration.supported_worker_substrates,
                "supported_mount_profiles": declaration.supported_mount_profiles,
                "forbidden_bypasses": FORBIDDEN_BYPASSES,
                "receipts_required": RECEIPTS_REQUIRED,
                "sealed_identity": declaration.sealed_identity,
                "attestation": {
                    "boot_receipt_ref": Value::Null,
                    "boot_receipt_root": Value::Null,
                    "verified_boot_epoch": Value::Null,
                    "verified_rollback_counter": Value::Null,
                    "temporal_validity_evaluation_ref": Value::Null,
                    "verified_at": Value::Null,
                },
                "node_epoch": sequence,
                "status": "candidate",
                "last_transition_at": Value::Null,
            })
        }
        NodeAttestationOp::SubmitBootReceipt => {
            let node = current.expect("submission predecessor was admitted");
            let receipt =
                trusted_boot_receipt.ok_or("boot receipt is not resolvable from durable truth")?;
            validate_architecture_contract(BOOT_RECEIPT_CONTRACT, receipt)
                .map_err(|error| format!("observed boot receipt is invalid: {error}"))?;
            if required_string(receipt, "/receipt_id")?
                != declaration.boot_receipt_ref.as_deref().unwrap_or("")
            {
                return Err(
                    "resolved boot receipt does not match the declared receipt ref".to_owned(),
                );
            }
            if required_string(receipt, "/node_id")? != declaration.node_id
                || required_string(receipt, "/node_record_ref")? != node_record_ref
            {
                return Err("boot receipt is not bound to the admitted node identity".to_owned());
            }
            if required_string(receipt, "/verification/verdict")? != "unverified" {
                return Err(
                    "an observed receipt arrives unverified; a pre-asserted verdict is refused"
                        .to_owned(),
                );
            }

            // Exact declared-profile binding.
            if receipt.pointer("/observation/boot_profile_ref")
                != boot_profile.get("boot_profile_id")
                || required_string(receipt, "/observation/boot_profile_root")?
                    != declared_boot_profile_root
            {
                return Err(
                    "boot receipt does not observe the exact declared boot profile revision"
                        .to_owned(),
                );
            }
            if receipt.pointer("/observation/temporal_state/temporal_verification_profile_ref")
                != temporal_profile.get("profile_ref")
                || receipt.pointer("/observation/temporal_state/temporal_verification_profile_hash")
                    != temporal_profile.get("profile_hash")
            {
                return Err(
                    "boot receipt temporal state is not bound to the declared temporal profile"
                        .to_owned(),
                );
            }

            // Measurement floors: exact equality with the declared floors.
            for (pointer, floor) in [
                ("/observation/image_hash", "/image_hash"),
                ("/observation/daemon_binary_hash", "/daemon_binary_hash"),
                (
                    "/observation/package_manifest_hash",
                    "/package_manifest_hash",
                ),
                ("/observation/driver_manifest_hash", "/driver_manifest_hash"),
            ] {
                if receipt.pointer(pointer) != boot_profile.pointer(floor) {
                    return Err(format!(
                        "observed measurement at '{pointer}' does not meet the declared floor"
                    ));
                }
            }

            // Posture, appraisal, nonce, and revocation admission.
            let assurance = receipt
                .pointer("/observation/attestation_assurance")
                .ok_or("boot receipt lacks its assurance block")?;
            let required_posture =
                required_string(boot_profile, "/attestation_assurance/required_posture")?;
            let effective = required_string(assurance, "/effective_posture")?;
            if !posture_satisfies(effective, required_posture) {
                return Err(format!(
                    "effective posture '{effective}' does not satisfy the required posture '{required_posture}'"
                ));
            }
            if required_string(assurance, "/appraisal_status")? != "pass" {
                return Err("boot receipt appraisal did not pass".to_owned());
            }
            if required_string(assurance, "/nonce_single_use_status")?
                != "consumed_for_this_appraisal"
            {
                return Err("boot receipt nonce is not single-use for this appraisal".to_owned());
            }
            if required_string(assurance, "/revocation_status")? != "current" {
                return Err("boot receipt revocation state is not current".to_owned());
            }
            if required_string(assurance, "/attester_ref")? != declaration.node_id {
                return Err("boot receipt attester is not the subject node".to_owned());
            }

            // Rollback floor: at or above the declared floor, never below a
            // previously verified counter, with a strictly advancing epoch.
            let observed_counter = receipt
                .pointer("/observation/rollback_state/observed_version_counter")
                .and_then(Value::as_u64)
                .ok_or("boot receipt lacks its rollback counter")?;
            let floor = boot_profile
                .pointer("/update_policy/rollback_floor/minimum_version_counter")
                .and_then(Value::as_u64)
                .ok_or("boot profile lacks its rollback floor")?;
            if observed_counter < floor {
                return Err(
                    "observed rollback counter is below the declared rollback floor".to_owned(),
                );
            }
            if let Some(previous) = node
                .pointer("/attestation/verified_rollback_counter")
                .and_then(Value::as_u64)
            {
                if observed_counter < previous {
                    return Err(
                        "observed rollback counter regresses below the verified floor".to_owned(),
                    );
                }
            }
            let boot_epoch = receipt
                .pointer("/observation/boot_epoch")
                .and_then(Value::as_u64)
                .ok_or("boot receipt lacks its boot epoch")?;
            if let Some(previous_epoch) = node
                .pointer("/attestation/verified_boot_epoch")
                .and_then(Value::as_u64)
            {
                if boot_epoch <= previous_epoch {
                    return Err("boot epoch does not advance past the verified epoch".to_owned());
                }
            }

            // Signature chain against the admitted sealed identity.
            let signed_material = validate_signature_chain(receipt, node, verify_signature)?;

            // Freshness under the declared temporal profile.
            let evaluation = trusted_temporal_evaluation
                .ok_or("temporal validity evaluation is not resolvable from durable truth")?;
            let evaluation_ref = declaration
                .temporal_validity_evaluation_ref
                .as_deref()
                .expect("declaration was validated");
            let evaluation_hash = validate_fresh_evaluation(
                evaluation,
                temporal_profile,
                evaluation_ref,
                required_string(receipt, "/receipt_id")?,
                &signed_material,
            )?;
            if evaluation.get("operation_class").and_then(Value::as_str)
                != Some("boot_verification")
            {
                return Err(
                    "temporal evaluation does not evaluate the boot_verification class".to_owned(),
                );
            }
            bound_evaluation_hash = Some(evaluation_hash.clone());

            // The committed receipt: same observation and signature, with the
            // verdict derived here — the node never wrote it.
            let mut committed = receipt.clone();
            committed["verification"] = json!({
                "verdict": "verified",
                "verified_against_boot_profile_root": declared_boot_profile_root,
                "temporal_validity_evaluation_ref": evaluation_ref,
                "temporal_validity_evaluation_hash": evaluation_hash,
                "evaluated_temporal_posture": "online_fresh",
                "refusal_codes": [],
                "verified_at": Value::Null,
            });
            validate_architecture_contract(BOOT_RECEIPT_CONTRACT, &committed)
                .map_err(|error| format!("committed boot receipt is invalid: {error}"))?;
            let committed_root = boot_receipt_root(&committed)?;

            let mut record = node.clone();
            record["attestation"] = json!({
                "boot_receipt_ref": receipt["receipt_id"],
                "boot_receipt_root": committed_root,
                "verified_boot_epoch": boot_epoch,
                "verified_rollback_counter": observed_counter,
                "temporal_validity_evaluation_ref": evaluation_ref,
                "verified_at": Value::Null,
            });
            record["status"] = json!("measured");
            committed_boot_receipt = Some(committed);
            committed_boot_receipt_root = Some(committed_root);
            record
        }
        NodeAttestationOp::MarkNodeReady => {
            let node = current.expect("readiness predecessor was measured");
            // Ready-before-proof is structurally impossible: readiness is
            // derived from the bound verified receipt, re-checked fresh.
            let receipt =
                trusted_boot_receipt.ok_or("readiness requires the bound verified boot receipt")?;
            validate_architecture_contract(BOOT_RECEIPT_CONTRACT, receipt)
                .map_err(|error| format!("bound boot receipt is invalid: {error}"))?;
            derive_node_readiness(node, Some(receipt))?;
            let evaluation = trusted_temporal_evaluation
                .ok_or("readiness requires a fresh temporal validity evaluation")?;
            let evaluation_ref = declaration
                .temporal_validity_evaluation_ref
                .as_deref()
                .expect("declaration was validated");
            let signed_material = required_string(receipt, "/signature/signed_material_hash")?;
            let evaluation_hash = validate_fresh_evaluation(
                evaluation,
                temporal_profile,
                evaluation_ref,
                required_string(receipt, "/receipt_id")?,
                signed_material,
            )?;
            bound_evaluation_hash = Some(evaluation_hash);
            let mut record = node.clone();
            record["attestation"]["temporal_validity_evaluation_ref"] = json!(evaluation_ref);
            record["status"] = json!("ready");
            record
        }
    };
    validate_architecture_contract(HYPERVISOROS_NODE_CONTRACT, &resulting_record)
        .map_err(|error| format!("resulting node record is invalid: {error}"))?;
    let resulting_record_root = node_record_root(&resulting_record)?;
    let resulting_status = required_string(&resulting_record, "/status")?.to_owned();

    let mut resulting_set: Vec<Value> = current_records
        .iter()
        .filter(|record| {
            record.get("node_id").and_then(Value::as_str) != Some(declaration.node_id.as_str())
        })
        .cloned()
        .collect();
    resulting_set.push(resulting_record.clone());
    let resulting_node_set_root = node_set_root(ns, &resulting_set)?;

    let mut authority_effect = json!({
        "schema_version": "ioi.hypervisoros-node-authority-effect.v1",
        "op": op.as_str(),
        "required_scope": op.required_scope(),
        "sequence": sequence,
        "estate_namespace": ns,
        "daemon_ref": binding.daemon_ref,
        "agentgres_domain_ref": binding.agentgres_domain_ref,
        "node_record_ref": node_record_ref,
        "node_id": declaration.node_id,
        "node_owner_ref": resulting_record["owner_ref"],
        "boot_profile_ref": boot_profile["boot_profile_id"],
        "boot_profile_root": declared_boot_profile_root,
        "temporal_profile_ref": temporal_profile["profile_ref"],
        "temporal_profile_hash": temporal_profile["profile_hash"],
        "temporal_profile_record_root": declared_temporal_root,
        "boot_receipt_ref": declaration.boot_receipt_ref,
        "committed_boot_receipt_root": committed_boot_receipt_root,
        "temporal_validity_evaluation_ref": declaration.temporal_validity_evaluation_ref,
        "temporal_validity_evaluation_hash": bound_evaluation_hash,
        "predecessor_status": predecessor_status,
        "resulting_status": resulting_status,
        "predecessor_node_set_root": derived_root,
        "resulting_node_set_root": resulting_node_set_root,
        "predecessor_record_root": predecessor_record_root,
        "resulting_record_root": resulting_record_root,
        "evidence_refs": declaration.evidence_refs,
        "boot_integrity_grants_system_authority": false,
        "privacy_from_measurement_claimed": false,
        "ready_before_proof_admitted": false,
        "private_material_embedded": false,
        "operation_commitment": Value::Null,
    });
    let operation_commitment = jcs_hash(&json!({
        "domain": NODE_OPERATION_HASH_PROFILE,
        "effect": authority_effect,
    }))?;
    authority_effect["operation_commitment"] = json!(operation_commitment);

    Ok(CompiledNodeAttestationPlan {
        op,
        sequence,
        node_id: declaration.node_id.clone(),
        node_record_ref,
        predecessor_status,
        resulting_status: required_string(&authority_effect, "/resulting_status")?.to_owned(),
        predecessor_node_set_root: derived_root,
        resulting_node_set_root,
        predecessor_record_root,
        resulting_record_root,
        resulting_record,
        committed_boot_receipt,
        committed_boot_receipt_root,
        authority_effect,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::crypto::{SerializableKey, SigningKeyPair, VerifyingKey};
    use ioi_crypto::sign::eddsa::{
        Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
    };

    fn h(marker: u8) -> String {
        format!("sha256:{}", format!("{marker:02x}").repeat(32))
    }

    fn fixture(path: &str) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/../../docs/architecture/_meta/schemas/fixtures/{path}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect(path),
        )
        .expect(path)
    }

    fn keypair(seed: u8) -> Ed25519KeyPair {
        let private_key = Ed25519PrivateKey::from_bytes(&[seed; 32]).expect("private key");
        Ed25519KeyPair::from_private_key(&private_key).expect("keypair")
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn verifier(
        suite: &str,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        if suite != "ed25519" {
            return Err("unsupported suite".to_owned());
        }
        let public_key = Ed25519PublicKey::from_bytes(public_key).map_err(|e| e.to_string())?;
        let signature = Ed25519Signature::from_bytes(signature).map_err(|e| e.to_string())?;
        public_key
            .verify(message, &signature)
            .map_err(|e| e.to_string())
    }

    fn binding() -> NodeEstateBinding {
        NodeEstateBinding {
            estate_namespace: "acme/estate-1".into(),
            daemon_ref: "runtime://acme/estate-1/daemon".into(),
            agentgres_domain_ref: "agentgres://domain/acme/estate-1".into(),
        }
    }

    fn boot_profile() -> Value {
        fixture("hypervisoros-boot-profile-v1/positive-declared.json")
    }

    fn temporal_profile() -> Value {
        fixture("temporal-verification-profile-v1/positive-declared.json")
    }

    const NODE: &str = "runtime://acme/estate-1/alpha-node-1";
    const NODE_RECORD_REF: &str = "hypervisoros-node://acme/estate-1/node/alpha-node-1";

    fn head_for(records: &[Value], sequence: u64) -> NodeAttestationLogHead {
        NodeAttestationLogHead {
            sequence,
            node_set_root: node_set_root("acme/estate-1", records).expect("set root"),
        }
    }

    fn base_declaration(records: &[Value]) -> NodeAttestationDeclaration {
        NodeAttestationDeclaration {
            node_id: NODE.into(),
            expected_node_set_root: node_set_root("acme/estate-1", records).expect("set root"),
            evidence_refs: vec![],
            node_owner_ref: None,
            sealed_identity: None,
            node_enforcement_profile_ref: None,
            measurement_policy_ref: None,
            ctee_policy_ref: None,
            supported_worker_substrates: vec![],
            supported_mount_profiles: vec![],
            boot_receipt_ref: None,
            temporal_validity_evaluation_ref: None,
        }
    }

    fn sealed_identity_for(pair: &Ed25519KeyPair) -> Value {
        let public_key = hex_encode(&pair.public_key().to_bytes());
        json!({
            "key_suite": "ed25519",
            "identity_public_key": public_key,
            "identity_key_commitment": identity_key_commitment("ed25519", &public_key)
                .expect("commitment"),
            "sealed_identity_alias": "vault://acme/node-identity/alpha-node-1",
            "sealing_receipt_ref": "receipt://acme/vault/seal/alpha-node-1",
        })
    }

    fn verified_ecd() -> Value {
        let mut declaration =
            fixture("enforcement-coverage-declaration-v1/positive-active-enforcement.json");
        declaration["subject"]["profile_or_adapter_ref"] =
            json!("node-enforcement://acme/estate-1/default");
        declaration
    }

    fn admit_declaration(pair: &Ed25519KeyPair, records: &[Value]) -> NodeAttestationDeclaration {
        NodeAttestationDeclaration {
            node_owner_ref: Some("wallet://acme/node-owner".into()),
            sealed_identity: Some(sealed_identity_for(pair)),
            node_enforcement_profile_ref: Some("node-enforcement://acme/estate-1/default".into()),
            measurement_policy_ref: Some("measurement-policy://acme/estate-1/default".into()),
            ctee_policy_ref: Some("policy://acme/estate-1/ctee".into()),
            supported_worker_substrates: vec!["microvm".into(), "container".into()],
            supported_mount_profiles: vec![
                "public_mount".into(),
                "plaintext_free_model_mount".into(),
            ],
            evidence_refs: vec!["evidence://acme/estate-1/admit/alpha-node-1".into()],
            ..base_declaration(records)
        }
    }

    /// One observed (unverified) boot receipt signed by the given keypair.
    fn observed_receipt(pair: &Ed25519KeyPair, boot_epoch: u64, counter: u64) -> Value {
        let profile = boot_profile();
        let profile_root = boot_profile_root(&profile).expect("profile root");
        let temporal = temporal_profile();
        let mut receipt = json!({
            "schema_version": "ioi.components.daemon-runtime.hypervisoros-boot-receipt.v1",
            "receipt_id": format!("receipt://acme/estate-1/boot/alpha-node-1/{boot_epoch}"),
            "node_id": NODE,
            "node_record_ref": NODE_RECORD_REF,
            "observation": {
                "boot_epoch": boot_epoch,
                "boot_profile_ref": profile["boot_profile_id"],
                "boot_profile_root": profile_root,
                "workload_identity": "workload://acme/estate-1/alpha-node-1/daemon",
                "image_hash": profile["image_hash"],
                "daemon_binary_hash": profile["daemon_binary_hash"],
                "policy_build_hash": h(0x2b),
                "package_manifest_hash": profile["package_manifest_hash"],
                "driver_manifest_hash": profile["driver_manifest_hash"],
                "measurement_method": "tpm_quote",
                "privacy_claim": "none",
                "quote_evidence_refs": [
                    format!("attestation://acme/estate-1/alpha-node-1/quote/{boot_epoch}")
                ],
                "attestation_assurance": {
                    "attester_ref": NODE,
                    "verifier_ref": "verifier://acme/estate-1/appraiser-service",
                    "appraiser_ref": "appraiser://acme/estate-1/appraiser-service",
                    "relying_party_ref": "runtime://acme/estate-1/daemon",
                    "nonce": "9f2c4d6e8a0b1c2d3e4f5a6b",
                    "nonce_single_use_status": "consumed_for_this_appraisal",
                    "nonce_consumption_receipt_ref": "receipt://acme/estate-1/nonce/42",
                    "endorsement_refs": ["endorsement://acme/tpm-vendor/root"],
                    "reference_value_refs": ["reference://acme/estate-1/pcr-baseline"],
                    "appraisal_policy_ref": "policy://acme/estate-1/appraisal",
                    "appraisal_result_ref": format!("appraisal://acme/estate-1/alpha-node-1/{boot_epoch}"),
                    "appraisal_status": "pass",
                    "appraised_at": "2026-07-27T12:00:00Z",
                    "appraisal_expires_at": "2026-07-27T12:10:00Z",
                    "effective_posture": "measured_boot",
                    "hardware_or_measured_attested": true,
                    "lease_ref": Value::Null,
                    "lease_expires_at": Value::Null,
                    "revocation_epoch": 12,
                    "revocation_status": "current",
                    "revocation_check_receipt_ref": "receipt://acme/estate-1/revocation/12",
                    "reattest_by": "2026-07-28T12:00:00Z",
                },
                "rollback_state": {
                    "observed_version_counter": counter,
                    "observed_image_head_hash": profile["image_hash"],
                },
                "temporal_state": {
                    "temporal_verification_profile_ref": temporal["profile_ref"],
                    "temporal_verification_profile_hash": temporal["profile_hash"],
                    "rollback_domain_ref": "failure-domain://acme/estate-1/node-local",
                    "continuity_floor_evidence_refs": [
                        "evidence://acme/estate-1/anchor/operator/9"
                    ],
                },
            },
            "verification": {
                "verdict": "unverified",
                "verified_against_boot_profile_root": profile_root,
                "temporal_validity_evaluation_ref": Value::Null,
                "temporal_validity_evaluation_hash": Value::Null,
                "evaluated_temporal_posture": Value::Null,
                "refusal_codes": [],
                "verified_at": Value::Null,
            },
            "signature": {
                "key_suite": "ed25519",
                "signer_public_key": hex_encode(&pair.public_key().to_bytes()),
                "signed_material_hash": Value::Null,
                "signature": "00".repeat(64),
            },
            "note": "Boot measurement is an integrity receipt, not a consumer-GPU plaintext privacy guarantee.",
        });
        let material = boot_receipt_signed_material_hash(&receipt).expect("signed material");
        let signature = pair.sign(material.as_bytes()).expect("sign").to_bytes();
        receipt["signature"]["signed_material_hash"] = json!(material);
        receipt["signature"]["signature"] = json!(hex_encode(&signature));
        receipt
    }

    fn evaluation_hash_for(evaluation: &Value) -> String {
        jcs_hash(&json!({
            "domain": "ioi.temporal-validity-evaluation-hash-jcs-sha256.v1",
            "evaluation_id": evaluation["evaluation_id"],
            "profile_ref": evaluation["profile_ref"],
            "profile_hash": evaluation["profile_hash"],
            "subject_ref": evaluation["subject_ref"],
            "subject_hash": evaluation["subject_hash"],
            "operation_class": evaluation["operation_class"],
            "evidence_refs": evaluation["evidence_refs"],
            "source_failure_domain_refs": evaluation["source_failure_domain_refs"],
            "claims": evaluation["claims"],
            "temporal_posture": evaluation["temporal_posture"],
            "evidence_horizon": evaluation["evidence_horizon"],
            "invalidation_triggers": evaluation["invalidation_triggers"],
            "obligations": evaluation["obligations"],
        }))
        .expect("evaluation hash")
    }

    fn fresh_evaluation(receipt: &Value, fresh: bool) -> Value {
        let temporal = temporal_profile();
        let mut evaluation = json!({
            "schema_version": "ioi.components.daemon-runtime.temporal-validity-evaluation.v1",
            "evaluation_id": "temporal-evaluation://acme/estate-1/boot/42",
            "profile_ref": temporal["profile_ref"],
            "profile_hash": temporal["profile_hash"],
            "subject_ref": receipt["receipt_id"],
            "subject_hash": receipt["signature"]["signed_material_hash"],
            "operation_class": "boot_verification",
            "evidence_refs": [
                "evidence://acme/estate-1/time/authenticated-ntp/42",
                "evidence://acme/estate-1/anchor/operator/9"
            ],
            "source_failure_domain_refs": [
                "failure-domain://acme/estate-1/ntp",
                "failure-domain://acme/operator"
            ],
            "claims": [
                {
                    "kind": "challenge_freshness",
                    "status": if fresh { "established" } else { "failed" },
                    "challenge_ref": "challenge://acme/estate-1/boot/42",
                    "maximum_age_ms": 5000,
                    "reason_codes": if fresh { json!([]) } else { json!(["challenge_window_exceeded"]) },
                },
                {
                    "kind": "status_as_of",
                    "status": "established",
                    "status_subject_ref": receipt["receipt_id"],
                    "status_kind": "appraisal_result",
                    "status_value_hash": h(0x2a),
                    "as_of": "2026-07-27T12:00:00Z",
                    "maximum_age_ms": 600000,
                    "reason_codes": [],
                },
                {
                    "kind": "continuity_floor",
                    "status": "established",
                    "namespace_ref": "boot-profile://acme/estate-1/baseline",
                    "floor_kind": "signed_update_version_and_image_head",
                    "accepted_version_or_epoch": 9,
                    "accepted_head_hash": h(0x1a),
                    "outside_rollback_domain_evidence_refs": [
                        "evidence://acme/estate-1/anchor/operator/9"
                    ],
                    "reason_codes": [],
                }
            ],
            "temporal_posture": if fresh { "online_fresh" } else { "insufficient" },
            "evidence_horizon": {
                "valid_from": "2026-07-27T12:00:00Z",
                "valid_until": "2026-07-27T12:10:00Z",
            },
            "invalidation_triggers": ["reboot", "restore", "profile_superseded"],
            "obligations": ["reattest_by_interval"],
            "evaluation_hash": h(0x00),
        });
        let hash = evaluation_hash_for(&evaluation);
        evaluation["evaluation_hash"] = json!(hash);
        evaluation
    }

    #[allow(clippy::too_many_arguments)]
    fn compile(
        op: NodeAttestationOp,
        records: &[Value],
        sequence: u64,
        declaration: &NodeAttestationDeclaration,
        receipt: Option<&Value>,
        evaluation: Option<&Value>,
        enforcement: &[Value],
    ) -> Result<CompiledNodeAttestationPlan, String> {
        compile_node_attestation_plan(
            op,
            &binding(),
            &boot_profile(),
            &temporal_profile(),
            records,
            &head_for(records, sequence),
            declaration,
            receipt,
            evaluation,
            enforcement,
            &verifier,
        )
    }

    /// admit -> submit(verified) -> ready, returning the live record set, the
    /// committed receipt, and every artifact produced along the way.
    fn ladder(pair: &Ed25519KeyPair) -> (Vec<Value>, Value, Vec<Value>) {
        let mut artifacts: Vec<Value> = Vec::new();
        let admitted = compile(
            NodeAttestationOp::AdmitNodeIdentity,
            &[],
            0,
            &admit_declaration(pair, &[]),
            None,
            None,
            &[verified_ecd()],
        )
        .expect("admit");
        assert_eq!(admitted.resulting_status, "candidate");
        artifacts.push(admitted.authority_effect.clone());
        artifacts.push(admitted.resulting_record.clone());
        let records = vec![admitted.resulting_record];

        let receipt = observed_receipt(pair, 3, 9);
        let evaluation = fresh_evaluation(&receipt, true);
        let mut submit = base_declaration(&records);
        submit.boot_receipt_ref = Some("receipt://acme/estate-1/boot/alpha-node-1/3".into());
        submit.temporal_validity_evaluation_ref =
            Some("temporal-evaluation://acme/estate-1/boot/42".into());
        let submitted = compile(
            NodeAttestationOp::SubmitBootReceipt,
            &records,
            1,
            &submit,
            Some(&receipt),
            Some(&evaluation),
            &[],
        )
        .expect("submit boot receipt");
        assert_eq!(submitted.resulting_status, "measured");
        let committed = submitted
            .committed_boot_receipt
            .clone()
            .expect("committed receipt");
        assert_eq!(committed["verification"]["verdict"], "verified");
        artifacts.push(submitted.authority_effect.clone());
        artifacts.push(submitted.resulting_record.clone());
        artifacts.push(committed.clone());
        let records = vec![submitted.resulting_record];

        let mut ready = base_declaration(&records);
        ready.temporal_validity_evaluation_ref =
            Some("temporal-evaluation://acme/estate-1/boot/42".into());
        let readied = compile(
            NodeAttestationOp::MarkNodeReady,
            &records,
            2,
            &ready,
            Some(&committed),
            Some(&evaluation),
            &[],
        )
        .expect("mark ready");
        assert_eq!(readied.resulting_status, "ready");
        artifacts.push(readied.authority_effect.clone());
        artifacts.push(readied.resulting_record.clone());
        (vec![readied.resulting_record], committed, artifacts)
    }

    #[test]
    fn scopes_are_distinct_and_never_reuse_membership_lifecycle_or_continuity_scopes() {
        let mut scopes: Vec<_> = NodeAttestationOp::ALL
            .into_iter()
            .map(NodeAttestationOp::required_scope)
            .collect();
        scopes.sort();
        scopes.dedup();
        assert_eq!(scopes.len(), NodeAttestationOp::ALL.len());
        assert!(scopes.iter().all(|scope| {
            scope.starts_with("scope:hypervisoros.node.")
                && !scope.contains('*')
                && !scope.starts_with("scope:autonomous_system.membership.")
                && !scope.starts_with("scope:autonomous_system.lifecycle.")
                && !scope.starts_with("scope:autonomous_system.continuity.")
        }));
    }

    #[test]
    fn node_attestation_ladder_validates_every_registered_envelope() {
        let pair = keypair(7);
        let (records, committed, artifacts) = ladder(&pair);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["status"], "ready");
        assert_eq!(
            records[0]["attestation"]["verified_boot_epoch"],
            json!(3u64)
        );
        assert_eq!(
            records[0]["attestation"]["verified_rollback_counter"],
            json!(9u64)
        );
        // Every registered envelope validates: the node record revisions, the
        // committed receipt, and the declared profiles (validated at compile).
        validate_architecture_contract(HYPERVISOROS_NODE_CONTRACT, &records[0])
            .expect("node record envelope");
        validate_architecture_contract(BOOT_RECEIPT_CONTRACT, &committed)
            .expect("committed receipt envelope");
        validate_architecture_contract(BOOT_PROFILE_CONTRACT, &boot_profile())
            .expect("boot profile envelope");
        validate_architecture_contract(TEMPORAL_PROFILE_CONTRACT, &temporal_profile())
            .expect("temporal profile envelope");
        // Readiness stays derivable from the durable pair alone.
        assert_eq!(
            derive_node_readiness(&records[0], Some(&committed)).expect("derivable"),
            "ready_derivable"
        );
        assert_eq!(artifacts.len(), 7);
    }

    // Branch — forged attestation: a tampered signature or a signer chain
    // that does not terminate at the admitted identity never compiles.
    #[test]
    fn forged_attestation_is_refused() {
        let pair = keypair(7);
        let admitted = compile(
            NodeAttestationOp::AdmitNodeIdentity,
            &[],
            0,
            &admit_declaration(&pair, &[]),
            None,
            None,
            &[verified_ecd()],
        )
        .expect("admit");
        let records = vec![admitted.resulting_record];
        let mut submit = base_declaration(&records);
        submit.boot_receipt_ref = Some("receipt://acme/estate-1/boot/alpha-node-1/3".into());
        submit.temporal_validity_evaluation_ref =
            Some("temporal-evaluation://acme/estate-1/boot/42".into());

        // (a) Bad signature bytes over otherwise-honest material.
        let mut tampered = observed_receipt(&pair, 3, 9);
        let mut signature = tampered["signature"]["signature"]
            .as_str()
            .expect("signature")
            .to_owned();
        signature.replace_range(0..2, if &signature[0..2] == "00" { "11" } else { "00" });
        tampered["signature"]["signature"] = json!(signature);
        let evaluation = fresh_evaluation(&tampered, true);
        assert!(compile(
            NodeAttestationOp::SubmitBootReceipt,
            &records,
            1,
            &submit,
            Some(&tampered),
            Some(&evaluation),
            &[],
        )
        .unwrap_err()
        .contains("forged or invalid"));

        // (b) Wrong signer chain: a valid signature from a key that is not
        // the admitted sealed identity.
        let impostor = keypair(9);
        let foreign = observed_receipt(&impostor, 3, 9);
        let evaluation = fresh_evaluation(&foreign, true);
        assert!(compile(
            NodeAttestationOp::SubmitBootReceipt,
            &records,
            1,
            &submit,
            Some(&foreign),
            Some(&evaluation),
            &[],
        )
        .unwrap_err()
        .contains("does not terminate at the admitted node identity"));
    }

    // Branch — stale attestation: evidence outside the declared temporal
    // window (failed freshness claim, non-fresh posture) never verifies.
    #[test]
    fn stale_attestation_outside_the_temporal_window_is_refused() {
        let pair = keypair(7);
        let admitted = compile(
            NodeAttestationOp::AdmitNodeIdentity,
            &[],
            0,
            &admit_declaration(&pair, &[]),
            None,
            None,
            &[verified_ecd()],
        )
        .expect("admit");
        let records = vec![admitted.resulting_record];
        let receipt = observed_receipt(&pair, 3, 9);
        let stale = fresh_evaluation(&receipt, false);
        let mut submit = base_declaration(&records);
        submit.boot_receipt_ref = Some("receipt://acme/estate-1/boot/alpha-node-1/3".into());
        submit.temporal_validity_evaluation_ref =
            Some("temporal-evaluation://acme/estate-1/boot/42".into());
        assert!(compile(
            NodeAttestationOp::SubmitBootReceipt,
            &records,
            1,
            &submit,
            Some(&receipt),
            Some(&stale),
            &[],
        )
        .unwrap_err()
        .contains("not online_fresh"));

        // An evaluation bound to a different subject cannot be borrowed.
        let mut borrowed = fresh_evaluation(&receipt, true);
        borrowed["subject_hash"] = json!(h(0x66));
        borrowed["evaluation_hash"] = json!(evaluation_hash_for(&borrowed));
        assert!(compile(
            NodeAttestationOp::SubmitBootReceipt,
            &records,
            1,
            &submit,
            Some(&receipt),
            Some(&borrowed),
            &[],
        )
        .unwrap_err()
        .contains("not bound to this exact subject"));
    }

    // Branch — rollback floor: below-floor counters are refused and the
    // verified floor never decreases; the boot epoch must strictly advance.
    #[test]
    fn rollback_floor_is_enforced_and_never_decreases() {
        let pair = keypair(7);
        let admitted = compile(
            NodeAttestationOp::AdmitNodeIdentity,
            &[],
            0,
            &admit_declaration(&pair, &[]),
            None,
            None,
            &[verified_ecd()],
        )
        .expect("admit");
        let records = vec![admitted.resulting_record];
        let mut submit = base_declaration(&records);
        submit.temporal_validity_evaluation_ref =
            Some("temporal-evaluation://acme/estate-1/boot/42".into());

        // Below the declared floor (7).
        let below = observed_receipt(&pair, 3, 4);
        submit.boot_receipt_ref = Some("receipt://acme/estate-1/boot/alpha-node-1/3".into());
        let evaluation = fresh_evaluation(&below, true);
        assert!(compile(
            NodeAttestationOp::SubmitBootReceipt,
            &records,
            1,
            &submit,
            Some(&below),
            Some(&evaluation),
            &[],
        )
        .unwrap_err()
        .contains("below the declared rollback floor"));

        // Verified at 9, then a later receipt claiming 8 regresses.
        let (ready_records, _committed, _) = ladder(&pair);
        let mut regress = base_declaration(&ready_records);
        regress.boot_receipt_ref = Some("receipt://acme/estate-1/boot/alpha-node-1/4".into());
        regress.temporal_validity_evaluation_ref =
            Some("temporal-evaluation://acme/estate-1/boot/42".into());
        let regressed = observed_receipt(&pair, 4, 8);
        let evaluation = fresh_evaluation(&regressed, true);
        assert!(compile(
            NodeAttestationOp::SubmitBootReceipt,
            &ready_records,
            3,
            &regress,
            Some(&regressed),
            Some(&evaluation),
            &[],
        )
        .unwrap_err()
        .contains("regresses below the verified floor"));

        // A non-advancing boot epoch is refused even at the verified counter.
        let mut replayed = base_declaration(&ready_records);
        replayed.boot_receipt_ref = Some("receipt://acme/estate-1/boot/alpha-node-1/3".into());
        replayed.temporal_validity_evaluation_ref =
            Some("temporal-evaluation://acme/estate-1/boot/42".into());
        let same_epoch = observed_receipt(&pair, 3, 9);
        let evaluation = fresh_evaluation(&same_epoch, true);
        assert!(compile(
            NodeAttestationOp::SubmitBootReceipt,
            &ready_records,
            3,
            &replayed,
            Some(&same_epoch),
            Some(&evaluation),
            &[],
        )
        .unwrap_err()
        .contains("does not advance past the verified epoch"));
    }

    // Branch — ready-before-proof is structurally impossible.
    #[test]
    fn ready_before_proof_is_structurally_impossible() {
        let pair = keypair(7);
        let admitted = compile(
            NodeAttestationOp::AdmitNodeIdentity,
            &[],
            0,
            &admit_declaration(&pair, &[]),
            None,
            None,
            &[verified_ecd()],
        )
        .expect("admit");
        let candidate = admitted.resulting_record.clone();
        let records = vec![admitted.resulting_record];

        // The operation refuses: a candidate has no verified receipt.
        let mut ready = base_declaration(&records);
        ready.temporal_validity_evaluation_ref =
            Some("temporal-evaluation://acme/estate-1/boot/42".into());
        assert!(compile(
            NodeAttestationOp::MarkNodeReady,
            &records,
            1,
            &ready,
            None,
            None,
            &[],
        )
        .unwrap_err()
        .contains("cannot lawfully leave candidate"));

        // The pure derivation refuses without a verified receipt.
        assert!(derive_node_readiness(&candidate, None)
            .unwrap_err()
            .contains("not derivable"));

        // The registered envelope itself refuses a bare ready claim.
        let mut bare = candidate.clone();
        bare["status"] = json!("ready");
        assert!(
            validate_architecture_contract(HYPERVISOROS_NODE_CONTRACT, &bare).is_err(),
            "a ready record without a bound verified receipt must not validate"
        );
    }

    // Branch — leaked secret: private material is refused at the boundary
    // and absent from every artifact the ladder produces.
    #[test]
    fn sealed_identity_material_is_refused_and_absent_from_all_artifacts() {
        let pair = keypair(7);

        // (a) Any undeclared field in the sealed-identity binding — in
        // particular private key material — is refused before compile.
        let mut smuggled = admit_declaration(&pair, &[]);
        let mut sealed = sealed_identity_for(&pair);
        sealed["identity_private_key"] = json!(hex_encode(&[7u8; 32]));
        smuggled.sealed_identity = Some(sealed);
        assert!(compile(
            NodeAttestationOp::AdmitNodeIdentity,
            &[],
            0,
            &smuggled,
            None,
            None,
            &[verified_ecd()],
        )
        .unwrap_err()
        .contains("only the public binding is admissible"));

        // (b) Absence proof: the full ladder's artifacts never contain the
        // private key bytes, the seed, or any secret-bearing key name.
        let (records, committed, artifacts) = ladder(&pair);
        let private_hex = hex_encode(&[7u8; 32]);
        let mut serialized = String::new();
        for artifact in artifacts
            .iter()
            .chain(records.iter())
            .chain(std::iter::once(&committed))
        {
            serialized.push_str(&serde_json::to_string(artifact).expect("artifact bytes"));
        }
        assert!(!serialized.contains(&private_hex));
        for needle in ["private_key", "privatekey", "seed", "mnemonic"] {
            assert!(
                !serialized.to_lowercase().contains(needle),
                "artifact stream leaked '{needle}'"
            );
        }
        // The public binding and the vault alias reference remain — public
        // bindings are the only identity material artifacts may carry.
        assert!(serialized.contains("vault://acme/node-identity/alpha-node-1"));
        assert!(serialized.contains(&hex_encode(&pair.public_key().to_bytes())));
    }

    // Branch — foreign node and stale set root.
    #[test]
    fn foreign_nodes_and_stale_set_roots_are_refused() {
        let pair = keypair(7);
        let mut foreign = admit_declaration(&pair, &[]);
        foreign.node_id = "runtime://mallory/estate-9/intruder".into();
        assert!(compile(
            NodeAttestationOp::AdmitNodeIdentity,
            &[],
            0,
            &foreign,
            None,
            None,
            &[verified_ecd()],
        )
        .unwrap_err()
        .contains("outside the estate namespace"));

        let mut stale = admit_declaration(&pair, &[]);
        stale.expected_node_set_root = h(0x99);
        assert!(compile(
            NodeAttestationOp::AdmitNodeIdentity,
            &[],
            0,
            &stale,
            None,
            None,
            &[verified_ecd()],
        )
        .unwrap_err()
        .contains("stale predecessor node set root"));
    }

    // Enforcement integration: only verified, freshness-current declarations
    // bound to the declared profile are admissible (INV-37: refs derive from
    // resolved declarations, never the caller).
    #[test]
    fn unverified_enforcement_coverage_is_refused_and_refs_are_server_derived() {
        let pair = keypair(7);
        let mut draft = verified_ecd();
        draft["status"] = json!("draft");
        assert!(compile(
            NodeAttestationOp::AdmitNodeIdentity,
            &[],
            0,
            &admit_declaration(&pair, &[]),
            None,
            None,
            &[draft],
        )
        .unwrap_err()
        .contains("freshness-current"));

        let plan = compile(
            NodeAttestationOp::AdmitNodeIdentity,
            &[],
            0,
            &admit_declaration(&pair, &[]),
            None,
            None,
            &[verified_ecd()],
        )
        .expect("admit");
        assert_eq!(
            plan.resulting_record["enforcement_coverage_declaration_refs"],
            json!(["enforcement-coverage://acme/node-alpha/shell/process-spawn/v1"])
        );
    }

    #[test]
    fn posture_admission_is_deterministic_and_branch_aware() {
        assert!(posture_satisfies("measured_boot", "measured_boot"));
        assert!(posture_satisfies("cpu_tee", "measured_boot"));
        assert!(posture_satisfies(
            "cpu_tee_and_gpu_confidential_compute",
            "cpu_tee"
        ));
        assert!(!posture_satisfies("cpu_tee", "gpu_confidential_compute"));
        assert!(!posture_satisfies("gpu_confidential_compute", "cpu_tee"));
        assert!(!posture_satisfies("software_only", "measured_boot"));
        assert!(!posture_satisfies("unverified", "trusted_operator"));
    }
}
