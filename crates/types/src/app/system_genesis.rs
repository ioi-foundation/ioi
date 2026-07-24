//! Pure proposal compiler for an immutable package release and explicit System coordinates.

use crate::app::generated::architecture_contracts::{
    validate_architecture_contract, AutonomousSystemGenesisV1,
    AutonomousSystemInitialProfileBundleV1, AutonomousSystemSequenceZeroMaterializationV1,
};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// RFC 8785 JCS + SHA-256 profile for a manifest's exact component-set material.
pub const SYSTEM_COMPONENT_SET_HASH_PROFILE: &str =
    "ioi.autonomous-system-component-set-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the immutable package-release body.
pub const SYSTEM_RELEASE_ROOT_HASH_PROFILE: &str =
    "ioi.autonomous-system-manifest-release-root-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the exact supplied initial profile bodies.
pub const SYSTEM_INITIAL_PROFILE_BUNDLE_HASH_PROFILE: &str =
    "ioi.autonomous-system-initial-profile-bundle-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the pre-transition genesis operation.
pub const SYSTEM_GENESIS_OPERATION_HASH_PROFILE: &str =
    "ioi.autonomous-system-genesis-operation-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the complete proposed genesis artifact.
pub const SYSTEM_GENESIS_PROPOSAL_ROOT_HASH_PROFILE: &str =
    "ioi.autonomous-system-genesis-proposal-root-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the exact normalized component registry.
pub const SYSTEM_COMPONENT_REGISTRY_HASH_PROFILE: &str =
    "ioi.autonomous-system-component-registry-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the exact profile refs and candidate bundle.
pub const SYSTEM_PROFILE_MATERIALIZATION_HASH_PROFILE: &str =
    "ioi.autonomous-system-profile-materialization-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 compatibility commitment for an immutable M1.3 deployment-profile ref
/// that predates content-addressed deployment-profile revisions.
pub const SYSTEM_LEGACY_DEPLOYMENT_PROFILE_REF_HASH_PROFILE: &str =
    "ioi.autonomous-system-legacy-deployment-profile-ref-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the separately governed M1.4 operation.
pub const SYSTEM_SEQUENCE_ZERO_OPERATION_HASH_PROFILE: &str =
    "ioi.autonomous-system-sequence-zero-operation-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the pre-activation sequence-zero state.
pub const SYSTEM_SEQUENCE_ZERO_STATE_HASH_PROFILE: &str =
    "ioi.autonomous-system-sequence-zero-state-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the sequence-zero receipt accumulator leaf.
pub const SYSTEM_SEQUENCE_ZERO_RECEIPT_HASH_PROFILE: &str =
    "ioi.autonomous-system-sequence-zero-receipt-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the complete sequence-zero transition.
pub const SYSTEM_SEQUENCE_ZERO_TRANSITION_HASH_PROFILE: &str =
    "ioi.autonomous-system-sequence-zero-transition-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the immutable M1.3 admission aggregate.
pub const SYSTEM_GENESIS_ADMISSION_RECORD_HASH_PROFILE: &str =
    "ioi.autonomous-system-genesis-admission-record-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the immutable M1.3 admission receipt.
pub const SYSTEM_GENESIS_ADMISSION_RECEIPT_HASH_PROFILE: &str =
    "ioi.autonomous-system-genesis-admission-receipt-jcs-sha256.v1";
/// Explicit statement that compilation is neither authority nor admission.
pub const SYSTEM_GENESIS_PROPOSAL_AUTHORITY_BOUNDARY: &str =
    "unverified_proposal_only_no_authority_admission_activation_or_effect";

const MANIFEST_CONTRACT_ID: &str = "schema://ioi/foundations/autonomous-system-manifest/v1";
const INITIAL_PROFILE_BUNDLE_CONTRACT_ID: &str =
    "schema://ioi/foundations/autonomous-system-initial-profile-bundle/v1";
const GENESIS_CONTRACT_ID: &str = "schema://ioi/foundations/autonomous-system-genesis/v1";
const SEQUENCE_ZERO_MATERIALIZATION_CONTRACT_ID: &str =
    "schema://ioi/foundations/autonomous-system-sequence-zero-materialization/v1";
const CONSTITUTION_CONTRACT_ID: &str = "schema://ioi/foundations/autonomous-system-constitution/v1";
const ORDERING_CONTRACT_ID: &str =
    "schema://ioi/foundations/ordering-admission-finality-profile/v1";
const ORACLE_CONTRACT_ID: &str = "schema://ioi/foundations/oracle-evidence-profile/v1";
const LIFECYCLE_CONTRACT_ID: &str = "schema://ioi/foundations/lifecycle-continuity-profile/v1";
const NETWORK_ENROLLMENT_CONTRACT_ID: &str = "schema://ioi/foundations/ioi-network-enrollment/v1";
const PROPOSAL_INPUT_SCHEMA_VERSION: &str = "ioi.autonomous-system-genesis-proposal-input.v1";
const INITIAL_PROFILE_BUNDLE_SCHEMA_VERSION: &str =
    "ioi.autonomous-system-initial-profile-bundle.v1";
const BLOCKER_REPORT_SCHEMA_VERSION: &str = "ioi.autonomous-system-genesis-blocker-report.v1";
const MAX_BLOCKERS: usize = 64;

const DIRECT_COMPONENT_BINDING_FIELDS: &[&str] = &[
    "goal_run_profiles",
    "workflow_templates",
    "automation_specs",
    "harness_profiles",
    "agent_harness_adapters",
    "data_recipes",
    "runtime_tool_contracts",
];

const TUPLE_FIELDS: &[&str] = &[
    "goal_run_profiles",
    "workflow_templates",
    "automation_specs",
    "harness_profiles",
    "agent_harness_adapters",
    "skill_manifests",
    "data_recipes",
    "runtime_tool_contracts",
    "mcp_gateway_requirements",
];

const LIVE_BINDING_FIELDS: &[&str] = &[
    "automation_installations",
    "skill_entries",
    "mcp_gateway_profiles",
];

/// Stable fail-closed reason emitted by the pure compiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemGenesisBlockerCode {
    /// The report reached its fixed blocker capacity.
    BlockerLimitExceeded,
    /// A live component binding differs from its package tuple.
    ComponentBindingMismatch,
    /// The declared component-set hash does not match the release body.
    ComponentSetHashMismatch,
    /// Constitution coordinates differ from the proposed System coordinates.
    ConstitutionCoordinateMismatch,
    /// A sequence-zero constitution carries activation evidence.
    ConstitutionActivationReceiptForbidden,
    /// A sequence-zero constitution carries a predecessor.
    ConstitutionPredecessorForbidden,
    /// The proposal claims authorization, admission, or activation.
    GenesisActivationClaimForbidden,
    /// Genesis identity does not belong to the proposed System namespace.
    GenesisCoordinateMismatch,
    /// The proposal carries lifecycle or status receipt history.
    GenesisHistoryForbidden,
    /// The sequence-zero proposal carries a predecessor commitment.
    GenesisPredecessorForbidden,
    /// The proposed genesis sequence is not zero.
    GenesisSequenceNotZero,
    /// The proposed genesis status is not `proposed`.
    GenesisStatusNotProposed,
    /// Canonicalization or hashing failed.
    HashingFailed,
    /// The exact initial profile bundle is malformed or internally inconsistent.
    InitialProfileBundleInvalid,
    /// The proposal contains a binding that requires later admission.
    LiveBindingAdmissionUnavailable,
    /// Manifest and package coordinates disagree.
    ManifestPackageMismatch,
    /// The package release cannot instantiate a new System.
    NewSystemInstantiationForbidden,
    /// An immutable coordinate uses a mutable alias.
    MutableReference,
    /// Network enrollment coordinates differ from the proposal.
    NetworkEnrollmentCoordinateMismatch,
    /// A sequence-zero enrollment carries a predecessor.
    NetworkEnrollmentPredecessorForbidden,
    /// Input contains a clock, random, process, or environment field.
    NondeterministicField,
    /// A reusable package contains live runtime state.
    PackageLiveStateForbidden,
    /// A profile differs from the proposed System coordinates.
    ProfileCoordinateMismatch,
    /// The explicit proposal input violates its closed shape.
    ProposedInstantiationInvalid,
    /// The package release violates the registered manifest contract.
    ReleaseContractInvalid,
    /// The declared release root does not match the immutable release body.
    ReleaseRootMismatch,
    /// A compiler-required field is absent.
    RequiredFieldMissing,
    /// A manifest-required template reference is absent.
    RequiredTemplateMissing,
    /// Concrete secret or credential material occurs in the input.
    SecretMaterialForbidden,
    /// A supplied template reference differs from the package requirement.
    TemplateBindingMismatch,
    /// One tuple identity is paired with conflicting hashes.
    TupleIdentityCollision,
    /// One immutable tuple identity occurs more than once.
    TupleIdentityDuplicate,
    /// Input contains a property outside the compiler contract.
    UnknownProperty,
}

impl SystemGenesisBlockerCode {
    fn message(self) -> &'static str {
        match self {
            Self::BlockerLimitExceeded => "additional blockers exceeded the bounded report",
            Self::ComponentBindingMismatch => {
                "proposed component binding differs from the exact package tuple or hash"
            }
            Self::ComponentSetHashMismatch => {
                "component_set_hash does not commit the exact declared component set"
            }
            Self::ConstitutionCoordinateMismatch => {
                "constitution coordinates differ from the proposed System or genesis"
            }
            Self::ConstitutionActivationReceiptForbidden => {
                "a sequence-zero constitution cannot carry an activation receipt"
            }
            Self::ConstitutionPredecessorForbidden => {
                "a sequence-zero constitution cannot carry a predecessor constitution"
            }
            Self::GenesisActivationClaimForbidden => {
                "a pure proposal cannot claim authorization, admission, or activation"
            }
            Self::GenesisCoordinateMismatch => {
                "genesis identity does not belong to the proposed System namespace"
            }
            Self::GenesisHistoryForbidden => {
                "a pure proposal cannot contain lifecycle or status receipt history"
            }
            Self::GenesisPredecessorForbidden => {
                "a genesis proposal cannot contain a predecessor commitment"
            }
            Self::GenesisSequenceNotZero => "a genesis proposal must use sequence zero",
            Self::GenesisStatusNotProposed => {
                "the pure compiler accepts only proposed genesis status"
            }
            Self::HashingFailed => "JCS canonicalization or SHA-256 hashing failed",
            Self::InitialProfileBundleInvalid => {
                "the closed initial profile bundle is malformed or internally inconsistent"
            }
            Self::LiveBindingAdmissionUnavailable => {
                "live installation, skill-entry, or gateway binding requires later admission"
            }
            Self::ManifestPackageMismatch => {
                "package and release coordinates do not identify the same package"
            }
            Self::NewSystemInstantiationForbidden => {
                "system_binding.allowed_use forbids new-System instantiation"
            }
            Self::MutableReference => {
                "mutable, floating, current, latest, or head reference is forbidden"
            }
            Self::NetworkEnrollmentCoordinateMismatch => {
                "network enrollment coordinates differ from the proposed genesis"
            }
            Self::NetworkEnrollmentPredecessorForbidden => {
                "a sequence-zero enrollment cannot carry a predecessor enrollment"
            }
            Self::NondeterministicField => {
                "clock, random, environment, process, or generated identity field is forbidden"
            }
            Self::PackageLiveStateForbidden => {
                "a reusable package cannot contain live System, node, run, lease, or assignment state"
            }
            Self::ProfileCoordinateMismatch => {
                "profile identity, System, constitution, or genesis binding differs"
            }
            Self::ProposedInstantiationInvalid => {
                "proposed instantiation is outside its closed contract"
            }
            Self::ReleaseContractInvalid => {
                "package release is outside the registered manifest contract"
            }
            Self::ReleaseRootMismatch => {
                "release_root does not commit the exact immutable release body"
            }
            Self::RequiredFieldMissing => "required proposal input is missing",
            Self::RequiredTemplateMissing => {
                "manifest-required constitution, deployment, ordering, oracle, or lifecycle template is missing"
            }
            Self::SecretMaterialForbidden => {
                "concrete secret or credential material is forbidden recursively"
            }
            Self::TemplateBindingMismatch => {
                "proposed template binding differs from the exact package requirement"
            }
            Self::TupleIdentityCollision => {
                "one immutable tuple identity is paired with conflicting content hashes"
            }
            Self::TupleIdentityDuplicate => {
                "one immutable tuple identity occurs more than once"
            }
            Self::UnknownProperty => "unknown property is forbidden",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::BlockerLimitExceeded => "blocker_limit_exceeded",
            Self::ComponentBindingMismatch => "component_binding_mismatch",
            Self::ComponentSetHashMismatch => "component_set_hash_mismatch",
            Self::ConstitutionCoordinateMismatch => "constitution_coordinate_mismatch",
            Self::ConstitutionActivationReceiptForbidden => {
                "constitution_activation_receipt_forbidden"
            }
            Self::ConstitutionPredecessorForbidden => "constitution_predecessor_forbidden",
            Self::GenesisActivationClaimForbidden => "genesis_activation_claim_forbidden",
            Self::GenesisCoordinateMismatch => "genesis_coordinate_mismatch",
            Self::GenesisHistoryForbidden => "genesis_history_forbidden",
            Self::GenesisPredecessorForbidden => "genesis_predecessor_forbidden",
            Self::GenesisSequenceNotZero => "genesis_sequence_not_zero",
            Self::GenesisStatusNotProposed => "genesis_status_not_proposed",
            Self::HashingFailed => "hashing_failed",
            Self::InitialProfileBundleInvalid => "initial_profile_bundle_invalid",
            Self::LiveBindingAdmissionUnavailable => "live_binding_admission_unavailable",
            Self::ManifestPackageMismatch => "manifest_package_mismatch",
            Self::NewSystemInstantiationForbidden => "new_system_instantiation_forbidden",
            Self::MutableReference => "mutable_reference",
            Self::NetworkEnrollmentCoordinateMismatch => "network_enrollment_coordinate_mismatch",
            Self::NetworkEnrollmentPredecessorForbidden => {
                "network_enrollment_predecessor_forbidden"
            }
            Self::NondeterministicField => "nondeterministic_field",
            Self::PackageLiveStateForbidden => "package_live_state_forbidden",
            Self::ProfileCoordinateMismatch => "profile_coordinate_mismatch",
            Self::ProposedInstantiationInvalid => "proposed_instantiation_invalid",
            Self::ReleaseContractInvalid => "release_contract_invalid",
            Self::ReleaseRootMismatch => "release_root_mismatch",
            Self::RequiredFieldMissing => "required_field_missing",
            Self::RequiredTemplateMissing => "required_template_missing",
            Self::SecretMaterialForbidden => "secret_material_forbidden",
            Self::TemplateBindingMismatch => "template_binding_mismatch",
            Self::TupleIdentityCollision => "tuple_identity_collision",
            Self::TupleIdentityDuplicate => "tuple_identity_duplicate",
            Self::UnknownProperty => "unknown_property",
        }
    }
}

/// One deterministic blocker and its exact input path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemGenesisBlocker {
    /// Stable machine-readable reason.
    pub code: SystemGenesisBlockerCode,
    /// JSON-style path into the supplied release or proposal.
    pub path: String,
    /// Stable human-readable explanation.
    pub message: String,
}

/// Bounded evidence report returned instead of a live record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemGenesisBlockerReport {
    /// Blocker report contract identifier.
    pub schema_version: &'static str,
    /// Sorted, deduplicated blockers.
    pub blockers: Vec<SystemGenesisBlocker>,
    /// Whether additional blockers were replaced by the limit marker.
    pub truncated: bool,
}

/// Exact candidate profile bodies and their canonical commitment.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledSystemInitialProfileBundle {
    /// Closed generated projection preserving the exact supplied profile bodies.
    pub bundle: AutonomousSystemInitialProfileBundleV1,
    /// RFC 8785 canonical bytes of `bundle`.
    pub canonical_json: Vec<u8>,
    /// Domain-separated SHA-256 commitment to `canonical_json`.
    pub bundle_root: String,
    /// Hash profile used for `bundle_root`.
    pub hash_profile: &'static str,
}

/// Canonical proposed genesis artifact and its root.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledSystemGenesisProposal {
    /// Exact initial profile material available to a later persistence step.
    pub initial_profile_bundle: CompiledSystemInitialProfileBundle,
    /// Typed proposed genesis artifact.
    pub genesis: AutonomousSystemGenesisV1,
    /// RFC 8785 canonical bytes of `genesis`.
    pub canonical_json: Vec<u8>,
    /// Domain-separated SHA-256 commitment to `canonical_json`.
    pub proposal_root: String,
    /// Hash profile used for `proposal_root`.
    pub hash_profile: &'static str,
}

/// Deterministic M1.4 plan derived only from one converged M1.3 admission.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledSystemSequenceZeroPlan {
    /// Immutable normalized registry payload admitted beside the materialization.
    pub component_registry_snapshot: Value,
    /// Canonical pre-activation materialization body without its authority timestamp.
    pub materialization_body: Value,
    /// Exact authority effect for the separate M1.4 crossing.
    pub authority_effect: Value,
    /// Domain-separated root of the normalized component registry.
    pub component_registry_root: String,
    /// Domain-separated root binding the exact candidate profile refs and bundle.
    pub profile_materialization_root: String,
    /// Domain-separated operation commitment.
    pub operation_commitment: String,
    /// Domain-separated resulting pre-activation state root.
    pub initial_state_root: String,
    /// Domain-separated sequence-zero receipt root.
    pub initial_receipt_root: String,
    /// Complete transition commitment ref binding operation, state, receipt, and proof.
    pub transition_commitment_ref: String,
}

/// Final typed M1.4 artifact plus its canonical bytes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledSystemSequenceZeroMaterialization {
    /// Registered closed projection.
    pub materialization: AutonomousSystemSequenceZeroMaterializationV1,
    /// RFC 8785 canonical bytes of `materialization`.
    pub canonical_json: Vec<u8>,
}

/// Pure compiler result. `proposal` is absent whenever any blocker exists.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SystemGenesisCompilation {
    /// Proposed artifact, present only for a blocker-free compilation.
    pub proposal: Option<CompiledSystemGenesisProposal>,
    /// Bounded validation evidence; this is not persisted by the compiler.
    pub blocker_report: SystemGenesisBlockerReport,
    /// Explicit authority and effect disclaimer.
    pub authority_effect_boundary: &'static str,
}

#[derive(Serialize)]
struct DomainSeparatedMaterial<'a> {
    domain: &'static str,
    value: &'a Value,
}

#[derive(Default)]
struct BlockerCollector {
    blockers: Vec<SystemGenesisBlocker>,
}

impl BlockerCollector {
    fn push(&mut self, code: SystemGenesisBlockerCode, path: impl Into<String>) {
        self.blockers.push(SystemGenesisBlocker {
            code,
            path: path.into(),
            message: code.message().to_owned(),
        });
    }

    fn finish(mut self) -> SystemGenesisBlockerReport {
        self.blockers.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.code.label().cmp(right.code.label()))
        });
        self.blockers
            .dedup_by(|left, right| left.code == right.code && left.path == right.path);
        let truncated = self.blockers.len() > MAX_BLOCKERS;
        if truncated {
            self.blockers.truncate(MAX_BLOCKERS - 1);
            self.blockers.push(SystemGenesisBlocker {
                code: SystemGenesisBlockerCode::BlockerLimitExceeded,
                path: "$".to_owned(),
                message: SystemGenesisBlockerCode::BlockerLimitExceeded
                    .message()
                    .to_owned(),
            });
            self.blockers.sort_by(|left, right| {
                left.path
                    .cmp(&right.path)
                    .then_with(|| left.code.label().cmp(right.code.label()))
            });
        }
        SystemGenesisBlockerReport {
            schema_version: BLOCKER_REPORT_SCHEMA_VERSION,
            blockers: self.blockers,
            truncated,
        }
    }
}

/// Compute the exact component-set hash declared by an AutonomousSystemManifest.
pub fn compute_system_component_set_hash(release: &Value) -> Result<String, String> {
    let typed_components = release
        .get("typed_components")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing typed_components".to_owned())?;
    let mut material = typed_components.clone();
    material.remove("component_set_hash");
    domain_hash(SYSTEM_COMPONENT_SET_HASH_PROFILE, &Value::Object(material))
}

/// Compute the immutable release root, excluding mutable registry and receipt projections.
pub fn compute_system_release_root(release: &Value) -> Result<String, String> {
    let mut material = release
        .as_object()
        .cloned()
        .ok_or_else(|| "manifest must be an object".to_owned())?;
    material.remove("release_root");
    material.remove("registry_status");
    if let Some(receipts) = material.get_mut("receipts").and_then(Value::as_object_mut) {
        receipts.remove("package_readiness_receipt_ref");
    }
    if let Some(release_projection) = material.get_mut("release").and_then(Value::as_object_mut) {
        release_projection.remove("publisher_signature_ref");
        release_projection.remove("registry_published_at");
    }
    domain_hash(SYSTEM_RELEASE_ROOT_HASH_PROFILE, &Value::Object(material))
}

/// Compute the immutable M1.3 admission-record root consumed by M1.4.
pub fn compute_system_genesis_admission_record_root(record: &Value) -> Result<String, String> {
    domain_hash(SYSTEM_GENESIS_ADMISSION_RECORD_HASH_PROFILE, record)
}

/// Compute the immutable M1.3 admission-receipt root consumed by M1.4.
pub fn compute_system_genesis_admission_receipt_root(receipt: &Value) -> Result<String, String> {
    domain_hash(SYSTEM_GENESIS_ADMISSION_RECEIPT_HASH_PROFILE, receipt)
}

fn required_string(value: &Value, pointer: &str) -> Result<String, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("missing canonical string at '{pointer}'"))
}

fn normalized_component_binding(
    kind: &str,
    binding_ref: &str,
    binding_hash: &str,
    evidence_refs: Vec<Value>,
    evidence_hashes: Vec<Value>,
) -> Value {
    serde_json::json!({
        "kind": kind,
        "binding_ref": binding_ref,
        "binding_hash": binding_hash,
        "evidence_refs": evidence_refs,
        "evidence_hashes": evidence_hashes
    })
}

fn normalize_component_bindings(genesis: &Value) -> Result<Vec<Value>, String> {
    let bindings = genesis
        .get("initial_component_bindings")
        .and_then(Value::as_object)
        .ok_or_else(|| "authorized genesis lacks initial_component_bindings".to_owned())?;
    let mut normalized = Vec::new();
    for (field, kind) in [
        ("goal_run_profiles", "goal_run_profile"),
        ("workflow_templates", "workflow_template"),
        ("automation_specs", "automation_spec"),
        ("harness_profiles", "harness_profile"),
        ("agent_harness_adapters", "agent_harness_adapter"),
        ("data_recipes", "data_recipe"),
        ("runtime_tool_contracts", "runtime_tool_contract"),
    ] {
        let rows = bindings
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("initial_component_bindings.{field} is not an array"))?;
        for (index, row) in rows.iter().enumerate() {
            normalized.push(normalized_component_binding(
                kind,
                &required_string(row, "/revision_ref").map_err(|error| {
                    format!("initial_component_bindings.{field}[{index}] {error}")
                })?,
                &required_string(row, "/content_hash").map_err(|error| {
                    format!("initial_component_bindings.{field}[{index}] {error}")
                })?,
                Vec::new(),
                Vec::new(),
            ));
        }
    }

    for (index, row) in bindings
        .get("automation_installations")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "initial_component_bindings.automation_installations is not an array".to_owned()
        })?
        .iter()
        .enumerate()
    {
        normalized.push(normalized_component_binding(
            "automation_installation",
            &required_string(row, "/binding_revision_ref").map_err(|error| {
                format!("initial_component_bindings.automation_installations[{index}] {error}")
            })?,
            &required_string(row, "/binding_hash").map_err(|error| {
                format!("initial_component_bindings.automation_installations[{index}] {error}")
            })?,
            vec![Value::String(
                required_string(row, "/admission_receipt_ref").map_err(|error| {
                    format!("initial_component_bindings.automation_installations[{index}] {error}")
                })?,
            )],
            Vec::new(),
        ));
    }

    for (index, row) in bindings
        .get("skill_entries")
        .and_then(Value::as_array)
        .ok_or_else(|| "initial_component_bindings.skill_entries is not an array".to_owned())?
        .iter()
        .enumerate()
    {
        normalized.push(normalized_component_binding(
            "skill_entry",
            &required_string(row, "/binding_revision_ref").map_err(|error| {
                format!("initial_component_bindings.skill_entries[{index}] {error}")
            })?,
            &required_string(row, "/binding_hash").map_err(|error| {
                format!("initial_component_bindings.skill_entries[{index}] {error}")
            })?,
            vec![Value::String(
                required_string(row, "/skill_manifest_revision_ref").map_err(|error| {
                    format!("initial_component_bindings.skill_entries[{index}] {error}")
                })?,
            )],
            vec![Value::String(
                required_string(row, "/skill_manifest_content_hash").map_err(|error| {
                    format!("initial_component_bindings.skill_entries[{index}] {error}")
                })?,
            )],
        ));
    }

    for (index, row) in bindings
        .get("mcp_gateway_profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "initial_component_bindings.mcp_gateway_profiles is not an array".to_owned()
        })?
        .iter()
        .enumerate()
    {
        normalized.push(normalized_component_binding(
            "mcp_gateway_profile",
            &required_string(row, "/profile_revision_ref").map_err(|error| {
                format!("initial_component_bindings.mcp_gateway_profiles[{index}] {error}")
            })?,
            &required_string(row, "/profile_content_hash").map_err(|error| {
                format!("initial_component_bindings.mcp_gateway_profiles[{index}] {error}")
            })?,
            Vec::new(),
            Vec::new(),
        ));
    }

    let mut identities = BTreeSet::new();
    let mut canonical = Vec::with_capacity(normalized.len());
    for binding in normalized {
        let kind = required_string(&binding, "/kind")?;
        let binding_ref = required_string(&binding, "/binding_ref")?;
        if !identities.insert((kind.clone(), binding_ref.clone())) {
            return Err(format!(
                "duplicate normalized component binding '{kind}:{binding_ref}'"
            ));
        }
        canonical.push((
            serde_jcs::to_vec(&binding)
                .map_err(|error| format!("component binding JCS failed ({error})"))?,
            binding,
        ));
    }
    canonical.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(canonical.into_iter().map(|(_, binding)| binding).collect())
}

fn deployment_profile_root(profile_refs: &Value) -> Result<String, String> {
    let deployment_profile_ref = required_string(profile_refs, "/deployment_profile_ref")?;
    let versioned = deployment_profile_ref
        .strip_prefix("deployment-profile://")
        .and_then(|value| value.rsplit_once("/revision/sha256:"));
    if let Some((identity, hash)) = versioned {
        if !identity.is_empty()
            && !identity
                .chars()
                .any(|ch| ch.is_whitespace() || matches!(ch, '?' | '#' | '\\'))
            && hash.len() == 64
            && hash
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        {
            return Ok(format!("sha256:{hash}"));
        }
    }

    // M1.3 admitted deployment-profile refs before revisions were required. Those immutable
    // records cannot be rewritten, so M1.4 freezes the exact legacy ref under a separate domain
    // instead of stranding the System or misrepresenting the result as a profile-content hash.
    // Activation must still replace this compatibility commitment with a content-addressed
    // revision through a separately governed later transition.
    domain_hash(
        SYSTEM_LEGACY_DEPLOYMENT_PROFILE_REF_HASH_PROFILE,
        &Value::String(deployment_profile_ref),
    )
}

/// Derive the complete M1.4 effect without trusting caller-authored root values.
pub fn compile_system_sequence_zero_plan(
    authorized_genesis: &Value,
    initial_profile_bundle: &Value,
    genesis_admission_record_root: &str,
    genesis_admission_receipt_ref: &str,
    genesis_admission_receipt_root: &str,
) -> Result<CompiledSystemSequenceZeroPlan, String> {
    validate_architecture_contract(GENESIS_CONTRACT_ID, authorized_genesis)
        .map_err(|error| format!("authorized genesis contract invalid ({error})"))?;
    validate_architecture_contract(INITIAL_PROFILE_BUNDLE_CONTRACT_ID, initial_profile_bundle)
        .map_err(|error| format!("initial profile bundle contract invalid ({error})"))?;
    if authorized_genesis.get("status").and_then(Value::as_str) != Some("authorized")
        || !authorized_genesis
            .get("activation_receipt_ref")
            .is_some_and(Value::is_null)
        || authorized_genesis
            .get("lifecycle_transition_refs")
            .and_then(Value::as_array)
            .is_none_or(|refs| !refs.is_empty())
    {
        return Err(
            "M1.4 requires an authorized, non-activated genesis with no lifecycle history"
                .to_owned(),
        );
    }
    if authorized_genesis
        .pointer("/cryptographic_origin/admission_proof_ref")
        .and_then(Value::as_str)
        != Some(genesis_admission_receipt_ref)
    {
        return Err("authorized genesis does not bind the supplied admission receipt".to_owned());
    }
    for (field, value) in [
        (
            "genesis_admission_record_root",
            genesis_admission_record_root,
        ),
        (
            "genesis_admission_receipt_root",
            genesis_admission_receipt_root,
        ),
    ] {
        if !value.strip_prefix("sha256:").is_some_and(|tail| {
            tail.len() == 64
                && tail
                    .chars()
                    .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        }) {
            return Err(format!(
                "{field} must be one canonical lowercase sha256 ref"
            ));
        }
    }
    if !genesis_admission_receipt_ref.starts_with("receipt://")
        || genesis_admission_receipt_ref
            .chars()
            .any(char::is_whitespace)
    {
        return Err("genesis_admission_receipt_ref must be canonical".to_owned());
    }

    let profile_bundle_root = domain_hash(
        SYSTEM_INITIAL_PROFILE_BUNDLE_HASH_PROFILE,
        initial_profile_bundle,
    )?;
    if authorized_genesis
        .get("initial_profile_bundle_root")
        .and_then(Value::as_str)
        != Some(profile_bundle_root.as_str())
    {
        return Err(
            "authorized genesis profile-bundle root does not match its exact bodies".into(),
        );
    }
    let system_id = required_string(authorized_genesis, "/system_id")?;
    let genesis_ref = required_string(authorized_genesis, "/genesis_id")?;
    let package_id = required_string(authorized_genesis, "/package_id")?;
    let manifest_ref = required_string(authorized_genesis, "/manifest_ref")?;
    let admitted_manifest_root = required_string(authorized_genesis, "/admitted_manifest_root")?;
    let proposed_initial_state_root = required_string(
        authorized_genesis,
        "/cryptographic_origin/initial_state_root",
    )?;
    let proposed_initial_receipt_root = required_string(
        authorized_genesis,
        "/cryptographic_origin/initial_receipt_root",
    )?;
    let constitution_ref = required_string(authorized_genesis, "/constitution_ref")?;
    let constitution_root =
        required_string(initial_profile_bundle, "/constitution/constitution_root")?;
    let profile_refs = authorized_genesis
        .get("initial_profile_refs")
        .cloned()
        .ok_or_else(|| "authorized genesis lacks initial_profile_refs".to_owned())?;
    let deployment_profile_root = deployment_profile_root(&profile_refs)?;
    let component_bindings = normalize_component_bindings(authorized_genesis)?;

    let component_registry_material = serde_json::json!({
        "schema_version": "ioi.autonomous-system-component-registry-snapshot.v1",
        "system_id": system_id,
        "genesis_ref": genesis_ref,
        "component_bindings": component_bindings
    });
    let component_registry_root = domain_hash(
        SYSTEM_COMPONENT_REGISTRY_HASH_PROFILE,
        &component_registry_material,
    )?;
    let component_registry_ref =
        format!("agentgres://object-set/autonomous-system-components/{component_registry_root}");
    let component_registry_snapshot = serde_json::json!({
        "schema_version": "ioi.autonomous-system-component-registry-snapshot.v1",
        "component_registry_ref": component_registry_ref,
        "component_registry_root": component_registry_root,
        "system_id": system_id,
        "genesis_ref": genesis_ref,
        "component_binding_count": component_bindings.len(),
        "component_bindings": component_bindings,
        "status": "frozen_pending_activation"
    });

    let profile_materialization_material = serde_json::json!({
        "schema_version": "ioi.autonomous-system-profile-materialization.v1",
        "system_id": system_id,
        "genesis_ref": genesis_ref,
        "profile_bundle_root": profile_bundle_root,
        "deployment_profile_root": deployment_profile_root,
        "profile_refs": profile_refs
    });
    let profile_materialization_root = domain_hash(
        SYSTEM_PROFILE_MATERIALIZATION_HASH_PROFILE,
        &profile_materialization_material,
    )?;
    let materialization_id =
        format!("system-materialization://sequence-zero/{genesis_admission_record_root}");
    let operation_material = serde_json::json!({
        "schema_version": "ioi.autonomous-system-sequence-zero-operation.v1",
        "operation": "materialize_sequence_zero",
        "materialization_id": materialization_id,
        "system_id": system_id,
        "genesis_ref": genesis_ref,
        "genesis_admission_receipt_ref": genesis_admission_receipt_ref,
        "genesis_admission_record_root": genesis_admission_record_root,
        "genesis_admission_receipt_root": genesis_admission_receipt_root,
        "proposed_initial_state_root": proposed_initial_state_root,
        "proposed_initial_receipt_root": proposed_initial_receipt_root,
        "package_id": package_id,
        "manifest_ref": manifest_ref,
        "admitted_manifest_root": admitted_manifest_root,
        "constitution_ref": constitution_ref,
        "constitution_root": constitution_root,
        "profile_bundle_root": profile_bundle_root,
        "profile_materialization_root": profile_materialization_root,
        "deployment_profile_root": deployment_profile_root,
        "profile_refs": profile_refs,
        "component_registry_ref": component_registry_ref,
        "component_registry_root": component_registry_root,
        "component_bindings": component_bindings,
        "sequence": 0,
        "predecessor_transition_commitment_ref": Value::Null,
        "target_status": "materialized_pending_activation",
        "activation_admitted": false,
        "runtime_effect_admitted": false
    });
    let operation_commitment = domain_hash(
        SYSTEM_SEQUENCE_ZERO_OPERATION_HASH_PROFILE,
        &operation_material,
    )?;
    let state_material = serde_json::json!({
        "schema_version": "ioi.autonomous-system-sequence-zero-state.v1",
        "materialization_id": materialization_id,
        "system_id": system_id,
        "genesis_ref": genesis_ref,
        "package_id": package_id,
        "manifest_ref": manifest_ref,
        "admitted_manifest_root": admitted_manifest_root,
        "constitution_ref": constitution_ref,
        "constitution_root": constitution_root,
        "profile_bundle_root": profile_bundle_root,
        "profile_materialization_root": profile_materialization_root,
        "deployment_profile_root": deployment_profile_root,
        "profile_refs": profile_refs,
        "component_registry_ref": component_registry_ref,
        "component_registry_root": component_registry_root,
        "component_bindings": component_bindings,
        "sequence": 0,
        "node_membership_refs": [],
        "worker_instance_refs": [],
        "workflow_refs": [],
        "activation_state": "not_started",
        "status": "materialized_pending_activation"
    });
    let initial_state_root = domain_hash(SYSTEM_SEQUENCE_ZERO_STATE_HASH_PROFILE, &state_material)?;
    let receipt_tail = operation_commitment
        .strip_prefix("sha256:")
        .ok_or_else(|| "operation commitment is not canonical".to_owned())?;
    let materialization_receipt_ref = format!("receipt://aszmr_{receipt_tail}");
    let receipt_material = serde_json::json!({
        "schema_version": "ioi.autonomous-system-sequence-zero-receipt-root.v1",
        "sequence": 0,
        "genesis_admission_receipt_ref": genesis_admission_receipt_ref,
        "genesis_admission_receipt_root": genesis_admission_receipt_root,
        "materialization_receipt_ref": materialization_receipt_ref,
        "operation_commitment": operation_commitment,
        "initial_state_root": initial_state_root
    });
    let initial_receipt_root =
        domain_hash(SYSTEM_SEQUENCE_ZERO_RECEIPT_HASH_PROFILE, &receipt_material)?;
    let transition_material = serde_json::json!({
        "schema_version": "ioi.autonomous-system-sequence-zero-transition.v1",
        "sequence": 0,
        "predecessor_transition_commitment_ref": Value::Null,
        "operation_commitment": operation_commitment,
        "admission_proof_ref": materialization_receipt_ref,
        "resulting_state_root": initial_state_root,
        "receipt_root": initial_receipt_root
    });
    let transition_hash = domain_hash(
        SYSTEM_SEQUENCE_ZERO_TRANSITION_HASH_PROFILE,
        &transition_material,
    )?;
    let transition_commitment_ref =
        format!("commitment://ioi/system-sequence-zero/{transition_hash}");
    let materialization_body = serde_json::json!({
        "schema_version": "ioi.autonomous-system-sequence-zero-materialization.v1",
        "materialization_id": materialization_id,
        "system_id": system_id,
        "genesis_ref": genesis_ref,
        "genesis_admission_receipt_ref": genesis_admission_receipt_ref,
        "genesis_admission_record_root": genesis_admission_record_root,
        "genesis_admission_receipt_root": genesis_admission_receipt_root,
        "proposed_initial_state_root": proposed_initial_state_root,
        "proposed_initial_receipt_root": proposed_initial_receipt_root,
        "package_id": package_id,
        "manifest_ref": manifest_ref,
        "admitted_manifest_root": admitted_manifest_root,
        "constitution_ref": constitution_ref,
        "constitution_root": constitution_root,
        "profile_bundle_root": profile_bundle_root,
        "profile_materialization_root": profile_materialization_root,
        "deployment_profile_root": deployment_profile_root,
        "profile_refs": profile_refs,
        "component_registry_ref": component_registry_ref,
        "component_registry_root": component_registry_root,
        "component_binding_count": component_bindings.len(),
        "component_bindings": component_bindings,
        "sequence": 0,
        "predecessor_transition_commitment_ref": Value::Null,
        "operation_commitment": operation_commitment,
        "transition_commitment_ref": transition_commitment_ref,
        "initial_state_root": initial_state_root,
        "initial_receipt_root": initial_receipt_root,
        "materialization_receipt_ref": materialization_receipt_ref,
        "activation_receipt_ref": Value::Null,
        "status": "materialized_pending_activation"
    });
    let authority_effect = serde_json::json!({
        "operation": "materialize_sequence_zero",
        "materialization": materialization_body,
        "activation_admitted": false,
        "runtime_effect_admitted": false
    });
    Ok(CompiledSystemSequenceZeroPlan {
        component_registry_snapshot,
        materialization_body,
        authority_effect,
        component_registry_root,
        profile_materialization_root,
        operation_commitment,
        initial_state_root,
        initial_receipt_root,
        transition_commitment_ref,
    })
}

/// Add wallet-derived time to a deterministic M1.4 plan and validate its registered contract.
pub fn finalize_system_sequence_zero_materialization(
    plan: &CompiledSystemSequenceZeroPlan,
    created_at: &str,
) -> Result<CompiledSystemSequenceZeroMaterialization, String> {
    let mut value = plan.materialization_body.clone();
    value
        .as_object_mut()
        .ok_or_else(|| "sequence-zero materialization plan is not an object".to_owned())?
        .insert(
            "created_at".to_owned(),
            Value::String(created_at.to_owned()),
        );
    validate_architecture_contract(SEQUENCE_ZERO_MATERIALIZATION_CONTRACT_ID, &value)
        .map_err(|error| format!("sequence-zero materialization contract invalid ({error})"))?;
    let materialization =
        serde_json::from_value::<AutonomousSystemSequenceZeroMaterializationV1>(value.clone())
            .map_err(|error| {
                format!("sequence-zero materialization projection failed ({error})")
            })?;
    let canonical_json = serde_jcs::to_vec(&value)
        .map_err(|error| format!("sequence-zero materialization JCS failed ({error})"))?;
    Ok(CompiledSystemSequenceZeroMaterialization {
        materialization,
        canonical_json,
    })
}

/// Compile a proposal without identity minting, authority verification, persistence, or effects.
pub fn compile_system_genesis_proposal(
    release: &Value,
    proposed_instantiation: &Value,
) -> SystemGenesisCompilation {
    let mut blockers = BlockerCollector::default();

    scan_forbidden_material(release, "$.release", true, &mut blockers);
    scan_forbidden_material(proposed_instantiation, "$.proposed", false, &mut blockers);
    scan_mutable_references(release, "$.release", &mut blockers);
    scan_mutable_references(proposed_instantiation, "$.proposed", &mut blockers);

    validate_contract(
        MANIFEST_CONTRACT_ID,
        release,
        "$.release",
        SystemGenesisBlockerCode::ReleaseContractInvalid,
        &mut blockers,
    );
    validate_proposal_input_shape(proposed_instantiation, &mut blockers);
    validate_manifest_coordinates(release, &mut blockers);
    validate_new_system_use(release, &mut blockers);
    validate_manifest_hashes_and_tuples(release, &mut blockers);
    validate_template_bindings(release, proposed_instantiation, &mut blockers);
    validate_proposal_coordinates(release, proposed_instantiation, &mut blockers);
    validate_component_bindings(release, proposed_instantiation, &mut blockers);

    let initial_profile_bundle_value = build_initial_profile_bundle(proposed_instantiation);
    validate_contract(
        INITIAL_PROFILE_BUNDLE_CONTRACT_ID,
        &initial_profile_bundle_value,
        "$.proposed.initial_profile_bundle",
        SystemGenesisBlockerCode::InitialProfileBundleInvalid,
        &mut blockers,
    );
    let initial_profile_bundle_canonical_json =
        match serde_jcs::to_vec(&initial_profile_bundle_value) {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                blockers.push(
                    SystemGenesisBlockerCode::HashingFailed,
                    "$.proposed.initial_profile_bundle",
                );
                None
            }
        };
    let initial_profile_bundle_root = match domain_hash(
        SYSTEM_INITIAL_PROFILE_BUNDLE_HASH_PROFILE,
        &initial_profile_bundle_value,
    ) {
        Ok(root) => Some(root),
        Err(_) => {
            blockers.push(
                SystemGenesisBlockerCode::HashingFailed,
                "$.proposed.initial_profile_bundle",
            );
            None
        }
    };

    let mut genesis_value = proposed_instantiation
        .pointer("/candidate")
        .cloned()
        .unwrap_or(Value::Null);
    let release_root = release.get("release_root").cloned();
    if let (Some(genesis), Some(release_root), Some(bundle_root)) = (
        genesis_value.as_object_mut(),
        release_root,
        initial_profile_bundle_root.as_ref(),
    ) {
        genesis.insert("admitted_manifest_root".to_owned(), release_root);
        genesis.insert(
            "initial_profile_bundle_root".to_owned(),
            Value::String(bundle_root.clone()),
        );
    }

    let operation_commitment = if genesis_value.is_object() {
        match domain_hash(SYSTEM_GENESIS_OPERATION_HASH_PROFILE, &genesis_value) {
            Ok(hash) => Some(hash),
            Err(_) => {
                blockers.push(
                    SystemGenesisBlockerCode::HashingFailed,
                    "$.proposed.candidate",
                );
                None
            }
        }
    } else {
        None
    };

    if let (Some(genesis), Some(operation_commitment)) =
        (genesis_value.as_object_mut(), operation_commitment)
    {
        if let Some(origin) = genesis
            .get_mut("cryptographic_origin")
            .and_then(Value::as_object_mut)
        {
            origin.insert(
                "genesis_operation_commitment".to_owned(),
                Value::String(operation_commitment.clone()),
            );
            origin.insert(
                "genesis_transition_commitment_ref".to_owned(),
                Value::String(format!(
                    "commitment://ioi/system-genesis/{operation_commitment}"
                )),
            );
        } else {
            blockers.push(
                SystemGenesisBlockerCode::RequiredFieldMissing,
                "$.proposed.candidate.cryptographic_origin",
            );
        }
    }

    validate_contract(
        GENESIS_CONTRACT_ID,
        &genesis_value,
        "$.proposed.candidate",
        SystemGenesisBlockerCode::ProposedInstantiationInvalid,
        &mut blockers,
    );

    let report = blockers.finish();
    if !report.blockers.is_empty() {
        return SystemGenesisCompilation {
            proposal: None,
            blocker_report: report,
            authority_effect_boundary: SYSTEM_GENESIS_PROPOSAL_AUTHORITY_BOUNDARY,
        };
    }

    let genesis = match serde_json::from_value::<AutonomousSystemGenesisV1>(genesis_value.clone()) {
        Ok(genesis) => genesis,
        Err(_) => {
            return failed_hash_or_projection(
                SystemGenesisBlockerCode::ProposedInstantiationInvalid,
                "$.proposed.candidate",
            );
        }
    };
    let initial_profile_bundle = match serde_json::from_value::<
        AutonomousSystemInitialProfileBundleV1,
    >(initial_profile_bundle_value)
    {
        Ok(bundle) => bundle,
        Err(_) => {
            return failed_hash_or_projection(
                SystemGenesisBlockerCode::InitialProfileBundleInvalid,
                "$.proposed.initial_profile_bundle",
            );
        }
    };
    let Some(initial_profile_bundle_canonical_json) = initial_profile_bundle_canonical_json else {
        return failed_hash_or_projection(
            SystemGenesisBlockerCode::HashingFailed,
            "$.proposed.initial_profile_bundle",
        );
    };
    let Some(initial_profile_bundle_root) = initial_profile_bundle_root else {
        return failed_hash_or_projection(
            SystemGenesisBlockerCode::HashingFailed,
            "$.proposed.initial_profile_bundle",
        );
    };
    let canonical_json = match serde_jcs::to_vec(&genesis_value) {
        Ok(bytes) => bytes,
        Err(_) => {
            return failed_hash_or_projection(
                SystemGenesisBlockerCode::HashingFailed,
                "$.proposed.candidate",
            );
        }
    };
    let proposal_root = match domain_hash(SYSTEM_GENESIS_PROPOSAL_ROOT_HASH_PROFILE, &genesis_value)
    {
        Ok(root) => root,
        Err(_) => {
            return failed_hash_or_projection(
                SystemGenesisBlockerCode::HashingFailed,
                "$.proposed.candidate",
            );
        }
    };

    SystemGenesisCompilation {
        proposal: Some(CompiledSystemGenesisProposal {
            initial_profile_bundle: CompiledSystemInitialProfileBundle {
                bundle: initial_profile_bundle,
                canonical_json: initial_profile_bundle_canonical_json,
                bundle_root: initial_profile_bundle_root,
                hash_profile: SYSTEM_INITIAL_PROFILE_BUNDLE_HASH_PROFILE,
            },
            genesis,
            canonical_json,
            proposal_root,
            hash_profile: SYSTEM_GENESIS_PROPOSAL_ROOT_HASH_PROFILE,
        }),
        blocker_report: report,
        authority_effect_boundary: SYSTEM_GENESIS_PROPOSAL_AUTHORITY_BOUNDARY,
    }
}

fn failed_hash_or_projection(
    code: SystemGenesisBlockerCode,
    path: &str,
) -> SystemGenesisCompilation {
    let mut blockers = BlockerCollector::default();
    blockers.push(code, path);
    SystemGenesisCompilation {
        proposal: None,
        blocker_report: blockers.finish(),
        authority_effect_boundary: SYSTEM_GENESIS_PROPOSAL_AUTHORITY_BOUNDARY,
    }
}

fn domain_hash(domain: &'static str, value: &Value) -> Result<String, String> {
    let canonical = serde_jcs::to_vec(&DomainSeparatedMaterial { domain, value })
        .map_err(|error| error.to_string())?;
    let digest = Sha256::digest(&canonical).map_err(|error| error.to_string())?;
    let hex = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("sha256:{hex}"))
}

fn validate_contract(
    contract_id: &str,
    value: &Value,
    base_path: &str,
    code: SystemGenesisBlockerCode,
    blockers: &mut BlockerCollector,
) {
    if let Err(error) = validate_architecture_contract(contract_id, value) {
        blockers.push(code, join_schema_path(base_path, &error));
    }
}

fn join_schema_path(base_path: &str, error: &str) -> String {
    let schema_path = error
        .split_once(':')
        .map(|(path, _)| path)
        .filter(|path| path.starts_with('$'))
        .unwrap_or("$");
    if schema_path == "$" {
        base_path.to_owned()
    } else {
        format!("{base_path}{}", schema_path.trim_start_matches('$'))
    }
}

fn build_initial_profile_bundle(proposed: &Value) -> Value {
    let mut bundle = Map::new();
    bundle.insert(
        "schema_version".to_owned(),
        Value::String(INITIAL_PROFILE_BUNDLE_SCHEMA_VERSION.to_owned()),
    );
    for field in [
        "constitution",
        "ordering_profile",
        "oracle_profiles",
        "lifecycle_profile",
        "network_enrollment",
    ] {
        bundle.insert(
            field.to_owned(),
            proposed.get(field).cloned().unwrap_or(Value::Null),
        );
    }
    Value::Object(bundle)
}

fn validate_proposal_input_shape(value: &Value, blockers: &mut BlockerCollector) {
    const TOP_LEVEL: &[&str] = &[
        "schema_version",
        "candidate",
        "template_bindings",
        "constitution",
        "ordering_profile",
        "oracle_profiles",
        "lifecycle_profile",
        "network_enrollment",
    ];
    const CANDIDATE: &[&str] = &[
        "schema_version",
        "genesis_id",
        "system_id",
        "package_id",
        "manifest_ref",
        "constitution_ref",
        "initial_profile_refs",
        "initial_component_bindings",
        "instantiation",
        "cryptographic_origin",
        "activation_receipt_ref",
        "lifecycle_transition_refs",
        "status_source_receipt_refs",
        "created_at",
        "status",
    ];
    const ORIGIN: &[&str] = &[
        "sequence",
        "predecessor_commitment_ref",
        "initial_state_root",
        "initial_receipt_root",
        "admission_proof_ref",
    ];
    const TEMPLATE_BINDINGS: &[&str] = &[
        "constitution_template_ref",
        "deployment_template_ref",
        "ordering_admission_finality_template_ref",
        "oracle_evidence_template_refs",
        "lifecycle_continuity_template_ref",
        "network_enrollment_constraint_ref",
    ];

    check_closed_object(value, "$.proposed", TOP_LEVEL, blockers);
    check_required_properties(value, "$.proposed", TOP_LEVEL, blockers);
    if value.get("schema_version").and_then(Value::as_str) != Some(PROPOSAL_INPUT_SCHEMA_VERSION) {
        blockers.push(
            SystemGenesisBlockerCode::ProposedInstantiationInvalid,
            "$.proposed.schema_version",
        );
    }
    let Some(proposal) = value.as_object() else {
        return;
    };
    check_type(
        proposal.get("schema_version"),
        "$.proposed.schema_version",
        Value::is_string,
        blockers,
    );
    for field in [
        "candidate",
        "template_bindings",
        "constitution",
        "ordering_profile",
        "lifecycle_profile",
    ] {
        check_type(
            proposal.get(field),
            &format!("$.proposed.{field}"),
            Value::is_object,
            blockers,
        );
    }
    check_type(
        proposal.get("oracle_profiles"),
        "$.proposed.oracle_profiles",
        Value::is_array,
        blockers,
    );
    if let Some(profiles) = proposal.get("oracle_profiles").and_then(Value::as_array) {
        for (index, profile) in profiles.iter().enumerate() {
            check_type(
                Some(profile),
                &format!("$.proposed.oracle_profiles[{index}]"),
                Value::is_object,
                blockers,
            );
        }
    }
    check_type(
        proposal.get("network_enrollment"),
        "$.proposed.network_enrollment",
        |candidate| candidate.is_null() || candidate.is_object(),
        blockers,
    );

    if let Some(candidate) = proposal.get("candidate").filter(|value| value.is_object()) {
        check_closed_object(candidate, "$.proposed.candidate", CANDIDATE, blockers);
        check_required_properties(candidate, "$.proposed.candidate", CANDIDATE, blockers);
        for field in [
            "schema_version",
            "genesis_id",
            "system_id",
            "package_id",
            "manifest_ref",
            "constitution_ref",
            "created_at",
            "status",
        ] {
            check_type(
                candidate.get(field),
                &format!("$.proposed.candidate.{field}"),
                Value::is_string,
                blockers,
            );
        }
        for field in [
            "initial_profile_refs",
            "initial_component_bindings",
            "instantiation",
            "cryptographic_origin",
        ] {
            check_type(
                candidate.get(field),
                &format!("$.proposed.candidate.{field}"),
                Value::is_object,
                blockers,
            );
        }
        check_type(
            candidate.get("activation_receipt_ref"),
            "$.proposed.candidate.activation_receipt_ref",
            is_nullable_string,
            blockers,
        );
        for field in ["lifecycle_transition_refs", "status_source_receipt_refs"] {
            check_string_array(
                candidate.get(field),
                &format!("$.proposed.candidate.{field}"),
                blockers,
            );
        }
        if let Some(origin) = candidate.get("cryptographic_origin") {
            check_closed_object(
                origin,
                "$.proposed.candidate.cryptographic_origin",
                ORIGIN,
                blockers,
            );
            check_required_properties(
                origin,
                "$.proposed.candidate.cryptographic_origin",
                ORIGIN,
                blockers,
            );
            if let Some(origin) = origin.as_object() {
                check_type(
                    origin.get("sequence"),
                    "$.proposed.candidate.cryptographic_origin.sequence",
                    is_json_integer,
                    blockers,
                );
                for field in ["predecessor_commitment_ref", "admission_proof_ref"] {
                    check_type(
                        origin.get(field),
                        &format!("$.proposed.candidate.cryptographic_origin.{field}"),
                        is_nullable_string,
                        blockers,
                    );
                }
                for field in ["initial_state_root", "initial_receipt_root"] {
                    check_type(
                        origin.get(field),
                        &format!("$.proposed.candidate.cryptographic_origin.{field}"),
                        Value::is_string,
                        blockers,
                    );
                }
            }
        }
    }
    if let Some(bindings) = proposal
        .get("template_bindings")
        .filter(|value| value.is_object())
    {
        check_closed_object(
            bindings,
            "$.proposed.template_bindings",
            TEMPLATE_BINDINGS,
            blockers,
        );
        check_required_properties(
            bindings,
            "$.proposed.template_bindings",
            TEMPLATE_BINDINGS,
            blockers,
        );
        for field in [
            "constitution_template_ref",
            "deployment_template_ref",
            "ordering_admission_finality_template_ref",
            "lifecycle_continuity_template_ref",
            "network_enrollment_constraint_ref",
        ] {
            check_type(
                bindings.get(field),
                &format!("$.proposed.template_bindings.{field}"),
                Value::is_string,
                blockers,
            );
        }
        check_string_array(
            bindings.get("oracle_evidence_template_refs"),
            "$.proposed.template_bindings.oracle_evidence_template_refs",
            blockers,
        );
    }
}

fn check_type(
    value: Option<&Value>,
    path: &str,
    predicate: impl Fn(&Value) -> bool,
    blockers: &mut BlockerCollector,
) {
    if value.is_some_and(|candidate| !predicate(candidate)) {
        blockers.push(SystemGenesisBlockerCode::ProposedInstantiationInvalid, path);
    }
}

fn check_string_array(value: Option<&Value>, path: &str, blockers: &mut BlockerCollector) {
    check_type(value, path, Value::is_array, blockers);
    if let Some(items) = value.and_then(Value::as_array) {
        for (index, item) in items.iter().enumerate() {
            check_type(
                Some(item),
                &format!("{path}[{index}]"),
                Value::is_string,
                blockers,
            );
        }
    }
}

fn is_nullable_string(value: &Value) -> bool {
    value.is_null() || value.is_string()
}

fn is_json_integer(value: &Value) -> bool {
    value.as_i64().is_some() || value.as_u64().is_some()
}

fn check_closed_object(
    value: &Value,
    path: &str,
    allowed: &[&str],
    blockers: &mut BlockerCollector,
) {
    let Some(object) = value.as_object() else {
        blockers.push(SystemGenesisBlockerCode::ProposedInstantiationInvalid, path);
        return;
    };
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            blockers.push(
                SystemGenesisBlockerCode::UnknownProperty,
                format!("{path}.{key}"),
            );
        }
    }
}

fn check_required_properties(
    value: &Value,
    path: &str,
    required: &[&str],
    blockers: &mut BlockerCollector,
) {
    let Some(object) = value.as_object() else {
        return;
    };
    for key in required {
        if !object.contains_key(*key) {
            blockers.push(
                SystemGenesisBlockerCode::RequiredFieldMissing,
                format!("{path}.{key}"),
            );
        }
    }
}

fn validate_new_system_use(release: &Value, blockers: &mut BlockerCollector) {
    if release
        .pointer("/system_binding/allowed_use")
        .and_then(Value::as_str)
        == Some("upgrade_existing")
    {
        blockers.push(
            SystemGenesisBlockerCode::NewSystemInstantiationForbidden,
            "$.release.system_binding.allowed_use",
        );
    }
}

fn validate_manifest_coordinates(release: &Value, blockers: &mut BlockerCollector) {
    let package_id = release.get("package_id").and_then(Value::as_str);
    let manifest_id = release.get("manifest_id").and_then(Value::as_str);
    if !package_id
        .zip(manifest_id)
        .is_some_and(|(package, manifest)| {
            manifest.starts_with(&format!("{package}/release/sha256:"))
        })
    {
        blockers.push(
            SystemGenesisBlockerCode::ManifestPackageMismatch,
            "$.release.manifest_id",
        );
    }
}

fn validate_manifest_hashes_and_tuples(release: &Value, blockers: &mut BlockerCollector) {
    match compute_system_component_set_hash(release) {
        Ok(expected) => {
            if release.pointer("/typed_components/component_set_hash")
                != Some(&Value::String(expected))
            {
                blockers.push(
                    SystemGenesisBlockerCode::ComponentSetHashMismatch,
                    "$.release.typed_components.component_set_hash",
                );
            }
        }
        Err(_) => blockers.push(
            SystemGenesisBlockerCode::HashingFailed,
            "$.release.typed_components",
        ),
    }
    match compute_system_release_root(release) {
        Ok(expected) => {
            if release.get("release_root") != Some(&Value::String(expected)) {
                blockers.push(
                    SystemGenesisBlockerCode::ReleaseRootMismatch,
                    "$.release.release_root",
                );
            }
        }
        Err(_) => blockers.push(SystemGenesisBlockerCode::HashingFailed, "$.release"),
    }

    let mut identities = BTreeMap::<String, String>::new();
    if let Some(worker) = release.get("worker") {
        register_tuple(
            worker.get("worker_revision_ref"),
            worker.get("worker_content_hash"),
            "$.release.worker.worker_revision_ref",
            &mut identities,
            blockers,
        );
    }
    for field in TUPLE_FIELDS {
        let Some(tuples) = release
            .pointer(&format!("/typed_components/{field}"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for (index, tuple) in tuples.iter().enumerate() {
            register_tuple(
                tuple.get("revision_ref"),
                tuple.get("content_hash"),
                &format!("$.release.typed_components.{field}[{index}].revision_ref"),
                &mut identities,
                blockers,
            );
        }
    }
}

fn register_tuple(
    revision_ref: Option<&Value>,
    content_hash: Option<&Value>,
    path: &str,
    identities: &mut BTreeMap<String, String>,
    blockers: &mut BlockerCollector,
) {
    let Some((revision_ref, content_hash)) = revision_ref
        .and_then(Value::as_str)
        .zip(content_hash.and_then(Value::as_str))
    else {
        return;
    };
    if let Some(existing_hash) = identities.insert(revision_ref.to_owned(), content_hash.to_owned())
    {
        blockers.push(
            if existing_hash == content_hash {
                SystemGenesisBlockerCode::TupleIdentityDuplicate
            } else {
                SystemGenesisBlockerCode::TupleIdentityCollision
            },
            path,
        );
    }
}

fn validate_template_bindings(release: &Value, proposed: &Value, blockers: &mut BlockerCollector) {
    const TEMPLATE_PAIRS: &[(&str, &str)] = &[
        (
            "/constitution_template_ref",
            "/template_bindings/constitution_template_ref",
        ),
        (
            "/required_profile_templates/deployment_template_ref",
            "/template_bindings/deployment_template_ref",
        ),
        (
            "/required_profile_templates/ordering_admission_finality_template_ref",
            "/template_bindings/ordering_admission_finality_template_ref",
        ),
        (
            "/required_profile_templates/oracle_evidence_template_refs",
            "/template_bindings/oracle_evidence_template_refs",
        ),
        (
            "/required_profile_templates/lifecycle_continuity_template_ref",
            "/template_bindings/lifecycle_continuity_template_ref",
        ),
        (
            "/required_profile_templates/network_enrollment_constraint_ref",
            "/template_bindings/network_enrollment_constraint_ref",
        ),
    ];
    for (release_pointer, proposal_pointer) in TEMPLATE_PAIRS {
        let release_value = release.pointer(release_pointer);
        if release_value.is_none()
            || release_value.is_some_and(|value| {
                value.is_null()
                    || value.as_str().is_some_and(str::is_empty)
                    || value.as_array().is_some_and(Vec::is_empty)
            })
        {
            blockers.push(
                SystemGenesisBlockerCode::RequiredTemplateMissing,
                format!("$.release{}", release_pointer.replace('/', ".")),
            );
        }
        if release_value != proposed.pointer(proposal_pointer) {
            blockers.push(
                SystemGenesisBlockerCode::TemplateBindingMismatch,
                format!("$.proposed{}", proposal_pointer.replace('/', ".")),
            );
        }
    }
}

fn validate_proposal_coordinates(
    release: &Value,
    proposed: &Value,
    blockers: &mut BlockerCollector,
) {
    let Some(candidate) = proposed.get("candidate") else {
        return;
    };
    check_equal(
        candidate.get("package_id"),
        release.get("package_id"),
        SystemGenesisBlockerCode::ManifestPackageMismatch,
        "$.proposed.candidate.package_id",
        blockers,
    );
    check_equal(
        candidate.get("manifest_ref"),
        release.get("manifest_id"),
        SystemGenesisBlockerCode::ManifestPackageMismatch,
        "$.proposed.candidate.manifest_ref",
        blockers,
    );
    let genesis_matches_system = candidate
        .get("genesis_id")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("genesis://"))
        .zip(
            candidate
                .get("system_id")
                .and_then(Value::as_str)
                .and_then(|value| value.strip_prefix("system://")),
        )
        .is_some_and(|(genesis, system)| genesis.starts_with(&format!("{system}/")));
    if !genesis_matches_system {
        blockers.push(
            SystemGenesisBlockerCode::GenesisCoordinateMismatch,
            "$.proposed.candidate.genesis_id",
        );
    }

    let status = candidate.get("status").and_then(Value::as_str);
    if status != Some("proposed") {
        blockers.push(
            SystemGenesisBlockerCode::GenesisStatusNotProposed,
            "$.proposed.candidate.status",
        );
    }
    if status
        .is_some_and(|value| matches!(value, "admitted" | "authorized" | "activated" | "active"))
    {
        blockers.push(
            SystemGenesisBlockerCode::GenesisActivationClaimForbidden,
            "$.proposed.candidate.status",
        );
    }
    if candidate
        .pointer("/cryptographic_origin/sequence")
        .and_then(Value::as_u64)
        != Some(0)
    {
        blockers.push(
            SystemGenesisBlockerCode::GenesisSequenceNotZero,
            "$.proposed.candidate.cryptographic_origin.sequence",
        );
    }
    if candidate
        .pointer("/cryptographic_origin/predecessor_commitment_ref")
        .is_some_and(|value| !value.is_null())
    {
        blockers.push(
            SystemGenesisBlockerCode::GenesisPredecessorForbidden,
            "$.proposed.candidate.cryptographic_origin.predecessor_commitment_ref",
        );
    }
    if candidate
        .pointer("/cryptographic_origin/admission_proof_ref")
        .is_some_and(|value| !value.is_null())
    {
        blockers.push(
            SystemGenesisBlockerCode::GenesisActivationClaimForbidden,
            "$.proposed.candidate.cryptographic_origin.admission_proof_ref",
        );
    }
    if candidate
        .get("activation_receipt_ref")
        .is_some_and(|value| !value.is_null())
    {
        blockers.push(
            SystemGenesisBlockerCode::GenesisActivationClaimForbidden,
            "$.proposed.candidate.activation_receipt_ref",
        );
    }
    for field in ["authority_grant_refs", "conformance_receipt_refs"] {
        if candidate
            .pointer(&format!("/instantiation/{field}"))
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
        {
            blockers.push(
                SystemGenesisBlockerCode::GenesisActivationClaimForbidden,
                format!("$.proposed.candidate.instantiation.{field}"),
            );
        }
    }
    for field in ["lifecycle_transition_refs", "status_source_receipt_refs"] {
        if candidate
            .get(field)
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
        {
            blockers.push(
                SystemGenesisBlockerCode::GenesisHistoryForbidden,
                format!("$.proposed.candidate.{field}"),
            );
        }
    }

    let system_id = candidate.get("system_id");
    let constitution_ref = candidate.get("constitution_ref");
    check_system_scoped_ref(
        constitution_ref,
        "constitution://",
        system_id,
        SystemGenesisBlockerCode::ConstitutionCoordinateMismatch,
        "$.proposed.candidate.constitution_ref",
        blockers,
    );
    check_system_scoped_ref(
        candidate.pointer("/initial_profile_refs/deployment_profile_ref"),
        "deployment-profile://",
        system_id,
        SystemGenesisBlockerCode::ProfileCoordinateMismatch,
        "$.proposed.candidate.initial_profile_refs.deployment_profile_ref",
        blockers,
    );
    check_system_scoped_ref(
        candidate.pointer("/initial_profile_refs/ordering_admission_finality_profile_ref"),
        "ordering-profile://",
        system_id,
        SystemGenesisBlockerCode::ProfileCoordinateMismatch,
        "$.proposed.candidate.initial_profile_refs.ordering_admission_finality_profile_ref",
        blockers,
    );
    if let Some(oracle_refs) = candidate
        .pointer("/initial_profile_refs/oracle_evidence_profile_refs")
        .and_then(Value::as_array)
    {
        for (index, oracle_ref) in oracle_refs.iter().enumerate() {
            check_system_scoped_ref(
                Some(oracle_ref),
                "oracle-evidence-profile://",
                system_id,
                SystemGenesisBlockerCode::ProfileCoordinateMismatch,
                &format!(
                    "$.proposed.candidate.initial_profile_refs.oracle_evidence_profile_refs[{index}]"
                ),
                blockers,
            );
        }
    }
    check_system_scoped_ref(
        candidate.pointer("/initial_profile_refs/lifecycle_continuity_profile_ref"),
        "lifecycle-profile://",
        system_id,
        SystemGenesisBlockerCode::ProfileCoordinateMismatch,
        "$.proposed.candidate.initial_profile_refs.lifecycle_continuity_profile_ref",
        blockers,
    );
    let network_ref = candidate.pointer("/initial_profile_refs/network_enrollment_ref");
    if network_ref.is_some_and(|value| !value.is_null()) {
        check_system_scoped_ref(
            network_ref,
            "network-enrollment://",
            system_id,
            SystemGenesisBlockerCode::NetworkEnrollmentCoordinateMismatch,
            "$.proposed.candidate.initial_profile_refs.network_enrollment_ref",
            blockers,
        );
    }
    if let Some(constitution) = proposed.get("constitution") {
        validate_contract(
            CONSTITUTION_CONTRACT_ID,
            constitution,
            "$.proposed.constitution",
            SystemGenesisBlockerCode::ProposedInstantiationInvalid,
            blockers,
        );
        check_equal(
            constitution.get("system_id"),
            system_id,
            SystemGenesisBlockerCode::ConstitutionCoordinateMismatch,
            "$.proposed.constitution.system_id",
            blockers,
        );
        check_equal(
            constitution.get("constitution_id"),
            constitution_ref,
            SystemGenesisBlockerCode::ConstitutionCoordinateMismatch,
            "$.proposed.constitution.constitution_id",
            blockers,
        );
        require_proposal_status(
            constitution,
            &["draft"],
            "$.proposed.constitution.status",
            blockers,
        );
        if constitution
            .get("predecessor_constitution_ref")
            .is_some_and(|value| !value.is_null())
        {
            blockers.push(
                SystemGenesisBlockerCode::ConstitutionPredecessorForbidden,
                "$.proposed.constitution.predecessor_constitution_ref",
            );
        }
        if constitution
            .get("activation_receipt_ref")
            .is_some_and(|value| !value.is_null())
        {
            blockers.push(
                SystemGenesisBlockerCode::ConstitutionActivationReceiptForbidden,
                "$.proposed.constitution.activation_receipt_ref",
            );
        }
    }

    if let Some(ordering) = proposed.get("ordering_profile") {
        validate_contract(
            ORDERING_CONTRACT_ID,
            ordering,
            "$.proposed.ordering_profile",
            SystemGenesisBlockerCode::ProposedInstantiationInvalid,
            blockers,
        );
        check_equal(
            ordering.get("system_id"),
            system_id,
            SystemGenesisBlockerCode::ProfileCoordinateMismatch,
            "$.proposed.ordering_profile.system_id",
            blockers,
        );
        check_equal(
            ordering.get("constitution_ref"),
            constitution_ref,
            SystemGenesisBlockerCode::ProfileCoordinateMismatch,
            "$.proposed.ordering_profile.constitution_ref",
            blockers,
        );
        check_equal(
            ordering.get("ordering_profile_id"),
            candidate.pointer("/initial_profile_refs/ordering_admission_finality_profile_ref"),
            SystemGenesisBlockerCode::ProfileCoordinateMismatch,
            "$.proposed.ordering_profile.ordering_profile_id",
            blockers,
        );
        require_proposal_status(
            ordering,
            &["draft"],
            "$.proposed.ordering_profile.status",
            blockers,
        );
        reject_nonempty_evidence_array(
            ordering,
            "/conformance_receipt_refs",
            "$.proposed.ordering_profile.conformance_receipt_refs",
            blockers,
        );
    }

    if let Some(lifecycle) = proposed.get("lifecycle_profile") {
        validate_contract(
            LIFECYCLE_CONTRACT_ID,
            lifecycle,
            "$.proposed.lifecycle_profile",
            SystemGenesisBlockerCode::ProposedInstantiationInvalid,
            blockers,
        );
        check_equal(
            lifecycle.get("system_id"),
            system_id,
            SystemGenesisBlockerCode::ProfileCoordinateMismatch,
            "$.proposed.lifecycle_profile.system_id",
            blockers,
        );
        check_equal(
            lifecycle.get("constitution_ref"),
            constitution_ref,
            SystemGenesisBlockerCode::ProfileCoordinateMismatch,
            "$.proposed.lifecycle_profile.constitution_ref",
            blockers,
        );
        check_equal(
            lifecycle.get("lifecycle_profile_id"),
            candidate.pointer("/initial_profile_refs/lifecycle_continuity_profile_ref"),
            SystemGenesisBlockerCode::ProfileCoordinateMismatch,
            "$.proposed.lifecycle_profile.lifecycle_profile_id",
            blockers,
        );
        require_proposal_status(
            lifecycle,
            &["draft"],
            "$.proposed.lifecycle_profile.status",
            blockers,
        );
    }

    let oracle_profiles = proposed.get("oracle_profiles").and_then(Value::as_array);
    let mut oracle_ids = Vec::new();
    if let Some(profiles) = oracle_profiles {
        for (index, profile) in profiles.iter().enumerate() {
            validate_contract(
                ORACLE_CONTRACT_ID,
                profile,
                &format!("$.proposed.oracle_profiles[{index}]"),
                SystemGenesisBlockerCode::ProposedInstantiationInvalid,
                blockers,
            );
            check_equal(
                profile.get("system_id"),
                system_id,
                SystemGenesisBlockerCode::ProfileCoordinateMismatch,
                &format!("$.proposed.oracle_profiles[{index}].system_id"),
                blockers,
            );
            require_proposal_status(
                profile,
                &["draft"],
                &format!("$.proposed.oracle_profiles[{index}].status"),
                blockers,
            );
            if let Some(id) = profile.get("oracle_evidence_profile_id") {
                oracle_ids.push(id.clone());
            }
        }
    }
    check_equal(
        Some(&Value::Array(oracle_ids)),
        candidate.pointer("/initial_profile_refs/oracle_evidence_profile_refs"),
        SystemGenesisBlockerCode::ProfileCoordinateMismatch,
        "$.proposed.candidate.initial_profile_refs.oracle_evidence_profile_refs",
        blockers,
    );

    match proposed.get("network_enrollment") {
        Some(enrollment) if !enrollment.is_null() => {
            validate_contract(
                NETWORK_ENROLLMENT_CONTRACT_ID,
                enrollment,
                "$.proposed.network_enrollment",
                SystemGenesisBlockerCode::ProposedInstantiationInvalid,
                blockers,
            );
            for (field, expected, path) in [
                (
                    "system_id",
                    system_id,
                    "$.proposed.network_enrollment.system_id",
                ),
                (
                    "constitution_ref",
                    constitution_ref,
                    "$.proposed.network_enrollment.constitution_ref",
                ),
                (
                    "manifest_ref",
                    release.get("manifest_id"),
                    "$.proposed.network_enrollment.manifest_ref",
                ),
                (
                    "network_enrollment_id",
                    candidate.pointer("/initial_profile_refs/network_enrollment_ref"),
                    "$.proposed.network_enrollment.network_enrollment_id",
                ),
            ] {
                check_equal(
                    enrollment.get(field),
                    expected,
                    SystemGenesisBlockerCode::NetworkEnrollmentCoordinateMismatch,
                    path,
                    blockers,
                );
            }
            require_proposal_status(
                enrollment,
                &["local_only", "pending"],
                "$.proposed.network_enrollment.status",
                blockers,
            );
            if enrollment
                .get("predecessor_enrollment_ref")
                .is_some_and(|value| !value.is_null())
            {
                blockers.push(
                    SystemGenesisBlockerCode::NetworkEnrollmentPredecessorForbidden,
                    "$.proposed.network_enrollment.predecessor_enrollment_ref",
                );
            }
            for (pointer, path) in [
                (
                    "/authority_grant_refs",
                    "$.proposed.network_enrollment.authority_grant_refs",
                ),
                (
                    "/conformance/conformance_receipt_refs",
                    "$.proposed.network_enrollment.conformance.conformance_receipt_refs",
                ),
                (
                    "/transition_receipt_refs",
                    "$.proposed.network_enrollment.transition_receipt_refs",
                ),
            ] {
                reject_nonempty_evidence_array(enrollment, pointer, path, blockers);
            }
        }
        Some(_) => {
            if candidate
                .pointer("/initial_profile_refs/network_enrollment_ref")
                .is_some_and(|value| !value.is_null())
            {
                blockers.push(
                    SystemGenesisBlockerCode::NetworkEnrollmentCoordinateMismatch,
                    "$.proposed.candidate.initial_profile_refs.network_enrollment_ref",
                );
            }
        }
        None => {}
    }
}

fn check_system_scoped_ref(
    reference: Option<&Value>,
    scheme: &str,
    system_id: Option<&Value>,
    code: SystemGenesisBlockerCode,
    path: &str,
    blockers: &mut BlockerCollector,
) {
    let matches = reference
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix(scheme))
        .zip(
            system_id
                .and_then(Value::as_str)
                .and_then(|value| value.strip_prefix("system://")),
        )
        .is_some_and(|(reference, system)| reference.starts_with(&format!("{system}/")));
    if !matches {
        blockers.push(code, path);
    }
}

fn require_proposal_status(
    value: &Value,
    allowed: &[&str],
    path: &str,
    blockers: &mut BlockerCollector,
) {
    if !value
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| allowed.contains(&status))
    {
        blockers.push(
            SystemGenesisBlockerCode::GenesisActivationClaimForbidden,
            path,
        );
    }
}

fn reject_nonempty_evidence_array(
    value: &Value,
    pointer: &str,
    path: &str,
    blockers: &mut BlockerCollector,
) {
    if value
        .pointer(pointer)
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
    {
        blockers.push(
            SystemGenesisBlockerCode::GenesisActivationClaimForbidden,
            path,
        );
    }
}

fn check_equal(
    left: Option<&Value>,
    right: Option<&Value>,
    code: SystemGenesisBlockerCode,
    path: &str,
    blockers: &mut BlockerCollector,
) {
    if left.is_none() || right.is_none() || left != right {
        blockers.push(code, path);
    }
}

fn validate_component_bindings(release: &Value, proposed: &Value, blockers: &mut BlockerCollector) {
    let Some(bindings) = proposed.pointer("/candidate/initial_component_bindings") else {
        return;
    };
    check_equal(
        bindings.get("admitted_component_set_snapshot_ref"),
        release.pointer("/typed_components/component_set_snapshot_ref"),
        SystemGenesisBlockerCode::ComponentBindingMismatch,
        "$.proposed.candidate.initial_component_bindings.admitted_component_set_snapshot_ref",
        blockers,
    );
    check_equal(
        bindings.get("admitted_component_set_hash"),
        release.pointer("/typed_components/component_set_hash"),
        SystemGenesisBlockerCode::ComponentBindingMismatch,
        "$.proposed.candidate.initial_component_bindings.admitted_component_set_hash",
        blockers,
    );
    for field in DIRECT_COMPONENT_BINDING_FIELDS {
        check_equal(
            bindings.get(*field),
            release.pointer(&format!("/typed_components/{field}")),
            SystemGenesisBlockerCode::ComponentBindingMismatch,
            &format!("$.proposed.candidate.initial_component_bindings.{field}"),
            blockers,
        );
    }
    for field in LIVE_BINDING_FIELDS {
        if bindings
            .get(*field)
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
        {
            blockers.push(
                SystemGenesisBlockerCode::LiveBindingAdmissionUnavailable,
                format!("$.proposed.candidate.initial_component_bindings.{field}"),
            );
        }
    }
}

fn scan_forbidden_material(
    value: &Value,
    path: &str,
    package_context: bool,
    blockers: &mut BlockerCollector,
) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path}.{key}");
                let normalized = key.to_ascii_lowercase().replace('-', "_");
                if is_secret_key(&normalized) || contains_secret_literal(child) {
                    blockers.push(
                        SystemGenesisBlockerCode::SecretMaterialForbidden,
                        &child_path,
                    );
                }
                if is_nondeterministic_key(&normalized) {
                    blockers.push(SystemGenesisBlockerCode::NondeterministicField, &child_path);
                }
                if package_context && is_live_package_key(&normalized) {
                    blockers.push(
                        SystemGenesisBlockerCode::PackageLiveStateForbidden,
                        &child_path,
                    );
                }
                scan_forbidden_material(child, &child_path, package_context, blockers);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_forbidden_material(
                    child,
                    &format!("{path}[{index}]"),
                    package_context,
                    blockers,
                );
            }
        }
        Value::String(text) if package_context && is_live_package_ref(text) => {
            blockers.push(SystemGenesisBlockerCode::PackageLiveStateForbidden, path);
        }
        _ => {}
    }
}

fn is_secret_key(key: &str) -> bool {
    if key.ends_with("_ref") || key.ends_with("_refs") {
        return false;
    }
    matches!(
        key,
        "api_key"
            | "private_key"
            | "access_key"
            | "access_key_id"
            | "authorization_header"
            | "bearer"
            | "seed_phrase"
    ) || key.split('_').any(|part| {
        matches!(
            part,
            "password" | "secret" | "credential" | "credentials" | "token" | "mnemonic" | "cookie"
        )
    })
}

fn contains_secret_literal(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        let trimmed = text.trim();
        let jwt_segments = trimmed.split('.').collect::<Vec<_>>();
        trimmed.contains("PRIVATE KEY")
            || [
                "sk-",
                "ghp_",
                "gho_",
                "github_pat_",
                "xoxb-",
                "xoxp-",
                "AKIA",
                "ASIA",
                "Bearer ",
            ]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
            || (jwt_segments.len() == 3
                && jwt_segments[0].starts_with("eyJ")
                && jwt_segments.iter().all(|segment| {
                    segment.len() >= 8
                        && segment.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
                        })
                }))
    })
}

fn is_nondeterministic_key(key: &str) -> bool {
    matches!(
        key,
        "now"
            | "current_time"
            | "generated_at"
            | "random"
            | "random_seed"
            | "nonce"
            | "uuid"
            | "environment"
            | "hostname"
            | "process_id"
            | "pid"
    )
}

fn is_live_package_key(key: &str) -> bool {
    matches!(
        key,
        "system_id"
            | "genesis_id"
            | "node_id"
            | "run_id"
            | "session_id"
            | "gateway_id"
            | "lease_id"
            | "grant_id"
            | "credential_id"
            | "runtime_assignment_id"
            | "active_skill_set_id"
            | "status"
    )
}

fn is_live_package_ref(value: &str) -> bool {
    [
        "system://",
        "genesis://",
        "node://",
        "run://",
        "session://",
        "mcp-gateway://",
        "mcp_gateway://",
        "lease://",
        "grant://",
        "credential://",
        "runtime-assignment://",
        "active-skill-set://",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

fn scan_mutable_references(value: &Value, path: &str, blockers: &mut BlockerCollector) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                scan_mutable_references(child, &format!("{path}.{key}"), blockers);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_mutable_references(child, &format!("{path}[{index}]"), blockers);
            }
        }
        Value::String(text) => {
            if uri_contains_mutable_alias(text) {
                blockers.push(SystemGenesisBlockerCode::MutableReference, path);
            }
        }
        _ => {}
    }
}

fn uri_contains_mutable_alias(text: &str) -> bool {
    let Some(colon) = text.find(':') else {
        return false;
    };
    let scheme = &text[..colon];
    if scheme.is_empty()
        || !scheme
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return false;
    }

    let mut decoded = text.to_owned();
    for _ in 0..4 {
        match percent_decode_once(&decoded) {
            Ok(next) if next == decoded => break,
            Ok(next) => decoded = next,
            Err(()) => return true,
        }
    }
    decoded
        .to_ascii_lowercase()
        .split(is_uri_token_separator)
        .filter(|token| !token.is_empty())
        .collect::<BTreeSet<_>>()
        .iter()
        .any(|token| matches!(*token, "current" | "latest" | "head" | "floating"))
}

fn percent_decode_once(value: &str) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let high = *bytes.get(index + 1).ok_or(())?;
        let low = *bytes.get(index + 2).ok_or(())?;
        decoded.push(
            hex_nibble(high)
                .zip(hex_nibble(low))
                .map_or(Err(()), |(high, low)| Ok((high << 4) | low))?,
        );
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_| ())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_uri_token_separator(character: char) -> bool {
    character.is_ascii_whitespace()
        || matches!(
            character,
            ':' | '/'
                | '?'
                | '#'
                | '['
                | ']'
                | '@'
                | '!'
                | '$'
                | '&'
                | '\''
                | '('
                | ')'
                | '*'
                | '+'
                | ','
                | ';'
                | '='
                | '\\'
                | '|'
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(body: &str) -> Value {
        serde_json::from_str(body).expect("fixture contains JSON")
    }

    fn valid_release() -> Value {
        let mut release = fixture(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/",
            "autonomous-system-manifest-v1/positive-reusable-release.json"
        )));
        let component_hash = compute_system_component_set_hash(&release).expect("component hash");
        release["typed_components"]["component_set_hash"] = Value::String(component_hash);
        let release_root = compute_system_release_root(&release).expect("release root");
        release["release_root"] = Value::String(release_root);
        release
    }

    fn valid_proposal(release: &Value) -> Value {
        let mut candidate = fixture(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/",
            "autonomous-system-genesis-v1/positive-proposed.json"
        )));
        candidate
            .as_object_mut()
            .expect("candidate object")
            .remove("admitted_manifest_root");
        candidate
            .as_object_mut()
            .expect("candidate object")
            .remove("initial_profile_bundle_root");
        let origin = candidate["cryptographic_origin"]
            .as_object_mut()
            .expect("origin object");
        origin.remove("genesis_operation_commitment");
        origin.remove("genesis_transition_commitment_ref");
        candidate["initial_component_bindings"]["admitted_component_set_hash"] =
            release["typed_components"]["component_set_hash"].clone();

        serde_json::json!({
            "schema_version": PROPOSAL_INPUT_SCHEMA_VERSION,
            "candidate": candidate,
            "template_bindings": {
                "constitution_template_ref": release["constitution_template_ref"],
                "deployment_template_ref": release["required_profile_templates"]["deployment_template_ref"],
                "ordering_admission_finality_template_ref": release["required_profile_templates"]["ordering_admission_finality_template_ref"],
                "oracle_evidence_template_refs": release["required_profile_templates"]["oracle_evidence_template_refs"],
                "lifecycle_continuity_template_ref": release["required_profile_templates"]["lifecycle_continuity_template_ref"],
                "network_enrollment_constraint_ref": release["required_profile_templates"]["network_enrollment_constraint_ref"]
            },
            "constitution": fixture(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/architecture/_meta/schemas/fixtures/",
                "autonomous-system-constitution-v1/positive-draft.json"
            ))),
            "ordering_profile": fixture(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/architecture/_meta/schemas/fixtures/",
                "ordering-admission-finality-profile-v1/positive-single-authority.json"
            ))),
            "oracle_profiles": [fixture(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/architecture/_meta/schemas/fixtures/",
                "oracle-evidence-profile-v1/positive-fail-closed.json"
            )))],
            "lifecycle_profile": fixture(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/architecture/_meta/schemas/fixtures/",
                "lifecycle-continuity-profile-v1/positive-successor-governed.json"
            ))),
            "network_enrollment": null
        })
    }

    fn compile_valid() -> (Value, Value, SystemGenesisCompilation) {
        let release = valid_release();
        let proposal = valid_proposal(&release);
        let compilation = compile_system_genesis_proposal(&release, &proposal);
        (release, proposal, compilation)
    }

    fn valid_sequence_zero_inputs() -> (Value, Value, String, String, String) {
        let (_, _, compilation) = compile_valid();
        let proposal = compilation.proposal.expect("valid genesis proposal");
        let mut genesis =
            serde_json::to_value(&proposal.genesis).expect("genesis projection serializes");
        let bundle = serde_json::to_value(&proposal.initial_profile_bundle.bundle)
            .expect("bundle projection serializes");
        let receipt_ref = format!("receipt://asgr_{}", "7".repeat(64));
        genesis["status"] = json!("authorized");
        genesis["instantiation"]["authority_grant_refs"] = json!([format!(
            "grant://wallet.network/approval/sha256:{}",
            "8".repeat(64)
        )]);
        genesis["cryptographic_origin"]["admission_proof_ref"] = json!(receipt_ref);
        genesis["status_source_receipt_refs"] = json!([receipt_ref]);
        validate_architecture_contract(GENESIS_CONTRACT_ID, &genesis)
            .expect("authorized genesis satisfies its contract");
        let record = json!({
            "schema_version": "ioi.hypervisor.autonomous-system-genesis-admission.v1",
            "authorized_genesis": genesis,
            "initial_profile_bundle": bundle,
            "admission_receipt_ref": receipt_ref
        });
        let receipt = json!({
            "schema_version": "ioi.hypervisor.autonomous-system-genesis-receipt.v1",
            "receipt_ref": receipt_ref,
            "subject": genesis["genesis_id"]
        });
        let record_root =
            compute_system_genesis_admission_record_root(&record).expect("record root");
        let receipt_root =
            compute_system_genesis_admission_receipt_root(&receipt).expect("receipt root");
        (genesis, bundle, record_root, receipt_ref, receipt_root)
    }

    #[test]
    fn sequence_zero_materialization_is_deterministic_typed_and_pre_activation() {
        let (genesis, bundle, record_root, receipt_ref, receipt_root) =
            valid_sequence_zero_inputs();
        let first = compile_system_sequence_zero_plan(
            &genesis,
            &bundle,
            &record_root,
            &receipt_ref,
            &receipt_root,
        )
        .expect("valid M1.3 admission compiles into an M1.4 plan");
        let second = compile_system_sequence_zero_plan(
            &genesis,
            &bundle,
            &record_root,
            &receipt_ref,
            &receipt_root,
        )
        .expect("same admission recompiles");
        assert_eq!(first, second);
        assert_eq!(
            first.authority_effect["operation"],
            "materialize_sequence_zero"
        );
        assert_eq!(first.authority_effect["activation_admitted"], false);
        assert_eq!(first.authority_effect["runtime_effect_admitted"], false);
        assert_eq!(
            first.materialization_body["status"],
            "materialized_pending_activation"
        );
        assert_eq!(first.materialization_body["sequence"], 0);
        assert!(first.materialization_body["activation_receipt_ref"].is_null());
        let compiled =
            finalize_system_sequence_zero_materialization(&first, "2026-07-19T12:00:00Z")
                .expect("materialization finalizes through the registered projection");
        let serialized =
            serde_json::to_value(&compiled.materialization).expect("projection serializes");
        validate_architecture_contract(SEQUENCE_ZERO_MATERIALIZATION_CONTRACT_ID, &serialized)
            .expect("final materialization satisfies the registered contract");
        assert_eq!(
            compiled.canonical_json,
            serde_jcs::to_vec(&serialized).expect("independent canonicalization")
        );
    }

    #[test]
    fn sequence_zero_roots_are_derived_instead_of_copying_proposal_placeholders() {
        let (genesis, bundle, record_root, receipt_ref, receipt_root) =
            valid_sequence_zero_inputs();
        let proposal_state = required_string(&genesis, "/cryptographic_origin/initial_state_root")
            .expect("proposal state root");
        let proposal_receipts =
            required_string(&genesis, "/cryptographic_origin/initial_receipt_root")
                .expect("proposal receipt root");
        let plan = compile_system_sequence_zero_plan(
            &genesis,
            &bundle,
            &record_root,
            &receipt_ref,
            &receipt_root,
        )
        .expect("materialization plan");
        assert_ne!(plan.initial_state_root, proposal_state);
        assert_ne!(plan.initial_receipt_root, proposal_receipts);
        assert_eq!(
            plan.materialization_body["proposed_initial_state_root"],
            proposal_state
        );
        assert_eq!(
            plan.materialization_body["proposed_initial_receipt_root"],
            proposal_receipts
        );
        assert_eq!(
            plan.materialization_body
                .pointer("/predecessor_transition_commitment_ref"),
            Some(&Value::Null)
        );
    }

    #[test]
    fn sequence_zero_exact_component_change_moves_registry_state_and_transition_roots() {
        let (genesis, bundle, record_root, receipt_ref, receipt_root) =
            valid_sequence_zero_inputs();
        let first = compile_system_sequence_zero_plan(
            &genesis,
            &bundle,
            &record_root,
            &receipt_ref,
            &receipt_root,
        )
        .expect("first plan");
        let mut changed = genesis.clone();
        changed["initial_component_bindings"]["goal_run_profiles"][0]["content_hash"] =
            json!(format!("sha256:{}", "a".repeat(64)));
        let second = compile_system_sequence_zero_plan(
            &changed,
            &bundle,
            &record_root,
            &receipt_ref,
            &receipt_root,
        )
        .expect("changed plan");
        assert_ne!(
            first.component_registry_root,
            second.component_registry_root
        );
        assert_ne!(first.operation_commitment, second.operation_commitment);
        assert_ne!(first.initial_state_root, second.initial_state_root);
        assert_ne!(
            first.transition_commitment_ref,
            second.transition_commitment_ref
        );
    }

    #[test]
    fn sequence_zero_binds_a_content_addressed_deployment_candidate() {
        let (genesis, bundle, record_root, receipt_ref, receipt_root) =
            valid_sequence_zero_inputs();
        let first = compile_system_sequence_zero_plan(
            &genesis,
            &bundle,
            &record_root,
            &receipt_ref,
            &receipt_root,
        )
        .expect("first deployment candidate");
        assert_eq!(
            first.materialization_body["deployment_profile_root"],
            format!("sha256:{}", "d".repeat(64))
        );

        let mut changed = genesis.clone();
        changed["initial_profile_refs"]["deployment_profile_ref"] = json!(format!(
            "deployment-profile://acme/system-alpha/local/revision/sha256:{}",
            "e".repeat(64)
        ));
        let second = compile_system_sequence_zero_plan(
            &changed,
            &bundle,
            &record_root,
            &receipt_ref,
            &receipt_root,
        )
        .expect("changed deployment candidate");
        assert_eq!(
            second.materialization_body["deployment_profile_root"],
            format!("sha256:{}", "e".repeat(64))
        );
        assert_ne!(
            first.profile_materialization_root,
            second.profile_materialization_root
        );
        assert_ne!(first.operation_commitment, second.operation_commitment);
        assert_ne!(first.initial_state_root, second.initial_state_root);
        assert_ne!(
            first.transition_commitment_ref,
            second.transition_commitment_ref
        );
    }

    #[test]
    fn sequence_zero_materializes_a_legacy_m1_3_deployment_ref_without_claiming_content() {
        let (mut genesis, bundle, record_root, receipt_ref, receipt_root) =
            valid_sequence_zero_inputs();
        genesis["initial_profile_refs"]["deployment_profile_ref"] =
            json!("deployment-profile://acme/system-alpha/local");
        let first = compile_system_sequence_zero_plan(
            &genesis,
            &bundle,
            &record_root,
            &receipt_ref,
            &receipt_root,
        )
        .expect("an immutable master-era M1.3 ref remains materializable");
        let second = compile_system_sequence_zero_plan(
            &genesis,
            &bundle,
            &record_root,
            &receipt_ref,
            &receipt_root,
        )
        .expect("legacy projection is deterministic");
        assert_eq!(
            first.materialization_body["deployment_profile_root"],
            second.materialization_body["deployment_profile_root"]
        );
        assert_eq!(
            first.materialization_body["profile_refs"]["deployment_profile_ref"],
            "deployment-profile://acme/system-alpha/local"
        );
        assert_ne!(
            first.materialization_body["deployment_profile_root"],
            format!("sha256:{}", "d".repeat(64)),
            "the compatibility commitment is not represented as deployment-profile content"
        );
    }

    #[test]
    fn sequence_zero_refuses_duplicate_bindings_and_activated_genesis() {
        let (genesis, bundle, record_root, receipt_ref, receipt_root) =
            valid_sequence_zero_inputs();
        let mut duplicate = genesis.clone();
        let mut second = duplicate["initial_component_bindings"]["goal_run_profiles"][0].clone();
        second["content_hash"] = json!(format!("sha256:{}", "a".repeat(64)));
        duplicate["initial_component_bindings"]["goal_run_profiles"]
            .as_array_mut()
            .expect("goal-run profile bindings")
            .push(second);
        let error = compile_system_sequence_zero_plan(
            &duplicate,
            &bundle,
            &record_root,
            &receipt_ref,
            &receipt_root,
        )
        .expect_err("duplicate normalized identity must refuse");
        assert!(error.contains("duplicate normalized component binding"));

        let mut activated = genesis;
        activated["status"] = json!("activated");
        activated["activation_receipt_ref"] = json!(format!("receipt://{}", "9".repeat(64)));
        activated["lifecycle_transition_refs"] =
            json!(["lifecycle-transition://acme/system-alpha/activate"]);
        let error = compile_system_sequence_zero_plan(
            &activated,
            &bundle,
            &record_root,
            &receipt_ref,
            &receipt_root,
        )
        .expect_err("activated genesis must refuse M1.4");
        assert!(error.contains("authorized, non-activated genesis"));
    }

    #[test]
    fn identical_input_produces_byte_identical_proposal_and_root() {
        let release = valid_release();
        let proposal = valid_proposal(&release);
        let first = compile_system_genesis_proposal(&release, &proposal);
        let second = compile_system_genesis_proposal(&release, &proposal);
        assert!(first.blocker_report.blockers.is_empty());
        assert_eq!(
            first.proposal.as_ref().map(|value| &value.canonical_json),
            second.proposal.as_ref().map(|value| &value.canonical_json)
        );
        assert_eq!(
            first.proposal.as_ref().map(|value| &value.proposal_root),
            second.proposal.as_ref().map(|value| &value.proposal_root)
        );
        assert_eq!(
            first
                .proposal
                .as_ref()
                .map(|value| value.proposal_root.as_str()),
            Some("sha256:a519964f16ab9974e009336f784a764d9c8ad1354879036d9846effd6680a2e5")
        );
        let compiled = first.proposal.as_ref().expect("valid compiled proposal");
        assert_eq!(
            compiled.initial_profile_bundle.bundle_root,
            "sha256:7cb2c381d5d98c2d220446a18a55b9f5be1dfbc824ebb5d8295be01138f6cbea",
        );
        assert_eq!(
            genesis_operation_commitment(compiled),
            "sha256:25ef56206ad8d951ab768106c8c47121d0a9ccf5ba54e116d514c643b645f83b",
        );
        assert_eq!(
            first.authority_effect_boundary,
            SYSTEM_GENESIS_PROPOSAL_AUTHORITY_BOUNDARY
        );
    }

    #[test]
    fn exact_profile_body_changes_bundle_operation_and_proposal_roots() {
        let release = valid_release();
        let first_input = valid_proposal(&release);
        let mut second_input = first_input.clone();
        second_input["constitution"]["declared_purpose"]["statement"] = Value::String(
            "Pursue bounded research outcomes for accountable project stakeholders with review."
                .to_owned(),
        );

        let first = compile_system_genesis_proposal(&release, &first_input)
            .proposal
            .expect("first profile bundle compiles");
        let second = compile_system_genesis_proposal(&release, &second_input)
            .proposal
            .expect("changed valid profile body compiles");

        assert_ne!(
            first.initial_profile_bundle.bundle_root, second.initial_profile_bundle.bundle_root,
            "the bundle root must commit the exact supplied profile bodies",
        );
        assert_ne!(
            genesis_operation_commitment(&first),
            genesis_operation_commitment(&second),
            "the operation commitment must bind the inserted bundle root",
        );
        assert_ne!(
            first.proposal_root, second.proposal_root,
            "the proposal root must bind the inserted bundle root",
        );
        assert_eq!(
            first.initial_profile_bundle.canonical_json,
            serde_jcs::to_vec(&build_initial_profile_bundle(&first_input))
                .expect("independent bundle canonicalization"),
            "the compiled result must return the exact closed canonical bundle",
        );
    }

    #[test]
    fn release_root_removes_only_canon_named_fields_and_preserves_empty_release() {
        let release = fixture(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/",
            "autonomous-system-manifest-v1/positive-reusable-release.json"
        )));
        let mut material = release.as_object().cloned().expect("manifest object");
        material.remove("release_root");
        material.remove("registry_status");
        material
            .get_mut("receipts")
            .and_then(Value::as_object_mut)
            .expect("receipt projection")
            .remove("package_readiness_receipt_ref");
        let release_projection = material
            .get_mut("release")
            .and_then(Value::as_object_mut)
            .expect("release projection");
        release_projection.remove("publisher_signature_ref");
        release_projection.remove("registry_published_at");
        assert_eq!(
            material.get("release"),
            Some(&Value::Object(Map::new())),
            "canon retains the resulting empty release object",
        );

        let material = Value::Object(material);
        let canonical = serde_jcs::to_vec(&serde_json::json!({
            "domain": SYSTEM_RELEASE_ROOT_HASH_PROFILE,
            "value": material,
        }))
        .expect("independent release-root canonicalization");
        let digest = Sha256::digest(&canonical).expect("independent release-root digest");
        let independently_computed = format!(
            "sha256:{}",
            digest
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        assert_eq!(
            compute_system_release_root(&release).expect("compiler release root"),
            independently_computed,
        );
        assert_eq!(
            independently_computed,
            "sha256:78ca76fbeb4fc51bdc114f68afd9078cedf52c8a3760ed1e2bb3be173091858b",
            "release-root golden drifted",
        );
    }

    #[test]
    fn upgrade_only_release_is_refused_after_release_hashes_are_recomputed() {
        let mut release = valid_release();
        release["system_binding"]["allowed_use"] = Value::String("upgrade_existing".to_owned());
        recompute_release_hashes(&mut release);
        let proposal = valid_proposal(&release);
        let result = compile_system_genesis_proposal(&release, &proposal);
        assert!(result.proposal.is_none());
        assert!(has_blocker(
            &result,
            SystemGenesisBlockerCode::NewSystemInstantiationForbidden,
            "$.release.system_binding.allowed_use",
        ));
        assert!(!result.blocker_report.blockers.iter().any(|blocker| {
            matches!(
                blocker.code,
                SystemGenesisBlockerCode::ComponentSetHashMismatch
                    | SystemGenesisBlockerCode::ReleaseRootMismatch
            )
        }));
    }

    #[test]
    fn every_proposal_top_level_member_has_a_fail_closed_type() {
        let release = valid_release();
        for (field, replacement) in [
            ("schema_version", Value::Bool(false)),
            ("candidate", Value::Array(Vec::new())),
            ("template_bindings", Value::String("invalid".to_owned())),
            ("constitution", Value::Array(Vec::new())),
            ("ordering_profile", Value::Bool(false)),
            ("oracle_profiles", serde_json::json!({"not": "an array"})),
            ("lifecycle_profile", Value::Null),
            ("network_enrollment", Value::String("invalid".to_owned())),
        ] {
            let mut proposal = valid_proposal(&release);
            proposal[field] = replacement;
            let result = compile_system_genesis_proposal(&release, &proposal);
            assert!(
                has_blocker(
                    &result,
                    SystemGenesisBlockerCode::ProposedInstantiationInvalid,
                    &format!("$.proposed.{field}"),
                ),
                "{field}: wrong top-level type escaped: {:?}",
                result.blocker_report.blockers,
            );
            assert!(result.proposal.is_none(), "{field}: wrong type compiled");
        }
    }

    #[test]
    fn sequence_zero_profiles_reject_predecessors_and_activation_residue() {
        let release = valid_release();

        let mut predecessor = valid_proposal(&release);
        predecessor["constitution"]["predecessor_constitution_ref"] =
            Value::String("constitution://acme/system-alpha/v0".to_owned());
        let result = compile_system_genesis_proposal(&release, &predecessor);
        assert!(has_blocker(
            &result,
            SystemGenesisBlockerCode::ConstitutionPredecessorForbidden,
            "$.proposed.constitution.predecessor_constitution_ref",
        ));

        let mut activation = valid_proposal(&release);
        activation["constitution"]["activation_receipt_ref"] =
            Value::String("receipt://acme/system-alpha/constitution-active".to_owned());
        let result = compile_system_genesis_proposal(&release, &activation);
        assert!(has_blocker(
            &result,
            SystemGenesisBlockerCode::ConstitutionActivationReceiptForbidden,
            "$.proposed.constitution.activation_receipt_ref",
        ));

        let mut enrollment = proposal_with_network_enrollment(&release);
        enrollment["network_enrollment"]["predecessor_enrollment_ref"] =
            Value::String("network-enrollment://acme/system-alpha/ioi/v0".to_owned());
        let result = compile_system_genesis_proposal(&release, &enrollment);
        assert!(has_blocker(
            &result,
            SystemGenesisBlockerCode::NetworkEnrollmentPredecessorForbidden,
            "$.proposed.network_enrollment.predecessor_enrollment_ref",
        ));
    }

    #[test]
    fn every_typed_component_lane_refuses_a_cross_category_revision() {
        const MANIFEST_LANES: &[(&str, &str)] = &[
            (
                "goal_run_profiles",
                "workflow-template://acme/cross-category/revision/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "workflow_templates",
                "goal-run-profile://acme/cross-category/revision/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "automation_specs",
                "workflow-template://acme/cross-category/revision/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "harness_profiles",
                "workflow-template://acme/cross-category/revision/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "agent_harness_adapters",
                "workflow-template://acme/cross-category/revision/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "data_recipes",
                "workflow-template://acme/cross-category/revision/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "runtime_tool_contracts",
                "workflow-template://acme/cross-category/revision/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "skill_manifests",
                "workflow-template://acme/cross-category/revision/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "mcp_gateway_requirements",
                "workflow-template://acme/cross-category/revision/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        ];
        for (field, wrong_ref) in MANIFEST_LANES {
            let mut release = valid_release();
            release["typed_components"][*field] = serde_json::json!([{
                "revision_ref": wrong_ref,
                "content_hash": format!("sha256:{}", "b".repeat(64)),
            }]);
            recompute_release_hashes(&mut release);
            let proposal = valid_proposal(&release);
            let result = compile_system_genesis_proposal(&release, &proposal);
            assert!(
                result.blocker_report.blockers.iter().any(|blocker| {
                    blocker.code == SystemGenesisBlockerCode::ReleaseContractInvalid
                        && blocker
                            .path
                            .starts_with(&format!("$.release.typed_components.{field}"))
                }),
                "manifest {field}: cross-category ref escaped: {:?}",
                result.blocker_report.blockers,
            );
            assert!(
                result.proposal.is_none(),
                "manifest {field}: cross-category ref compiled",
            );
        }

        let release = valid_release();
        for (field, wrong_ref) in MANIFEST_LANES
            .iter()
            .filter(|(field, _)| !matches!(*field, "skill_manifests" | "mcp_gateway_requirements"))
        {
            let mut proposal = valid_proposal(&release);
            proposal["candidate"]["initial_component_bindings"][*field] = serde_json::json!([{
                "revision_ref": wrong_ref,
                "content_hash": format!("sha256:{}", "b".repeat(64)),
            }]);
            let result = compile_system_genesis_proposal(&release, &proposal);
            assert!(
                result.blocker_report.blockers.iter().any(|blocker| {
                    blocker.code == SystemGenesisBlockerCode::ProposedInstantiationInvalid
                        && blocker.path.starts_with(&format!(
                            "$.proposed.candidate.initial_component_bindings.{field}"
                        ))
                }),
                "{field}: cross-category ref escaped: {:?}",
                result.blocker_report.blockers,
            );
            assert!(
                result.proposal.is_none(),
                "{field}: cross-category ref compiled"
            );
        }
    }

    #[test]
    fn mutable_uri_aliases_are_tokenized_without_rejecting_ordinary_names() {
        for malicious in [
            "schema://acme/api?ref=latest",
            "schema://acme/api#head",
            "schema://acme/api?ref%3Dcurrent",
            "schema://acme/api%253Fref%253Dfloating",
            "schema://acme/api\\latest\\revision",
            "schema://acme/api;ref=LATEST",
        ] {
            assert!(
                uri_contains_mutable_alias(malicious),
                "mutable alias escaped: {malicious}",
            );
        }
        for immutable in [
            "schema://acme/latest-api",
            "schema://acme/headless-browser",
            "schema://acme/api?mode=strict#v1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(
                !uri_contains_mutable_alias(immutable),
                "ordinary canonical ref was over-rejected: {immutable}",
            );
        }

        let release = valid_release();
        let mut proposal = valid_proposal(&release);
        proposal["candidate"]["initial_profile_refs"]["deployment_profile_ref"] =
            Value::String("deployment-profile://acme/system-alpha/latest-api".to_owned());
        let result = compile_system_genesis_proposal(&release, &proposal);
        assert!(
            result.blocker_report.blockers.is_empty(),
            "ordinary canonical ref did not compile: {:?}",
            result.blocker_report.blockers,
        );
    }

    #[test]
    fn one_release_two_explicit_identities_produce_distinct_stable_roots() {
        let release = valid_release();
        let package_before = serde_jcs::to_vec(&release).expect("package canonical bytes");
        let first_input = valid_proposal(&release);
        let mut second_input = first_input.clone();
        rebind_candidate_identity(
            &mut second_input,
            "system://acme/system-beta",
            "genesis://acme/system-beta/zero",
            "constitution://acme/system-beta/v1",
            "ordering-profile://acme/system-beta/poa1",
            "oracle-evidence-profile://acme/system-beta/public-records",
            "lifecycle-profile://acme/system-beta/default",
        );
        let first = compile_system_genesis_proposal(&release, &first_input);
        let second = compile_system_genesis_proposal(&release, &second_input);
        let second_again = compile_system_genesis_proposal(&release, &second_input);
        assert!(first.blocker_report.blockers.is_empty());
        assert!(second.blocker_report.blockers.is_empty());
        assert_ne!(
            first.proposal.as_ref().map(|value| &value.proposal_root),
            second.proposal.as_ref().map(|value| &value.proposal_root)
        );
        assert_eq!(
            second.proposal.as_ref().map(|value| &value.proposal_root),
            second_again
                .proposal
                .as_ref()
                .map(|value| &value.proposal_root)
        );
        assert_eq!(
            package_before,
            serde_jcs::to_vec(&release).expect("package remains canonical")
        );
    }

    #[test]
    fn blocker_report_is_sorted_deduplicated_and_bounded() {
        let release = valid_release();
        let mut proposal = valid_proposal(&release);
        let object = proposal.as_object_mut().expect("proposal is an object");
        for index in 0..80 {
            object.insert(format!("unknown_{index:02}"), Value::Bool(true));
        }
        let result = compile_system_genesis_proposal(&release, &proposal);
        assert!(result.proposal.is_none());
        assert!(result.blocker_report.truncated);
        assert_eq!(result.blocker_report.blockers.len(), MAX_BLOCKERS);
        assert!(result
            .blocker_report
            .blockers
            .iter()
            .any(|blocker| blocker.code == SystemGenesisBlockerCode::BlockerLimitExceeded));
        let paths = result
            .blocker_report
            .blockers
            .iter()
            .map(|blocker| (blocker.path.as_str(), blocker.code.label()))
            .collect::<Vec<_>>();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted);
    }

    #[test]
    fn adversarial_corpus_rejects_every_named_fail_closed_case() {
        let corpus = fixture(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/",
            "system-genesis-compiler-v1/adversarial-cases.json"
        )));
        let cases = corpus["cases"].as_array().expect("adversarial cases");
        assert_eq!(cases.len(), 93, "adversarial census drift");

        for case in cases {
            let id = case["id"].as_str().expect("case id");
            let mut release = valid_release();
            let mut proposal = valid_proposal(&release);
            let target = match case["target"].as_str() {
                Some("release") => &mut release,
                Some("proposal") => &mut proposal,
                _ => panic!("{id}: unknown mutation target"),
            };
            apply_corpus_mutation(target, case);
            if case
                .get("recompute_release_hashes")
                .and_then(Value::as_bool)
                == Some(true)
            {
                recompute_release_hashes(&mut release);
            }

            let result = compile_system_genesis_proposal(&release, &proposal);
            assert!(result.proposal.is_none(), "{id}: mutation compiled");
            let expected_code = case["expected_code"].as_str().expect("expected code");
            let expected_path = case["expected_path"].as_str().expect("expected path");
            assert!(
                result.blocker_report.blockers.iter().any(|blocker| {
                    blocker.code.label() == expected_code && blocker.path == expected_path
                }),
                "{id}: expected {expected_code} at {expected_path}, got {:?}",
                result.blocker_report.blockers
            );
        }
    }

    #[test]
    fn proposal_is_a_typed_generated_projection() {
        let (_, _, compilation) = compile_valid();
        let proposal = compilation.proposal.expect("valid proposal");
        let serialized = serde_json::to_value(&proposal.genesis).expect("projection serializes");
        validate_architecture_contract(GENESIS_CONTRACT_ID, &serialized)
            .expect("compiled projection satisfies generated contract");
        assert_eq!(
            proposal.hash_profile,
            SYSTEM_GENESIS_PROPOSAL_ROOT_HASH_PROFILE
        );
        let bundle = serde_json::to_value(&proposal.initial_profile_bundle.bundle)
            .expect("bundle serializes");
        validate_architecture_contract(INITIAL_PROFILE_BUNDLE_CONTRACT_ID, &bundle)
            .expect("compiled bundle satisfies generated contract");
        assert_eq!(
            proposal.initial_profile_bundle.hash_profile,
            SYSTEM_INITIAL_PROFILE_BUNDLE_HASH_PROFILE,
        );
    }

    fn genesis_operation_commitment(proposal: &CompiledSystemGenesisProposal) -> String {
        serde_json::to_value(&proposal.genesis)
            .expect("genesis serializes")
            .pointer("/cryptographic_origin/genesis_operation_commitment")
            .and_then(Value::as_str)
            .expect("compiled genesis has operation commitment")
            .to_owned()
    }

    fn has_blocker(
        compilation: &SystemGenesisCompilation,
        code: SystemGenesisBlockerCode,
        path: &str,
    ) -> bool {
        compilation
            .blocker_report
            .blockers
            .iter()
            .any(|blocker| blocker.code == code && blocker.path == path)
    }

    fn recompute_release_hashes(release: &mut Value) {
        let component_hash =
            compute_system_component_set_hash(release).expect("recomputed component hash");
        release["typed_components"]["component_set_hash"] = Value::String(component_hash);
        let release_root = compute_system_release_root(release).expect("recomputed release root");
        release["release_root"] = Value::String(release_root);
    }

    fn proposal_with_network_enrollment(release: &Value) -> Value {
        let mut proposal = valid_proposal(release);
        let bundle = fixture(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/",
            "autonomous-system-initial-profile-bundle-v1/positive-closed.json"
        )));
        let enrollment = bundle["network_enrollment"].clone();
        proposal["candidate"]["initial_profile_refs"]["network_enrollment_ref"] =
            enrollment["network_enrollment_id"].clone();
        proposal["network_enrollment"] = enrollment;
        let compilation = compile_system_genesis_proposal(release, &proposal);
        assert!(
            compilation.blocker_report.blockers.is_empty(),
            "network-enrollment baseline must compile: {:?}",
            compilation.blocker_report.blockers,
        );
        proposal
    }

    fn apply_corpus_mutation(target: &mut Value, case: &Value) {
        let id = case["id"].as_str().expect("case id");
        match case["operation"].as_str() {
            Some("set") => {
                let pointer = case["pointer"].as_str().expect("mutation pointer");
                set_pointer(
                    target,
                    pointer,
                    case.get("value").cloned().expect("set value"),
                );
            }
            Some("remove") => {
                let pointer = case["pointer"].as_str().expect("mutation pointer");
                let (parent, key) = pointer.rsplit_once('/').expect("remove parent");
                let object = target
                    .pointer_mut(parent)
                    .and_then(Value::as_object_mut)
                    .unwrap_or_else(|| panic!("{id}: remove parent {parent}"));
                assert!(
                    object.remove(key).is_some(),
                    "{id}: remove target {pointer}"
                );
            }
            Some("append") => {
                let pointer = case["pointer"].as_str().expect("mutation pointer");
                target
                    .pointer_mut(pointer)
                    .and_then(Value::as_array_mut)
                    .unwrap_or_else(|| panic!("{id}: append target {pointer}"))
                    .push(case.get("value").cloned().expect("append value"));
            }
            Some("merge") => {
                merge_value(target, case.get("value").cloned().expect("merge value"));
            }
            _ => panic!("{id}: unknown mutation operation"),
        }
    }

    fn merge_value(target: &mut Value, patch: Value) {
        match (target, patch) {
            (Value::Object(target), Value::Object(patch)) => {
                for (key, value) in patch {
                    match target.get_mut(&key) {
                        Some(target) => merge_value(target, value),
                        None => {
                            target.insert(key, value);
                        }
                    }
                }
            }
            (target, patch) => *target = patch,
        }
    }

    fn set_pointer(target: &mut Value, pointer: &str, replacement: Value) {
        let mut segments = pointer
            .strip_prefix('/')
            .expect("absolute JSON pointer")
            .split('/')
            .peekable();
        let mut current = target;
        while let Some(segment) = segments.next() {
            if segments.peek().is_none() {
                match current {
                    Value::Object(object) => {
                        object.insert(segment.to_owned(), replacement);
                    }
                    Value::Array(items) => {
                        items[segment.parse::<usize>().expect("array index")] = replacement;
                    }
                    _ => panic!("set parent is not a container at {pointer}"),
                }
                return;
            }
            current = match current {
                Value::Object(object) => object
                    .entry(segment.to_owned())
                    .or_insert_with(|| Value::Object(Map::new())),
                Value::Array(items) => &mut items[segment.parse::<usize>().expect("array index")],
                _ => panic!("set path is not a container at {pointer}"),
            };
        }
        panic!("empty set pointer");
    }

    fn rebind_candidate_identity(
        proposal: &mut Value,
        system_id: &str,
        genesis_id: &str,
        constitution_ref: &str,
        ordering_profile_ref: &str,
        oracle_profile_ref: &str,
        lifecycle_profile_ref: &str,
    ) {
        proposal["candidate"]["system_id"] = Value::String(system_id.to_owned());
        proposal["candidate"]["genesis_id"] = Value::String(genesis_id.to_owned());
        proposal["candidate"]["constitution_ref"] = Value::String(constitution_ref.to_owned());
        proposal["candidate"]["initial_profile_refs"]["deployment_profile_ref"] =
            Value::String(format!(
                "deployment-profile://{}/local",
                system_id
                    .strip_prefix("system://")
                    .expect("test System ref has canonical scheme")
            ));
        proposal["candidate"]["initial_profile_refs"]["ordering_admission_finality_profile_ref"] =
            Value::String(ordering_profile_ref.to_owned());
        proposal["candidate"]["initial_profile_refs"]["oracle_evidence_profile_refs"] =
            Value::Array(vec![Value::String(oracle_profile_ref.to_owned())]);
        proposal["candidate"]["initial_profile_refs"]["lifecycle_continuity_profile_ref"] =
            Value::String(lifecycle_profile_ref.to_owned());
        proposal["constitution"]["system_id"] = Value::String(system_id.to_owned());
        proposal["constitution"]["constitution_id"] = Value::String(constitution_ref.to_owned());
        proposal["ordering_profile"]["system_id"] = Value::String(system_id.to_owned());
        proposal["ordering_profile"]["constitution_ref"] =
            Value::String(constitution_ref.to_owned());
        proposal["ordering_profile"]["ordering_profile_id"] =
            Value::String(ordering_profile_ref.to_owned());
        proposal["oracle_profiles"][0]["system_id"] = Value::String(system_id.to_owned());
        proposal["oracle_profiles"][0]["oracle_evidence_profile_id"] =
            Value::String(oracle_profile_ref.to_owned());
        proposal["lifecycle_profile"]["system_id"] = Value::String(system_id.to_owned());
        proposal["lifecycle_profile"]["constitution_ref"] =
            Value::String(constitution_ref.to_owned());
        proposal["lifecycle_profile"]["lifecycle_profile_id"] =
            Value::String(lifecycle_profile_ref.to_owned());
    }
}
