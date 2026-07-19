//! Pure proposal compiler for an immutable package release and explicit System coordinates.

use crate::app::generated::architecture_contracts::{
    validate_architecture_contract, AutonomousSystemGenesisV1,
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
/// RFC 8785 JCS + SHA-256 profile for the pre-transition genesis operation.
pub const SYSTEM_GENESIS_OPERATION_HASH_PROFILE: &str =
    "ioi.autonomous-system-genesis-operation-jcs-sha256.v1";
/// RFC 8785 JCS + SHA-256 profile for the complete proposed genesis artifact.
pub const SYSTEM_GENESIS_PROPOSAL_ROOT_HASH_PROFILE: &str =
    "ioi.autonomous-system-genesis-proposal-root-jcs-sha256.v1";
/// Explicit statement that compilation is neither authority nor admission.
pub const SYSTEM_GENESIS_PROPOSAL_AUTHORITY_BOUNDARY: &str =
    "unverified_proposal_only_no_authority_admission_activation_or_effect";

const MANIFEST_CONTRACT_ID: &str = "schema://ioi/foundations/autonomous-system-manifest/v1";
const GENESIS_CONTRACT_ID: &str = "schema://ioi/foundations/autonomous-system-genesis/v1";
const CONSTITUTION_CONTRACT_ID: &str = "schema://ioi/foundations/autonomous-system-constitution/v1";
const ORDERING_CONTRACT_ID: &str =
    "schema://ioi/foundations/ordering-admission-finality-profile/v1";
const ORACLE_CONTRACT_ID: &str = "schema://ioi/foundations/oracle-evidence-profile/v1";
const LIFECYCLE_CONTRACT_ID: &str = "schema://ioi/foundations/lifecycle-continuity-profile/v1";
const NETWORK_ENROLLMENT_CONTRACT_ID: &str = "schema://ioi/foundations/ioi-network-enrollment/v1";
const PROPOSAL_INPUT_SCHEMA_VERSION: &str = "ioi.autonomous-system-genesis-proposal-input.v1";
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
    /// The proposal contains a binding that requires later admission.
    LiveBindingAdmissionUnavailable,
    /// Manifest and package coordinates disagree.
    ManifestPackageMismatch,
    /// An immutable coordinate uses a mutable alias.
    MutableReference,
    /// Network enrollment coordinates differ from the proposal.
    NetworkEnrollmentCoordinateMismatch,
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
            Self::LiveBindingAdmissionUnavailable => {
                "live installation, skill-entry, or gateway binding requires later admission"
            }
            Self::ManifestPackageMismatch => {
                "package and release coordinates do not identify the same package"
            }
            Self::MutableReference => {
                "mutable, floating, current, latest, or head reference is forbidden"
            }
            Self::NetworkEnrollmentCoordinateMismatch => {
                "network enrollment coordinates differ from the proposed genesis"
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
            Self::GenesisActivationClaimForbidden => "genesis_activation_claim_forbidden",
            Self::GenesisCoordinateMismatch => "genesis_coordinate_mismatch",
            Self::GenesisHistoryForbidden => "genesis_history_forbidden",
            Self::GenesisPredecessorForbidden => "genesis_predecessor_forbidden",
            Self::GenesisSequenceNotZero => "genesis_sequence_not_zero",
            Self::GenesisStatusNotProposed => "genesis_status_not_proposed",
            Self::HashingFailed => "hashing_failed",
            Self::LiveBindingAdmissionUnavailable => "live_binding_admission_unavailable",
            Self::ManifestPackageMismatch => "manifest_package_mismatch",
            Self::MutableReference => "mutable_reference",
            Self::NetworkEnrollmentCoordinateMismatch => "network_enrollment_coordinate_mismatch",
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

/// Canonical proposed genesis artifact and its root.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledSystemGenesisProposal {
    /// Typed proposed genesis artifact.
    pub genesis: AutonomousSystemGenesisV1,
    /// RFC 8785 canonical bytes of `genesis`.
    pub canonical_json: Vec<u8>,
    /// Domain-separated SHA-256 commitment to `canonical_json`.
    pub proposal_root: String,
    /// Hash profile used for `proposal_root`.
    pub hash_profile: &'static str,
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
    if material
        .get("release")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty)
    {
        material.remove("release");
    }
    domain_hash(SYSTEM_RELEASE_ROOT_HASH_PROFILE, &Value::Object(material))
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
    validate_manifest_hashes_and_tuples(release, &mut blockers);
    validate_template_bindings(release, proposed_instantiation, &mut blockers);
    validate_proposal_coordinates(release, proposed_instantiation, &mut blockers);
    validate_component_bindings(release, proposed_instantiation, &mut blockers);

    let mut genesis_value = proposed_instantiation
        .pointer("/candidate")
        .cloned()
        .unwrap_or(Value::Null);
    let release_root = release.get("release_root").cloned();
    if let (Some(genesis), Some(release_root)) = (genesis_value.as_object_mut(), release_root) {
        genesis.insert("admitted_manifest_root".to_owned(), release_root);
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
    if let Some(candidate) = value.get("candidate") {
        check_closed_object(candidate, "$.proposed.candidate", CANDIDATE, blockers);
        check_required_properties(candidate, "$.proposed.candidate", CANDIDATE, blockers);
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
        }
    }
    if let Some(bindings) = value.get("template_bindings") {
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
    }
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
        Value::String(text) if text.contains("://") => {
            let lower = text.to_ascii_lowercase();
            let segments = lower
                .split(['/', ':'])
                .filter(|segment| !segment.is_empty())
                .collect::<BTreeSet<_>>();
            if ["current", "latest", "head", "floating"]
                .iter()
                .any(|alias| segments.contains(alias))
            {
                blockers.push(SystemGenesisBlockerCode::MutableReference, path);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            Some("sha256:28a6c2094b6b2a0b24c53fb488ca8fadcbec795bc55123d459989e4a2fc71bb7")
        );
        assert_eq!(
            first.authority_effect_boundary,
            SYSTEM_GENESIS_PROPOSAL_AUTHORITY_BOUNDARY
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
        assert_eq!(cases.len(), 77, "adversarial census drift");

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
