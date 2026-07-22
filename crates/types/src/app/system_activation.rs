//! Pure M1.5a compiler for governed System initialization and activation.
//!
//! The commitment graph is deliberately acyclic:
//! active-profile admission -> semantic lifecycle state -> transition -> portable receipt -> chain.
//! Candidate profile bodies remain immutable; the active-profile set is the admission projection.

use crate::app::generated::architecture_contracts::validate_architecture_contract;
use crate::app::system_genesis::{
    compute_system_genesis_admission_receipt_root, compute_system_genesis_admission_record_root,
    SYSTEM_COMPONENT_REGISTRY_HASH_PROFILE,
};
use crate::app::wallet_network::validate_principal_authority_ref;
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Registered deployment-profile revision contract.
pub const SYSTEM_DEPLOYMENT_PROFILE_REVISION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-deployment-profile-revision/v1";
/// Registered lifecycle-state contract.
pub const SYSTEM_LIFECYCLE_STATE_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-activation-state/v1";
/// Registered active-profile admission contract.
pub const SYSTEM_ACTIVE_PROFILE_SET_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-active-profile-set/v1";
/// Registered activation-owned home-domain binding contract.
pub const SYSTEM_HOME_DOMAIN_BINDING_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-home-domain-binding/v1";
/// Registered immutable System operation-log revision contract.
pub const SYSTEM_OPERATION_LOG_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-operation-log/v1";
/// Registered live-chain contract.
pub const SYSTEM_CHAIN_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-chain/v1";
/// Registered portable lifecycle-transition receipt contract.
pub const SYSTEM_LIFECYCLE_TRANSITION_RECEIPT_CONTRACT: &str =
    "schema://ioi/foundations/lifecycle-transition-receipt/v1";
/// Registered sequence-two activation receipt contract.
pub const SYSTEM_ACTIVATION_RECEIPT_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-activation-receipt/v1";
/// Registered immutable lifecycle proposal contract.
pub const SYSTEM_LIFECYCLE_PROPOSAL_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-activation-proposal/v1";
/// Registered immutable lifecycle authority-decision contract.
pub const SYSTEM_LIFECYCLE_AUTHORITY_DECISION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-activation-authority-decision/v1";
/// Existing generic lifecycle-transition contract.
pub const LIFECYCLE_TRANSITION_CONTRACT: &str = "schema://ioi/foundations/lifecycle-transition/v1";

/// Distinct wallet.network operation scope for sequence-one initialization.
pub const SYSTEM_INITIALIZE_SCOPE: &str = "scope:autonomous_system.lifecycle.initialize";
/// Distinct wallet.network operation scope for sequence-two activation.
pub const SYSTEM_ACTIVATE_SCOPE: &str = "scope:autonomous_system.lifecycle.activate";
/// Contract/compiler boundary: this module's public APIs derive unverified plans and effects only.
/// Wallet signer/grant/consumption verification and admitted artifact construction belong to the
/// Hypervisor daemon transaction and are not implemented by this cut.
pub const SYSTEM_LIFECYCLE_COMPILER_AUTHORITY_BOUNDARY: &str =
    "unverified_plan_only; no authority, admission, receipt, or live-chain persistence";

const INITIAL_PROFILE_BUNDLE_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-initial-profile-bundle/v1";
const GENESIS_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-genesis/v1";
const MATERIALIZATION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-sequence-zero-materialization/v1";
const CURRENT_MATERIALIZATION_RECEIPT_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2";
const CONSTITUTION_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-constitution/v1";
const ORDERING_CONTRACT: &str = "schema://ioi/foundations/ordering-admission-finality-profile/v1";
const ORACLE_CONTRACT: &str = "schema://ioi/foundations/oracle-evidence-profile/v1";
const LIFECYCLE_PROFILE_CONTRACT: &str = "schema://ioi/foundations/lifecycle-continuity-profile/v1";
const NETWORK_ENROLLMENT_CONTRACT: &str = "schema://ioi/foundations/ioi-network-enrollment/v1";

const PROFILE_BUNDLE_HASH_PROFILE: &str =
    "ioi.autonomous-system-initial-profile-bundle-jcs-sha256.v1";
const PROFILE_CANDIDATE_HASH_PROFILE: &str =
    "ioi.autonomous-system-profile-candidate-jcs-sha256.v1";
const DEPLOYMENT_PROFILE_REVISION_HASH_PROFILE: &str =
    "ioi.autonomous-system-deployment-profile-revision-jcs-sha256.v1";
const LIFECYCLE_STATE_HASH_PROFILE: &str = "ioi.autonomous-system-activation-state-jcs-sha256.v1";
const ACTIVE_PROFILE_SET_HASH_PROFILE: &str =
    "ioi.autonomous-system-active-profile-set-jcs-sha256.v1";
const HOME_DOMAIN_IDENTITY_HASH_PROFILE: &str =
    "ioi.autonomous-system-home-domain-identity-jcs-sha256.v1";
const HOME_DOMAIN_BINDING_HASH_PROFILE: &str =
    "ioi.autonomous-system-home-domain-binding-jcs-sha256.v1";
const LIFECYCLE_OPERATION_COMMITMENT_HASH_PROFILE: &str =
    "ioi.autonomous-system-lifecycle-operation-commitment-jcs-sha256.v1";
const LIFECYCLE_TRANSITION_HASH_PROFILE: &str =
    "ioi.autonomous-system-lifecycle-transition-jcs-sha256.v1";
const LIFECYCLE_RECEIPT_ROOT_HASH_PROFILE: &str =
    "ioi.lifecycle-transition-receipt-artifact-jcs-sha256.v1";
const ACTIVATION_RECEIPT_ROOT_HASH_PROFILE: &str =
    "ioi.autonomous-system-activation-receipt-artifact-jcs-sha256.v1";
const LIFECYCLE_PROPOSAL_HASH_PROFILE: &str =
    "ioi.autonomous-system-activation-proposal-jcs-sha256.v1";
const LIFECYCLE_AUTHORITY_DECISION_HASH_PROFILE: &str =
    "ioi.autonomous-system-activation-authority-decision-jcs-sha256.v1";
#[cfg(test)]
const SYSTEM_CHAIN_HASH_PROFILE: &str = "ioi.autonomous-system-chain-jcs-sha256.v1";
#[cfg(test)]
const SYSTEM_OPERATION_LOG_HASH_PROFILE: &str = "ioi.autonomous-system-operation-log-jcs-sha256.v1";
const SYSTEM_MODULE_REGISTRY_ROOT_HASH_PROFILE: &str =
    "ioi.autonomous-system-module-registry-root-jcs-sha256.v1";
#[cfg(test)]
const SYSTEM_MEMBERSHIP_ROOT_HASH_PROFILE: &str =
    "ioi.autonomous-system-node-membership-root-jcs-sha256.v1";
#[cfg(test)]
const SYSTEM_PROPOSAL_QUEUE_ROOT_HASH_PROFILE: &str =
    "ioi.autonomous-system-proposal-queue-root-jcs-sha256.v1";
const SYSTEM_LIFECYCLE_AUTHORITY_REQUEST_DOMAIN: &str =
    "hypervisor.system-lifecycle.decision.request.v1";
const DETERMINISTIC_REF_HASH_PROFILE: &str =
    "ioi.autonomous-system-lifecycle-evidence-ref-jcs-sha256.v1";

/// Raw, explicitly unverified compiler input carrying the immutable M1.3/M1.4 artifacts.
/// Contract compilation rechecks portable roots and coordinates, but this type alone carries no
/// loader provenance, wallet authority, admission, or persistence claim. Production callers must
/// obtain it through the daemon's locked verified-source loader.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnverifiedSystemSequenceZeroActivationSource {
    /// Exact M1.3 governing authority under which the first home domain is admitted.
    pub source_governing_authority_ref: String,
    /// Immutable M1.3 admission aggregate.
    pub genesis_admission_record: Value,
    /// Immutable M1.3 admission receipt.
    pub genesis_admission_receipt: Value,
    /// Exact converged M1.4 materialization.
    pub materialization: Value,
    /// Exact converged M1.4 portable receipt.
    pub materialization_receipt: Value,
    /// Exact normalized component registry.
    pub component_registry: Value,
    /// Exact wallet.network consumption receipt used by M1.4.
    pub materialization_wallet_consumption: Value,
}

/// Lifecycle operation admitted by this cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemLifecycleOperation {
    /// Commit sequence one (`draft -> initialized`).
    Initialize,
    /// Commit sequence two (`initialized -> active`).
    Activate,
}

impl SystemLifecycleOperation {
    /// Canonical operation name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Activate => "activate",
        }
    }

    /// Canonical committed sequence.
    pub fn sequence(self) -> u64 {
        match self {
            Self::Initialize => 1,
            Self::Activate => 2,
        }
    }

    /// Exact wallet.network operation scope.
    pub fn required_scope(self) -> &'static str {
        match self {
            Self::Initialize => SYSTEM_INITIALIZE_SCOPE,
            Self::Activate => SYSTEM_ACTIVATE_SCOPE,
        }
    }
}

/// Server-derived plan produced before wallet authorization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledSystemLifecyclePlan {
    /// Operation and sequence.
    pub operation: SystemLifecycleOperation,
    /// Exact validated predecessor source.
    pub source: UnverifiedSystemSequenceZeroActivationSource,
    /// Exact immutable deployment-profile revision.
    pub deployment_profile_revision: Value,
    /// Explicitly unverified initialized artifact tuple for activation planning only.
    pub previous_step: Option<UnverifiedCommittedSystemLifecycleStep>,
    /// Semantic resulting lifecycle-state projection with downstream evidence slots empty.
    pub semantic_state: Value,
    /// Exact resulting lifecycle-state root.
    pub resulting_state_root: String,
    /// Active-profile set semantic projection for activation only.
    pub semantic_active_profile_set: Option<Value>,
    /// Exact active-profile set root for activation only.
    pub active_profile_set_root: Option<String>,
    /// Activation-owned home-domain binding semantic projection for sequence two only.
    pub semantic_home_domain_binding: Option<Value>,
    /// Exact home-domain binding root for sequence two only.
    pub home_domain_binding_root: Option<String>,
    /// Exact daemon-derived effect passed to wallet.network authorization.
    pub authority_effect: Value,
}

/// Retained authority and single-use wallet-consumption coordinates supplied after authorization.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
struct SystemLifecycleAuthorityEvidence {
    /// Exact daemon-derived effect retained by the governed decision.
    authorized_effect: Value,
    /// Canonical retained grant identity.
    authority_grant_ref: String,
    /// Daemon-derived request hash.
    input_hash: String,
    /// Daemon-derived policy hash.
    policy_hash: String,
    /// Daemon-derived effect hash.
    effect_hash: String,
    /// Separately durable retained authority tuple.
    authority_evidence_ref: String,
    /// Root of the retained authority tuple.
    authority_evidence_root: String,
    /// wallet.network single-use consumption ref.
    wallet_grant_consumption_ref: String,
    /// Root of the exact wallet.network single-use consumption artifact.
    wallet_grant_consumption_root: String,
    /// Separately durable local/Agentgres consumption evidence ref.
    wallet_grant_consumption_evidence_ref: String,
}

/// Explicitly unverified sequence-one artifact tuple used only as deterministic sequence-two input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnverifiedCommittedSystemLifecycleStep {
    /// Immutable server-derived lifecycle proposal.
    pub proposal: Value,
    /// Immutable wallet-authorized lifecycle decision.
    pub decision: Value,
    /// Registered lifecycle-state projection.
    pub state: Value,
    /// Generic committed LifecycleTransition.
    pub transition: Value,
    /// Portable transition receipt.
    pub receipt: Value,
    /// Resulting semantic state root.
    pub state_root: String,
    /// Proposal artifact root.
    pub proposal_root: String,
    /// Decision artifact root.
    pub decision_root: String,
    /// Transition artifact root.
    pub transition_root: String,
    /// Portable receipt artifact root.
    pub receipt_root: String,
}

/// Test-only artifact graph used to pressure-test contract reconstruction before daemon ownership.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
struct FinalizedSystemLifecycleArtifacts {
    /// Committed lifecycle step.
    step: UnverifiedCommittedSystemLifecycleStep,
    /// Active profile admission projection created only by activation.
    active_profile_set: Option<Value>,
    /// Activation-owned admitted home-domain binding created only at sequence two.
    home_domain_binding: Option<Value>,
    /// Immutable sequence-zero/initialize/activate operation-log revision.
    operation_log: Option<Value>,
    /// First live AutonomousSystemChain created only by activation.
    chain: Option<Value>,
}

fn jcs_hash(material: &Value) -> Result<String, String> {
    let canonical = serde_jcs::to_vec(material).map_err(|error| error.to_string())?;
    let digest = Sha256::digest(&canonical).map_err(|error| error.to_string())?;
    let encoded = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("sha256:{encoded}"))
}

fn artifact_root(domain: &str, artifact: &Value) -> Result<String, String> {
    jcs_hash(&json!({"domain": domain, "artifact": artifact}))
}

fn required_string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| format!("missing canonical string at {pointer}"))
}

#[cfg(test)]
fn canonical_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|tail| {
        tail.len() == 64
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn contract(contract_id: &str, value: &Value, label: &str) -> Result<(), String> {
    validate_architecture_contract(contract_id, value)
        .map_err(|error| format!("{label} violates {contract_id} ({error})"))
}

fn namespace(system_id: &str) -> Result<&str, String> {
    system_id
        .strip_prefix("system://")
        .filter(|tail| {
            !tail.is_empty()
                && tail.len() <= 224
                && !tail
                    .chars()
                    .any(|ch| ch.is_whitespace() || matches!(ch, '?' | '#' | '\\'))
        })
        .ok_or_else(|| "system_id is not a canonical system ref".to_owned())
}

fn candidate_root(kind: &str, candidate: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": PROFILE_CANDIDATE_HASH_PROFILE,
        "kind": kind,
        "candidate": candidate,
    }))
}

fn deterministic_receipt_ref(
    system_id: &str,
    operation: SystemLifecycleOperation,
) -> Result<String, String> {
    let root = jcs_hash(&json!({
        "domain": DETERMINISTIC_REF_HASH_PROFILE,
        "system_id": system_id,
        "sequence": operation.sequence(),
        "kind": match operation {
            SystemLifecycleOperation::Initialize => "lifecycle_transition_receipt",
            SystemLifecycleOperation::Activate => "autonomous_system_activation_receipt",
        },
    }))?;
    let prefix = match operation {
        SystemLifecycleOperation::Initialize => "ltr_",
        SystemLifecycleOperation::Activate => "asar_",
    };
    Ok(format!(
        "receipt://{prefix}{}",
        root.strip_prefix("sha256:").expect("hash helper prefix")
    ))
}

/// Recompute the exact hash used by the governed-decision runtime for this plane.
fn unverified_system_lifecycle_effect_hash(effect: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": format!("{SYSTEM_LIFECYCLE_AUTHORITY_REQUEST_DOMAIN}.effect.v1"),
        "effect": effect,
    }))
}

fn source_coordinates(
    source: &UnverifiedSystemSequenceZeroActivationSource,
) -> Result<SourceCoordinates<'_>, String> {
    contract(
        MATERIALIZATION_CONTRACT,
        &source.materialization,
        "sequence-zero materialization",
    )?;
    contract(
        CURRENT_MATERIALIZATION_RECEIPT_CONTRACT,
        &source.materialization_receipt,
        "sequence-zero materialization receipt",
    )?;
    let genesis = source
        .genesis_admission_record
        .get("authorized_genesis")
        .ok_or_else(|| "M1.3 admission lacks authorized_genesis".to_owned())?;
    let profile_bundle = source
        .genesis_admission_record
        .get("initial_profile_bundle")
        .ok_or_else(|| "M1.3 admission lacks initial_profile_bundle".to_owned())?;
    validate_principal_authority_ref(&source.source_governing_authority_ref)
        .map_err(|error| format!("source governing authority is not canonical ({error})"))?;
    if required_string(&source.genesis_admission_record, "/governing_authority_ref")?
        != source.source_governing_authority_ref
    {
        return Err("source governing authority detaches the M1.3 admission".to_owned());
    }
    contract(GENESIS_CONTRACT, genesis, "authorized genesis")?;
    contract(
        INITIAL_PROFILE_BUNDLE_CONTRACT,
        profile_bundle,
        "initial profile bundle",
    )?;
    let materialization = &source.materialization;
    let system_id = required_string(materialization, "/system_id")?;
    let genesis_ref = required_string(materialization, "/genesis_ref")?;
    let manifest_ref = required_string(materialization, "/manifest_ref")?;
    let admitted_manifest_root = required_string(materialization, "/admitted_manifest_root")?;
    let package_id = required_string(materialization, "/package_id")?;
    let profile_bundle_root = required_string(materialization, "/profile_bundle_root")?;
    let genesis_admission_receipt_ref =
        required_string(materialization, "/genesis_admission_receipt_ref")?;
    let genesis_admission_record_root =
        compute_system_genesis_admission_record_root(&source.genesis_admission_record)?;
    let genesis_admission_receipt_root =
        compute_system_genesis_admission_receipt_root(&source.genesis_admission_receipt)?;
    if required_string(&source.genesis_admission_record, "/admission_receipt_ref")?
        != genesis_admission_receipt_ref
        || required_string(&source.genesis_admission_receipt, "/receipt_ref")?
            != genesis_admission_receipt_ref
        || required_string(materialization, "/genesis_admission_record_root")?
            != genesis_admission_record_root
        || required_string(materialization, "/genesis_admission_receipt_root")?
            != genesis_admission_receipt_root
    {
        return Err("M1.3 admission record and receipt do not match M1.4 roots".to_owned());
    }
    let deployment_profile_ref =
        required_string(materialization, "/profile_refs/deployment_profile_ref")?;
    if !deployment_profile_ref.contains("/revision/sha256:") {
        return Err(
            "legacy deployment-profile compatibility commitment cannot authorize activation"
                .to_owned(),
        );
    }
    let computed_bundle_root = jcs_hash(&json!({
        "domain": PROFILE_BUNDLE_HASH_PROFILE,
        "value": profile_bundle,
    }))?;
    if computed_bundle_root != profile_bundle_root {
        return Err("M1.3 candidate profile bundle root does not match M1.4".to_owned());
    }
    for (left, right, label) in [
        (
            genesis.get("system_id").and_then(Value::as_str),
            Some(system_id),
            "system",
        ),
        (
            genesis.get("genesis_id").and_then(Value::as_str),
            Some(genesis_ref),
            "genesis",
        ),
        (
            genesis.get("manifest_ref").and_then(Value::as_str),
            Some(manifest_ref),
            "manifest",
        ),
    ] {
        if left != right {
            return Err(format!("M1.3/M1.4 {label} coordinate mismatch"));
        }
    }
    let receipt_effect = source
        .materialization_receipt
        .pointer("/authorized_effect/materialization")
        .ok_or_else(|| "M1.4 receipt lacks authorized materialization".to_owned())?;
    let mut receipt_comparable_materialization = materialization.clone();
    receipt_comparable_materialization
        .as_object_mut()
        .ok_or_else(|| "M1.4 materialization is not an object".to_owned())?
        .remove("created_at");
    if receipt_effect != &receipt_comparable_materialization
        || required_string(materialization, "/created_at")?
            != required_string(&source.materialization_receipt, "/timestamp")?
    {
        return Err("M1.4 receipt does not embed the exact materialization".to_owned());
    }
    let component_ref = required_string(materialization, "/component_registry_ref")?;
    let component_root = required_string(materialization, "/component_registry_root")?;
    if source
        .component_registry
        .get("component_registry_ref")
        .and_then(Value::as_str)
        != Some(component_ref)
        || source
            .component_registry
            .get("component_registry_root")
            .and_then(Value::as_str)
            != Some(component_root)
    {
        return Err("M1.4 component registry does not match its materialization".to_owned());
    }
    let component_registry_material = json!({
        "schema_version": "ioi.autonomous-system-component-registry-snapshot.v1",
        "system_id": required_string(&source.component_registry, "/system_id")?,
        "genesis_ref": required_string(&source.component_registry, "/genesis_ref")?,
        "component_bindings": source.component_registry
            .get("component_bindings")
            .cloned()
            .ok_or_else(|| "M1.4 component registry lacks component_bindings".to_owned())?,
    });
    let computed_component_root = jcs_hash(&json!({
        "domain": SYSTEM_COMPONENT_REGISTRY_HASH_PROFILE,
        "value": component_registry_material,
    }))?;
    if computed_component_root != component_root {
        return Err("M1.4 component registry root does not bind its exact bytes".to_owned());
    }
    let materialization_root = artifact_root(
        "ioi.autonomous-system-sequence-zero-materialization-artifact-jcs-sha256.v1",
        materialization,
    )?;
    let materialization_receipt_root = artifact_root(
        "ioi.autonomous-system-sequence-zero-materialization-receipt-artifact-jcs-sha256.v1",
        &source.materialization_receipt,
    )?;
    let materialization_wallet_consumption_ref = required_string(
        &source.materialization_receipt,
        "/bound_facts/wallet_grant_consumption_ref",
    )?;
    let materialization_wallet_consumption_root = artifact_root(
        "ioi.autonomous-system-sequence-zero-wallet-consumption-artifact-jcs-sha256.v1",
        &source.materialization_wallet_consumption,
    )?;
    let constitution = profile_bundle
        .get("constitution")
        .ok_or_else(|| "M1.3 profile bundle lacks constitution".to_owned())?;
    let ordering_profile = profile_bundle
        .get("ordering_profile")
        .ok_or_else(|| "M1.3 profile bundle lacks ordering profile".to_owned())?;
    let source_governing_authority_ref = source.source_governing_authority_ref.as_str();
    let home_domain_commitment = jcs_hash(&json!({
        "domain": HOME_DOMAIN_IDENTITY_HASH_PROFILE,
        "system_id": system_id,
        "genesis_ref": genesis_ref,
        "source_governing_authority_ref": source_governing_authority_ref,
        "source_genesis_admission_receipt_ref": genesis_admission_receipt_ref,
        "source_genesis_admission_receipt_root": genesis_admission_receipt_root,
        "source_sequence_zero_materialization_ref": required_string(materialization, "/materialization_id")?,
        "source_sequence_zero_materialization_root": materialization_root,
        "source_sequence_zero_receipt_ref": required_string(materialization, "/materialization_receipt_ref")?,
        "source_sequence_zero_receipt_root": required_string(materialization, "/initial_receipt_root")?,
        "source_sequence_zero_receipt_artifact_root": materialization_receipt_root,
    }))?;
    let home_domain_ref = format!(
        "agentgres://domain/autonomous-system/{}/{}",
        namespace(system_id)?,
        home_domain_commitment
    );
    let module_registry_root = jcs_hash(&json!({
        "domain": SYSTEM_MODULE_REGISTRY_ROOT_HASH_PROFILE,
        "module_refs": [],
    }))?;
    Ok(SourceCoordinates {
        #[cfg(test)]
        materialization,
        genesis,
        profile_bundle,
        #[cfg(test)]
        constitution,
        source_governing_authority_ref,
        system_id,
        genesis_ref,
        package_id,
        manifest_ref,
        admitted_manifest_root,
        profile_bundle_root,
        deployment_profile_ref,
        deployment_profile_root: required_string(materialization, "/deployment_profile_root")?,
        lifecycle_profile_ref: required_string(
            materialization,
            "/profile_refs/lifecycle_continuity_profile_ref",
        )?,
        component_ref,
        component_root,
        sequence_zero_materialization_ref: required_string(materialization, "/materialization_id")?,
        sequence_zero_materialization_root: materialization_root,
        sequence_zero_receipt_ref: required_string(
            materialization,
            "/materialization_receipt_ref",
        )?,
        sequence_zero_receipt_root: required_string(materialization, "/initial_receipt_root")?,
        sequence_zero_receipt_artifact_root: materialization_receipt_root,
        genesis_admission_record_root,
        genesis_admission_receipt_ref,
        genesis_admission_receipt_root,
        materialization_wallet_consumption_ref,
        materialization_wallet_consumption_root,
        sequence_zero_state_root: required_string(materialization, "/initial_state_root")?,
        #[cfg(test)]
        sequence_zero_operation_commitment: required_string(
            materialization,
            "/operation_commitment",
        )?,
        home_domain_ref,
        home_domain_commitment,
        policy_root: required_string(ordering_profile, "/admission/policy_root")?,
        module_registry_root,
        upgrade_policy_ref: required_string(
            constitution,
            "/governance/ordinary_upgrade_policy_ref",
        )?,
    })
}

struct SourceCoordinates<'a> {
    #[cfg(test)]
    materialization: &'a Value,
    genesis: &'a Value,
    profile_bundle: &'a Value,
    #[cfg(test)]
    constitution: &'a Value,
    source_governing_authority_ref: &'a str,
    system_id: &'a str,
    genesis_ref: &'a str,
    package_id: &'a str,
    manifest_ref: &'a str,
    admitted_manifest_root: &'a str,
    profile_bundle_root: &'a str,
    deployment_profile_ref: &'a str,
    deployment_profile_root: &'a str,
    lifecycle_profile_ref: &'a str,
    component_ref: &'a str,
    component_root: &'a str,
    sequence_zero_materialization_ref: &'a str,
    sequence_zero_materialization_root: String,
    sequence_zero_receipt_ref: &'a str,
    sequence_zero_receipt_root: &'a str,
    sequence_zero_receipt_artifact_root: String,
    genesis_admission_record_root: String,
    genesis_admission_receipt_ref: &'a str,
    genesis_admission_receipt_root: String,
    materialization_wallet_consumption_ref: &'a str,
    materialization_wallet_consumption_root: String,
    sequence_zero_state_root: &'a str,
    #[cfg(test)]
    sequence_zero_operation_commitment: &'a str,
    home_domain_ref: String,
    home_domain_commitment: String,
    policy_root: &'a str,
    module_registry_root: String,
    upgrade_policy_ref: &'a str,
}

fn validate_deployment(source: &SourceCoordinates<'_>, revision: &Value) -> Result<(), String> {
    contract(
        SYSTEM_DEPLOYMENT_PROFILE_REVISION_CONTRACT,
        revision,
        "deployment-profile revision",
    )?;
    if revision
        .get("deployment_profile_ref")
        .and_then(Value::as_str)
        != Some(source.deployment_profile_ref)
    {
        return Err("deployment-profile revision does not match M1.4".to_owned());
    }
    let root = required_string(revision, "/deployment_profile_root")?;
    let profile = revision
        .get("profile")
        .ok_or_else(|| "deployment revision lacks profile".to_owned())?;
    let recomputed_root = jcs_hash(&json!({
        "domain": DEPLOYMENT_PROFILE_REVISION_HASH_PROFILE,
        "profile": profile,
    }))?;
    if root != recomputed_root {
        return Err("deployment-profile declared root does not bind its exact body".to_owned());
    }
    if source
        .genesis
        .pointer("/initial_profile_refs/deployment_profile_ref")
        .and_then(Value::as_str)
        != Some(source.deployment_profile_ref)
    {
        return Err("M1.3/M1.4 deployment-profile ref mismatch".to_owned());
    }
    let materialized_root = source
        .deployment_profile_ref
        .rsplit_once("/revision/")
        .map(|(_, hash)| hash)
        .ok_or_else(|| "M1.3 deployment profile is not content addressed".to_owned())?;
    if root != materialized_root || root != source.deployment_profile_root {
        return Err("deployment-profile root does not match M1.3/M1.4".to_owned());
    }
    validate_deployment_coordinates(source, revision)
}

fn validate_deployment_coordinates(
    source: &SourceCoordinates<'_>,
    revision: &Value,
) -> Result<(), String> {
    let profile = revision
        .get("profile")
        .ok_or_else(|| "deployment revision lacks profile".to_owned())?;
    for (pointer, expected, label) in [
        ("/system_id", source.system_id, "system"),
        (
            "/constitution_ref",
            required_string(source.genesis, "/constitution_ref")?,
            "constitution",
        ),
        ("/manifest_ref", source.manifest_ref, "manifest"),
        (
            "/ordering_admission_finality_profile_ref",
            required_string(
                source.genesis,
                "/initial_profile_refs/ordering_admission_finality_profile_ref",
            )?,
            "ordering profile",
        ),
    ] {
        if required_string(profile, pointer)? != expected {
            return Err(format!("deployment-profile {label} coordinate mismatch"));
        }
    }
    Ok(())
}

fn profile_admission(kind: &str, contract_id: &str, body: &Value) -> Result<Value, String> {
    contract(contract_id, body, kind)?;
    Ok(json!({
        "candidate_profile_ref": profile_ref(kind, body)?,
        "candidate_profile_root": candidate_root(kind, body)?,
        "admitted_posture": "active",
    }))
}

fn profile_ref<'a>(kind: &str, body: &'a Value) -> Result<&'a str, String> {
    let pointer = match kind {
        "constitution" => "/constitution_id",
        "ordering_admission_finality" => "/ordering_profile_id",
        "oracle_evidence" => "/oracle_evidence_profile_id",
        "lifecycle_continuity" => "/lifecycle_profile_id",
        "network_enrollment" => "/network_enrollment_id",
        _ => return Err(format!("unknown profile kind {kind}")),
    };
    required_string(body, pointer)
}

fn network_profile_admission(
    profile: &Value,
    system_id: &str,
    constitution_ref: &str,
    manifest_ref: &str,
) -> Result<Value, String> {
    contract(NETWORK_ENROLLMENT_CONTRACT, profile, "network enrollment")?;
    for (pointer, expected, label) in [
        ("/system_id", system_id, "system"),
        ("/constitution_ref", constitution_ref, "constitution"),
        ("/manifest_ref", manifest_ref, "manifest"),
    ] {
        if required_string(profile, pointer)? != expected {
            return Err(format!(
                "network-enrollment candidate {label} coordinate mismatch"
            ));
        }
    }
    Ok(json!({
        "candidate_profile_ref": profile_ref("network_enrollment", profile)?,
        "candidate_profile_root": candidate_root("network_enrollment", profile)?,
        "admitted_posture": "local_only",
    }))
}

fn active_profile_set_semantic(
    source: &SourceCoordinates<'_>,
    revision: &Value,
) -> Result<(Value, String), String> {
    let bundle = source.profile_bundle;
    let constitution = profile_admission(
        "constitution",
        CONSTITUTION_CONTRACT,
        &bundle["constitution"],
    )?;
    let deployment = json!({
        "candidate_profile_ref": required_string(revision, "/deployment_profile_ref")?,
        "candidate_profile_root": required_string(revision, "/deployment_profile_root")?,
        "admitted_posture": "active",
    });
    let ordering = profile_admission(
        "ordering_admission_finality",
        ORDERING_CONTRACT,
        &bundle["ordering_profile"],
    )?;
    let oracles = bundle
        .get("oracle_profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| "initial profile bundle oracle_profiles is not an array".to_owned())?
        .iter()
        .map(|profile| profile_admission("oracle_evidence", ORACLE_CONTRACT, profile))
        .collect::<Result<Vec<_>, _>>()?;
    let lifecycle = profile_admission(
        "lifecycle_continuity",
        LIFECYCLE_PROFILE_CONTRACT,
        &bundle["lifecycle_profile"],
    )?;
    let network = match bundle.get("network_enrollment") {
        Some(Value::Null) | None => Value::Null,
        Some(profile) => network_profile_admission(
            profile,
            source.system_id,
            required_string(source.genesis, "/constitution_ref")?,
            source.manifest_ref,
        )?,
    };
    let active_profile_set_ref = format!(
        "active-profile-set://{}/sequence/2",
        namespace(source.system_id)?
    );
    let material = json!({
        "domain": ACTIVE_PROFILE_SET_HASH_PROFILE,
        "active_profile_set_ref": active_profile_set_ref,
        "system_id": source.system_id,
        "genesis_ref": source.genesis_ref,
        "profile_bundle_root": source.profile_bundle_root,
        "constitution": constitution,
        "deployment": deployment,
        "ordering_admission_finality": ordering,
        "oracle_evidence_profiles": oracles,
        "lifecycle_continuity": lifecycle,
        "network_enrollment": network,
        "status": "active",
    });
    let root = jcs_hash(&material)?;
    let semantic = json!({
        "schema_version": "ioi.autonomous-system-active-profile-set.v1",
        "active_profile_set_ref": material["active_profile_set_ref"],
        "active_profile_set_root": root,
        "system_id": source.system_id,
        "genesis_ref": source.genesis_ref,
        "profile_bundle_root": source.profile_bundle_root,
        "activation_transition_ref": Value::Null,
        "activation_receipt_ref": Value::Null,
        "constitution": material["constitution"],
        "deployment": material["deployment"],
        "ordering_admission_finality": material["ordering_admission_finality"],
        "oracle_evidence_profiles": material["oracle_evidence_profiles"],
        "lifecycle_continuity": material["lifecycle_continuity"],
        "network_enrollment": material["network_enrollment"],
        "status": "active",
        "created_at": Value::Null,
    });
    Ok((semantic, root))
}

fn semantic_state(
    source: &SourceCoordinates<'_>,
    operation: SystemLifecycleOperation,
    predecessor_state_root: &str,
    active_profile_set: Option<(&str, &str)>,
) -> Result<(Value, String), String> {
    let sequence = operation.sequence();
    let status = match operation {
        SystemLifecycleOperation::Initialize => "initialized",
        SystemLifecycleOperation::Activate => "active",
    };
    let state_ref = format!(
        "system-activation-state://{}/sequence/{sequence}",
        namespace(source.system_id)?
    );
    let active_ref = active_profile_set.map(|(reference, _)| reference);
    let active_root = active_profile_set.map(|(_, root)| root);
    let material = json!({
        "domain": LIFECYCLE_STATE_HASH_PROFILE,
        "activation_state_ref": state_ref,
        "system_id": source.system_id,
        "genesis_ref": source.genesis_ref,
        "manifest_ref": source.manifest_ref,
        "admitted_manifest_root": source.admitted_manifest_root,
        "lifecycle_profile_ref": source.lifecycle_profile_ref,
        "sequence": sequence,
        "status": status,
        "predecessor_state_root": predecessor_state_root,
        "active_profile_set_ref": active_ref,
        "active_profile_set_root": active_root,
        "live_chain_created": operation == SystemLifecycleOperation::Activate,
        "node_membership_refs": [],
        "runtime_effect_admitted": false,
        "network_effect_admitted": false,
    });
    let root = jcs_hash(&material)?;
    let chain_ref = (operation == SystemLifecycleOperation::Activate).then(|| {
        format!(
            "autonomous-system-chain://{}",
            namespace(source.system_id).unwrap()
        )
    });
    Ok((
        json!({
            "schema_version": "ioi.autonomous-system-activation-state.v1",
            "activation_state_ref": material["activation_state_ref"],
            "activation_state_root": root,
            "system_id": source.system_id,
            "genesis_ref": source.genesis_ref,
            "manifest_ref": source.manifest_ref,
            "admitted_manifest_root": source.admitted_manifest_root,
            "lifecycle_profile_ref": source.lifecycle_profile_ref,
            "sequence": sequence,
            "status": status,
            "predecessor_state_root": predecessor_state_root,
            "transition_ref": Value::Null,
            "transition_root": Value::Null,
            "transition_receipt_ref": Value::Null,
            "transition_receipt_root": Value::Null,
            "active_profile_set_ref": active_ref,
            "active_profile_set_root": active_root,
            "chain_ref": chain_ref,
            "live_chain_created": operation == SystemLifecycleOperation::Activate,
            "node_membership_refs": [],
            "runtime_effect_admitted": false,
            "network_effect_admitted": false,
            "created_at": Value::Null,
        }),
        root,
    ))
}

fn semantic_home_domain_binding(source: &SourceCoordinates<'_>) -> Result<(Value, String), String> {
    let transition_ref = format!(
        "lifecycle-transition://{}/sequence/2",
        namespace(source.system_id)?
    );
    let receipt_ref =
        deterministic_receipt_ref(source.system_id, SystemLifecycleOperation::Activate)?;
    let material = json!({
        "domain": HOME_DOMAIN_BINDING_HASH_PROFILE,
        "system_id": source.system_id,
        "genesis_ref": source.genesis_ref,
        "home_domain_ref": source.home_domain_ref,
        "home_domain_commitment": source.home_domain_commitment,
        "source_governing_authority_ref": source.source_governing_authority_ref,
        "source_genesis_admission_receipt_ref": source.genesis_admission_receipt_ref,
        "source_genesis_admission_receipt_root": source.genesis_admission_receipt_root,
        "source_sequence_zero_materialization_ref": source.sequence_zero_materialization_ref,
        "source_sequence_zero_materialization_root": source.sequence_zero_materialization_root,
        "source_sequence_zero_receipt_ref": source.sequence_zero_receipt_ref,
        "source_sequence_zero_receipt_root": source.sequence_zero_receipt_root,
        "source_sequence_zero_receipt_artifact_root": source.sequence_zero_receipt_artifact_root,
        "status": "admitted",
    });
    let root = jcs_hash(&material)?;
    let binding_ref = format!(
        "system-home-domain-binding://{}/{}",
        namespace(source.system_id)?,
        root
    );
    Ok((
        json!({
            "schema_version": "ioi.autonomous-system-home-domain-binding.v1",
            "home_domain_binding_ref": binding_ref,
            "home_domain_binding_root": root,
            "system_id": source.system_id,
            "genesis_ref": source.genesis_ref,
            "home_domain_ref": source.home_domain_ref,
            "home_domain_commitment": source.home_domain_commitment,
            "source_governing_authority_ref": source.source_governing_authority_ref,
            "source_genesis_admission_receipt_ref": source.genesis_admission_receipt_ref,
            "source_genesis_admission_receipt_root": source.genesis_admission_receipt_root,
            "source_sequence_zero_materialization_ref": source.sequence_zero_materialization_ref,
            "source_sequence_zero_materialization_root": source.sequence_zero_materialization_root,
            "source_sequence_zero_receipt_ref": source.sequence_zero_receipt_ref,
            "source_sequence_zero_receipt_root": source.sequence_zero_receipt_root,
            "source_sequence_zero_receipt_artifact_root": source.sequence_zero_receipt_artifact_root,
            "activation_transition_ref": transition_ref,
            "activation_receipt_ref": receipt_ref,
            "status": "admitted",
            "created_at": Value::Null,
        }),
        root,
    ))
}

fn operation_commitment_from_effect(effect: &Value) -> Result<String, String> {
    let field = |name: &str| {
        effect
            .get(name)
            .cloned()
            .ok_or_else(|| format!("authority effect lacks {name}"))
    };
    jcs_hash(&json!({
        "domain": LIFECYCLE_OPERATION_COMMITMENT_HASH_PROFILE,
        "operation": field("operation")?,
        "required_scope": field("required_scope")?,
        "sequence": field("sequence")?,
        "system_id": field("system_id")?,
        "genesis_ref": field("genesis_ref")?,
        "home_domain_ref": field("home_domain_ref")?,
        "home_domain_commitment": field("home_domain_commitment")?,
        "home_domain_binding_ref": field("home_domain_binding_ref")?,
        "home_domain_binding_root": field("home_domain_binding_root")?,
        "policy_root": field("policy_root")?,
        "module_registry_root": field("module_registry_root")?,
        "upgrade_policy_ref": field("upgrade_policy_ref")?,
        "deployment_profile_ref": field("deployment_profile_ref")?,
        "deployment_profile_root": field("deployment_profile_root")?,
        "predecessor_state_root": field("predecessor_state_root")?,
        "resulting_state_ref": field("resulting_state_ref")?,
        "resulting_state_root": field("resulting_state_root")?,
        "active_profile_set_ref": field("active_profile_set_ref")?,
        "active_profile_set_root": field("active_profile_set_root")?,
        "chain_ref": field("chain_ref")?,
        "live_chain_created": field("live_chain_created")?,
        "node_membership_created": field("node_membership_created")?,
        "runtime_effect_admitted": field("runtime_effect_admitted")?,
        "network_effect_admitted": field("network_effect_admitted")?,
    }))
}

/// Compile sequence one from exact M1.3/M1.4 evidence and an immutable deployment revision.
pub fn compile_system_initialize_plan(
    source: &UnverifiedSystemSequenceZeroActivationSource,
    deployment_profile_revision: &Value,
) -> Result<CompiledSystemLifecyclePlan, String> {
    let coordinates = source_coordinates(source)?;
    validate_deployment(&coordinates, deployment_profile_revision)?;
    let (state, state_root) = semantic_state(
        &coordinates,
        SystemLifecycleOperation::Initialize,
        coordinates.sequence_zero_state_root,
        None,
    )?;
    let effect = authority_effect(
        &coordinates,
        SystemLifecycleOperation::Initialize,
        coordinates.sequence_zero_state_root,
        &state,
        &state_root,
        None,
        None,
        None,
    )?;
    Ok(CompiledSystemLifecyclePlan {
        operation: SystemLifecycleOperation::Initialize,
        source: source.clone(),
        deployment_profile_revision: deployment_profile_revision.clone(),
        previous_step: None,
        semantic_state: state,
        resulting_state_root: state_root,
        semantic_active_profile_set: None,
        active_profile_set_root: None,
        semantic_home_domain_binding: None,
        home_domain_binding_root: None,
        authority_effect: effect,
    })
}

fn validate_step_source(
    step: &UnverifiedCommittedSystemLifecycleStep,
    source: &SourceCoordinates<'_>,
) -> Result<(), String> {
    let expected = [
        ("/system_id", source.system_id),
        ("/genesis_ref", source.genesis_ref),
        ("/manifest_ref", source.manifest_ref),
        ("/admitted_manifest_root", source.admitted_manifest_root),
        ("/lifecycle_profile_ref", source.lifecycle_profile_ref),
    ];
    for (pointer, value) in expected {
        if required_string(&step.state, pointer)? != value
            || required_string(&step.transition, pointer)? != value
        {
            return Err(format!(
                "initialized lifecycle state and transition detach source coordinate {pointer}"
            ));
        }
    }
    let effect_facts = [
        ("system_id", source.system_id),
        ("genesis_ref", source.genesis_ref),
        (
            "genesis_admission_record_root",
            source.genesis_admission_record_root.as_str(),
        ),
        (
            "genesis_admission_receipt_ref",
            source.genesis_admission_receipt_ref,
        ),
        (
            "genesis_admission_receipt_root",
            source.genesis_admission_receipt_root.as_str(),
        ),
        ("package_id", source.package_id),
        ("manifest_ref", source.manifest_ref),
        ("admitted_manifest_root", source.admitted_manifest_root),
        ("lifecycle_profile_ref", source.lifecycle_profile_ref),
        ("profile_bundle_root", source.profile_bundle_root),
        (
            "sequence_zero_materialization_id",
            source.sequence_zero_materialization_ref,
        ),
        (
            "sequence_zero_materialization_root",
            source.sequence_zero_materialization_root.as_str(),
        ),
        (
            "sequence_zero_receipt_ref",
            source.sequence_zero_receipt_ref,
        ),
        (
            "sequence_zero_receipt_root",
            source.sequence_zero_receipt_root,
        ),
        (
            "sequence_zero_receipt_artifact_root",
            source.sequence_zero_receipt_artifact_root.as_str(),
        ),
        ("component_registry_ref", source.component_ref),
        ("component_registry_root", source.component_root),
        (
            "materialization_wallet_consumption_ref",
            source.materialization_wallet_consumption_ref,
        ),
        (
            "materialization_wallet_consumption_root",
            source.materialization_wallet_consumption_root.as_str(),
        ),
        ("deployment_profile_ref", source.deployment_profile_ref),
        ("deployment_profile_root", source.deployment_profile_root),
        (
            "source_governing_authority_ref",
            source.source_governing_authority_ref,
        ),
        ("home_domain_ref", source.home_domain_ref.as_str()),
        (
            "home_domain_commitment",
            source.home_domain_commitment.as_str(),
        ),
        ("policy_root", source.policy_root),
        ("module_registry_root", source.module_registry_root.as_str()),
        ("upgrade_policy_ref", source.upgrade_policy_ref),
    ];
    for (field, expected) in effect_facts {
        let effect_pointer = format!("/authority_effect/{field}");
        if required_string(&step.proposal, &effect_pointer)? != expected {
            return Err(format!(
                "initialized proposal detaches exact source coordinate {field}"
            ));
        }
    }
    let receipt_facts = [
        ("system_id", source.system_id),
        ("genesis_ref", source.genesis_ref),
        (
            "genesis_admission_record_root",
            source.genesis_admission_record_root.as_str(),
        ),
        (
            "genesis_admission_receipt_ref",
            source.genesis_admission_receipt_ref,
        ),
        (
            "genesis_admission_receipt_root",
            source.genesis_admission_receipt_root.as_str(),
        ),
        (
            "sequence_zero_materialization_id",
            source.sequence_zero_materialization_ref,
        ),
        (
            "sequence_zero_materialization_root",
            source.sequence_zero_materialization_root.as_str(),
        ),
        (
            "sequence_zero_receipt_ref",
            source.sequence_zero_receipt_ref,
        ),
        (
            "sequence_zero_receipt_root",
            source.sequence_zero_receipt_root,
        ),
        (
            "sequence_zero_receipt_artifact_root",
            source.sequence_zero_receipt_artifact_root.as_str(),
        ),
        (
            "source_governing_authority_ref",
            source.source_governing_authority_ref,
        ),
        ("home_domain_ref", source.home_domain_ref.as_str()),
        (
            "home_domain_commitment",
            source.home_domain_commitment.as_str(),
        ),
        ("component_registry_ref", source.component_ref),
        ("component_registry_root", source.component_root),
        (
            "materialization_wallet_consumption_ref",
            source.materialization_wallet_consumption_ref,
        ),
        (
            "materialization_wallet_consumption_root",
            source.materialization_wallet_consumption_root.as_str(),
        ),
        ("deployment_profile_ref", source.deployment_profile_ref),
        ("deployment_profile_root", source.deployment_profile_root),
        ("profile_bundle_root", source.profile_bundle_root),
        ("policy_root", source.policy_root),
        ("module_registry_root", source.module_registry_root.as_str()),
        ("upgrade_policy_ref", source.upgrade_policy_ref),
    ];
    for (field, expected) in receipt_facts {
        let receipt_pointer = format!("/bound_facts/{field}");
        if required_string(&step.receipt, &receipt_pointer)? != expected {
            return Err(format!(
                "initialized receipt detaches exact source coordinate {field}"
            ));
        }
    }
    Ok(())
}

/// Compile sequence two from the exact initialized evidence.
pub fn compile_system_activate_plan(
    source: &UnverifiedSystemSequenceZeroActivationSource,
    deployment_profile_revision: &Value,
    initialized: &UnverifiedCommittedSystemLifecycleStep,
) -> Result<CompiledSystemLifecyclePlan, String> {
    let coordinates = source_coordinates(source)?;
    validate_deployment(&coordinates, deployment_profile_revision)?;
    validate_committed_step(
        initialized,
        SystemLifecycleOperation::Initialize,
        coordinates.sequence_zero_state_root,
    )?;
    validate_step_source(initialized, &coordinates)?;
    let (active_set, active_root) =
        active_profile_set_semantic(&coordinates, deployment_profile_revision)?;
    let (home_domain_binding, home_domain_binding_root) =
        semantic_home_domain_binding(&coordinates)?;
    let active_ref = required_string(&active_set, "/active_profile_set_ref")?;
    let (state, state_root) = semantic_state(
        &coordinates,
        SystemLifecycleOperation::Activate,
        &initialized.state_root,
        Some((active_ref, &active_root)),
    )?;
    let effect = authority_effect(
        &coordinates,
        SystemLifecycleOperation::Activate,
        &initialized.state_root,
        &state,
        &state_root,
        Some((&active_set, &active_root)),
        Some(initialized),
        Some((&home_domain_binding, &home_domain_binding_root)),
    )?;
    Ok(CompiledSystemLifecyclePlan {
        operation: SystemLifecycleOperation::Activate,
        source: source.clone(),
        deployment_profile_revision: deployment_profile_revision.clone(),
        previous_step: Some(initialized.clone()),
        semantic_state: state,
        resulting_state_root: state_root,
        semantic_active_profile_set: Some(active_set),
        active_profile_set_root: Some(active_root),
        semantic_home_domain_binding: Some(home_domain_binding),
        home_domain_binding_root: Some(home_domain_binding_root),
        authority_effect: effect,
    })
}

fn authority_effect(
    source: &SourceCoordinates<'_>,
    operation: SystemLifecycleOperation,
    predecessor_state_root: &str,
    state: &Value,
    state_root: &str,
    active_set: Option<(&Value, &str)>,
    previous_step: Option<&UnverifiedCommittedSystemLifecycleStep>,
    home_domain_binding: Option<(&Value, &str)>,
) -> Result<Value, String> {
    let previous = |artifact: &str, pointer: &str| {
        previous_step
            .and_then(|step| match artifact {
                "proposal" => step.proposal.pointer(pointer),
                "decision" => step.decision.pointer(pointer),
                "transition" => step.transition.pointer(pointer),
                "receipt" => step.receipt.pointer(pointer),
                "state" => step.state.pointer(pointer),
                _ => None,
            })
            .cloned()
            .unwrap_or(Value::Null)
    };
    let mut effect = json!({
        "schema_version": "ioi.autonomous-system-lifecycle-authority-effect.v1",
        "operation": operation.as_str(),
        "required_scope": operation.required_scope(),
        "sequence": operation.sequence(),
        "system_id": source.system_id,
        "genesis_ref": source.genesis_ref,
        "source_governing_authority_ref": source.source_governing_authority_ref,
        "genesis_admission_record_root": source.genesis_admission_record_root,
        "genesis_admission_receipt_ref": source.genesis_admission_receipt_ref,
        "genesis_admission_receipt_root": source.genesis_admission_receipt_root,
        "package_id": source.package_id,
        "manifest_ref": source.manifest_ref,
        "admitted_manifest_root": source.admitted_manifest_root,
        "lifecycle_profile_ref": source.lifecycle_profile_ref,
        "profile_bundle_root": source.profile_bundle_root,
        "sequence_zero_materialization_id": source.sequence_zero_materialization_ref,
        "sequence_zero_materialization_root": source.sequence_zero_materialization_root,
        "sequence_zero_receipt_ref": source.sequence_zero_receipt_ref,
        "sequence_zero_receipt_root": source.sequence_zero_receipt_root,
        "sequence_zero_receipt_artifact_root": source.sequence_zero_receipt_artifact_root,
        "component_registry_ref": source.component_ref,
        "component_registry_root": source.component_root,
        "materialization_wallet_consumption_ref": source.materialization_wallet_consumption_ref,
        "materialization_wallet_consumption_root": source.materialization_wallet_consumption_root,
        "deployment_profile_ref": source.deployment_profile_ref,
        "deployment_profile_root": source.deployment_profile_root,
        "home_domain_ref": source.home_domain_ref,
        "home_domain_commitment": source.home_domain_commitment,
        "home_domain_binding_ref": home_domain_binding
            .and_then(|(binding, _)| binding.get("home_domain_binding_ref"))
            .cloned()
            .unwrap_or(Value::Null),
        "home_domain_binding_root": home_domain_binding
            .map(|(_, root)| Value::String(root.to_owned()))
            .unwrap_or(Value::Null),
        "policy_root": source.policy_root,
        "module_registry_root": source.module_registry_root,
        "upgrade_policy_ref": source.upgrade_policy_ref,
        "operation_commitment": Value::Null,
    });
    effect["predecessor_proposal_ref"] = previous("proposal", "/proposal_ref");
    effect["predecessor_proposal_root"] = previous_step
        .map(|step| Value::String(step.proposal_root.clone()))
        .unwrap_or(Value::Null);
    effect["predecessor_decision_ref"] = previous("decision", "/decision_ref");
    effect["predecessor_decision_root"] = previous_step
        .map(|step| Value::String(step.decision_root.clone()))
        .unwrap_or(Value::Null);
    effect["predecessor_transition_ref"] = previous("transition", "/lifecycle_transition_id");
    effect["predecessor_transition_root"] = previous_step
        .map(|step| Value::String(step.transition_root.clone()))
        .unwrap_or(Value::Null);
    effect["predecessor_receipt_ref"] = previous("receipt", "/receipt_ref");
    effect["predecessor_receipt_root"] = previous_step
        .map(|step| Value::String(step.receipt_root.clone()))
        .unwrap_or(Value::Null);
    effect["predecessor_state_ref"] = previous("state", "/activation_state_ref");
    effect["predecessor_state_root"] = Value::String(predecessor_state_root.to_owned());
    effect["resulting_state_ref"] = state
        .get("activation_state_ref")
        .cloned()
        .unwrap_or(Value::Null);
    effect["resulting_state_root"] = Value::String(state_root.to_owned());
    effect["active_profile_set_ref"] = active_set
        .and_then(|(set, _)| set.get("active_profile_set_ref"))
        .cloned()
        .unwrap_or(Value::Null);
    effect["active_profile_set_root"] = active_set
        .map(|(_, root)| Value::String(root.to_owned()))
        .unwrap_or(Value::Null);
    effect["chain_ref"] = if operation == SystemLifecycleOperation::Activate {
        Value::String(format!(
            "autonomous-system-chain://{}",
            namespace(source.system_id)?
        ))
    } else {
        Value::Null
    };
    effect["live_chain_created"] = Value::Bool(operation == SystemLifecycleOperation::Activate);
    effect["node_membership_created"] = Value::Bool(false);
    effect["runtime_effect_admitted"] = Value::Bool(false);
    effect["network_effect_admitted"] = Value::Bool(false);
    effect["operation_commitment"] = Value::String(operation_commitment_from_effect(&effect)?);
    Ok(effect)
}

#[cfg(test)]
fn lifecycle_proposal(
    plan: &CompiledSystemLifecyclePlan,
    evidence: &SystemLifecycleAuthorityEvidence,
    timestamp: &str,
) -> Result<(Value, String), String> {
    if evidence.authorized_effect != plan.authority_effect {
        return Err("governed authority evidence does not bind the compiled effect".to_owned());
    }
    let expected_effect_hash = unverified_system_lifecycle_effect_hash(&plan.authority_effect)?;
    if evidence.effect_hash != expected_effect_hash {
        return Err("governed authority effect hash does not bind the compiled effect".to_owned());
    }
    let source = source_coordinates(&plan.source)?;
    let proposal_ref = format!(
        "proposal://{}/lifecycle/sequence/{}",
        namespace(source.system_id)?,
        plan.operation.sequence()
    );
    let material = json!({
        "domain": LIFECYCLE_PROPOSAL_HASH_PROFILE,
        "proposal_ref": proposal_ref,
        "system_id": source.system_id,
        "genesis_ref": source.genesis_ref,
        "operation": plan.operation.as_str(),
        "sequence": plan.operation.sequence(),
        "required_scope": plan.operation.required_scope(),
        "operation_commitment": required_string(&plan.authority_effect, "/operation_commitment")?,
        "authority_effect": plan.authority_effect,
        "authority_effect_hash": evidence.effect_hash,
        "status": "proposed",
        "created_at": timestamp,
    });
    let root = jcs_hash(&material)?;
    let mut proposal = material;
    proposal
        .as_object_mut()
        .expect("proposal material object")
        .remove("domain");
    proposal["schema_version"] =
        Value::String("ioi.autonomous-system-activation-proposal.v1".to_owned());
    proposal["proposal_root"] = Value::String(root.clone());
    contract(
        SYSTEM_LIFECYCLE_PROPOSAL_CONTRACT,
        &proposal,
        "lifecycle proposal",
    )?;
    Ok((proposal, root))
}

#[cfg(test)]
fn lifecycle_authority_decision(
    plan: &CompiledSystemLifecyclePlan,
    evidence: &SystemLifecycleAuthorityEvidence,
    proposal: &Value,
    proposal_root: &str,
    timestamp: &str,
) -> Result<(Value, String), String> {
    let source = source_coordinates(&plan.source)?;
    let decision_ref = format!(
        "decision://{}/lifecycle/sequence/{}",
        namespace(source.system_id)?,
        plan.operation.sequence()
    );
    let material = json!({
        "domain": LIFECYCLE_AUTHORITY_DECISION_HASH_PROFILE,
        "decision_ref": decision_ref,
        "proposal_ref": required_string(proposal, "/proposal_ref")?,
        "proposal_root": proposal_root,
        "system_id": source.system_id,
        "genesis_ref": source.genesis_ref,
        "operation": plan.operation.as_str(),
        "sequence": plan.operation.sequence(),
        "required_scope": plan.operation.required_scope(),
        "operation_commitment": required_string(&plan.authority_effect, "/operation_commitment")?,
        "input_hash": evidence.input_hash,
        "policy_hash": evidence.policy_hash,
        "effect_hash": evidence.effect_hash,
        "authority_grant_ref": evidence.authority_grant_ref,
        "authority_evidence_ref": evidence.authority_evidence_ref,
        "authority_evidence_root": evidence.authority_evidence_root,
        "wallet_grant_consumption_ref": evidence.wallet_grant_consumption_ref,
        "wallet_grant_consumption_root": evidence.wallet_grant_consumption_root,
        "wallet_grant_consumption_evidence_ref": evidence.wallet_grant_consumption_evidence_ref,
        "outcome": "admitted",
        "decided_at": timestamp,
    });
    let root = jcs_hash(&material)?;
    let mut decision = material;
    decision
        .as_object_mut()
        .expect("decision material object")
        .remove("domain");
    decision["schema_version"] =
        Value::String("ioi.autonomous-system-activation-authority-decision.v1".to_owned());
    decision["decision_root"] = Value::String(root.clone());
    contract(
        SYSTEM_LIFECYCLE_AUTHORITY_DECISION_CONTRACT,
        &decision,
        "lifecycle authority decision",
    )?;
    Ok((decision, root))
}

#[cfg(test)]
fn committed_transition(
    plan: &CompiledSystemLifecyclePlan,
    evidence: &SystemLifecycleAuthorityEvidence,
    proposal: &Value,
    decision: &Value,
    receipt_ref: &str,
) -> Result<(Value, String), String> {
    let source = source_coordinates(&plan.source)?;
    let op = plan.operation;
    let sequence = op.sequence();
    let namespace = namespace(source.system_id)?;
    let previous = match op {
        SystemLifecycleOperation::Initialize => "draft",
        SystemLifecycleOperation::Activate => "initialized",
    };
    let proposed = match op {
        SystemLifecycleOperation::Initialize => "initialized",
        SystemLifecycleOperation::Activate => "active",
    };
    let predecessor = match &plan.previous_step {
        Some(step) => step.state_root.as_str(),
        None => source.sequence_zero_state_root,
    };
    let trigger_evidence_refs = match &plan.previous_step {
        Some(step) => vec![
            Value::String(source.sequence_zero_receipt_ref.to_owned()),
            Value::String(required_string(&step.receipt, "/receipt_ref")?.to_owned()),
        ],
        None => vec![Value::String(source.sequence_zero_receipt_ref.to_owned())],
    };
    let transition_ref = format!("lifecycle-transition://{namespace}/sequence/{sequence}");
    let transition = json!({
        "schema_version": "ioi.lifecycle-transition.v1",
        "lifecycle_transition_id": transition_ref,
        "system_id": source.system_id,
        "resulting_or_related_system_id": Value::Null,
        "lifecycle_profile_ref": source.lifecycle_profile_ref,
        "transition_kind": op.as_str(),
        "genesis_ref": source.genesis_ref,
        "manifest_ref": source.manifest_ref,
        "admitted_manifest_root": source.admitted_manifest_root,
        "previous_state": previous,
        "proposed_state": proposed,
        "trigger_evidence_refs": trigger_evidence_refs,
        "oracle_evidence_profile_refs": source.genesis.pointer("/initial_profile_refs/oracle_evidence_profile_refs").cloned().unwrap_or_else(|| json!([])),
        "proposal_ref": required_string(proposal, "/proposal_ref")?,
        "decision_ref": required_string(decision, "/decision_ref")?,
        "authority_grant_refs": [evidence.authority_grant_ref.clone()],
        "challenge_opened_at": Value::Null,
        "challenge_closes_at": Value::Null,
        "predecessor_state_root": predecessor,
        "resulting_state_root": plan.resulting_state_root,
        "operation_commitment": required_string(&plan.authority_effect, "/operation_commitment")?,
        "state_transition_commitment_ref": Value::Null,
        "lineage_ref": Value::Null,
        "identity_continuity_decision_ref": Value::Null,
        "disposition_receipt_refs": [],
        "receipt_refs": [receipt_ref],
        "public_commitment_ref": Value::Null,
        "status": "committed",
    });
    contract(
        LIFECYCLE_TRANSITION_CONTRACT,
        &transition,
        "lifecycle transition",
    )?;
    let root = artifact_root(LIFECYCLE_TRANSITION_HASH_PROFILE, &transition)?;
    Ok((transition, root))
}

#[cfg(test)]
fn portable_receipt(
    plan: &CompiledSystemLifecyclePlan,
    evidence: &SystemLifecycleAuthorityEvidence,
    proposal: &Value,
    proposal_root: &str,
    decision: &Value,
    decision_root: &str,
    transition: &Value,
    transition_root: &str,
    receipt_ref: &str,
    timestamp: &str,
) -> Result<(Value, String), String> {
    let source = source_coordinates(&plan.source)?;
    let active_ref = plan
        .semantic_active_profile_set
        .as_ref()
        .and_then(|set| set.get("active_profile_set_ref"))
        .cloned()
        .unwrap_or(Value::Null);
    let active_root = plan
        .active_profile_set_root
        .as_ref()
        .map(|root| Value::String(root.clone()))
        .unwrap_or(Value::Null);
    let chain_ref = if plan.operation == SystemLifecycleOperation::Activate {
        Value::String(format!(
            "autonomous-system-chain://{}",
            namespace(source.system_id)?
        ))
    } else {
        Value::Null
    };
    let home_binding_ref = plan
        .semantic_home_domain_binding
        .as_ref()
        .and_then(|binding| binding.get("home_domain_binding_ref"))
        .cloned()
        .unwrap_or(Value::Null);
    let home_binding_root = plan
        .home_domain_binding_root
        .as_ref()
        .map(|root| Value::String(root.clone()))
        .unwrap_or(Value::Null);
    let transition_ref = required_string(transition, "/lifecycle_transition_id")?;
    let state_ref = required_string(&plan.semantic_state, "/activation_state_ref")?;
    let mut boundary = vec![
        source.system_id.to_owned(),
        source.genesis_ref.to_owned(),
        source.genesis_admission_receipt_ref.to_owned(),
        source.sequence_zero_materialization_ref.to_owned(),
        source.sequence_zero_receipt_ref.to_owned(),
        source.component_ref.to_owned(),
        source.deployment_profile_ref.to_owned(),
        source.materialization_wallet_consumption_ref.to_owned(),
        source.home_domain_ref.clone(),
        source.source_governing_authority_ref.to_owned(),
        source.upgrade_policy_ref.to_owned(),
        required_string(proposal, "/proposal_ref")?.to_owned(),
        required_string(decision, "/decision_ref")?.to_owned(),
        transition_ref.to_owned(),
        state_ref.to_owned(),
        evidence.authority_evidence_ref.clone(),
        evidence.wallet_grant_consumption_ref.clone(),
        evidence.wallet_grant_consumption_evidence_ref.clone(),
        evidence.authority_grant_ref.clone(),
    ];
    if let Some(value) = active_ref.as_str() {
        boundary.push(value.to_owned());
    }
    if let Some(value) = chain_ref.as_str() {
        boundary.push(value.to_owned());
    }
    if let Some(value) = home_binding_ref.as_str() {
        boundary.push(value.to_owned());
    }
    boundary.sort();
    boundary.dedup();
    let mut bound_facts = json!({
        "system_id": source.system_id,
        "operation": plan.operation.as_str(),
        "sequence": plan.operation.sequence(),
        "required_scope": plan.operation.required_scope(),
        "authority_effect_hash": evidence.effect_hash,
        "genesis_ref": source.genesis_ref,
        "genesis_admission_record_root": source.genesis_admission_record_root,
        "genesis_admission_receipt_ref": source.genesis_admission_receipt_ref,
        "genesis_admission_receipt_root": source.genesis_admission_receipt_root,
        "sequence_zero_materialization_id": source.sequence_zero_materialization_ref,
        "sequence_zero_materialization_root": source.sequence_zero_materialization_root,
        "sequence_zero_receipt_ref": source.sequence_zero_receipt_ref,
        "sequence_zero_receipt_root": source.sequence_zero_receipt_root,
        "sequence_zero_receipt_artifact_root": source.sequence_zero_receipt_artifact_root,
        "source_governing_authority_ref": source.source_governing_authority_ref,
        "home_domain_ref": source.home_domain_ref,
        "home_domain_commitment": source.home_domain_commitment,
        "home_domain_binding_ref": home_binding_ref,
        "home_domain_binding_root": home_binding_root,
        "component_registry_ref": source.component_ref,
        "component_registry_root": source.component_root,
        "materialization_wallet_consumption_ref": source.materialization_wallet_consumption_ref,
        "materialization_wallet_consumption_root": source.materialization_wallet_consumption_root,
        "deployment_profile_ref": source.deployment_profile_ref,
        "deployment_profile_root": required_string(&plan.deployment_profile_revision, "/deployment_profile_root")?,
        "profile_bundle_root": source.profile_bundle_root,
    });
    bound_facts
        .as_object_mut()
        .expect("bound facts object")
        .extend(
        json!({
        "policy_root": source.policy_root,
        "module_registry_root": source.module_registry_root,
        "upgrade_policy_ref": source.upgrade_policy_ref,
        "operation_commitment": required_string(&plan.authority_effect, "/operation_commitment")?,
        "proposal_ref": required_string(proposal, "/proposal_ref")?,
        "proposal_root": proposal_root,
        "decision_ref": required_string(decision, "/decision_ref")?,
        "decision_root": decision_root,
        "transition_ref": transition_ref,
        "transition_root": transition_root,
        "predecessor_state_root": transition["predecessor_state_root"],
        "resulting_state_ref": state_ref,
        "resulting_state_root": plan.resulting_state_root,
        "active_profile_set_ref": active_ref,
        "active_profile_set_root": active_root,
        "chain_ref": chain_ref,
        "live_chain_created": plan.operation == SystemLifecycleOperation::Activate,
            })
        .as_object()
        .expect("bound facts continuation object")
        .clone(),
    );
    let (schema_version, receipt_type, receipt_profile_ref, assurance_posture, assurance_note) =
        match plan.operation {
            SystemLifecycleOperation::Initialize => (
                "ioi.lifecycle-transition-receipt.v1",
                "lifecycle_transition",
                SYSTEM_LIFECYCLE_TRANSITION_RECEIPT_CONTRACT,
                "initialized_not_active",
                "sequence one initialized; no live chain, membership, runtime, or network effect exists",
            ),
            SystemLifecycleOperation::Activate => (
                "ioi.autonomous-system-activation-receipt.v1",
                "autonomous_system_activation",
                SYSTEM_ACTIVATION_RECEIPT_CONTRACT,
                "active_chain_created",
                "sequence two admitted constitutional and logical continuity; no membership, runtime, or network effect exists",
            ),
        };
    let receipt = json!({
        "schema_version": schema_version,
        "receipt_id": receipt_ref,
        "receipt_ref": receipt_ref,
        "receipt_type": receipt_type,
        "receipt_profile_ref": receipt_profile_ref,
        "actor_id": "runtime://hypervisor-runtime",
        "subject_ref": transition_ref,
        "op": plan.operation.as_str(),
        "sequence": plan.operation.sequence(),
        "attested_boundary_fact_refs": boundary,
        "bound_facts": bound_facts,
        "input_hash": evidence.input_hash,
        "output_hash": plan.resulting_state_root,
        "policy_hash": evidence.policy_hash,
        "effect_hash": evidence.effect_hash,
        "authority_grant_id": evidence.authority_grant_ref,
        "required_scope": plan.operation.required_scope(),
        "authority_scopes": [plan.operation.required_scope()],
        "authority_evidence_ref": evidence.authority_evidence_ref,
        "authority_evidence_root": evidence.authority_evidence_root,
        "wallet_grant_consumption_ref": evidence.wallet_grant_consumption_ref,
        "wallet_grant_consumption_root": evidence.wallet_grant_consumption_root,
        "wallet_grant_consumption_evidence_ref": evidence.wallet_grant_consumption_evidence_ref,
        "primitive_capabilities": [],
        "artifact_refs": [],
        "evidence_bundle_refs": [],
        "verification_ref": Value::Null,
        "acceptance_ref": Value::Null,
        "claim_scope_ref": Value::Null,
        "run_id": Value::Null,
        "task_id": Value::Null,
        "adjudication_ref": Value::Null,
        "settlement_ref": Value::Null,
        "signature": Value::Null,
        "public_commitment_ref": Value::Null,
        "assurance_posture": assurance_posture,
        "assurance_note": assurance_note,
        "timestamp": timestamp,
        "outcome": "ok",
        "at": timestamp,
    });
    let (contract_id, hash_profile) = match plan.operation {
        SystemLifecycleOperation::Initialize => (
            SYSTEM_LIFECYCLE_TRANSITION_RECEIPT_CONTRACT,
            LIFECYCLE_RECEIPT_ROOT_HASH_PROFILE,
        ),
        SystemLifecycleOperation::Activate => (
            SYSTEM_ACTIVATION_RECEIPT_CONTRACT,
            ACTIVATION_RECEIPT_ROOT_HASH_PROFILE,
        ),
    };
    contract(contract_id, &receipt, "portable lifecycle receipt")?;
    let root = artifact_root(hash_profile, &receipt)?;
    Ok((receipt, root))
}

#[cfg(test)]
fn final_state(
    plan: &CompiledSystemLifecyclePlan,
    transition: &Value,
    transition_root: &str,
    receipt_ref: &str,
    receipt_root: &str,
    timestamp: &str,
) -> Result<Value, String> {
    let mut state = plan.semantic_state.clone();
    state["transition_ref"] = transition["lifecycle_transition_id"].clone();
    state["transition_root"] = Value::String(transition_root.to_owned());
    state["transition_receipt_ref"] = Value::String(receipt_ref.to_owned());
    state["transition_receipt_root"] = Value::String(receipt_root.to_owned());
    state["created_at"] = Value::String(timestamp.to_owned());
    contract(SYSTEM_LIFECYCLE_STATE_CONTRACT, &state, "lifecycle state")?;
    Ok(state)
}

#[cfg(test)]
fn final_active_profile_set(
    plan: &CompiledSystemLifecyclePlan,
    transition: &Value,
    receipt_ref: &str,
    timestamp: &str,
) -> Result<Option<Value>, String> {
    let Some(mut active_set) = plan.semantic_active_profile_set.clone() else {
        return Ok(None);
    };
    active_set["activation_transition_ref"] = transition["lifecycle_transition_id"].clone();
    active_set["activation_receipt_ref"] = Value::String(receipt_ref.to_owned());
    active_set["created_at"] = Value::String(timestamp.to_owned());
    contract(
        SYSTEM_ACTIVE_PROFILE_SET_CONTRACT,
        &active_set,
        "active-profile set",
    )?;
    Ok(Some(active_set))
}

#[cfg(test)]
fn final_home_domain_binding(
    plan: &CompiledSystemLifecyclePlan,
    timestamp: &str,
) -> Result<Option<Value>, String> {
    let Some(mut binding) = plan.semantic_home_domain_binding.clone() else {
        return Ok(None);
    };
    binding["created_at"] = Value::String(timestamp.to_owned());
    contract(
        SYSTEM_HOME_DOMAIN_BINDING_CONTRACT,
        &binding,
        "home-domain binding",
    )?;
    Ok(Some(binding))
}

#[cfg(test)]
fn sequence_zero_log_entry(source: &SourceCoordinates<'_>) -> Result<Value, String> {
    Ok(json!({
        "sequence": 0,
        "entry_kind": "sequence_zero_materialization",
        "operation_name": "materialize_sequence_zero",
        "operation_owner_profile_ref": MATERIALIZATION_CONTRACT,
        "operation_owner_ref": source.sequence_zero_materialization_ref,
        "operation_owner_root": source.sequence_zero_materialization_root,
        "required_scope": "scope:autonomous_system.genesis_materialize",
        "materialization_ref": source.sequence_zero_materialization_ref,
        "materialization_root": source.sequence_zero_materialization_root,
        "deployment_profile_ref": source.deployment_profile_ref,
        "deployment_profile_root": source.deployment_profile_root,
        "operation_commitment": source.sequence_zero_operation_commitment,
        "proposal_ref": Value::Null,
        "proposal_root": Value::Null,
        "decision_ref": Value::Null,
        "decision_root": Value::Null,
        "transition_ref": Value::Null,
        "transition_root": Value::Null,
        "state_transition_commitment_ref": Value::Null,
        "state_ref": Value::Null,
        "state_root": source.sequence_zero_state_root,
        "predecessor_state_root": Value::Null,
        "receipt_profile_ref": CURRENT_MATERIALIZATION_RECEIPT_CONTRACT,
        "receipt_ref": source.sequence_zero_receipt_ref,
        "receipt_root": source.sequence_zero_receipt_root,
        "receipt_artifact_root": source.sequence_zero_receipt_artifact_root,
        "component_registry_ref": source.component_ref,
        "component_registry_root": source.component_root,
        "active_profile_set_ref": Value::Null,
        "active_profile_set_root": Value::Null,
        "chain_ref": Value::Null,
        "authority_evidence_ref": Value::Null,
        "authority_evidence_root": Value::Null,
        "wallet_consumption_ref": source.materialization_wallet_consumption_ref,
        "wallet_consumption_root": source.materialization_wallet_consumption_root,
        "live_chain_created": false,
        "committed_at": required_string(source.materialization, "/created_at")?,
    }))
}

#[cfg(test)]
fn lifecycle_log_entry(
    plan: &CompiledSystemLifecyclePlan,
    step: &UnverifiedCommittedSystemLifecycleStep,
    timestamp: &str,
) -> Result<Value, String> {
    let source = source_coordinates(&plan.source)?;
    let is_activation = plan.operation == SystemLifecycleOperation::Activate;
    Ok(json!({
        "sequence": plan.operation.sequence(),
        "entry_kind": if is_activation { "system_activation" } else { "system_initialization" },
        "operation_name": plan.operation.as_str(),
        "operation_owner_profile_ref": LIFECYCLE_TRANSITION_CONTRACT,
        "operation_owner_ref": required_string(&step.transition, "/lifecycle_transition_id")?,
        "operation_owner_root": step.transition_root,
        "required_scope": plan.operation.required_scope(),
        "materialization_ref": Value::Null,
        "materialization_root": Value::Null,
        "deployment_profile_ref": source.deployment_profile_ref,
        "deployment_profile_root": source.deployment_profile_root,
        "operation_commitment": required_string(&plan.authority_effect, "/operation_commitment")?,
        "proposal_ref": required_string(&step.proposal, "/proposal_ref")?,
        "proposal_root": step.proposal_root,
        "decision_ref": required_string(&step.decision, "/decision_ref")?,
        "decision_root": step.decision_root,
        "transition_ref": required_string(&step.transition, "/lifecycle_transition_id")?,
        "transition_root": step.transition_root,
        "state_transition_commitment_ref": Value::Null,
        "state_ref": required_string(&step.state, "/activation_state_ref")?,
        "state_root": step.state_root,
        "predecessor_state_root": required_string(&step.transition, "/predecessor_state_root")?,
        "receipt_profile_ref": if is_activation {
            SYSTEM_ACTIVATION_RECEIPT_CONTRACT
        } else {
            SYSTEM_LIFECYCLE_TRANSITION_RECEIPT_CONTRACT
        },
        "receipt_ref": required_string(&step.receipt, "/receipt_ref")?,
        "receipt_root": step.receipt_root,
        "receipt_artifact_root": step.receipt_root,
        "component_registry_ref": source.component_ref,
        "component_registry_root": source.component_root,
        "active_profile_set_ref": if is_activation {
            step.receipt["bound_facts"]["active_profile_set_ref"].clone()
        } else {
            Value::Null
        },
        "active_profile_set_root": if is_activation {
            step.receipt["bound_facts"]["active_profile_set_root"].clone()
        } else {
            Value::Null
        },
        "chain_ref": if is_activation {
            step.receipt["bound_facts"]["chain_ref"].clone()
        } else {
            Value::Null
        },
        "authority_evidence_ref": required_string(&step.decision, "/authority_evidence_ref")?,
        "authority_evidence_root": required_string(&step.decision, "/authority_evidence_root")?,
        "wallet_consumption_ref": required_string(&step.decision, "/wallet_grant_consumption_ref")?,
        "wallet_consumption_root": required_string(&step.decision, "/wallet_grant_consumption_root")?,
        "live_chain_created": is_activation,
        "committed_at": timestamp,
    }))
}

#[cfg(test)]
fn operation_log_root(log: &Value) -> Result<String, String> {
    let mut material = log
        .as_object()
        .cloned()
        .ok_or_else(|| "operation log is not an object".to_owned())?;
    material.remove("schema_version");
    material.remove("operation_log_ref");
    material.remove("operation_log_root");
    material.insert(
        "domain".to_owned(),
        Value::String(SYSTEM_OPERATION_LOG_HASH_PROFILE.to_owned()),
    );
    jcs_hash(&Value::Object(material))
}

#[cfg(test)]
fn final_operation_log(
    plan: &CompiledSystemLifecyclePlan,
    step: &UnverifiedCommittedSystemLifecycleStep,
    home_binding: &Value,
    timestamp: &str,
) -> Result<Option<Value>, String> {
    if plan.operation != SystemLifecycleOperation::Activate {
        return Ok(None);
    }
    let source = source_coordinates(&plan.source)?;
    let initialized = plan
        .previous_step
        .as_ref()
        .ok_or_else(|| "activation lacks initialized predecessor".to_owned())?;
    let sequence_zero = sequence_zero_log_entry(&source)?;
    let initialize_plan =
        compile_system_initialize_plan(&plan.source, &plan.deployment_profile_revision)?;
    let sequence_one = lifecycle_log_entry(
        &initialize_plan,
        initialized,
        required_string(&initialized.decision, "/decided_at")?,
    )?;
    let sequence_two = lifecycle_log_entry(plan, step, timestamp)?;
    let mut log = json!({
        "schema_version": "ioi.autonomous-system-operation-log.v1",
        "operation_log_ref": Value::Null,
        "operation_log_root": Value::Null,
        "predecessor_operation_log_ref": Value::Null,
        "predecessor_operation_log_root": Value::Null,
        "snapshot_kind": "activation_prefix",
        "system_id": source.system_id,
        "genesis_ref": source.genesis_ref,
        "home_domain_ref": source.home_domain_ref,
        "home_domain_commitment": source.home_domain_commitment,
        "home_domain_binding_ref": required_string(home_binding, "/home_domain_binding_ref")?,
        "home_domain_binding_root": required_string(home_binding, "/home_domain_binding_root")?,
        "policy_root": source.policy_root,
        "module_registry_root": source.module_registry_root,
        "upgrade_policy_ref": source.upgrade_policy_ref,
        "activation_prefix": {
            "sequence_zero": sequence_zero,
            "sequence_one": sequence_one,
            "sequence_two": sequence_two,
        },
        "entries": [sequence_zero, sequence_one, sequence_two],
        "head_entry": sequence_two,
        "latest_sequence": 2,
        "latest_operation_commitment": required_string(&plan.authority_effect, "/operation_commitment")?,
        "latest_transition_commitment_ref": Value::Null,
        "latest_transition_ref": required_string(&step.transition, "/lifecycle_transition_id")?,
        "latest_transition_root": step.transition_root,
        "latest_receipt_ref": required_string(&step.receipt, "/receipt_ref")?,
        "latest_receipt_root": step.receipt_root,
        "latest_state_ref": required_string(&step.state, "/activation_state_ref")?,
        "latest_state_root": step.state_root,
        "status": "committed",
        "created_at": timestamp,
    });
    let root = operation_log_root(&log)?;
    log["operation_log_ref"] = Value::String(format!(
        "agentgres://operation-log/autonomous-system/{}/revision/{root}",
        namespace(source.system_id)?
    ));
    log["operation_log_root"] = Value::String(root);
    contract(SYSTEM_OPERATION_LOG_CONTRACT, &log, "System operation log")?;
    Ok(Some(log))
}

#[cfg(test)]
fn chain_root(chain: &Value) -> Result<String, String> {
    let mut material = chain
        .as_object()
        .cloned()
        .ok_or_else(|| "chain is not an object".to_owned())?;
    material.remove("schema_version");
    material.remove("chain_root");
    material.remove("created_at");
    material.insert(
        "domain".to_owned(),
        Value::String(SYSTEM_CHAIN_HASH_PROFILE.to_owned()),
    );
    jcs_hash(&Value::Object(material))
}

#[cfg(test)]
fn final_chain(
    plan: &CompiledSystemLifecyclePlan,
    step: &UnverifiedCommittedSystemLifecycleStep,
    active_set: &Value,
    home_binding: &Value,
    operation_log: &Value,
    timestamp: &str,
) -> Result<Option<Value>, String> {
    if plan.operation != SystemLifecycleOperation::Activate {
        return Ok(None);
    }
    let source = source_coordinates(&plan.source)?;
    let active = |pointer: &str| required_string(active_set, pointer);
    let oracle_refs = active_set
        .get("oracle_evidence_profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| "active profile set oracle admissions are not an array".to_owned())?
        .iter()
        .map(|entry| required_string(entry, "/candidate_profile_ref").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let network_ref = active_set
        .get("network_enrollment")
        .and_then(|value| (!value.is_null()).then_some(value))
        .map(|value| required_string(value, "/candidate_profile_ref").map(str::to_owned))
        .transpose()?;
    let node_membership_refs = json!([]);
    let node_membership_root = jcs_hash(&json!({
        "domain": SYSTEM_MEMBERSHIP_ROOT_HASH_PROFILE,
        "node_membership_refs": node_membership_refs,
    }))?;
    let pending_proposal_refs = json!([]);
    let proposal_queue_root = jcs_hash(&json!({
        "domain": SYSTEM_PROPOSAL_QUEUE_ROOT_HASH_PROFILE,
        "pending_proposal_refs": pending_proposal_refs,
    }))?;
    let chain_ref = format!("autonomous-system-chain://{}", namespace(source.system_id)?);
    let mut chain = json!({
        "schema_version": "ioi.autonomous-system-chain.v1",
        "chain_ref": chain_ref,
        "chain_root": Value::Null,
        "system_id": source.system_id,
        "home_domain_ref": source.home_domain_ref,
        "home_domain_binding_ref": required_string(home_binding, "/home_domain_binding_ref")?,
        "home_domain_binding_root": required_string(home_binding, "/home_domain_binding_root")?,
        "governance_owner_refs": source.constitution["governance"]["governance_owner_refs"],
        "genesis_ref": source.genesis_ref,
        "genesis_admission_record_root": source.genesis_admission_record_root,
        "package_id": source.package_id,
        "manifest_ref": source.manifest_ref,
        "admitted_manifest_root": source.admitted_manifest_root,
        "constitution_ref": active("/constitution/candidate_profile_ref")?,
        "constitution_root": active("/constitution/candidate_profile_root")?,
        "deployment_profile_ref": active("/deployment/candidate_profile_ref")?,
        "deployment_profile_root": active("/deployment/candidate_profile_root")?,
        "ordering_admission_finality_profile_ref": active("/ordering_admission_finality/candidate_profile_ref")?,
        "oracle_evidence_profile_refs": oracle_refs,
        "lifecycle_continuity_profile_ref": active("/lifecycle_continuity/candidate_profile_ref")?,
        "network_enrollment_ref": network_ref,
        "active_profile_set_ref": active("/active_profile_set_ref")?,
        "active_profile_set_root": active("/active_profile_set_root")?,
        "node_membership_refs": node_membership_refs,
        "node_membership_root": node_membership_root,
        "active_writer_epoch": Value::Null,
        "latest_sequence": 2,
        "latest_operation_commitment": required_string(&plan.authority_effect, "/operation_commitment")?,
        "latest_transition_commitment_ref": Value::Null,
    });
    let object = chain
        .as_object_mut()
        .ok_or_else(|| "chain constructor did not produce an object".to_owned())?;
    object.extend(
        json!({
        "latest_transition_id": required_string(&step.transition, "/lifecycle_transition_id")?,
        "latest_transition_root": step.transition_root,
        "latest_receipt_ref": required_string(&step.receipt, "/receipt_ref")?,
        "latest_receipt_root": step.receipt_root,
        "latest_state_ref": required_string(&step.state, "/activation_state_ref")?,
        "latest_state_root": step.state_root,
        "worker_instance_refs": [],
        "workflow_refs": [],
        "active_component_registry_ref": source.component_ref,
        "active_component_registry_root": source.component_root,
        "policy_root": source.policy_root,
        "module_registry_root": source.module_registry_root,
        "pending_proposal_refs": pending_proposal_refs,
        "proposal_queue_root": proposal_queue_root,
        "operation_log_ref": required_string(operation_log, "/operation_log_ref")?,
        "operation_log_root": required_string(operation_log, "/operation_log_root")?,
        "upgrade_policy_ref": source.upgrade_policy_ref,
        "settlement_policy_ref": Value::Null,
        "default_settlement_mode": Value::Null,
        "allowed_settlement_modes": [],
        "settlement_profile_refs": [],
        "public_commitment_policy_ref": Value::Null,
        "status": "active",
        "created_at": timestamp,
        })
        .as_object()
        .cloned()
        .ok_or_else(|| "chain continuation did not produce an object".to_owned())?,
    );
    chain["chain_root"] = Value::String(chain_root(&chain)?);
    contract(SYSTEM_CHAIN_CONTRACT, &chain, "autonomous System chain")?;
    validate_chain_against_operation_log(&chain, operation_log)?;
    Ok(Some(chain))
}

#[cfg(test)]
fn validate_chain_against_operation_log(chain: &Value, log: &Value) -> Result<(), String> {
    contract(SYSTEM_CHAIN_CONTRACT, chain, "autonomous System chain")?;
    contract(SYSTEM_OPERATION_LOG_CONTRACT, log, "System operation log")?;
    for pointer in [
        "/system_id",
        "/genesis_ref",
        "/home_domain_ref",
        "/home_domain_binding_ref",
        "/home_domain_binding_root",
        "/policy_root",
        "/module_registry_root",
        "/upgrade_policy_ref",
    ] {
        if chain.pointer(pointer) != log.pointer(pointer) {
            return Err(format!(
                "chain detaches operation-log intrinsic header {pointer}"
            ));
        }
    }
    for (chain_pointer, log_pointer) in [
        ("/operation_log_ref", "/operation_log_ref"),
        ("/operation_log_root", "/operation_log_root"),
        ("/latest_sequence", "/latest_sequence"),
        (
            "/latest_operation_commitment",
            "/latest_operation_commitment",
        ),
        (
            "/latest_transition_commitment_ref",
            "/latest_transition_commitment_ref",
        ),
        ("/latest_transition_id", "/latest_transition_ref"),
        ("/latest_transition_root", "/latest_transition_root"),
        ("/latest_receipt_ref", "/latest_receipt_ref"),
        ("/latest_receipt_root", "/latest_receipt_root"),
        ("/latest_state_ref", "/latest_state_ref"),
        ("/latest_state_root", "/latest_state_root"),
    ] {
        if chain.pointer(chain_pointer) != log.pointer(log_pointer) {
            return Err(format!(
                "chain {chain_pointer} detaches operation log {log_pointer}"
            ));
        }
    }
    let entries = log
        .pointer("/entries")
        .and_then(Value::as_array)
        .ok_or_else(|| "activation operation log lacks entries".to_owned())?;
    if log.pointer("/snapshot_kind") != Some(&json!("activation_prefix"))
        || entries.len() != 3
        || entries[0].pointer("/sequence") != Some(&json!(0))
        || entries[1].pointer("/sequence") != Some(&json!(1))
        || entries[2].pointer("/sequence") != Some(&json!(2))
        || log.pointer("/activation_prefix/sequence_zero") != Some(&entries[0])
        || log.pointer("/activation_prefix/sequence_one") != Some(&entries[1])
        || log.pointer("/activation_prefix/sequence_two") != Some(&entries[2])
        || log.pointer("/head_entry") != Some(&entries[2])
        || log.pointer("/latest_sequence") != Some(&json!(2))
    {
        return Err("M1.5a chain requires the exact terminal 0/1/2 activation prefix".to_owned());
    }
    let head = &entries[2];
    for (log_pointer, head_pointer) in [
        ("/latest_operation_commitment", "/operation_commitment"),
        (
            "/latest_transition_commitment_ref",
            "/state_transition_commitment_ref",
        ),
        ("/latest_transition_ref", "/transition_ref"),
        ("/latest_transition_root", "/transition_root"),
        ("/latest_receipt_ref", "/receipt_ref"),
        ("/latest_receipt_root", "/receipt_root"),
        ("/latest_state_ref", "/state_ref"),
        ("/latest_state_root", "/state_root"),
    ] {
        if log.pointer(log_pointer) != head.pointer(head_pointer) {
            return Err(format!(
                "operation-log head detaches terminal entry at {log_pointer}"
            ));
        }
    }
    for (chain_pointer, head_pointer) in [
        ("/active_component_registry_ref", "/component_registry_ref"),
        (
            "/active_component_registry_root",
            "/component_registry_root",
        ),
        ("/active_profile_set_ref", "/active_profile_set_ref"),
        ("/active_profile_set_root", "/active_profile_set_root"),
    ] {
        if chain.pointer(chain_pointer) != head.pointer(head_pointer) {
            return Err(format!("chain detaches activation head at {chain_pointer}"));
        }
    }
    Ok(())
}

/// Finalize one authorized plan into its exact durable artifacts.
#[cfg(test)]
fn finalize_system_lifecycle_plan(
    plan: &CompiledSystemLifecyclePlan,
    evidence: &SystemLifecycleAuthorityEvidence,
    timestamp: &str,
) -> Result<FinalizedSystemLifecycleArtifacts, String> {
    let reconstructed = match plan.operation {
        SystemLifecycleOperation::Initialize => {
            compile_system_initialize_plan(&plan.source, &plan.deployment_profile_revision)?
        }
        SystemLifecycleOperation::Activate => compile_system_activate_plan(
            &plan.source,
            &plan.deployment_profile_revision,
            plan.previous_step
                .as_ref()
                .ok_or_else(|| "activation plan lacks initialized predecessor".to_owned())?,
        )?,
    };
    if reconstructed != *plan {
        return Err("lifecycle plan does not byte-match server-derived reconstruction".to_owned());
    }
    if evidence.authorized_effect != plan.authority_effect {
        return Err("governed authority evidence does not bind the compiled effect".to_owned());
    }
    for (label, hash) in [
        ("input_hash", evidence.input_hash.as_str()),
        ("policy_hash", evidence.policy_hash.as_str()),
        ("effect_hash", evidence.effect_hash.as_str()),
        (
            "authority_evidence_root",
            evidence.authority_evidence_root.as_str(),
        ),
        (
            "wallet_grant_consumption_root",
            evidence.wallet_grant_consumption_root.as_str(),
        ),
    ] {
        if !canonical_hash(hash) {
            return Err(format!("{label} is not a canonical sha256 ref"));
        }
    }
    let expected_effect_hash = unverified_system_lifecycle_effect_hash(&plan.authority_effect)?;
    if evidence.effect_hash != expected_effect_hash {
        return Err(
            "governed authority evidence effect hash does not bind the compiled effect".to_owned(),
        );
    }
    let receipt_ref = deterministic_receipt_ref(
        required_string(&plan.source.materialization, "/system_id")?,
        plan.operation,
    )?;
    let (proposal, proposal_root) = lifecycle_proposal(plan, evidence, timestamp)?;
    let (decision, decision_root) =
        lifecycle_authority_decision(plan, evidence, &proposal, &proposal_root, timestamp)?;
    let (transition, transition_root) =
        committed_transition(plan, evidence, &proposal, &decision, &receipt_ref)?;
    let (receipt, receipt_root) = portable_receipt(
        plan,
        evidence,
        &proposal,
        &proposal_root,
        &decision,
        &decision_root,
        &transition,
        &transition_root,
        &receipt_ref,
        timestamp,
    )?;
    let state = final_state(
        plan,
        &transition,
        &transition_root,
        &receipt_ref,
        &receipt_root,
        timestamp,
    )?;
    let step = UnverifiedCommittedSystemLifecycleStep {
        proposal,
        decision,
        state,
        transition,
        receipt,
        state_root: plan.resulting_state_root.clone(),
        proposal_root,
        decision_root,
        transition_root,
        receipt_root,
    };
    let predecessor_root = match &plan.previous_step {
        Some(previous) => previous.state_root.as_str(),
        None => required_string(&plan.source.materialization, "/initial_state_root")?,
    };
    validate_committed_step(&step, plan.operation, predecessor_root)?;
    let active_profile_set =
        final_active_profile_set(plan, &step.transition, &receipt_ref, timestamp)?;
    let home_domain_binding = final_home_domain_binding(plan, timestamp)?;
    let operation_log = match home_domain_binding.as_ref() {
        Some(binding) => final_operation_log(plan, &step, binding, timestamp)?,
        None => None,
    };
    let chain = match (
        active_profile_set.as_ref(),
        home_domain_binding.as_ref(),
        operation_log.as_ref(),
    ) {
        (Some(active_set), Some(binding), Some(log)) => {
            final_chain(plan, &step, active_set, binding, log, timestamp)?
        }
        (None, None, None) => None,
        _ => return Err("activation finalization produced a partial live-chain tuple".to_owned()),
    };
    Ok(FinalizedSystemLifecycleArtifacts {
        step,
        active_profile_set,
        home_domain_binding,
        operation_log,
        chain,
    })
}

fn proposal_root_from_artifact(proposal: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": LIFECYCLE_PROPOSAL_HASH_PROFILE,
        "proposal_ref": proposal.get("proposal_ref"),
        "system_id": proposal.get("system_id"),
        "genesis_ref": proposal.get("genesis_ref"),
        "operation": proposal.get("operation"),
        "sequence": proposal.get("sequence"),
        "required_scope": proposal.get("required_scope"),
        "operation_commitment": proposal.get("operation_commitment"),
        "authority_effect": proposal.get("authority_effect"),
        "authority_effect_hash": proposal.get("authority_effect_hash"),
        "status": proposal.get("status"),
        "created_at": proposal.get("created_at"),
    }))
}

fn decision_root_from_artifact(decision: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": LIFECYCLE_AUTHORITY_DECISION_HASH_PROFILE,
        "decision_ref": decision.get("decision_ref"),
        "proposal_ref": decision.get("proposal_ref"),
        "proposal_root": decision.get("proposal_root"),
        "system_id": decision.get("system_id"),
        "genesis_ref": decision.get("genesis_ref"),
        "operation": decision.get("operation"),
        "sequence": decision.get("sequence"),
        "required_scope": decision.get("required_scope"),
        "operation_commitment": decision.get("operation_commitment"),
        "input_hash": decision.get("input_hash"),
        "policy_hash": decision.get("policy_hash"),
        "effect_hash": decision.get("effect_hash"),
        "authority_grant_ref": decision.get("authority_grant_ref"),
        "authority_evidence_ref": decision.get("authority_evidence_ref"),
        "authority_evidence_root": decision.get("authority_evidence_root"),
        "wallet_grant_consumption_ref": decision.get("wallet_grant_consumption_ref"),
        "wallet_grant_consumption_root": decision.get("wallet_grant_consumption_root"),
        "wallet_grant_consumption_evidence_ref": decision.get("wallet_grant_consumption_evidence_ref"),
        "outcome": decision.get("outcome"),
        "decided_at": decision.get("decided_at"),
    }))
}

fn activation_state_root_from_artifact(state: &Value) -> Result<String, String> {
    let field = |name: &str| {
        state
            .get(name)
            .cloned()
            .ok_or_else(|| format!("activation state lacks {name}"))
    };
    jcs_hash(&json!({
        "domain": LIFECYCLE_STATE_HASH_PROFILE,
        "activation_state_ref": field("activation_state_ref")?,
        "system_id": field("system_id")?,
        "genesis_ref": field("genesis_ref")?,
        "manifest_ref": field("manifest_ref")?,
        "admitted_manifest_root": field("admitted_manifest_root")?,
        "lifecycle_profile_ref": field("lifecycle_profile_ref")?,
        "sequence": field("sequence")?,
        "status": field("status")?,
        "predecessor_state_root": field("predecessor_state_root")?,
        "active_profile_set_ref": field("active_profile_set_ref")?,
        "active_profile_set_root": field("active_profile_set_root")?,
        "live_chain_created": field("live_chain_created")?,
        "node_membership_refs": field("node_membership_refs")?,
        "runtime_effect_admitted": field("runtime_effect_admitted")?,
        "network_effect_admitted": field("network_effect_admitted")?,
    }))
}

/// Validate one committed step and recompute every acyclic artifact root.
fn validate_committed_step(
    step: &UnverifiedCommittedSystemLifecycleStep,
    operation: SystemLifecycleOperation,
    expected_predecessor_state_root: &str,
) -> Result<(), String> {
    contract(
        SYSTEM_LIFECYCLE_PROPOSAL_CONTRACT,
        &step.proposal,
        "lifecycle proposal",
    )?;
    contract(
        SYSTEM_LIFECYCLE_AUTHORITY_DECISION_CONTRACT,
        &step.decision,
        "lifecycle authority decision",
    )?;
    contract(
        SYSTEM_LIFECYCLE_STATE_CONTRACT,
        &step.state,
        "lifecycle state",
    )?;
    contract(
        LIFECYCLE_TRANSITION_CONTRACT,
        &step.transition,
        "lifecycle transition",
    )?;
    let (receipt_contract, receipt_hash_profile) = match operation {
        SystemLifecycleOperation::Initialize => (
            SYSTEM_LIFECYCLE_TRANSITION_RECEIPT_CONTRACT,
            LIFECYCLE_RECEIPT_ROOT_HASH_PROFILE,
        ),
        SystemLifecycleOperation::Activate => (
            SYSTEM_ACTIVATION_RECEIPT_CONTRACT,
            ACTIVATION_RECEIPT_ROOT_HASH_PROFILE,
        ),
    };
    contract(receipt_contract, &step.receipt, "lifecycle receipt")?;
    let proposal_ref = required_string(&step.proposal, "/proposal_ref")?;
    let decision_ref = required_string(&step.decision, "/decision_ref")?;
    let transition_ref = required_string(&step.transition, "/lifecycle_transition_id")?;
    let receipt_ref = required_string(&step.receipt, "/receipt_ref")?;
    let state_ref = required_string(&step.state, "/activation_state_ref")?;
    let system_id = required_string(&step.state, "/system_id")?;
    let genesis_ref = required_string(&step.state, "/genesis_ref")?;
    let proposal_root = proposal_root_from_artifact(&step.proposal)?;
    let decision_root = decision_root_from_artifact(&step.decision)?;
    let transition_root = artifact_root(LIFECYCLE_TRANSITION_HASH_PROFILE, &step.transition)?;
    let receipt_root = artifact_root(receipt_hash_profile, &step.receipt)?;
    let recomputed_state_root = activation_state_root_from_artifact(&step.state)?;
    let expected_state_ref_value = format!(
        "system-activation-state://{}/sequence/{}",
        namespace(system_id)?,
        operation.sequence()
    );
    if state_ref != expected_state_ref_value {
        return Err(
            "activation state ref is not the deterministic System/sequence identity".to_owned(),
        );
    }
    let authority_effect = step
        .proposal
        .get("authority_effect")
        .ok_or_else(|| "lifecycle proposal lacks authority_effect".to_owned())?;
    let operation_commitment = operation_commitment_from_effect(authority_effect)?;
    let unverified_effect_hash = unverified_system_lifecycle_effect_hash(authority_effect)?;
    let expect = |value: &Value, pointer: &str, expected: &Value, label: &str| {
        if value.pointer(pointer) != Some(expected) {
            Err(format!("committed lifecycle tuple detached at {label}"))
        } else {
            Ok(())
        }
    };
    let expected_sequence = json!(operation.sequence());
    let expected_operation = json!(operation.as_str());
    let expected_scope = json!(operation.required_scope());
    let expected_predecessor = json!(expected_predecessor_state_root);
    let expected_state_root = json!(recomputed_state_root.clone());
    let expected_proposal_ref = json!(proposal_ref);
    let expected_proposal_root = json!(proposal_root);
    let expected_decision_ref = json!(decision_ref);
    let expected_decision_root = json!(decision_root);
    let expected_transition_ref = json!(transition_ref);
    let expected_transition_root = json!(transition_root);
    let expected_receipt_ref = json!(receipt_ref);
    let expected_receipt_root = json!(receipt_root);
    let expected_state_ref = json!(state_ref);
    let expected_system = json!(system_id);
    let expected_genesis = json!(genesis_ref);
    let expected_operation_commitment = json!(operation_commitment);
    let expected_effect_hash = json!(unverified_effect_hash);
    let expected_authority_grant = step
        .decision
        .get("authority_grant_ref")
        .cloned()
        .ok_or_else(|| "unverified decision lacks authority_grant_ref".to_owned())?;
    let expected_authority_evidence_ref = step
        .decision
        .get("authority_evidence_ref")
        .cloned()
        .ok_or_else(|| "unverified decision lacks authority_evidence_ref".to_owned())?;
    let expected_authority_evidence_root = step
        .decision
        .get("authority_evidence_root")
        .cloned()
        .ok_or_else(|| "unverified decision lacks authority_evidence_root".to_owned())?;
    let expected_wallet_consumption_ref = step
        .decision
        .get("wallet_grant_consumption_ref")
        .cloned()
        .ok_or_else(|| "unverified decision lacks wallet_grant_consumption_ref".to_owned())?;
    let expected_wallet_consumption_root = step
        .decision
        .get("wallet_grant_consumption_root")
        .cloned()
        .ok_or_else(|| "unverified decision lacks wallet_grant_consumption_root".to_owned())?;
    let expected_wallet_consumption_evidence_ref = step
        .decision
        .get("wallet_grant_consumption_evidence_ref")
        .cloned()
        .ok_or_else(|| {
            "unverified decision lacks wallet_grant_consumption_evidence_ref".to_owned()
        })?;

    for (actual, expected, label) in [
        (
            step.proposal_root.as_str(),
            proposal_root.as_str(),
            "proposal root",
        ),
        (
            step.decision_root.as_str(),
            decision_root.as_str(),
            "decision root",
        ),
        (
            step.transition_root.as_str(),
            transition_root.as_str(),
            "transition root",
        ),
        (
            step.receipt_root.as_str(),
            receipt_root.as_str(),
            "receipt root",
        ),
        (
            required_string(&step.state, "/activation_state_root")?,
            recomputed_state_root.as_str(),
            "state root",
        ),
        (
            step.state_root.as_str(),
            recomputed_state_root.as_str(),
            "retained state root",
        ),
    ] {
        if actual != expected {
            return Err(format!("committed lifecycle artifact mismatch at {label}"));
        }
    }

    for (value, pointer, expected, label) in [
        (
            &step.proposal,
            "/proposal_root",
            &expected_proposal_root,
            "proposal.root",
        ),
        (
            &step.proposal,
            "/system_id",
            &expected_system,
            "proposal.system",
        ),
        (
            &step.proposal,
            "/genesis_ref",
            &expected_genesis,
            "proposal.genesis",
        ),
        (
            &step.proposal,
            "/operation",
            &expected_operation,
            "proposal.operation",
        ),
        (
            &step.proposal,
            "/sequence",
            &expected_sequence,
            "proposal.sequence",
        ),
        (
            &step.proposal,
            "/required_scope",
            &expected_scope,
            "proposal.scope",
        ),
        (
            &step.proposal,
            "/operation_commitment",
            &expected_operation_commitment,
            "proposal.operation_commitment",
        ),
        (
            &step.proposal,
            "/authority_effect/system_id",
            &expected_system,
            "effect.system",
        ),
        (
            &step.proposal,
            "/authority_effect/genesis_ref",
            &expected_genesis,
            "effect.genesis",
        ),
        (
            &step.proposal,
            "/authority_effect/operation",
            &expected_operation,
            "effect.operation",
        ),
        (
            &step.proposal,
            "/authority_effect/sequence",
            &expected_sequence,
            "effect.sequence",
        ),
        (
            &step.proposal,
            "/authority_effect/required_scope",
            &expected_scope,
            "effect.scope",
        ),
        (
            &step.proposal,
            "/authority_effect/operation_commitment",
            &expected_operation_commitment,
            "effect.operation_commitment",
        ),
        (
            &step.proposal,
            "/authority_effect/predecessor_state_root",
            &expected_predecessor,
            "effect.predecessor",
        ),
        (
            &step.proposal,
            "/authority_effect/resulting_state_ref",
            &expected_state_ref,
            "effect.state_ref",
        ),
        (
            &step.proposal,
            "/authority_effect/resulting_state_root",
            &expected_state_root,
            "effect.state_root",
        ),
        (
            &step.decision,
            "/decision_root",
            &expected_decision_root,
            "decision.root",
        ),
        (
            &step.decision,
            "/proposal_ref",
            &expected_proposal_ref,
            "decision.proposal_ref",
        ),
        (
            &step.decision,
            "/proposal_root",
            &expected_proposal_root,
            "decision.proposal_root",
        ),
        (
            &step.decision,
            "/system_id",
            &expected_system,
            "decision.system",
        ),
        (
            &step.decision,
            "/genesis_ref",
            &expected_genesis,
            "decision.genesis",
        ),
        (
            &step.decision,
            "/operation",
            &expected_operation,
            "decision.operation",
        ),
        (
            &step.decision,
            "/sequence",
            &expected_sequence,
            "decision.sequence",
        ),
        (
            &step.decision,
            "/required_scope",
            &expected_scope,
            "decision.scope",
        ),
        (
            &step.decision,
            "/operation_commitment",
            &expected_operation_commitment,
            "decision.operation_commitment",
        ),
        (
            &step.decision,
            "/effect_hash",
            &expected_effect_hash,
            "decision.effect_hash",
        ),
        (
            &step.state,
            "/sequence",
            &expected_sequence,
            "state.sequence",
        ),
        (
            &step.state,
            "/predecessor_state_root",
            &expected_predecessor,
            "state.predecessor",
        ),
        (
            &step.state,
            "/transition_ref",
            &expected_transition_ref,
            "state.transition_ref",
        ),
        (
            &step.state,
            "/transition_root",
            &expected_transition_root,
            "state.transition_root",
        ),
        (
            &step.state,
            "/transition_receipt_ref",
            &expected_receipt_ref,
            "state.receipt_ref",
        ),
        (
            &step.state,
            "/transition_receipt_root",
            &expected_receipt_root,
            "state.receipt_root",
        ),
        (
            &step.transition,
            "/system_id",
            &expected_system,
            "transition.system",
        ),
        (
            &step.transition,
            "/genesis_ref",
            &expected_genesis,
            "transition.genesis",
        ),
        (
            &step.transition,
            "/transition_kind",
            &expected_operation,
            "transition.operation",
        ),
        (
            &step.transition,
            "/operation_commitment",
            &expected_operation_commitment,
            "transition.operation_commitment",
        ),
        (
            &step.transition,
            "/manifest_ref",
            &step.state["manifest_ref"],
            "transition.manifest",
        ),
        (
            &step.transition,
            "/admitted_manifest_root",
            &step.state["admitted_manifest_root"],
            "transition.manifest_root",
        ),
        (
            &step.transition,
            "/lifecycle_profile_ref",
            &step.state["lifecycle_profile_ref"],
            "transition.lifecycle_profile",
        ),
        (
            &step.transition,
            "/proposal_ref",
            &expected_proposal_ref,
            "transition.proposal_ref",
        ),
        (
            &step.transition,
            "/decision_ref",
            &expected_decision_ref,
            "transition.decision_ref",
        ),
        (
            &step.transition,
            "/predecessor_state_root",
            &expected_predecessor,
            "transition.predecessor",
        ),
        (
            &step.transition,
            "/resulting_state_root",
            &expected_state_root,
            "transition.state_root",
        ),
        (
            &step.receipt,
            "/subject_ref",
            &expected_transition_ref,
            "receipt.subject",
        ),
        (
            &step.receipt,
            "/op",
            &expected_operation,
            "receipt.operation",
        ),
        (
            &step.receipt,
            "/sequence",
            &expected_sequence,
            "receipt.sequence",
        ),
        (
            &step.receipt,
            "/required_scope",
            &expected_scope,
            "receipt.scope",
        ),
        (
            &step.receipt,
            "/effect_hash",
            &expected_effect_hash,
            "receipt.effect_hash",
        ),
        (
            &step.receipt,
            "/output_hash",
            &expected_state_root,
            "receipt.output",
        ),
        (
            &step.receipt,
            "/bound_facts/system_id",
            &expected_system,
            "receipt.system",
        ),
        (
            &step.receipt,
            "/bound_facts/operation",
            &expected_operation,
            "receipt.bound_operation",
        ),
        (
            &step.receipt,
            "/bound_facts/sequence",
            &expected_sequence,
            "receipt.bound_sequence",
        ),
        (
            &step.receipt,
            "/bound_facts/required_scope",
            &expected_scope,
            "receipt.bound_scope",
        ),
        (
            &step.receipt,
            "/bound_facts/authority_effect_hash",
            &expected_effect_hash,
            "receipt.bound_effect_hash",
        ),
        (
            &step.receipt,
            "/bound_facts/genesis_ref",
            &expected_genesis,
            "receipt.genesis",
        ),
        (
            &step.receipt,
            "/bound_facts/proposal_ref",
            &expected_proposal_ref,
            "receipt.proposal_ref",
        ),
        (
            &step.receipt,
            "/bound_facts/proposal_root",
            &expected_proposal_root,
            "receipt.proposal_root",
        ),
        (
            &step.receipt,
            "/bound_facts/decision_ref",
            &expected_decision_ref,
            "receipt.decision_ref",
        ),
        (
            &step.receipt,
            "/bound_facts/decision_root",
            &expected_decision_root,
            "receipt.decision_root",
        ),
        (
            &step.receipt,
            "/bound_facts/transition_ref",
            &expected_transition_ref,
            "receipt.transition_ref",
        ),
        (
            &step.receipt,
            "/bound_facts/transition_root",
            &expected_transition_root,
            "receipt.transition_root",
        ),
        (
            &step.receipt,
            "/bound_facts/predecessor_state_root",
            &expected_predecessor,
            "receipt.predecessor",
        ),
        (
            &step.receipt,
            "/bound_facts/resulting_state_ref",
            &expected_state_ref,
            "receipt.state_ref",
        ),
        (
            &step.receipt,
            "/bound_facts/resulting_state_root",
            &expected_state_root,
            "receipt.state_root",
        ),
        (
            &step.receipt,
            "/bound_facts/operation_commitment",
            &expected_operation_commitment,
            "receipt.operation_commitment",
        ),
        (
            &step.receipt,
            "/authority_evidence_ref",
            &expected_authority_evidence_ref,
            "receipt.authority_evidence_ref",
        ),
        (
            &step.receipt,
            "/authority_evidence_root",
            &expected_authority_evidence_root,
            "receipt.authority_evidence_root",
        ),
        (
            &step.receipt,
            "/wallet_grant_consumption_ref",
            &expected_wallet_consumption_ref,
            "receipt.wallet_consumption_ref",
        ),
        (
            &step.receipt,
            "/wallet_grant_consumption_root",
            &expected_wallet_consumption_root,
            "receipt.wallet_consumption_root",
        ),
        (
            &step.receipt,
            "/wallet_grant_consumption_evidence_ref",
            &expected_wallet_consumption_evidence_ref,
            "receipt.wallet_consumption_evidence_ref",
        ),
    ] {
        expect(value, pointer, expected, label)?;
    }
    if step.transition.pointer("/receipt_refs") != Some(&json!([receipt_ref]))
        || step.receipt.pointer("/authority_scopes") != Some(&json!([operation.required_scope()]))
        || step.transition.pointer("/authority_grant_refs")
            != Some(&json!([expected_authority_grant]))
        || step.receipt.pointer("/effect_hash") != step.proposal.pointer("/authority_effect_hash")
        || step.receipt.pointer("/effect_hash") != step.decision.pointer("/effect_hash")
    {
        return Err(
            "committed lifecycle receipt, transition, and authority tuple diverge".to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::system_genesis::{
        compile_system_genesis_proposal, compile_system_sequence_zero_plan,
        compute_system_component_set_hash, compute_system_release_root,
        finalize_system_sequence_zero_materialization,
    };

    fn fixture(path: &str) -> Value {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bytes = std::fs::read(root.join(path)).expect("fixture bytes");
        serde_json::from_slice(&bytes).expect("fixture json")
    }

    fn hash_bytes(hash: &str) -> Vec<Value> {
        hash.strip_prefix("sha256:")
            .expect("canonical hash")
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                Value::from(
                    u8::from_str_radix(std::str::from_utf8(pair).expect("hex pair"), 16)
                        .expect("hex byte"),
                )
            })
            .collect()
    }

    fn deployment_revision(
        system_id: &str,
        constitution_ref: &str,
        manifest_ref: &str,
        ordering_ref: &str,
    ) -> Value {
        let mut revision = fixture(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-deployment-profile-revision-v1/positive-candidate.json",
        );
        let profile = revision
            .get_mut("profile")
            .expect("deployment profile body");
        profile["system_id"] = json!(system_id);
        profile["constitution_ref"] = json!(constitution_ref);
        profile["manifest_ref"] = json!(manifest_ref);
        profile["ordering_admission_finality_profile_ref"] = json!(ordering_ref);
        rehash_deployment_revision(&mut revision);
        contract(
            SYSTEM_DEPLOYMENT_PROFILE_REVISION_CONTRACT,
            &revision,
            "test deployment revision",
        )
        .expect("content-addressed deployment revision");
        revision
    }

    fn rehash_deployment_revision(revision: &mut Value) {
        let profile = revision.get("profile").expect("deployment profile body");
        let root = jcs_hash(&json!({
            "domain": "ioi.autonomous-system-deployment-profile-revision-jcs-sha256.v1",
            "profile": profile,
        }))
        .expect("deployment profile root");
        let identity = required_string(profile, "/deployment_profile_id")
            .expect("deployment identity")
            .to_owned();
        revision["deployment_profile_ref"] = json!(format!("{identity}/revision/{root}"));
        revision["deployment_profile_root"] = json!(root);
    }

    fn genesis_release() -> Value {
        let mut release = fixture(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-manifest-v1/positive-reusable-release.json",
        );
        release["typed_components"]["component_set_hash"] =
            json!(compute_system_component_set_hash(&release).expect("component hash"));
        release["release_root"] =
            json!(compute_system_release_root(&release).expect("release root"));
        release
    }

    fn genesis_proposal_input(release: &Value, deployment_ref: &str) -> Value {
        let mut candidate = fixture(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-genesis-v1/positive-proposed.json",
        );
        candidate
            .as_object_mut()
            .expect("candidate object")
            .remove("admitted_manifest_root");
        candidate
            .as_object_mut()
            .expect("candidate object")
            .remove("initial_profile_bundle_root");
        candidate["cryptographic_origin"]
            .as_object_mut()
            .expect("origin object")
            .remove("genesis_operation_commitment");
        candidate["cryptographic_origin"]
            .as_object_mut()
            .expect("origin object")
            .remove("genesis_transition_commitment_ref");
        candidate["initial_component_bindings"]["admitted_component_set_hash"] =
            release["typed_components"]["component_set_hash"].clone();
        candidate["initial_profile_refs"]["deployment_profile_ref"] = json!(deployment_ref);
        json!({
            "schema_version": "ioi.autonomous-system-genesis-proposal-input.v1",
            "candidate": candidate,
            "template_bindings": {
                "constitution_template_ref": release["constitution_template_ref"],
                "deployment_template_ref": release["required_profile_templates"]["deployment_template_ref"],
                "ordering_admission_finality_template_ref": release["required_profile_templates"]["ordering_admission_finality_template_ref"],
                "oracle_evidence_template_refs": release["required_profile_templates"]["oracle_evidence_template_refs"],
                "lifecycle_continuity_template_ref": release["required_profile_templates"]["lifecycle_continuity_template_ref"],
                "network_enrollment_constraint_ref": release["required_profile_templates"]["network_enrollment_constraint_ref"]
            },
            "constitution": fixture("docs/architecture/_meta/schemas/fixtures/autonomous-system-constitution-v1/positive-draft.json"),
            "ordering_profile": fixture("docs/architecture/_meta/schemas/fixtures/ordering-admission-finality-profile-v1/positive-single-authority.json"),
            "oracle_profiles": [fixture("docs/architecture/_meta/schemas/fixtures/oracle-evidence-profile-v1/positive-fail-closed.json")],
            "lifecycle_profile": fixture("docs/architecture/_meta/schemas/fixtures/lifecycle-continuity-profile-v1/positive-successor-governed.json"),
            "network_enrollment": Value::Null,
        })
    }

    fn structural_current_materialization_receipt(
        materialization: &Value,
        governing_authority_ref: &str,
    ) -> Value {
        let mut receipt = fixture(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
        );
        let mut materialization_body = materialization.clone();
        materialization_body
            .as_object_mut()
            .expect("materialization object")
            .remove("created_at");
        let receipt_ref = required_string(materialization, "/materialization_receipt_ref")
            .expect("materialization receipt ref")
            .to_owned();
        let authorized_effect = json!({
            "operation": "materialize_sequence_zero",
            "materialization": materialization_body,
            "activation_admitted": false,
            "runtime_effect_admitted": false,
        });
        let effect_hash = jcs_hash(&json!({
            "domain": "hypervisor.system-sequence-zero.decision.request.v1.effect.v1",
            "effect": authorized_effect,
        }))
        .expect("M1.4 effect hash");
        let policy_hash = jcs_hash(&json!({
            "domain": "hypervisor.system-sequence-zero.decision.policy.v1",
            "governance": "system_owner",
            "genesis_id": materialization["genesis_ref"],
            "system_id": materialization["system_id"],
            "required_authority_ref": governing_authority_ref,
            "required_scope": "scope:autonomous_system.genesis_materialize",
        }))
        .expect("M1.4 policy hash");
        let request_hash = jcs_hash(&json!({
            "domain": "hypervisor.system-sequence-zero.decision.request.v1",
            "governance": "system_owner",
            "subject_ref": materialization["materialization_id"],
            "op": "genesis_materialize",
            "revision": 0,
            "required_authority_ref": governing_authority_ref,
            "required_scope": "scope:autonomous_system.genesis_materialize",
            "effect_hash": effect_hash,
        }))
        .expect("M1.4 request hash");
        receipt["wallet_approval_grant"]["request_hash"] = Value::Array(hash_bytes(&request_hash));
        receipt["wallet_approval_grant"]["policy_hash"] = Value::Array(hash_bytes(&policy_hash));
        let grant_hash =
            jcs_hash(&receipt["wallet_approval_grant"]).expect("retained grant artifact hash");
        let grant_ref = format!(
            "grant://wallet.network/approval/sha256:{}",
            grant_hash.trim_start_matches("sha256:")
        );
        let consumption_tail = "2020202020202020202020202020202020202020202020202020202020202020";
        let consumption_ref = format!(
            "wallet.network://approval-effect-consumption/{}/{consumption_tail}",
            request_hash.trim_start_matches("sha256:")
        );
        let consumption_evidence_ref =
            format!("system-sequence-zero-authority-consumption://aszmc_{consumption_tail}");
        receipt["receipt_id"] = json!(receipt_ref);
        receipt["receipt_ref"] = json!(receipt_ref);
        receipt["subject_ref"] = materialization["materialization_id"].clone();
        receipt["authorized_effect"] = authorized_effect;
        receipt["input_hash"] = json!(request_hash);
        receipt["policy_hash"] = json!(policy_hash);
        receipt["effect_hash"] = json!(effect_hash);
        receipt["authority_grant_id"] = json!(grant_ref);
        receipt["timestamp"] = materialization["created_at"].clone();
        receipt["at"] = materialization["created_at"].clone();
        receipt["bound_facts"]["governing_authority_ref"] = json!(governing_authority_ref);
        receipt["bound_facts"]["authority_effect_hash"] = json!(effect_hash);
        receipt["bound_facts"]["wallet_grant_consumption_ref"] = json!(consumption_ref);
        receipt["bound_facts"]["wallet_grant_consumption_evidence_ref"] =
            json!(consumption_evidence_ref);
        receipt["principal_authority_binding"]["principal_ref"] = json!(governing_authority_ref);
        receipt["principal_authority_binding"]["binding_proof"]["statement"]["principal_ref"] =
            json!(governing_authority_ref);
        let statement_hash = jcs_hash(&json!({
            "domain": "ioi.wallet-network.principal-authority-binding.v1",
            "statement": receipt["principal_authority_binding"]["binding_proof"]["statement"],
        }))
        .expect("authority binding statement hash");
        receipt["principal_authority_binding"]["binding_proof"]["statement_hash"] =
            Value::Array(hash_bytes(&statement_hash));
        let binding_hash = jcs_hash(&json!({
            "domain": "ioi.wallet-network.principal-authority-binding-proof.v1",
            "schema_version": receipt["principal_authority_binding"]["binding_proof"]["schema_version"],
            "statement": receipt["principal_authority_binding"]["binding_proof"]["statement"],
            "statement_hash": receipt["principal_authority_binding"]["binding_proof"]["statement_hash"],
            "issuer_signature_proof": receipt["principal_authority_binding"]["binding_proof"]["issuer_signature_proof"],
        }))
        .expect("authority binding proof hash");
        let binding_ref = format!(
            "wallet.network://principal-authority-binding/{}",
            binding_hash.trim_start_matches("sha256:")
        );
        receipt["principal_authority_binding"]["binding_proof"]["binding_hash"] =
            Value::Array(hash_bytes(&binding_hash));
        receipt["principal_authority_binding"]["binding_proof"]["binding_ref"] = json!(binding_ref);
        receipt["principal_authority_binding"]["coordinates"]["binding_hash"] =
            Value::Array(hash_bytes(&binding_hash));
        receipt["principal_authority_binding"]["coordinates"]["binding_ref"] = json!(binding_ref);
        for field in [
            "materialization_id",
            "system_id",
            "genesis_ref",
            "genesis_admission_receipt_ref",
            "genesis_admission_record_root",
            "genesis_admission_receipt_root",
            "proposed_initial_state_root",
            "proposed_initial_receipt_root",
            "package_id",
            "manifest_ref",
            "admitted_manifest_root",
            "constitution_ref",
            "constitution_root",
            "profile_bundle_root",
            "profile_materialization_root",
            "deployment_profile_root",
            "profile_refs",
            "component_registry_ref",
            "component_registry_root",
            "component_binding_count",
            "sequence",
            "predecessor_transition_commitment_ref",
            "operation_commitment",
            "transition_commitment_ref",
            "initial_state_root",
            "initial_receipt_root",
        ] {
            receipt["bound_facts"][field] = materialization[field].clone();
        }
        let mut boundary = vec![
            materialization["system_id"].clone(),
            materialization["genesis_ref"].clone(),
            materialization["manifest_ref"].clone(),
            materialization["constitution_ref"].clone(),
            materialization["component_registry_ref"].clone(),
            materialization["profile_refs"]["deployment_profile_ref"].clone(),
            materialization["profile_refs"]["ordering_admission_finality_profile_ref"].clone(),
            materialization["profile_refs"]["lifecycle_continuity_profile_ref"].clone(),
            materialization["genesis_admission_record_root"].clone(),
            materialization["genesis_admission_receipt_ref"].clone(),
            json!(governing_authority_ref),
            json!(grant_ref),
            json!(consumption_ref),
            json!(consumption_evidence_ref),
        ];
        boundary.extend(
            materialization["profile_refs"]["oracle_evidence_profile_refs"]
                .as_array()
                .expect("oracle refs")
                .iter()
                .cloned(),
        );
        if !materialization["profile_refs"]["network_enrollment_ref"].is_null() {
            boundary.push(materialization["profile_refs"]["network_enrollment_ref"].clone());
        }
        boundary.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
        boundary.dedup();
        receipt["attested_boundary_fact_refs"] = Value::Array(boundary);
        contract(
            CURRENT_MATERIALIZATION_RECEIPT_CONTRACT,
            &receipt,
            "test M1.4 receipt",
        )
        .expect("reconstructed current M1.4 receipt");
        receipt
    }

    fn full_source() -> (UnverifiedSystemSequenceZeroActivationSource, Value) {
        let release = genesis_release();
        let candidate = fixture(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-genesis-v1/positive-proposed.json",
        );
        let revision = deployment_revision(
            required_string(&candidate, "/system_id").unwrap(),
            required_string(&candidate, "/constitution_ref").unwrap(),
            required_string(&candidate, "/manifest_ref").unwrap(),
            required_string(
                &candidate,
                "/initial_profile_refs/ordering_admission_finality_profile_ref",
            )
            .unwrap(),
        );
        let proposal_input = genesis_proposal_input(
            &release,
            required_string(&revision, "/deployment_profile_ref").unwrap(),
        );
        let proposal = compile_system_genesis_proposal(&release, &proposal_input)
            .proposal
            .expect("valid M1.3 proposal");
        let mut genesis = serde_json::to_value(&proposal.genesis).expect("genesis JSON");
        let bundle =
            serde_json::to_value(&proposal.initial_profile_bundle.bundle).expect("bundle JSON");
        let genesis_receipt_ref = format!("receipt://asgr_{}", "7".repeat(64));
        genesis["status"] = json!("authorized");
        genesis["instantiation"]["authority_grant_refs"] = json!([format!(
            "grant://wallet.network/approval/sha256:{}",
            "8".repeat(64)
        )]);
        genesis["cryptographic_origin"]["admission_proof_ref"] = json!(genesis_receipt_ref);
        genesis["status_source_receipt_refs"] = json!([genesis_receipt_ref]);
        contract(GENESIS_CONTRACT, &genesis, "authorized test genesis")
            .expect("authorized genesis contract");
        let governing_authority_ref = "org://acme/research";
        let record = json!({
            "schema_version": "ioi.hypervisor.autonomous-system-genesis-admission.v1",
            "authorized_genesis": genesis,
            "initial_profile_bundle": bundle,
            "admission_receipt_ref": genesis_receipt_ref,
            "governing_authority_ref": governing_authority_ref,
        });
        let genesis_receipt = json!({
            "schema_version": "ioi.hypervisor.autonomous-system-genesis-receipt.v1",
            "receipt_ref": genesis_receipt_ref,
            "subject": genesis["genesis_id"],
        });
        let record_root =
            compute_system_genesis_admission_record_root(&record).expect("M1.3 record root");
        let receipt_root = compute_system_genesis_admission_receipt_root(&genesis_receipt)
            .expect("M1.3 receipt root");
        let sequence_zero = compile_system_sequence_zero_plan(
            &genesis,
            &record["initial_profile_bundle"],
            &record_root,
            &genesis_receipt_ref,
            &receipt_root,
        )
        .expect("M1.4 plan");
        let materialization = serde_json::to_value(
            finalize_system_sequence_zero_materialization(&sequence_zero, "2026-07-21T11:00:00Z")
                .expect("M1.4 materialization")
                .materialization,
        )
        .expect("materialization JSON");
        let materialization_receipt =
            structural_current_materialization_receipt(&materialization, governing_authority_ref);
        let wallet_ref =
            materialization_receipt["bound_facts"]["wallet_grant_consumption_ref"].clone();
        let source = UnverifiedSystemSequenceZeroActivationSource {
            source_governing_authority_ref: governing_authority_ref.to_owned(),
            genesis_admission_record: record,
            genesis_admission_receipt: genesis_receipt,
            materialization,
            materialization_receipt,
            component_registry: sequence_zero.component_registry_snapshot,
            materialization_wallet_consumption: json!({
                "schema_version": "ioi.test-wallet-consumption.v1",
                "consumption_ref": wallet_ref,
            }),
        };
        (source, revision)
    }

    fn authority_evidence(
        plan: &CompiledSystemLifecyclePlan,
        marker: char,
    ) -> SystemLifecycleAuthorityEvidence {
        let fill = marker.to_string().repeat(64);
        SystemLifecycleAuthorityEvidence {
            authorized_effect: plan.authority_effect.clone(),
            authority_grant_ref: format!("grant://wallet.network/approval/sha256:{fill}"),
            input_hash: format!("sha256:{}", "1".repeat(64)),
            policy_hash: format!("sha256:{}", "2".repeat(64)),
            effect_hash: unverified_system_lifecycle_effect_hash(&plan.authority_effect)
                .expect("effect hash"),
            authority_evidence_ref: format!("system-lifecycle-authority-evidence://aslae_{fill}"),
            authority_evidence_root: format!("sha256:{}", "3".repeat(64)),
            wallet_grant_consumption_ref: format!(
                "wallet.network://approval-effect-consumption/{}/{}",
                "4".repeat(64),
                fill
            ),
            wallet_grant_consumption_root: format!("sha256:{}", "5".repeat(64)),
            wallet_grant_consumption_evidence_ref: format!(
                "system-lifecycle-authority-consumption://aslac_{fill}"
            ),
        }
    }

    #[test]
    fn full_content_addressed_initialize_activate_compilation_is_exact_and_compact() {
        let (source, revision) = full_source();
        let source_materialization = serde_jcs::to_vec(&source.materialization).unwrap();
        let source_receipt = serde_jcs::to_vec(&source.materialization_receipt).unwrap();
        let initialize_plan = compile_system_initialize_plan(&source, &revision)
            .expect("content-addressed M1.4 source initializes");
        let initialize = finalize_system_lifecycle_plan(
            &initialize_plan,
            &authority_evidence(&initialize_plan, '6'),
            "2026-07-21T12:00:00Z",
        )
        .expect("sequence one finalizes");
        assert!(initialize.active_profile_set.is_none());
        assert!(initialize.home_domain_binding.is_none());
        assert!(initialize.operation_log.is_none());
        assert!(initialize.chain.is_none());
        assert_eq!(
            initialize.step.receipt["schema_version"],
            "ioi.lifecycle-transition-receipt.v1"
        );
        assert_eq!(
            initialize.step.transition["state_transition_commitment_ref"],
            Value::Null
        );
        let initialize_commitment = &initialize.step.proposal["operation_commitment"];
        for value in [
            &initialize.step.proposal["authority_effect"]["operation_commitment"],
            &initialize.step.decision["operation_commitment"],
            &initialize.step.transition["operation_commitment"],
            &initialize.step.receipt["bound_facts"]["operation_commitment"],
        ] {
            assert_eq!(value, initialize_commitment);
        }

        let activate_plan = compile_system_activate_plan(&source, &revision, &initialize.step)
            .expect("exact initialized tuple activates");
        let activated = finalize_system_lifecycle_plan(
            &activate_plan,
            &authority_evidence(&activate_plan, '7'),
            "2026-07-21T13:00:00Z",
        )
        .expect("sequence two finalizes");
        let active_set = activated.active_profile_set.as_ref().expect("active set");
        let home_binding = activated
            .home_domain_binding
            .as_ref()
            .expect("home binding");
        let operation_log = activated.operation_log.as_ref().expect("operation log");
        let chain = activated.chain.as_ref().expect("live chain");
        assert_eq!(
            activated.step.receipt["schema_version"],
            "ioi.autonomous-system-activation-receipt.v1"
        );
        assert_eq!(chain["status"], "active");
        assert_eq!(chain["latest_sequence"], 2);
        assert_eq!(
            chain["operation_log_ref"],
            operation_log["operation_log_ref"]
        );
        assert_eq!(
            chain["operation_log_root"],
            operation_log["operation_log_root"]
        );
        assert_eq!(
            chain["home_domain_binding_ref"],
            home_binding["home_domain_binding_ref"]
        );
        assert_ne!(
            chain["home_domain_ref"],
            json!(source.source_governing_authority_ref)
        );
        assert!(required_string(chain, "/home_domain_ref")
            .unwrap()
            .starts_with("agentgres://domain/autonomous-system/"));
        assert_eq!(
            chain["active_profile_set_ref"],
            active_set["active_profile_set_ref"]
        );
        assert_eq!(chain["node_membership_refs"], json!([]));
        assert_eq!(chain["active_writer_epoch"], Value::Null);
        assert_eq!(chain["worker_instance_refs"], json!([]));
        assert_eq!(chain["workflow_refs"], json!([]));
        assert_eq!(chain["latest_transition_commitment_ref"], Value::Null);
        assert_eq!(chain["settlement_policy_ref"], Value::Null);
        assert_eq!(chain["public_commitment_policy_ref"], Value::Null);
        assert_eq!(operation_log["entries"].as_array().unwrap().len(), 3);
        let activation_commitment = &activated.step.proposal["operation_commitment"];
        for value in [
            &activated.step.proposal["authority_effect"]["operation_commitment"],
            &activated.step.decision["operation_commitment"],
            &activated.step.transition["operation_commitment"],
            &activated.step.receipt["bound_facts"]["operation_commitment"],
            &operation_log["entries"][2]["operation_commitment"],
            &operation_log["latest_operation_commitment"],
            &chain["latest_operation_commitment"],
        ] {
            assert_eq!(value, activation_commitment);
        }
        validate_chain_against_operation_log(chain, operation_log)
            .expect("compact chain binds the exact log head");
        assert_eq!(
            serde_jcs::to_vec(&source.materialization).unwrap(),
            source_materialization
        );
        assert_eq!(
            serde_jcs::to_vec(&source.materialization_receipt).unwrap(),
            source_receipt
        );
    }

    #[test]
    fn compact_chain_refuses_stale_non_head_detached_and_foreign_logs() {
        let (source, revision) = full_source();
        let initialize_plan = compile_system_initialize_plan(&source, &revision).unwrap();
        let initialize = finalize_system_lifecycle_plan(
            &initialize_plan,
            &authority_evidence(&initialize_plan, '6'),
            "2026-07-21T12:00:00Z",
        )
        .unwrap();
        let activate_plan =
            compile_system_activate_plan(&source, &revision, &initialize.step).unwrap();
        let activated = finalize_system_lifecycle_plan(
            &activate_plan,
            &authority_evidence(&activate_plan, '7'),
            "2026-07-21T13:00:00Z",
        )
        .unwrap();
        let chain = activated.chain.as_ref().unwrap();
        let log = activated.operation_log.as_ref().unwrap();

        let mut stale_root = log.clone();
        stale_root["operation_log_root"] = json!(format!("sha256:{}", "f".repeat(64)));
        assert!(validate_chain_against_operation_log(chain, &stale_root).is_err());

        let mut non_head = log.clone();
        non_head["head_entry"] = non_head["entries"][1].clone();
        assert!(validate_chain_against_operation_log(chain, &non_head).is_err());

        let mut detached_chain = chain.clone();
        let detached_root = format!("sha256:{}", "e".repeat(64));
        detached_chain["operation_log_ref"] = json!(format!(
            "agentgres://operation-log/autonomous-system/acme/system-alpha/revision/{detached_root}"
        ));
        detached_chain["operation_log_root"] = json!(detached_root);
        detached_chain["chain_root"] = json!(chain_root(&detached_chain).unwrap());
        contract(SYSTEM_CHAIN_CONTRACT, &detached_chain, "detached chain")
            .expect("detached chain remains structurally valid");
        assert!(validate_chain_against_operation_log(&detached_chain, log).is_err());

        let foreign_log = fixture(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-operation-log-v1/positive-activation-prefix.json",
        );
        contract(
            SYSTEM_OPERATION_LOG_CONTRACT,
            &foreign_log,
            "foreign operation log",
        )
        .expect("foreign operation log remains structurally valid");
        assert!(validate_chain_against_operation_log(chain, &foreign_log).is_err());
    }

    #[test]
    fn legacy_compatibility_and_deployment_substitutions_refuse() {
        let (source, revision) = full_source();
        let mut legacy = source.clone();
        let legacy_ref = "deployment-profile://acme/system-alpha/legacy";
        let legacy_root = jcs_hash(&json!({
            "domain": "ioi.autonomous-system-legacy-deployment-profile-ref-jcs-sha256.v1",
            "value": legacy_ref,
        }))
        .unwrap();
        legacy.materialization["profile_refs"]["deployment_profile_ref"] = json!(legacy_ref);
        legacy.materialization["deployment_profile_root"] = json!(legacy_root);
        contract(
            MATERIALIZATION_CONTRACT,
            &legacy.materialization,
            "legacy M1.4 fixture",
        )
        .expect("legacy compatibility materialization remains readable");
        let error = compile_system_initialize_plan(&legacy, &revision)
            .expect_err("legacy compatibility commitment cannot initialize");
        assert!(error.contains("legacy deployment-profile compatibility commitment"));

        let mut body_mutation = revision.clone();
        body_mutation["profile"]["environment_class"] = json!("production");
        assert!(compile_system_initialize_plan(&source, &body_mutation).is_err());

        let mut root_mutation = revision.clone();
        root_mutation["deployment_profile_root"] = json!(format!("sha256:{}", "f".repeat(64)));
        assert!(compile_system_initialize_plan(&source, &root_mutation).is_err());

        let mut identity_substitution = revision.clone();
        identity_substitution["deployment_profile_ref"] = json!(format!(
            "deployment-profile://acme/foreign/revision/{}",
            required_string(&revision, "/deployment_profile_root").unwrap()
        ));
        assert!(compile_system_initialize_plan(&source, &identity_substitution).is_err());

        for (pointer, replacement) in [
            ("/system_id", json!("system://acme/foreign")),
            ("/constitution_ref", json!("constitution://acme/foreign/v1")),
            (
                "/manifest_ref",
                json!(format!(
                    "package://acme/foreign/release/sha256:{}",
                    "a".repeat(64)
                )),
            ),
            (
                "/ordering_admission_finality_profile_ref",
                json!("ordering-profile://acme/foreign/v1"),
            ),
        ] {
            let mut detached = revision.clone();
            let field = pointer.trim_start_matches('/');
            detached["profile"][field] = replacement;
            rehash_deployment_revision(&mut detached);
            contract(
                SYSTEM_DEPLOYMENT_PROFILE_REVISION_CONTRACT,
                &detached,
                "coordinate mutation",
            )
            .expect("coordinate mutation remains a valid foreign revision");
            assert!(
                compile_system_initialize_plan(&source, &detached).is_err(),
                "{pointer} substitution must refuse"
            );
        }
    }

    #[test]
    fn finalization_rejects_forged_plan_and_unrelated_authority_effect() {
        let (source, revision) = full_source();
        let plan = compile_system_initialize_plan(&source, &revision).unwrap();

        let mut forged_plan = plan.clone();
        forged_plan.authority_effect["home_domain_ref"] = json!(format!(
            "agentgres://domain/autonomous-system/acme/forged/sha256:{}",
            "f".repeat(64)
        ));
        forged_plan.authority_effect["operation_commitment"] =
            json!(operation_commitment_from_effect(&forged_plan.authority_effect).unwrap());
        let forged_evidence = authority_evidence(&forged_plan, '8');
        assert!(finalize_system_lifecycle_plan(
            &forged_plan,
            &forged_evidence,
            "2026-07-21T12:00:00Z",
        )
        .is_err());

        let mut unrelated = authority_evidence(&plan, '9');
        unrelated.authorized_effect["sequence"] = json!(2);
        assert!(
            finalize_system_lifecycle_plan(&plan, &unrelated, "2026-07-21T12:00:00Z",).is_err()
        );

        let mut unrelated_hash = authority_evidence(&plan, 'a');
        unrelated_hash.effect_hash = format!("sha256:{}", "f".repeat(64));
        assert!(
            finalize_system_lifecycle_plan(&plan, &unrelated_hash, "2026-07-21T12:00:00Z",)
                .is_err()
        );
    }

    fn valid_committed_initialize_step() -> UnverifiedCommittedSystemLifecycleStep {
        let mut state = fixture(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-activation-state-v1/positive-initialized.json",
        );
        let state_root = required_string(&state, "/activation_state_root")
            .unwrap()
            .to_owned();
        let state_ref = required_string(&state, "/activation_state_ref")
            .unwrap()
            .to_owned();
        let predecessor = required_string(&state, "/predecessor_state_root")
            .unwrap()
            .to_owned();
        let system_id = required_string(&state, "/system_id").unwrap().to_owned();
        let genesis_ref = required_string(&state, "/genesis_ref").unwrap().to_owned();
        let transition_ref = required_string(&state, "/transition_ref")
            .unwrap()
            .to_owned();
        let receipt_ref = required_string(&state, "/transition_receipt_ref")
            .unwrap()
            .to_owned();
        let mut proposal = fixture(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-activation-proposal-v1/positive-initialize.json",
        );
        proposal["system_id"] = json!(system_id);
        proposal["genesis_ref"] = json!(genesis_ref);
        proposal["authority_effect"]["system_id"] = json!(system_id);
        proposal["authority_effect"]["genesis_ref"] = json!(genesis_ref);
        proposal["authority_effect"]["manifest_ref"] = state["manifest_ref"].clone();
        proposal["authority_effect"]["admitted_manifest_root"] =
            state["admitted_manifest_root"].clone();
        proposal["authority_effect"]["lifecycle_profile_ref"] =
            state["lifecycle_profile_ref"].clone();
        proposal["authority_effect"]["predecessor_state_root"] = json!(predecessor);
        proposal["authority_effect"]["resulting_state_ref"] = json!(state_ref);
        proposal["authority_effect"]["resulting_state_root"] = json!(state_root);
        let operation_commitment =
            operation_commitment_from_effect(&proposal["authority_effect"]).unwrap();
        proposal["authority_effect"]["operation_commitment"] = json!(operation_commitment);
        proposal["operation_commitment"] = json!(operation_commitment);
        proposal["authority_effect_hash"] =
            json!(unverified_system_lifecycle_effect_hash(&proposal["authority_effect"]).unwrap());
        let proposal_root = proposal_root_from_artifact(&proposal).unwrap();
        proposal["proposal_root"] = json!(proposal_root);
        contract(
            SYSTEM_LIFECYCLE_PROPOSAL_CONTRACT,
            &proposal,
            "test proposal",
        )
        .unwrap();

        let mut decision = fixture(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-activation-authority-decision-v1/positive-initialize.json",
        );
        decision["proposal_ref"] = proposal["proposal_ref"].clone();
        decision["proposal_root"] = json!(proposal_root);
        decision["system_id"] = json!(system_id);
        decision["genesis_ref"] = json!(genesis_ref);
        decision["operation_commitment"] = proposal["operation_commitment"].clone();
        decision["effect_hash"] = proposal["authority_effect_hash"].clone();
        let decision_root = decision_root_from_artifact(&decision).unwrap();
        decision["decision_root"] = json!(decision_root);
        contract(
            SYSTEM_LIFECYCLE_AUTHORITY_DECISION_CONTRACT,
            &decision,
            "test decision",
        )
        .unwrap();

        let transition = json!({
            "schema_version": "ioi.lifecycle-transition.v1",
            "lifecycle_transition_id": transition_ref,
            "system_id": system_id,
            "resulting_or_related_system_id": Value::Null,
            "lifecycle_profile_ref": state["lifecycle_profile_ref"],
            "transition_kind": "initialize",
            "genesis_ref": genesis_ref,
            "manifest_ref": state["manifest_ref"],
            "admitted_manifest_root": state["admitted_manifest_root"],
            "previous_state": "draft",
            "proposed_state": "initialized",
            "trigger_evidence_refs": ["receipt://aszmr_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],
            "oracle_evidence_profile_refs": [],
            "proposal_ref": proposal["proposal_ref"],
            "decision_ref": decision["decision_ref"],
            "authority_grant_refs": [decision["authority_grant_ref"].clone()],
            "challenge_opened_at": Value::Null,
            "challenge_closes_at": Value::Null,
            "predecessor_state_root": predecessor,
            "resulting_state_root": state_root,
            "operation_commitment": proposal["operation_commitment"],
            "state_transition_commitment_ref": Value::Null,
            "lineage_ref": Value::Null,
            "identity_continuity_decision_ref": Value::Null,
            "disposition_receipt_refs": [],
            "receipt_refs": [receipt_ref],
            "public_commitment_ref": Value::Null,
            "status": "committed",
        });
        contract(
            LIFECYCLE_TRANSITION_CONTRACT,
            &transition,
            "test transition",
        )
        .unwrap();
        let transition_root =
            artifact_root(LIFECYCLE_TRANSITION_HASH_PROFILE, &transition).unwrap();

        let mut receipt = fixture(
            "docs/architecture/_meta/schemas/fixtures/lifecycle-transition-receipt-v1/positive-initialize.json",
        );
        receipt["receipt_id"] = json!(receipt_ref);
        receipt["receipt_ref"] = json!(receipt_ref);
        receipt["subject_ref"] = json!(transition_ref);
        receipt["bound_facts"]["system_id"] = json!(system_id);
        receipt["bound_facts"]["genesis_ref"] = json!(genesis_ref);
        receipt["bound_facts"]["proposal_ref"] = proposal["proposal_ref"].clone();
        receipt["bound_facts"]["proposal_root"] = json!(proposal_root);
        receipt["bound_facts"]["decision_ref"] = decision["decision_ref"].clone();
        receipt["bound_facts"]["decision_root"] = json!(decision_root);
        receipt["bound_facts"]["transition_ref"] = json!(transition_ref);
        receipt["bound_facts"]["transition_root"] = json!(transition_root);
        receipt["bound_facts"]["predecessor_state_root"] = json!(predecessor);
        receipt["bound_facts"]["resulting_state_ref"] = json!(state_ref);
        receipt["bound_facts"]["resulting_state_root"] = json!(state_root);
        receipt["bound_facts"]["operation_commitment"] = proposal["operation_commitment"].clone();
        receipt["output_hash"] = json!(state_root);
        receipt["effect_hash"] = proposal["authority_effect_hash"].clone();
        receipt["bound_facts"]["authority_effect_hash"] = proposal["authority_effect_hash"].clone();
        contract(
            SYSTEM_LIFECYCLE_TRANSITION_RECEIPT_CONTRACT,
            &receipt,
            "test receipt",
        )
        .unwrap();
        let receipt_root = artifact_root(LIFECYCLE_RECEIPT_ROOT_HASH_PROFILE, &receipt).unwrap();
        state["transition_root"] = json!(transition_root);
        state["transition_receipt_root"] = json!(receipt_root);
        UnverifiedCommittedSystemLifecycleStep {
            proposal,
            decision,
            state,
            transition,
            receipt,
            state_root,
            proposal_root,
            decision_root,
            transition_root,
            receipt_root,
        }
    }

    #[test]
    fn commitment_order_is_acyclic_and_downstream_navigation_is_not_state_material() {
        let semantic = json!({
            "domain": LIFECYCLE_STATE_HASH_PROFILE,
            "activation_state_ref": "system-activation-state://acme/system/sequence/1",
            "system_id": "system://acme/system",
            "genesis_ref": "genesis://acme/system/zero",
            "manifest_ref": format!("package://acme/system/release/sha256:{}", "a".repeat(64)),
            "admitted_manifest_root": format!("sha256:{}", "b".repeat(64)),
            "lifecycle_profile_ref": "lifecycle-profile://acme/system/default",
            "sequence": 1,
            "status": "initialized",
            "predecessor_state_root": format!("sha256:{}", "c".repeat(64)),
            "active_profile_set_ref": Value::Null,
            "active_profile_set_root": Value::Null,
            "live_chain_created": false,
            "node_membership_refs": [],
            "runtime_effect_admitted": false,
            "network_effect_admitted": false,
        });
        let first = jcs_hash(&semantic).expect("semantic state hash");
        let mut projection = semantic;
        projection["transition_ref"] = json!("lifecycle-transition://acme/system/sequence/1");
        projection["transition_receipt_ref"] = json!("receipt://acme/system/sequence/1");
        projection["chain_ref"] = Value::Null;
        let mut reduced = projection.as_object().expect("object").clone();
        reduced.remove("transition_ref");
        reduced.remove("transition_receipt_ref");
        reduced.remove("chain_ref");
        assert_eq!(jcs_hash(&Value::Object(reduced)).unwrap(), first);
    }

    #[test]
    fn committed_step_rejects_detached_navigation_roots_and_coordinates() {
        let step = valid_committed_initialize_step();
        validate_committed_step(
            &step,
            SystemLifecycleOperation::Initialize,
            required_string(&step.state, "/predecessor_state_root").unwrap(),
        )
        .expect("valid singular tuple");
        let mutations: Vec<(
            &str,
            Box<dyn Fn(&mut UnverifiedCommittedSystemLifecycleStep)>,
        )> = vec![
            (
                "state transition ref",
                Box::new(|s| {
                    s.state["transition_ref"] =
                        json!("lifecycle-transition://acme/system-alpha/detached")
                }),
            ),
            (
                "state transition root",
                Box::new(|s| {
                    s.state["transition_root"] = json!(format!("sha256:{}", "f".repeat(64)))
                }),
            ),
            (
                "state receipt ref",
                Box::new(|s| {
                    s.state["transition_receipt_ref"] =
                        json!(format!("receipt://ltr_{}", "f".repeat(64)))
                }),
            ),
            (
                "state receipt root",
                Box::new(|s| {
                    s.state["transition_receipt_root"] = json!(format!("sha256:{}", "f".repeat(64)))
                }),
            ),
            (
                "state manifest",
                Box::new(|s| {
                    s.state["manifest_ref"] = json!(format!(
                        "package://acme/system-alpha/release/sha256:{}",
                        "f".repeat(64)
                    ))
                }),
            ),
            (
                "state admitted manifest",
                Box::new(|s| {
                    s.state["admitted_manifest_root"] = json!(format!("sha256:{}", "f".repeat(64)))
                }),
            ),
            (
                "state lifecycle profile",
                Box::new(|s| {
                    s.state["lifecycle_profile_ref"] =
                        json!("lifecycle-profile://acme/system-alpha/foreign")
                }),
            ),
            (
                "state status",
                Box::new(|s| s.state["status"] = json!("active")),
            ),
            (
                "state sequence",
                Box::new(|s| s.state["sequence"] = json!(2)),
            ),
            (
                "state predecessor",
                Box::new(|s| {
                    s.state["predecessor_state_root"] = json!(format!("sha256:{}", "f".repeat(64)))
                }),
            ),
            (
                "state active set",
                Box::new(|s| {
                    s.state["active_profile_set_ref"] =
                        json!("active-profile-set://acme/system-alpha/sequence/2");
                    s.state["active_profile_set_root"] =
                        json!(format!("sha256:{}", "f".repeat(64)));
                }),
            ),
            (
                "state live chain",
                Box::new(|s| s.state["live_chain_created"] = json!(true)),
            ),
            (
                "state membership nonclaim",
                Box::new(|s| {
                    s.state["node_membership_refs"] = json!(["node-membership://acme/forged"])
                }),
            ),
            (
                "state runtime nonclaim",
                Box::new(|s| s.state["runtime_effect_admitted"] = json!(true)),
            ),
            (
                "state network nonclaim",
                Box::new(|s| s.state["network_effect_admitted"] = json!(true)),
            ),
            (
                "transition system",
                Box::new(|s| s.transition["system_id"] = json!("system://acme/other")),
            ),
            (
                "transition resulting root",
                Box::new(|s| {
                    s.transition["resulting_state_root"] =
                        json!(format!("sha256:{}", "e".repeat(64)))
                }),
            ),
            (
                "proposal commitment",
                Box::new(|s| {
                    s.proposal["operation_commitment"] = json!(format!("sha256:{}", "e".repeat(64)))
                }),
            ),
            (
                "effect commitment",
                Box::new(|s| {
                    s.proposal["authority_effect"]["operation_commitment"] =
                        json!(format!("sha256:{}", "e".repeat(64)))
                }),
            ),
            (
                "decision commitment",
                Box::new(|s| {
                    s.decision["operation_commitment"] = json!(format!("sha256:{}", "e".repeat(64)))
                }),
            ),
            (
                "transition commitment",
                Box::new(|s| {
                    s.transition["operation_commitment"] =
                        json!(format!("sha256:{}", "e".repeat(64)))
                }),
            ),
            (
                "receipt commitment",
                Box::new(|s| {
                    s.receipt["bound_facts"]["operation_commitment"] =
                        json!(format!("sha256:{}", "e".repeat(64)))
                }),
            ),
            (
                "transition receipt",
                Box::new(|s| {
                    s.transition["receipt_refs"] =
                        json!([format!("receipt://ltr_{}", "e".repeat(64))])
                }),
            ),
            (
                "receipt subject",
                Box::new(|s| {
                    s.receipt["subject_ref"] =
                        json!("lifecycle-transition://acme/system-alpha/detached")
                }),
            ),
            (
                "receipt proposal root",
                Box::new(|s| {
                    s.receipt["bound_facts"]["proposal_root"] =
                        json!(format!("sha256:{}", "d".repeat(64)))
                }),
            ),
            (
                "receipt boundary coverage",
                Box::new(|s| s.receipt["attested_boundary_fact_refs"] = json!([])),
            ),
            (
                "decision proposal ref",
                Box::new(|s| {
                    s.decision["proposal_ref"] = json!("proposal://acme/system-alpha/detached")
                }),
            ),
            (
                "effect state ref",
                Box::new(|s| {
                    s.proposal["authority_effect"]["resulting_state_ref"] =
                        json!("system-activation-state://acme/system-alpha/detached")
                }),
            ),
        ];
        for (label, mutate) in mutations {
            let mut detached = step.clone();
            mutate(&mut detached);
            assert!(
                validate_committed_step(
                    &detached,
                    SystemLifecycleOperation::Initialize,
                    required_string(&step.state, "/predecessor_state_root").unwrap(),
                )
                .is_err(),
                "{label} must refuse"
            );
        }
    }

    #[test]
    fn optional_network_candidate_is_local_only_and_coordinate_bound() {
        let profile = fixture(
            "docs/architecture/_meta/schemas/fixtures/ioi-network-enrollment-v1/positive-local-only.json",
        );
        let admitted = network_profile_admission(
            &profile,
            "system://acme/system-alpha",
            "constitution://acme/system-alpha/v1",
            "package://acme/outcome-operator/release/sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("valid optional local candidate");
        assert_eq!(admitted["admitted_posture"], json!("local_only"));
        assert_eq!(
            admitted["candidate_profile_ref"],
            json!("network-enrollment://acme/system-alpha/local")
        );
        let mut mismatched = profile.clone();
        mismatched["system_id"] = json!("system://acme/foreign");
        assert!(network_profile_admission(
            &mismatched,
            "system://acme/system-alpha",
            "constitution://acme/system-alpha/v1",
            "package://acme/outcome-operator/release/sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .is_err());
        let mut malformed = profile;
        malformed
            .as_object_mut()
            .unwrap()
            .remove("network_enrollment_id");
        assert!(network_profile_admission(
            &malformed,
            "system://acme/system-alpha",
            "constitution://acme/system-alpha/v1",
            "package://acme/outcome-operator/release/sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .is_err());
    }
}
