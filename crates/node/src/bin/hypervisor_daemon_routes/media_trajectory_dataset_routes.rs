//! M05.9 — policy-bound media, demonstration and trajectory datasets, as owner-scoped runtime.
//!
//! Four Data-owned families ride the ONE durable spine every v2 ODK family rides: the Agentgres
//! owner-namespaced operation chain through `admit_owner_scoped_mutation`. This module writes no
//! file of its own, mints no second store, and rebuilds every projection from the chain on each
//! read. `4e03a1eef` registered the contracts; this is the half that ADMITS them and then REFUSES,
//! at the moment bytes would be bound, everything the contracts can only describe.
//!
//! OBSERVATION IS NOT CONSENT. A snapshot records what was captured and under which rights, and
//! grants nothing. `permits_learned_use` is NEVER accepted from a caller: it is DERIVED from the
//! source-rights claims this seam actually resolved, so a capture whose training rights nobody
//! granted cannot describe itself as learnable. ACC-16 clause 1 splits the two failures exactly —
//! missing CAPTURE rights refuses every profile, while missing training or secondary-use rights
//! leaves the procedural path open and only the learned claim inadmissible.
//!
//! THE LOAD-BEARING RULE, AND ITS THIRD EXPRESSION. A `video_inferred` or `model_inferred` label is
//! an `uncertain_attributed_label` and is never controller ground truth. The schema conditional and
//! the registered coverage invariant already refuse it offline; this module refuses it again HERE,
//! by name, naming which label crossed. Three independent expressions is the point: no single edit
//! defeats them all. Beyond refusing, the ground-truth-eligible set is not accepted from the caller
//! at all — it is DERIVED from the `controller_recorded` subset, which makes a smuggled inferred
//! label unrepresentable rather than merely refused (ACC-16 clause 10, ACC-19 clause 5).
//!
//! EVERY BINDING CROSSES ITS OWNER'S SEAM UNDER THE CALLER'S OWN BINDING. The policy-bound view
//! comes from M05.8, the source-rights claims from M10.3, the redaction recipe and the source-impact
//! lineage from M05.7, and each is resolved rather than shape-checked — so a cross-tenant or
//! cross-principal input is refused at the scope boundary BEFORE any bytes are bound, not
//! discovered afterwards when the protected material has already moved. Each bound revision's
//! committed hash is compared against what its owner serves right now, so a silent re-admission
//! underneath a snapshot is detectable.
//!
//! THE TIMEBASE IS DETECTED, NOT NORMALIZED. Gaps, reordering, clock regression and rate changes are
//! RETAINED as discontinuities. A caller that declares its timebase non-monotonic, or that asks for
//! a discontinuity to be absorbed, is refused: a run that sorts a clock regression into order has
//! destroyed the evidence ACC-16 clause 3 exists to preserve. Per INV-39 the admission stamp is the
//! authenticated one the operation carries, never a caller-asserted capture clock.
//!
//! CORRUPT, TRUNCATED AND VARIABLE-RATE INPUT IS REFUSED BY NAME, NEVER REPAIRED. A quality finding
//! of those classes must be `refused` or `excluded`; a corpus that retained one and carried on has
//! absorbed a defect into a dataset, which is the silence ACC-19 clause 5 forbids.
//!
//! THIS MODULE ADMITS NO WORK, MINTS NO AUTHORITY AND OWNS NO SESSION. It may REFERENCE a
//! `session://` or a `work-result://`, but it never writes work-lifecycle, frontier, claim, attempt
//! or contribution state (INV-35, INV-31), and no snapshot, episode, split or census grants a
//! capability, mints a lease, widens a policy decision or admits an effect. An `active` ArtifactRef
//! names bytes and grants no read, no replay and no current authority.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::data_transformation_routes::{
    resolve_admitted_connector_mapping, resolve_admitted_data_recipe,
    resolve_admitted_transformation_run,
};
use super::institutional_learning_boundary_routes::resolve_admitted_source_rights_claim;
use super::model_route_rights_routes::{
    bad, body_object, body_str, contract_owner_ref, contract_tenant_ref, digest_over, family_query,
    family_token, finish_admission, head_assertion, is_sha256, parse_revision_ref,
    projection_cache_state, read_stream, refuse, reject_authored, replay_for_key,
    require_exact_head, sha256_of, AdmittedRecord, FamilySpec, Reply, StreamQuery,
};
use super::mutation_event_foundation::{admitted_stamp, require_write_caller, scope_refusal_reply};
use super::policy_bound_data_view_revision_routes::resolve_admitted_policy_bound_data_view;
use super::substrate_store::{
    authorize_request_resource_scope, bind_request_resource_scope, resolve_request_identity,
    RequestIdentity,
};
use super::DaemonState;

// ===================================================================== the closed vocabularies

/// The label provenance classes that can NEVER be controller ground truth.
///
/// DECLARED AS A TABLE so a reviewer can disagree with one member and a mutation can flip one
/// member and watch the gate go red. An inferred label is an attribution: something looked at the
/// pixels and guessed. Passive video never observes the controller.
const INFERRED_LABEL_PROVENANCE: &[&str] = &["video_inferred", "model_inferred"];

/// The one provenance class an admitted controller stream can support.
const CONTROLLER_RECORDED: &str = "controller_recorded";

/// The quality findings that may never be absorbed. A corpus that RETAINED one of these and carried
/// on has put a known defect into a dataset.
const NEVER_RETAINED_FINDINGS: &[&str] =
    &["corrupt_chunk", "truncated_file", "variable_rate_segment"];

/// The dispositions those findings must carry instead.
const REFUSING_SEVERITIES: &[&str] = &["refused", "excluded"];

const SNAPSHOT_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "media_snapshot_id",
    "revision_ref",
    "tenant_ref",
    "principal_resolution",
    "resolved_principal_ref",
    // DERIVED FROM THE RESOLVED CLAIMS, NEVER AUTHORED. A capture that could declare itself
    // learnable would make the rights resolution decorative.
    "permits_learned_use",
    "admitted_at",
    "constants",
    "authority_nonclaim",
    "artifact_authority",
    "capture_authority_does_not_travel_into_replay",
    "demonstration_is_not_consent",
    "snapshot_is_not_a_skill_or_workflow",
    "content_hash",
];

const EPISODE_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "episode_id",
    "revision_ref",
    "tenant_ref",
    "principal_resolution",
    "resolved_principal_ref",
    // THE GROUND-TRUTH SET IS DERIVED, WHICH IS STRONGER THAN REFUSING A BAD ONE. A caller cannot
    // offer a ground-truth list at all, so an inferred label inside one is unrepresentable.
    "ground_truth_eligible_label_refs",
    "controller_recorded_label_refs",
    "session_ref",
    "admitted_at",
    "constants",
    "authority_nonclaim",
    "inferred_label_is_never_ground_truth",
    "episode_is_not_a_skill_or_workflow",
    "content_hash",
];

const SPLIT_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "split_manifest_id",
    "revision_ref",
    "tenant_ref",
    "principal_resolution",
    "resolved_principal_ref",
    "all_member_episode_revision_refs",
    "member_count",
    "splits",
    "membership_is_immutable",
    "admitted_at",
    "constants",
    "authority_nonclaim",
    "manifest_selects_no_evaluation_evidence_for_its_own_producer",
    "content_hash",
];

const CENSUS_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "corpus_census_id",
    "tenant_ref",
    "principal_resolution",
    "resolved_principal_ref",
    "floors",
    "ceilings",
    "payload_custody",
    "does_not_claim_custody_of_imported_media_bytes",
    "distinct_content_hash_count",
    "does_not_claim_hours_scale_qualification",
    "does_not_claim_throughput_or_latency",
    "admitted_at",
    "constants",
    "authority_nonclaim",
    "content_hash",
];

// ===================================================================== the four family specs

const SNAPSHOT_MATERIAL: &[&str] = &[
    "schema_version",
    "media_snapshot_id",
    "revision_ref",
    "owner_ref",
    "tenant_ref",
    "principal_resolution",
    "resolved_principal_ref",
    "acquisition_class",
    "capture_binding",
    "source_rights",
    "policy_bound_data_view_revision_refs",
    "timebase",
    "valid_time",
    "artifact_bindings",
    "availability",
    "information_flow_label_refs",
    "quarantine",
    "redaction",
    "deduplication",
    "quality_findings",
    "source_impact_lineage",
    "raw_census",
    "accepted_census",
    "registry_status",
    "admitted_at",
    "succession",
    "migration",
    "constants",
    "authority_nonclaim",
    "artifact_authority",
    "capture_authority_does_not_travel_into_replay",
    "demonstration_is_not_consent",
    "snapshot_is_not_a_skill_or_workflow",
];

pub(crate) static SNAPSHOT: FamilySpec = FamilySpec {
    owner_namespace: "media-snapshot-revisions",
    resource_kind: "media_snapshot",
    admit_op: "media_snapshot.admit_revision",
    payload_schema: "ioi.hypervisor.media-snapshot-admission.v1",
    contract_id: "schema://ioi/foundations/objects/policy-bound-media-snapshot/v1",
    schema_version: "ioi.policy-bound-media-snapshot.v1",
    record_key: "media_snapshot_record",
    code_prefix: "media_snapshot",
    commitment_domain: "ioi.policy-bound-media-snapshot-content-commitment-jcs-sha256.v1",
    material_fields: SNAPSHOT_MATERIAL,
    identity_field: "revision_ref",
    ref_scheme: "media-snapshot://",
    stamp_field: "admitted_at",
};

const EPISODE_MATERIAL: &[&str] = &[
    "schema_version",
    "episode_id",
    "revision_ref",
    "owner_ref",
    "tenant_ref",
    "principal_resolution",
    "resolved_principal_ref",
    "media_snapshot_revision_ref",
    "media_snapshot_content_hash",
    "session_ref",
    "bounds",
    "streams",
    "synchronization",
    "labels",
    "ground_truth_eligible_label_refs",
    "controller_recorded_label_refs",
    "exception_labels",
    "determinism",
    "registry_status",
    "admitted_at",
    "succession",
    "migration",
    "constants",
    "authority_nonclaim",
    "inferred_label_is_never_ground_truth",
    "episode_is_not_a_skill_or_workflow",
];

pub(crate) static EPISODE: FamilySpec = FamilySpec {
    owner_namespace: "observation-action-episode-revisions",
    resource_kind: "observation_action_episode",
    admit_op: "observation_action_episode.admit_revision",
    payload_schema: "ioi.hypervisor.observation-action-episode-admission.v1",
    contract_id: "schema://ioi/foundations/objects/observation-action-episode/v1",
    schema_version: "ioi.observation-action-episode.v1",
    record_key: "observation_action_episode_record",
    code_prefix: "observation_action_episode",
    commitment_domain: "ioi.observation-action-episode-content-commitment-jcs-sha256.v1",
    material_fields: EPISODE_MATERIAL,
    identity_field: "revision_ref",
    ref_scheme: "episode://",
    stamp_field: "admitted_at",
};

const SPLIT_MATERIAL: &[&str] = &[
    "schema_version",
    "split_manifest_id",
    "revision_ref",
    "owner_ref",
    "tenant_ref",
    "principal_resolution",
    "resolved_principal_ref",
    "members",
    "splits",
    "all_member_episode_revision_refs",
    "member_count",
    "membership_is_immutable",
    "leakage_controls",
    "registry_status",
    "admitted_at",
    "succession",
    "migration",
    "constants",
    "authority_nonclaim",
    "manifest_selects_no_evaluation_evidence_for_its_own_producer",
];

pub(crate) static SPLIT: FamilySpec = FamilySpec {
    owner_namespace: "dataset-split-manifest-revisions",
    resource_kind: "dataset_split_manifest",
    admit_op: "dataset_split_manifest.admit_revision",
    payload_schema: "ioi.hypervisor.dataset-split-manifest-admission.v1",
    contract_id: "schema://ioi/foundations/objects/dataset-split-manifest/v1",
    schema_version: "ioi.dataset-split-manifest.v1",
    record_key: "dataset_split_manifest_record",
    code_prefix: "dataset_split_manifest",
    commitment_domain: "ioi.dataset-split-manifest-content-commitment-jcs-sha256.v1",
    material_fields: SPLIT_MATERIAL,
    identity_field: "revision_ref",
    ref_scheme: "split-manifest://",
    stamp_field: "admitted_at",
};

const CENSUS_MATERIAL: &[&str] = &[
    "schema_version",
    "corpus_census_id",
    "owner_ref",
    "tenant_ref",
    "principal_resolution",
    "resolved_principal_ref",
    "claimed_scale",
    "profile",
    "corpus_content_root",
    "raw",
    "accepted",
    "rejected",
    "deduplicated",
    "deduplication_policy",
    "payload_custody",
    "does_not_claim_custody_of_imported_media_bytes",
    "file_dispositions",
    "distinct_payloads",
    "near_duplicate_exclusions",
    "profile_required_label_classes",
    "observed_label_classes",
    "floors",
    "ceilings",
    "runtime_evidence",
    "degeneracy_findings",
    "distinct_content_hash_count",
    "does_not_claim_hours_scale_qualification",
    "does_not_claim_throughput_or_latency",
    "admitted_at",
    "constants",
    "authority_nonclaim",
];

pub(crate) static CENSUS: FamilySpec = FamilySpec {
    owner_namespace: "media-corpus-censuses",
    resource_kind: "media_corpus_census",
    admit_op: "media_corpus_census.admit_census",
    payload_schema: "ioi.hypervisor.media-corpus-census-admission.v1",
    contract_id: "schema://ioi/foundations/objects/media-corpus-qualification-census/v1",
    schema_version: "ioi.media-corpus-qualification-census.v1",
    record_key: "media_corpus_census_record",
    code_prefix: "media_corpus_census",
    commitment_domain: "ioi.media-corpus-qualification-census-content-commitment-jcs-sha256.v1",
    material_fields: CENSUS_MATERIAL,
    identity_field: "corpus_census_id",
    // CONTENT-ADDRESSED, NOT NUMBERED: the census IS its corpus's digest, so two runs over the same
    // corpus collide by construction and a shortened corpus cannot hide behind a fresh identity.
    ref_scheme: "corpus-census://",
    stamp_field: "admitted_at",
};

// ===================================================================== small shared readers

fn item_str(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn item_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn nested_u64(value: &Value, pointer: &str) -> Option<u64> {
    value.pointer(pointer).and_then(Value::as_u64)
}

/// The total bytes this route will regenerate for one census before it refuses to keep going.
///
/// Regeneration is the whole point of recipe-borne custody, but it is also work a caller asks for,
/// so it is BOUNDED rather than trusted: 64 blocks of up to 64 KiB across up to a million payloads
/// would be terabytes. The bound sits at the corpus byte ceiling because a corpus that would
/// regenerate more than it is allowed to accept is already outside its own limits.
const MAX_REGENERATED_BYTES: u64 = 2_147_483_648;

/// Regenerate a payload from its recipe — THE STEP THAT MAKES THIS SEAM MORE THAN LABEL MATCHING.
///
/// Without it, `content_sha256`, `byte_count` and `similarity_fingerprint` are three caller-supplied
/// fields, and comparing any of them to any other is label-to-label validation: a fabricated but
/// internally consistent corpus would pass every cross-check the record can express. Regenerating
/// the bytes here gives the runtime its own copy to digest, measure and fingerprint, so all three
/// become DERIVED and a fabricated payload has nothing left to agree with.
fn regenerate_payload(recipe: &Value) -> Option<Vec<u8>> {
    if item_str(recipe, "recipe_method") != "ioi.m059.two-level-block-payload.v1" {
        return None;
    }
    let blocks = item_u64(recipe, "block_count")? as usize;
    let width = item_u64(recipe, "block_width_bytes")? as usize;
    let low = u8::try_from(item_u64(recipe, "low_level")?).ok()?;
    let high = u8::try_from(item_u64(recipe, "high_level")?).ok()?;
    if blocks != 64 || width == 0 || width > 65_536 {
        return None;
    }
    let flipped: BTreeSet<u64> = recipe
        .get("flipped_blocks")?
        .as_array()?
        .iter()
        .filter_map(Value::as_u64)
        .collect();
    let seed = Sha256::digest(
        format!("ioi.m059.corpus.payload:{}", item_str(recipe, "seed_tag")).as_bytes(),
    );
    let mut bytes = vec![0u8; blocks * width];
    for block in 0..blocks {
        let bit = (seed[block >> 3] >> (block & 7)) & 1;
        let level = if (bit == 1) != flipped.contains(&(block as u64)) {
            high
        } else {
            low
        };
        bytes[block * width..(block + 1) * width].fill(level);
    }
    Some(bytes)
}

/// `perceptual-block-mean-hamming-64`, computed over bytes THIS PROCESS produced.
fn similarity_fingerprint(bytes: &[u8]) -> Option<String> {
    let width = bytes.len() / 64;
    if width == 0 {
        return None;
    }
    let sums: Vec<u64> = (0..64)
        .map(|block| {
            bytes[block * width..(block + 1) * width]
                .iter()
                .map(|byte| u64::from(*byte))
                .sum()
        })
        .collect();
    let total: u64 = sums.iter().sum();
    let mut hex = String::with_capacity(16);
    for nibble in 0..16 {
        let mut value = 0u8;
        for bit in 0..4 {
            // `sum > mean` without dividing, so the comparison stays in integers.
            let over = sums[nibble * 4 + bit] * 64 > total;
            value = (value << 1) | u8::from(over);
        }
        hex.push(char::from_digit(u32::from(value), 16)?);
    }
    Some(hex)
}

/// The bitwise distance between two equal-length lowercase-hex similarity digests.
///
/// THIS IS WHY THE CENSUS CARRIES BOTH FINGERPRINTS. Exact duplication is decidable from a content
/// digest alone, but near duplication is a JUDGEMENT, and a census that reported only the excluded
/// file's fingerprint beside a distance would be reporting a number nobody could re-derive. With
/// both sides present the judgement is re-decidable by anyone holding the record — no daemon, no
/// payload bytes, no registry read — which is the difference between evidence and assertion.
/// `None` when the two digests are not comparable, because a distance between digests of different
/// lengths or non-hex content is undefined rather than large.
fn hamming_distance_hex(left: &str, right: &str) -> Option<u64> {
    if left.is_empty() || left.len() != right.len() {
        return None;
    }
    let mut distance = 0u64;
    for (a, b) in left.bytes().zip(right.bytes()) {
        if !a.is_ascii_hexdigit() || a.is_ascii_uppercase() {
            return None;
        }
        if !b.is_ascii_hexdigit() || b.is_ascii_uppercase() {
            return None;
        }
        let a = (a as char).to_digit(16)?;
        let b = (b as char).to_digit(16)?;
        distance += u64::from((a ^ b).count_ones());
    }
    Some(distance)
}

fn object_list(
    body: &Value,
    key: &str,
    limit: usize,
    spec: &FamilySpec,
) -> Result<Vec<Value>, Reply> {
    let Some(items) = body.get(key).and_then(Value::as_array) else {
        return Err(refuse(
            &spec.code("list_not_canonical"),
            format!("'{key}' is a JSON array of objects; an absent or scalar value is refused rather than read as empty"),
        ));
    };
    if items.len() > limit {
        return Err(refuse(
            &spec.code("list_too_long"),
            format!(
                "'{key}' carries {} entries; this contract bounds it at {limit}",
                items.len()
            ),
        ));
    }
    if items.iter().any(|item| !item.is_object()) {
        return Err(refuse(
            &spec.code("list_not_canonical"),
            format!("every '{key}' entry is an object"),
        ));
    }
    Ok(items.clone())
}

fn string_list(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

// ===================================================================== the snapshot owner seam

/// One exact admitted snapshot revision, resolved under the CALLER'S OWN owner binding.
///
/// THE OWNER SEAM THIS MODULE PUBLISHES. An episode binds a snapshot and a census counts over one;
/// each writing its own reader is how a family acquires a second interpretation of its own truth.
/// A family head is refused by the ref grammar rather than resolved to "latest", because an episode
/// that bound `media-snapshot://acme.desk` would be cut from whichever bytes that family last held.
pub(crate) struct ResolvedMediaSnapshot {
    pub(crate) revision_ref: String,
    pub(crate) tenant_ref: String,
    pub(crate) content_hash: String,
    pub(crate) record: Value,
    pub(crate) index_state: &'static str,
}

impl ResolvedMediaSnapshot {
    pub(crate) fn timebase_id(&self) -> String {
        self.record
            .pointer("/timebase/timebase_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    pub(crate) fn session_ref(&self) -> String {
        self.record
            .pointer("/capture_binding/session_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    pub(crate) fn permits_learned_use(&self) -> bool {
        self.record
            .pointer("/source_rights/permits_learned_use")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    pub(crate) fn is_active(&self) -> bool {
        self.record.get("registry_status").and_then(Value::as_str) == Some("active")
    }
}

pub(crate) fn resolve_admitted_media_snapshot(
    data_dir: &str,
    identity: &RequestIdentity,
    expected_owner_ref: Option<&str>,
    revision_ref: &str,
) -> Result<ResolvedMediaSnapshot, Reply> {
    let Some((family, ordinal)) = parse_revision_ref(SNAPSHOT.ref_scheme, revision_ref) else {
        return Err(refuse(
            &SNAPSHOT.code("revision_ref_not_canonical"),
            "a snapshot binding names media-snapshot://<family>/revision/<n>; a family head or a mutable-latest reference is refused where a revision is required",
        ));
    };
    let resource = format!("{}{family}", SNAPSHOT.ref_scheme);
    let scope = authorize_request_resource_scope(
        data_dir,
        identity,
        SNAPSHOT.resource_kind,
        &resource,
        expected_owner_ref,
    )
    .map_err(scope_refusal_reply)?;
    let stream = read_stream(&SNAPSHOT, data_dir, identity, &scope, &resource)?;
    let index_state = projection_cache_state(&resource, &stream);
    let wanted = format!("{resource}/revision/{ordinal}");
    let Some(entry) = stream
        .iter()
        .find(|entry| entry.record.get("revision_ref") == Some(&json!(wanted)))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &SNAPSHOT.code("revision_absent"),
            "this snapshot family has no admitted revision at that ordinal; an absent revision is a typed absence, never the nearest one",
        ));
    };
    Ok(ResolvedMediaSnapshot {
        revision_ref: wanted,
        tenant_ref: item_str(&entry.record, "tenant_ref"),
        content_hash: item_str(&entry.record, "content_hash"),
        record: entry.record.clone(),
        index_state,
    })
}

/// One exact admitted episode revision. The split manifest's seam.
pub(crate) struct ResolvedObservationActionEpisode {
    pub(crate) revision_ref: String,
    pub(crate) tenant_ref: String,
    pub(crate) content_hash: String,
    pub(crate) record: Value,
}

impl ResolvedObservationActionEpisode {
    pub(crate) fn snapshot_revision_ref(&self) -> String {
        item_str(&self.record, "media_snapshot_revision_ref")
    }

    pub(crate) fn max_tick(&self) -> u64 {
        nested_u64(&self.record, "/bounds/end_tick").unwrap_or(0)
    }
}

pub(crate) fn resolve_admitted_observation_action_episode(
    data_dir: &str,
    identity: &RequestIdentity,
    expected_owner_ref: Option<&str>,
    revision_ref: &str,
) -> Result<ResolvedObservationActionEpisode, Reply> {
    let Some((family, ordinal)) = parse_revision_ref(EPISODE.ref_scheme, revision_ref) else {
        return Err(refuse(
            &EPISODE.code("revision_ref_not_canonical"),
            "an episode binding names episode://<family>/revision/<n>; a family head is refused where a revision is required",
        ));
    };
    let resource = format!("{}{family}", EPISODE.ref_scheme);
    let scope = authorize_request_resource_scope(
        data_dir,
        identity,
        EPISODE.resource_kind,
        &resource,
        expected_owner_ref,
    )
    .map_err(scope_refusal_reply)?;
    let stream = read_stream(&EPISODE, data_dir, identity, &scope, &resource)?;
    let wanted = format!("{resource}/revision/{ordinal}");
    let Some(entry) = stream
        .iter()
        .find(|entry| entry.record.get("revision_ref") == Some(&json!(wanted)))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &EPISODE.code("revision_absent"),
            "this episode family has no admitted revision at that ordinal",
        ));
    };
    Ok(ResolvedObservationActionEpisode {
        revision_ref: wanted,
        tenant_ref: item_str(&entry.record, "tenant_ref"),
        content_hash: item_str(&entry.record, "content_hash"),
        record: entry.record.clone(),
    })
}

// ===================================================================== POST media snapshots

/// POST /v1/hypervisor/media-snapshot-revisions
pub(crate) async fn handle_media_snapshot_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let spec = &SNAPSHOT;
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &spec.code("owner_scheme_unsupported"))
    {
        return response;
    }
    if let Err(response) = reject_authored(&body, spec, SNAPSHOT_SERVER_RESOLVED) {
        return response;
    }
    let family = body_str(&body, "family");
    if !family_token(&family) {
        return refuse(
            &spec.code("family_not_canonical"),
            "'family' is the lineage token this revision extends: [a-z0-9][a-z0-9._-]{0,127}",
        );
    }
    let resource = format!("{}{family}", spec.ref_scheme);
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        spec.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(spec, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    // REPLAY BEFORE PRECONDITIONS: a retry after an ambiguous response necessarily observes a newer
    // head than the one it first compare-and-swapped against.
    match replay_for_key(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "media_snapshot",
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let expected_head = match head_assertion(&body, spec.code_prefix) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, spec.code_prefix) {
        return response;
    }
    let recorded_at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));
    if recorded_at_ms == 0 {
        return refuse(
            &spec.code("effective_at_not_canonical"),
            "'effective_at' is the RFC3339 instant this admission is stamped with; an absent or malformed stamp reads as absent, never as zero-o'clock",
        );
    }

    let acquisition_class = body_str(&body, "acquisition_class");
    if !matches!(
        acquisition_class.as_str(),
        "imported_recording" | "live_demonstration"
    ) {
        return refuse(
            &spec.code("acquisition_class_outside_vocabulary"),
            "'acquisition_class' is imported_recording or live_demonstration; imported media must not silently become a live-capture dependency",
        );
    }

    let tenant_ref = contract_tenant_ref(&caller.owner_ref);

    // ---------------------------------------------------------- the timebase, retained not repaired
    let timebase = match body_object(&body, "timebase", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if timebase.get("declared_monotonic").and_then(Value::as_bool) != Some(true) {
        return refuse(
            &spec.code("timebase_not_declared_monotonic"),
            "a snapshot declares ONE monotonic timebase; a non-monotonic declaration is refused rather than repaired, and the irregularity is recorded as a retained discontinuity instead",
        );
    }
    if body
        .get("normalize_discontinuities")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return refuse(
            &spec.code("discontinuity_normalization_refused"),
            "reordering, gaps and clock regression are DETECTED AND RETAINED, never normalized away; a run that sorted a clock regression into order destroyed the evidence ACC-16 clause 3 preserves",
        );
    }

    // ---------------------------------------------------------- ingest quality, refused by name
    let quality_findings = match object_list(&body, "quality_findings", 4096, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    for finding in &quality_findings {
        let class = item_str(finding, "finding_class");
        let severity = item_str(finding, "severity");
        if NEVER_RETAINED_FINDINGS.contains(&class.as_str())
            && !REFUSING_SEVERITIES.contains(&severity.as_str())
        {
            return refuse(
                &spec.code("degraded_input_retained_instead_of_refused"),
                format!(
                    "a '{class}' finding carries severity '{severity}'; corrupt, truncated and variable-rate input is refused or excluded BY NAME and never repaired, padded or absorbed into an accepted corpus"
                ),
            );
        }
    }

    // ---------------------------------------------------------- CAPTURE RIGHTS: refuses every profile
    let capture_rights_ref = body_str(&body, "capture_rights_revision_ref");
    let capture_claim = match resolve_admitted_source_rights_claim(
        &st.data_dir,
        &caller.identity,
        Some(&caller.owner_ref),
        &capture_rights_ref,
    ) {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    if capture_claim.tenant_ref != tenant_ref {
        return refuse(
            &spec.code("cross_tenant_capture_rights_refused"),
            format!(
                "the capture-rights claim carries {} while this snapshot is bound to {tenant_ref}; a rights claim belonging to another tenant is inadmissible rather than a discovery after the bytes moved",
                capture_claim.tenant_ref
            ),
        );
    }
    if !capture_claim.is_live() || capture_claim.expires_before(recorded_at_ms) {
        return refuse(
            &spec.code("capture_rights_not_live"),
            "the capture-rights claim is expired or revoked at this admission instant; MISSING CAPTURE RIGHTS REFUSES EVERY PROFILE, procedural included (ACC-16 clause 1)",
        );
    }

    // -------------------------------- LEARNED RIGHTS: refuses only the learned claim, not procedural
    let learned_claim_refs = string_list(&body, "learning_source_rights_claim_revision_refs");
    let mut resolved_claims = Vec::new();
    let mut permits_learned_use = !learned_claim_refs.is_empty();
    for claim_ref in &learned_claim_refs {
        let claim = match resolve_admitted_source_rights_claim(
            &st.data_dir,
            &caller.identity,
            Some(&caller.owner_ref),
            claim_ref,
        ) {
            Ok(claim) => claim,
            Err(response) => return response,
        };
        if claim.tenant_ref != tenant_ref {
            return refuse(
                &spec.code("cross_tenant_source_rights_refused"),
                format!("source-rights claim '{claim_ref}' belongs to another tenant"),
            );
        }
        // A claim that is not live does not refuse the SNAPSHOT — it refuses the LEARNED CLAIM.
        // That asymmetry is ACC-16 clause 1 and it is the whole reason this is a derivation rather
        // than a validation.
        if !claim.is_live() || claim.expires_before(recorded_at_ms) {
            permits_learned_use = false;
        }
        resolved_claims.push(json!({
            "claim_revision_ref": claim.revision_ref,
            "claim_content_hash": claim.content_hash,
            "live_at_admission": claim.is_live() && !claim.expires_before(recorded_at_ms),
        }));
    }

    // ---------------------------------------------------------- consent must ride an admitted claim
    let consent_bindings = match object_list(&body, "consent_bindings", 64, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let covered_bases: BTreeSet<String> = resolved_claims
        .iter()
        .filter_map(|c| c.get("claim_revision_ref").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    for binding in &consent_bindings {
        if item_str(binding, "consent_state") != "active" {
            permits_learned_use = false;
        }
        if covered_bases.is_empty() {
            return refuse(
                &spec.code("consent_without_a_covering_claim"),
                "a consent held outside every admitted source-rights claim is REFUSED rather than trusted from the record's own consent_state; a state a caller attested is not a state anyone can recheck",
            );
        }
    }

    // ---------------------------------------------------------- the policy-bound views (M05.8 seam)
    let view_refs = string_list(&body, "policy_bound_data_view_revision_refs");
    let mut resolved_views = Vec::new();
    for view_ref in &view_refs {
        let view = match resolve_admitted_policy_bound_data_view(
            &st.data_dir,
            &caller.identity,
            Some(&caller.owner_ref),
            view_ref,
        ) {
            Ok(view) => view,
            Err(response) => return response,
        };
        if view.tenant_ref != tenant_ref {
            return refuse(
                &spec.code("cross_tenant_view_refused"),
                format!(
                    "policy-bound view '{view_ref}' carries {} while this snapshot is bound to {tenant_ref}",
                    view.tenant_ref
                ),
            );
        }
        if !view.is_active() {
            // A view that allows nothing cannot make a capture learnable.
            permits_learned_use = false;
        }
        resolved_views.push(json!({
            "view_revision_ref": view.revision_ref,
            "view_content_hash": view.content_hash,
            "view_allowed_uses": view.allowed_uses(),
            "view_active_at_binding": view.is_active(),
        }));
    }
    // THE BYTES A LEARNED USE READS RIDE A PROVED VIEW. Without one, the learned claim is
    // inadmissible while the procedural path stays open.
    if view_refs.is_empty() {
        permits_learned_use = false;
    }

    // ---------------------------------------------------------- quarantine gates the learned claim
    let quarantine = match body_object(&body, "quarantine", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if item_str(&quarantine, "quarantine_state") != "accepted" {
        permits_learned_use = false;
    }

    let registry_status = body_str(&body, "registry_status");
    if !matches!(
        registry_status.as_str(),
        "draft" | "active" | "suspended" | "expired" | "superseded" | "revoked"
    ) {
        return refuse(
            &spec.code("registry_status_outside_vocabulary"),
            "'registry_status' is one of draft|active|suspended|expired|superseded|revoked",
        );
    }
    if registry_status != "active" {
        permits_learned_use = false;
    }

    // ---------------------------------------------------------- redaction reduces, creates nothing
    let redaction = match body_object(&body, "redaction", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if redaction.get("creates_permission").and_then(Value::as_bool) == Some(true) {
        return refuse(
            &spec.code("redaction_as_permission_refused"),
            "redaction reduces exposure and creates NOTHING; a caller declaring creates_permission is refused BY NAME rather than having the field corrected underneath it",
        );
    }
    if redaction.get("severs_lineage").and_then(Value::as_bool) == Some(true) {
        return refuse(
            &spec.code("redaction_severs_lineage_refused"),
            "redaction never severs lineage; a redacted snapshot still cites what it was derived from",
        );
    }
    if item_str(&redaction, "source_privacy_class") != item_str(&redaction, "output_privacy_class")
    {
        return refuse(
            &spec.code("redaction_declassifies_refused"),
            "the redacted output's privacy class must equal its source class; a silently repaired declassification is a declassification that happened and was not recorded, and declassification stays Governance-owned",
        );
    }
    let recipe = match resolve_admitted_data_recipe(
        &st.data_dir,
        &caller.identity,
        &item_str(&redaction, "recipe_revision_ref"),
    ) {
        Ok(recipe) => recipe,
        Err(response) => return response,
    };

    // ---------------------------------------------------------- source-impact lineage (M05.7 seams)
    let lineage = match body_object(&body, "source_impact_lineage", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut resolved_lineage = Vec::new();
    for recipe_ref in string_list(&lineage, "data_recipe_revision_refs") {
        match resolve_admitted_data_recipe(&st.data_dir, &caller.identity, &recipe_ref) {
            Ok(r) => resolved_lineage.push(json!({"kind": "data_recipe", "revision_ref": r.revision_ref, "content_hash": r.content_hash})),
            Err(response) => return response,
        }
    }
    for mapping_ref in string_list(&lineage, "connector_mapping_revision_refs") {
        match resolve_admitted_connector_mapping(&st.data_dir, &caller.identity, &mapping_ref) {
            Ok(m) => resolved_lineage.push(json!({"kind": "connector_mapping", "revision_ref": m.revision_ref, "content_hash": m.content_hash})),
            Err(response) => return response,
        }
    }
    for run_ref in string_list(&lineage, "transformation_run_refs") {
        match resolve_admitted_transformation_run(&st.data_dir, &caller.identity, &run_ref) {
            Ok(r) => resolved_lineage.push(json!({"kind": "transformation_run", "run_id": r.transformation_run_id, "content_hash": r.content_hash})),
            Err(response) => return response,
        }
    }

    // ---------------------------------------------------------- artifacts and the census closure
    let artifact_bindings = match object_list(&body, "artifact_bindings", 4096, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if artifact_bindings.is_empty() {
        return refuse(
            &spec.code("artifact_bindings_required"),
            "a snapshot over no bytes is not a snapshot; admitting one would let an audit count an empty capture as coverage",
        );
    }
    let mut seen_digests = BTreeSet::new();
    for binding in &artifact_bindings {
        let digest = item_str(binding, "sha256");
        if !is_sha256(&digest) {
            return refuse(
                &spec.code("artifact_digest_not_canonical"),
                "every artifact binding names sha256:<64 lowercase hex>; a ref names a location that may since have been re-admitted, and the digest names what was actually bound",
            );
        }
        if !seen_digests.insert(digest.clone()) {
            return refuse(
                &spec.code("repeated_artifact_digest_refused"),
                format!("artifact digest {digest} appears twice; a repeated payload is a degenerate corpus inflating its own census by restating the same bytes"),
            );
        }
    }

    let raw_census = match body_object(&body, "raw_census", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let accepted_census = match body_object(&body, "accepted_census", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    for key in ["source_seconds", "byte_count"] {
        let accepted = item_u64(&accepted_census, key).unwrap_or(u64::MAX);
        let raw = item_u64(&raw_census, key).unwrap_or(0);
        if accepted > raw {
            return refuse(
                &spec.code("accepted_exceeds_raw"),
                format!("accepted {key} exceeds raw {key}; a corpus cannot grow across acceptance, and one that did is padding wearing an acceptance's clothes"),
            );
        }
    }
    if item_u64(&accepted_census, "file_count") != Some(artifact_bindings.len() as u64) {
        return refuse(
            &spec.code("accepted_file_count_drift"),
            "the declared accepted file count disagrees with the artifact bindings enumerated; two independent statements about one set is what stops a file being dropped from the readable list after the fact",
        );
    }

    let record = json!({
        "schema_version": spec.schema_version,
        "media_snapshot_id": resource,
        "revision_ref": format!("{resource}/revision/{}", stream.len() + 1),
        "owner_ref": caller.owner_ref,
        "tenant_ref": tenant_ref,
        "principal_resolution": "server_resolved",
        "resolved_principal_ref": caller.identity.principal_ref,
        "acquisition_class": acquisition_class,
        "capture_binding": match body_object(&body, "capture_binding", spec) {
            Ok(value) => value,
            Err(response) => return response,
        },
        "source_rights": {
            "capture_rights_revision_ref": capture_claim.revision_ref,
            "learning_source_rights_claim_revision_refs": learned_claim_refs,
            "consent_bindings": consent_bindings,
            // DERIVED, NEVER AUTHORED.
            "permits_learned_use": permits_learned_use,
        },
        "policy_bound_data_view_revision_refs": view_refs,
        "timebase": timebase,
        "valid_time": match body_object(&body, "valid_time", spec) {
            Ok(value) => value,
            Err(response) => return response,
        },
        "artifact_bindings": artifact_bindings,
        "availability": match body_object(&body, "availability", spec) {
            Ok(value) => value,
            Err(response) => return response,
        },
        "information_flow_label_refs": string_list(&body, "information_flow_label_refs"),
        "quarantine": quarantine,
        "redaction": redaction,
        "deduplication": match body_object(&body, "deduplication", spec) {
            Ok(value) => value,
            Err(response) => return response,
        },
        "quality_findings": quality_findings,
        "source_impact_lineage": lineage,
        "raw_census": raw_census,
        "accepted_census": accepted_census,
        "registry_status": registry_status,
        "admitted_at": admitted_stamp(recorded_at_ms),
        "succession": {
            "predecessor_revision_ref": Value::Null,
            "predecessor_content_hash": Value::Null,
        },
        "migration": { "compatibility": "initial", "downgrade_to_predecessor": "refused" },
        "constants": { "commitment_domain": spec.commitment_domain },
        "authority_nonclaim": "policy_bound_media_snapshot_grants_no_authority",
        "artifact_authority": "none — an active ArtifactRef names bytes and grants no read, no replay, no current authority",
        "capture_authority_does_not_travel_into_replay": true,
        "demonstration_is_not_consent": true,
        "snapshot_is_not_a_skill_or_workflow": true,
    });

    finish_admission(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        "media_snapshot",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({
            "resolved_capture_rights": capture_claim.revision_ref,
            "resolved_source_rights_claims": resolved_claims,
            "resolved_policy_bound_views": resolved_views,
            "resolved_redaction_recipe": recipe.revision_ref,
            "resolved_source_impact_lineage": resolved_lineage,
            "permits_learned_use_is_derived_not_authored": true,
            "observation_is_not_consent": true,
        }),
    )
}

// ===================================================================== POST episodes

/// POST /v1/hypervisor/observation-action-episode-revisions
pub(crate) async fn handle_episode_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let spec = &EPISODE;
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &spec.code("owner_scheme_unsupported"))
    {
        return response;
    }
    if let Err(response) = reject_authored(&body, spec, EPISODE_SERVER_RESOLVED) {
        return response;
    }
    let family = body_str(&body, "family");
    if !family_token(&family) {
        return refuse(
            &spec.code("family_not_canonical"),
            "'family' is the lineage token this revision extends",
        );
    }
    let resource = format!("{}{family}", spec.ref_scheme);
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        spec.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(spec, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    match replay_for_key(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "observation_action_episode",
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let expected_head = match head_assertion(&body, spec.code_prefix) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, spec.code_prefix) {
        return response;
    }
    let recorded_at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));
    if recorded_at_ms == 0 {
        return refuse(
            &spec.code("effective_at_not_canonical"),
            "'effective_at' is the RFC3339 instant this admission is stamped with",
        );
    }

    // ---------------------------------------------------------- the snapshot, through its own seam
    let snapshot_ref = body_str(&body, "media_snapshot_revision_ref");
    let snapshot = match resolve_admitted_media_snapshot(
        &st.data_dir,
        &caller.identity,
        Some(&caller.owner_ref),
        &snapshot_ref,
    ) {
        Ok(snapshot) => snapshot,
        Err(response) => return response,
    };
    let tenant_ref = contract_tenant_ref(&caller.owner_ref);
    if snapshot.tenant_ref != tenant_ref {
        return refuse(
            &spec.code("cross_tenant_snapshot_refused"),
            format!(
                "the bound snapshot carries {} while this episode is bound to {tenant_ref}",
                snapshot.tenant_ref
            ),
        );
    }
    // THE BYTES, NOT ONLY THE REF. A committed hash that disagrees with what the owner serves right
    // now means the snapshot was re-admitted underneath this episode.
    let asserted_hash = body_str(&body, "media_snapshot_content_hash");
    if !asserted_hash.is_empty() && asserted_hash != snapshot.content_hash {
        return refuse(
            &spec.code("snapshot_content_hash_drifted"),
            "the asserted snapshot content hash is not what its owner currently serves; a ref names a location that may since have been re-admitted, and this is how that re-admission becomes detectable",
        );
    }
    if !snapshot.is_active() {
        return refuse(
            &spec.code("snapshot_not_active"),
            "an episode may only be cut from an ACTIVE snapshot; a suspended, expired, superseded or revoked capture is not eligible material",
        );
    }

    // ---------------------------------------------------------- the timebase must be the SAME one
    let bounds = match body_object(&body, "bounds", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let episode_timebase = item_str(&bounds, "timebase_id");
    if episode_timebase != snapshot.timebase_id() {
        return refuse(
            &spec.code("episode_timebase_differs_from_its_snapshot"),
            format!(
                "this episode declares timebase '{episode_timebase}' while its snapshot declares '{}'; an episode measured on a clock nobody declared has bounds no one can check",
                snapshot.timebase_id()
            ),
        );
    }
    let start_tick = item_u64(&bounds, "start_tick").unwrap_or(0);
    let end_tick = item_u64(&bounds, "end_tick").unwrap_or(0);
    if start_tick >= end_tick {
        return refuse(
            &spec.code("episode_bounds_not_forward"),
            "an episode is an interval, not a point or a reversal; a start tick at or after the end tick is the shape a reordered timebase produces",
        );
    }

    // ---------------------------------------------------------- synchronization envelope
    let synchronization = match body_object(&body, "synchronization", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let observed = item_u64(&synchronization, "max_observed_skew_ticks").unwrap_or(u64::MAX);
    let envelope = item_u64(&synchronization, "declared_skew_envelope_ticks").unwrap_or(0);
    if observed > envelope {
        return refuse(
            &spec.code("observed_skew_exceeds_declared_envelope"),
            format!("observed frame/action skew {observed} exceeds the declared envelope {envelope}; absorbing it would attribute actions to the wrong frames and produce a mislabel that reads as data"),
        );
    }

    // ---------------------------------------------------------- THE LABEL RULE, THIRD EXPRESSION
    let labels = match object_list(&body, "labels", 100_000, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if labels.is_empty() {
        return refuse(
            &spec.code("labels_required"),
            "an episode with no labels is not evidence about anything",
        );
    }
    let mut seen_label_refs = BTreeSet::new();
    let mut controller_recorded = Vec::new();
    for label in &labels {
        let label_ref = item_str(label, "label_ref");
        if !seen_label_refs.insert(label_ref.clone()) {
            return refuse(
                &spec.code("repeated_label_ref_refused"),
                format!("label ref {label_ref} appears twice; a repeated label lets one annotation be counted twice toward a required class"),
            );
        }
        let provenance = item_str(label, "label_provenance_class");
        let status = item_str(label, "epistemic_status");
        let claims_ground_truth = label
            .get("is_controller_ground_truth")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if INFERRED_LABEL_PROVENANCE.contains(&provenance.as_str()) {
            if claims_ground_truth {
                return refuse(
                    &spec.code("inferred_label_claims_controller_ground_truth"),
                    format!("label '{label_ref}' is {provenance} and claims controller ground truth; A VIDEO-INFERRED ACTION REMAINS AN UNCERTAIN ATTRIBUTED LABEL and never silently becomes controller ground truth (ACC-16 clause 10)"),
                );
            }
            if status != "uncertain_attributed_label" {
                return refuse(
                    &spec.code("inferred_label_claims_certain_status"),
                    format!("label '{label_ref}' is {provenance} but carries epistemic_status '{status}'; an inferred label is an attribution and its status is uncertain_attributed_label, refused here rather than defaulted underneath the caller"),
                );
            }
        }
        if claims_ground_truth {
            if provenance != CONTROLLER_RECORDED {
                return refuse(
                    &spec.code("ground_truth_claimed_without_a_controller_stream"),
                    format!("label '{label_ref}' claims controller ground truth from provenance '{provenance}'; only an admitted controller stream supports that claim"),
                );
            }
            controller_recorded.push(label_ref);
        }
    }

    let session_ref = snapshot.session_ref();
    let record = json!({
        "schema_version": spec.schema_version,
        "episode_id": resource,
        "revision_ref": format!("{resource}/revision/{}", stream.len() + 1),
        "owner_ref": caller.owner_ref,
        "tenant_ref": tenant_ref,
        "principal_resolution": "server_resolved",
        "resolved_principal_ref": caller.identity.principal_ref,
        "media_snapshot_revision_ref": snapshot.revision_ref,
        // TAKEN FROM THE OWNER, NOT THE CALLER.
        "media_snapshot_content_hash": snapshot.content_hash,
        // INHERITED FROM THE SNAPSHOT, so the two can never disagree.
        "session_ref": session_ref,
        "bounds": bounds,
        "streams": match object_list(&body, "streams", 256, spec) {
            Ok(list) => list,
            Err(response) => return response,
        },
        "synchronization": synchronization,
        "labels": labels,
        // DERIVED FROM THE CONTROLLER-RECORDED SUBSET. A caller cannot offer these at all, which
        // makes a smuggled inferred label UNREPRESENTABLE rather than merely refused.
        "ground_truth_eligible_label_refs": controller_recorded,
        "controller_recorded_label_refs": controller_recorded,
        "exception_labels": match object_list(&body, "exception_labels", 10_000, spec) {
            Ok(list) => list,
            Err(response) => return response,
        },
        "determinism": match body_object(&body, "determinism", spec) {
            Ok(value) => value,
            Err(response) => return response,
        },
        "registry_status": body_str(&body, "registry_status"),
        "admitted_at": admitted_stamp(recorded_at_ms),
        "succession": {
            "predecessor_revision_ref": Value::Null,
            "predecessor_content_hash": Value::Null,
        },
        "migration": { "compatibility": "initial", "downgrade_to_predecessor": "refused" },
        "constants": { "commitment_domain": spec.commitment_domain },
        "authority_nonclaim": "observation_action_episode_grants_no_authority",
        "inferred_label_is_never_ground_truth": true,
        "episode_is_not_a_skill_or_workflow": true,
    });

    finish_admission(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        "observation_action_episode",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({
            "resolved_snapshot_revision_ref": snapshot.revision_ref,
            "resolved_snapshot_content_hash": snapshot.content_hash,
            "snapshot_index_state": snapshot.index_state,
            "inherited_session_ref": session_ref,
            "ground_truth_set_is_derived_not_authored": true,
            "snapshot_permits_learned_use": snapshot.permits_learned_use(),
        }),
    )
}

// ===================================================================== POST split manifests

/// POST /v1/hypervisor/dataset-split-manifest-revisions
pub(crate) async fn handle_split_manifest_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let spec = &SPLIT;
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &spec.code("owner_scheme_unsupported"))
    {
        return response;
    }
    if let Err(response) = reject_authored(&body, spec, SPLIT_SERVER_RESOLVED) {
        return response;
    }
    let family = body_str(&body, "family");
    if !family_token(&family) {
        return refuse(
            &spec.code("family_not_canonical"),
            "'family' is the lineage token this revision extends",
        );
    }
    let resource = format!("{}{family}", spec.ref_scheme);
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        spec.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(spec, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    match replay_for_key(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "dataset_split_manifest",
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let expected_head = match head_assertion(&body, spec.code_prefix) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, spec.code_prefix) {
        return response;
    }
    let recorded_at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));
    if recorded_at_ms == 0 {
        return refuse(
            &spec.code("effective_at_not_canonical"),
            "'effective_at' is the RFC3339 instant this admission is stamped with",
        );
    }

    let members = match object_list(&body, "members", 100_000, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if members.is_empty() {
        return refuse(
            &spec.code("members_required"),
            "a split manifest over no episodes is not a partition",
        );
    }

    let tenant_ref = contract_tenant_ref(&caller.owner_ref);
    let mut seen_members = BTreeSet::new();
    let mut all_refs = Vec::new();
    let mut per_class: BTreeMap<String, u64> = BTreeMap::new();
    let mut resolved_members = Vec::new();
    // Actor/world partition keys per split class, so a holdout that shares an actor or a world with
    // training is refused rather than reported as a clean holdout.
    let mut train_actors: BTreeSet<String> = BTreeSet::new();
    let mut train_worlds: BTreeSet<String> = BTreeSet::new();
    let mut holdout_actors: BTreeSet<String> = BTreeSet::new();
    let mut holdout_worlds: BTreeSet<String> = BTreeSet::new();

    for member in &members {
        let episode_ref = item_str(member, "episode_revision_ref");
        if !seen_members.insert(episode_ref.clone()) {
            return refuse(
                &spec.code("episode_is_a_member_twice"),
                format!("episode '{episode_ref}' is assigned to more than one split; double membership is exactly the leakage ACC-16 clause 8 refuses"),
            );
        }
        let episode = match resolve_admitted_observation_action_episode(
            &st.data_dir,
            &caller.identity,
            Some(&caller.owner_ref),
            &episode_ref,
        ) {
            Ok(episode) => episode,
            Err(response) => return response,
        };
        if episode.tenant_ref != tenant_ref {
            return refuse(
                &spec.code("cross_tenant_member_refused"),
                format!("episode '{episode_ref}' belongs to another tenant"),
            );
        }
        let asserted = item_str(member, "episode_content_hash");
        if !asserted.is_empty() && asserted != episode.content_hash {
            return refuse(
                &spec.code("member_content_hash_drifted"),
                format!("episode '{episode_ref}' was re-admitted since this membership was computed; a frozen membership over drifting bytes is not frozen"),
            );
        }
        let split_class = item_str(member, "split_class");
        *per_class.entry(split_class.clone()).or_insert(0) += 1;
        let actor = item_str(member, "actor_partition_key");
        let world = item_str(member, "world_partition_key");
        match split_class.as_str() {
            "train" => {
                train_actors.insert(actor);
                train_worlds.insert(world);
            }
            "actor_holdout" => {
                holdout_actors.insert(actor);
            }
            "world_holdout" => {
                holdout_worlds.insert(world);
            }
            _ => {}
        }
        all_refs.push(episode_ref.clone());
        resolved_members.push(json!({
            "episode_revision_ref": episode.revision_ref,
            "episode_content_hash": episode.content_hash,
            "snapshot_revision_ref": episode.snapshot_revision_ref(),
            "max_tick": episode.max_tick(),
        }));
    }

    // ACTOR AND WORLD HOLDOUT DISJOINTNESS. A holdout sharing an actor with training is not a
    // holdout; it is training data with a different label on it.
    if let Some(shared) = train_actors.intersection(&holdout_actors).next() {
        return refuse(
            &spec.code("actor_holdout_overlaps_training"),
            format!("actor partition '{shared}' appears in both train and actor_holdout; a holdout that shares an actor with training measures memorization, not transfer"),
        );
    }
    if let Some(shared) = train_worlds.intersection(&holdout_worlds).next() {
        return refuse(
            &spec.code("world_holdout_overlaps_training"),
            format!("world partition '{shared}' appears in both train and world_holdout"),
        );
    }

    // ---------------------------------------------------------- the temporal fence
    let leakage = match body_object(&body, "leakage_controls", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let max_train = item_u64(&leakage, "max_train_tick").unwrap_or(u64::MAX);
    let cut = item_u64(&leakage, "temporal_cut_tick").unwrap_or(0);
    let min_holdout = item_u64(&leakage, "min_temporal_holdout_tick").unwrap_or(0);
    if max_train >= cut {
        return refuse(
            &spec.code("training_crosses_the_temporal_cut"),
            format!("max_train_tick {max_train} is not strictly before temporal_cut_tick {cut}; future-frame leakage is refused by comparison rather than declared absent"),
        );
    }
    if cut > min_holdout {
        return refuse(
            &spec.code("temporal_holdout_begins_before_the_cut"),
            format!("temporal_cut_tick {cut} is after min_temporal_holdout_tick {min_holdout}; a holdout that began before the cut scores the model on material it could have trained on"),
        );
    }

    let splits: Vec<Value> = per_class
        .iter()
        .map(|(split_class, member_count)| json!({"split_class": split_class, "member_count": member_count}))
        .collect();

    let record = json!({
        "schema_version": spec.schema_version,
        "split_manifest_id": resource,
        "revision_ref": format!("{resource}/revision/{}", stream.len() + 1),
        "owner_ref": caller.owner_ref,
        "tenant_ref": tenant_ref,
        "principal_resolution": "server_resolved",
        "resolved_principal_ref": caller.identity.principal_ref,
        "members": members,
        // DERIVED FROM THE ROWS, so the enumerated membership and the rows can never disagree.
        "splits": splits,
        "all_member_episode_revision_refs": all_refs,
        "member_count": members.len(),
        "membership_is_immutable": true,
        "leakage_controls": leakage,
        "registry_status": body_str(&body, "registry_status"),
        "admitted_at": admitted_stamp(recorded_at_ms),
        "succession": {
            "predecessor_revision_ref": Value::Null,
            "predecessor_content_hash": Value::Null,
        },
        "migration": { "compatibility": "initial", "downgrade_to_predecessor": "refused" },
        "constants": { "commitment_domain": spec.commitment_domain },
        "authority_nonclaim": "dataset_split_manifest_grants_no_authority",
        "manifest_selects_no_evaluation_evidence_for_its_own_producer": true,
    });

    finish_admission(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        "dataset_split_manifest",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({
            "resolved_members": resolved_members,
            "membership_is_an_exact_partition": true,
            "membership_is_derived_not_authored": true,
        }),
    )
}

// ===================================================================== POST corpus censuses

/// POST /v1/hypervisor/media-corpus-censuses
pub(crate) async fn handle_corpus_census_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let spec = &CENSUS;
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &spec.code("owner_scheme_unsupported"))
    {
        return response;
    }
    if let Err(response) = reject_authored(&body, spec, CENSUS_SERVER_RESOLVED) {
        return response;
    }
    let family = body_str(&body, "family");
    if !family_token(&family) {
        return refuse(
            &spec.code("family_not_canonical"),
            "'family' is the corpus lineage token this census is filed under",
        );
    }
    let resource = format!("{}{family}", spec.ref_scheme);
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        spec.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(spec, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    match replay_for_key(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "media_corpus_census",
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let expected_head = match head_assertion(&body, spec.code_prefix) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, spec.code_prefix) {
        return response;
    }
    let recorded_at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));
    if recorded_at_ms == 0 {
        return refuse(
            &spec.code("effective_at_not_canonical"),
            "'effective_at' is the RFC3339 instant this admission is stamped with",
        );
    }

    let claimed_scale = body_str(&body, "claimed_scale");
    if !matches!(
        claimed_scale.as_str(),
        "compact_deterministic_fixture" | "hours_scale_qualification"
    ) {
        return refuse(
            &spec.code("claimed_scale_outside_vocabulary"),
            "'claimed_scale' is compact_deterministic_fixture or hours_scale_qualification; neither lane may claim the other's coverage",
        );
    }
    let profile = body_str(&body, "profile");
    if !matches!(
        profile.as_str(),
        "composed-model-harness" | "interactive-learned" | "synthetic-learned-sensitive"
    ) {
        return refuse(
            &spec.code("profile_outside_vocabulary"),
            "'profile' is one of the three ACC-19 reference profiles; a run that silently picked one would let its evidence be filed under another's name",
        );
    }

    let corpus_content_root = body_str(&body, "corpus_content_root");
    if !is_sha256(&corpus_content_root) {
        return refuse(
            &spec.code("corpus_content_root_not_canonical"),
            "'corpus_content_root' is sha256:<64 lowercase hex>; the census IS its corpus's digest",
        );
    }

    let raw = match body_object(&body, "raw", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let accepted = match body_object(&body, "accepted", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let file_dispositions = match object_list(&body, "file_dispositions", 1_000_000, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };

    // ---------------------------------------------------------- the partition closure
    if item_u64(&raw, "file_count") != Some(file_dispositions.len() as u64) {
        return refuse(
            &spec.code("raw_file_without_a_disposition"),
            "every raw file has exactly one disposition row; a file with none is missing from the count rather than silently absorbed",
        );
    }
    // ------------------------------------------- identity, content, and the difference between them
    // THE FIRST VERSION OF THIS ROUTE CONFLATED THE TWO. It keyed distinctness on `content_sha256`
    // alone, so two DISTINCT source files carrying byte-identical content were refused as padding —
    // which is exactly the exact duplication a corpus exists to detect and exclude. The consequence
    // was that `exact_duplicate` could never be earned by any corpus, and content-addressed
    // deduplication was unprovable while appearing to be policed. Identity is keyed here; content
    // is reconciled against the payload table below.
    let mut seen_sources = BTreeSet::new();
    let mut instances: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut row_bytes: u64 = 0;
    for (index, row) in file_dispositions.iter().enumerate() {
        let source_ref = item_str(row, "source_file_ref");
        if !seen_sources.insert(source_ref.clone()) {
            return refuse(
                &spec.code("repeated_source_identity_in_the_corpus"),
                format!("source file {source_ref} appears twice; ONE SOURCE INSTANCE COUNTED TWICE IS PADDING, and PADDED, REPEATED OR OTHERWISE DEGENERATE CORPORA REFUSE (ACC-19 clause 5)"),
            );
        }
        instances
            .entry(item_str(row, "content_sha256"))
            .or_default()
            .push(index);
        row_bytes = row_bytes.saturating_add(item_u64(row, "byte_count").unwrap_or(0));
    }
    // A byte count nobody sums is a claim ABOUT the corpus rather than a measurement OF it.
    if item_u64(&raw, "byte_count") != Some(row_bytes) {
        return refuse(
            &spec.code("raw_bytes_do_not_close_over_the_rows"),
            format!(
                "the raw census claims {} bytes over disposition rows summing to {row_bytes}",
                item_u64(&raw, "byte_count").unwrap_or(0)
            ),
        );
    }

    let distinct_payloads = match object_list(&body, "distinct_payloads", 1_000_000, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    // ---- CUSTODY: the runtime regenerates the bytes and derives all three payload facts itself ----
    // Before this seam every payload fact was caller-supplied, so checking the digest against the
    // byte count against the fingerprint was label-to-label validation: a fabricated corpus that
    // agreed with itself passed. v1 admits recipe-borne custody ONLY, and makes no claim about
    // imported media bytes it never holds.
    // `payload_custody` is PINNED SERVER-SIDE rather than read from the body — a caller that could
    // name its own custody mode could name one nobody implements, and `reject_authored` already
    // refuses the attempt. v1 has exactly one mode and enforces it by regenerating every payload.
    let mut declared: BTreeMap<String, Value> = BTreeMap::new();
    let mut fingerprints: BTreeMap<String, String> = BTreeMap::new();
    let mut regenerated_total: u64 = 0;
    for payload in &distinct_payloads {
        let digest = item_str(payload, "content_sha256");
        let Some(recipe) = payload.get("payload_recipe") else {
            return refuse(
                &spec.code("payload_recipe_required"),
                format!("payload {digest} carries no recipe; under recipe-borne custody a payload the runtime cannot regenerate is a payload it cannot verify"),
            );
        };
        let Some(bytes) = regenerate_payload(recipe) else {
            return refuse(
                &spec.code("payload_recipe_is_not_executable"),
                format!("payload {digest} carries a recipe this version cannot run; an unrunnable recipe is an assertion about bytes, not the bytes"),
            );
        };
        regenerated_total = regenerated_total.saturating_add(bytes.len() as u64);
        if regenerated_total > MAX_REGENERATED_BYTES {
            return refuse(
                &spec.code("corpus_regeneration_exceeds_its_bound"),
                "regenerating this payload table would exceed the corpus byte ceiling; a corpus that must produce more than it may accept is already outside its own limits",
            );
        }
        let derived_digest = sha256_of(&bytes);
        if derived_digest != digest {
            return refuse(
                &spec.code("payload_digest_is_not_of_its_bytes"),
                format!("payload {digest} regenerates to {derived_digest}; THE DIGEST IS OF THE BYTES OR IT IS OF NOTHING"),
            );
        }
        if item_u64(payload, "byte_count") != Some(bytes.len() as u64) {
            return refuse(
                &spec.code("payload_byte_count_is_not_of_its_bytes"),
                format!(
                    "payload {digest} claims {} bytes and regenerates to {}",
                    item_u64(payload, "byte_count").unwrap_or(0),
                    bytes.len()
                ),
            );
        }
        let Some(derived_fingerprint) = similarity_fingerprint(&bytes) else {
            return refuse(
                &spec.code("payload_fingerprint_is_not_computable"),
                format!(
                    "payload {digest} regenerates to bytes no 64-block fingerprint is defined over"
                ),
            );
        };
        if item_str(payload, "similarity_fingerprint") != derived_fingerprint {
            return refuse(
                &spec.code("payload_fingerprint_is_not_of_its_bytes"),
                format!("payload {digest} declares fingerprint {} while its own bytes produce {derived_fingerprint}", item_str(payload, "similarity_fingerprint")),
            );
        }
        if declared.insert(digest.clone(), payload.clone()).is_some() {
            return refuse(
                &spec.code("payload_declared_twice"),
                format!("payload {digest} is listed twice; one payload claiming two canonical instances is how a second accepted copy of the same bytes would slip past the exact-duplicate rule"),
            );
        }
        fingerprints.insert(digest, derived_fingerprint);
    }
    if declared.len() != instances.len() {
        return refuse(
            &spec.code("payload_table_does_not_cover_the_rows"),
            format!("{} distinct payloads are declared over {} observed in the rows; the table IS the corpus's content index, not a summary of it", declared.len(), instances.len()),
        );
    }
    for (digest, rows_at) in &instances {
        let Some(payload) = declared.get(digest) else {
            return refuse(
                &spec.code("payload_table_does_not_cover_the_rows"),
                format!("payload {digest} appears in the rows and not in the payload table"),
            );
        };
        // Every INSTANCE of a payload carries that payload's regenerated length; a row free to
        // state its own size could inflate the byte census over bytes the recipe never produced.
        for index in rows_at {
            if item_u64(&file_dispositions[*index], "byte_count") != item_u64(payload, "byte_count")
            {
                return refuse(
                    &spec.code("row_byte_count_is_not_its_payload_length"),
                    format!(
                        "{} claims {} bytes while payload {digest} regenerates to {}",
                        item_str(&file_dispositions[*index], "source_file_ref"),
                        item_u64(&file_dispositions[*index], "byte_count").unwrap_or(0),
                        item_u64(payload, "byte_count").unwrap_or(0)
                    ),
                );
            }
        }
        if item_u64(payload, "instance_count") != Some(rows_at.len() as u64) {
            return refuse(
                &spec.code("payload_instance_count_drifted"),
                format!(
                    "payload {digest} declares {} instances over {} rows",
                    item_u64(payload, "instance_count").unwrap_or(0),
                    rows_at.len()
                ),
            );
        }
        let accepted_here: Vec<usize> = rows_at
            .iter()
            .copied()
            .filter(|index| item_str(&file_dispositions[*index], "disposition") == "accepted")
            .collect();
        // EXACTLY ONE INSTANCE OF ANY PAYLOAD MAY BE ACCEPTED, and that is enforced ONCE — by the
        // loop below, which requires every non-canonical instance to be filed as an exact duplicate
        // and so refuses a second accepted copy. An extra `accepted_here.len() > 1` guard stood here
        // and refused the same inputs under the same code; two checks that cover each other are two
        // checks NEITHER of which can be shown to work, because disabling either leaves the other to
        // keep the gate green. The mutation battery is what surfaced it: the guard's mutant scored a
        // MISS not because the gate was weak but because the guard was unreachable evidence.
        if rows_at.len() > 1 {
            let Some(canonical_index) = accepted_here.first().copied() else {
                return refuse(
                    &spec.code("exact_duplicate_without_a_canonical_instance"),
                    format!("payload {digest} carries {} instances and none of them is accepted; an exclusion with nothing retained excluded the evidence, not the duplicate", rows_at.len()),
                );
            };
            let canonical = item_str(&file_dispositions[canonical_index], "source_file_ref");
            if item_str(payload, "canonical_source_file_ref") != canonical {
                return refuse(
                    &spec.code("canonical_instance_is_not_the_accepted_one"),
                    format!("payload {digest} names {} as canonical while {canonical} is the accepted instance", item_str(payload, "canonical_source_file_ref")),
                );
            }
            for index in rows_at {
                if *index == canonical_index {
                    continue;
                }
                let row = &file_dispositions[*index];
                if item_str(row, "disposition") != "deduplicated"
                    || item_str(row, "reason_class") != "exact_duplicate"
                {
                    return refuse(
                        &spec.code("repeated_payload_passes_as_distinct"),
                        format!("{} repeats payload {digest} and is filed as {}/{}; every repeat of an accepted payload is an exact duplicate and is excluded as one", item_str(row, "source_file_ref"), item_str(row, "disposition"), item_str(row, "reason_class")),
                    );
                }
            }
        }
    }

    // --------------------------------------- near duplication, re-decided rather than believed
    let dedup_policy = match body_object(&body, "deduplication_policy", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let declared_method = item_str(&dedup_policy, "near_duplicate_method");
    let declared_threshold = item_u64(&dedup_policy, "near_duplicate_threshold").unwrap_or(0);
    let near_exclusions = match object_list(&body, "near_duplicate_exclusions", 1_000_000, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    // THE CLOSURE IS EXECUTED, NOT NAMED. Each exclusion is resolved all the way down — source ref
    // to its one disposition row, retained ref to its one ACCEPTED row, both rows to their payload
    // digests, both digests to the payload table's fingerprints — and only then is the distance
    // recomputed. A check that stopped at the labels would accept an exclusion whose "retained
    // sibling" was itself excluded, whose fingerprints belonged to other payloads entirely, or whose
    // distance described a comparison it never made.
    let row_by_source: BTreeMap<String, &Value> = file_dispositions
        .iter()
        .map(|row| (item_str(row, "source_file_ref"), row))
        .collect();
    let mut excluded_sources = BTreeSet::new();
    for exclusion in &near_exclusions {
        let source_ref = item_str(exclusion, "source_file_ref");
        if !excluded_sources.insert(source_ref.clone()) {
            return refuse(
                &spec.code("near_duplicate_excluded_twice"),
                format!("{source_ref} is excluded twice; listing an instance again inflates the excluded count without excluding anything"),
            );
        }
        if item_str(exclusion, "similarity_method") != declared_method {
            return refuse(
                &spec.code("near_duplicate_method_was_not_declared"),
                format!("{source_ref} was judged under '{}' while the census declared '{declared_method}'; a row free to name its own method can justify any judgement after the fact", item_str(exclusion, "similarity_method")),
            );
        }
        if item_u64(exclusion, "threshold") != Some(declared_threshold) {
            return refuse(
                &spec.code("near_duplicate_threshold_was_not_declared"),
                format!("{source_ref} carries threshold {} against a declared {declared_threshold}; raising the bar beside a distance is threshold shopping", item_u64(exclusion, "threshold").unwrap_or(0)),
            );
        }

        // --- join 1: the excluded ref resolves to exactly one row, filed as a near duplicate
        let Some(source_row) = row_by_source.get(&source_ref) else {
            return refuse(
                &spec.code("near_duplicate_source_is_not_a_corpus_row"),
                format!("{source_ref} is excluded but appears in no disposition row; an exclusion over a file the corpus never ingested excludes nothing"),
            );
        };
        if item_str(source_row, "disposition") != "deduplicated"
            || item_str(source_row, "reason_class") != "near_duplicate"
        {
            return refuse(
                &spec.code("near_duplicate_source_is_not_filed_as_one"),
                format!("{source_ref} carries a near-duplicate exclusion while its row is filed as {}/{}; the exclusion and the disposition must be the same statement", item_str(source_row, "disposition"), item_str(source_row, "reason_class")),
            );
        }

        // --- join 2: the retained ref resolves to exactly one row, and that row is ACCEPTED
        let retained_ref = item_str(exclusion, "retained_source_file_ref");
        let Some(retained_row) = row_by_source.get(&retained_ref) else {
            return refuse(
                &spec.code("near_duplicate_retained_sibling_is_not_a_corpus_row"),
                format!("{source_ref} was excluded in favour of {retained_ref}, which appears in no disposition row"),
            );
        };
        if item_str(retained_row, "disposition") != "accepted" {
            return refuse(
                &spec.code("near_duplicate_retains_no_accepted_sibling"),
                format!("{source_ref} was excluded in favour of {retained_ref}, which this corpus filed as {}; an exclusion that retained nothing dropped the evidence rather than the duplicate", item_str(retained_row, "disposition")),
            );
        }

        // --- join 3: both rows resolve to payloads, and the two payloads are DIFFERENT
        let source_digest = item_str(source_row, "content_sha256");
        let retained_digest = item_str(retained_row, "content_sha256");
        if source_digest == retained_digest {
            return refuse(
                &spec.code("near_duplicate_is_an_exact_duplicate"),
                format!("{source_ref} and {retained_ref} carry byte-identical payloads; that is an EXACT duplicate and is filed as one, never as a near duplicate"),
            );
        }
        // --- join 4: the cited fingerprints are the ones THIS PROCESS derived from regenerated
        // bytes, not the ones the record carries. Comparing a row's fingerprint to the payload
        // table's would still be two caller-supplied strings agreeing with each other.
        let (Some(source_fingerprint), Some(retained_fingerprint)) = (
            fingerprints.get(&source_digest).cloned(),
            fingerprints.get(&retained_digest).cloned(),
        ) else {
            return refuse(
                &spec.code("payload_table_does_not_cover_the_rows"),
                format!("{source_ref} or {retained_ref} names a payload the payload table does not carry"),
            );
        };
        if item_str(exclusion, "similarity_fingerprint") != source_fingerprint {
            return refuse(
                &spec.code("near_duplicate_source_fingerprint_substituted"),
                format!("{source_ref} cites fingerprint {} while its payload's is {source_fingerprint}; a citing row does not get to choose the number it is judged on", item_str(exclusion, "similarity_fingerprint")),
            );
        }
        if item_str(exclusion, "retained_similarity_fingerprint") != retained_fingerprint {
            return refuse(
                &spec.code("near_duplicate_retained_fingerprint_substituted"),
                format!("{source_ref} cites {retained_ref}'s fingerprint as {} while that payload's is {retained_fingerprint}", item_str(exclusion, "retained_similarity_fingerprint")),
            );
        }

        // --- and only now the metric, recomputed over the payload table's own fingerprints
        let Some(distance) = hamming_distance_hex(&source_fingerprint, &retained_fingerprint)
        else {
            return refuse(
                &spec.code("near_duplicate_fingerprints_are_not_comparable"),
                format!("{source_ref} and {retained_ref} carry fingerprints that are not two equal-length lowercase-hex digests, so no distance between them is defined"),
            );
        };
        if item_u64(exclusion, "distance") != Some(distance) {
            return refuse(
                &spec.code("near_duplicate_distance_was_not_recomputed"),
                format!("{source_ref} declares distance {} while its payload sits {distance} from {retained_ref}'s under '{declared_method}'", item_u64(exclusion, "distance").unwrap_or(0)),
            );
        }
        if distance == 0 {
            return refuse(
                &spec.code("near_duplicate_is_an_exact_duplicate"),
                format!("{source_ref} is at distance 0 from {retained_ref}; payloads whose similarity digests agree exactly are filed as an exact duplicate"),
            );
        }
        if distance > declared_threshold {
            return refuse(
                &spec.code("near_duplicate_distance_exceeds_the_declared_threshold"),
                format!("{source_ref} is {distance} from {retained_ref} against a declared threshold of {declared_threshold}"),
            );
        }
    }
    let near_rows: BTreeSet<String> = file_dispositions
        .iter()
        .filter(|row| {
            item_str(row, "disposition") == "deduplicated"
                && item_str(row, "reason_class") == "near_duplicate"
        })
        .map(|row| item_str(row, "source_file_ref"))
        .collect();
    if near_rows != excluded_sources {
        return refuse(
            &spec.code("near_duplicate_rows_and_exclusions_disagree"),
            format!("{} rows are filed as near duplicates against {} exclusion rows; every near-duplicate exclusion shows its working or it is not one", near_rows.len(), excluded_sources.len()),
        );
    }

    // ------------------------------------------------------- the root is recomputed, not accepted
    let rejected = match body_object(&body, "rejected", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let deduplicated = match body_object(&body, "deduplicated", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let root_material = json!({
        "file_dispositions": file_dispositions,
        "distinct_payloads": distinct_payloads,
        "near_duplicate_exclusions": near_exclusions,
        "deduplication_policy": dedup_policy,
        "raw": raw,
        "accepted": accepted,
        "rejected": rejected,
        "deduplicated": deduplicated,
    });
    let recomputed_root = match digest_over(
        &root_material,
        "ioi.media-corpus-content-root-jcs-sha256.v1",
        &[
            "file_dispositions",
            "distinct_payloads",
            "near_duplicate_exclusions",
            "deduplication_policy",
            "raw",
            "accepted",
            "rejected",
            "deduplicated",
        ],
    ) {
        Ok(root) => root,
        Err(error) => return refuse(&spec.code("corpus_content_root_failed"), error),
    };
    if corpus_content_root != recomputed_root {
        return refuse(
            &spec.code("corpus_content_root_does_not_commit_the_rows"),
            "the declared corpus root is not the digest of the rows and counts filed under it; AN UNBACKED ROOT IS A CLAIM ABOUT A CORPUS RATHER THAN THE CORPUS ITSELF — two different corpora could file one root, and one corpus could file two, with neither detectable offline",
        );
    }

    // ---------------------------------------------------------- duration closure
    let before = item_u64(&accepted, "seconds_before_deduplication").unwrap_or(u64::MAX);
    let after = item_u64(&accepted, "seconds_after_deduplication").unwrap_or(u64::MAX);
    let raw_seconds = item_u64(&raw, "source_seconds").unwrap_or(0);
    if after > before {
        return refuse(
            &spec.code("deduplication_increased_accepted_time"),
            "accepted time AFTER exclusion exceeds the time before it; that is the arithmetic a padded corpus produces when exclusion is declared but not performed",
        );
    }
    if before > raw_seconds {
        return refuse(
            &spec.code("accepted_time_exceeds_raw_time"),
            "no lane may accept more source time than it ingested",
        );
    }

    // ---------------------------------------------------------- label-class coverage
    let required_classes: BTreeSet<String> = string_list(&body, "profile_required_label_classes")
        .into_iter()
        .collect();
    let observed_classes: BTreeSet<String> = string_list(&body, "observed_label_classes")
        .into_iter()
        .collect();
    if required_classes.is_empty() {
        return refuse(
            &spec.code("profile_required_label_classes_required"),
            "a census over no required label vocabulary cannot show coverage of one",
        );
    }
    if let Some(missing) = required_classes.difference(&observed_classes).next() {
        return refuse(
            &spec.code("required_label_class_not_observed"),
            format!("required label class '{missing}' was never observed; a high label count over a narrow vocabulary is not coverage"),
        );
    }

    // ---------------------------------------------------------- bounded queue and backpressure
    let runtime_evidence = match body_object(&body, "runtime_evidence", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let declared_bound =
        item_u64(&runtime_evidence, "max_undelivered_events_declared").unwrap_or(0);
    let high_water = item_u64(&runtime_evidence, "queue_high_water").unwrap_or(u64::MAX);
    if high_water > declared_bound {
        return refuse(
            &spec.code("queue_exceeded_its_declared_bound"),
            format!("the ingest queue reached {high_water} against a declared bound of {declared_bound}; EXCEEDING THE BOUND PRODUCES A TYPED OUTCOME, it never silently drops an accepted event"),
        );
    }
    // THE LEASE IS RESOLVED, NOT NAMED. `projection_subscription_lease_ref` was a caller-supplied
    // string beside a caller-supplied window, so a census could report backpressure evidence for a
    // lease nobody ever created and the two numbers would agree with each other perfectly. Resolving
    // it against the subscription plane makes the window the LEASE'S OWN declared bound, and a
    // fabricated lease has nothing to resolve to.
    let lease_ref = item_str(&runtime_evidence, "projection_subscription_lease_ref");
    let Some((lease_namespace, lease_tail)) = lease_ref
        .strip_prefix("subscription-lease://")
        .and_then(|rest| rest.split_once('/'))
        .filter(|(namespace, tail)| {
            family_token(namespace) && !tail.is_empty() && !tail.contains('/')
        })
    else {
        return refuse(
            &spec.code("subscription_lease_ref_not_canonical"),
            "'projection_subscription_lease_ref' is subscription-lease://<owner-namespace>/<lease-tail>; a ref this route cannot resolve is a name for evidence rather than the evidence",
        );
    };
    let leased_window = match super::event_stream_routes::admitted_lease(
        &st,
        lease_namespace,
        lease_tail,
    ) {
        Ok(Some((state, _, _))) => state
            .pointer("/backpressure/max_undelivered_events")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        Ok(None) => {
            return refuse(
                &spec.code("subscription_lease_not_admitted"),
                format!("{lease_ref} names no admitted subscription lease; BACKPRESSURE EVIDENCE FOR A LEASE NOBODY CREATED IS A NARRATION OF A SOAK, NOT THE RECORD OF ONE"),
            );
        }
        Err(_) => {
            return refuse(
                &spec.code("subscription_lease_not_readable"),
                format!("{lease_ref} could not be read from the subscription plane"),
            );
        }
    };
    if declared_bound != leased_window {
        return refuse(
            &spec.code("backpressure_window_is_not_the_leases_own"),
            format!("the census declares a bound of {declared_bound} while {lease_ref} was admitted with {leased_window}; a lane that could restate its own window is not held to one"),
        );
    }

    let pre = runtime_evidence
        .pointer("/restart_equivalence/pre_restart_root")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let post = runtime_evidence
        .pointer("/restart_equivalence/post_restart_root")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if pre.is_empty() || pre != post {
        return refuse(
            &spec.code("restart_equivalence_not_established"),
            "the pre- and post-restart lineage roots must be equal and present; a census carrying only a boolean would let a run that compared nothing report success",
        );
    }
    if runtime_evidence
        .get("durability_class_achieved")
        .and_then(Value::as_str)
        .is_none()
    {
        return refuse(
            &spec.code("durability_class_not_reported"),
            "the durability class REACHED by the writer is reported, never the one requested",
        );
    }

    // ---------------------------------------------------------- the floors, bound to their lane
    let hours_scale = claimed_scale == "hours_scale_qualification";
    if hours_scale {
        let episodes = item_u64(&accepted, "bounded_episode_count").unwrap_or(0);
        let tasks = item_u64(&accepted, "task_count").unwrap_or(0);
        let sessions = item_u64(&accepted, "source_session_count").unwrap_or(0);
        if after < 7200 {
            return refuse(
                &spec.code("below_the_accepted_duration_floor"),
                format!("{after} accepted seconds after exact and near-duplicate exclusion is below the 7200-second floor; the floors cannot shrink"),
            );
        }
        if episodes < 8 || tasks < 8 {
            return refuse(
                &spec.code("below_the_bounded_episode_floor"),
                format!("{episodes} bounded episodes and {tasks} tasks are below the floor of 8 independently bounded episodes/tasks"),
            );
        }
        if sessions < 2 {
            return refuse(
                &spec.code("below_the_source_session_floor"),
                format!("{sessions} source Sessions is below the floor of 2"),
            );
        }
    }
    let accepted_bytes = item_u64(&accepted, "byte_count").unwrap_or(u64::MAX);
    if accepted_bytes > 2_147_483_648 {
        return refuse(
            &spec.code("corpus_exceeds_the_byte_ceiling"),
            "the accepted corpus exceeds the 2 GiB ceiling; duration and diversity are the floors, fidelity is not",
        );
    }

    // The census identity IS the corpus digest, so two runs over one corpus collide by construction.
    let census_id = format!(
        "{resource}/{}",
        corpus_content_root.trim_start_matches("sha256:")
    );

    let record = json!({
        "schema_version": spec.schema_version,
        "corpus_census_id": census_id,
        "owner_ref": caller.owner_ref,
        "tenant_ref": contract_tenant_ref(&caller.owner_ref),
        "principal_resolution": "server_resolved",
        "resolved_principal_ref": caller.identity.principal_ref,
        "claimed_scale": claimed_scale,
        "profile": profile,
        "corpus_content_root": corpus_content_root,
        "raw": raw,
        "accepted": accepted,
        "rejected": rejected,
        "deduplicated": deduplicated,
        "deduplication_policy": dedup_policy,
        "payload_custody": "deterministic_recipe",
        // DERIVED FROM THE SEAM, never authored: recomputing a recipe's bytes says nothing about an
        // imported recording, whose bytes this version never holds.
        "does_not_claim_custody_of_imported_media_bytes": true,
        "file_dispositions": file_dispositions,
        "distinct_payloads": distinct_payloads,
        "near_duplicate_exclusions": near_exclusions,
        "profile_required_label_classes": string_list(&body, "profile_required_label_classes"),
        "observed_label_classes": string_list(&body, "observed_label_classes"),
        // PINNED SERVER-SIDE. A lane that could lower its own floor is not held to one.
        "floors": {
            "accepted_seconds_after_deduplication": 7200,
            "bounded_episode_count": 8,
            "source_session_count": 2,
        },
        "ceilings": { "corpus_byte_count": 2_147_483_648u64 },
        "runtime_evidence": runtime_evidence,
        "degeneracy_findings": match object_list(&body, "degeneracy_findings", 4096, spec) {
            Ok(list) => list,
            Err(response) => return response,
        },
        // DISTINCT PAYLOADS, not rows. Deriving it from the row count made it equal by construction
        // and turned the degeneracy check into a restatement of the uniqueness rule beside it.
        "distinct_content_hash_count": declared.len(),
        // DERIVED FROM THE LANE, never authored: the compact lane cannot drop its own nonclaim.
        "does_not_claim_hours_scale_qualification": !hours_scale,
        "does_not_claim_throughput_or_latency": true,
        "admitted_at": admitted_stamp(recorded_at_ms),
        "constants": { "commitment_domain": spec.commitment_domain },
        "authority_nonclaim": "media_corpus_qualification_census_grants_no_authority",
    });

    finish_admission(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        "media_corpus_census",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({
            "floors_are_pinned_server_side": true,
            "hours_scale_floors_enforced": hours_scale,
            "no_throughput_or_latency_is_claimed": true,
        }),
    )
}

// ===================================================================== the read side

/// GET /v1/hypervisor/media-snapshot-revisions
pub(crate) async fn handle_media_snapshot_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    family_query(&SNAPSHOT, "media_snapshots", st, &headers, query)
}

/// GET /v1/hypervisor/observation-action-episode-revisions
pub(crate) async fn handle_episode_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    family_query(&EPISODE, "observation_action_episodes", st, &headers, query)
}

/// GET /v1/hypervisor/dataset-split-manifest-revisions
pub(crate) async fn handle_split_manifest_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    family_query(&SPLIT, "dataset_split_manifests", st, &headers, query)
}

/// GET /v1/hypervisor/media-corpus-censuses
pub(crate) async fn handle_corpus_census_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    family_query(&CENSUS, "media_corpus_censuses", st, &headers, query)
}

#[derive(serde::Deserialize)]
pub(crate) struct ErasureImpactQuery {
    pub(crate) snapshot_revision_ref: String,
    pub(crate) episode_family: Option<String>,
    pub(crate) split_family: Option<String>,
}

/// GET /v1/hypervisor/media-snapshot-revisions/erasure-impact
///
/// RETENTION AND ERASURE PRODUCE AN IMPACT GRAPH, NOT A REWRITE. Hold, erasure, source-right
/// revocation or a corrected label must produce a governed rebuild/withdrawal DECISION over the
/// dependents, "without rewriting historical evidence" (ACC-16 clause 12). This read walks the
/// chain and reports which episodes and split manifests would be affected; it mutates nothing, and
/// deliberately offers no verb that could retro-edit an admitted revision.
pub(crate) async fn handle_media_snapshot_erasure_impact(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<ErasureImpactQuery>,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let snapshot = match resolve_admitted_media_snapshot(
        &st.data_dir,
        &identity,
        None,
        &query.snapshot_revision_ref,
    ) {
        Ok(snapshot) => snapshot,
        Err(response) => return response,
    };

    let mut affected_episodes = Vec::new();
    if let Some(family) = query.episode_family.as_deref() {
        let resource = format!("{}{family}", EPISODE.ref_scheme);
        let scope = match authorize_request_resource_scope(
            &st.data_dir,
            &identity,
            EPISODE.resource_kind,
            &resource,
            None,
        ) {
            Ok(scope) => scope,
            Err(error) => return scope_refusal_reply(error),
        };
        let stream: Vec<AdmittedRecord> =
            match read_stream(&EPISODE, &st.data_dir, &identity, &scope, &resource) {
                Ok(stream) => stream,
                Err(response) => return response,
            };
        for entry in &stream {
            if item_str(&entry.record, "media_snapshot_revision_ref") == snapshot.revision_ref {
                affected_episodes.push(item_str(&entry.record, "revision_ref"));
            }
        }
    }

    let mut affected_splits = Vec::new();
    if let Some(family) = query.split_family.as_deref() {
        let resource = format!("{}{family}", SPLIT.ref_scheme);
        let scope = match authorize_request_resource_scope(
            &st.data_dir,
            &identity,
            SPLIT.resource_kind,
            &resource,
            None,
        ) {
            Ok(scope) => scope,
            Err(error) => return scope_refusal_reply(error),
        };
        let stream: Vec<AdmittedRecord> =
            match read_stream(&SPLIT, &st.data_dir, &identity, &scope, &resource) {
                Ok(stream) => stream,
                Err(response) => return response,
            };
        for entry in &stream {
            let members = entry
                .record
                .get("all_member_episode_revision_refs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if members
                .iter()
                .filter_map(Value::as_str)
                .any(|member| affected_episodes.iter().any(|e| e == member))
            {
                affected_splits.push(item_str(&entry.record, "revision_ref"));
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "snapshot_revision_ref": snapshot.revision_ref,
            "snapshot_content_hash": snapshot.content_hash,
            "snapshot_permits_learned_use": snapshot.permits_learned_use(),
            "affected_episode_revision_refs": affected_episodes,
            "affected_split_manifest_revision_refs": affected_splits,
            "decision_class": "governed_rebuild_or_withdrawal_required",
            "historical_evidence_rewritten": false,
            "impact_is_a_decision_not_a_deletion": true,
        })),
    )
}
