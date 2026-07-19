//! Central information-flow admission for consequential daemon effects.
//!
//! This module is not a second privacy runtime. It compiles the registered
//! `InformationFlowLabel`, `RuntimeToolContract`, and `DeclassificationApproval`
//! contracts into one fail-closed pre-effect decision used by existing daemon
//! execution boundaries.

use std::collections::BTreeSet;
use std::future::Future;

use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const INFORMATION_FLOW_LABEL_CONTRACT_ID: &str =
    "schema://ioi/foundations/information-flow-label/v1";
pub const RUNTIME_TOOL_CONTRACT_ID: &str =
    "schema://ioi/components/connectors-tools/runtime-tool-contract/v1";
pub const DECLASSIFICATION_APPROVAL_CONTRACT_ID: &str =
    "schema://ioi/foundations/declassification-approval/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfcDenial {
    pub code: &'static str,
    pub message: String,
}

impl IfcDenial {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectBinding {
    pub effect_hash: String,
    pub request_hash: String,
    pub reviewed_representation_hash: Option<String>,
}

pub struct PreEffectAdmission<'a> {
    pub label: &'a Value,
    pub tool_contract: &'a Value,
    pub destination: &'a str,
    pub method: &'a str,
    pub request: &'a Value,
    pub reviewed_representation: Option<&'a Value>,
    pub declassification_approval: Option<&'a Value>,
}

fn value_str<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn string_set(value: &Value, pointer: &str) -> Option<BTreeSet<String>> {
    Some(
        value
            .pointer(pointer)?
            .as_array()?
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .map(str::to_string)
            .collect(),
    )
}

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, IfcDenial> {
    serde_jcs::to_vec(value).map_err(|error| {
        IfcDenial::new(
            "ifc_canonicalization_failed",
            format!("effect input could not be canonically encoded: {error}"),
        )
    })
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    format!("sha256:{:x}", hash.finalize())
}

pub fn sha256_value(value: &Value) -> Result<String, IfcDenial> {
    canonical_bytes(value).map(|bytes| sha256_bytes(&bytes))
}

pub fn effect_binding(
    method: &str,
    destination: &str,
    request: &Value,
    reviewed_representation: Option<&Value>,
) -> Result<EffectBinding, IfcDenial> {
    let exact_effect = json!({
        "method": method.to_ascii_uppercase(),
        "destination": destination,
        "request": request,
    });
    Ok(EffectBinding {
        effect_hash: sha256_value(&exact_effect)?,
        request_hash: sha256_value(request)?,
        reviewed_representation_hash: reviewed_representation.map(sha256_value).transpose()?,
    })
}

fn destination_matches(pattern: &str, destination: &str) -> bool {
    let wildcard = pattern.ends_with('*');
    let declared = if wildcard {
        &pattern[..pattern.len().saturating_sub(1)]
    } else {
        pattern
    };
    let (Ok(declared_url), Ok(destination_url)) = (
        reqwest::Url::parse(declared),
        reqwest::Url::parse(destination),
    ) else {
        return false;
    };
    let same_origin = declared_url.scheme() == destination_url.scheme()
        && declared_url.host_str() == destination_url.host_str()
        && declared_url.port_or_known_default() == destination_url.port_or_known_default();
    if !same_origin {
        return false;
    }
    if wildcard {
        declared.ends_with('/') && destination.starts_with(declared)
    } else {
        declared_url == destination_url
    }
}

fn destination_allowed(value: &Value, pointer: &str, destination: &str) -> bool {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .is_some_and(|patterns| {
            patterns
                .iter()
                .filter_map(Value::as_str)
                .any(|pattern| destination_matches(pattern, destination))
        })
}

fn is_unknown_axis(label: &Value) -> bool {
    [
        "/origin",
        "/integrity",
        "/confidentiality",
        "/instruction_authority",
    ]
    .iter()
    .any(|pointer| value_str(label, pointer) == Some("unknown"))
        || value_str(label, "/retention/disposition") == Some("unknown")
}

fn has_untrusted_derivation(label: &Value) -> bool {
    matches!(
        value_str(label, "/origin"),
        Some("external_untrusted" | "connector_output" | "tool_output" | "memory_import")
    ) || value_str(label, "/integrity") == Some("untrusted")
        || value_str(label, "/instruction_authority") == Some("untrusted")
}

fn confidentiality_rank(value: &str) -> Option<u8> {
    match value {
        "public" => Some(0),
        "internal" => Some(1),
        "confidential" => Some(2),
        "private" => Some(3),
        "restricted" => Some(4),
        "unknown" => Some(5),
        _ => None,
    }
}

fn verify_declassification(
    admission: &PreEffectAdmission<'_>,
    approval: &Value,
    binding: &EffectBinding,
) -> Result<String, IfcDenial> {
    validate_architecture_contract(DECLASSIFICATION_APPROVAL_CONTRACT_ID, approval).map_err(
        |error| {
            IfcDenial::new(
                "ifc_declassification_invalid",
                format!("declassification approval is not contract-valid: {error}"),
            )
        },
    )?;

    if value_str(approval, "/status") != Some("active") {
        return Err(IfcDenial::new(
            "ifc_declassification_inactive",
            "declassification approval is not active",
        ));
    }
    let expires_at = value_str(approval, "/expires_at")
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .ok_or_else(|| {
            IfcDenial::new(
                "ifc_declassification_invalid",
                "declassification expiry is missing or invalid",
            )
        })?;
    if expires_at <= OffsetDateTime::now_utc() {
        return Err(IfcDenial::new(
            "ifc_declassification_expired",
            "declassification approval has expired",
        ));
    }

    let reviewed_hash = binding
        .reviewed_representation_hash
        .as_deref()
        .ok_or_else(|| {
            IfcDenial::new(
                "ifc_reviewed_representation_required",
                "protected egress requires the exact representation reviewed by the approver",
            )
        })?;
    let exact_pairs = [
        (
            "/tool_contract_revision_ref",
            value_str(admission.tool_contract, "/revision_ref"),
        ),
        ("/label_ref", value_str(admission.label, "/label_ref")),
        (
            "/label_content_hash",
            value_str(admission.label, "/content_hash"),
        ),
        ("/exact_effect_hash", Some(binding.effect_hash.as_str())),
        ("/exact_request_hash", Some(binding.request_hash.as_str())),
        ("/reviewed_representation_hash", Some(reviewed_hash)),
        ("/destination", Some(admission.destination)),
        ("/purpose", value_str(admission.label, "/purpose")),
    ];
    for (pointer, expected) in exact_pairs {
        if value_str(approval, pointer) != expected {
            return Err(IfcDenial::new(
                "ifc_declassification_binding_mismatch",
                format!("declassification approval does not bind exact field {pointer}"),
            ));
        }
    }

    value_str(approval, "/declassified_to")
        .map(str::to_string)
        .ok_or_else(|| {
            IfcDenial::new(
                "ifc_declassification_invalid",
                "declassification target is missing",
            )
        })
}

/// Evaluate one consequential effect immediately before its external invoker.
/// Unknown/missing axes and undeclared destinations fail closed.
pub fn admit_pre_effect(admission: &PreEffectAdmission<'_>) -> Result<EffectBinding, IfcDenial> {
    validate_architecture_contract(INFORMATION_FLOW_LABEL_CONTRACT_ID, admission.label).map_err(
        |error| {
            IfcDenial::new(
                "ifc_label_invalid",
                format!("information-flow label is not contract-valid: {error}"),
            )
        },
    )?;
    validate_architecture_contract(RUNTIME_TOOL_CONTRACT_ID, admission.tool_contract).map_err(
        |error| {
            IfcDenial::new(
                "ifc_tool_contract_invalid",
                format!("runtime tool contract is not contract-valid: {error}"),
            )
        },
    )?;

    if is_unknown_axis(admission.label) {
        return Err(IfcDenial::new(
            "ifc_unknown_label",
            "unknown information-flow axes cannot cross a consequential effect boundary",
        ));
    }
    if value_str(admission.label, "/instruction_authority") != Some("authoritative") {
        return Err(IfcDenial::new(
            "ifc_instruction_not_authoritative",
            "context-only, absent, or untrusted instructions cannot authorize a consequential effect",
        ));
    }

    let confidentiality = value_str(admission.label, "/confidentiality")
        .ok_or_else(|| IfcDenial::new("ifc_unknown_label", "confidentiality is missing"))?;
    let private_or_higher = confidentiality_rank(confidentiality).is_some_and(|rank| rank >= 3);
    if private_or_higher && has_untrusted_derivation(admission.label) {
        return Err(IfcDenial::new(
            "ifc_private_untrusted_egress",
            "private-or-higher context derived from untrusted content cannot egress",
        ));
    }

    if value_str(admission.label, "/egress_policy/mode") == Some("deny") {
        return Err(IfcDenial::new(
            "ifc_label_egress_denied",
            "the data label denies egress",
        ));
    }
    if !destination_allowed(
        admission.label,
        "/egress_policy/allowed_destination_patterns",
        admission.destination,
    ) {
        return Err(IfcDenial::new(
            "ifc_label_destination_denied",
            "destination is outside the label egress policy",
        ));
    }
    if value_str(admission.tool_contract, "/egress_policy/default") != Some("allow_declared")
        || !destination_allowed(
            admission.tool_contract,
            "/egress_policy/allowed_destination_patterns",
            admission.destination,
        )
    {
        return Err(IfcDenial::new(
            "ifc_tool_destination_denied",
            "destination is not declared by the exact RuntimeToolContract revision",
        ));
    }

    let binding = effect_binding(
        admission.method,
        admission.destination,
        admission.request,
        admission.reviewed_representation,
    )?;
    let effective_class = if private_or_higher
        || value_str(admission.label, "/egress_policy/mode") == Some("declassification_required")
    {
        let approval = admission.declassification_approval.ok_or_else(|| {
            IfcDenial::new(
                "ifc_declassification_required",
                "protected egress requires an exact declassification approval",
            )
        })?;
        verify_declassification(admission, approval, &binding)?
    } else {
        confidentiality.to_string()
    };

    let tool_data_classes = string_set(admission.tool_contract, "/data_class_allowlist")
        .ok_or_else(|| {
            IfcDenial::new(
                "ifc_tool_contract_invalid",
                "RuntimeToolContract data-class allowlist is missing",
            )
        })?;
    let label_data_classes = string_set(admission.label, "/egress_policy/allowed_data_classes")
        .ok_or_else(|| {
            IfcDenial::new("ifc_label_invalid", "label data-class allowlist is missing")
        })?;
    if !tool_data_classes.contains(&effective_class)
        || !label_data_classes.contains(&effective_class)
    {
        return Err(IfcDenial::new(
            "ifc_data_class_denied",
            format!("effective data class '{effective_class}' is outside an allowlist"),
        ));
    }

    Ok(binding)
}

/// Use this wrapper at an effect boundary so admission failure makes invoking
/// the external implementation structurally impossible.
pub async fn invoke_after_ifc<F, Fut, T>(
    admission: &PreEffectAdmission<'_>,
    invoker: F,
) -> Result<T, IfcDenial>
where
    F: FnOnce(EffectBinding) -> Fut,
    Fut: Future<Output = T>,
{
    let binding = admit_pre_effect(admission)?;
    Ok(invoker(binding).await)
}

/// Recompute the effective label from the actual parent set, admit the exact
/// effect, and only then call the external implementation. This is the common
/// boundary wrapper for browser/computer-use style drivers whose upstream
/// authority label must not be able to weaken observed data labels.
pub async fn invoke_with_parents_after_ifc<F, Fut, T>(
    parents: &[Value],
    authority_label: &Value,
    tool_contract: &Value,
    destination: &str,
    method: &str,
    request: &Value,
    reviewed_representation: Option<&Value>,
    declassification_approval: Option<&Value>,
    invoker: F,
) -> Result<(T, Value, EffectBinding), IfcDenial>
where
    F: FnOnce(EffectBinding) -> Fut,
    Fut: Future<Output = T>,
{
    let exact_request_content_hash = sha256_value(request)?;
    let effective_label =
        compile_admitted_effect_label(parents, authority_label, &exact_request_content_hash)?;
    let admission = PreEffectAdmission {
        label: &effective_label,
        tool_contract,
        destination,
        method,
        request,
        reviewed_representation,
        declassification_approval,
    };
    let binding = admit_pre_effect(&admission)?;
    let output = invoker(binding.clone()).await;
    Ok((output, effective_label, binding))
}

fn worst_axis<'a>(
    parents: &'a [Value],
    pointer: &str,
    order: &[&str],
) -> Result<&'a str, IfcDenial> {
    parents
        .iter()
        .map(|parent| {
            let value = value_str(parent, pointer).ok_or_else(|| {
                IfcDenial::new("ifc_label_invalid", format!("parent is missing {pointer}"))
            })?;
            let rank = order
                .iter()
                .position(|candidate| *candidate == value)
                .ok_or_else(|| {
                    IfcDenial::new("ifc_label_invalid", format!("parent has invalid {pointer}"))
                })?;
            Ok((rank, value))
        })
        .collect::<Result<Vec<_>, IfcDenial>>()?
        .into_iter()
        .max_by_key(|(rank, _)| *rank)
        .map(|(_, value)| value)
        .ok_or_else(|| IfcDenial::new("ifc_derivation_empty", "derivation needs a parent label"))
}

fn intersect_sets(parents: &[Value], pointer: &str) -> Result<Vec<String>, IfcDenial> {
    let mut sets = parents.iter().map(|parent| {
        string_set(parent, pointer).ok_or_else(|| {
            IfcDenial::new("ifc_label_invalid", format!("parent is missing {pointer}"))
        })
    });
    let mut intersection = sets
        .next()
        .transpose()?
        .ok_or_else(|| IfcDenial::new("ifc_derivation_empty", "derivation needs a parent label"))?;
    for set in sets {
        intersection = intersection
            .intersection(&set?)
            .cloned()
            .collect::<BTreeSet<_>>();
    }
    Ok(intersection.into_iter().collect())
}

/// Derive a label for summarization, model substitution, memory import, tool
/// output, or a general join. Axes only become more restrictive, and the full
/// transitive parent closure is retained in sorted deterministic order.
pub fn derive_label(
    parents: &[Value],
    label_ref: &str,
    content_hash: &str,
    derivation_kind: &str,
) -> Result<Value, IfcDenial> {
    if parents.is_empty() {
        return Err(IfcDenial::new(
            "ifc_derivation_empty",
            "derivation needs at least one parent label",
        ));
    }
    for parent in parents {
        validate_architecture_contract(INFORMATION_FLOW_LABEL_CONTRACT_ID, parent).map_err(
            |error| {
                IfcDenial::new(
                    "ifc_label_invalid",
                    format!("parent label is not contract-valid: {error}"),
                )
            },
        )?;
    }

    let origins = [
        "operator",
        "admitted_artifact",
        "model_output",
        "memory_import",
        "connector_output",
        "tool_output",
        "external_untrusted",
        "unknown",
    ];
    let integrities = ["verified", "admitted", "declared", "untrusted", "unknown"];
    let confidentialities = [
        "public",
        "internal",
        "confidential",
        "private",
        "restricted",
        "unknown",
    ];
    let instruction_authorities = [
        "authoritative",
        "context_only",
        "none",
        "untrusted",
        "unknown",
    ];
    let egress_modes = ["allow_declared", "declassification_required", "deny"];
    let retention_dispositions = [
        "retain_under_policy",
        "return_to_owner",
        "delete",
        "unknown",
    ];

    let parent_refs = parents
        .iter()
        .filter_map(|parent| value_str(parent, "/label_ref"))
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let mut closure = parent_refs.clone();
    closure.insert(label_ref.to_string());
    for parent in parents {
        closure.extend(
            string_set(parent, "/derivation_closure_refs").ok_or_else(|| {
                IfcDenial::new("ifc_label_invalid", "parent derivation closure is missing")
            })?,
        );
    }
    let purposes = parents
        .iter()
        .filter_map(|parent| value_str(parent, "/purpose"))
        .collect::<BTreeSet<_>>();
    let purpose = if purposes.len() == 1 {
        purposes
            .iter()
            .next()
            .copied()
            .unwrap_or("unknown")
            .to_string()
    } else {
        format!(
            "composed:[{}]",
            purposes.into_iter().collect::<Vec<_>>().join("|")
        )
    };
    let profile_refs = parents
        .iter()
        .filter_map(|parent| value_str(parent, "/profile_ref"))
        .collect::<BTreeSet<_>>();
    let profile_ref = if profile_refs.len() == 1 {
        profile_refs
            .iter()
            .next()
            .copied()
            .unwrap_or("policy://ifc/join-v1")
            .to_string()
    } else {
        "policy://ifc/join-v1".to_string()
    };
    let max_seconds = parents
        .iter()
        .filter_map(|parent| {
            parent
                .pointer("/retention/max_seconds")
                .and_then(Value::as_u64)
        })
        .min()
        .ok_or_else(|| IfcDenial::new("ifc_label_invalid", "parent retention is missing"))?;

    let derived = json!({
        "schema_version": "ioi.foundations.information-flow-label.v1",
        "label_ref": label_ref,
        "profile_ref": profile_ref,
        "content_hash": content_hash,
        "origin": worst_axis(parents, "/origin", &origins)?,
        "integrity": worst_axis(parents, "/integrity", &integrities)?,
        "confidentiality": worst_axis(parents, "/confidentiality", &confidentialities)?,
        "instruction_authority": worst_axis(parents, "/instruction_authority", &instruction_authorities)?,
        "egress_policy": {
            "mode": worst_axis(parents, "/egress_policy/mode", &egress_modes)?,
            "allowed_destination_patterns": intersect_sets(parents, "/egress_policy/allowed_destination_patterns")?,
            "allowed_data_classes": intersect_sets(parents, "/egress_policy/allowed_data_classes")?,
        },
        "purpose": purpose,
        "retention": {
            "max_seconds": max_seconds,
            "disposition": worst_axis(parents, "/retention/disposition", &retention_dispositions)?,
        },
        "derivation_kind": derivation_kind,
        "derivation_parent_refs": parent_refs.into_iter().collect::<Vec<_>>(),
        "derivation_closure_refs": closure.into_iter().collect::<Vec<_>>(),
    });
    validate_architecture_contract(INFORMATION_FLOW_LABEL_CONTRACT_ID, &derived).map_err(
        |error| {
            IfcDenial::new(
                "ifc_derived_label_invalid",
                format!("derived label violates the registered contract: {error}"),
            )
        },
    )?;
    Ok(derived)
}

/// Compile an independently admitted effect label over the actual parent set.
/// The authority label may authorize the effect, but it cannot replace or
/// weaken parent confidentiality, integrity, egress, purpose, or retention.
pub fn compile_admitted_effect_label(
    parents: &[Value],
    authority_label: &Value,
    exact_request_content_hash: &str,
) -> Result<Value, IfcDenial> {
    validate_architecture_contract(INFORMATION_FLOW_LABEL_CONTRACT_ID, authority_label).map_err(
        |error| {
            IfcDenial::new(
                "ifc_effect_authority_label_invalid",
                format!("effect authority label is not contract-valid: {error}"),
            )
        },
    )?;
    if value_str(authority_label, "/instruction_authority") != Some("authoritative") {
        return Err(IfcDenial::new(
            "ifc_effect_authority_required",
            "an independently admitted authoritative effect label is required",
        ));
    }
    if parents.is_empty() {
        return Err(IfcDenial::new(
            "ifc_effect_parent_labels_required",
            "effect admission requires the actual parent-label set",
        ));
    }
    let label_ref = value_str(authority_label, "/label_ref").ok_or_else(|| {
        IfcDenial::new(
            "ifc_effect_authority_label_invalid",
            "effect authority label is missing label_ref",
        )
    })?;
    let authority_content_hash = value_str(authority_label, "/content_hash").ok_or_else(|| {
        IfcDenial::new(
            "ifc_effect_authority_label_invalid",
            "effect authority label is missing content_hash",
        )
    })?;
    let authority_label_body_hash = sha256_value(authority_label)?;
    let mut parent_bindings = parents
        .iter()
        .map(|parent| {
            let parent_ref = value_str(parent, "/label_ref").ok_or_else(|| {
                IfcDenial::new("ifc_label_invalid", "effect parent is missing label_ref")
            })?;
            let parent_content_hash = value_str(parent, "/content_hash").ok_or_else(|| {
                IfcDenial::new("ifc_label_invalid", "effect parent is missing content_hash")
            })?;
            let parent_label_body_hash = sha256_value(parent)?;
            Ok(json!({
                "label_ref": parent_ref,
                "content_hash": parent_content_hash,
                "label_body_hash": parent_label_body_hash,
            }))
        })
        .collect::<Result<Vec<_>, IfcDenial>>()?;
    parent_bindings.sort_by(|left, right| {
        value_str(left, "/label_ref")
            .cmp(&value_str(right, "/label_ref"))
            .then_with(|| value_str(left, "/content_hash").cmp(&value_str(right, "/content_hash")))
            .then_with(|| {
                value_str(left, "/label_body_hash").cmp(&value_str(right, "/label_body_hash"))
            })
    });
    let effective_identity_hash = sha256_value(&json!({
        "authority_label_ref": label_ref,
        "authority_label_content_hash": authority_content_hash,
        "authority_label_body_hash": authority_label_body_hash,
        "parent_bindings": parent_bindings,
        "exact_request_content_hash": exact_request_content_hash,
    }))?;
    let effective_label_ref = format!(
        "ifc-label://runtime/effect/{}",
        effective_identity_hash.trim_start_matches("sha256:")
    );
    let mut joined_parents = parents.to_vec();
    joined_parents.push(authority_label.clone());
    let mut effective = derive_label(
        &joined_parents,
        &effective_label_ref,
        exact_request_content_hash,
        "join",
    )?;
    // Authority is supplied by the independently admitted effect object, not
    // inferred from content. Every data-control axis remains the restrictive
    // join computed above.
    effective["instruction_authority"] = json!("authoritative");
    validate_architecture_contract(INFORMATION_FLOW_LABEL_CONTRACT_ID, &effective).map_err(
        |error| {
            IfcDenial::new(
                "ifc_effect_label_invalid",
                format!("compiled effect label violates the registered contract: {error}"),
            )
        },
    )?;
    Ok(effective)
}

pub fn summarize_label(
    parents: &[Value],
    label_ref: &str,
    content_hash: &str,
) -> Result<Value, IfcDenial> {
    derive_label(parents, label_ref, content_hash, "summarization")
}

pub fn model_substitution_label(
    parents: &[Value],
    label_ref: &str,
    content_hash: &str,
) -> Result<Value, IfcDenial> {
    derive_label(parents, label_ref, content_hash, "model_substitution")
}

pub fn memory_import_label(
    parents: &[Value],
    label_ref: &str,
    content_hash: &str,
) -> Result<Value, IfcDenial> {
    derive_label(parents, label_ref, content_hash, "memory_import")
}

fn authority_rank(value: &str) -> Option<u8> {
    match value {
        "authoritative" => Some(0),
        "context_only" => Some(1),
        "none" => Some(2),
        "untrusted" => Some(3),
        "unknown" => Some(4),
        _ => None,
    }
}

fn integrity_rank(value: &str) -> Option<u8> {
    match value {
        "verified" => Some(0),
        "admitted" => Some(1),
        "declared" => Some(2),
        "untrusted" => Some(3),
        "unknown" => Some(4),
        _ => None,
    }
}

/// Project a boundary-produced value without allowing that boundary to mint
/// instruction authority. Confidentiality, egress, purpose, retention, and
/// the complete parent closure continue to come from the restrictive join.
pub fn derive_boundary_output_label(
    parents: &[Value],
    label_ref: &str,
    content_hash: &str,
    derivation_kind: &str,
    origin: &str,
    integrity: &str,
    instruction_authority_ceiling: &str,
) -> Result<Value, IfcDenial> {
    if !matches!(
        origin,
        "external_untrusted"
            | "connector_output"
            | "tool_output"
            | "model_output"
            | "memory_import"
    ) {
        return Err(IfcDenial::new(
            "ifc_boundary_origin_invalid",
            "boundary output origin is not a registered v1 origin",
        ));
    }
    let boundary_integrity_rank = integrity_rank(integrity)
        .filter(|rank| *rank < integrity_rank("unknown").unwrap_or(u8::MAX))
        .ok_or_else(|| {
            IfcDenial::new(
                "ifc_boundary_integrity_invalid",
                "boundary output integrity is not a registered non-unknown v1 value",
            )
        })?;
    let ceiling_rank = authority_rank(instruction_authority_ceiling).ok_or_else(|| {
        IfcDenial::new(
            "ifc_boundary_instruction_authority_invalid",
            "boundary instruction-authority ceiling is not registered",
        )
    })?;
    if ceiling_rank < authority_rank("context_only").unwrap_or(1) {
        return Err(IfcDenial::new(
            "ifc_boundary_instruction_authority_invalid",
            "boundary outputs cannot acquire authoritative instruction status",
        ));
    }

    let mut derived = derive_label(parents, label_ref, content_hash, derivation_kind)?;
    derived["origin"] = json!(origin);
    let joined_integrity_rank = value_str(&derived, "/integrity")
        .and_then(integrity_rank)
        .ok_or_else(|| {
            IfcDenial::new("ifc_derived_label_invalid", "derived integrity is invalid")
        })?;
    let effective_integrity = match joined_integrity_rank.max(boundary_integrity_rank) {
        0 => "verified",
        1 => "admitted",
        2 => "declared",
        3 => "untrusted",
        _ => "unknown",
    };
    derived["integrity"] = json!(effective_integrity);
    let joined_authority = value_str(&derived, "/instruction_authority")
        .and_then(authority_rank)
        .ok_or_else(|| {
            IfcDenial::new(
                "ifc_derived_label_invalid",
                "derived instruction authority is invalid",
            )
        })?;
    let effective_rank = joined_authority.max(ceiling_rank);
    let effective_authority = match effective_rank {
        0 => "authoritative",
        1 => "context_only",
        2 => "none",
        3 => "untrusted",
        _ => "unknown",
    };
    derived["instruction_authority"] = json!(effective_authority);
    validate_architecture_contract(INFORMATION_FLOW_LABEL_CONTRACT_ID, &derived).map_err(
        |error| {
            IfcDenial::new(
                "ifc_derived_label_invalid",
                format!("boundary label violates the registered contract: {error}"),
            )
        },
    )?;
    Ok(derived)
}

/// Label an MCP tool/resource result as external tool output. The result keeps
/// every argument/context parent and can never become executable instruction.
pub fn mcp_output_label(
    parents: &[Value],
    label_ref: &str,
    content_hash: &str,
) -> Result<Value, IfcDenial> {
    derive_boundary_output_label(
        parents,
        label_ref,
        content_hash,
        "tool_output",
        "tool_output",
        "untrusted",
        "none",
    )
}

/// Label browser/web or computer-use observations as untrusted external data.
pub fn browser_observation_label(
    parents: &[Value],
    label_ref: &str,
    content_hash: &str,
) -> Result<Value, IfcDenial> {
    derive_boundary_output_label(
        parents,
        label_ref,
        content_hash,
        "tool_output",
        "external_untrusted",
        "untrusted",
        "none",
    )
}

/// Label provider output while retaining the complete input derivation closure.
/// Raw provider output is untrusted content until a separate verifier/admission
/// promotes it; model inference itself cannot mint integrity.
pub fn model_output_label(
    parents: &[Value],
    label_ref: &str,
    content_hash: &str,
) -> Result<Value, IfcDenial> {
    derive_boundary_output_label(
        parents,
        label_ref,
        content_hash,
        "model_substitution",
        "model_output",
        "untrusted",
        "none",
    )
}

/// Label imported/stored memory while preserving the most restrictive parent
/// confidentiality, egress, purpose, retention, integrity, and authority.
pub fn memory_storage_label(
    parents: &[Value],
    label_ref: &str,
    content_hash: &str,
) -> Result<Value, IfcDenial> {
    derive_boundary_output_label(
        parents,
        label_ref,
        content_hash,
        "memory_import",
        "memory_import",
        "declared",
        "none",
    )
}

/// Label a summary before it enters durable memory. Summarization may reduce
/// representation size, but it cannot reduce any information-flow axis or
/// turn the summary into executable instruction.
pub fn memory_summary_label(
    parents: &[Value],
    label_ref: &str,
    content_hash: &str,
) -> Result<Value, IfcDenial> {
    derive_boundary_output_label(
        parents,
        label_ref,
        content_hash,
        "summarization",
        "memory_import",
        "declared",
        "none",
    )
}

/// Attach the canonical restrictive label immediately before durable memory
/// storage, then invoke the storage implementation. Any label already present
/// on a replayed record is treated as another parent instead of being trusted
/// as the result, which prevents edit/import relabeling from laundering data.
///
/// `derivation_kind` is deliberately limited to the two v1 memory-boundary
/// transformations. The closure is not called unless the actual supplied
/// parent set is non-empty and every parent is contract-valid.
pub fn invoke_memory_store_after_ifc<F, T>(
    payload: &mut Value,
    supplied_parent_labels: &[Value],
    label_ref: &str,
    derivation_kind: &str,
    invoker: F,
) -> Result<T, IfcDenial>
where
    F: FnOnce(&Value) -> T,
{
    if supplied_parent_labels.is_empty() {
        return Err(IfcDenial::new(
            "ifc_memory_parent_labels_required",
            "memory storage requires the actual supplied parent-label set",
        ));
    }
    let object = payload.as_object_mut().ok_or_else(|| {
        IfcDenial::new(
            "ifc_memory_payload_invalid",
            "memory storage payload must be an object",
        )
    })?;
    let prior_label = object.remove("information_flow_label");
    let content_hash = sha256_value(payload)?;
    let mut parents = supplied_parent_labels.to_vec();
    if let Some(prior_label) = prior_label {
        parents.push(prior_label);
    }
    let label = match derivation_kind {
        "memory_import" => memory_storage_label(&parents, label_ref, &content_hash)?,
        "summarization" => memory_summary_label(&parents, label_ref, &content_hash)?,
        _ => {
            return Err(IfcDenial::new(
                "ifc_memory_derivation_kind_invalid",
                "memory storage derivation must be memory_import or summarization",
            ))
        }
    };
    payload
        .as_object_mut()
        .expect("memory payload object was checked above")
        .insert("information_flow_label".to_string(), label);
    Ok(invoker(payload))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    fn hash(ch: char) -> String {
        format!("sha256:{}", ch.to_string().repeat(64))
    }

    fn label(origin: &str, integrity: &str, confidentiality: &str, authority: &str) -> Value {
        json!({
            "schema_version": "ioi.foundations.information-flow-label.v1",
            "label_ref": "ifc-label://test/input",
            "profile_ref": "policy://ifc/default-v1",
            "content_hash": hash('a'),
            "origin": origin,
            "integrity": integrity,
            "confidentiality": confidentiality,
            "instruction_authority": authority,
            "egress_policy": {
                "mode": if matches!(confidentiality, "private" | "restricted") { "declassification_required" } else { "allow_declared" },
                "allowed_destination_patterns": ["https://api.example.test/v1/*"],
                "allowed_data_classes": ["public", "internal", "confidential", "private", "restricted"]
            },
            "purpose": "test-effect",
            "retention": { "max_seconds": 60, "disposition": "delete" },
            "derivation_kind": "direct",
            "derivation_parent_refs": [],
            "derivation_closure_refs": ["ifc-label://test/input"]
        })
    }

    fn tool_contract(destinations: Vec<&str>) -> Value {
        json!({
            "schema_version": "ioi.components.connectors-tools.runtime-tool-contract.v1",
            "tool_id": "tool://example.send",
            "revision_ref": "tool://example.send/revision/1.0.0",
            "predecessor_revision_ref": null,
            "content_hash": hash('b'),
            "namespace": "example",
            "display_name": "Send example",
            "version": "1.0.0",
            "risk_class": "external_message",
            "effect_class": "external_message",
            "primitive_capabilities_required": ["prim:net.request"],
            "authority_scopes_required": ["scope:example.send"],
            "approval_required": true,
            "evidence_required": ["request_preview"],
            "owner": "connector://example",
            "data_class_allowlist": ["public", "internal", "confidential"],
            "egress_policy": {
                "default": "allow_declared",
                "allowed_destination_patterns": destinations
            }
        })
    }

    fn approval_for(
        label: &Value,
        tool: &Value,
        destination: &str,
        method: &str,
        request: &Value,
        reviewed: &Value,
    ) -> Value {
        let binding = effect_binding(method, destination, request, Some(reviewed)).unwrap();
        json!({
            "schema_version": "ioi.foundations.declassification-approval.v1",
            "approval_ref": "approval://test/exact",
            "issuer_ref": "wallet://test",
            "subject_ref": "agent://test",
            "authority_grant_ref": "grant://test/declassify",
            "tool_contract_revision_ref": tool["revision_ref"],
            "label_ref": label["label_ref"],
            "label_content_hash": label["content_hash"],
            "decision": "allow",
            "declassified_to": "public",
            "exact_effect_hash": binding.effect_hash,
            "exact_request_hash": binding.request_hash,
            "reviewed_representation_hash": binding.reviewed_representation_hash,
            "destination": destination,
            "purpose": label["purpose"],
            "issued_at": "2026-07-16T00:00:00Z",
            "expires_at": "2099-07-16T00:05:00Z",
            "status": "active",
            "approval_receipt_ref": "receipt://test/exact"
        })
    }

    #[tokio::test]
    async fn private_untrusted_flow_never_calls_external_invoker() {
        let label = label(
            "external_untrusted",
            "untrusted",
            "private",
            "authoritative",
        );
        let tool = tool_contract(vec!["https://api.example.test/v1/*"]);
        let request = json!({ "private": "secret" });
        let reviewed = request.clone();
        let approval = approval_for(
            &label,
            &tool,
            "https://api.example.test/v1/send",
            "POST",
            &request,
            &reviewed,
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let invoked = calls.clone();
        let result = invoke_after_ifc(
            &PreEffectAdmission {
                label: &label,
                tool_contract: &tool,
                destination: "https://api.example.test/v1/send",
                method: "POST",
                request: &request,
                reviewed_representation: Some(&reviewed),
                declassification_approval: Some(&approval),
            },
            move |_| async move {
                invoked.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert_eq!(result.unwrap_err().code, "ifc_private_untrusted_egress");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn parent_aware_browser_boundary_denies_laundered_private_observation_before_driver() {
        let mut parent = label("external_untrusted", "untrusted", "private", "untrusted");
        parent["label_ref"] = json!("ifc-label://browser/private-observation");
        let mut authority = label("operator", "verified", "public", "authoritative");
        authority["label_ref"] = json!("ifc-label://browser/navigation-authority");
        let tool = tool_contract(vec!["https://api.example.test/v1/*"]);
        let request = json!({"url": "https://api.example.test/v1/next"});
        let calls = Arc::new(AtomicUsize::new(0));
        let invoked = Arc::clone(&calls);
        let denied = invoke_with_parents_after_ifc(
            &[parent],
            &authority,
            &tool,
            "https://api.example.test/v1/next",
            "GET",
            &request,
            None,
            None,
            move |_| async move { invoked.fetch_add(1, Ordering::SeqCst) },
        )
        .await
        .expect_err("private untrusted browser context must fail before navigation");
        assert_eq!(denied.code, "ifc_private_untrusted_egress");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn private_verified_input_cannot_launder_through_raw_model_output() {
        let mut private_input = label("operator", "verified", "private", "context_only");
        private_input["label_ref"] = json!("ifc-label://model/private-input");
        let output_hash = sha256_value(&json!({"text": "provider response"})).unwrap();
        let model_output = model_output_label(
            &[private_input],
            "ifc-label://model/raw-output",
            &output_hash,
        )
        .expect("model output label");
        assert_eq!(model_output["integrity"], "untrusted");
        assert_eq!(model_output["instruction_authority"], "none");

        let mut authority = label("operator", "verified", "public", "authoritative");
        authority["label_ref"] = json!("ifc-label://model/followup-authority");
        let tool = tool_contract(vec!["https://api.example.test/v1/*"]);
        let request = json!({"message": "send provider response"});
        let calls = Arc::new(AtomicUsize::new(0));
        let invoked = Arc::clone(&calls);
        let denied = invoke_with_parents_after_ifc(
            &[model_output],
            &authority,
            &tool,
            "https://api.example.test/v1/send",
            "POST",
            &request,
            None,
            None,
            move |_| async move { invoked.fetch_add(1, Ordering::SeqCst) },
        )
        .await
        .expect_err("raw private model output must not authorize egress");
        assert_eq!(denied.code, "ifc_private_untrusted_egress");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn effective_effect_label_ref_binds_request_and_parent_identity() {
        let mut parent = label("operator", "verified", "public", "context_only");
        parent["label_ref"] = json!("ifc-label://effect/parent-a");
        let mut authority = label("admitted_artifact", "admitted", "public", "authoritative");
        authority["label_ref"] = json!("ifc-label://effect/authority");

        let first = compile_admitted_effect_label(&[parent.clone()], &authority, &hash('c'))
            .expect("first effect label");
        let changed_request =
            compile_admitted_effect_label(&[parent.clone()], &authority, &hash('d'))
                .expect("changed-request effect label");
        assert_ne!(first["label_ref"], changed_request["label_ref"]);

        let mut axis_changed_parent = parent.clone();
        axis_changed_parent["confidentiality"] = json!("confidential");
        let axis_changed =
            compile_admitted_effect_label(&[axis_changed_parent], &authority, &hash('c'))
                .expect("axis-changed-parent effect label");
        assert_ne!(first["label_ref"], axis_changed["label_ref"]);

        parent["content_hash"] = json!(hash('e'));
        let changed_parent = compile_admitted_effect_label(&[parent], &authority, &hash('c'))
            .expect("changed-parent effect label");
        assert_ne!(first["label_ref"], changed_parent["label_ref"]);
        assert!(first["derivation_closure_refs"]
            .as_array()
            .is_some_and(|refs| refs.contains(&json!("ifc-label://effect/authority"))));
    }

    #[test]
    fn approval_is_invalidated_by_effect_review_or_destination_mutation() {
        let label = label("operator", "verified", "private", "authoritative");
        let tool = tool_contract(vec!["https://api.example.test/v1/*"]);
        let request = json!({ "private": "secret" });
        let reviewed = json!({ "preview": "secret" });
        let approval = approval_for(
            &label,
            &tool,
            "https://api.example.test/v1/send",
            "POST",
            &request,
            &reviewed,
        );
        for (destination, changed_request, changed_reviewed) in [
            (
                "https://api.example.test/v1/other",
                request.clone(),
                reviewed.clone(),
            ),
            (
                "https://api.example.test/v1/send",
                json!({ "private": "changed" }),
                reviewed.clone(),
            ),
            (
                "https://api.example.test/v1/send",
                request.clone(),
                json!({ "preview": "changed" }),
            ),
        ] {
            let result = admit_pre_effect(&PreEffectAdmission {
                label: &label,
                tool_contract: &tool,
                destination,
                method: "POST",
                request: &changed_request,
                reviewed_representation: Some(&changed_reviewed),
                declassification_approval: Some(&approval),
            });
            assert_eq!(
                result.unwrap_err().code,
                "ifc_declassification_binding_mismatch"
            );
        }
    }

    #[test]
    fn derivation_helpers_preserve_most_restrictive_axes_and_full_closure() {
        let public = label("operator", "verified", "public", "authoritative");
        let mut private = label("tool_output", "untrusted", "private", "untrusted");
        private["label_ref"] = json!("ifc-label://test/private-parent");
        private["derivation_closure_refs"] = json!([
            "ifc-label://test/grandparent",
            "ifc-label://test/private-parent"
        ]);
        for derived in [
            summarize_label(
                &[public.clone(), private.clone()],
                "ifc-label://test/summary",
                &hash('c'),
            )
            .unwrap(),
            model_substitution_label(
                &[public.clone(), private.clone()],
                "ifc-label://test/model-substitution",
                &hash('d'),
            )
            .unwrap(),
            memory_import_label(
                &[public.clone(), private.clone()],
                "ifc-label://test/memory-import",
                &hash('e'),
            )
            .unwrap(),
        ] {
            assert_eq!(derived["confidentiality"], "private");
            assert_eq!(derived["integrity"], "untrusted");
            assert_eq!(derived["instruction_authority"], "untrusted");
            let closure = derived["derivation_closure_refs"].as_array().unwrap();
            assert!(closure.contains(&json!("ifc-label://test/grandparent")));
            assert!(closure.contains(&json!("ifc-label://test/private-parent")));
        }
    }

    #[test]
    fn memory_storage_recomputes_restrictive_join_and_never_invokes_without_parents() {
        let calls = Arc::new(AtomicUsize::new(0));
        let missing_parent_calls = Arc::clone(&calls);
        let mut unlabeled_payload = json!({"fact": "private operational fact"});
        let denied = invoke_memory_store_after_ifc(
            &mut unlabeled_payload,
            &[],
            "ifc-label://memory/test",
            "memory_import",
            |_| missing_parent_calls.fetch_add(1, Ordering::SeqCst),
        )
        .expect_err("unlabeled memory must fail before storage");
        assert_eq!(denied.code, "ifc_memory_parent_labels_required");
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let mut private_parent = label("external_untrusted", "untrusted", "private", "untrusted");
        private_parent["label_ref"] = json!("ifc-label://memory/private-parent");
        let mut forged_public = label("operator", "verified", "public", "authoritative");
        forged_public["label_ref"] = json!("ifc-label://memory/forged-public");
        let mut payload = json!({
            "fact": "private operational fact",
            "information_flow_label": forged_public,
        });
        let successful_calls = Arc::clone(&calls);
        invoke_memory_store_after_ifc(
            &mut payload,
            &[private_parent],
            "ifc-label://memory/stored",
            "summarization",
            |_| successful_calls.fetch_add(1, Ordering::SeqCst),
        )
        .expect("storage should preserve the restrictive join");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            payload["information_flow_label"]["confidentiality"],
            "private"
        );
        assert_eq!(payload["information_flow_label"]["integrity"], "untrusted");
        assert_eq!(
            payload["information_flow_label"]["instruction_authority"],
            "untrusted"
        );
        assert_eq!(
            payload["information_flow_label"]["derivation_kind"],
            "summarization"
        );
    }

    #[test]
    fn public_verified_declared_flow_is_allowed() {
        let label = label("operator", "verified", "public", "authoritative");
        let tool = tool_contract(vec!["https://api.example.test/v1/*"]);
        let request = json!({ "hello": "world" });
        let result = admit_pre_effect(&PreEffectAdmission {
            label: &label,
            tool_contract: &tool,
            destination: "https://api.example.test/v1/send",
            method: "POST",
            request: &request,
            reviewed_representation: None,
            declassification_approval: None,
        });
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn shared_adversarial_fixture_matrix_matches_rust_evaluator() {
        let fixture: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/information-flow/ifc-cases.v1.json"
        )))
        .unwrap();
        let destination = fixture["destination"].as_str().unwrap();
        let changed_destination = fixture["changed_destination"].as_str().unwrap();
        let request = fixture["request"].clone();
        let changed_request = fixture["changed_request"].clone();
        let reviewed = fixture["reviewed_representation"].clone();
        let changed_reviewed = fixture["changed_reviewed_representation"].clone();

        for case in fixture["cases"].as_array().unwrap() {
            let id = case["id"].as_str().unwrap();
            let label = label(
                case["origin"].as_str().unwrap(),
                case["integrity"].as_str().unwrap(),
                case["confidentiality"].as_str().unwrap(),
                case["instruction_authority"].as_str().unwrap(),
            );
            let declarations = case["tool_destination_declarations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect();
            let tool = tool_contract(declarations);
            let approval = case["with_approval"]
                .as_bool()
                .unwrap()
                .then(|| approval_for(&label, &tool, destination, "POST", &request, &reviewed));
            let mutation = case["mutation"].as_str().unwrap();
            let actual_destination = if mutation == "destination" {
                changed_destination
            } else {
                destination
            };
            let actual_request = if mutation == "request" {
                &changed_request
            } else {
                &request
            };
            let actual_reviewed = if mutation == "reviewed_representation" {
                &changed_reviewed
            } else {
                &reviewed
            };
            let result = admit_pre_effect(&PreEffectAdmission {
                label: &label,
                tool_contract: &tool,
                destination: actual_destination,
                method: "POST",
                request: actual_request,
                reviewed_representation: Some(actual_reviewed),
                declassification_approval: approval.as_ref(),
            });
            assert_eq!(
                result.is_ok(),
                case["expected_ok"].as_bool().unwrap(),
                "{id}: {result:?}"
            );
            if let Some(expected_code) = case["expected_code"].as_str() {
                assert_eq!(result.unwrap_err().code, expected_code, "{id}");
            }
        }
    }
}
