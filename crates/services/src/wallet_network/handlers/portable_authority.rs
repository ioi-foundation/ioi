use std::collections::BTreeSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::VaultAuditEventKind;
use ioi_types::app::SignatureSuite;
use ioi_types::error::TransactionError;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::wallet_network::handlers::principal_authority::validate_expected_principal_authority_binding;
use crate::wallet_network::keys::{
    portable_authority_ceremony_consumption_key, portable_authority_effect_consumption_receipt_key,
    portable_authority_grant_v3_state_key,
};
use crate::wallet_network::portable_authority::{
    verify_portable_authority_issuance_bundle_v3, verify_portable_authority_v3,
    PortableAuthorityIssuanceBundleV3Input, PortableAuthorityVerificationInput,
    TrustedPortableAuthorityDelegationClosure,
};
use crate::wallet_network::support::{
    append_audit_event_with_records, base_audit_metadata, block_timestamp_ms, load_typed,
};
use crate::wallet_network::{
    ConsumePortableAuthorityGrantV3ForEffectParams, PortableAuthorityCeremonyConsumptionV1,
    PortableAuthorityGrantV3ConsumptionReceipt, PortableAuthorityGrantV3State,
    PortableAuthorityGrantV3Status, PortableAuthorityIssuerBindingV1,
    RecordPortableAuthorityGrantV3Params,
};

const PORTABLE_ISSUER_SCOPE: &str = "scope:wallet.authority.portable.issue";
const MAX_EVIDENCE_BYTES: usize = 256 * 1024;
const MAX_CHAIN_DEPTH: usize = 32;
const MAX_ISSUERS: usize = 32;

fn invalid(message: impl Into<String>) -> TransactionError {
    TransactionError::Invalid(format!("portable_authority_v3: {}", message.into()))
}

fn parse_canonical_json(bytes: &[u8], label: &str) -> Result<(Value, Vec<u8>), TransactionError> {
    if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(invalid(format!(
            "{label} must contain 1..={MAX_EVIDENCE_BYTES} bytes"
        )));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("{label} is invalid JSON: {error}")))?;
    let canonical = serde_jcs::to_vec(&value)
        .map_err(|error| invalid(format!("{label} cannot be canonicalized: {error}")))?;
    Ok((value, canonical))
}

fn parse_json_set(
    entries: &[Vec<u8>],
    label: &str,
    max: usize,
) -> Result<(Vec<Value>, Vec<Vec<u8>>), TransactionError> {
    if entries.is_empty() || entries.len() > max {
        return Err(invalid(format!("{label} count must be 1..={max}")));
    }
    let mut values = Vec::with_capacity(entries.len());
    let mut canonical = Vec::with_capacity(entries.len());
    for (index, bytes) in entries.iter().enumerate() {
        let (value, bytes) = parse_canonical_json(bytes, &format!("{label}[{index}]"))?;
        values.push(value);
        canonical.push(bytes);
    }
    Ok((values, canonical))
}

fn hash32(value: &str, label: &str) -> Result<[u8; 32], TransactionError> {
    let encoded = value
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid(format!("{label} is not a sha256 ref")))?;
    if encoded.len() != 64
        || encoded != encoded.to_ascii_lowercase()
        || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid(format!(
            "{label} is not 32 lowercase hexadecimal bytes"
        )));
    }
    let decoded = hex::decode(encoded).map_err(|_| invalid(format!("{label} is not hex")))?;
    let mut output = [0u8; 32];
    output.copy_from_slice(&decoded);
    if output == [0; 32] {
        return Err(invalid(format!("{label} must not be zero")));
    }
    Ok(output)
}

fn validate_issuer_authorities(
    state: &dyn StateAccess,
    ctx: &TxContext<'_>,
    grants: &[Value],
    key_sets: &[Value],
    snapshots: &[Value],
    expected: &[PortableAuthorityIssuerBindingV1],
) -> Result<(), TransactionError> {
    let mut required_issuers = BTreeSet::new();
    let mut required_coordinates = BTreeSet::new();
    for grant in grants {
        let issuer = grant
            .get("issuer_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("grant issuer_id is absent"))?;
        let key_set_ref = grant
            .get("issuer_key_set_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("grant issuer_key_set_ref is absent"))?;
        let version = grant
            .get("issuer_key_set_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("grant issuer_key_set_version is absent"))?;
        required_issuers.insert(issuer.to_owned());
        required_coordinates.insert((issuer.to_owned(), key_set_ref.to_owned(), version));
    }
    if required_issuers.len() != expected.len() || required_issuers.len() > MAX_ISSUERS {
        return Err(invalid(
            "issuer-authority bindings must be an exact unique projection of the grant chain",
        ));
    }
    let supplied_key_coordinates: BTreeSet<_> = key_sets
        .iter()
        .map(|key_set| {
            Ok::<_, TransactionError>((
                key_set
                    .get("issuer_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("key set issuer_id is absent"))?
                    .to_owned(),
                key_set
                    .get("key_set_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("key set key_set_id is absent"))?
                    .to_owned(),
                key_set
                    .get("version")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| invalid("key set version is absent"))?,
            ))
        })
        .collect::<Result<_, _>>()?;
    let supplied_snapshot_coordinates: BTreeSet<_> = snapshots
        .iter()
        .map(|snapshot| {
            Ok::<_, TransactionError>((
                snapshot
                    .get("issuer_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("snapshot issuer_id is absent"))?
                    .to_owned(),
                snapshot
                    .get("issuer_key_set_ref")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("snapshot issuer_key_set_ref is absent"))?
                    .to_owned(),
                snapshot
                    .get("issuer_key_set_version")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| invalid("snapshot key-set version is absent"))?,
            ))
        })
        .collect::<Result<_, _>>()?;
    if supplied_key_coordinates != required_coordinates
        || supplied_snapshot_coordinates != required_coordinates
        || key_sets.len() != required_coordinates.len()
        || snapshots.len() != required_coordinates.len()
    {
        return Err(invalid(
            "trusted key sets and revocation snapshots must exactly cover the chain coordinates",
        ));
    }
    let mut seen = BTreeSet::new();
    for issuer_binding in expected {
        let binding = &issuer_binding.current_authority;
        if binding.required_scope != PORTABLE_ISSUER_SCOPE
            || !seen.insert(issuer_binding.issuer_id.clone())
        {
            return Err(invalid(
                "issuer-authority binding has the wrong scope or a duplicate principal",
            ));
        }
        if !required_issuers.contains(&issuer_binding.issuer_id) {
            return Err(invalid(
                "issuer-authority binding names a foreign principal",
            ));
        }
        let authority = validate_expected_principal_authority_binding(state, ctx, binding)?;
        if authority.signature_suite != SignatureSuite::ED25519 {
            return Err(invalid("portable v3 issuer authority must use Ed25519"));
        }
        for grant in grants.iter().filter(|grant| {
            grant.get("issuer_id").and_then(Value::as_str)
                == Some(issuer_binding.issuer_id.as_str())
        }) {
            let key_set_ref = grant["issuer_key_set_ref"]
                .as_str()
                .ok_or_else(|| invalid("grant issuer_key_set_ref is absent"))?;
            let version = grant["issuer_key_set_version"]
                .as_u64()
                .ok_or_else(|| invalid("grant issuer_key_set_version is absent"))?;
            let key_id = grant["issuer_key_id"]
                .as_str()
                .ok_or_else(|| invalid("grant issuer_key_id is absent"))?;
            let key_set = key_sets
                .iter()
                .find(|candidate| {
                    candidate.get("issuer_id").and_then(Value::as_str)
                        == Some(issuer_binding.issuer_id.as_str())
                        && candidate.get("key_set_id").and_then(Value::as_str) == Some(key_set_ref)
                        && candidate.get("version").and_then(Value::as_u64) == Some(version)
                })
                .ok_or_else(|| invalid("issuer authority has no exact trusted key set"))?;
            let key = key_set
                .get("keys")
                .and_then(Value::as_array)
                .and_then(|keys| {
                    keys.iter().find(|candidate| {
                        candidate.get("key_id").and_then(Value::as_str) == Some(key_id)
                    })
                })
                .ok_or_else(|| invalid("issuer authority key is absent from its key set"))?;
            let public_key = key
                .get("public_key")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("issuer key public_key is absent"))?;
            let public_key = URL_SAFE_NO_PAD
                .decode(public_key)
                .map_err(|_| invalid("issuer key public_key is not base64url"))?;
            if public_key != authority.public_key {
                return Err(invalid(
                    "request-carried key set differs from current owner authority",
                ));
            }
        }
    }
    Ok(())
}

struct ParsedPortableState {
    grants: Vec<Value>,
    key_sets: Vec<Value>,
    snapshots: Vec<Value>,
    closure: Option<TrustedPortableAuthorityDelegationClosure>,
    request: Value,
    context: Value,
    review: Value,
}

fn parse_state(
    record: &PortableAuthorityGrantV3State,
) -> Result<ParsedPortableState, TransactionError> {
    let (grants, _) = parse_json_set(&record.grant_chain_json, "grant_chain", MAX_CHAIN_DEPTH)?;
    let (key_sets, _) = parse_json_set(
        &record.trusted_key_sets_json,
        "trusted_key_sets",
        MAX_ISSUERS,
    )?;
    let (snapshots, _) = parse_json_set(
        &record.revocation_snapshots_json,
        "revocation_snapshots",
        MAX_ISSUERS,
    )?;
    let closure = record
        .delegation_closure_json
        .as_ref()
        .map(|bytes| {
            let (value, _) = parse_canonical_json(bytes, "delegation_closure")?;
            serde_json::from_value(value)
                .map_err(|error| invalid(format!("delegation closure is malformed: {error}")))
        })
        .transpose()?;
    Ok(ParsedPortableState {
        grants,
        key_sets,
        snapshots,
        closure,
        request: parse_canonical_json(&record.authority_request_json, "authority_request")?.0,
        context: parse_canonical_json(
            &record.approval_ceremony_context_json,
            "approval_ceremony_context",
        )?
        .0,
        review: parse_canonical_json(
            &record.authority_review_receipt_json,
            "authority_review_receipt",
        )?
        .0,
    })
}

pub(crate) fn record_portable_authority_grant_v3(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: RecordPortableAuthorityGrantV3Params,
) -> Result<(), TransactionError> {
    let (grants, grant_chain_json) =
        parse_json_set(&params.grant_chain_json, "grant_chain", MAX_CHAIN_DEPTH)?;
    let (key_sets, trusted_key_sets_json) = parse_json_set(
        &params.trusted_key_sets_json,
        "trusted_key_sets",
        MAX_ISSUERS,
    )?;
    let (snapshots, revocation_snapshots_json) = parse_json_set(
        &params.revocation_snapshots_json,
        "revocation_snapshots",
        MAX_ISSUERS,
    )?;
    let (request, authority_request_json) =
        parse_canonical_json(&params.authority_request_json, "authority_request")?;
    let (context, approval_ceremony_context_json) = parse_canonical_json(
        &params.approval_ceremony_context_json,
        "approval_ceremony_context",
    )?;
    let (review, authority_review_receipt_json) = parse_canonical_json(
        &params.authority_review_receipt_json,
        "authority_review_receipt",
    )?;
    let (closure, delegation_closure_json) = params
        .delegation_closure_json
        .as_ref()
        .map(|bytes| {
            let (value, canonical) = parse_canonical_json(bytes, "delegation_closure")?;
            let closure = serde_json::from_value(value)
                .map_err(|error| invalid(format!("delegation closure is malformed: {error}")))?;
            Ok::<_, TransactionError>((Some(closure), Some(canonical)))
        })
        .transpose()?
        .unwrap_or((None, None));

    validate_issuer_authorities(
        state,
        ctx,
        &grants,
        &key_sets,
        &snapshots,
        &params.issuer_authorities,
    )?;
    let leaf = grants
        .last()
        .ok_or_else(|| invalid("grant chain must not be empty"))?;
    let expected_audience = leaf
        .get("audience")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("leaf audience is absent"))?;
    let expected_holder_id = leaf
        .get("holder_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("leaf holder_id is absent"))?;
    let expected_holder_key_id = leaf
        .get("holder_key_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("leaf holder_key_id is absent"))?;
    let now_seconds = block_timestamp_ms(ctx) / 1_000;
    let verified = verify_portable_authority_v3(PortableAuthorityVerificationInput {
        grant_chain: &grants,
        trusted_key_sets: &key_sets,
        revocation_snapshots: &snapshots,
        now: now_seconds,
        max_snapshot_age_seconds: 300,
        expected_audience,
        expected_holder_id,
        expected_holder_key_id,
        consumed_grant_refs: &BTreeSet::new(),
        delegation_closure: closure.as_ref(),
    })
    .map_err(|error| invalid(error.to_string()))?;
    let issuance =
        verify_portable_authority_issuance_bundle_v3(PortableAuthorityIssuanceBundleV3Input {
            verified_grant: &verified,
            leaf_grant: leaf,
            authority_request: &request,
            approval_ceremony_context: &context,
            authority_review_receipt: &review,
        })
        .map_err(|error| invalid(error.to_string()))?;
    let grant_hash = hash32(&issuance.authority_grant_hash, "grant body hash")?;
    let ceremony_hash = hash32(
        &issuance.approval_ceremony_context_hash,
        "approval ceremony context hash",
    )?;
    let max_calls = verified.max_calls;
    if max_calls == 0 {
        return Err(invalid("portable grant max_calls must be positive"));
    }
    let key = portable_authority_grant_v3_state_key(&grant_hash);
    if let Some(existing) = load_typed::<PortableAuthorityGrantV3State>(state, &key)? {
        let immutable_same = existing.schema_version == 1
            && existing.authority_grant_ref == issuance.authority_grant_ref
            && existing.grant_hash == grant_hash
            && existing.grant_chain_json == grant_chain_json
            && existing.trusted_key_sets_json == trusted_key_sets_json
            && existing.revocation_snapshots_json == revocation_snapshots_json
            && existing.delegation_closure_json == delegation_closure_json
            && existing.authority_request_json == authority_request_json
            && existing.approval_ceremony_context_json == approval_ceremony_context_json
            && existing.authority_review_receipt_json == authority_review_receipt_json
            && existing.issuer_authorities == params.issuer_authorities
            && existing.max_calls == max_calls;
        if immutable_same {
            return Ok(());
        }
        return Err(invalid(
            "grant hash is already bound to different owner state",
        ));
    }
    let ceremony_key = portable_authority_ceremony_consumption_key(&ceremony_hash);
    if let Some(existing) =
        load_typed::<PortableAuthorityCeremonyConsumptionV1>(state, &ceremony_key)?
    {
        if existing.grant_hash != grant_hash {
            return Err(invalid(
                "single-use approval ceremony already minted a different portable grant",
            ));
        }
    }
    let record = PortableAuthorityGrantV3State {
        schema_version: 1,
        authority_grant_ref: issuance.authority_grant_ref,
        grant_hash,
        grant_chain_json,
        trusted_key_sets_json,
        revocation_snapshots_json,
        delegation_closure_json,
        authority_request_json,
        approval_ceremony_context_json,
        authority_review_receipt_json,
        issuer_authorities: params.issuer_authorities,
        max_calls,
        uses_consumed: 0,
        remaining_calls: max_calls,
        last_consumed_at_ms: None,
        status: PortableAuthorityGrantV3Status::Active,
    };
    let ceremony = PortableAuthorityCeremonyConsumptionV1 {
        schema_version: 1,
        approval_ceremony_context_hash: ceremony_hash,
        grant_hash,
        consumed_at_ms: block_timestamp_ms(ctx),
    };
    let mut metadata = base_audit_metadata(ctx);
    metadata.insert("portable_grant_hash".into(), hex::encode(grant_hash));
    metadata.insert(
        "portable_grant_ref".into(),
        record.authority_grant_ref.clone(),
    );
    append_audit_event_with_records(
        state,
        ctx,
        VaultAuditEventKind::ApprovalDecided,
        metadata,
        |_| {
            Ok(vec![
                (key, ioi_types::codec::to_bytes_canonical(&record)?),
                (
                    ceremony_key,
                    ioi_types::codec::to_bytes_canonical(&ceremony)?,
                ),
            ])
        },
    )
    .map(|_| ())
}

fn receipt_hash(
    receipt: &PortableAuthorityGrantV3ConsumptionReceipt,
) -> Result<[u8; 32], TransactionError> {
    let mut value = serde_json::to_value(receipt)
        .map_err(|error| invalid(format!("consumption receipt is not serializable: {error}")))?;
    value["receipt_hash"] = serde_json::json!(vec![0u8; 32]);
    let canonical = serde_jcs::to_vec(&value)
        .map_err(|error| invalid(format!("consumption receipt is not canonical: {error}")))?;
    Ok(Sha256::digest(canonical).into())
}

fn validate_receipt(
    receipt: &PortableAuthorityGrantV3ConsumptionReceipt,
    params: &ConsumePortableAuthorityGrantV3ForEffectParams,
) -> Result<(), TransactionError> {
    if receipt.schema_version != 1
        || receipt.receipt_hash != receipt_hash(receipt)?
        || receipt.grant_hash != params.grant_hash
        || receipt.consumption_id != params.consumption_id
        || receipt.actual_effect_ref != params.actual_effect_ref
        || receipt.actual_effect_hash != params.actual_effect_hash
        || receipt.audience != params.expected_audience
        || receipt.holder_id != params.expected_holder_id
        || receipt.holder_key_id != params.expected_holder_key_id
    {
        return Err(invalid(
            "consumption id is bound to a different grant, effect, audience, or holder",
        ));
    }
    Ok(())
}

pub(crate) fn consume_portable_authority_grant_v3_for_effect(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ConsumePortableAuthorityGrantV3ForEffectParams,
) -> Result<(), TransactionError> {
    if params.grant_hash == [0; 32]
        || params.consumption_id == [0; 32]
        || params.actual_effect_hash == [0; 32]
        || params.expected_audience.is_empty()
        || params.expected_holder_id.is_empty()
        || params.expected_holder_key_id.is_empty()
        || params.actual_effect_ref.is_empty()
    {
        return Err(invalid(
            "consumption parameters contain an empty identity or hash",
        ));
    }
    let receipt_key = portable_authority_effect_consumption_receipt_key(&params.consumption_id);
    if let Some(existing) =
        load_typed::<PortableAuthorityGrantV3ConsumptionReceipt>(state, &receipt_key)?
    {
        validate_receipt(&existing, &params)?;
        return Ok(());
    }
    let state_key = portable_authority_grant_v3_state_key(&params.grant_hash);
    let mut record: PortableAuthorityGrantV3State = load_typed(state, &state_key)?
        .ok_or_else(|| invalid("portable grant is not registered"))?;
    if record.status != PortableAuthorityGrantV3Status::Active
        || record.remaining_calls == 0
        || record.uses_consumed.saturating_add(record.remaining_calls) != record.max_calls
    {
        return Err(invalid(
            "portable grant is revoked, exhausted, or has invalid counters",
        ));
    }
    let parsed = parse_state(&record)?;
    validate_issuer_authorities(
        state,
        ctx,
        &parsed.grants,
        &parsed.key_sets,
        &parsed.snapshots,
        &record.issuer_authorities,
    )?;
    let leaf = parsed
        .grants
        .last()
        .ok_or_else(|| invalid("stored grant chain is empty"))?;
    let verified = verify_portable_authority_v3(PortableAuthorityVerificationInput {
        grant_chain: &parsed.grants,
        trusted_key_sets: &parsed.key_sets,
        revocation_snapshots: &parsed.snapshots,
        now: block_timestamp_ms(ctx) / 1_000,
        max_snapshot_age_seconds: 300,
        expected_audience: &params.expected_audience,
        expected_holder_id: &params.expected_holder_id,
        expected_holder_key_id: &params.expected_holder_key_id,
        consumed_grant_refs: &BTreeSet::new(),
        delegation_closure: parsed.closure.as_ref(),
    })
    .map_err(|error| invalid(error.to_string()))?;
    verify_portable_authority_issuance_bundle_v3(PortableAuthorityIssuanceBundleV3Input {
        verified_grant: &verified,
        leaf_grant: leaf,
        authority_request: &parsed.request,
        approval_ceremony_context: &parsed.context,
        authority_review_receipt: &parsed.review,
    })
    .map_err(|error| invalid(error.to_string()))?;
    let effect_hash_ref = format!("sha256:{}", hex::encode(params.actual_effect_hash));
    if leaf
        .pointer("/request_commitment/authorization_subject/kind")
        .and_then(Value::as_str)
        == Some("exact_effect")
        && (leaf
            .pointer("/request_commitment/authorization_subject/subject_ref")
            .and_then(Value::as_str)
            != Some(params.actual_effect_ref.as_str())
            || leaf
                .pointer("/request_commitment/authorization_subject/subject_hash")
                .and_then(Value::as_str)
                != Some(effect_hash_ref.as_str()))
    {
        return Err(invalid(
            "daemon-derived exact effect differs from the portable authorization subject",
        ));
    }

    record.uses_consumed = record
        .uses_consumed
        .checked_add(1)
        .ok_or_else(|| invalid("portable usage counter overflow"))?;
    record.remaining_calls = record.remaining_calls.saturating_sub(1);
    record.last_consumed_at_ms = Some(block_timestamp_ms(ctx));
    if record.remaining_calls == 0 {
        record.status = PortableAuthorityGrantV3Status::Exhausted;
    }
    let mut receipt = PortableAuthorityGrantV3ConsumptionReceipt {
        schema_version: 1,
        receipt_hash: [0; 32],
        grant_hash: params.grant_hash,
        consumption_id: params.consumption_id,
        authority_grant_ref: verified.authority_grant_ref,
        actual_effect_ref: params.actual_effect_ref,
        actual_effect_hash: params.actual_effect_hash,
        audience: params.expected_audience,
        holder_id: params.expected_holder_id,
        holder_key_id: params.expected_holder_key_id,
        consumed_at_ms: block_timestamp_ms(ctx),
        usage_ordinal: record.uses_consumed,
        remaining_calls: record.remaining_calls,
    };
    receipt.receipt_hash = receipt_hash(&receipt)?;
    let mut metadata = base_audit_metadata(ctx);
    metadata.insert("portable_grant_hash".into(), hex::encode(params.grant_hash));
    metadata.insert("consumption_id".into(), hex::encode(params.consumption_id));
    metadata.insert("remaining_calls".into(), record.remaining_calls.to_string());
    append_audit_event_with_records(
        state,
        ctx,
        VaultAuditEventKind::ApprovalDecided,
        metadata,
        |_| {
            Ok(vec![
                (state_key, ioi_types::codec::to_bytes_canonical(&record)?),
                (receipt_key, ioi_types::codec::to_bytes_canonical(&receipt)?),
            ])
        },
    )
    .map(|_| ())
}
