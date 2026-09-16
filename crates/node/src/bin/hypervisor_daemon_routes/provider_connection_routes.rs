//! M03.16 — external-account connection and brokered-credential lifecycle: connected is not
//! authorized.
//!
//! Canon: `components/wallet-network/api-authority-scopes.md` § Provider Connection Binding (the
//! eight verbs; the ceremony's members; what completion validates and refuses; the binding's
//! shape; fencing at final admission; successor lineage on reconnect) and `doctrine.md` § the five
//! truths the word "connect" must not collapse. Two registered families live here on the shared
//! owner-scoped mutation chain:
//!
//!   * THE CEREMONY (`connection-ceremony://…`): single-use and expiring, admitted at
//!     `authorization/start` bound to the RESOLVED principal, the exact provider profile revision
//!     (content-addressed over the connector's registered auth profile with sealed members
//!     excluded), the exact redirect, state and nonce, the S256 challenge of a verifier that is
//!     SEALED server-side and never a member, the requested scopes, the custody profile, the
//!     audience classes and the product-session origin. `authorization/complete` names the
//!     ceremony by its state, refuses a completion by another principal, a consumed or expired
//!     ceremony, redirect drift, a profile edited since issue, an exchange the provider refused,
//!     an unresolvable or substituted account subject and a widened scope set — every refusal is
//!     admitted as the ceremony's own `refused` successor so the chain says what happened.
//!   * THE BINDING (`connection://provider/{connector}/{principal}`): versioned append-only;
//!     completion admits version 1 (or a successor on reauthorization and reconnect), `verify`
//!     admits a successor carrying the provider verification it observed, `disconnect` admits a
//!     successor with the revocation epoch advanced and durable dependent obligations. Provider
//!     verification that observes revocation advances the epoch too.
//!
//! THE FENCE is one check site: the capability-lease gateway resolves NO sealed credential whose
//! connection is not `active`, does not act through that exact credential binding at that exact
//! epoch, or has passed its reauthorization deadline (`fence_credential`). Every brokered use — connector
//! sessions, connector execution (REST and MCP `tools/call`), materializing runs — crosses that
//! gateway, so API, SDK and MCP paths share the fence by construction. A credential sealed by the
//! legacy routes without a connection (`/:id/credential`, the device flow) is not a connection and
//! is not fenced by one; that is typed in the register, not hidden.
//!
//! What this basis does NOT hold: a CLI (none exists on the tree); connections for more than one
//! principal per connector (the credential store is keyed by connector); the `superseded` status
//! (a connection family is never replaced by another on this basis; reconnect is a successor
//! version of the same family); provider-native revocation callbacks (revocation is observed by
//! `verify`).

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::lifecycle_routes::{
    exchange_oauth_code, mint_oauth_access_token, oidc_userinfo, open_scm_token, pct,
    pkce_challenge, random_token, seal_oauth_result, seal_scm_token,
};
use super::model_route_rights_routes::{
    authorized_stream, bad, body_str, finish_admission, head_assertion, read_stream,
    reject_authored, replay_for_key, require_exact_head, AdmittedRecord, FamilySpec, Reply,
};
use super::mutation_event_foundation::{
    admitted_stamp, require_write_caller, scope_refusal_reply, stream_tail, WriteCaller,
};
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity, RequestResourceScope,
};
use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const CEREMONY_DOMAIN: &str =
    "ioi.wallet.provider-connection-ceremony-content-commitment-jcs-sha256.v1";
const BINDING_DOMAIN: &str =
    "ioi.wallet.provider-connection-binding-content-commitment-jcs-sha256.v1";
/// A ceremony expires ten minutes after issue: long enough for a human to authorize at the
/// provider, short enough that a leaked state token is worthless by the next coffee.
const CEREMONY_TTL_MS: u64 = 10 * 60 * 1000;
/// Reauthorization is required thirty days after a completion or reauthorization; the provider's
/// refresh-token lifetime is not observable at the token endpoint, so the deadline is policy.
const REAUTHORIZATION_INTERVAL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_CUSTODY_PROFILE: &str = "custody-profile://brokered/local@1";
const DEFAULT_SESSION_ORIGIN: &str = "session://hypervisor/local";
const AUDIENCE_CLASSES: &[&str] = &["connector", "final_invoker"];
const CEREMONY_SECRETS: &str = "provider-connection-ceremony-secrets";
const CEREMONY_STATES: &str = "provider-connection-ceremony-states";
const CONNECTION_EVIDENCE: &str = "provider-connection-evidence";
const CONNECTION_OBLIGATIONS: &str = "connection-dependent-obligations";
const CONNECTION_INDEX: &str = "provider-connection-index";

static CEREMONY: FamilySpec = FamilySpec {
    owner_namespace: "provider-connection-ceremonies",
    resource_kind: "provider_connection_ceremony",
    admit_op: "event_stream.provider_connection_ceremony_admitted",
    payload_schema: "ioi.hypervisor.provider-connection-ceremony-admission.v1",
    contract_id: "schema://ioi/components/wallet-network/provider-connection-ceremony/v1",
    schema_version: "ioi.wallet.provider-connection-ceremony.v1",
    record_key: "provider_connection_ceremony_record",
    code_prefix: "provider_connection_ceremony",
    commitment_domain: CEREMONY_DOMAIN,
    material_fields: &[
        "schema_version",
        "ceremony_ref",
        "owner_ref",
        "principal_ref",
        "connector_ref",
        "provider_profile_ref",
        "redirect",
        "state",
        "nonce",
        "proof",
        "requested_scopes",
        "declared_account_subject",
        "credential_custody_profile_ref",
        "permitted_audience_classes",
        "product_session_origin",
        "issued_at",
        "expires_at",
        "status",
        "completion",
        "refusal",
        "receipt_refs",
    ],
    identity_field: "ceremony_ref",
    ref_scheme: "connection-ceremony://",
    stamp_field: "admitted_at",
};

static CONNECTION: FamilySpec = FamilySpec {
    owner_namespace: "provider-connections",
    resource_kind: "provider_connection",
    admit_op: "event_stream.provider_connection_version_admitted",
    payload_schema: "ioi.hypervisor.provider-connection-admission.v1",
    contract_id: "schema://ioi/components/wallet-network/provider-connection-binding/v1",
    schema_version: "ioi.wallet.provider-connection-binding.v1",
    record_key: "provider_connection_binding_record",
    code_prefix: "provider_connection",
    commitment_domain: BINDING_DOMAIN,
    material_fields: &[
        "schema_version",
        "connection_ref",
        "connection_version",
        "predecessor_ref",
        "owner_ref",
        "principal_ref",
        "connector_ref",
        "provider_profile_ref",
        "provider_account_subject_hash",
        "provider_tenant_subject_hash",
        "provider_granted_scopes",
        "credential_binding_ref",
        "credential_custody_profile_ref",
        "permitted_audience_classes",
        "connection_revocation_epoch",
        "reauthorization_required_at",
        "last_provider_verification",
        "status",
        "successor_ref",
        "ceremony_ref",
        "receipt_refs",
    ],
    identity_field: "connection_ref",
    ref_scheme: "connection://",
    stamp_field: "admitted_at",
};

const START_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "connector_id",
    "redirect_uri",
    "requested_scopes",
    "declared_account_subject",
    "credential_custody_profile_ref",
    "permitted_audience_classes",
    "product_session_origin",
];
const START_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "ceremony_ref",
    "principal_ref",
    "connector_ref",
    "provider_profile_ref",
    "redirect",
    "state",
    "nonce",
    "proof",
    "issued_at",
    "expires_at",
    "status",
    "completion",
    "refusal",
    "receipt_refs",
    "content_hash",
    "admitted_at",
];
const COMPLETE_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "state",
    "code",
    "redirect_uri",
];
const COMPLETE_SERVER_RESOLVED: &[&str] = &[
    "completion",
    "refusal",
    "status",
    "content_hash",
    "admitted_at",
    "provider_account_subject_hash",
    "provider_tenant_subject_hash",
    "provider_granted_scopes",
    "credential_binding_ref",
    "connection_revocation_epoch",
    "last_provider_verification",
];
const TRANSITION_FIELDS: &[&str] = &["owner_ref", "idempotency_key", "expected_head", "reason"];
const TRANSITION_SERVER_RESOLVED: &[&str] = &[
    "connection_version",
    "connection_revocation_epoch",
    "last_provider_verification",
    "status",
    "successor_ref",
    "content_hash",
    "admitted_at",
];

// ======================================================================================== helpers

/// The ceremony TTL; a verifier may shorten it through the environment to reach the expiry branch
/// without waiting ten minutes. It can only be read at issue, never asserted by a request.
fn ceremony_ttl_ms() -> u64 {
    std::env::var("IOI_PROVIDER_CONNECTION_CEREMONY_TTL_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .unwrap_or(CEREMONY_TTL_MS)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or_default()
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn list(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
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

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::from(s.as_str())).collect())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

fn jcs(value: &Value) -> String {
    fn walk(value: &Value, out: &mut String) {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (index, key) in keys.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(key).unwrap_or_default());
                    out.push(':');
                    walk(&map[*key], out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    walk(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
        }
    }
    let mut out = String::new();
    walk(value, &mut out);
    out
}

/// `user://principal_01` → `user-principal_01`; the family token a connection carries in its ref.
fn principal_slug(principal_ref: &str) -> String {
    principal_ref
        .replacen("://", "-", 1)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '.'
            }
        })
        .collect()
}

fn connection_id(connector_id: &str, principal_ref: &str) -> String {
    format!("{connector_id}~{}", principal_slug(principal_ref))
}

fn connection_ref_for(connector_id: &str, principal_ref: &str) -> String {
    format!(
        "connection://provider/{connector_id}/{}",
        principal_slug(principal_ref)
    )
}

fn parse_connection_id(id: &str) -> Result<(String, String), Reply> {
    let Some((connector_id, slug)) = id.split_once('~') else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &CONNECTION.code("id_not_canonical"),
            "a connection id is {connector_id}~{principal-slug}, exactly as the daemon served it",
        ));
    };
    if connector_id.is_empty() || slug.is_empty() || slug.contains('/') {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &CONNECTION.code("id_not_canonical"),
            "a connection id is {connector_id}~{principal-slug}, exactly as the daemon served it",
        ));
    }
    Ok((
        connector_id.to_string(),
        format!("connection://provider/{connector_id}/{slug}"),
    ))
}

fn refuse_unknown_fields(body: &Value, spec: &FamilySpec, allowed: &[&str]) -> Result<(), Reply> {
    let Some(object) = body.as_object() else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &spec.code("request_body_not_object"),
            "the request body must be a JSON object",
        ));
    };
    let permitted: BTreeSet<&str> = allowed.iter().copied().collect();
    let unknown: Vec<String> = object
        .keys()
        .filter(|key| !permitted.contains(key.as_str()))
        .cloned()
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(bad(
        StatusCode::BAD_REQUEST,
        &spec.code("request_unknown_field"),
        format!(
            "this route does not admit field(s): {}; the ceremony, the binding and every provider fact are derived, never authored",
            unknown.join(", ")
        ),
    ))
}

fn connector_record(data_dir: &str, connector_id: &str) -> Result<Value, Reply> {
    read_record_dir(data_dir, "connectors")
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(connector_id))
        .ok_or_else(|| {
            bad(
                StatusCode::NOT_FOUND,
                &CEREMONY.code("connector_unknown"),
                format!("connector_id '{connector_id}' is not registered in the connector estate"),
            )
        })
}

/// The provider profile REVISION: content-addressed over the connector's registered auth profile
/// with every sealed member excluded, so a profile edited after a ceremony was issued cannot
/// complete it, and no secret ever contributes to a ref.
fn provider_profile_ref(connector: &Value) -> String {
    let connector_id = text(connector, "connector_id");
    let mut profile = connector["auth_profile"].clone();
    if let Some(map) = profile.as_object_mut() {
        map.retain(|key, _| !key.starts_with("sealed_"));
    }
    format!(
        "provider-profile://{connector_id}@sha256:{}",
        sha256_hex(jcs(&profile).as_bytes())
    )
}

struct OAuthProfile {
    authorization_endpoint: String,
    token_endpoint: String,
    client_id: String,
    client_secret: String,
    userinfo_endpoint: String,
    scopes: Vec<String>,
}

fn oauth_profile(connector: &Value) -> Result<OAuthProfile, Reply> {
    let ap = &connector["auth_profile"];
    let profile = OAuthProfile {
        authorization_endpoint: text(ap, "authorization_endpoint"),
        token_endpoint: text(ap, "token_endpoint"),
        client_id: text(ap, "client_id"),
        client_secret: ap["sealed_client_secret"]
            .as_str()
            .and_then(open_scm_token)
            .unwrap_or_default(),
        userinfo_endpoint: text(ap, "userinfo_endpoint"),
        scopes: list(ap, "scopes"),
    };
    if profile.authorization_endpoint.is_empty()
        || profile.token_endpoint.is_empty()
        || profile.client_id.is_empty()
    {
        return Err(bad(
            StatusCode::CONFLICT,
            &CEREMONY.code("profile_missing"),
            "this connector has no OAuth auth_profile (authorization_endpoint, token_endpoint, client_id); discover or register one first",
        ));
    }
    Ok(profile)
}

fn redirect_origin(uri: &str) -> Option<String> {
    let (scheme, rest) = uri.split_once("://")?;
    let host = rest.split('/').next()?;
    if scheme.is_empty() || host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

fn subject_hash(provider_profile_ref: &str, subject: &str) -> String {
    format!(
        "sha256:{}",
        sha256_hex(
            jcs(&json!({ "provider_profile_ref": provider_profile_ref, "subject": subject }))
                .as_bytes()
        )
    )
}

fn head_record(stream: &[AdmittedRecord]) -> Option<&Value> {
    stream.last().map(|entry| &entry.record)
}

fn rfc3339_ms(ms: u64) -> String {
    admitted_stamp(ms)
}

fn parse_rfc3339_ms(value: &str) -> Option<u64> {
    let ms = agentgres::parse_rfc3339_ms(value);
    (ms > 0).then_some(ms)
}

fn admission_head(reply: &Reply) -> Option<String> {
    reply
        .1
         .0
        .get("expected_head_for_successor")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn record_from_reply<'a>(reply: &'a Reply, key: &str) -> Option<&'a Value> {
    reply.1 .0.get(key)
}

// ================================================================================== the ceremony

struct CeremonyIssue {
    reply: Reply,
    authorize_url: String,
    state: String,
}

/// Issue a ceremony for `connector_id` bound to the caller. Shared by `authorization/start`,
/// `reauthorize` and the legacy connector `oauth/start` alias, so every path mints the same
/// registered record.
#[allow(clippy::too_many_arguments)]
async fn issue_ceremony(
    st: &DaemonState,
    caller: &WriteCaller,
    body: &Value,
    connector_id: &str,
    default_scopes: Option<Vec<String>>,
) -> Result<CeremonyIssue, Reply> {
    let connector = connector_record(&st.data_dir, connector_id)?;
    let profile = oauth_profile(&connector)?;
    let redirect_uri = body_str(body, "redirect_uri");
    let Some(origin) = redirect_origin(&redirect_uri) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CEREMONY.code("redirect_required"),
            "redirect_uri is the exact absolute callback the product session will be redirected to",
        ));
    };
    let mut requested = list(body, "requested_scopes");
    if requested.is_empty() {
        requested = default_scopes.unwrap_or_else(|| profile.scopes.clone());
    }
    if requested.is_empty() {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CEREMONY.code("scopes_required"),
            "requested_scopes names at least one provider scope; the connector's auth_profile declares none",
        ));
    }
    let mut audiences = list(body, "permitted_audience_classes");
    if audiences.is_empty() {
        audiences = vec!["connector".to_string()];
    }
    if let Some(bad_class) = audiences
        .iter()
        .find(|class| !AUDIENCE_CLASSES.contains(&class.as_str()))
    {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CEREMONY.code("audience_class_outside_vocabulary"),
            format!(
                "'{bad_class}' is not an audience class; one of {}",
                AUDIENCE_CLASSES.join(" | ")
            ),
        ));
    }
    let custody = {
        let raw = body_str(body, "credential_custody_profile_ref");
        if raw.is_empty() {
            DEFAULT_CUSTODY_PROFILE.to_string()
        } else {
            raw
        }
    };
    if !custody.starts_with("custody-profile://") {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CEREMONY.code("custody_profile_required"),
            "credential_custody_profile_ref is a custody-profile:// ref; a connection without custody is refused",
        ));
    }
    let session_origin = {
        let raw = body_str(body, "product_session_origin");
        if raw.is_empty() {
            DEFAULT_SESSION_ORIGIN.to_string()
        } else {
            raw
        }
    };
    let declared_subject = body
        .get("declared_account_subject")
        .and_then(Value::as_str)
        .map(str::to_string);

    // The ceremony id is DERIVED from the owner and the idempotency key, so an exact retry opens the
    // same family and replays the ceremony it already issued instead of minting a second state.
    let ceremony_id = format!(
        "cer_{}",
        &sha256_hex(format!("{}|{}", caller.owner_ref, caller.idempotency_key).as_bytes())[..32]
    );
    let resource = format!("{}{ceremony_id}", CEREMONY.ref_scheme);
    let state = random_token(32);
    let nonce = random_token(32);
    let verifier = random_token(64);
    let challenge = pkce_challenge(&verifier);
    let Some(sealed_verifier) = seal_scm_token(&verifier) else {
        return Err(bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CEREMONY.code("verifier_seal_failed"),
            "the PKCE verifier could not be sealed; no ceremony was issued",
        ));
    };
    let scope = bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        CEREMONY.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    )
    .map_err(scope_refusal_reply)?;
    let stream = read_stream(&CEREMONY, &st.data_dir, &caller.identity, &scope, &resource)?;
    if let Some(reply) = replay_for_key(
        &CEREMONY,
        st,
        caller,
        &scope,
        &resource,
        &stream,
        CEREMONY.record_key,
    )? {
        let state = record_from_reply(&reply, CEREMONY.record_key)
            .map(|record| text(record, "state"))
            .unwrap_or_default();
        let authorize_url = read_record_dir(&st.data_dir, CEREMONY_STATES)
            .into_iter()
            .find(|entry| entry["state"].as_str() == Some(state.as_str()))
            .map(|entry| text(&entry, "authorize_url"))
            .unwrap_or_default();
        let mut reply = reply;
        reply.1 .0["state"] = json!(state);
        reply.1 .0["authorize_url"] = json!(authorize_url);
        return Ok(CeremonyIssue {
            reply,
            authorize_url,
            state,
        });
    }
    // The sealed verifier and the state index are written BEFORE the admission: handing back an
    // authorize URL over a discarded write sends the operator to the provider for a flow the
    // daemon has already lost the means to finish.
    if persist_record(
        &st.data_dir,
        CEREMONY_SECRETS,
        &ceremony_id,
        &json!({ "ceremony_ref": resource, "sealed_verifier": sealed_verifier, "created_at": iso_now() }),
    )
    .is_err()
    {
        return Err(bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CEREMONY.code("secret_persistence_failed"),
            "the sealed PKCE verifier could not be durably recorded; no ceremony was issued",
        ));
    }
    let provider_profile = provider_profile_ref(&connector);
    let authorize_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256&scope={}",
        profile.authorization_endpoint,
        pct(&profile.client_id),
        pct(&redirect_uri),
        pct(&state),
        pct(&nonce),
        pct(&challenge),
        pct(&requested.join(" "))
    );
    if persist_record(
        &st.data_dir,
        CEREMONY_STATES,
        &state,
        &json!({ "state": state, "ceremony_ref": resource, "ceremony_id": ceremony_id, "authorize_url": authorize_url, "created_at": iso_now() }),
    )
    .is_err()
    {
        return Err(bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CEREMONY.code("state_persistence_failed"),
            "the ceremony state index could not be durably recorded; no ceremony was issued",
        ));
    }
    let recorded_at_ms = now_ms();
    let record = json!({
        "schema_version": CEREMONY.schema_version,
        "ceremony_ref": resource,
        "owner_ref": caller.owner_ref,
        "principal_ref": caller.identity.principal_ref,
        "connector_ref": format!("connector://{connector_id}"),
        "provider_profile_ref": provider_profile,
        "redirect": { "origin": origin, "uri": redirect_uri },
        "state": state,
        "nonce": nonce,
        "proof": { "kind": "pkce_s256", "code_challenge": challenge, "code_challenge_method": "S256" },
        "requested_scopes": strings(&requested),
        "declared_account_subject": declared_subject,
        "credential_custody_profile_ref": custody,
        "permitted_audience_classes": strings(&audiences),
        "product_session_origin": session_origin,
        "issued_at": rfc3339_ms(recorded_at_ms),
        "expires_at": rfc3339_ms(recorded_at_ms + ceremony_ttl_ms()),
        "status": "issued",
        "completion": empty_completion(),
        "refusal": { "code": Value::Null, "refused_at": Value::Null },
        "receipt_refs": [format!("receipt://wallet/provider-connection/{ceremony_id}/issued")],
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    let reply = finish_admission(
        &CEREMONY,
        st,
        caller,
        &scope,
        &resource,
        CEREMONY.record_key,
        record,
        None,
        recorded_at_ms,
        body,
        json!({ "authorize_url": authorize_url, "state": state }),
    );
    if reply.0 != StatusCode::CREATED && reply.0 != StatusCode::OK {
        let _ = remove_record(&st.data_dir, CEREMONY_STATES, &state);
        let _ = remove_record(&st.data_dir, CEREMONY_SECRETS, &ceremony_id);
        return Err(reply);
    }
    Ok(CeremonyIssue {
        reply,
        authorize_url,
        state,
    })
}

fn empty_completion() -> Value {
    json!({
        "completed_at": Value::Null,
        "connection_ref": Value::Null,
        "provider_account_subject_hash": Value::Null,
        "provider_tenant_subject_hash": Value::Null,
        "provider_granted_scopes": [],
        "evidence_ref": Value::Null,
    })
}

/// POST /v1/hypervisor/auth/connections/authorization/start
pub(crate) async fn handle_connection_start(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) = reject_authored(&body, &CEREMONY, START_SERVER_RESOLVED) {
        return response;
    }
    if let Err(response) = refuse_unknown_fields(&body, &CEREMONY, START_FIELDS) {
        return response;
    }
    let connector_id = body_str(&body, "connector_id");
    if connector_id.is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CEREMONY.code("connector_required"),
            "connector_id names the registered connector whose provider profile the ceremony binds",
        );
    }
    match issue_ceremony(&st, &caller, &body, &connector_id, None).await {
        Ok(issued) => issued.reply,
        Err(response) => response,
    }
}

struct CeremonyWrite {
    caller: WriteCaller,
    scope: RequestResourceScope,
    resource: String,
    stream: Vec<AdmittedRecord>,
    head: String,
}

/// Resolve the issued ceremony a completion names by its state, under the completing caller.
fn open_ceremony_by_state(
    st: &DaemonState,
    headers: &HeaderMap,
    body: &Value,
    state: &str,
) -> Result<CeremonyWrite, Reply> {
    let caller = require_write_caller(&st.data_dir, headers, body)?;
    let Some(index) = read_record_dir(&st.data_dir, CEREMONY_STATES)
        .into_iter()
        .find(|entry| entry["state"].as_str() == Some(state))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &CEREMONY.code("unknown"),
            "no issued ceremony answers to that state; a consumed, expired or never-issued state completes nothing",
        ));
    };
    let resource = text(&index, "ceremony_ref");
    let scope = authorize_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        CEREMONY.resource_kind,
        &resource,
        Some(caller.owner_ref.as_str()),
    )
    .map_err(scope_refusal_reply)?;
    let stream = read_stream(&CEREMONY, &st.data_dir, &caller.identity, &scope, &resource)?;
    let Some(head) = stream.last() else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &CEREMONY.code("unknown"),
            "the state index names a ceremony the chain never admitted",
        ));
    };
    if text(&head.record, "principal_ref") != caller.identity.principal_ref {
        return Err(bad(
            StatusCode::FORBIDDEN,
            &CEREMONY.code("principal_mismatch"),
            "a ceremony completes only under the principal that initiated it; a completion not linked to the initiating principal is refused",
        ));
    }
    let head_hash = head.head.clone();
    Ok(CeremonyWrite {
        caller,
        scope,
        resource,
        stream,
        head: head_hash,
    })
}

/// Admit the ceremony's own successor: `completed` with its completion, or `refused` / `expired`
/// with the typed code — so the chain, not a log line, says what happened to the state token.
#[allow(clippy::too_many_arguments)]
fn close_ceremony(
    st: &DaemonState,
    write: &CeremonyWrite,
    body: &Value,
    status: &str,
    completion: Value,
    refusal_code: Option<&str>,
    recorded_at_ms: u64,
) -> Reply {
    let Some(current) = head_record(&write.stream).cloned() else {
        return bad(
            StatusCode::NOT_FOUND,
            &CEREMONY.code("unknown"),
            "no ceremony to close",
        );
    };
    let mut record = current;
    let ceremony_id = write
        .resource
        .trim_start_matches(CEREMONY.ref_scheme)
        .to_string();
    record["status"] = json!(status);
    record["completion"] = completion;
    record["refusal"] = match refusal_code {
        Some(code) => json!({ "code": code, "refused_at": rfc3339_ms(recorded_at_ms) }),
        None => json!({ "code": Value::Null, "refused_at": Value::Null }),
    };
    let mut receipts = list(&record, "receipt_refs");
    receipts.push(format!(
        "receipt://wallet/provider-connection/{ceremony_id}/{status}"
    ));
    record["receipt_refs"] = strings(&receipts);
    record["admitted_at"] = json!(admitted_stamp(recorded_at_ms));
    if let Some(map) = record.as_object_mut() {
        map.remove("content_hash");
    }
    let mut body = body.clone();
    body["expected_head"] = json!(write.head);
    let reply = finish_admission(
        &CEREMONY,
        st,
        &write.caller,
        &write.scope,
        &write.resource,
        CEREMONY.record_key,
        record,
        Some(write.head.clone()),
        recorded_at_ms,
        &body,
        json!({}),
    );
    // Consuming the state index is what makes the state single-use for the ISSUED ceremony; the
    // chain already refuses a second successor by its head, so a stale index is reported, never
    // load-bearing.
    let state = head_record(&write.stream)
        .map(|record| text(record, "state"))
        .unwrap_or_default();
    let _ = remove_record(&st.data_dir, CEREMONY_STATES, &state);
    let _ = remove_record(&st.data_dir, CEREMONY_SECRETS, &ceremony_id);
    reply
}

fn refused(
    st: &DaemonState,
    write: &CeremonyWrite,
    body: &Value,
    status: StatusCode,
    code: &str,
    message: &str,
) -> Reply {
    let closed = close_ceremony(
        st,
        write,
        body,
        "refused",
        empty_completion(),
        Some(code),
        now_ms(),
    );
    let mut reply = bad(status, &CEREMONY.code(code), message);
    reply.1 .0["ceremony_closed"] = json!(closed.0.as_u16() < 300);
    reply.1 .0["ceremony"] = closed
        .1
         .0
        .get(CEREMONY.record_key)
        .cloned()
        .unwrap_or(Value::Null);
    reply
}

struct ProviderOutcome {
    access: String,
    refresh: Option<String>,
    granted: Vec<String>,
    subject: String,
    subject_source: String,
    tenant: Option<String>,
    token_response: Value,
}

fn decode_jwt_payload(token: &str) -> Option<Value> {
    use base64::Engine as _;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Exchange the code and resolve the provider's account subject. Subject sources, in order: the
/// profile's userinfo endpoint; the token response's `id_token` claims (decoded, not signature
/// verified, and recorded as such); a top-level `sub` on the token response; the owner's declared
/// account subject on the ceremony. None of them is a caller claim at completion time.
async fn provider_outcome(
    profile: &OAuthProfile,
    ceremony: &Value,
    code: &str,
    verifier: &str,
) -> Result<ProviderOutcome, (String, String)> {
    let redirect_uri = ceremony
        .pointer("/redirect/uri")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (access, refresh, token_response) = exchange_oauth_code(
        &profile.token_endpoint,
        &profile.client_id,
        &profile.client_secret,
        code,
        redirect_uri,
        verifier,
    )
    .await
    .map_err(|error| ("exchange_failed".to_string(), error))?;
    let requested = list(ceremony, "requested_scopes");
    let granted: Vec<String> = match token_response.get("scope").and_then(Value::as_str) {
        Some(scope) if !scope.trim().is_empty() => scope
            .split_whitespace()
            .map(str::to_string)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        _ => requested.clone(),
    };
    let widened: Vec<&String> = granted
        .iter()
        .filter(|scope| !requested.contains(scope))
        .collect();
    if !widened.is_empty() {
        return Err((
            "scope_widened".to_string(),
            format!(
                "the provider granted scopes the ceremony never requested ({}); a connection binds the requested set or less, never more",
                widened.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    let mut subject = None;
    let mut source = String::new();
    let mut tenant = None;
    if !profile.userinfo_endpoint.is_empty() {
        if let Ok(info) = oidc_userinfo(&profile.userinfo_endpoint, &access).await {
            if let Some(sub) = info.get("sub").and_then(Value::as_str) {
                subject = Some(sub.to_string());
                source = "userinfo".to_string();
                tenant = info
                    .get("tid")
                    .or_else(|| info.get("hd"))
                    .or_else(|| info.get("tenant"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
        }
    }
    if subject.is_none() {
        if let Some(claims) = token_response
            .get("id_token")
            .and_then(Value::as_str)
            .and_then(decode_jwt_payload)
        {
            if let Some(sub) = claims.get("sub").and_then(Value::as_str) {
                subject = Some(sub.to_string());
                source = "id_token_unverified".to_string();
                tenant = claims
                    .get("tid")
                    .or_else(|| claims.get("hd"))
                    .or_else(|| claims.get("tenant"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
        }
    }
    if subject.is_none() {
        if let Some(sub) = token_response.get("sub").and_then(Value::as_str) {
            subject = Some(sub.to_string());
            source = "token_response".to_string();
        }
    }
    let declared = ceremony
        .get("declared_account_subject")
        .and_then(Value::as_str)
        .map(str::to_string);
    let subject = match (subject, declared) {
        (Some(observed), Some(declared)) if observed != declared => {
            return Err((
                "account_substituted".to_string(),
                "the provider returned a different account subject than the ceremony declared; a connection never binds a substituted account".to_string(),
            ));
        }
        (Some(observed), _) => observed,
        (None, Some(declared)) => {
            source = "owner_declared".to_string();
            declared
        }
        (None, None) => {
            return Err((
                "subject_unresolvable".to_string(),
                "the provider returned no account subject (no userinfo endpoint, no id_token, no sub) and the ceremony declared none; a connection without an account subject cannot refuse substitution and is refused".to_string(),
            ));
        }
    };
    let mut scrubbed = token_response.clone();
    if let Some(map) = scrubbed.as_object_mut() {
        for secret in ["access_token", "refresh_token", "id_token"] {
            if map.contains_key(secret) {
                map.insert(secret.to_string(), json!("<redacted>"));
            }
        }
    }
    Ok(ProviderOutcome {
        access,
        refresh,
        granted,
        subject,
        subject_source: source,
        tenant,
        token_response: scrubbed,
    })
}

/// POST /v1/hypervisor/auth/connections/authorization/complete
pub(crate) async fn handle_connection_complete(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    if let Err(response) = reject_authored(&body, &CONNECTION, COMPLETE_SERVER_RESOLVED) {
        return response;
    }
    if let Err(response) = refuse_unknown_fields(&body, &CEREMONY, COMPLETE_FIELDS) {
        return response;
    }
    let state = body_str(&body, "state");
    let code = body_str(&body, "code");
    if state.is_empty() || code.is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CEREMONY.code("state_and_code_required"),
            "a completion carries the ceremony's state and the provider's authorization code",
        );
    }
    let write = match open_ceremony_by_state(&st, &headers, &body, &state) {
        Ok(write) => write,
        Err(response) => return response,
    };
    complete_ceremony(&st, write, &body, &code).await
}

async fn complete_ceremony(
    st: &DaemonState,
    write: CeremonyWrite,
    body: &Value,
    code: &str,
) -> Reply {
    let Some(ceremony) = head_record(&write.stream).cloned() else {
        return bad(
            StatusCode::NOT_FOUND,
            &CEREMONY.code("unknown"),
            "no ceremony",
        );
    };
    let ceremony_id = write
        .resource
        .trim_start_matches(CEREMONY.ref_scheme)
        .to_string();
    if text(&ceremony, "status") != "issued" {
        return bad(
            StatusCode::CONFLICT,
            &CEREMONY.code("consumed"),
            format!(
                "this ceremony is {}; a ceremony is single-use and completes at most once",
                text(&ceremony, "status")
            ),
        );
    }
    let now = now_ms();
    if parse_rfc3339_ms(&text(&ceremony, "expires_at")).is_some_and(|deadline| now > deadline) {
        let closed = close_ceremony(st, &write, body, "expired", empty_completion(), None, now);
        let mut reply = bad(
            StatusCode::GONE,
            &CEREMONY.code("expired"),
            "the ceremony expired before completion; start a new one",
        );
        reply.1 .0["ceremony"] = closed
            .1
             .0
            .get(CEREMONY.record_key)
            .cloned()
            .unwrap_or(Value::Null);
        return reply;
    }
    let asserted_redirect = body_str(body, "redirect_uri");
    if !asserted_redirect.is_empty()
        && ceremony.pointer("/redirect/uri").and_then(Value::as_str)
            != Some(asserted_redirect.as_str())
    {
        return refused(
            st,
            &write,
            body,
            StatusCode::CONFLICT,
            "redirect_drift",
            "the completion names a different redirect than the ceremony was issued for",
        );
    }
    let connector_id = text(&ceremony, "connector_ref")
        .trim_start_matches("connector://")
        .to_string();
    let connector = match connector_record(&st.data_dir, &connector_id) {
        Ok(connector) => connector,
        Err(response) => return response,
    };
    if provider_profile_ref(&connector) != text(&ceremony, "provider_profile_ref") {
        return refused(
            st,
            &write,
            body,
            StatusCode::CONFLICT,
            "profile_drift",
            "the connector's provider profile changed since the ceremony was issued; the ceremony bound the exact revision and cannot complete against another",
        );
    }
    let profile = match oauth_profile(&connector) {
        Ok(profile) => profile,
        Err(response) => return response,
    };
    let Some(verifier) = read_record_dir(&st.data_dir, CEREMONY_SECRETS)
        .into_iter()
        .find(|entry| entry["ceremony_ref"].as_str() == Some(write.resource.as_str()))
        .and_then(|entry| entry["sealed_verifier"].as_str().and_then(open_scm_token))
    else {
        return refused(
            st,
            &write,
            body,
            StatusCode::CONFLICT,
            "verifier_unavailable",
            "the sealed PKCE verifier for this ceremony is not available; the ceremony cannot complete and is closed",
        );
    };
    let outcome = match provider_outcome(&profile, &ceremony, code, &verifier).await {
        Ok(outcome) => outcome,
        Err((code, message)) => {
            let status = match code.as_str() {
                "exchange_failed" => StatusCode::BAD_GATEWAY,
                "scope_widened" | "account_substituted" => StatusCode::CONFLICT,
                _ => StatusCode::UNPROCESSABLE_ENTITY,
            };
            return refused(st, &write, body, status, &code, &message);
        }
    };
    let principal_ref = text(&ceremony, "principal_ref");
    let provider_profile = text(&ceremony, "provider_profile_ref");
    let account_hash = subject_hash(&provider_profile, &outcome.subject);
    let tenant_hash = outcome
        .tenant
        .as_deref()
        .map(|tenant| subject_hash(&provider_profile, &format!("tenant:{tenant}")));

    // The connection family for this connector and principal: version 1, or a successor on
    // reauthorization (head active) and reconnect (head disconnected / revoked / lapsed).
    let connection_ref = connection_ref_for(&connector_id, &principal_ref);
    let connection_scope = bind_request_resource_scope(
        &st.data_dir,
        &write.caller.identity,
        CONNECTION.resource_kind,
        &connection_ref,
        &write.caller.owner_ref,
        &write.caller.owner_ref,
        &write.caller.idempotency_key,
    );
    let connection_scope = match connection_scope {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let existing = match read_stream(
        &CONNECTION,
        &st.data_dir,
        &write.caller.identity,
        &connection_scope,
        &connection_ref,
    ) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let (version, predecessor, epoch, credential_version, expected_head) = match existing.last() {
        None => (1u64, Value::Null, 0u64, 1u64, None),
        Some(prior) => {
            let record = &prior.record;
            if text(record, "provider_account_subject_hash") != account_hash {
                return refused(
                    st,
                    &write,
                    body,
                    StatusCode::CONFLICT,
                    "account_substituted",
                    "a reconnect or reauthorization binds the SAME provider account as the connection it succeeds; a different account is a different connection, never a silent retarget",
                );
            }
            if record
                .get("provider_tenant_subject_hash")
                .and_then(Value::as_str)
                .map(str::to_string)
                != tenant_hash
            {
                return refused(
                    st,
                    &write,
                    body,
                    StatusCode::CONFLICT,
                    "tenant_substituted",
                    "a reconnect or reauthorization binds the SAME provider tenant as the connection it succeeds",
                );
            }
            let version = record["connection_version"].as_u64().unwrap_or(0) + 1;
            let credential_version = text(record, "credential_binding_ref")
                .rsplit('@')
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0)
                + 1;
            (
                version,
                json!(format!("{connection_ref}@{}", version - 1)),
                record["connection_revocation_epoch"].as_u64().unwrap_or(0),
                credential_version,
                Some(prior.head.clone()),
            )
        }
    };
    let credential_binding_ref = format!(
        "credential://{connector_id}/{}@{credential_version}",
        principal_slug(&principal_ref)
    );
    let evidence_ref = format!("evidence://provider-connection/{ceremony_id}/token-response");
    let observed_at = rfc3339_ms(now);
    if persist_record(
        &st.data_dir,
        CONNECTION_EVIDENCE,
        &ceremony_id,
        &json!({
            "evidence_ref": evidence_ref,
            "ceremony_ref": write.resource,
            "connection_ref": connection_ref,
            "observed_at": observed_at,
            "kind": "token_response",
            "subject_source": outcome.subject_source,
            "provider_account_subject_hash": account_hash,
            "provider_tenant_subject_hash": tenant_hash,
            "provider_granted_scopes": outcome.granted,
            "token_response": outcome.token_response,
        }),
    )
    .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CONNECTION.code("evidence_persistence_failed"),
            "the provider evidence could not be durably recorded; nothing was connected",
        );
    }
    // Seal the credential under the SAME store the gateway resolves from, carrying the connection
    // coordinates the fence checks. The bytes are never returned, logged or receipted.
    let Some(mut credential) = seal_oauth_result(
        &connector_id,
        &profile.token_endpoint,
        &profile.client_id,
        &profile.client_secret,
        &outcome.access,
        outcome.refresh.as_deref(),
    ) else {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CONNECTION.code("credential_seal_failed"),
            "the exchanged credential could not be sealed; nothing was connected",
        );
    };
    credential["connection_ref"] = json!(connection_ref);
    credential["connection_version"] = json!(version);
    credential["connection_revocation_epoch"] = json!(epoch);
    credential["credential_binding_ref"] = json!(credential_binding_ref);
    credential["principal_ref"] = json!(principal_ref);
    credential["owner_ref"] = json!(write.caller.owner_ref);
    if persist_record(
        &st.data_dir,
        "connector-credentials",
        &connector_id,
        &credential,
    )
    .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CONNECTION.code("credential_persistence_failed"),
            "the sealed credential could not be durably recorded; nothing was connected",
        );
    }
    let binding = json!({
        "schema_version": CONNECTION.schema_version,
        "connection_ref": connection_ref,
        "connection_version": version,
        "predecessor_ref": predecessor,
        "owner_ref": write.caller.owner_ref,
        "principal_ref": principal_ref,
        "connector_ref": format!("connector://{connector_id}"),
        "provider_profile_ref": provider_profile,
        "provider_account_subject_hash": account_hash,
        "provider_tenant_subject_hash": tenant_hash,
        "provider_granted_scopes": strings(&outcome.granted),
        "credential_binding_ref": credential_binding_ref,
        "credential_custody_profile_ref": text(&ceremony, "credential_custody_profile_ref"),
        "permitted_audience_classes": ceremony["permitted_audience_classes"].clone(),
        "connection_revocation_epoch": epoch,
        "reauthorization_required_at": rfc3339_ms(now + REAUTHORIZATION_INTERVAL_MS),
        "last_provider_verification": { "observed_at": observed_at, "evidence_ref": evidence_ref, "status": "current" },
        "status": "active",
        "successor_ref": Value::Null,
        "ceremony_ref": write.resource,
        "receipt_refs": [format!("receipt://wallet/provider-connection/{connector_id}/{}/{version}/admitted", principal_slug(&principal_ref))],
        "admitted_at": admitted_stamp(now),
    });
    let mut binding_body = body.clone();
    binding_body["expected_head"] = expected_head.clone().map_or(Value::Null, Value::String);
    let admitted = finish_admission(
        &CONNECTION,
        st,
        &write.caller,
        &connection_scope,
        &connection_ref,
        CONNECTION.record_key,
        binding,
        expected_head,
        now,
        &binding_body,
        json!({}),
    );
    if admitted.0 != StatusCode::CREATED && admitted.0 != StatusCode::OK {
        return admitted;
    }
    let _ = persist_record(
        &st.data_dir,
        CONNECTION_INDEX,
        &connection_id(&connector_id, &principal_ref),
        &json!({ "connection_ref": connection_ref, "connector_id": connector_id, "principal_ref": principal_ref, "owner_ref": write.caller.owner_ref, "updated_at": iso_now() }),
    );
    if let Some(mut c) = read_record_dir(&st.data_dir, "connectors")
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(connector_id.as_str()))
    {
        c["auth_posture"] = json!("token-lease:bound");
        let _ = persist_record(&st.data_dir, "connectors", &connector_id, &c);
    }
    let completion = json!({
        "completed_at": observed_at,
        "connection_ref": format!("{connection_ref}@{version}"),
        "provider_account_subject_hash": account_hash,
        "provider_tenant_subject_hash": tenant_hash,
        "provider_granted_scopes": strings(&outcome.granted),
        "evidence_ref": evidence_ref,
    });
    let closed = close_ceremony(st, &write, body, "completed", completion, None, now);
    if closed.0 != StatusCode::CREATED && closed.0 != StatusCode::OK {
        return closed;
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "connected": true,
            "connector_id": connector_id,
            "connection_id": connection_id(&connector_id, &principal_ref),
            "credential_kind": credential["kind"],
            "connection": admitted.1 .0.get(CONNECTION.record_key).cloned().unwrap_or(Value::Null),
            "connection_head": admission_head(&admitted),
            "ceremony": closed.1 .0.get(CEREMONY.record_key).cloned().unwrap_or(Value::Null),
            "subject_source": outcome.subject_source,
        })),
    )
}

// =================================================================================== the binding

fn open_connection(
    st: &DaemonState,
    headers: &HeaderMap,
    id: &str,
) -> Result<(RequestIdentity, String, String, Vec<AdmittedRecord>), Reply> {
    let (connector_id, resource) = parse_connection_id(id)?;
    let identity = resolve_request_identity(&st.data_dir, headers).map_err(scope_refusal_reply)?;
    let stream = authorized_stream(&CONNECTION, &st.data_dir, &identity, &resource)?;
    if stream.is_empty() {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &CONNECTION.code("absent"),
            "no connection answers to that id",
        ));
    }
    Ok((identity, connector_id, resource, stream))
}

fn connection_view(stream: &[AdmittedRecord]) -> Value {
    json!({
        "current": stream.last().map(|entry| entry.record.clone()),
        "versions": stream.iter().map(|entry| entry.record.clone()).collect::<Vec<_>>(),
        "head": stream.last().map(|entry| entry.head.clone()),
    })
}

/// GET /v1/hypervisor/auth/connections
pub(crate) async fn handle_connection_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let refs =
        match authorized_request_resource_refs(&st.data_dir, &identity, CONNECTION.resource_kind) {
            Ok(refs) => refs,
            Err(error) => return scope_refusal_reply(error),
        };
    let mut connections = Vec::new();
    for resource in refs {
        match authorized_stream(&CONNECTION, &st.data_dir, &identity, &resource) {
            Ok(stream) if !stream.is_empty() => {
                let record = &stream[stream.len() - 1].record;
                let connector_id = text(record, "connector_ref")
                    .trim_start_matches("connector://")
                    .to_string();
                connections.push(json!({
                    "connection_id": connection_id(&connector_id, &text(record, "principal_ref")),
                    "connection_ref": resource,
                    "connection_version": record["connection_version"],
                    "status": record["status"],
                    "connection_revocation_epoch": record["connection_revocation_epoch"],
                    "reauthorization_required_at": record["reauthorization_required_at"],
                    "connector_ref": record["connector_ref"],
                }));
            }
            Ok(_) => {}
            Err(response) => return response,
        }
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "connections": connections })),
    )
}

/// GET /v1/hypervisor/auth/connections/:id
pub(crate) async fn handle_connection_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Reply {
    match open_connection(&st, &headers, &id) {
        Ok((_, _, _, stream)) => {
            let mut view = connection_view(&stream);
            view["ok"] = json!(true);
            (StatusCode::OK, Json(view))
        }
        Err(response) => response,
    }
}

/// The records that DEPEND on a connection: grants and sealed sessions over its connector, and the
/// durable obligations disconnect or revocation admitted over them. Derived on every read.
fn dependents(data_dir: &str, connector_id: &str, connection_ref: &str) -> Value {
    let grants: Vec<Value> = read_record_dir(data_dir, "principal-lease-grants")
        .into_iter()
        .filter(|grant| grant["connector_id"].as_str() == Some(connector_id))
        .map(|grant| json!({ "grant_id": grant["grant_id"], "principal_id": grant["principal_id"], "tools": grant["tools"], "expires_at_ms": grant["expires_at_ms"] }))
        .collect();
    let sessions: Vec<Value> = read_record_dir(data_dir, "odk-connector-sessions")
        .into_iter()
        .filter(|session| session["connector_id"].as_str() == Some(connector_id))
        .map(|session| json!({ "session_id": session["session_id"], "status": session["status"], "lease_id": session["lease_id"] }))
        .collect();
    let obligations: Vec<Value> = read_record_dir(data_dir, CONNECTION_OBLIGATIONS)
        .into_iter()
        .filter(|obligation| obligation["connection_ref"].as_str() == Some(connection_ref))
        .collect();
    json!({
        "lease_grants": grants,
        "connector_sessions": sessions,
        "obligations": obligations,
    })
}

/// GET /v1/hypervisor/auth/connections/:id/dependents
pub(crate) async fn handle_connection_dependents(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Reply {
    match open_connection(&st, &headers, &id) {
        Ok((_, connector_id, resource, stream)) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "connection_ref": resource,
                "connection_version": stream.last().map(|entry| entry.record["connection_version"].clone()),
                "dependents": dependents(&st.data_dir, &connector_id, &resource),
            })),
        ),
        Err(response) => response,
    }
}

struct ConnectionWrite {
    caller: WriteCaller,
    scope: RequestResourceScope,
    resource: String,
    connector_id: String,
    stream: Vec<AdmittedRecord>,
    expected_head: Option<String>,
}

fn open_connection_write(
    st: &DaemonState,
    caller: WriteCaller,
    body: &Value,
    id: &str,
    allowed: &[&str],
) -> Result<ConnectionWrite, Reply> {
    let (connector_id, resource) = parse_connection_id(id)?;
    reject_authored(body, &CONNECTION, TRANSITION_SERVER_RESOLVED)?;
    refuse_unknown_fields(body, &CONNECTION, allowed)?;
    let scope = authorize_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        CONNECTION.resource_kind,
        &resource,
        Some(caller.owner_ref.as_str()),
    )
    .map_err(scope_refusal_reply)?;
    let stream = read_stream(
        &CONNECTION,
        &st.data_dir,
        &caller.identity,
        &scope,
        &resource,
    )?;
    if stream.is_empty() {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &CONNECTION.code("absent"),
            "no connection answers to that id",
        ));
    }
    if head_record(&stream).map(|record| text(record, "principal_ref"))
        != Some(caller.identity.principal_ref.clone())
    {
        return Err(bad(
            StatusCode::FORBIDDEN,
            &CONNECTION.code("principal_mismatch"),
            "a connection is moved only by the principal it binds",
        ));
    }
    if let Some(reply) = replay_for_key(
        &CONNECTION,
        st,
        &caller,
        &scope,
        &resource,
        &stream,
        CONNECTION.record_key,
    )? {
        return Err(reply);
    }
    let expected_head = head_assertion(body, CONNECTION.code_prefix)?;
    require_exact_head(&stream, &expected_head, CONNECTION.code_prefix)?;
    Ok(ConnectionWrite {
        caller,
        scope,
        resource,
        connector_id,
        stream,
        expected_head,
    })
}

/// Admit the next version of a connection as a copy of the head with the given members moved.
fn admit_successor(
    st: &DaemonState,
    write: &ConnectionWrite,
    body: &Value,
    mutate: impl FnOnce(&mut Value, u64),
    recorded_at_ms: u64,
) -> Reply {
    let Some(current) = head_record(&write.stream).cloned() else {
        return bad(
            StatusCode::NOT_FOUND,
            &CONNECTION.code("absent"),
            "no connection",
        );
    };
    let version = current["connection_version"].as_u64().unwrap_or(0) + 1;
    let mut next = current.clone();
    next["connection_version"] = json!(version);
    next["predecessor_ref"] = json!(format!("{}@{}", write.resource, version - 1));
    next["successor_ref"] = Value::Null;
    next["receipt_refs"] = json!([]);
    if let Some(map) = next.as_object_mut() {
        map.remove("content_hash");
    }
    mutate(&mut next, version);
    next["admitted_at"] = json!(admitted_stamp(recorded_at_ms));
    finish_admission(
        &CONNECTION,
        st,
        &write.caller,
        &write.scope,
        &write.resource,
        CONNECTION.record_key,
        next,
        write.expected_head.clone(),
        recorded_at_ms,
        body,
        json!({}),
    )
}

fn receipt(connector_id: &str, principal_ref: &str, version: u64, event: &str) -> Value {
    json!([format!(
        "receipt://wallet/provider-connection/{connector_id}/{}/{version}/{event}",
        principal_slug(principal_ref)
    )])
}

/// POST /v1/hypervisor/auth/connections/:id/verify — a LIVE re-mint through the sealed credential
/// against the provider, recorded as the version's provider verification. Observed revocation
/// advances the epoch and fences the next use; a provider the daemon cannot reach is `degraded`,
/// never `current`.
pub(crate) async fn handle_connection_verify(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    // Identity FIRST, in the handler: the caller is resolved before any record is read or moved.
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let write = match open_connection_write(&st, caller, &body, &id, TRANSITION_FIELDS) {
        Ok(write) => write,
        Err(response) => return response,
    };
    let current = head_record(&write.stream).cloned().unwrap_or(Value::Null);
    let status = text(&current, "status");
    if status == "disconnected" || status == "superseded" {
        return bad(
            StatusCode::CONFLICT,
            &CONNECTION.code("not_live"),
            format!("a {status} connection is not verified; reconnect creates a successor"),
        );
    }
    let credential = read_record_dir(&st.data_dir, "connector-credentials")
        .into_iter()
        .find(|c| {
            c["connector_id"].as_str() == Some(write.connector_id.as_str())
                && c["connection_ref"].as_str() == Some(write.resource.as_str())
        });
    let now = now_ms();
    let (verification_status, detail) = match credential {
        None => ("provider_revoked".to_string(), "no sealed credential is bound to this connection version; the credential was rotated or removed".to_string()),
        Some(credential) => match credential["kind"].as_str() {
            Some("oauth-refresh") => {
                let refresh = credential["sealed_refresh_token"].as_str().and_then(open_scm_token);
                let client_secret = credential["sealed_client_secret"].as_str().and_then(open_scm_token).unwrap_or_default();
                match refresh {
                    None => ("provider_revoked".to_string(), "the sealed refresh token could not be opened".to_string()),
                    Some(refresh) => match mint_oauth_access_token(&text(&credential, "token_url"), &text(&credential, "client_id"), &client_secret, &refresh).await {
                        Ok(_) => ("current".to_string(), "the provider minted an access token from the sealed refresh token".to_string()),
                        Err(error) if error.contains("invalid_grant") || error.contains("401") || error.contains("400") => ("provider_revoked".to_string(), error),
                        Err(error) => ("degraded".to_string(), error),
                    },
                }
            }
            Some("bearer") => {
                let connector = connector_record(&st.data_dir, &write.connector_id).ok();
                let userinfo = connector.as_ref().map(|c| text(&c["auth_profile"], "userinfo_endpoint")).unwrap_or_default();
                let access = credential["sealed_token"].as_str().and_then(open_scm_token);
                match (userinfo.is_empty(), access) {
                    (true, _) => ("unknown".to_string(), "a bearer credential without a userinfo endpoint cannot be verified against the provider".to_string()),
                    (false, None) => ("provider_revoked".to_string(), "the sealed bearer token could not be opened".to_string()),
                    (false, Some(access)) => match oidc_userinfo(&userinfo, &access).await {
                        Ok(_) => ("current".to_string(), "the provider answered userinfo for the sealed bearer".to_string()),
                        Err(error) if error.contains("401") || error.contains("403") => ("provider_revoked".to_string(), error),
                        Err(error) => ("degraded".to_string(), error),
                    },
                }
            }
            other => ("unknown".to_string(), format!("credential kind {other:?} has no provider verification on this basis")),
        },
    };
    let evidence_id = format!("verify_{}", random_token(16).to_lowercase());
    let evidence_ref = format!("evidence://provider-connection/{evidence_id}/verification");
    let observed_at = rfc3339_ms(now);
    if persist_record(
        &st.data_dir,
        CONNECTION_EVIDENCE,
        &evidence_id,
        &json!({ "evidence_ref": evidence_ref, "connection_ref": write.resource, "observed_at": observed_at, "kind": "provider_verification", "status": verification_status, "detail": detail }),
    )
    .is_err()
    {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CONNECTION.code("evidence_persistence_failed"),
            "the verification evidence could not be durably recorded",
        );
    }
    let revoked = verification_status == "provider_revoked";
    let connector_id = write.connector_id.clone();
    let principal_ref = text(&current, "principal_ref");
    let reply = admit_successor(
        &st,
        &write,
        &body,
        |next, version| {
            next["last_provider_verification"] = json!({ "observed_at": observed_at, "evidence_ref": evidence_ref, "status": verification_status });
            if revoked {
                next["status"] = json!("provider_revoked");
                next["connection_revocation_epoch"] =
                    json!(next["connection_revocation_epoch"].as_u64().unwrap_or(0) + 1);
            } else if verification_status == "degraded" {
                next["status"] = json!("degraded");
            } else if verification_status == "current" && text(next, "status") == "degraded" {
                next["status"] = json!("active");
            }
            next["receipt_refs"] = receipt(&connector_id, &principal_ref, version, "verified");
        },
        now,
    );
    if revoked && reply.0.is_success() {
        record_obligations(
            &st.data_dir,
            &write.connector_id,
            &write.resource,
            "provider_revoked",
            now,
        );
    }
    reply
}

/// The durable obligations a fence leaves behind: every dependent grant and session over the
/// connector receives a quarantine/revocation obligation with a receipt. Cleanup is not awaited —
/// the gateway fence already refuses the next use.
fn record_obligations(
    data_dir: &str,
    connector_id: &str,
    connection_ref: &str,
    cause: &str,
    now: u64,
) -> Vec<Value> {
    let deps = dependents(data_dir, connector_id, connection_ref);
    let mut recorded = Vec::new();
    let mut subjects: Vec<(String, String)> = Vec::new();
    for grant in deps["lease_grants"].as_array().into_iter().flatten() {
        subjects.push(("principal_lease_grant".to_string(), text(grant, "grant_id")));
    }
    for session in deps["connector_sessions"].as_array().into_iter().flatten() {
        subjects.push(("connector_session".to_string(), text(session, "session_id")));
    }
    for (kind, subject) in subjects {
        let id = format!(
            "obl_{}",
            sha256_hex(format!("{connection_ref}|{kind}|{subject}|{cause}").as_bytes())[..24]
                .to_string()
        );
        let obligation = json!({
            "schema_version": "ioi.hypervisor.connection-dependent-obligation.v1",
            "obligation_id": id,
            "connection_ref": connection_ref,
            "cause": cause,
            "subject_kind": kind,
            "subject_ref": subject,
            "obligation": if kind == "connector_session" { "revoke" } else { "quarantine" },
            "state": "open",
            "admitted_at": rfc3339_ms(now),
            "receipt_ref": format!("receipt://wallet/provider-connection/obligation/{id}"),
        });
        if persist_record(data_dir, CONNECTION_OBLIGATIONS, &id, &obligation).is_ok() {
            recorded.push(obligation);
        }
    }
    recorded
}

/// POST /v1/hypervisor/auth/connections/:id/disconnect — the epoch advances, the sealed credential
/// is retired, every dependent receives a durable obligation, and the next brokered use is fenced
/// at admission without waiting for cleanup.
pub(crate) async fn handle_connection_disconnect(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    // Identity FIRST, in the handler: the caller is resolved before any record is read or moved.
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let write = match open_connection_write(&st, caller, &body, &id, TRANSITION_FIELDS) {
        Ok(write) => write,
        Err(response) => return response,
    };
    let current = head_record(&write.stream).cloned().unwrap_or(Value::Null);
    if text(&current, "status") == "disconnected" {
        return bad(
            StatusCode::CONFLICT,
            &CONNECTION.code("already_disconnected"),
            "this connection is already disconnected; reconnect creates a successor",
        );
    }
    let now = now_ms();
    let connector_id = write.connector_id.clone();
    let principal_ref = text(&current, "principal_ref");
    let reply = admit_successor(
        &st,
        &write,
        &body,
        |next, version| {
            next["status"] = json!("disconnected");
            next["connection_revocation_epoch"] =
                json!(next["connection_revocation_epoch"].as_u64().unwrap_or(0) + 1);
            next["receipt_refs"] = receipt(&connector_id, &principal_ref, version, "disconnected");
        },
        now,
    );
    if !reply.0.is_success() {
        return reply;
    }
    // Retire the sealed material: the fence already refuses by epoch; removing the bytes is the
    // cleanup canon says need not complete before fencing, done here because it is cheap.
    if let Some(mut credential) = read_record_dir(&st.data_dir, "connector-credentials")
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(write.connector_id.as_str()))
    {
        if credential["connection_ref"].as_str() == Some(write.resource.as_str()) {
            if let Some(map) = credential.as_object_mut() {
                map.retain(|key, _| !key.starts_with("sealed_"));
                map.insert("retired_at".into(), json!(iso_now()));
                map.insert("retired_by".into(), json!("disconnect"));
            }
            let _ = persist_record(
                &st.data_dir,
                "connector-credentials",
                &write.connector_id,
                &credential,
            );
        }
    }
    if let Some(mut c) = read_record_dir(&st.data_dir, "connectors")
        .into_iter()
        .find(|c| c["connector_id"].as_str() == Some(write.connector_id.as_str()))
    {
        c["auth_posture"] = json!("token-lease:unbound");
        let _ = persist_record(&st.data_dir, "connectors", &write.connector_id, &c);
    }
    let obligations = record_obligations(
        &st.data_dir,
        &write.connector_id,
        &write.resource,
        "disconnected",
        now,
    );
    let mut reply = reply;
    reply.1 .0["obligations"] = json!(obligations);
    reply
}

/// POST /v1/hypervisor/auth/connections/:id/reauthorize — a new ceremony for the connection's
/// connector under the connection's principal; its completion admits the successor version with a
/// successor credential binding. Predecessor grants never revive: the fence keys on the version.
pub(crate) async fn handle_connection_reauthorize(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let (connector_id, resource) = match parse_connection_id(&id) {
        Ok(parts) => parts,
        Err(response) => return response,
    };
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) = reject_authored(&body, &CEREMONY, START_SERVER_RESOLVED) {
        return response;
    }
    if let Err(response) = refuse_unknown_fields(&body, &CEREMONY, START_FIELDS) {
        return response;
    }
    let stream = match authorized_stream(&CONNECTION, &st.data_dir, &caller.identity, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let Some(current) = head_record(&stream).cloned() else {
        return bad(
            StatusCode::NOT_FOUND,
            &CONNECTION.code("absent"),
            "no connection answers to that id",
        );
    };
    if text(&current, "principal_ref") != caller.identity.principal_ref {
        return bad(
            StatusCode::FORBIDDEN,
            &CONNECTION.code("principal_mismatch"),
            "a connection is reauthorized only by the principal it binds",
        );
    }
    let granted = list(&current, "provider_granted_scopes");
    match issue_ceremony(&st, &caller, &body, &connector_id, Some(granted)).await {
        Ok(issued) => issued.reply,
        Err(response) => response,
    }
}

// ================================================================================= the fence

/// THE ONE CHECK SITE. A credential record that names a connection resolves only while that
/// connection is `active`, acts through that exact credential binding at that exact epoch, and is
/// before its reauthorization deadline; anything else is a typed cause the gateway turns into a
/// 428. A record with no connection is a legacy credential and passes unchanged — typed in the
/// register.
pub(crate) fn fence_credential(data_dir: &str, credential: &Value) -> Result<(), String> {
    let Some(connection_ref) = credential.get("connection_ref").and_then(Value::as_str) else {
        return Ok(());
    };
    let tail = stream_tail(CONNECTION.resource_kind, connection_ref);
    let head = super::substrate_store::read_event_stream_operation(
        data_dir,
        CONNECTION.owner_namespace,
        &tail,
    )
    .map_err(|error| format!("connection_unreadable: {error}"))?;
    let Some(head) = head else {
        return Err(format!(
            "connection_absent: {connection_ref} has no admitted version"
        ));
    };
    let record = &head.operation.payload[CONNECTION.record_key];
    let status = text(record, "status");
    if status != "active" {
        return Err(format!("connection_{status}: {connection_ref} is {status}"));
    }
    // The head may be a later VERSION than the one that sealed the credential (a verification
    // admits a successor without rotating anything); what must agree is the CREDENTIAL BINDING the
    // head names and the epoch — a reauthorization or reconnect names a successor binding, and
    // every fence event advances the epoch.
    let binding = text(record, "credential_binding_ref");
    if credential["credential_binding_ref"].as_str() != Some(binding.as_str()) {
        return Err(format!(
            "connection_credential_superseded: the credential is binding {} and the connection now acts through {binding}",
            credential["credential_binding_ref"]
        ));
    }
    let epoch = record["connection_revocation_epoch"].as_u64().unwrap_or(0);
    if credential["connection_revocation_epoch"].as_u64() != Some(epoch) {
        return Err(format!(
            "connection_epoch_advanced: the credential binds epoch {} and the connection is at epoch {epoch}",
            credential["connection_revocation_epoch"]
        ));
    }
    if let Some(deadline) = record
        .get("reauthorization_required_at")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339_ms)
    {
        if now_ms() > deadline {
            return Err(format!(
                "connection_reauthorization_required: {connection_ref} passed its reauthorization deadline"
            ));
        }
    }
    Ok(())
}

// ============================================================================ legacy aliases

fn alias_caller_body(
    identity: &RequestIdentity,
    key_seed: &str,
    mut body: Value,
) -> Result<Value, Reply> {
    let owner = identity
        .tenant_refs
        .iter()
        .find(|tenant| tenant.starts_with("org://") || tenant.starts_with("project://"))
        .cloned();
    let Some(owner) = owner else {
        return Err(bad(
            StatusCode::FORBIDDEN,
            &CEREMONY.code("owner_unresolvable"),
            "the authenticated principal holds no org:// or project:// tenant to own a connection",
        ));
    };
    body["owner_ref"] = json!(owner);
    body["idempotency_key"] = json!(format!(
        "legacy-oauth:{}",
        sha256_hex(format!("{key_seed}|{}", identity.principal_ref).as_bytes())
    ));
    Ok(body)
}

/// The legacy `POST /v1/hypervisor/connectors/:id/oauth/start` — the product UI's connect button —
/// now issues the registered ceremony and answers in the shape the UI reads. One lineage.
pub(crate) async fn legacy_oauth_start(
    st: &DaemonState,
    headers: &HeaderMap,
    connector_id: &str,
    body: &Value,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let redirect_uri = body
        .get("redirect_uri")
        .and_then(Value::as_str)
        .unwrap_or("http://127.0.0.1:4173/__ioi/integrations/oauth/callback")
        .to_string();
    let seed = format!("start|{connector_id}|{redirect_uri}|{}", random_token(12));
    let body = match alias_caller_body(
        &identity,
        &seed,
        json!({ "connector_id": connector_id, "redirect_uri": redirect_uri }),
    ) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let caller = match require_write_caller(&st.data_dir, headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    match issue_ceremony(st, &caller, &body, connector_id, None).await {
        Ok(issued) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "authorize_url": issued.authorize_url,
                "state": issued.state,
                "ceremony_ref": issued.reply.1 .0.get(CEREMONY.record_key).map(|r| r["ceremony_ref"].clone()).unwrap_or(Value::Null),
            })),
        ),
        Err(response) => {
            let mut response = response;
            if response.1 .0.get("reason").is_none() {
                response.1 .0["reason"] = response
                    .1
                     .0
                    .pointer("/error/code")
                    .cloned()
                    .unwrap_or(json!("provider_connection_refused"));
                response.1 .0["message"] = response
                    .1
                     .0
                    .pointer("/error/message")
                    .cloned()
                    .unwrap_or(Value::Null);
            }
            response
        }
    }
}

/// The legacy `POST /v1/hypervisor/connectors/oauth/callback` — completes the ceremony the state
/// names and answers in the shape the UI reads.
pub(crate) async fn legacy_oauth_callback(
    st: &DaemonState,
    headers: &HeaderMap,
    body: &Value,
) -> Reply {
    let state = body_str(body, "state");
    let code = body_str(body, "code");
    if state.is_empty() || code.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "reason": "state and code are required" })),
        );
    }
    let identity = match resolve_request_identity(&st.data_dir, headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let body = match alias_caller_body(
        &identity,
        &format!("complete|{state}"),
        json!({ "state": state, "code": code }),
    ) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let write = match open_ceremony_by_state(st, headers, &body, &state) {
        Ok(write) => write,
        Err(response) => {
            let mut response = response;
            response.1 .0["reason"] = response
                .1
                 .0
                .pointer("/error/code")
                .cloned()
                .unwrap_or(json!("unknown or expired state"));
            return response;
        }
    };
    let reply = complete_ceremony(st, write, &body, &code).await;
    if reply.0.is_success() {
        let mut out = reply;
        out.1 .0["state_consumed"] = json!(true);
        (StatusCode::OK, out.1)
    } else {
        let mut response = reply;
        if response.1 .0.get("reason").is_none() {
            response.1 .0["reason"] = response
                .1
                 .0
                .pointer("/error/code")
                .cloned()
                .unwrap_or(json!("provider_connection_refused"));
            response.1 .0["message"] = response
                .1
                 .0
                .pointer("/error/message")
                .cloned()
                .unwrap_or(Value::Null);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_ids_round_trip_and_refuse_spelling() {
        let id = connection_id("cnx_abc", "user://principal_01");
        assert_eq!(id, "cnx_abc~user-principal_01");
        let (connector, resource) = parse_connection_id(&id).unwrap();
        assert_eq!(connector, "cnx_abc");
        assert_eq!(resource, "connection://provider/cnx_abc/user-principal_01");
        assert!(parse_connection_id("cnx_abc").is_err());
        assert!(parse_connection_id("cnx_abc~a/b").is_err());
    }

    #[test]
    fn provider_profile_ref_excludes_sealed_members_and_moves_with_the_profile() {
        let a = json!({ "connector_id": "cnx_a", "auth_profile": { "authorization_endpoint": "https://p/auth", "token_endpoint": "https://p/token", "client_id": "c1", "sealed_client_secret": "xxx" } });
        let b = json!({ "connector_id": "cnx_a", "auth_profile": { "authorization_endpoint": "https://p/auth", "token_endpoint": "https://p/token", "client_id": "c1", "sealed_client_secret": "yyy" } });
        let c = json!({ "connector_id": "cnx_a", "auth_profile": { "authorization_endpoint": "https://p/auth", "token_endpoint": "https://p/token2", "client_id": "c1" } });
        assert_eq!(
            provider_profile_ref(&a),
            provider_profile_ref(&b),
            "a sealed member never contributes"
        );
        assert_ne!(
            provider_profile_ref(&a),
            provider_profile_ref(&c),
            "an endpoint edit is a new revision"
        );
        assert!(provider_profile_ref(&a).starts_with("provider-profile://cnx_a@sha256:"));
    }

    #[test]
    fn fence_lets_a_legacy_credential_through_and_refuses_an_absent_connection() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        assert!(fence_credential(
            data_dir,
            &json!({ "connector_id": "cnx", "kind": "bearer" })
        )
        .is_ok());
        let err = fence_credential(data_dir, &json!({ "connector_id": "cnx", "connection_ref": "connection://provider/cnx/user-p", "credential_binding_ref": "credential://cnx/user-p@1", "connection_revocation_epoch": 0 })).unwrap_err();
        assert!(err.starts_with("connection_absent"), "{err}");
        super::super::substrate_store::reset_handle_for_test();
    }

    #[test]
    fn subject_hash_commits_the_profile_and_the_subject() {
        let a = subject_hash("provider-profile://x@sha256:aa", "sub-1");
        assert_ne!(a, subject_hash("provider-profile://x@sha256:bb", "sub-1"));
        assert_ne!(a, subject_hash("provider-profile://x@sha256:aa", "sub-2"));
        assert!(a.starts_with("sha256:") && a.len() == 71);
    }

    #[test]
    fn redirect_origin_is_scheme_and_host_only() {
        assert_eq!(
            redirect_origin("http://127.0.0.1:4173/__ioi/cb?x=1").as_deref(),
            Some("http://127.0.0.1:4173")
        );
        assert_eq!(redirect_origin("not a uri"), None);
    }
}
