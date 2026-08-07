//! Deployment-local portal -> daemon authentication exchange.
//!
//! This is deliberately an outer-identity bridge, not wallet/effect authority. A trusted ioi.ai
//! serve process exchanges one verified portal identity for a five-minute daemon session. The
//! assertion is issuer-, audience-, tenant-, expiry-, and one-time-JTI-bound; the daemon resolves
//! the local principal and current tenant membership from its own durable registries. Browser
//! cookies, body-carried owner refs, and assertion-carried tenant sets are never authority inputs.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::{json, Value};

use super::durable_fs::{persist_receipt_no_clobber, CommitFailure};
use super::{iso_now, read_record_dir, sha256_hex_str, DaemonState};

const ASSERTION_TYPE: &str = "ioi-portal-daemon-exchange+jwt";
const CONSUMPTION_FAMILY: &str = "portal-session-exchange-consumptions";
const MAX_ASSERTION_BYTES: usize = 8 * 1024;
const MAX_ASSERTION_TTL_SECONDS: i64 = 60;
const CLOCK_SKEW_SECONDS: i64 = 5;

#[derive(Clone, Debug)]
struct PortalExchangeConfig {
    secret: String,
    issuer: String,
    audience: String,
    tenant_ref: String,
}

impl PortalExchangeConfig {
    fn from_env() -> Result<Self, String> {
        let value = |name: &str| std::env::var(name).unwrap_or_default().trim().to_string();
        let config = Self {
            secret: value("IOI_PORTAL_DAEMON_EXCHANGE_SECRET"),
            issuer: value("IOI_PORTAL_DAEMON_EXCHANGE_ISSUER"),
            audience: value("IOI_PORTAL_DAEMON_EXCHANGE_AUDIENCE"),
            tenant_ref: value("IOI_PORTAL_DAEMON_EXCHANGE_TENANT_REF"),
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if self.secret.as_bytes().len() < 32 {
            return Err("portal-daemon exchange secret must be at least 32 bytes".to_string());
        }
        if !bounded_text(&self.issuer, 300) || !bounded_text(&self.audience, 300) {
            return Err("portal-daemon exchange issuer and audience must be explicit".to_string());
        }
        if !canonical_tenant_ref(&self.tenant_ref) {
            return Err(
                "portal-daemon exchange tenant must be one canonical org:// or project:// ref"
                    .to_string(),
            );
        }
        Ok(())
    }
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .chars()
            .any(|character| character.is_control() || character == '\u{7f}')
}

fn canonical_tenant_ref(value: &str) -> bool {
    let suffix = value
        .strip_prefix("org://")
        .or_else(|| value.strip_prefix("project://"));
    suffix.is_some_and(|suffix| {
        bounded_text(suffix, 480)
            && !suffix
                .chars()
                .any(|character| character.is_whitespace() || matches!(character, '?' | '#' | '\\'))
    })
}

fn canonical_principal_id(value: &str) -> bool {
    bounded_text(value, 480)
        && !value.chars().any(|character| {
            character.is_whitespace() || matches!(character, '/' | '?' | '#' | '\\')
        })
}

fn claim_i64(claims: &Value, name: &str) -> Option<i64> {
    claims.get(name).and_then(Value::as_i64)
}

fn verify_assertion(
    assertion: &str,
    config: &PortalExchangeConfig,
    now: i64,
) -> Result<Value, String> {
    if assertion.is_empty() || assertion.len() > MAX_ASSERTION_BYTES {
        return Err("assertion size is invalid".to_string());
    }
    let header = decode_header(assertion).map_err(|_| "assertion header is invalid".to_string())?;
    if header.alg != Algorithm::HS256 || header.typ.as_deref() != Some(ASSERTION_TYPE) {
        return Err("assertion type or algorithm is invalid".to_string());
    }
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[config.audience.as_str()]);
    validation.leeway = CLOCK_SKEW_SECONDS as u64;
    validation.validate_nbf = true;
    validation.required_spec_claims = HashSet::from_iter(
        ["iss", "aud", "sub", "exp", "nbf", "iat", "jti"]
            .into_iter()
            .map(str::to_string),
    );
    let claims = decode::<Value>(
        assertion,
        &DecodingKey::from_secret(config.secret.as_bytes()),
        &validation,
    )
    .map_err(|_| "assertion signature or registered claims are invalid".to_string())?
    .claims;
    let Some(object) = claims.as_object() else {
        return Err("assertion claims are not an object".to_string());
    };
    let allowed = [
        "iss",
        "aud",
        "sub",
        "tenant_ref",
        "source_identity_hash",
        "iat",
        "nbf",
        "exp",
        "jti",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("assertion claims are not closed".to_string());
    }
    let subject = claims["sub"].as_str().unwrap_or_default();
    let tenant_ref = claims["tenant_ref"].as_str().unwrap_or_default();
    let source_hash = claims["source_identity_hash"].as_str().unwrap_or_default();
    let jti = claims["jti"].as_str().unwrap_or_default();
    let (Some(iat), Some(nbf), Some(exp)) = (
        claim_i64(&claims, "iat"),
        claim_i64(&claims, "nbf"),
        claim_i64(&claims, "exp"),
    ) else {
        return Err("assertion timestamps are invalid".to_string());
    };
    if !canonical_principal_id(subject)
        || claims["iss"].as_str() != Some(config.issuer.as_str())
        || claims["aud"].as_str() != Some(config.audience.as_str())
        || tenant_ref != config.tenant_ref
        || !canonical_tenant_ref(tenant_ref)
        || source_hash.len() != 71
        || !source_hash.starts_with("sha256:")
        || !source_hash[7..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        || !source_hash[7..]
            .chars()
            .all(|character| !character.is_ascii_uppercase())
        || !(32..=128).contains(&jti.len())
        || !jti
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        || nbf < iat - CLOCK_SKEW_SECONDS
        || iat > now + CLOCK_SKEW_SECONDS
        || exp <= now
        || exp - iat < 10
        || exp - iat > MAX_ASSERTION_TTL_SECONDS
    {
        return Err("assertion identity, tenant, nonce, or lifetime is invalid".to_string());
    }
    Ok(claims)
}

fn exchange_assertion(
    data_dir: &str,
    assertion: &str,
    config: &PortalExchangeConfig,
    now: i64,
) -> (StatusCode, Value) {
    let claims = match verify_assertion(assertion, config, now) {
        Ok(claims) => claims,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                json!({
                    "ok": false,
                    "code": "hypervisor.portal_exchange_assertion_invalid",
                    "message": "portal session exchange assertion was refused"
                }),
            )
        }
    };
    let principal_id = claims["sub"].as_str().unwrap_or_default();
    let principals = read_record_dir(data_dir, "principals")
        .into_iter()
        .filter(|principal| principal["principal_id"].as_str() == Some(principal_id))
        .collect::<Vec<_>>();
    if principals.len() != 1 {
        return (
            StatusCode::NOT_FOUND,
            json!({
                "ok": false,
                "code": "hypervisor.portal_exchange_principal_unknown",
                "message": "portal principal is not uniquely provisioned in this daemon"
            }),
        );
    }
    if principals[0]["status"].as_str() != Some("active") {
        return (
            StatusCode::FORBIDDEN,
            json!({
                "ok": false,
                "code": "hypervisor.portal_exchange_principal_inactive"
            }),
        );
    }
    let principal_ref = format!("user://{principal_id}");
    let tenant_refs =
        match super::lifecycle_routes::resolve_principal_tenant_refs(data_dir, &principal_ref) {
            Ok(tenant_refs) => tenant_refs,
            Err(message) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({
                        "ok": false,
                        "code": "hypervisor.portal_exchange_membership_registry_unavailable",
                        "message": message
                    }),
                )
            }
        };
    if !tenant_refs.contains(&config.tenant_ref) {
        return (
            StatusCode::FORBIDDEN,
            json!({
                "ok": false,
                "code": "hypervisor.portal_exchange_tenant_membership_denied",
                "message": "daemon membership does not admit this principal to the configured portal tenant"
            }),
        );
    }

    let jti = claims["jti"].as_str().unwrap_or_default();
    let jti_hash = sha256_hex_str(&format!(
        "ioi.hypervisor.portal-session-exchange-jti.v1\0{jti}"
    ));
    let assertion_hash = format!("sha256:{}", sha256_hex_str(assertion));
    let consumption_ref = format!("receipt://hypervisor/portal-session-exchange/{jti_hash}");
    // A fresh attempt ref deliberately makes an occupied JTI slot byte-different. The shared
    // no-clobber writer therefore distinguishes replay atomically across threads and restarts.
    let consumption = json!({
        "schema_version": "ioi.hypervisor.portal-session-exchange-consumption.v1",
        "consumption_ref": consumption_ref,
        "admission_attempt_ref": format!("attempt://hypervisor/portal-session-exchange/{}", uuid::Uuid::new_v4().simple()),
        "jti_hash": format!("sha256:{jti_hash}"),
        "assertion_hash": assertion_hash,
        "issuer": config.issuer,
        "audience": config.audience,
        "principal_ref": principal_ref,
        "tenant_ref": config.tenant_ref,
        "source_identity_hash": claims["source_identity_hash"],
        "assertion_expires_at_unix": claims["exp"],
        "consumed_at": iso_now(),
    });
    match persist_receipt_no_clobber(data_dir, CONSUMPTION_FAMILY, &jti_hash, &consumption) {
        Ok(()) => {}
        Err(CommitFailure::Conflict(_)) => {
            return (
                StatusCode::CONFLICT,
                json!({
                    "ok": false,
                    "code": "hypervisor.portal_exchange_replayed",
                    "message": "portal session exchange assertion was already consumed"
                }),
            )
        }
        Err(error) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "ok": false,
                    "code": "hypervisor.portal_exchange_consumption_unavailable",
                    "message": format!("exchange JTI was not durably consumed ({error:?})")
                }),
            )
        }
    }

    super::lifecycle_routes::issue_portal_exchange_session(
        data_dir,
        principal_id,
        &config.issuer,
        &config.audience,
        &config.tenant_ref,
        consumption["consumption_ref"].as_str().unwrap_or_default(),
    )
}

/// POST /v1/hypervisor/auth/portal-session-exchange — independently authenticated bootstrap
/// route. Configuration is mandatory; absence is a 503, never loopback or header trust.
pub(crate) async fn handle_portal_session_exchange(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(request) = body.as_object() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "code": "hypervisor.portal_exchange_request_invalid" })),
        );
    };
    if request.len() != 1 || !request.contains_key("assertion") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "code": "hypervisor.portal_exchange_request_closed",
                "message": "request must contain only assertion"
            })),
        );
    }
    let assertion = body["assertion"].as_str().unwrap_or_default();
    let config = match PortalExchangeConfig::from_env() {
        Ok(config) => config,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "code": "hypervisor.portal_exchange_not_configured",
                    "message": "portal session exchange trust is not configured"
                })),
            )
        }
    };
    let (status, response) = exchange_assertion(&st.data_dir, assertion, &config, now_seconds());
    (status, Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderMap};
    use jsonwebtoken::{encode, EncodingKey, Header};

    const SECRET: &str = "portal-daemon-exchange-test-secret-000000000000000000";
    const OPERATOR_ID: &str = "00000000-0000-4000-8000-000000000001";

    fn config(tenant_ref: &str) -> PortalExchangeConfig {
        PortalExchangeConfig {
            secret: SECRET.to_string(),
            issuer: "surface://ioi.ai/test".to_string(),
            audience: "daemon://hypervisor/test".to_string(),
            tenant_ref: tenant_ref.to_string(),
        }
    }

    fn assertion(config: &PortalExchangeConfig, jti: &str, issuer: &str, audience: &str) -> String {
        let now = now_seconds();
        let claims = json!({
            "iss": issuer,
            "aud": audience,
            "sub": OPERATOR_ID,
            "tenant_ref": config.tenant_ref,
            "source_identity_hash": format!("sha256:{}", "a".repeat(64)),
            "iat": now,
            "nbf": now,
            "exp": now + 30,
            "jti": jti,
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(ASSERTION_TYPE.to_string());
        encode(
            &header,
            &claims,
            &EncodingKey::from_secret(config.secret.as_bytes()),
        )
        .unwrap()
    }

    fn fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        super::super::lifecycle_routes::ensure_identity_foundation(
            directory.path().to_str().unwrap(),
        )
        .unwrap();
        directory
    }

    #[test]
    fn valid_exchange_resolves_daemon_membership_and_issues_only_a_short_lived_session() {
        let directory = fixture();
        let data_dir = directory.path().to_str().unwrap();
        let config = config("org://local");
        let token = assertion(
            &config,
            &format!("valid_{}", "1".repeat(32)),
            &config.issuer,
            &config.audience,
        );
        let (status, response) = exchange_assertion(data_dir, &token, &config, now_seconds());
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["principal"]["principal_id"], OPERATOR_ID);
        assert!(response["principal"]["tenant_refs"]
            .as_array()
            .unwrap()
            .contains(&json!("org://local")));
        let session = response["session_token"].as_str().unwrap();
        assert!(session.starts_with("ioi_sess_"));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {session}").parse().unwrap(),
        );
        let resolved =
            super::super::lifecycle_routes::resolve_principal(data_dir, &headers).unwrap();
        assert_eq!(resolved["principal_id"], OPERATOR_ID);
        assert!(super::super::lifecycle_routes::session_allows_route(
            data_dir,
            &headers,
            "/v1/goal-orchestration/goal-runs"
        ));
        assert!(!super::super::lifecycle_routes::session_allows_route(
            data_dir,
            &headers,
            "/v1/hypervisor/secrets"
        ));
        let stored = read_record_dir(data_dir, "sessions");
        assert_eq!(stored.len(), 1);
        assert!(stored[0].get("session_token").is_none());
        assert_eq!(stored[0]["source"], "portal_exchange");
        assert_eq!(stored[0]["source_tenant_ref"], "org://local");
        assert_eq!(
            stored[0]["allowed_route_prefixes"],
            json!(["/v1/goal-orchestration/"])
        );
    }

    #[test]
    fn consumed_jti_refuses_replay_from_durable_bytes_without_process_memory() {
        let directory = fixture();
        let data_dir = directory.path().to_str().unwrap();
        let config = config("org://local");
        let token = assertion(
            &config,
            &format!("restart_replay_{}", "2".repeat(32)),
            &config.issuer,
            &config.audience,
        );
        assert_eq!(
            exchange_assertion(data_dir, &token, &config, now_seconds()).0,
            StatusCode::OK
        );
        let restarted_config = config.clone();
        let (status, refusal) =
            exchange_assertion(data_dir, &token, &restarted_config, now_seconds());
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(refusal["code"], "hypervisor.portal_exchange_replayed");
        assert_eq!(read_record_dir(data_dir, "sessions").len(), 1);
    }

    #[test]
    fn wrong_issuer_and_audience_are_refused_before_consuming_the_jti() {
        let directory = fixture();
        let data_dir = directory.path().to_str().unwrap();
        let config = config("org://local");
        let jti = format!("wrong_registered_claims_{}", "3".repeat(32));
        for (issuer, audience) in [
            ("surface://attacker", config.audience.as_str()),
            (config.issuer.as_str(), "daemon://wrong-audience"),
        ] {
            let token = assertion(&config, &jti, issuer, audience);
            assert_eq!(
                exchange_assertion(data_dir, &token, &config, now_seconds()).0,
                StatusCode::UNAUTHORIZED
            );
        }
        let now = now_seconds();
        let multi_audience_claims = json!({
            "iss": config.issuer,
            "aud": [config.audience, "daemon://also-not-this-deployment"],
            "sub": OPERATOR_ID,
            "tenant_ref": config.tenant_ref,
            "source_identity_hash": format!("sha256:{}", "a".repeat(64)),
            "iat": now,
            "nbf": now,
            "exp": now + 30,
            "jti": jti,
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(ASSERTION_TYPE.to_string());
        let multi_audience = encode(
            &header,
            &multi_audience_claims,
            &EncodingKey::from_secret(config.secret.as_bytes()),
        )
        .unwrap();
        assert_eq!(
            exchange_assertion(data_dir, &multi_audience, &config, now_seconds()).0,
            StatusCode::UNAUTHORIZED
        );
        assert!(read_record_dir(data_dir, CONSUMPTION_FAMILY).is_empty());
        let valid = assertion(&config, &jti, &config.issuer, &config.audience);
        assert_eq!(
            exchange_assertion(data_dir, &valid, &config, now_seconds()).0,
            StatusCode::OK
        );
    }

    #[test]
    fn assertion_cannot_invent_a_tenant_membership() {
        let directory = fixture();
        let data_dir = directory.path().to_str().unwrap();
        let config = config("project://not-a-member");
        let token = assertion(
            &config,
            &format!("wrong_tenant_{}", "4".repeat(32)),
            &config.issuer,
            &config.audience,
        );
        let (status, refusal) = exchange_assertion(data_dir, &token, &config, now_seconds());
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            refusal["code"],
            "hypervisor.portal_exchange_tenant_membership_denied"
        );
        assert!(read_record_dir(data_dir, CONSUMPTION_FAMILY).is_empty());
        assert!(read_record_dir(data_dir, "sessions").is_empty());
    }
}
