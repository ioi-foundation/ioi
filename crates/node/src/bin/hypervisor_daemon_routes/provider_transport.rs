//! ProviderTransport (W3.2, first cut) — the provider-protocol adaptation boundary, and the first
//! daemon-issued model invocation whose endpoint comes from the model-route REGISTRY rather than a
//! boot-time environment singleton.
//!
//! Canon: `docs/architecture/components/model-router/doctrine.md` §Provider Transport Boundary and
//! §Route Economic Comparison (filed 2026-08-12, next-legs VI Leg 0b).
//!
//! WHAT THIS OWNS (the replaceable transport concern):
//!   * request/response normalization for one provider dialect;
//!   * streaming and cancellation protocol handling;
//!   * error normalization and retryability CLASSIFICATION;
//!   * the observed evidence a response carries — token mix, latency breakdown, finish condition.
//!
//! WHAT IT MUST NEVER OWN (each already has a kernel owner; taking one would mint a second spine):
//!   * route selection and admission — the registry decides, this module only executes what it is
//!     handed. `model_routes::load_route_record` is the reader; there is no second census here.
//!   * credential custody — `lifecycle_routes::authorize_capability_lease` is THE crossing. A
//!     credentialed route is REFUSED here, typed, rather than reading a process env var: the env
//!     path (`resolve_inference`) bypasses the lease gateway entirely and this module will not
//!     reproduce that bypass.
//!   * retry and fallback DECISIONS — a transport classifies an error as retryable; only the router
//!     decides whether to retry. This cut performs exactly one attempt and says so in the record.
//!   * billing — the transport reports what it observed; the economics ledger owns what it cost.
//!     No `UsageRecord` is written here (named residual, see the module tail).
//!
//! HONESTY RULES enforced below, not merely described:
//!   * Every token-mix and latency field the provider did NOT report is `null` — a TYPED GAP. It is
//!     never zero-filled, and never derived. A synthesized measurement is worse than an absent one
//!     because it reads as evidence.
//!   * A failed invocation is receipted with the same care as a successful one. The attempt, its
//!     classified error, its latency, and its typed outcome are durable. A provider that is
//!     unreachable produces an honest `ProviderUnavailable` record, never a fabricated completion.
//!   * The receipt is the TYPED `ModelInvocationReceipt` from the kernel
//!     (`ioi_services::agentic::runtime::kernel::inference`), not a fresh ad-hoc `json!` shape.
//!     That struct existed and had never been constructed anywhere in `crates/node/`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use sha2::Digest;

use ioi_services::agentic::runtime::kernel::inference::{
    ModelInvocationReceipt, ModelRuntimeErrorClass,
};

use super::mutation_event_foundation::{
    admit_owner_scoped_write, replay_stable_id, require_write_caller, scope_refusal_reply,
    MutationCommit, WriteCaller,
};
use super::{persist_record, DaemonState};

const INVOCATION_NAMESPACE: &str = "hypervisor-model-invocations";
const KIND_INVOCATION: &str = "model-invocations";
const SCHEMA_VERSION: &str = "ioi.hypervisor.model-invocation.v1";
/// One attempt per invocation in this cut. Retry/fallback DECISIONS belong to the router; the
/// field exists so a later router can extend the lineage rather than re-shape the record.
const ATTEMPTS_THIS_CUT: usize = 1;
/// Wall-clock ceiling for one invocation. Exceeding it is `Timeout`, classified, never silent.
const INVOKE_TIMEOUT_MS: u64 = 120_000;
/// A stream that produces no further chunk for this long is a stall, distinct from a slow model.
const STREAM_STALL_MS: u64 = 30_000;

type Reply = (StatusCode, Json<Value>);

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}

fn digest_hex(bytes: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(bytes))
}

fn load_invocation(data_dir: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(data_dir)
                .join(KIND_INVOCATION)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}

// ---------------------------------------------------------------- the transport contract

/// What a transport is asked to do. Everything here is resolved by an owner ABOVE the transport:
/// the endpoint and model by the registry, the credential by the lease gateway.
pub(crate) struct TransportRequest {
    pub base_url: String,
    pub model_id: String,
    pub prompt: String,
    pub stream: bool,
    /// Resolved through the CapabilityLease gateway when the route is credentialed. `None` means
    /// the route declared no credential requirement — never "we could not find one".
    pub credential: Option<String>,
}

/// The observed token mix. Every field is optional BECAUSE providers differ in what they report,
/// and an unreported quantity is a typed gap. Zero would be a lie; these stay `None`.
#[derive(Default, Clone)]
pub(crate) struct TokenMix {
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub cache_read: Option<u64>,
    pub cache_write: Option<u64>,
    pub reasoning: Option<u64>,
}

impl TokenMix {
    fn total(&self) -> Option<u64> {
        match (self.input, self.output) {
            (Some(i), Some(o)) => Some(i + o),
            _ => None,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "input": self.input,
            "output": self.output,
            "cache_read": self.cache_read,
            "cache_write": self.cache_write,
            "reasoning": self.reasoning,
            "total": self.total(),
            "unreported": self.unreported(),
        })
    }

    /// Naming the gaps is the point: a consumer must be able to tell "the provider does not report
    /// cache tokens" from "this call used no cache".
    fn unreported(&self) -> Vec<&'static str> {
        let mut gaps = Vec::new();
        if self.input.is_none() {
            gaps.push("input");
        }
        if self.output.is_none() {
            gaps.push("output");
        }
        if self.cache_read.is_none() {
            gaps.push("cache_read");
        }
        if self.cache_write.is_none() {
            gaps.push("cache_write");
        }
        if self.reasoning.is_none() {
            gaps.push("reasoning");
        }
        gaps
    }
}

/// One attempt against one provider. Attempts are the lineage a later router extends; there was no
/// attempt lineage of any spelling in this repository before this cut.
pub(crate) struct TransportAttempt {
    pub index: usize,
    pub latency_ms: u64,
    pub first_token_ms: Option<u64>,
    pub http_status: Option<u16>,
    pub outcome: &'static str,
    pub error_class: Option<ModelRuntimeErrorClass>,
    pub retryable: bool,
    pub detail: Option<String>,
}

impl TransportAttempt {
    fn to_json(&self) -> Value {
        json!({
            "attempt_index": self.index,
            "latency_ms": self.latency_ms,
            "first_token_ms": self.first_token_ms,
            "http_status": self.http_status,
            "outcome": self.outcome,
            "error_class": self.error_class.map(|c| c.as_str()),
            "retryable": self.retryable,
            "detail": self.detail,
        })
    }
}

pub(crate) struct TransportOutcome {
    pub output: String,
    pub token_mix: TokenMix,
    pub attempts: Vec<TransportAttempt>,
    pub total_latency_ms: u64,
    pub first_token_ms: Option<u64>,
    pub finish_reason: Option<String>,
    pub streaming: bool,
}

pub(crate) struct TransportFailure {
    pub attempts: Vec<TransportAttempt>,
    pub total_latency_ms: u64,
    pub error_class: ModelRuntimeErrorClass,
    pub detail: String,
}

/// The boundary itself. One dialect per implementation; nothing above the wire belongs here.
#[allow(async_fn_in_trait)]
pub(crate) trait ProviderTransport {
    fn transport_kind(&self) -> &'static str;

    /// The verbatim price-schedule ref this transport can attribute a call to, when the route
    /// carries one. `None` is a typed gap the economics join must surface, never a zero price.
    fn price_schedule_ref(&self, route: &Value) -> Option<String> {
        route
            .pointer("/provider_binding/price_schedule_ref")
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    async fn invoke(
        &self,
        request: &TransportRequest,
    ) -> Result<TransportOutcome, TransportFailure>;
}

// ---------------------------------------------------------------- the one native implementation

/// Ollama, the only transport the registry admits as executable today
/// (`model_routes.rs`: "only ollama-transport routes are bindable for session execution").
/// Native-first: this implementation is what DEFINES the contract above. No adapted or absorbed
/// transport may claim to conform until this one has executed end to end.
pub(crate) struct OllamaTransport;

impl OllamaTransport {
    /// Provider failures are classified, never flattened to "error". The taxonomy is the kernel's
    /// existing `ModelRuntimeErrorClass` — this module maps onto it rather than inventing a second.
    fn classify(error: &reqwest::Error) -> (ModelRuntimeErrorClass, bool) {
        if error.is_timeout() {
            return (ModelRuntimeErrorClass::Timeout, true);
        }
        if error.is_connect() {
            return (ModelRuntimeErrorClass::ProviderUnavailable, true);
        }
        if error.is_decode() {
            return (ModelRuntimeErrorClass::MalformedStructuredOutput, false);
        }
        (ModelRuntimeErrorClass::UnknownProviderError, false)
    }

    fn classify_status(status: u16) -> (ModelRuntimeErrorClass, bool) {
        match status {
            429 => (ModelRuntimeErrorClass::RateLimited, true),
            // Ollama answers 404 for a model it does not hold — an unavailable provider capability,
            // not a malformed request.
            404 => (ModelRuntimeErrorClass::ProviderUnavailable, false),
            413 => (ModelRuntimeErrorClass::ContextOverflow, false),
            500..=599 => (ModelRuntimeErrorClass::ProviderUnavailable, true),
            _ => (ModelRuntimeErrorClass::UnknownProviderError, false),
        }
    }
}

impl ProviderTransport for OllamaTransport {
    fn transport_kind(&self) -> &'static str {
        "ollama"
    }

    async fn invoke(
        &self,
        request: &TransportRequest,
    ) -> Result<TransportOutcome, TransportFailure> {
        let started = Instant::now();
        let url = format!("{}/api/chat", request.base_url.trim_end_matches('/'));
        let body = json!({
            "model": request.model_id,
            "messages": [{ "role": "user", "content": request.prompt }],
            "stream": request.stream,
        });

        let client = reqwest::Client::new();
        let mut builder = client
            .post(&url)
            .timeout(Duration::from_millis(INVOKE_TIMEOUT_MS))
            .json(&body);
        // A credential is attached only when an owner above resolved one. This module never reads
        // a key from the environment — that path bypasses the lease gateway.
        if let Some(token) = request.credential.as_deref() {
            builder = builder.bearer_auth(token);
        }

        let response = match builder.send().await {
            Ok(response) => response,
            Err(error) => {
                let (class, retryable) = Self::classify(&error);
                let latency = started.elapsed().as_millis() as u64;
                return Err(TransportFailure {
                    attempts: vec![TransportAttempt {
                        index: 0,
                        latency_ms: latency,
                        first_token_ms: None,
                        http_status: None,
                        outcome: "failed",
                        error_class: Some(class),
                        retryable,
                        detail: Some(error.to_string()),
                    }],
                    total_latency_ms: latency,
                    error_class: class,
                    detail: error.to_string(),
                });
            }
        };

        let status = response.status().as_u16();
        if !response.status().is_success() {
            let (class, retryable) = Self::classify_status(status);
            let latency = started.elapsed().as_millis() as u64;
            let detail = response.text().await.unwrap_or_default();
            let detail = format!(
                "upstream HTTP {status}: {}",
                detail.chars().take(240).collect::<String>()
            );
            return Err(TransportFailure {
                attempts: vec![TransportAttempt {
                    index: 0,
                    latency_ms: latency,
                    first_token_ms: None,
                    http_status: Some(status),
                    outcome: "failed",
                    error_class: Some(class),
                    retryable,
                    detail: Some(detail.clone()),
                }],
                total_latency_ms: latency,
                error_class: class,
                detail,
            });
        }

        // Streaming and non-streaming are one protocol here: NDJSON frames versus a single object.
        // Both paths derive first-token latency from the same clock, so the field means the same
        // thing in either mode.
        let (output, mix, finish_reason, first_token_ms) = if request.stream {
            match read_ollama_stream(response, started).await {
                Ok(parts) => parts,
                Err(failure) => return Err(failure),
            }
        } else {
            let text = match response.text().await {
                Ok(text) => text,
                Err(error) => {
                    let (class, retryable) = Self::classify(&error);
                    let latency = started.elapsed().as_millis() as u64;
                    return Err(TransportFailure {
                        attempts: vec![TransportAttempt {
                            index: 0,
                            latency_ms: latency,
                            first_token_ms: None,
                            http_status: Some(status),
                            outcome: "failed",
                            error_class: Some(class),
                            retryable,
                            detail: Some(error.to_string()),
                        }],
                        total_latency_ms: latency,
                        error_class: class,
                        detail: error.to_string(),
                    });
                }
            };
            let frame: Value = match serde_json::from_str(&text) {
                Ok(frame) => frame,
                Err(error) => {
                    let latency = started.elapsed().as_millis() as u64;
                    return Err(TransportFailure {
                        attempts: vec![TransportAttempt {
                            index: 0,
                            latency_ms: latency,
                            first_token_ms: None,
                            http_status: Some(status),
                            outcome: "failed",
                            error_class: Some(ModelRuntimeErrorClass::MalformedStructuredOutput),
                            retryable: false,
                            detail: Some(error.to_string()),
                        }],
                        total_latency_ms: latency,
                        error_class: ModelRuntimeErrorClass::MalformedStructuredOutput,
                        detail: error.to_string(),
                    });
                }
            };
            let content = frame
                .pointer("/message/content")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let elapsed = started.elapsed().as_millis() as u64;
            (
                content,
                ollama_token_mix(&frame),
                frame
                    .get("done_reason")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                Some(elapsed),
            )
        };

        let latency = started.elapsed().as_millis() as u64;
        Ok(TransportOutcome {
            output,
            token_mix: mix,
            attempts: vec![TransportAttempt {
                index: 0,
                latency_ms: latency,
                first_token_ms,
                http_status: Some(status),
                outcome: "succeeded",
                error_class: None,
                retryable: false,
                detail: None,
            }],
            total_latency_ms: latency,
            first_token_ms,
            finish_reason,
            streaming: request.stream,
        })
    }
}

/// Ollama reports `prompt_eval_count` / `eval_count` and nothing about cache or reasoning tokens.
/// Those two stay `None` — the provider does not report them, which is a gap, not a zero.
fn ollama_token_mix(frame: &Value) -> TokenMix {
    TokenMix {
        input: frame.get("prompt_eval_count").and_then(Value::as_u64),
        output: frame.get("eval_count").and_then(Value::as_u64),
        cache_read: None,
        cache_write: None,
        reasoning: None,
    }
}

/// Read an NDJSON stream to completion, timing the first content frame and detecting a stall.
async fn read_ollama_stream(
    response: reqwest::Response,
    started: Instant,
) -> Result<(String, TokenMix, Option<String>, Option<u64>), TransportFailure> {
    use futures::StreamExt;

    let mut stream = response.bytes_stream();
    let mut buffer = String::new();
    let mut output = String::new();
    let mut mix = TokenMix::default();
    let mut finish_reason = None;
    let mut first_token_ms = None;

    loop {
        let next =
            tokio::time::timeout(Duration::from_millis(STREAM_STALL_MS), stream.next()).await;
        let chunk = match next {
            // A stall is its own class: the provider accepted the request and then stopped
            // producing. Reporting it as Timeout would erase that distinction.
            Err(_) => {
                let latency = started.elapsed().as_millis() as u64;
                return Err(TransportFailure {
                    attempts: vec![TransportAttempt {
                        index: 0,
                        latency_ms: latency,
                        first_token_ms,
                        http_status: Some(200),
                        outcome: "failed",
                        error_class: Some(ModelRuntimeErrorClass::StreamingStall),
                        retryable: true,
                        detail: Some(format!("no stream frame for {STREAM_STALL_MS}ms")),
                    }],
                    total_latency_ms: latency,
                    error_class: ModelRuntimeErrorClass::StreamingStall,
                    detail: format!("no stream frame for {STREAM_STALL_MS}ms"),
                });
            }
            Ok(None) => break,
            Ok(Some(Err(error))) => {
                let (class, retryable) = OllamaTransport::classify(&error);
                let latency = started.elapsed().as_millis() as u64;
                return Err(TransportFailure {
                    attempts: vec![TransportAttempt {
                        index: 0,
                        latency_ms: latency,
                        first_token_ms,
                        http_status: Some(200),
                        outcome: "failed",
                        error_class: Some(class),
                        retryable,
                        detail: Some(error.to_string()),
                    }],
                    total_latency_ms: latency,
                    error_class: class,
                    detail: error.to_string(),
                });
            }
            Ok(Some(Ok(bytes))) => bytes,
        };

        buffer.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(newline) = buffer.find('\n') {
            let line = buffer[..newline].trim().to_string();
            buffer.drain(..=newline);
            if line.is_empty() {
                continue;
            }
            let Ok(frame) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if let Some(piece) = frame.pointer("/message/content").and_then(Value::as_str) {
                if !piece.is_empty() && first_token_ms.is_none() {
                    first_token_ms = Some(started.elapsed().as_millis() as u64);
                }
                output.push_str(piece);
            }
            if frame.get("done").and_then(Value::as_bool) == Some(true) {
                mix = ollama_token_mix(&frame);
                finish_reason = frame
                    .get("done_reason")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
        }
    }

    Ok((output, mix, finish_reason, first_token_ms))
}

// ---------------------------------------------------------------- the route

/// POST /v1/hypervisor/model-routes/:id/invoke
///
/// The first daemon-issued model call whose endpoint comes from the registry. Composition order,
/// each step owned elsewhere:
///   1. identity FIRST (rule E) — `require_write_caller` before any record is read, so an anonymous
///      caller is owed 401 before a 404 can act as an existence oracle;
///   2. INV-37 — the acting principal is resolved server-side; a body carrying a WHO field refuses;
///   3. route resolution — `model_routes::load_route_record`, then the registry's own executable
///      predicate (active + available + ollama). No second census, no second predicate;
///   4. credential — a credentialed route is refused TYPED here rather than read from the process
///      environment, because custody belongs to the CapabilityLease gateway;
///   5. execution — `ProviderTransport::invoke`;
///   6. receipt — the TYPED kernel `ModelInvocationReceipt`, admitted through the shared write path
///      with expected-head CAS, then projected. Failure is receipted as carefully as success.
pub(crate) async fn handle_model_route_invoke(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    // (1) identity before any record read
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // (2) INV-37 — server-resolved actor
    let acting_principal_ref = match super::lifecycle_routes::resolve_acting_principal_ref(
        &st.data_dir,
        &headers,
        &body,
    ) {
        Ok(actor_ref) => actor_ref,
        Err((status, value)) => return (status, Json(value)),
    };

    let prompt = body
        .get("prompt")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if prompt.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "model_invocation_prompt_required",
            "an invocation carries a non-empty prompt",
        );
    }
    let stream = body.get("stream").and_then(Value::as_bool).unwrap_or(false);

    // Replay before work: the same caller + idempotency key returns the stored record rather than
    // spending a second provider call.
    let invocation_id = replay_stable_id(
        "model_invocation",
        &caller.owner_ref,
        &caller.idempotency_key,
    );
    if let Some(existing) = load_invocation(&st.data_dir, &invocation_id) {
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "replayed": true, "invocation": existing })),
        );
    }

    // (3) route resolution through the registry's own reader
    let Some(route) = super::model_routes::load_route_record(&st.data_dir, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "model_route_not_found",
            "no model route exists at this id",
        );
    };
    let transport_kind = route
        .pointer("/provider_binding/transport")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let lifecycle = route
        .pointer("/lifecycle/status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let availability = route
        .pointer("/availability/state")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // Transport support is checked BEFORE availability, deliberately. A route whose transport has
    // no implementation can never execute no matter how healthy its provider is, so answering
    // "not executable (availability)" would name the wrong blocker — and would make this refusal
    // unreachable in practice, since an unimplemented transport never probes to `available`.
    if transport_kind != "ollama" {
        // The honest boundary, not a stub: no other transport is admitted for execution yet, and
        // this cut will not pretend otherwise.
        return bad(
            StatusCode::NOT_IMPLEMENTED,
            "provider_transport_unimplemented",
            format!(
                "transport '{transport_kind}' has no admitted ProviderTransport implementation"
            ),
        );
    }
    if lifecycle != "active" || availability != "available" {
        return bad(
            StatusCode::CONFLICT,
            "model_route_not_executable",
            format!(
                "route lifecycle '{lifecycle}' / availability '{availability}' is not an executable pair; probe the route first"
            ),
        );
    }

    // (4) credential custody stays with the lease gateway
    let credential_posture = route
        .get("credential_posture")
        .and_then(Value::as_str)
        .unwrap_or("no_credentials_required");
    // `no_credentials_required` is the registry's own default for an ollama route (model_routes.rs
    // credential-posture resolution). It is the ONLY posture that needs no crossing; every other
    // posture names a credential this cut cannot obtain without the lease gateway.
    if credential_posture != "no_credentials_required" {
        return bad(
            StatusCode::NOT_IMPLEMENTED,
            "provider_credential_lease_unimplemented",
            format!(
                "route credential posture '{credential_posture}' requires a CapabilityLease-resolved provider credential; \
                 no model-route credential lease is minted or consumed yet, and this transport will not read a provider key \
                 from the process environment"
            ),
        );
    }

    let base_url = route
        .pointer("/provider_binding/base_url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let model_id = route
        .pointer("/model/model_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let route_ref = route
        .get("route_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    // (5) execution
    let transport = OllamaTransport;
    let price_schedule_ref = transport.price_schedule_ref(&route);
    let request = TransportRequest {
        base_url: base_url.clone(),
        model_id: model_id.clone(),
        prompt: prompt.clone(),
        stream,
        credential: None,
    };
    let result = transport.invoke(&request).await;

    // (6) receipt — typed, and emitted on BOTH paths
    let (receipt, evidence, outcome_state, http_status) = match &result {
        Ok(success) => {
            let receipt = ModelInvocationReceipt {
                model_id: model_id.clone(),
                provider: transport.transport_kind().to_string(),
                latency_ms: success.total_latency_ms,
                prompt_tokens: success.token_mix.input.map(|v| v as u32),
                completion_tokens: success.token_mix.output.map(|v| v as u32),
                total_tokens: success.token_mix.total().map(|v| v as u32),
                streaming: success.streaming,
                structured_output_schema_hash: None,
                output_hash: sha2::Sha256::digest(success.output.as_bytes()).into(),
                error_class: None,
            };
            let evidence = json!({
                "token_mix": success.token_mix.to_json(),
                "latency": {
                    "total_ms": success.total_latency_ms,
                    "first_token_ms": success.first_token_ms,
                },
                "attempts": success.attempts.iter().map(TransportAttempt::to_json).collect::<Vec<_>>(),
                "attempt_count": success.attempts.len(),
                "finish_reason": success.finish_reason,
                "streaming": success.streaming,
                "price_schedule_ref": price_schedule_ref,
                "outcome": "succeeded",
                // W4-F consumes these. Naming what is NOT collected keeps a later economic
                // comparison from reading absence as zero.
                "evidence_gaps": evidence_gaps(&success.token_mix, price_schedule_ref.is_none()),
            });
            (receipt, evidence, "succeeded", StatusCode::OK)
        }
        Err(failure) => {
            let receipt = ModelInvocationReceipt {
                model_id: model_id.clone(),
                provider: transport.transport_kind().to_string(),
                latency_ms: failure.total_latency_ms,
                prompt_tokens: None,
                completion_tokens: None,
                total_tokens: None,
                streaming: stream,
                structured_output_schema_hash: None,
                // An empty output is hashed honestly rather than left absent: the receipt states
                // that nothing was produced, and the hash proves which nothing.
                output_hash: sha2::Sha256::digest(b"").into(),
                error_class: Some(failure.error_class),
            };
            let evidence = json!({
                "token_mix": TokenMix::default().to_json(),
                "latency": { "total_ms": failure.total_latency_ms, "first_token_ms": Value::Null },
                "attempts": failure.attempts.iter().map(TransportAttempt::to_json).collect::<Vec<_>>(),
                "attempt_count": failure.attempts.len(),
                "finish_reason": Value::Null,
                "streaming": stream,
                "price_schedule_ref": price_schedule_ref,
                "outcome": "failed",
                "error_class": failure.error_class.as_str(),
                "detail": failure.detail,
                "evidence_gaps": evidence_gaps(&TokenMix::default(), price_schedule_ref.is_none()),
            });
            (receipt, evidence, "failed", StatusCode::BAD_GATEWAY)
        }
    };

    let receipt_json = match serde_json::to_value(&receipt) {
        Ok(value) => value,
        Err(error) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "model_invocation_receipt_unserializable",
                error.to_string(),
            )
        }
    };

    // The admitted payload carries no clock and no head — a wall-clock field makes every retry
    // byte-different and silently defeats replay.
    let admitted = json!({
        "schema_version": SCHEMA_VERSION,
        "invocation_id": invocation_id,
        "owner_ref": caller.owner_ref,
        "acting_principal_ref": acting_principal_ref,
        "route_id": id,
        "route_ref": route_ref,
        "transport": transport.transport_kind(),
        "model_id": model_id,
        "base_url": base_url,
        "prompt_hash": format!("sha256:{}", digest_hex(prompt.as_bytes())),
        "outcome": outcome_state,
        "attempts_this_cut": ATTEMPTS_THIS_CUT,
        "model_invocation_receipt": receipt_json,
        "evidence": evidence,
    });

    let commit: MutationCommit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        INVOCATION_NAMESPACE,
        KIND_INVOCATION,
        &format!("model-invocation://{invocation_id}"),
        "model_invocation.executed",
        None,
        &admitted,
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };

    let mut record = admitted.clone();
    record["admitted_head"] = json!(commit.projection.head);
    record["recorded_at"] = json!(super::iso_now());
    if persist_record(&st.data_dir, KIND_INVOCATION, &invocation_id, &record).is_err() {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "model_invocation_persistence_failed",
            "the invocation is admitted but its projection could not be written; replay to reconcile",
        );
    }

    (
        http_status,
        Json(json!({ "ok": outcome_state == "succeeded", "invocation": record })),
    )
}

/// Name every W4-F field this invocation could not supply. An economic comparison that cannot see
/// its own gaps will read them as zeros.
fn evidence_gaps(mix: &TokenMix, price_schedule_missing: bool) -> Vec<String> {
    let mut gaps: Vec<String> = mix
        .unreported()
        .into_iter()
        .map(|field| format!("token_mix.{field}"))
        .collect();
    if price_schedule_missing {
        gaps.push("price_schedule_ref".to_string());
    }
    // Named residual, visible in every record rather than only in a ledger row: this cut observes
    // and receipts, but does not yet join to the economics ledger.
    gaps.push("economics.usage_record".to_string());
    gaps
}

/// GET /v1/hypervisor/model-invocations/:id — readback of one admitted invocation.
///
/// Identity resolves BEFORE the record is read: an anonymous caller is owed 401 rather than a 404
/// that would answer "does this id exist?" for free.
pub(crate) async fn handle_model_invocation_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(refusal) => return scope_refusal_reply(refusal),
    };
    let Some(record) = load_invocation(&st.data_dir, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "model_invocation_not_found",
            "no model invocation exists at this id",
        );
    };
    let tenant_authorized = record["owner_ref"]
        .as_str()
        .is_some_and(|owner_ref| identity.authorizes_tenant(owner_ref));
    if !tenant_authorized {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceScopeRequired,
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "invocation": record })),
    )
}
