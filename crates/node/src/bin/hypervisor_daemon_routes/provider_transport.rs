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
//!   * credential custody — `lifecycle_routes::authorize_capability_lease` is THE crossing, and
//!     this module CONSUMES it rather than reimplementing it. A credentialed route resolves its
//!     sealed provider key through the gateway, presents the bearer once, and drops it. There is no
//!     process-environment path here and never was: the boot-time `resolve_inference` singleton is
//!     a separate, now dev-posture-gated lane that this module does not touch.
//!   * retry and fallback DECISIONS — a transport classifies an error as retryable; only the router
//!     decides whether to retry. This cut performs exactly one attempt and says so in the record.
//!   * billing — the transport reports what it OBSERVED; the economics ledger owns what it COST.
//!     The join below hands the ledger an observed quantity and lets it price, sequence, hash-chain
//!     and refuse on its own terms. This module computes no rate, no charge, and no total: it does
//!     not know what anything costs and must never learn.
//!   * spend authorization — a `UsageRecord` records work done, and a `FinalDebit` spends. The
//!     latter still demands a live grant through `require_spend_authority`, which this cut does not
//!     touch. No quantity of usage ever becomes an authority to debit.
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

use super::lifecycle_routes::AuthorizedCapabilityLease;

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
    /// What the provider METERED before the call failed. Suppliers bill failed attempts: a request
    /// that consumed input tokens and then hit a content filter, a stream that emitted tokens and
    /// then stalled. Where the provider reports those counts they are real usage and the economics
    /// join must see them, so this field exists on the failure path and not only on success.
    ///
    /// Empty here means the provider reported nothing, which is a typed gap — never an assertion
    /// that the failed call was free. `OllamaTransport` reports a mix only on a `done` frame, so
    /// every failure it produces today leaves this default; the field carries the SHAPE the second
    /// transport needs rather than waiting to be retrofitted after a dialect that meters failures.
    pub token_mix: TokenMix,
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
                    // Nothing reached the provider, so nothing was metered.
                    token_mix: TokenMix::default(),
                    detail: error.to_string(),
                });
            }
        };

        let status = response.status().as_u16();
        if !response.status().is_success() {
            let (class, retryable) = Self::classify_status(status);
            let latency = started.elapsed().as_millis() as u64;
            // The upstream error body is HASHED, never stored verbatim. A destination the daemon
            // was pointed at can reflect the request's `Authorization: Bearer <key>` header straight
            // back in its 4xx body — and this `detail` is admitted into the hash-chained, non-
            // redactable event stream and returned to the caller. Storing the raw body would put a
            // leased provider key into permanent storage on the say-so of whatever host answered.
            // The status, byte length, and a digest are enough to correlate and compare failures
            // without ever making the content durable. (Adversarial review, finding #2.)
            let raw = response.text().await.unwrap_or_default();
            let detail = format!(
                "upstream HTTP {status}: {} body bytes, sha256:{}",
                raw.len(),
                digest_hex(raw.as_bytes())
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
                // Ollama reports no counts on an error status. A dialect that DOES report them on a
                // 4xx populates this instead; zero-filling it here would bill the caller nothing for
                // input the provider charged for.
                token_mix: TokenMix::default(),
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
                        token_mix: TokenMix::default(),
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
                        // The body did not parse, so no counts could be read out of it.
                        token_mix: TokenMix::default(),
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
                    // Whatever the stream already reported travels with the failure. A `done` frame
                    // followed by a stall is a metered call that did not complete, and the provider
                    // bills it: carrying the mix here is what lets the join charge for it.
                    token_mix: mix.clone(),
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
                    token_mix: mix.clone(),
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

// ---------------------------------------------------------------- the economics join

/// What a caller may say about billing, and nothing more. Two refs — WHICH quote to charge and
/// under WHICH quoted posture — both of which the ledger independently re-authorizes.
///
/// What is deliberately absent is the point: there is no field here for a quantity, a meter class,
/// a rate, or a receipt ref. A caller who can name their own token count can name their own bill,
/// so the quantity reaches the ledger only as a `u64` this module OBSERVED at the wire. This is the
/// same rule INV-37 applies to WHO, applied to HOW MUCH.
struct EconomicsRequest {
    quote_ref: String,
    commercial_posture: String,
}

/// Fields that describe a charge rather than name a billing target. Accepting any of them would
/// make the ledger's own server-derivation guarantees reachable from a request body.
const CLIENT_SETTABLE_CHARGE_FIELDS: &[&str] = &[
    "quantity_units",
    "meter_class",
    "runtime_receipt_refs",
    "charged_work_credits",
    "rate_work_credit_micro_units_per_meter_unit",
    "cost_breakdown",
    "sequence",
];

/// SHAPE ONLY — a pure function of the request, so it is reachable (and therefore provable) without
/// a reachable provider. Whether the named quote actually RESOLVES for this caller is world state
/// and is answered later by the ledger's own resolver, once the route itself is known executable.
fn parse_economics_request(body: &Value) -> Result<Option<EconomicsRequest>, Reply> {
    let Some(raw) = body.get("economics") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    let Some(object) = raw.as_object() else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "model_invocation_economics_invalid",
            "economics must be an object naming the quote this invocation bills against",
        ));
    };
    if let Some(field) = CLIENT_SETTABLE_CHARGE_FIELDS
        .iter()
        .find(|field| object.contains_key(**field))
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "model_invocation_economics_quantity_not_client_settable",
            format!(
                "economics.{field} is derived from the observed invocation, never accepted from a caller: \
                 the quantity charged is the token mix this daemon read off the provider response"
            ),
        ));
    }
    let field = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let quote_ref = field("quote_ref");
    if quote_ref.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "model_invocation_economics_quote_ref_required",
            "economics.quote_ref is required: a charge binds to exactly one quote",
        ));
    }
    let commercial_posture = field("commercial_posture");
    if commercial_posture.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "model_invocation_economics_posture_required",
            "economics.commercial_posture is required and must be one the quote allows",
        ));
    }
    Ok(Some(EconomicsRequest {
        quote_ref,
        commercial_posture,
    }))
}

/// The join, run AFTER the invocation is admitted.
///
/// ORDER IS LOAD-BEARING and the alternative was considered and rejected. Appending usage first
/// would let the invocation's own admission fail behind it, leaving a charge whose
/// `runtime_receipt_refs` names a record that does not exist — precisely the unauditable charge the
/// ledger refuses at `economics_usage_evidence_required`. Admitting first can instead leave an
/// invocation whose join did not land, which this function reports as a TYPED GAP on the record
/// rather than silence. An orphan charge is a lie; a named gap is not.
///
/// NEVER SYNTHESIZES. Every path that cannot produce a real quantity returns `joined: false` with a
/// reason code. There is no branch here that writes a zero.
fn join_economics(
    data_dir: &str,
    caller: &WriteCaller,
    request: Option<&EconomicsRequest>,
    observed: &TokenMix,
    invocation_ref: &str,
    outcome_state: &str,
) -> Value {
    let Some(request) = request else {
        return json!({
            "joined": false,
            "reason_code": "economics_join_not_requested",
            "gap": "economics.usage_record",
            "message": "this invocation named no quote, so it is metered nowhere; W4-F reads this as an absent cost, never a zero one",
        });
    };
    // A mix the provider did not report cannot become a quantity. Failed invocations reach here on
    // the same terms as successful ones: where the provider metered the failed attempt the charge
    // is real and lands, and where it reported nothing the gap is named.
    let Some(quantity) = observed.total() else {
        return json!({
            "joined": false,
            "reason_code": "economics_join_token_mix_absent",
            "gap": "economics.usage_record",
            "quote_ref": request.quote_ref,
            "unreported": observed.unreported(),
            "outcome": outcome_state,
            "message": "the provider reported no usable token mix, so no quantity exists to charge; \
                        a zero-quantity row would read as a free call rather than an unmeasured one",
        });
    };
    match super::economics_routes::append_model_token_usage(
        data_dir,
        caller,
        &request.quote_ref,
        &request.commercial_posture,
        quantity,
        &[invocation_ref.to_string()],
    ) {
        Ok((usage, chain_length)) => json!({
            "joined": true,
            "usage_ref": usage["usage_ref"],
            "quote_ref": request.quote_ref,
            "chain_ref": super::economics_routes::usage_chain_ref_for(&request.quote_ref),
            "chain_length": chain_length,
            "sequence": usage["sequence"],
            "meter_class": super::economics_routes::METER_MODEL_TOKENS,
            "commercial_posture": request.commercial_posture,
            "quantity_units": quantity,
            // Say what the number MEANS. `model_tokens` prices one meter unit, and this cut charges
            // input+output. Cache and reasoning classes are reported by no transport yet; folding
            // an unreported class in as zero would understate a bill, and inventing a second meter
            // class the rate card does not price would refuse at admission.
            "quantity_basis": "token_mix.input + token_mix.output (observed); cache and reasoning classes are unreported by this transport and are folded in nowhere",
            "charged_work_credits": usage["charged_work_credits"],
            "rate_work_credit_micro_units_per_meter_unit": usage["rate_work_credit_micro_units_per_meter_unit"],
            "runtime_receipt_ref": invocation_ref,
            // The ledger charged the work; it did not authorize a spend. A FinalDebit still demands
            // a live grant through require_spend_authority, and no usage row weakens that.
            "authorizes_spend": false,
        }),
        Err((status, Json(refusal))) => json!({
            "joined": false,
            "reason_code": "economics_join_refused",
            "gap": "economics.usage_record",
            "quote_ref": request.quote_ref,
            "quantity_units_observed": quantity,
            "refusal_status": status.as_u16(),
            // The ledger's own refusal, verbatim. Re-wording it here would mint a second vocabulary
            // for the same condition.
            "refusal": refusal,
        }),
    }
}

// ---------------------------------------------------------------- credential custody

/// Resolve a route's provider credential through THE authority crossing, or establish that it needs
/// none. Returns the lease still holding its bearer, plus the non-secret labels that go on the
/// record.
///
/// This function is the whole of Leg 2's claim, so what it must NOT do is worth stating: it never
/// reads a process environment variable, never falls back to another route's credential, and never
/// proceeds when the credential fails to resolve. The gateway's own refusals — 428 when the sealed
/// credential will not open, 403 with a wallet challenge when no live grant is presented — are
/// returned VERBATIM. Re-wording them here would mint a second vocabulary for an authority
/// decision this module does not own.
///
/// `no_credentials_required` is the registry's default for an ollama route and is the only posture
/// that legitimately reaches a provider with no crossing behind it. It is answered here rather than
/// at the call site so there is exactly one place that decides whether a crossing is owed.
#[allow(clippy::too_many_arguments)]
async fn resolve_route_credential(
    st: &Arc<DaemonState>,
    route_id: &str,
    credential_posture: &str,
    base_url: &str,
    model_id: &str,
    credential_binding: &Value,
    body: &Value,
) -> Result<(Option<AuthorizedCapabilityLease>, Value), Reply> {
    // CUSTODY PRESENCE decides the crossing, not the posture STRING. A sealed credential in
    // custody forces the wallet crossing even if the posture field says `no_credentials_required` —
    // so a route that somehow reaches this point with a bound key and a downgraded posture cannot
    // execute with no lease, no grant, and no receipt. The posture string is a hint about what a
    // route WANTS; the sealed record is the fact about what it HAS, and authority keys off the fact.
    let has_sealed_custody =
        credential_binding.get("kind").and_then(Value::as_str) == Some("sealed_capability_lease");
    if credential_posture == "no_credentials_required" && !has_sealed_custody {
        return Ok((
            None,
            json!({
                "crossing": "none_required",
                "credential_posture": credential_posture,
                "reason": "the route declares no credential and holds none; nothing is presented to the provider",
            }),
        ));
    }
    // A route that names or holds a credential but has nothing sealed behind it is refused BEFORE
    // the wallet crossing. The gateway would answer 428 for the same condition, but only after
    // consuming a grant use to get there — and an operator who simply has not bound a key should not
    // pay owner authority to be told so.
    if !has_sealed_custody {
        return Err(bad(
            StatusCode::PRECONDITION_REQUIRED,
            "model_route_credential_unbound",
            format!(
                "route credential posture '{credential_posture}' names a provider credential, but none is sealed into \
                 route custody. Bind one with POST /v1/hypervisor/model-routes/{route_id}/credential; this transport \
                 will not read a provider key from the process environment"
            ),
        ));
    }

    let lease_request = super::lifecycle_routes::CapabilityLeaseRequest {
        authority_provider_ref: "wallet.network".to_string(),
        backing_provider: format!("model-route:{route_id}"),
        allowed_tools: vec!["model.invoke".to_string()],
        resource_refs: vec![format!("model-route:{route_id}")],
        scopes: vec!["model.invoke".to_string()],
        policy_domain: "hypervisor.model-route.invoke.policy.v1".to_string(),
        request_domain: "hypervisor.model-route.invoke.request.v1".to_string(),
        // THE DESTINATION IS BOUND INTO THE CROSSING, and that is load-bearing, not cosmetic.
        //
        // `capability_lease_request_hash` folds `request_facets` into the hash a wallet grant is
        // approved against. If the facets named only the route id, a grant approved for "invoke
        // route R" would stay valid after R's `base_url` was repointed — so an owner's ordinary,
        // already-approved grant would ship the sealed provider key to whatever host the route now
        // names. Binding `base_url` and `model_id` here means a repointed route no longer matches
        // the grant that was approved for the original destination: the crossing refuses, and the
        // owner is forced to approve a NEW grant that names the new host. (An adversarial review
        // caught this; the first cut bound only the route id.)
        //
        // The PROMPT is still deliberately absent: folding it in would make every invocation a
        // distinct crossing needing its own grant — a per-prompt approval treadmill rather than a
        // bounded authority to use a route against a fixed destination.
        request_facets: json!({
            "route_id": route_id,
            "credential_posture": credential_posture,
            "base_url": base_url,
            "model_id": model_id,
        }),
        credential_connector_id: Some(route_id.to_string()),
        credential_store: super::model_routes::CREDENTIAL_DIR.to_string(),
        credential_required: true,
        // Model routes have no host-credential fallback. A route either presents its OWN sealed
        // credential or it does not execute — borrowing another family's token would make the
        // receipt's credential_source a fiction.
        github_host_fallback: false,
        receipt_required: true,
        revocation_ref: format!("model-routes/{route_id}/credential"),
        authority_reason: "model_route_invocation_authority_required".to_string(),
        grant_value: body
            .get("wallet_approval_grant")
            .cloned()
            .unwrap_or(Value::Null),
    };

    match super::lifecycle_routes::authorize_capability_lease(st, &lease_request).await {
        Err((status, challenge)) => Err((status, Json(challenge))),
        Ok(lease) => {
            let descriptor = &lease.descriptor;
            let projection = json!({
                "crossing": "capability_lease",
                "credential_posture": credential_posture,
                "lease_id": descriptor.get("lease_id"),
                "lease_ref": descriptor.get("lease_id").and_then(Value::as_str)
                    .map(|id| json!(format!("capability-lease://{id}"))).unwrap_or(Value::Null),
                "grant_ref": lease.grant_ref,
                "backing_provider": descriptor.get("backing_provider"),
                "allowed_tools": descriptor.get("allowed_tools"),
                "policy_hash": descriptor.get("policy_hash"),
                "request_hash": descriptor.get("request_hash"),
                "revocation_ref": descriptor.get("revocation_ref"),
                // Labels describing WHERE the bearer came from, never the bearer.
                "credential_source": lease.credential_source,
                "credential_key_source": lease.credential_key_source,
                "credential_material": false,
            });
            Ok((Some(lease), projection))
        }
    }
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
    // Request SHAPE before world state, for the same reason the prompt is checked here: a
    // malformed billing block is the caller's own error and is answerable without consulting the
    // registry, the provider, or the ledger. It is also the only part of the join reachable on a
    // machine with no model provider, which is what makes it CI-provable rather than a claim.
    let economics_request = match parse_economics_request(&body) {
        Ok(request) => request,
        Err(response) => return response,
    };

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

    let credential_posture = route
        .get("credential_posture")
        .and_then(Value::as_str)
        .unwrap_or("no_credentials_required")
        .to_string();

    // (4) billing PREFLIGHT — resolve the named quote BEFORE spending a provider call.
    //
    // The ledger's own resolver answers this, not a copy of its rules: a quote that does not
    // resolve, is not this caller's, has expired, does not allow the named posture, or whose rate
    // card does not price `model_tokens` refuses HERE, verbatim, while refusing is still free. The
    // append after execution runs the same resolver, so a preflight that passes and an append that
    // then refuses cannot disagree about the rules — only about elapsed time.
    if let Some(request) = economics_request.as_ref() {
        if let Err(response) = super::economics_routes::resolve_usage_target(
            &st.data_dir,
            &caller,
            &request.quote_ref,
            super::economics_routes::METER_MODEL_TOKENS,
            &request.commercial_posture,
            super::economics_routes::now_ms(),
        ) {
            return response;
        }
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

    // (5) credential custody — THE authority crossing, and it runs LAST among the checks.
    //
    // Ordering is a correctness property, not tidiness. `authorize_capability_lease` atomically
    // CONSUMES one wallet-owned use of the owner's grant. Every refusal that a pure read can
    // discover — unknown route, unimplemented transport, unprobed availability, an unresolvable
    // quote — therefore has to happen before it, or a caller's own request error silently spends
    // owner authority they cannot get back.
    let (mut credential_lease, credential_projection) = match resolve_route_credential(
        &st,
        &id,
        &credential_posture,
        &base_url,
        &model_id,
        route.get("credential_binding").unwrap_or(&Value::Null),
        &body,
    )
    .await
    {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };

    // (6) execution
    let transport = OllamaTransport;
    let price_schedule_ref = transport.price_schedule_ref(&route);
    let request = TransportRequest {
        base_url: base_url.clone(),
        model_id: model_id.clone(),
        prompt: prompt.clone(),
        stream,
        // The bearer MOVES out of the lease and into the one request that uses it. It is never
        // cloned, so there is exactly one copy in the process, and it dies with `request` below.
        credential: credential_lease
            .as_mut()
            .and_then(|lease| lease.token.take()),
    };
    let result = transport.invoke(&request).await;
    // Explicit, immediately after the only call that needs it. The bearer is not in the receipt,
    // not in the admitted payload, and not in the projection — `credential_projection` carries
    // lease labels only, exactly as the connector-session crossing does.
    drop(request);
    drop(credential_lease);

    // (6) receipt — typed, and emitted on BOTH paths
    let (receipt, evidence, outcome_state, http_status, observed_mix) = match &result {
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
            (
                receipt,
                evidence,
                "succeeded",
                StatusCode::OK,
                success.token_mix.clone(),
            )
        }
        Err(failure) => {
            let receipt = ModelInvocationReceipt {
                model_id: model_id.clone(),
                provider: transport.transport_kind().to_string(),
                latency_ms: failure.total_latency_ms,
                // Whatever the provider METERED before it failed. `None` where it reported nothing,
                // which is the ordinary case for this transport; a supplier that bills a failed
                // attempt reports counts here and they reach the receipt and the ledger alike.
                prompt_tokens: failure.token_mix.input.map(|v| v as u32),
                completion_tokens: failure.token_mix.output.map(|v| v as u32),
                total_tokens: failure.token_mix.total().map(|v| v as u32),
                streaming: stream,
                structured_output_schema_hash: None,
                // An empty output is hashed honestly rather than left absent: the receipt states
                // that nothing was produced, and the hash proves which nothing.
                output_hash: sha2::Sha256::digest(b"").into(),
                error_class: Some(failure.error_class),
            };
            let evidence = json!({
                "token_mix": failure.token_mix.to_json(),
                "latency": { "total_ms": failure.total_latency_ms, "first_token_ms": Value::Null },
                "attempts": failure.attempts.iter().map(TransportAttempt::to_json).collect::<Vec<_>>(),
                "attempt_count": failure.attempts.len(),
                "finish_reason": Value::Null,
                "streaming": stream,
                "price_schedule_ref": price_schedule_ref,
                "outcome": "failed",
                "error_class": failure.error_class.as_str(),
                "detail": failure.detail,
                "evidence_gaps": evidence_gaps(&failure.token_mix, price_schedule_ref.is_none()),
            });
            (
                receipt,
                evidence,
                "failed",
                StatusCode::BAD_GATEWAY,
                failure.token_mix.clone(),
            )
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
        // Which custody answered for this call, in labels. A reader can resolve the lease, the
        // grant it was issued under, and the surface that revokes it — and can resolve no secret.
        "credential": credential_projection,
        "prompt_hash": format!("sha256:{}", digest_hex(prompt.as_bytes())),
        "outcome": outcome_state,
        "attempts_this_cut": ATTEMPTS_THIS_CUT,
        "model_invocation_receipt": receipt_json,
        "evidence": evidence,
    });

    // The ref the invocation is ADMITTED under is the same string the charge cites as its runtime
    // evidence. Deriving the join key from the admission ref rather than re-spelling it is what
    // makes "the key resolves both ways" a property of the code and not of a convention.
    let invocation_ref = format!("model-invocation://{invocation_id}");
    let commit: MutationCommit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        INVOCATION_NAMESPACE,
        KIND_INVOCATION,
        &invocation_ref,
        "model_invocation.executed",
        None,
        &admitted,
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };

    // (7) the economics join — after admission, so the charge can cite a receipt that EXISTS.
    //
    // It lands on the projection beside `admitted_head` and `recorded_at`, the other two facts that
    // are only knowable after admission. The admitted payload stays the pre-join transport
    // observation and is not rewritten; the usage append is durably evented by the economics
    // stream, which is its own owner. One fact, one owner: `evidence.evidence_gaps` names what the
    // TRANSPORT could not observe, and `economics` names whether the charge landed.
    let mut record = admitted.clone();
    record["admitted_head"] = json!(commit.projection.head);
    record["recorded_at"] = json!(super::iso_now());
    record["economics"] = join_economics(
        &st.data_dir,
        &caller,
        economics_request.as_ref(),
        &observed_mix,
        &invocation_ref,
        outcome_state,
    );
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

/// Name every W4-F field THIS TRANSPORT could not observe at the wire. An economic comparison that
/// cannot see its own gaps will read them as zeros.
///
/// Scope changed when the economics join landed. This list used to also carry
/// `economics.usage_record` unconditionally, which was correct while no invocation could ever be
/// metered — and would now be a lie on every metered call. Whether the charge landed is answered by
/// the record's `economics` block, which is the only owner of that fact; a gap list that guessed at
/// it would be a second, staler answer to the same question.
fn evidence_gaps(mix: &TokenMix, price_schedule_missing: bool) -> Vec<String> {
    let mut gaps: Vec<String> = mix
        .unreported()
        .into_iter()
        .map(|field| format!("token_mix.{field}"))
        .collect();
    if price_schedule_missing {
        gaps.push("price_schedule_ref".to_string());
    }
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
