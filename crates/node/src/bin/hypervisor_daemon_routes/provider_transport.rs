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
//!     decides whether to retry. The router now exists (see `decide_after_failure`): it may
//!     re-attempt one route up to a caller-authorized bound, and it may move to a caller-DECLARED
//!     fallback route. Every attempt is its own authority crossing, and the lineage records which
//!     route each attempt hit and what was decided about it.
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
    /// Add another attempt's observed counts into this one.
    ///
    /// `None` means UNREPORTED, never zero — the distinction the whole meter is built on. So a
    /// class stays `None` until some attempt reports it, and thereafter accumulates only what was
    /// actually observed: an attempt that reported nothing contributes nothing rather than being
    /// counted as a zero. The sum is therefore what the provider TOLD us it metered across the
    /// invocation, which is exactly what the ledger is entitled to charge.
    fn accumulate(&mut self, other: &TokenMix) {
        fn add(into: &mut Option<u64>, value: Option<u64>) {
            if let Some(value) = value {
                *into = Some(into.unwrap_or(0).saturating_add(value));
            }
        }
        add(&mut self.input, other.input);
        add(&mut self.output, other.output);
        add(&mut self.cache_read, other.cache_read);
        add(&mut self.cache_write, other.cache_write);
        add(&mut self.reasoning, other.reasoning);
    }

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

// ---------------------------------------------------------------- the second native conformer

/// The OpenAI-compatible dialect — the FIRST transport to conform to a contract it did not define.
///
/// WHY THIS ONE IS THE PROOF. `OllamaTransport` defined the `ProviderTransport` shape by being the
/// only implementation, so nothing yet showed whether that shape generalizes or had simply been
/// fitted to one provider. This dialect differs from Ollama's in every mechanical way that matters —
/// SSE frames rather than NDJSON, `usage` rather than `*_eval_count`, an HTTP error envelope with a
/// typed `error.code`, and cache/reasoning token classes Ollama has no concept of — and it required
/// NO change to the trait, the receipt, the attempt lineage, or the economics join. That is the
/// native-first gate the absorption ruling names: only after a second native conformer proves the
/// contract generalizes does adapted-transport work become eligible.
///
/// ANTI-EXFILTRATION, UNCHANGED. The PROBE for this transport stays posture-only — the daemon never
/// sends a credential to a caller-supplied `base_url` to discover a catalog. This type performs the
/// EXECUTION only, and it is reached solely through the Leg-2 CapabilityLease crossing.
pub(crate) struct OpenAiCompatibleTransport;

impl OpenAiCompatibleTransport {
    /// Transport-level (pre-response) failures.
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

    /// HTTP status → kernel class. The dialect's own `error.code` refines a 400, because
    /// "context_length_exceeded" and "invalid_request_error" are different operator problems and
    /// flattening both to one class would erase which.
    ///
    /// TYPED TAXONOMY GAP, named rather than papered over: the kernel's `ModelRuntimeErrorClass` has
    /// no AUTHENTICATION class. A 401/403 is an authorization refusal by the provider, so it maps to
    /// `PolicyRefusal` — the nearest true class — and the detail says it was an auth refusal. Adding
    /// a kernel variant is a wider change than this cut owns; the residual is recorded.
    fn classify_status(status: u16, code: Option<&str>) -> (ModelRuntimeErrorClass, bool) {
        match status {
            401 | 403 => (ModelRuntimeErrorClass::PolicyRefusal, false),
            404 => (ModelRuntimeErrorClass::ProviderUnavailable, false),
            408 => (ModelRuntimeErrorClass::Timeout, true),
            429 => (ModelRuntimeErrorClass::RateLimited, true),
            413 => (ModelRuntimeErrorClass::ContextOverflow, false),
            400 | 422 => match code {
                Some(c) if c.contains("context_length") || c.contains("context_window") => {
                    (ModelRuntimeErrorClass::ContextOverflow, false)
                }
                Some(c) if c.contains("content_filter") || c.contains("content_policy") => {
                    (ModelRuntimeErrorClass::SafetyRefusal, false)
                }
                _ => (ModelRuntimeErrorClass::MalformedStructuredOutput, false),
            },
            500..=599 => (ModelRuntimeErrorClass::ProviderUnavailable, true),
            _ => (ModelRuntimeErrorClass::UnknownProviderError, false),
        }
    }

    /// A `finish_reason` the provider reports as a refusal is NOT a success with short output.
    fn finish_reason_refusal(reason: Option<&str>) -> Option<ModelRuntimeErrorClass> {
        match reason {
            Some("content_filter") => Some(ModelRuntimeErrorClass::SafetyRefusal),
            _ => None,
        }
    }
}

/// `usage` in this dialect. Cache and reasoning classes live in OPTIONAL detail objects that most
/// servers omit entirely — so they read as `None` (a typed gap) rather than zero, exactly as the
/// honesty rule requires. A server that does report them is captured without a code change.
fn openai_token_mix(usage: &Value) -> TokenMix {
    TokenMix {
        input: usage.get("prompt_tokens").and_then(Value::as_u64),
        output: usage.get("completion_tokens").and_then(Value::as_u64),
        cache_read: usage
            .pointer("/prompt_tokens_details/cached_tokens")
            .and_then(Value::as_u64),
        // No mainstream server reports a cache WRITE count on this dialect; it stays a typed gap
        // rather than being inferred from anything.
        cache_write: None,
        reasoning: usage
            .pointer("/completion_tokens_details/reasoning_tokens")
            .and_then(Value::as_u64),
    }
}

impl ProviderTransport for OpenAiCompatibleTransport {
    fn transport_kind(&self) -> &'static str {
        "openai_compatible"
    }

    async fn invoke(
        &self,
        request: &TransportRequest,
    ) -> Result<TransportOutcome, TransportFailure> {
        let started = Instant::now();
        // The registry stores the provider ROOT (normalize_base_url strips a trailing /v1), so the
        // dialect's path is re-appended here rather than assumed to be on the stored value.
        let url = format!(
            "{}/v1/chat/completions",
            request.base_url.trim_end_matches('/')
        );
        let mut body = json!({
            "model": request.model_id,
            "messages": [{ "role": "user", "content": request.prompt }],
            "stream": request.stream,
        });
        if request.stream {
            // Without this most servers omit `usage` entirely on a streamed response — and an absent
            // mix means no economics join. Asking for it is how a streamed call stays billable.
            body["stream_options"] = json!({ "include_usage": true });
        }

        let client = reqwest::Client::new();
        let mut builder = client
            .post(&url)
            .timeout(Duration::from_millis(INVOKE_TIMEOUT_MS))
            .json(&body);
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
                    token_mix: TokenMix::default(),
                    detail: error.to_string(),
                });
            }
        };

        let status = response.status().as_u16();
        if !response.status().is_success() {
            let raw = response.text().await.unwrap_or_default();
            // The dialect's typed error code is READ to classify, and then only the CODE travels
            // into the record. The body itself is hashed: a destination can reflect the request's
            // Authorization header in its error text, and this detail is admitted into the
            // hash-chained event stream.
            let parsed: Option<Value> = serde_json::from_str(&raw).ok();
            let code = parsed
                .as_ref()
                .and_then(|v| v.pointer("/error/code"))
                .and_then(Value::as_str)
                .or_else(|| {
                    parsed
                        .as_ref()
                        .and_then(|v| v.pointer("/error/type"))
                        .and_then(Value::as_str)
                })
                .map(str::to_string);
            let (class, retryable) = Self::classify_status(status, code.as_deref());
            let latency = started.elapsed().as_millis() as u64;
            let detail = format!(
                "upstream HTTP {status}{}: {} body bytes, sha256:{}",
                code.as_deref()
                    .map(|c| format!(" ({c})"))
                    .unwrap_or_default(),
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
                token_mix: TokenMix::default(),
                detail,
            });
        }

        let (output, mix, finish_reason, first_token_ms) = if request.stream {
            match read_openai_sse(response, started).await {
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
                        token_mix: TokenMix::default(),
                        detail: error.to_string(),
                    });
                }
            };
            let content = frame
                .pointer("/choices/0/message/content")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let reason = frame
                .pointer("/choices/0/finish_reason")
                .and_then(Value::as_str)
                .map(str::to_string);
            let mix = frame.get("usage").map(openai_token_mix).unwrap_or_default();
            let elapsed = started.elapsed().as_millis() as u64;
            (content, mix, reason, Some(elapsed))
        };

        // A provider-reported refusal is receipted as a FAILURE with its class, never as a short
        // success. The tokens it consumed are still real, so the observed mix travels with it and
        // the economics join can charge for work the supplier metered.
        if let Some(class) = Self::finish_reason_refusal(finish_reason.as_deref()) {
            let latency = started.elapsed().as_millis() as u64;
            let detail = format!(
                "provider refused via finish_reason '{}'",
                finish_reason.clone().unwrap_or_default()
            );
            return Err(TransportFailure {
                attempts: vec![TransportAttempt {
                    index: 0,
                    latency_ms: latency,
                    first_token_ms,
                    http_status: Some(status),
                    outcome: "failed",
                    error_class: Some(class),
                    retryable: false,
                    detail: Some(detail.clone()),
                }],
                total_latency_ms: latency,
                error_class: class,
                token_mix: mix,
                detail,
            });
        }

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

/// Read an SSE stream to completion.
///
/// Two dialect facts drive this: frames arrive as `data: {json}` lines terminated by a blank line,
/// and the stream ends with a literal `data: [DONE]` sentinel that is NOT json. A `usage` block
/// arrives on a late frame (usually the one carrying no choices), which is why the mix is taken from
/// whichever frame reports it rather than from the first or last.
async fn read_openai_sse(
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
                    // Whatever the stream already reported travels with the failure — a metered
                    // stall is still billable work.
                    token_mix: mix.clone(),
                    detail: format!("no stream frame for {STREAM_STALL_MS}ms"),
                });
            }
            Ok(None) => break,
            Ok(Some(Err(error))) => {
                let (class, retryable) = OpenAiCompatibleTransport::classify(&error);
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
            let Some(payload) = line.strip_prefix("data:") else {
                continue;
            };
            let payload = payload.trim();
            // The terminator is a sentinel, not json. Parsing it would be a decode error on a
            // perfectly healthy stream.
            if payload == "[DONE]" {
                continue;
            }
            let Ok(frame) = serde_json::from_str::<Value>(payload) else {
                continue;
            };
            if let Some(piece) = frame
                .pointer("/choices/0/delta/content")
                .and_then(Value::as_str)
            {
                if !piece.is_empty() && first_token_ms.is_none() {
                    first_token_ms = Some(started.elapsed().as_millis() as u64);
                }
                output.push_str(piece);
            }
            if let Some(reason) = frame
                .pointer("/choices/0/finish_reason")
                .and_then(Value::as_str)
            {
                finish_reason = Some(reason.to_string());
            }
            if let Some(usage) = frame.get("usage").filter(|u| !u.is_null()) {
                mix = openai_token_mix(usage);
            }
        }
    }

    Ok((output, mix, finish_reason, first_token_ms))
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

/// Dialect dispatch. The registry decides WHICH transport a route speaks; this only executes it.
///
/// The variants deliberately share every surrounding owner — the same receipt, the same attempt
/// lineage, the same economics join, the same credential crossing. A transport that needed its own
/// version of any of those would not be a transport; it would be a second spine.
pub(crate) enum ModelTransport {
    Ollama(OllamaTransport),
    OpenAiCompatible(OpenAiCompatibleTransport),
}

impl ModelTransport {
    fn for_kind(kind: &str) -> Self {
        match kind {
            "ollama" => Self::Ollama(OllamaTransport),
            // The caller has already refused any kind not in the admitted set, so this arm is
            // reached only for `openai_compatible`.
            _ => Self::OpenAiCompatible(OpenAiCompatibleTransport),
        }
    }

    fn transport_kind(&self) -> &'static str {
        match self {
            Self::Ollama(t) => t.transport_kind(),
            Self::OpenAiCompatible(t) => t.transport_kind(),
        }
    }

    fn price_schedule_ref(&self, route: &Value) -> Option<String> {
        match self {
            Self::Ollama(t) => t.price_schedule_ref(route),
            Self::OpenAiCompatible(t) => t.price_schedule_ref(route),
        }
    }

    async fn invoke(
        &self,
        request: &TransportRequest,
    ) -> Result<TransportOutcome, TransportFailure> {
        match self {
            Self::Ollama(t) => t.invoke(request).await,
            Self::OpenAiCompatible(t) => t.invoke(request).await,
        }
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

// ---------------------------------------------------------------------------
// the ROUTER — retry and fallback DECISIONS
// ---------------------------------------------------------------------------
//
// The standing separation this module was built around: a transport CLASSIFIES an error
// (`ModelRuntimeErrorClass` + `retryable`); only the router DECIDES what to do about it. Before this
// cut nothing decided, so `retryable` was a field nobody read and attempt lineage was a one-element
// list under every spelling. The types below are deliberately the router's own and not the
// transport's: a transport that could express "retry me" would be making the decision.

/// The ceiling on attempts against ONE route.
const MAX_ATTEMPTS_PER_ROUTE_CEILING: usize = 4;
/// Wall-clock ceiling across the WHOLE router loop, not per attempt.
///
/// `INVOKE_TIMEOUT_MS` bounds one provider call. Without a bound over the loop, the worst case is
/// every attempt against every target running to its own ceiling — sixteen calls holding one daemon
/// task and socket for over half an hour. The router stops starting attempts once this has elapsed
/// and records that it stopped, so an exhausted deadline is a stated outcome rather than a hang.
const ROUTER_DEADLINE_MS: u128 = 180_000;
/// Backoff before re-attempting the SAME route. A retryable failure is very often a rate limit
/// (429 classifies retryable), and answering it with immediate re-hits under the owner's key is how
/// a client turns its own throttling into a ban.
const RETRY_BACKOFF_MS: [u64; 3] = [250, 1_000, 2_500];
/// A declared fallback chain is bounded for the same reason each attempt is: every hop is a fresh
/// authority crossing.
const MAX_FALLBACK_ROUTES: usize = 3;

/// How many times the router may attempt one route.
///
/// The default is ONE attempt — retries are OFF unless the caller asks for them. That is a spend
/// ruling, not timidity: every attempt against a credentialed route mints its own CapabilityLease
/// crossing and therefore CONSUMES another wallet-owned use of the owner's grant. A router that
/// retried by default would spend owner authority the caller never asked to spend, which is the
/// class of weakening `require_spend_authority` exists to prevent.
#[derive(Clone, Copy)]
struct RetryPolicy {
    max_attempts_per_route: usize,
}

impl RetryPolicy {
    /// `retry: { max_attempts: N }`. Absent means one attempt. Above the ceiling REFUSES rather than
    /// silently clamping — a caller who asked for fifty attempts has misunderstood what an attempt
    /// costs, and quietly giving them four would hide that rather than correct it.
    fn parse(body: &Value) -> Result<Self, Reply> {
        let Some(retry) = body.get("retry") else {
            return Ok(Self {
                max_attempts_per_route: 1,
            });
        };
        // A PRESENT-BUT-UNREADABLE value refuses. `unwrap_or(1)` here silently clamped
        // `-1`, `"3"`, `3.5` and a non-object `retry` down to a single attempt — which is the very
        // clamping this refusal exists to prevent, arriving through the type system instead of
        // through the range check.
        let requested = match retry.get("max_attempts") {
            None => 1,
            Some(value) => match value.as_u64() {
                Some(parsed) => parsed as usize,
                None => 0,
            },
        };
        if requested == 0 || requested > MAX_ATTEMPTS_PER_ROUTE_CEILING {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "model_invocation_retry_policy_invalid",
                format!(
                    "retry.max_attempts must be between 1 and {MAX_ATTEMPTS_PER_ROUTE_CEILING}; each attempt against a credentialed route consumes another use of the owner's grant"
                ),
            ));
        }
        Ok(Self {
            max_attempts_per_route: requested,
        })
    }
}

/// What the router decided after one failed attempt. Recorded on the attempt itself, so the lineage
/// says why it moved on rather than leaving a reader to infer it from what happened next.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RouterDecision {
    RetrySameRoute,
    FallbackNextRoute,
    GiveUp,
}

impl RouterDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::RetrySameRoute => "retry_same_route",
            Self::FallbackNextRoute => "fallback_next_route",
            Self::GiveUp => "give_up",
        }
    }
}

/// THE DECISION. Note what it reads: the transport's `retryable` classification, the policy the
/// caller authorized, and where it stands in the target list. It never inspects the provider's
/// response body and never re-classifies the error — either would be the router quietly taking over
/// the transport's job, which is the separation this whole module is organised around.
fn decide_after_failure(
    retryable: bool,
    attempt_on_this_route: usize,
    policy: RetryPolicy,
    target_index: usize,
    target_count: usize,
) -> RouterDecision {
    if retryable && attempt_on_this_route < policy.max_attempts_per_route {
        return RouterDecision::RetrySameRoute;
    }
    // A fallback is offered for ANY exhausted route, retryable or not: a route that fails
    // non-retryably — an overflowed context, a provider that will not serve this model — is exactly
    // the case a declared alternative exists for.
    if target_index + 1 < target_count {
        return RouterDecision::FallbackNextRoute;
    }
    RouterDecision::GiveUp
}

/// One route the router may execute against, already admission-checked.
struct ExecutionTarget {
    route_id: String,
    route: Value,
    route_ref: String,
    transport_kind: String,
    base_url: String,
    model_id: String,
    credential_posture: String,
}

/// Whether invoking this route will cross the CapabilityLease gateway.
///
/// Mirrors `resolve_route_credential`'s own rule rather than restating it loosely: sealed custody
/// forces a crossing even where the posture string says otherwise, because the posture is a hint
/// about what a route WANTS and the sealed record is the fact about what it HAS.
fn route_is_credentialed(route: &Value) -> bool {
    route.get("credential_posture").and_then(Value::as_str) != Some("no_credentials_required")
        || route
            .pointer("/credential_binding/kind")
            .and_then(Value::as_str)
            == Some("sealed_capability_lease")
}

/// Admission for ONE route, applied identically to the primary and to every declared fallback.
///
/// A fallback is not a privileged path. Were these checks relaxed for backups, declaring a route as
/// a fallback would become a way to reach an unimplemented transport or an unprobed provider that
/// the primary path refuses outright.
fn admit_execution_target(route_id: &str, route: Value) -> Result<ExecutionTarget, Reply> {
    let transport_kind = route
        .pointer("/provider_binding/transport")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let lifecycle = route
        .pointer("/lifecycle/status")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let availability = route
        .pointer("/availability/state")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    // Transport support is checked BEFORE availability, deliberately. A route whose transport has no
    // implementation can never execute no matter how healthy its provider is, so answering "not
    // executable (availability)" would name the wrong blocker.
    if !matches!(transport_kind.as_str(), "ollama" | "openai_compatible") {
        return Err(bad(
            StatusCode::NOT_IMPLEMENTED,
            "provider_transport_unimplemented",
            format!(
                "transport '{transport_kind}' has no admitted ProviderTransport implementation"
            ),
        ));
    }
    // WHAT COUNTS AS EXECUTABLE DIFFERS BY TRANSPORT, because what a PROBE can honestly learn
    // differs by transport. Ollama's probe reads a real catalog, so `available` means the model is
    // actually served. The openai_compatible probe is deliberately POSTURE-ONLY — the daemon never
    // sends a credential to a caller-supplied base_url to discover a catalog — so the strongest
    // honest state it reaches is `credentials_present`.
    let executable_availability: &[&str] = match transport_kind.as_str() {
        "ollama" => &["available"],
        _ => &["credentials_present"],
    };
    if lifecycle != "active" || !executable_availability.contains(&availability.as_str()) {
        return Err(bad(
            StatusCode::CONFLICT,
            "model_route_not_executable",
            format!(
                "route lifecycle '{lifecycle}' / availability '{availability}' is not an executable pair for transport '{transport_kind}' (expected one of {executable_availability:?}); probe the route first"
            ),
        ));
    }
    Ok(ExecutionTarget {
        route_id: route_id.to_string(),
        route_ref: route
            .get("route_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        base_url: route
            .pointer("/provider_binding/base_url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        model_id: route
            .pointer("/model/model_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        credential_posture: route
            .get("credential_posture")
            .and_then(Value::as_str)
            .unwrap_or("no_credentials_required")
            .to_string(),
        transport_kind,
        route,
    })
}

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
    // (3a) OWNERSHIP. Invoking is the operation that actually SPENDS a route: it contacts the
    // destination the owner configured, and on a credentialed route it resolves that owner's sealed
    // provider key. A registry that decides who may CONFIGURE a route and not who may USE it has
    // drawn the boundary in the wrong place, so the same gate the mutation surface uses applies
    // here — before any provider contact, credential resolution, or ledger charge.
    if let Err((status, body)) = super::model_routes::authorize_route_owner_for_headers(
        &st.data_dir,
        &headers,
        &id,
        &route,
        "invoke",
    ) {
        return (status, body);
    }
    // (3b) THE ROUTER'S TARGET LIST — explicit, never inferred.
    //
    // Fallbacks are DECLARED by the caller, never chosen by this daemon from the registry. Inferring
    // them would mint a placement policy beside the ones the estate already owns (the venue picker,
    // the improvement-governance gates, W4-F's advisory economics) — a second switching mechanism,
    // which the one structural law forbids. W4-F's own ruling is explicit that economic comparison
    // "neither grants route rights nor independently authorizes placement"; a router that picked its
    // own alternates would be doing exactly that, one layer down and unreviewed.
    let policy = match RetryPolicy::parse(&body) {
        Ok(policy) => policy,
        Err(response) => return response,
    };
    let mut declared: Vec<(String, Value)> = vec![(id.clone(), route.clone())];
    if let Some(declared_refs) = body.get("fallback_route_refs") {
        let Some(list) = declared_refs.as_array() else {
            return bad(
                StatusCode::BAD_REQUEST,
                "model_invocation_fallback_routes_invalid",
                "fallback_route_refs must be an array of model-route refs",
            );
        };
        if list.len() > MAX_FALLBACK_ROUTES {
            return bad(
                StatusCode::BAD_REQUEST,
                "model_invocation_fallback_routes_invalid",
                format!(
                    "at most {MAX_FALLBACK_ROUTES} fallback routes may be declared; each hop is its own authority crossing"
                ),
            );
        }
        for entry in list {
            let Some(reference) = entry
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return bad(
                    StatusCode::BAD_REQUEST,
                    "model_invocation_fallback_routes_invalid",
                    "each fallback_route_refs entry must be a non-empty model-route ref",
                );
            };
            let fallback_id = reference
                .strip_prefix("model-route:")
                .unwrap_or(reference)
                .to_string();
            // A repeated route is refused rather than silently deduplicated: a caller who listed the
            // primary again is asking for retries and should say so through `retry`, where the cost
            // of an extra attempt is stated in the refusal that bounds it.
            if declared
                .iter()
                .any(|(existing, _)| existing == &fallback_id)
            {
                return bad(
                    StatusCode::BAD_REQUEST,
                    "model_invocation_fallback_routes_invalid",
                    format!(
                        "route '{fallback_id}' appears twice in the target list; use retry.max_attempts to re-attempt one route"
                    ),
                );
            }
            let Some(fallback_route) =
                super::model_routes::load_route_record(&st.data_dir, &fallback_id)
            else {
                return bad(
                    StatusCode::NOT_FOUND,
                    "model_route_not_found",
                    format!("declared fallback route '{fallback_id}' does not exist"),
                );
            };
            // OWNERSHIP, ON EVERY HOP. Without this a caller could name any route in the deployment
            // as a fallback and reach a provider through it — and, on a credentialed route, another
            // principal's sealed key — by a path the primary gate refuses outright. A fallback is a
            // route the caller must already be entitled to invoke.
            if let Err((status, response)) = super::model_routes::authorize_route_owner_for_headers(
                &st.data_dir,
                &headers,
                &fallback_id,
                &fallback_route,
                "invoke_fallback",
            ) {
                return (status, response);
            }
            declared.push((fallback_id, fallback_route));
        }
    }

    // F1/F3 — WHAT THIS CUT REFUSES, AND WHY IT REFUSES RATHER THAN WEAKENS.
    //
    // A credential crossing is DETERMINISTIC by construction. `capability_lease_request_hash` folds
    // {domain, allowed_tools, resource_refs, scopes, facets} and nothing else — no nonce, no attempt
    // index — and the consumption commitment built from it (`governed_authority.rs`) is keyed on the
    // same fields plus the grant. So a SECOND crossing for the same route under the same grant is
    // byte-identical to the first and is refused `authority_operation_already_admitted`: the
    // substrate correctly reads it as a replay. The resume-checkpoint states this exact hazard —
    // "two crossings of the same kind that must be independently authorized need a per-request nonce
    // in the facets, or the second reads as a replay of the first" — and a router that retried a
    // credentialed route would hit it on every attempt after the first.
    //
    // The same determinism defeats a credentialed FALLBACK from the other side: the facets bind
    // `base_url` and `model_id` (the IX anti-exfiltration hardening), so this request's single
    // `wallet_approval_grant` — approved for the primary's destination — cannot satisfy a second
    // route's.
    //
    // THE SPEND SEMANTICS ARE RULED (owner, 2026-08-13), so what remains is BUILD, not a decision.
    // The two cases are NOT the same authority boundary:
    //   - A RETRY on one credentialed route is ONE grant carrying `max_usages: N` — the field the
    //     substrate already enforces (`governed_authority.rs`) — because every attempt crosses the
    //     SAME boundary: same owner, same destination, same model. Three separately signed grants
    //     would duplicate one bounded approval and ignore what `max_usages` exists to express.
    //     Making it work needs a per-attempt EFFECT identity (an attempt ordinal folded into the
    //     facets) so consumption N+1 is a distinct operation rather than a replay of N, and
    //     idempotent recovery of an already-consumed attempt that spends no further use.
    //   - A FALLBACK to a DIFFERENT route is a DIFFERENT boundary — a destination the primary's
    //     grant does not cover — so it genuinely needs its OWN grant, one per declared credentialed
    //     hop. Borrowing the primary's grant for another destination would be exactly the weakening
    //     `require_spend_authority` exists to prevent.
    // The build is out of scope for a routing cut, so this refuses, typed and BEFORE anything
    // executes, and the residual is named.
    // Checked on the DECLARED records, before admission: this is a refusal about the shape of the
    // request, and the module's standing order is request shape before world state. Ordered after
    // admission it would answer "not executable" to a caller whose real error is that they asked
    // for retries on a credentialed route — naming the wrong blocker, and reachable only for routes
    // that happen to be healthy.
    let credentialed: Vec<&str> = declared
        .iter()
        .filter(|(_, record)| route_is_credentialed(record))
        .map(|(route_id, _)| route_id.as_str())
        .collect();
    if !credentialed.is_empty() && (policy.max_attempts_per_route > 1 || declared.len() > 1) {
        return bad(
            StatusCode::NOT_IMPLEMENTED,
            "model_invocation_multi_attempt_credentialed_unsupported",
            format!(
                "retry and fallback are not available for credentialed routes ({}): each crossing is deterministic, so a second under the same grant reads as a replay. This is a build gap, not a policy one — a same-route retry is one grant carrying an approved usage ceiling (max_usages: N) plus a per-attempt effect identity, and a fallback to a different destination needs its own grant. Invoke a credentialed route with a single attempt and no fallback.",
                credentialed.join(", ")
            ),
        );
    }

    let mut targets: Vec<ExecutionTarget> = Vec::with_capacity(declared.len());
    for (target_id, target_route) in declared {
        match admit_execution_target(&target_id, target_route) {
            Ok(target) => targets.push(target),
            Err(response) => return response,
        }
    }

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

    // (5) + (6) THE ROUTER LOOP — one credential crossing and one provider call per ATTEMPT.
    //
    // Ordering inside the loop preserves the correctness property the single-attempt cut
    // established: `authorize_capability_lease` atomically CONSUMES one wallet-owned use of the
    // owner's grant, so it runs only after every pure-read refusal for THIS target has passed. What
    // is new is that it runs per attempt rather than per invocation. That is not incidental — the
    // bearer moves into the request and dies with it, so a retry cannot reuse the previous lease
    // even in principle, and a fallback crosses against its OWN route: `request_facets` fold in
    // `route_id`, `base_url` and `model_id`, so a different route is a different grant hash and an
    // owner's approval for one destination never silently covers another.
    //
    // A credential refusal ENDS the invocation; it is never a reason to try the next target. An
    // authority refusal is not a provider failure, and treating it as one would let a caller sweep a
    // declared chain to discover which routes hold credentials, spending a grant use per probe.
    let mut lineage: Vec<Value> = Vec::new();
    let mut final_result: Option<Result<TransportOutcome, TransportFailure>> = None;
    let mut used_index = 0usize;
    let mut credential_projection = Value::Null;
    // F4 — WHAT THE PROVIDER METERED ACROSS EVERY ATTEMPT, not just the last one.
    //
    // A failed attempt that consumed tokens is billed by the supplier: a stream that emitted a
    // `done` frame and then stalled, a call that hit a content filter after reading the prompt.
    // `TransportFailure::token_mix` exists to carry exactly those counts, and charging only the
    // final attempt would drop every earlier one — an UNDERCHARGE presented as a complete
    // measurement, which is worse than an absent one because nothing marks it incomplete.
    let mut billed_mix = TokenMix::default();
    let router_started = Instant::now();
    let mut deadline_exhausted = false;

    'targets: for (target_index, target) in targets.iter().enumerate() {
        let transport = ModelTransport::for_kind(&target.transport_kind);
        for attempt_on_route in 1..=policy.max_attempts_per_route {
            // The deadline is checked BEFORE starting an attempt, never mid-flight: a call already
            // in progress has already spent its authority and must be allowed to produce evidence.
            if router_started.elapsed().as_millis() >= ROUTER_DEADLINE_MS && !lineage.is_empty() {
                deadline_exhausted = true;
                break 'targets;
            }
            // Backoff belongs to the ROUTER, beside the decision that caused it — a transport that
            // slept would be deciding when to try again.
            if attempt_on_route > 1 {
                let step = RETRY_BACKOFF_MS[(attempt_on_route - 2).min(RETRY_BACKOFF_MS.len() - 1)];
                tokio::time::sleep(std::time::Duration::from_millis(step)).await;
            }
            let (mut credential_lease, projection) = match resolve_route_credential(
                &st,
                &target.route_id,
                &target.credential_posture,
                &target.base_url,
                &target.model_id,
                target
                    .route
                    .get("credential_binding")
                    .unwrap_or(&Value::Null),
                &body,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(response) => return response,
            };
            credential_projection = projection;
            used_index = target_index;

            let request = TransportRequest {
                base_url: target.base_url.clone(),
                model_id: target.model_id.clone(),
                prompt: prompt.clone(),
                stream,
                // The bearer MOVES out of the lease and into the one request that uses it. It is
                // never cloned, so there is exactly one copy in the process, and it dies below.
                credential: credential_lease
                    .as_mut()
                    .and_then(|lease| lease.token.take()),
            };
            let result = transport.invoke(&request).await;
            // Explicit, immediately after the only call that needs it.
            drop(request);
            drop(credential_lease);

            // Collect the transport's own attempt rows as OWNED values before deciding anything, so
            // the classification is read once and the borrow ends before the result moves.
            match &result {
                Ok(success) => billed_mix.accumulate(&success.token_mix),
                Err(failure) => billed_mix.accumulate(&failure.token_mix),
            }
            let (attempt_rows, succeeded, retryable) = match &result {
                Ok(success) => (
                    success
                        .attempts
                        .iter()
                        .map(TransportAttempt::to_json)
                        .collect::<Vec<_>>(),
                    true,
                    false,
                ),
                Err(failure) => (
                    failure
                        .attempts
                        .iter()
                        .map(TransportAttempt::to_json)
                        .collect::<Vec<_>>(),
                    false,
                    failure
                        .attempts
                        .last()
                        .map(|attempt| attempt.retryable)
                        .unwrap_or(false),
                ),
            };
            let decision = if succeeded {
                None
            } else {
                Some(decide_after_failure(
                    retryable,
                    attempt_on_route,
                    policy,
                    target_index,
                    targets.len(),
                ))
            };

            // THE LINEAGE. The transport's row says what happened on the wire; these columns are the
            // ROUTER's and say which route it happened against and what was decided about it.
            // Keeping them separate is why `TransportAttempt` still cannot express a decision.
            for mut row in attempt_rows {
                row["lineage_index"] = json!(lineage.len());
                row["route_id"] = json!(target.route_id);
                row["route_ref"] = json!(target.route_ref);
                row["attempt_on_route"] = json!(attempt_on_route);
                row["router_decision"] = json!(decision.map(RouterDecision::as_str));
                // WHICH CUSTODY ANSWERED FOR *THIS* ATTEMPT. The record's top-level `credential`
                // describes the answering target only; an invocation that crossed more than once
                // would otherwise present one label for several crossings and read as complete.
                row["credential"] = credential_projection.clone();
                row["token_mix"] = match &result {
                    Ok(success) => success.token_mix.to_json(),
                    Err(failure) => failure.token_mix.to_json(),
                };
                lineage.push(row);
            }

            match decision {
                None => {
                    final_result = Some(result);
                    break 'targets;
                }
                Some(RouterDecision::RetrySameRoute) => {
                    final_result = Some(result);
                    continue;
                }
                Some(RouterDecision::FallbackNextRoute) => {
                    final_result = Some(result);
                    continue 'targets;
                }
                Some(RouterDecision::GiveUp) => {
                    final_result = Some(result);
                    break 'targets;
                }
            }
        }
    }

    let Some(result) = final_result else {
        // Unreachable: the primary target is always present and the inner loop always runs at least
        // once. Typed rather than unwrapped, because a panic here would be a 500 with no record and
        // no receipt — the one outcome this handler exists to make impossible.
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "model_invocation_router_produced_no_attempt",
            "the router executed no attempt; nothing was invoked and nothing was charged",
        );
    };
    let used_target = &targets[used_index];
    let transport = ModelTransport::for_kind(&used_target.transport_kind);
    let price_schedule_ref = transport.price_schedule_ref(&used_target.route);
    let base_url = used_target.base_url.clone();
    let model_id = used_target.model_id.clone();
    let route_ref = used_target.route_ref.clone();
    let lineage_len = lineage.len();
    // Keyed on route_id, the IDENTITY the dedup check and the record loader both use. `route_ref`
    // is written with `unwrap_or_default()`, so two targets missing it would collapse to one empty
    // string and undercount.
    let routes_attempted = lineage
        .iter()
        .filter_map(|row| row.get("route_id").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    // (6) receipt — typed, and emitted on BOTH paths.
    //
    // The receipt describes the attempt that ANSWERED; `billed_mix` below is what the whole
    // invocation consumed. They differ exactly when the router re-attempted, which is the case the
    // ledger must not undercharge.
    let (receipt, evidence, outcome_state, http_status, _final_mix) = match &result {
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
                "attempts": lineage,
                "attempt_count": lineage.len(),
                "routes_attempted": routes_attempted,
                "retry_policy": { "max_attempts_per_route": policy.max_attempts_per_route },
                "router_deadline_exhausted": deadline_exhausted,
                // What the LEDGER is handed: every attempt's observed counts, not just this one's.
                "billed_token_mix": billed_mix.to_json(),
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
                "attempts": lineage,
                "attempt_count": lineage.len(),
                "routes_attempted": routes_attempted,
                "retry_policy": { "max_attempts_per_route": policy.max_attempts_per_route },
                "router_deadline_exhausted": deadline_exhausted,
                "billed_token_mix": billed_mix.to_json(),
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
        // THE ROUTE THAT ANSWERED, not the one the request was addressed to. With a fallback chain
        // these differ, and recording the requested id would make the record state that a route was
        // used which never served the call — the receipt, the credential projection and the billed
        // mix all belong to the target that actually executed. `requested_route_id` keeps the
        // caller's entry point legible beside it rather than losing it.
        "route_id": used_target.route_id,
        "requested_route_id": id,
        "route_ref": route_ref,
        "transport": transport.transport_kind(),
        "model_id": model_id,
        "base_url": base_url,
        // Which custody answered for this call, in labels. A reader can resolve the lease, the
        // grant it was issued under, and the surface that revokes it — and can resolve no secret.
        "credential": credential_projection,
        "prompt_hash": format!("sha256:{}", digest_hex(prompt.as_bytes())),
        "outcome": outcome_state,
        // The lineage's own length, not a constant. The field it replaces was pinned at 1 and
        // would now be a false statement about a record that can carry several attempts across
        // several routes.
        "attempt_count": lineage_len,
        "routes_attempted": routes_attempted,
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
        &billed_mix,
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

#[cfg(test)]
mod router_tests {
    use super::*;

    /// The distinction the whole meter rests on: `None` is UNREPORTED, never zero. An attempt that
    /// reported nothing must not be summed in as a zero (which would assert the provider metered
    /// nothing), and a class no attempt reported must stay absent so a consumer can tell "not
    /// metered" from "metered at zero".
    #[test]
    fn accumulate_keeps_absent_absent_and_sums_only_what_was_observed() {
        let mut mix = TokenMix::default();
        mix.accumulate(&TokenMix::default());
        assert_eq!(mix.input, None, "nothing observed stays unreported");
        assert_eq!(mix.total(), None);

        // A failed attempt that the provider DID meter.
        mix.accumulate(&TokenMix {
            input: Some(9_000),
            output: Some(400),
            ..TokenMix::default()
        });
        // A later attempt that reported nothing contributes nothing — and does not erase the first.
        mix.accumulate(&TokenMix::default());
        // The attempt that finally succeeded.
        mix.accumulate(&TokenMix {
            input: Some(20),
            output: Some(5),
            ..TokenMix::default()
        });

        // 9_400 of these tokens belong to an attempt that FAILED. Charging only the final attempt
        // would bill 25 for a call that really consumed 9_425 — a 99.7% undercharge presented as a
        // complete measurement, which is the defect this accumulation exists to prevent.
        assert_eq!(mix.input, Some(9_020));
        assert_eq!(mix.output, Some(405));
        assert_eq!(mix.total(), Some(9_425));
        // A class no attempt reported is still absent, not zero.
        assert_eq!(mix.reasoning, None);
        assert_eq!(mix.cache_read, None);
    }
}
