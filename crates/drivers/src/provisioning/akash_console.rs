//! Akash **Console (managed) API** — request specifications and response
//! accessors for the managed-wallet REST surface.
//!
//! This is the managed path: authenticate with an `x-api-key` and let the
//! Console back-end custody the wallet/escrow. There is no chain transaction,
//! no AKT, and no key-signing here — only REST. It is the surface behind the
//! `$100 credit` API keys created at `console.akash.network`.
//!
//! **Transport-free by design.** Each builder returns a [`ConsoleRequest`]
//! describing exactly what to send (method, path incl. query, the `x-api-key`
//! header, optional JSON body). The daemon executes it with `reqwest` ONLY
//! behind its `mode==live` + wallet-lease gate; the spend-capable operations
//! (`create_deployment`, `create_lease`, `deposit_deployment`, and the
//! resource-changing `update_deployment`) are **never executed from this
//! crate**. Keeping the contract pure makes the request shapes unit-testable
//! without a network and keeps every real spend on the gated side.
//!
//! Contract source: `akash-network/console` — `console-api-types`
//! (OpenAPI-generated `operations.gen.ts`) and the
//! `managed-api-deployment-flow` end-to-end test. Auth note from the same
//! source: `x-api-key` and `Authorization` are **mutually exclusive**, so we
//! send `x-api-key` only.

use serde_json::{json, Value};

/// Base URL for the managed Console API.
pub const AKASH_CONSOLE_BASE_URL: &str = "https://console-api.akash.network";
/// The (only) auth header. Never send `Authorization` alongside it.
pub const API_KEY_HEADER: &str = "x-api-key";

/// HTTP method for a [`ConsoleRequest`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsoleMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl ConsoleMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConsoleMethod::Get => "GET",
            ConsoleMethod::Post => "POST",
            ConsoleMethod::Put => "PUT",
            ConsoleMethod::Delete => "DELETE",
        }
    }
}

/// A fully-specified Console API request. `api_key` is carried for the header
/// only and is deliberately excluded from `Debug` so the secret cannot leak
/// into a log line.
#[derive(Clone)]
pub struct ConsoleRequest {
    pub method: ConsoleMethod,
    /// Path including any query string, e.g. `"/v1/bids?dseq=123"`. Join to
    /// [`AKASH_CONSOLE_BASE_URL`] (or an override base) to form the full URL.
    pub path: String,
    /// JSON body for POST/PUT operations; `None` for GET/DELETE.
    pub body: Option<Value>,
    /// Whether this request moves money / provisions resources. The daemon
    /// MUST require a redeemed wallet lease (and, for the first live run, an
    /// explicit human confirm) before executing a spend request.
    pub spend: bool,
    api_key: String,
}

impl std::fmt::Debug for ConsoleRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsoleRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body", &self.body)
            .field("spend", &self.spend)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl ConsoleRequest {
    fn get(api_key: &str, path: impl Into<String>) -> Self {
        Self {
            method: ConsoleMethod::Get,
            path: path.into(),
            body: None,
            spend: false,
            api_key: api_key.to_string(),
        }
    }

    /// The auth header pair to attach to the outgoing request.
    pub fn header(&self) -> (&'static str, &str) {
        (API_KEY_HEADER, &self.api_key)
    }

    /// True iff this request provisions resources or moves credits.
    pub fn is_spend(&self) -> bool {
        self.spend
    }
}

/// A selected bid, extracted from `GET /v1/bids?dseq=…`. The provider-native
/// ids (`gseq`/`oseq`/`provider`) are evidence used to create the lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AkashBid {
    pub gseq: i64,
    pub oseq: i64,
    pub provider: String,
}

// ----- read-only operations (never spend) -----

/// Read-only credential probe. Lists deployments with a minimal page: a managed
/// key that authenticates returns `200` (even with an empty list), so this is
/// the reliable "does the key authenticate" check. (`/v1/wallet-settings` was
/// the first choice but 404s on an account that has no settings configured yet,
/// even when the key is valid.) A `2xx` is how an akash account transitions to
/// `status == "verified"` WITHOUT any spend. `GET /v1/deployments?skip=0&limit=1`.
pub fn verify_key(api_key: &str) -> ConsoleRequest {
    ConsoleRequest::get(api_key, "/v1/deployments?skip=0&limit=1")
}

/// List existing deployments (read-only). `GET /v1/deployments?skip=&limit=`.
pub fn list_deployments(api_key: &str, skip: u32, limit: u32) -> ConsoleRequest {
    ConsoleRequest::get(
        api_key,
        format!("/v1/deployments?skip={skip}&limit={limit}"),
    )
}

/// List bids for a deployment (read-only). Poll until `data.data[0]` exists.
/// `GET /v1/bids?dseq=…`.
pub fn list_bids(api_key: &str, dseq: &str) -> ConsoleRequest {
    ConsoleRequest::get(api_key, format!("/v1/bids?dseq={dseq}"))
}

/// Get one deployment incl. leases + escrow (read-only). Used to poll status
/// and read lease endpoints. `GET /v1/deployments/{dseq}`.
pub fn get_deployment(api_key: &str, dseq: &str) -> ConsoleRequest {
    ConsoleRequest::get(api_key, format!("/v1/deployments/{dseq}"))
}

// ----- state-changing operations -----

/// Close a deployment. `DELETE /v1/deployments/{dseq}`. Not a *spend* (it stops
/// spend), but it IS a lifecycle mutation the daemon receipts.
pub fn close_deployment(api_key: &str, dseq: &str) -> ConsoleRequest {
    ConsoleRequest {
        method: ConsoleMethod::Delete,
        path: format!("/v1/deployments/{dseq}"),
        body: None,
        spend: false,
        api_key: api_key.to_string(),
    }
}

// ----- SPEND operations (daemon must gate on a redeemed wallet lease) -----

/// Create a deployment from an SDL yaml string, funded with `deposit` credits
/// (dollars on the managed wallet). SPEND. `POST /v1/deployments` with body
/// `{"data": {"sdl": "<yaml>", "deposit": <n>}}`.
pub fn create_deployment(api_key: &str, sdl_yaml: &str, deposit: f64) -> ConsoleRequest {
    ConsoleRequest {
        method: ConsoleMethod::Post,
        path: "/v1/deployments".to_string(),
        body: Some(json!({ "data": { "sdl": sdl_yaml, "deposit": deposit } })),
        spend: true,
        api_key: api_key.to_string(),
    }
}

/// Create a lease against a selected bid, sending the encoded manifest returned
/// by `create_deployment`. SPEND (starts the accruing lease). `POST /v1/leases`
/// with body `{"manifest": "<enc>", "leases": [{dseq, gseq, oseq, provider}]}`.
pub fn create_lease(api_key: &str, manifest: &str, dseq: &str, bid: &AkashBid) -> ConsoleRequest {
    ConsoleRequest {
        method: ConsoleMethod::Post,
        path: "/v1/leases".to_string(),
        body: Some(json!({
            "manifest": manifest,
            "leases": [{
                "dseq": dseq,
                "gseq": bid.gseq,
                "oseq": bid.oseq,
                "provider": bid.provider,
            }],
        })),
        spend: true,
        api_key: api_key.to_string(),
    }
}

/// Add credits to an existing deployment's escrow. SPEND.
/// `POST /v1/deposit-deployment` with body `{"data": {"dseq", "deposit"}}`.
pub fn deposit_deployment(api_key: &str, dseq: &str, deposit: f64) -> ConsoleRequest {
    ConsoleRequest {
        method: ConsoleMethod::Post,
        path: "/v1/deposit-deployment".to_string(),
        body: Some(json!({ "data": { "dseq": dseq, "deposit": deposit } })),
        spend: true,
        api_key: api_key.to_string(),
    }
}

// ----- response accessors (pure; over the documented shapes) -----

/// The `dseq` from a `createDeployment` response: `{"data": {"dseq": "…"}}`.
pub fn parse_created_dseq(resp: &Value) -> Option<String> {
    resp.pointer("/data/dseq")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// The encoded manifest from a `createDeployment` response, needed by
/// `create_lease`: `{"data": {"manifest": "…"}}`.
pub fn parse_created_manifest(resp: &Value) -> Option<String> {
    resp.pointer("/data/manifest")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn bid_entries(resp: &Value) -> Option<&Vec<Value>> {
    // Current Console API ListBidsResponse is `{ data: Bid[] }`. Retain the
    // older nested envelope only as a compatibility read path.
    resp.get("data")
        .and_then(Value::as_array)
        .or_else(|| resp.pointer("/data/data").and_then(Value::as_array))
}

/// The first bid from a current Console `listBids` response, shape `{"data": [{"bid":
/// {"id": {"gseq", "oseq", "provider"}}}]}`. Returns `None` while no provider
/// has bid yet (keep polling).
pub fn parse_first_bid(resp: &Value) -> Option<AkashBid> {
    let bid = bid_entries(resp)?.first()?.pointer("/bid/id")?;
    Some(AkashBid {
        gseq: bid.get("gseq").and_then(Value::as_i64)?,
        oseq: bid.get("oseq").and_then(Value::as_i64)?,
        provider: bid.get("provider").and_then(Value::as_str)?.to_string(),
    })
}

/// The lowest-priced bid across a `listBids` response, so selection can respect
/// a price cap. Falls back to the first bid's ordering when prices are absent.
pub fn parse_cheapest_bid(resp: &Value) -> Option<AkashBid> {
    let bids = bid_entries(resp)?;
    let mut best: Option<(f64, AkashBid)> = None;
    for entry in bids {
        let id = entry.pointer("/bid/id")?;
        let bid = AkashBid {
            gseq: id.get("gseq").and_then(Value::as_i64)?,
            oseq: id.get("oseq").and_then(Value::as_i64)?,
            provider: id.get("provider").and_then(Value::as_str)?.to_string(),
        };
        // price.amount is a decimal string in the smallest denom; missing → max.
        let price = entry
            .pointer("/bid/price/amount")
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| s.parse::<f64>().ok())
                    .or_else(|| v.as_f64())
            })
            .unwrap_or(f64::MAX);
        match &best {
            Some((p, _)) if *p <= price => {}
            _ => best = Some((price, bid)),
        }
    }
    best.map(|(_, b)| b)
}

/// Lowest bid whose exact provider-native price is in the owner-approved denomination and at or
/// below the approved ceiling. Missing/malformed prices are ineligible, never treated as cheap.
pub fn parse_cheapest_qualified_bid(
    resp: &Value,
    ceiling_denom: &str,
    ceiling_amount: f64,
) -> Option<AkashBid> {
    let bids = bid_entries(resp)?;
    let mut best: Option<(f64, AkashBid)> = None;
    for entry in bids {
        let Some(price) = entry.pointer("/bid/price") else {
            continue;
        };
        if price.get("denom").and_then(Value::as_str) != Some(ceiling_denom) {
            continue;
        }
        let Some(amount) = price
            .get("amount")
            .and_then(|value| {
                value
                    .as_str()
                    .and_then(|raw| raw.parse::<f64>().ok())
                    .or_else(|| value.as_f64())
            })
            .filter(|amount| amount.is_finite() && *amount >= 0.0 && *amount <= ceiling_amount)
        else {
            continue;
        };
        let Some(id) = entry.pointer("/bid/id") else {
            continue;
        };
        let bid = AkashBid {
            gseq: id.get("gseq").and_then(Value::as_i64)?,
            oseq: id.get("oseq").and_then(Value::as_i64)?,
            provider: id.get("provider").and_then(Value::as_str)?.to_string(),
        };
        match &best {
            Some((current, _)) if *current <= amount => {}
            _ => best = Some((amount, bid)),
        }
    }
    best.map(|(_, bid)| bid)
}

/// The bid from one exact provider, but only when its provider-native price is in the exact
/// owner-approved denomination and at or below the approved ceiling. An exact provider pin is
/// never permission to bypass the spend ceiling.
pub fn parse_pinned_qualified_bid(
    resp: &Value,
    provider: &str,
    ceiling_denom: &str,
    ceiling_amount: f64,
) -> Option<AkashBid> {
    let bids = bid_entries(resp)?;
    for entry in bids {
        let id = entry.pointer("/bid/id")?;
        if id.get("provider").and_then(Value::as_str) != Some(provider) {
            continue;
        }
        let price = entry.pointer("/bid/price")?;
        if price.get("denom").and_then(Value::as_str) != Some(ceiling_denom) {
            return None;
        }
        let amount = price
            .get("amount")
            .and_then(|value| {
                value
                    .as_str()
                    .and_then(|raw| raw.parse::<f64>().ok())
                    .or_else(|| value.as_f64())
            })
            .filter(|amount| amount.is_finite() && *amount >= 0.0)?;
        if amount > ceiling_amount {
            return None;
        }
        return Some(AkashBid {
            gseq: id.get("gseq").and_then(Value::as_i64)?,
            oseq: id.get("oseq").and_then(Value::as_i64)?,
            provider: provider.to_string(),
        });
    }
    None
}

/// The bid from a SPECIFIC provider address in a `getBids` response, or `None` if
/// that provider is not among the bidders. C6 provider-pin: when a caller pins a
/// provider address (the one the wallet challenge hashed), the daemon deploys on
/// THAT provider or refuses — it never silently falls through to the cheapest.
/// Selecting by pin proves `selected == pinned` by construction.
pub fn parse_pinned_bid(resp: &Value, provider: &str) -> Option<AkashBid> {
    let bids = bid_entries(resp)?;
    for entry in bids {
        let id = entry.pointer("/bid/id")?;
        if id.get("provider").and_then(Value::as_str) == Some(provider) {
            return Some(AkashBid {
                gseq: id.get("gseq").and_then(Value::as_i64)?,
                oseq: id.get("oseq").and_then(Value::as_i64)?,
                provider: provider.to_string(),
            });
        }
    }
    None
}

/// Extract one active lease's provider-reported service endpoint without conflating endpoint
/// discovery with workload readiness. A provider URI proves routing information exists; only a
/// positive provider-reported ready/available replica count proves workload readiness.
pub fn parse_active_lease_endpoint(resp: &Value) -> Option<Value> {
    let leases = resp.pointer("/data/leases").and_then(Value::as_array)?;
    for lease in leases {
        if lease.get("state").and_then(Value::as_str) != Some("active") {
            continue;
        }
        let services = lease
            .pointer("/status/services")
            .and_then(Value::as_object)?;
        let service_uri_present = services.values().any(|service| {
            service
                .get("uris")
                .and_then(Value::as_array)
                .map(|uris| !uris.is_empty())
                .unwrap_or(false)
        });
        let forwarded_port_present = lease
            .pointer("/status/forwarded_ports")
            .and_then(Value::as_object)
            .map(|ports| !ports.is_empty())
            .unwrap_or(false);
        let ip_present = lease
            .pointer("/status/ips")
            .and_then(Value::as_object)
            .map(|ips| !ips.is_empty())
            .unwrap_or(false);
        if !service_uri_present && !forwarded_port_present && !ip_present {
            continue;
        }
        let desired_replicas = services
            .values()
            .map(|service| {
                service
                    .get("replicas")
                    .or_else(|| service.get("total"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            })
            .sum::<u64>();
        let ready_replicas = services
            .values()
            .map(|service| {
                service
                    .get("ready_replicas")
                    .or_else(|| service.get("available_replicas"))
                    .or_else(|| service.get("available"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            })
            .sum::<u64>();
        return Some(json!({
            "provider_address": lease.pointer("/id/provider").cloned().unwrap_or(Value::Null),
            "lease_id": lease.get("id").cloned().unwrap_or(Value::Null),
            "services": services,
            "forwarded_ports": lease.pointer("/status/forwarded_ports").cloned().unwrap_or(Value::Null),
            "ips": lease.pointer("/status/ips").cloned().unwrap_or(Value::Null),
            "endpoint_discovered": true,
            "service_uri_present": service_uri_present,
            "desired_replicas": desired_replicas,
            "ready_replicas": ready_replicas,
            "workload_readiness_proven": ready_replicas > 0,
        }));
    }
    None
}

/// The deployment `state` from a `getDeployment` response
/// (`{"data": {"deployment": {"state": "…"}}}`), e.g. `"active"`/`"closed"`.
pub fn parse_deployment_state(resp: &Value) -> Option<String> {
    resp.pointer("/data/deployment/state")
        .or_else(|| resp.pointer("/deployment/state"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Normalize the provider-native close/escrow readback without inferring settlement from the
/// DELETE response. A terminal verdict requires the deployment and escrow account to be closed,
/// a provider `settled_at` height, no active lease, and zero funds left in escrow. `transferred`
/// is the exact deployment debit in the managed `uact` denomination; the remainder of the
/// caller-recorded deposit is the refund. Unknown/malformed amounts stay reconciliation-required.
pub fn parse_settlement_readback(resp: &Value, deposit_usd: f64) -> Value {
    let deployment_state = resp
        .pointer("/data/deployment/state")
        .or_else(|| resp.pointer("/deployment/state"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let escrow = resp
        .pointer("/data/escrow_account")
        .or_else(|| resp.pointer("/escrow_account"))
        .cloned()
        .unwrap_or(Value::Null);
    let escrow_state = escrow
        .pointer("/state/state")
        .or_else(|| escrow.get("state").filter(|value| value.is_string()))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let settled_at = escrow
        .pointer("/state/settled_at")
        .or_else(|| escrow.get("settled_at"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let leases = resp
        .pointer("/data/leases")
        .or_else(|| resp.get("leases"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let active_lease_count = leases
        .iter()
        .filter(|lease| {
            lease
                .pointer("/lease/state")
                .or_else(|| lease.get("state"))
                .and_then(Value::as_str)
                .map(|state| matches!(state, "active" | "open"))
                .unwrap_or(false)
        })
        .count();
    let coins = |field: &str| {
        escrow
            .pointer(&format!("/state/{field}"))
            .or_else(|| escrow.get(field))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let funds = coins("funds");
    let transferred = coins("transferred");
    let sum_uact = |values: &[Value]| -> Option<f64> {
        let mut total = 0.0;
        for coin in values {
            if coin.get("denom").and_then(Value::as_str) != Some("uact") {
                continue;
            }
            let amount = coin
                .get("amount")
                .and_then(Value::as_str)?
                .parse::<f64>()
                .ok()?;
            if !amount.is_finite() || amount < 0.0 {
                return None;
            }
            total += amount;
        }
        Some(total)
    };
    let funds_uact = sum_uact(&funds);
    let transferred_uact = sum_uact(&transferred);
    let terminal = deployment_state == "closed"
        && escrow_state == "closed"
        && !settled_at.is_empty()
        && active_lease_count == 0
        && funds_uact == Some(0.0)
        && transferred_uact.is_some();
    let final_debit_usd = transferred_uact.map(|amount| amount / 1_000_000.0);
    let refund_usd = final_debit_usd.map(|debit| (deposit_usd - debit).max(0.0));
    let settlement_state = if terminal {
        if transferred_uact == Some(0.0) {
            "refund_settled"
        } else {
            "final_debit_settled"
        }
    } else {
        "reconciliation_required"
    };
    json!({
        "schema_version": "ioi.hypervisor.akash-settlement-readback.v1",
        "settlement_state": settlement_state,
        "deployment_state": deployment_state,
        "escrow_state": escrow_state,
        "settled_at_height": if settled_at.is_empty() { Value::Null } else { json!(settled_at) },
        "active_lease_count": active_lease_count,
        "funds": funds,
        "transferred": transferred,
        "deposit_usd": deposit_usd,
        "final_debit_usd": final_debit_usd,
        "refund_usd": refund_usd,
        "provider_terminal": terminal,
        "basis": "provider-native deployment + escrow + lease readback; close HTTP alone never settles",
    })
}

/// Backward-compatible strict readiness accessor. Callers that only need endpoint discovery must
/// use `parse_active_lease_endpoint` and preserve its explicit readiness fields.
pub fn parse_ready_lease_endpoint(resp: &Value) -> Option<Value> {
    parse_active_lease_endpoint(resp).filter(|endpoint| {
        endpoint
            .get("workload_readiness_proven")
            .and_then(Value::as_bool)
            == Some(true)
    })
}

#[cfg(test)]
#[path = "akash_console/tests.rs"]
mod tests;
