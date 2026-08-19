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

use rust_decimal::Decimal;
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

/// The first bid from a `listBids` response, shape `{"data": {"data": [ {"bid":
/// {"id": {"gseq", "oseq", "provider"}}} ]}}`. Returns `None` while no provider
/// has bid yet (keep polling).
pub fn parse_first_bid(resp: &Value) -> Option<AkashBid> {
    let bid = resp.pointer("/data/data/0/bid/id")?;
    Some(AkashBid {
        gseq: bid.get("gseq").and_then(Value::as_i64)?,
        oseq: bid.get("oseq").and_then(Value::as_i64)?,
        provider: bid.get("provider").and_then(Value::as_str)?.to_string(),
    })
}

/// The lowest-priced bid across a `listBids` response, so selection can respect
/// a price cap. Falls back to the first bid's ordering when prices are absent.
pub fn parse_cheapest_bid(resp: &Value) -> Option<AkashBid> {
    let bids = resp.pointer("/data/data").and_then(Value::as_array)?;
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

/// The bid from a SPECIFIC provider address in a `getBids` response, or `None` if
/// that provider is not among the bidders. C6 provider-pin: when a caller pins a
/// provider address (the one the wallet challenge hashed), the daemon deploys on
/// THAT provider or refuses — it never silently falls through to the cheapest.
/// Selecting by pin proves `selected == pinned` by construction.
pub fn parse_pinned_bid(resp: &Value, provider: &str) -> Option<AkashBid> {
    let bids = resp.pointer("/data/data").and_then(Value::as_array)?;
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

/// The single denomination the C7 capstone accepts. Akash's current SDL/bid API prices in
/// `uact` (micro-AKT/block); a bid in any OTHER denom is a circuit-breaker event — refuse and
/// close, never auto-accept a fallback denom (that would need fresh authorization).
pub const AKASH_CAPSTONE_DENOM: &str = "uact";

/// Max SDL bytes we will parse. Akash SDLs are a few hundred bytes; this bounds oversized and
/// expansion-style inputs before the YAML parser runs.
const MAX_SDL_BYTES: usize = 16 * 1024;

/// An absurd upper bound on a per-block ceiling — well above any real `uact/block` price. A
/// larger amount is a typo or an attack, not a bound. (rust_decimal cannot represent ±inf, so
/// non-finite amounts are already impossible here.)
fn max_ceiling_uact() -> Decimal {
    Decimal::from(1_000_000_000_i64)
}

/// Parse an Akash SDL `amount` field into an EXACT positive, finite, bounded Decimal. Accepts an
/// integer or a canonical decimal STRING — never a YAML float (which would introduce binary
/// rounding and can carry `.inf`). Errs on anything else.
fn decimal_amount(v: Option<&Value>, what: &str) -> Result<Decimal, String> {
    let v = v.ok_or_else(|| format!("akash_{what}_no_amount — no amount field"))?;
    let dec = if let Some(i) = v.as_i64() {
        Decimal::from(i)
    } else if let Some(u) = v.as_u64() {
        Decimal::from(u)
    } else if let Some(s) = v.as_str() {
        Decimal::from_str_exact(s.trim())
            .map_err(|e| format!("akash_{what}_amount_not_decimal — '{s}': {e}"))?
    } else {
        // A YAML float (incl. .inf/.nan) lands here and is refused: money is never an f64.
        return Err(format!(
            "akash_{what}_amount_not_exact — amount must be an integer or a decimal string, never a float"
        ));
    };
    if dec <= Decimal::ZERO {
        return Err(format!(
            "akash_{what}_amount_not_positive — amount {dec} must be > 0"
        ));
    }
    if dec > max_ceiling_uact() {
        return Err(format!(
            "akash_{what}_amount_overlarge — amount {dec} exceeds the max"
        ));
    }
    Ok(dec)
}

/// C7 Stage A — parse a caller-supplied Akash SDL and return the SINGLE deployment group's price
/// ceiling as an EXACT decimal `(denom, amount)`. Deliberately restricted to the capstone's
/// honest shape — exactly one deployed service, one placement, one referenced compute profile,
/// `count == 1`, priced in `uact` — so there is exactly one order, one bid, one price, one lease.
/// Multi-group SDLs (Akash creates separate orders/bids/leases per group) are REFUSED here rather
/// than modelled with a false deployment-wide sum; group-aware support is a later leg. The price
/// is looked up by the REFERENCED COMPUTE PROFILE, not the service name. Errs (the gate refuses →
/// NO deployment is created) on any departure from that shape, an oversized/aliased/unparseable
/// SDL, or a non-positive/overlarge amount.
pub fn parse_c7_sdl_ceiling(sdl_yaml: &str) -> Result<(String, Decimal), String> {
    if sdl_yaml.len() > MAX_SDL_BYTES {
        return Err(format!(
            "akash_sdl_too_large — SDL is {} bytes (max {MAX_SDL_BYTES})",
            sdl_yaml.len()
        ));
    }
    // Reject YAML anchors/aliases/merge-keys: the accepted subset never uses them and they are the
    // vector for expansion bombs. A scan suffices for this restricted subset.
    if sdl_yaml.contains(" &") || sdl_yaml.contains(" *") || sdl_yaml.contains("<<:") {
        return Err(
            "akash_sdl_alias_forbidden — YAML anchors/aliases/merge-keys are not accepted".into(),
        );
    }
    // serde_yaml_ng errs on duplicate mapping keys, so a duplicate lands in `unparseable`.
    let doc: Value =
        serde_yaml_ng::from_str(sdl_yaml).map_err(|e| format!("akash_sdl_unparseable: {e}"))?;

    // deployment: EXACTLY one service.
    let deployment = doc
        .get("deployment")
        .and_then(Value::as_object)
        .ok_or("akash_sdl_no_deployment — the SDL declares no `deployment` block")?;
    if deployment.len() != 1 {
        return Err(format!(
            "akash_sdl_not_single_group — C7 accepts exactly one deployed service, found {}",
            deployment.len()
        ));
    }
    let (service, placements) = deployment.iter().next().unwrap();
    let placements = placements.as_object().ok_or_else(|| {
        format!("akash_sdl_service_malformed — service '{service}' has no placement mapping")
    })?;
    if placements.len() != 1 {
        return Err(format!(
            "akash_sdl_not_single_placement — service '{service}' must name exactly one placement, found {}",
            placements.len()
        ));
    }
    let (placement_name, group) = placements.iter().next().unwrap();
    // count == 1 → exactly one order/group.
    let count = group.get("count").and_then(|v| v.as_i64()).ok_or_else(|| {
        format!("akash_sdl_no_count — placement '{placement_name}' has no integer count")
    })?;
    if count != 1 {
        return Err(format!(
            "akash_sdl_count_not_one — C7 accepts count == 1, found {count}"
        ));
    }
    // Pricing is keyed by the referenced COMPUTE PROFILE, not the service name.
    let profile = group
        .get("profile")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!("akash_sdl_no_profile — placement '{placement_name}' names no compute profile")
        })?;
    if doc
        .pointer("/profiles/compute")
        .and_then(|c| c.get(profile))
        .is_none()
    {
        return Err(format!(
            "akash_sdl_profile_absent — compute profile '{profile}' is not defined under profiles.compute"
        ));
    }
    let price = doc
        .get("profiles")
        .and_then(|p| p.get("placement"))
        .and_then(|pl| pl.get(placement_name))
        .and_then(|p| p.get("pricing"))
        .and_then(|pr| pr.get(profile))
        .ok_or_else(|| {
            format!("akash_sdl_service_unpriced — compute profile '{profile}' has no price ceiling under placement '{placement_name}'; the deployed group MUST bound its max bid")
        })?;
    let denom = price
        .get("denom")
        .and_then(Value::as_str)
        .ok_or("akash_sdl_price_no_denom — the price has no denom")?
        .to_string();
    if denom != AKASH_CAPSTONE_DENOM {
        return Err(format!(
            "akash_sdl_denom_not_accepted — C7 prices in '{AKASH_CAPSTONE_DENOM}', SDL declares '{denom}'"
        ));
    }
    let amount = decimal_amount(price.get("amount"), "sdl")?;
    Ok((denom, amount))
}

/// The pinned provider's bid WITH its EXACT price + denom — the post-bid quote to check against
/// the SDL ceiling. `None` if that provider did not bid; `Err` if it bid with an unreadable price
/// (either refuses Stage B → the deposit is closed). For C7's single group there is one bid per
/// provider; this returns the pinned provider's bid.
pub fn parse_pinned_bid_priced(
    resp: &Value,
    provider: &str,
) -> Option<Result<(AkashBid, Decimal, String), String>> {
    let bids = resp.pointer("/data/data").and_then(Value::as_array)?;
    for entry in bids {
        let id = entry.pointer("/bid/id")?;
        if id.get("provider").and_then(Value::as_str) == Some(provider) {
            let (Some(gseq), Some(oseq)) = (
                id.get("gseq").and_then(Value::as_i64),
                id.get("oseq").and_then(Value::as_i64),
            ) else {
                return Some(Err("akash_bid_malformed_id — bid lacks gseq/oseq".into()));
            };
            let bid = AkashBid {
                gseq,
                oseq,
                provider: provider.to_string(),
            };
            let price = entry.pointer("/bid/price");
            let amount = match decimal_amount(price.and_then(|p| p.get("amount")), "bid") {
                Ok(a) => a,
                Err(e) => return Some(Err(e)),
            };
            let Some(denom) = price.and_then(|p| p.get("denom")).and_then(Value::as_str) else {
                return Some(Err("akash_bid_no_denom — bid price has no denom".into()));
            };
            return Some(Ok((bid, amount, denom.to_string())));
        }
    }
    None
}

/// C7 Stage B — the real bid must price in the accepted denom and at or below the SDL ceiling.
/// A bid in a different denom (a circuit-breaker) or over the ceiling is refused (the lease never
/// opens; Stage B then closes the deposit). Exact Decimal comparison — no f64.
pub fn bid_passes_ceiling(
    bid_amount: Decimal,
    bid_denom: &str,
    ceiling_denom: &str,
    ceiling: Decimal,
) -> Result<(), String> {
    if bid_denom != ceiling_denom {
        return Err(format!(
            "akash_bid_denom_mismatch — bid prices in '{bid_denom}' but the ceiling is '{ceiling_denom}' (denomination change → halt, do not auto-accept)"
        ));
    }
    if bid_amount > ceiling {
        return Err(format!(
            "akash_bid_over_ceiling — bid {bid_amount} {bid_denom} exceeds the SDL max {ceiling} {ceiling_denom}"
        ));
    }
    Ok(())
}

/// The deployment `state` from a `getDeployment` response
/// (`{"data": {"deployment": {"state": "…"}}}`), e.g. `"active"`/`"closed"`.
pub fn parse_deployment_state(resp: &Value) -> Option<String> {
    resp.pointer("/data/deployment/state")
        .or_else(|| resp.pointer("/deployment/state"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

#[cfg(test)]
#[path = "akash_console/tests.rs"]
mod tests;
