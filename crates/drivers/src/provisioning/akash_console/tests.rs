use super::*;
use serde_json::json;

const KEY: &str = "ak-secret-do-not-log";

// ----- request construction is exact (method, path, header, body, spend flag) -----

#[test]
fn verify_key_is_a_read_only_deployments_probe() {
    let r = verify_key(KEY);
    assert_eq!(r.method, ConsoleMethod::Get);
    assert_eq!(r.path, "/v1/deployments?skip=0&limit=1");
    assert!(r.body.is_none());
    assert!(!r.is_spend(), "a credential probe must never be a spend");
    assert_eq!(r.header(), (API_KEY_HEADER, KEY));
    assert_eq!(API_KEY_HEADER, "x-api-key");
}

#[test]
fn list_bids_carries_the_dseq_query() {
    let r = list_bids(KEY, "123456");
    assert_eq!(r.method, ConsoleMethod::Get);
    assert_eq!(r.path, "/v1/bids?dseq=123456");
    assert!(!r.is_spend());
}

#[test]
fn get_and_close_deployment_hit_the_dseq_path() {
    let g = get_deployment(KEY, "42");
    assert_eq!(g.method, ConsoleMethod::Get);
    assert_eq!(g.path, "/v1/deployments/42");
    assert!(!g.is_spend());

    let c = close_deployment(KEY, "42");
    assert_eq!(c.method, ConsoleMethod::Delete);
    assert_eq!(c.path, "/v1/deployments/42");
    // Closing stops spend; it is not itself a spend.
    assert!(!c.is_spend());
}

#[test]
fn create_deployment_wraps_sdl_and_deposit_and_is_a_spend() {
    let r = create_deployment(KEY, "version: \"2.0\"\n", 5.0);
    assert_eq!(r.method, ConsoleMethod::Post);
    assert_eq!(r.path, "/v1/deployments");
    assert_eq!(
        r.body.as_ref().unwrap(),
        &json!({ "data": { "sdl": "version: \"2.0\"\n", "deposit": 5.0 } })
    );
    assert!(
        r.is_spend(),
        "creating a funded deployment MUST classify as spend"
    );
}

#[test]
fn create_lease_targets_the_selected_bid_and_is_a_spend() {
    let bid = AkashBid {
        gseq: 1,
        oseq: 2,
        provider: "akash1prov".into(),
    };
    let r = create_lease(KEY, "ENCODED_MANIFEST", "789", &bid);
    assert_eq!(r.method, ConsoleMethod::Post);
    assert_eq!(r.path, "/v1/leases");
    assert_eq!(
        r.body.as_ref().unwrap(),
        &json!({
            "manifest": "ENCODED_MANIFEST",
            "leases": [{ "dseq": "789", "gseq": 1, "oseq": 2, "provider": "akash1prov" }]
        })
    );
    assert!(r.is_spend(), "opening a lease starts accruing spend");
}

#[test]
fn deposit_is_a_spend_with_the_documented_body() {
    let r = deposit_deployment(KEY, "789", 0.5);
    assert_eq!(r.method, ConsoleMethod::Post);
    assert_eq!(r.path, "/v1/deposit-deployment");
    assert_eq!(
        r.body.as_ref().unwrap(),
        &json!({ "data": { "dseq": "789", "deposit": 0.5 } })
    );
    assert!(r.is_spend());
}

// ----- the secret never leaks through Debug -----

#[test]
fn debug_redacts_the_api_key() {
    let r = create_deployment(KEY, "sdl", 5.0);
    let dbg = format!("{r:?}");
    assert!(
        !dbg.contains(KEY),
        "Debug must not print the api key: {dbg}"
    );
    assert!(dbg.contains("<redacted>"));
}

// ----- response accessors over the documented shapes -----

#[test]
fn parse_created_deployment_reads_dseq_and_manifest() {
    let resp = json!({ "data": { "dseq": "555", "manifest": "ENC" } });
    assert_eq!(parse_created_dseq(&resp).as_deref(), Some("555"));
    assert_eq!(parse_created_manifest(&resp).as_deref(), Some("ENC"));
    // A missing field yields None, never a panic or a fabricated value.
    assert_eq!(parse_created_dseq(&json!({ "data": {} })), None);
}

#[test]
fn parse_first_bid_reads_the_provider_native_ids() {
    let resp = json!({
        "data": { "data": [
            { "bid": { "id": { "gseq": 1, "oseq": 3, "provider": "akash1abc" } } }
        ]}
    });
    assert_eq!(
        parse_first_bid(&resp),
        Some(AkashBid {
            gseq: 1,
            oseq: 3,
            provider: "akash1abc".into()
        })
    );
    // No bids yet → None (keep polling), not an error.
    assert_eq!(parse_first_bid(&json!({ "data": { "data": [] } })), None);
}

#[test]
fn parse_cheapest_bid_selects_the_lowest_price() {
    let resp = json!({
        "data": { "data": [
            { "bid": { "id": { "gseq": 1, "oseq": 1, "provider": "expensive" }, "price": { "amount": "1000", "denom": "uakt" } } },
            { "bid": { "id": { "gseq": 1, "oseq": 2, "provider": "cheap"     }, "price": { "amount": "250",  "denom": "uakt" } } },
            { "bid": { "id": { "gseq": 1, "oseq": 3, "provider": "mid"       }, "price": { "amount": "500",  "denom": "uakt" } } }
        ]}
    });
    assert_eq!(parse_cheapest_bid(&resp).unwrap().provider, "cheap");
}

#[test]
fn parse_pinned_bid_selects_the_pinned_provider_or_refuses() {
    // C6 provider-pin: the pinned provider's bid is selected EVEN when it is not
    // the cheapest (so the daemon deploys where the wallet approved, never on the
    // cheapest fall-through); a pin that did not bid returns None → the caller refuses.
    let resp = json!({
        "data": { "data": [
            { "bid": { "id": { "gseq": 1, "oseq": 1, "provider": "expensive" }, "price": { "amount": "1000", "denom": "uakt" } } },
            { "bid": { "id": { "gseq": 1, "oseq": 2, "provider": "cheap"     }, "price": { "amount": "250",  "denom": "uakt" } } },
            { "bid": { "id": { "gseq": 1, "oseq": 3, "provider": "mid"       }, "price": { "amount": "500",  "denom": "uakt" } } }
        ]}
    });
    // Pinning "mid" selects mid — NOT the cheapest "cheap".
    let pinned = parse_pinned_bid(&resp, "mid").expect("the pinned provider bid is present");
    assert_eq!(pinned.provider, "mid");
    assert_eq!(pinned.oseq, 3);
    // A provider that did not bid is refused (None), never silently downgraded.
    assert!(parse_pinned_bid(&resp, "akash1neverbid").is_none());
}

#[test]
fn parse_deployment_state_reads_either_envelope() {
    assert_eq!(
        parse_deployment_state(&json!({ "data": { "deployment": { "state": "active" } } }))
            .as_deref(),
        Some("active")
    );
    assert_eq!(
        parse_deployment_state(&json!({ "deployment": { "state": "closed" } })).as_deref(),
        Some("closed")
    );
}

// ----- C7 Stage A/B: SDL price-ceiling parsing + bid ceiling checks -----

const PRICED_SDL: &str = r#"
version: "2.0"
services:
  web:
    image: nginx:alpine
    expose:
      - port: 80
        as: 80
        to:
          - global: true
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 0.1
        memory:
          size: 128Mi
        storage:
          size: 128Mi
  placement:
    dcloud:
      pricing:
        web:
          denom: uakt
          amount: 1000
deployment:
  web:
    dcloud:
      profile: web
      count: 1
"#;

#[test]
fn parse_sdl_price_ceilings_reads_every_deployed_service_price() {
    let ceilings = parse_sdl_price_ceilings(PRICED_SDL).expect("a fully-priced SDL parses");
    assert_eq!(ceilings.get("web"), Some(&("uakt".to_string(), 1000.0)));
    let (denom, total) = sdl_ceiling_total(&ceilings).unwrap();
    assert_eq!(denom, "uakt");
    assert_eq!(total, 1000.0);
}

#[test]
fn parse_sdl_price_ceilings_refuses_an_unpriced_service() {
    // A deployed service with no placement pricing → the pre-bid gate must refuse (no unbounded spend).
    let sdl = PRICED_SDL.replace(
        "      pricing:\n        web:\n          denom: uakt\n          amount: 1000\n",
        "",
    );
    let err = parse_sdl_price_ceilings(&sdl).unwrap_err();
    assert!(err.contains("unpriced"), "got: {err}");
}

#[test]
fn parse_sdl_price_ceilings_refuses_a_zero_or_unparseable_bound() {
    let zero = PRICED_SDL.replace("amount: 1000", "amount: 0");
    assert!(parse_sdl_price_ceilings(&zero)
        .unwrap_err()
        .contains("not_positive"));
    assert!(parse_sdl_price_ceilings("::: not yaml :::").is_err());
    // An SDL that deploys nothing is refused.
    assert!(parse_sdl_price_ceilings("version: \"2.0\"\n").is_err());
}

#[test]
fn sdl_ceiling_total_refuses_disallowed_or_mixed_denoms() {
    let mut mixed = std::collections::BTreeMap::new();
    mixed.insert("a".to_string(), ("uakt".to_string(), 500.0));
    mixed.insert("b".to_string(), ("uusdc".to_string(), 500.0));
    assert!(sdl_ceiling_total(&mixed)
        .unwrap_err()
        .contains("mixed_denoms"));
    let mut weird = std::collections::BTreeMap::new();
    weird.insert("a".to_string(), ("uxyz".to_string(), 500.0));
    assert!(sdl_ceiling_total(&weird)
        .unwrap_err()
        .contains("denom_not_allowed"));
}

#[test]
fn parse_pinned_bid_priced_extracts_price_and_denom() {
    let resp = json!({
        "data": { "data": [
            { "bid": { "id": { "gseq": 1, "oseq": 2, "provider": "akash1prov" }, "price": { "amount": "750", "denom": "uakt" } } }
        ]}
    });
    let (bid, amount, denom) = parse_pinned_bid_priced(&resp, "akash1prov").unwrap();
    assert_eq!(bid.provider, "akash1prov");
    assert_eq!(amount, 750.0);
    assert_eq!(denom, "uakt");
    assert!(parse_pinned_bid_priced(&resp, "absent").is_none());
}

#[test]
fn bid_passes_ceiling_enforces_denom_and_amount() {
    assert!(bid_passes_ceiling(750.0, "uakt", "uakt", 1000.0).is_ok());
    assert!(bid_passes_ceiling(1000.0, "uakt", "uakt", 1000.0).is_ok()); // equal is allowed
    assert!(bid_passes_ceiling(1001.0, "uakt", "uakt", 1000.0)
        .unwrap_err()
        .contains("over_ceiling"));
    assert!(bid_passes_ceiling(500.0, "uusdc", "uakt", 1000.0)
        .unwrap_err()
        .contains("denom_mismatch"));
}
