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

// ----- C7 Stage A/B: single-group SDL ceiling (exact decimal) + bid ceiling checks -----

use rust_decimal::Decimal;

// The honest C7 shape: one service, one placement, one compute profile, count == 1, uact.
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
          denom: uact
          amount: 1000
deployment:
  web:
    dcloud:
      profile: web
      count: 1
"#;

#[test]
fn parse_c7_sdl_ceiling_reads_the_single_group_price_exactly() {
    let (denom, amount) = parse_c7_sdl_ceiling(PRICED_SDL).expect("the single-group SDL parses");
    assert_eq!(denom, "uact");
    assert_eq!(amount, Decimal::from(1000));
}

#[test]
fn pricing_is_looked_up_by_compute_profile_not_service_name() {
    // Service name "app" references compute profile "svc"; the price lives under the PROFILE.
    // A service-name lookup would miss it and refuse — so a pass proves profile-based lookup.
    let sdl = r#"
version: "2.0"
services:
  app:
    image: nginx:alpine
profiles:
  compute:
    svc:
      resources:
        cpu: { units: 0.1 }
        memory: { size: 128Mi }
        storage: { size: 128Mi }
  placement:
    dcloud:
      pricing:
        svc:
          denom: uact
          amount: 500
deployment:
  app:
    dcloud:
      profile: svc
      count: 1
"#;
    let (denom, amount) = parse_c7_sdl_ceiling(sdl).expect("profile-keyed pricing resolves");
    assert_eq!(denom, "uact");
    assert_eq!(amount, Decimal::from(500));
}

#[test]
fn parse_c7_sdl_ceiling_refuses_departures_from_the_single_group_shape() {
    // Wrong denom (the current allowlist scar): uakt is not the accepted capstone denom.
    assert!(
        parse_c7_sdl_ceiling(&PRICED_SDL.replace("denom: uact", "denom: uakt"))
            .unwrap_err()
            .contains("denom_not_accepted")
    );
    // count != 1 → not a single order/group.
    assert!(
        parse_c7_sdl_ceiling(&PRICED_SDL.replace("count: 1", "count: 3"))
            .unwrap_err()
            .contains("count_not_one")
    );
    // Unpriced compute profile → refuse (no unbounded spend).
    assert!(parse_c7_sdl_ceiling(&PRICED_SDL.replace(
        "        web:\n          denom: uact\n          amount: 1000\n",
        ""
    ))
    .unwrap_err()
    .contains("unpriced"));
    // References a compute profile that is not defined.
    assert!(
        parse_c7_sdl_ceiling(&PRICED_SDL.replace("profile: web", "profile: ghost"))
            .unwrap_err()
            .contains("profile_absent")
    );
    // A second deployed service → multi-group, refused.
    let two_service = PRICED_SDL.replace(
        "deployment:\n  web:\n    dcloud:\n      profile: web\n      count: 1\n",
        "deployment:\n  web:\n    dcloud:\n      profile: web\n      count: 1\n  web2:\n    dcloud:\n      profile: web\n      count: 1\n",
    );
    assert!(parse_c7_sdl_ceiling(&two_service)
        .unwrap_err()
        .contains("not_single_group"));
    // A second placement on the one service → multi-group, refused.
    let two_placement = PRICED_SDL.replace(
        "  web:\n    dcloud:\n      profile: web\n      count: 1\n",
        "  web:\n    dcloud:\n      profile: web\n      count: 1\n    dcloud2:\n      profile: web\n      count: 1\n",
    );
    assert!(parse_c7_sdl_ceiling(&two_placement)
        .unwrap_err()
        .contains("not_single_placement"));
}

#[test]
fn parse_c7_sdl_ceiling_refuses_bad_amounts_and_bad_yaml() {
    // Zero / non-positive.
    assert!(
        parse_c7_sdl_ceiling(&PRICED_SDL.replace("amount: 1000", "amount: 0"))
            .unwrap_err()
            .contains("not_positive")
    );
    // A YAML FLOAT (incl. .inf) is refused — money is never an f64.
    assert!(
        parse_c7_sdl_ceiling(&PRICED_SDL.replace("amount: 1000", "amount: 1000.5"))
            .unwrap_err()
            .contains("not_exact")
    );
    assert!(
        parse_c7_sdl_ceiling(&PRICED_SDL.replace("amount: 1000", "amount: .inf"))
            .unwrap_err()
            .contains("not_exact")
    );
    // Overlarge amount.
    assert!(
        parse_c7_sdl_ceiling(&PRICED_SDL.replace("amount: 1000", "amount: 2000000000"))
            .unwrap_err()
            .contains("overlarge")
    );
    // Unparseable / no deployment.
    assert!(parse_c7_sdl_ceiling("::: not yaml :::").is_err());
    assert!(parse_c7_sdl_ceiling("version: \"2.0\"\n").is_err());
}

#[test]
fn duplicate_keys_resolve_last_wins_consistently_with_what_akash_receives() {
    // serde_yaml_ng resolves a duplicate mapping key last-wins (it does not error). That is SAFE
    // for the spend gate: the daemon sends the EXACT same sdl_yaml string to Akash (bound by the
    // SDL-hash), so the validator's ceiling is exactly what Akash prices against — a duplicate can
    // only raise the deployer's OWN ceiling, which the deposit cap still bounds. This test pins
    // that determinism so a future parser swap that changes the resolution is caught.
    let dup = PRICED_SDL.replace(
        "          denom: uact\n          amount: 1000\n",
        "          denom: uact\n          amount: 1000\n          amount: 900\n",
    );
    let (denom, amount) = parse_c7_sdl_ceiling(&dup).expect("last-wins resolves to a valid group");
    assert_eq!(denom, "uact");
    assert_eq!(
        amount,
        Decimal::from(900),
        "last-wins takes the final amount"
    );
}

#[test]
fn parse_c7_sdl_ceiling_bounds_the_yaml() {
    // Oversized SDL.
    let huge = format!("{PRICED_SDL}{}", "#".repeat(20 * 1024));
    assert!(parse_c7_sdl_ceiling(&huge)
        .unwrap_err()
        .contains("too_large"));
    // Anchors/aliases (expansion vector) are refused.
    let aliased = PRICED_SDL.replace("version: \"2.0\"", "version: &v \"2.0\"");
    assert!(parse_c7_sdl_ceiling(&aliased)
        .unwrap_err()
        .contains("alias_forbidden"));
}

#[test]
fn parse_pinned_bid_priced_extracts_exact_price_and_denom() {
    let resp = json!({
        "data": { "data": [
            { "bid": { "id": { "gseq": 1, "oseq": 2, "provider": "akash1prov" }, "price": { "amount": "750", "denom": "uact" } } }
        ]}
    });
    let (bid, amount, denom) = parse_pinned_bid_priced(&resp, "akash1prov")
        .expect("provider bid present")
        .expect("bid price readable");
    assert_eq!(bid.provider, "akash1prov");
    assert_eq!(bid.gseq, 1);
    assert_eq!(bid.oseq, 2);
    assert_eq!(amount, Decimal::from(750));
    assert_eq!(denom, "uact");
    // A provider that did not bid → None (not an error).
    assert!(parse_pinned_bid_priced(&resp, "absent").is_none());
    // A malformed bid price → Some(Err) (Stage B refuses + closes).
    let bad = json!({
        "data": { "data": [
            { "bid": { "id": { "gseq": 1, "oseq": 2, "provider": "akash1prov" }, "price": { "amount": 1.5, "denom": "uact" } } }
        ]}
    });
    assert!(parse_pinned_bid_priced(&bad, "akash1prov")
        .unwrap()
        .is_err());
}

#[test]
fn bid_passes_ceiling_enforces_denom_and_amount_exactly() {
    let c = Decimal::from(1000);
    assert!(bid_passes_ceiling(Decimal::from(750), "uact", "uact", c).is_ok());
    assert!(bid_passes_ceiling(Decimal::from(1000), "uact", "uact", c).is_ok()); // equal allowed
    assert!(bid_passes_ceiling(Decimal::from(1001), "uact", "uact", c)
        .unwrap_err()
        .contains("over_ceiling"));
    // A denomination change is a circuit-breaker → refuse (never auto-accept a fallback).
    assert!(bid_passes_ceiling(Decimal::from(500), "uakt", "uact", c)
        .unwrap_err()
        .contains("denom_mismatch"));
}

#[test]
fn deployment_has_auto_topup_detects_any_enabled_representation() {
    // A compliant one-time-deposit deployment carries no enabled auto-top-up → provably off.
    assert!(!deployment_has_auto_topup(
        &json!({ "data": { "deployment": { "state": "active", "deposit": "1000000" } } })
    ));
    // Enabled representations anywhere in the detail are caught (bool, string, nested object).
    assert!(deployment_has_auto_topup(&json!({ "autoTopUp": true })));
    assert!(deployment_has_auto_topup(
        &json!({ "data": { "auto_top_up": "enabled" } })
    ));
    assert!(deployment_has_auto_topup(
        &json!({ "settings": { "auto-refill": { "threshold": 5 } } })
    ));
    // A present-but-off flag is not "on".
    assert!(!deployment_has_auto_topup(&json!({ "autoTopup": false })));
}
