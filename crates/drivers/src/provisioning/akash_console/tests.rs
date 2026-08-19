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
