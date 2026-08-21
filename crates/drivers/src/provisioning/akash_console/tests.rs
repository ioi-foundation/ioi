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
fn cheapest_qualified_bid_enforces_exact_denom_and_ceiling() {
    let bids = json!({ "data": [
        { "bid": { "id": { "gseq": 1, "oseq": 1, "provider": "over" }, "price": { "amount": "1001", "denom": "uact" } } },
        { "bid": { "id": { "gseq": 1, "oseq": 2, "provider": "wrong" }, "price": { "amount": "1", "denom": "uakt" } } },
        { "bid": { "id": { "gseq": 1, "oseq": 3, "provider": "qualified" }, "price": { "amount": "999", "denom": "uact" } } }
    ] });
    assert_eq!(
        parse_cheapest_qualified_bid(&bids, "uact", 1000.0)
            .expect("one qualified bid")
            .provider,
        "qualified"
    );
    assert!(parse_cheapest_qualified_bid(&bids, "uact", 998.0).is_none());
}

#[test]
fn settlement_requires_closed_provider_readback_and_computes_zero_debit_refund() {
    let detail = json!({ "data": {
        "deployment": { "state": "closed" },
        "escrow_account": { "state": {
            "state": "closed", "settled_at": "28269748",
            "funds": [{ "amount": "0.000000000000000000", "denom": "uact" }],
            "transferred": [{ "amount": "0.000000000000000000", "denom": "uact" }]
        }},
        "leases": []
    }});
    let settled = parse_settlement_readback(&detail, 1.0);
    assert_eq!(settled["settlement_state"], "refund_settled");
    assert_eq!(settled["provider_terminal"], true);
    assert_eq!(settled["final_debit_usd"], 0.0);
    assert_eq!(settled["refund_usd"], 1.0);

    let mut pending = detail;
    pending["data"]["escrow_account"]["state"]["settled_at"] = Value::Null;
    assert_eq!(
        parse_settlement_readback(&pending, 1.0)["settlement_state"],
        "reconciliation_required"
    );
}

#[test]
fn positive_branch_requires_active_lease_and_provider_reported_endpoint() {
    let detail = json!({ "data": { "leases": [{
        "id": { "dseq": "1", "gseq": 1, "oseq": 1, "provider": "akash1provider" },
        "state": "active",
        "status": { "services": { "web": { "uris": ["https://example.invalid"], "available_replicas": 1 } }, "forwarded_ports": {}, "ips": {} }
    }] }});
    let endpoint = parse_ready_lease_endpoint(&detail).expect("active live service endpoint");
    assert_eq!(endpoint["provider_address"], "akash1provider");
    let mut pending = detail;
    pending["data"]["leases"][0]["status"]["services"]["web"]["uris"] = json!([]);
    pending["data"]["leases"][0]["status"]["services"]["web"]["available_replicas"] = json!(0);
    assert!(parse_ready_lease_endpoint(&pending).is_none());
}

#[test]
fn endpoint_discovery_does_not_inflate_zero_ready_replicas() {
    let detail = json!({ "data": { "leases": [{
        "id": { "dseq": "1", "gseq": 1, "oseq": 1, "provider": "akash1provider" },
        "state": "active",
        "status": { "services": { "web": {
            "uris": ["https://example.invalid"],
            "replicas": 1,
            "ready_replicas": 0,
            "available_replicas": 0
        } }, "forwarded_ports": {}, "ips": {} }
    }] }});
    let endpoint = parse_active_lease_endpoint(&detail).expect("URI is endpoint discovery");
    assert_eq!(endpoint["endpoint_discovered"], true);
    assert_eq!(endpoint["service_uri_present"], true);
    assert_eq!(endpoint["desired_replicas"], 1);
    assert_eq!(endpoint["ready_replicas"], 0);
    assert_eq!(endpoint["workload_readiness_proven"], false);
    assert!(parse_ready_lease_endpoint(&detail).is_none());
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
fn pinned_qualified_bid_enforces_provider_denom_and_ceiling_together() {
    let resp = json!({ "data": [
        { "bid": { "id": { "gseq": 1, "oseq": 1, "provider": "akash1exact" }, "price": { "amount": "999", "denom": "uact" } } },
        { "bid": { "id": { "gseq": 1, "oseq": 2, "provider": "akash1cheap" }, "price": { "amount": "1", "denom": "uact" } } }
    ] });
    let exact = parse_pinned_qualified_bid(&resp, "akash1exact", "uact", 1000.0)
        .expect("exact provider is within the approved ceiling");
    assert_eq!(exact.provider, "akash1exact");
    assert!(parse_pinned_qualified_bid(&resp, "akash1exact", "uact", 998.0).is_none());
    assert!(parse_pinned_qualified_bid(&resp, "akash1exact", "uakt", 1000.0).is_none());
    assert!(parse_pinned_qualified_bid(&resp, "akash1missing", "uact", 1000.0).is_none());
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
