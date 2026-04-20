use super::{
    classify_domain, filesystem_scope_paths, network_host, network_url, wallet_approval_token_ref,
    wallet_eei_bundle, wallet_tx_hash, RrsaDomain,
};
use ioi_types::app::agentic::AgentTool;
use serde_json::json;

#[test]
fn classify_domain_maps_fs_write_to_filesystem() {
    let tool = AgentTool::FsWrite {
        path: "a.txt".to_string(),
        content: "hello".to_string(),
        line_number: None,
    };
    assert!(matches!(
        classify_domain(&tool),
        Some(RrsaDomain::Filesystem)
    ));
}

#[test]
fn classify_domain_maps_net_fetch_to_network() {
    let tool = AgentTool::NetFetch {
        url: "https://example.com".to_string(),
        max_chars: None,
    };
    assert!(matches!(classify_domain(&tool), Some(RrsaDomain::Network)));
}

#[test]
fn network_url_uses_tool_argument_when_present() {
    let tool = AgentTool::WebSearch {
        query: "internet of intelligence".to_string(),
        query_contract: None,
        retrieval_contract: None,
        limit: None,
        url: None,
    };
    let args = json!({ "url": "https://example.org/path?q=1" });
    assert_eq!(
        network_url(&tool, &args).as_deref(),
        Some("https://example.org/path?q=1")
    );
}

#[test]
fn network_url_falls_back_to_web_search_serp_url() {
    let tool = AgentTool::WebSearch {
        query: "internet of intelligence".to_string(),
        query_contract: None,
        retrieval_contract: None,
        limit: Some(5),
        url: None,
    };
    let args = json!({});
    let resolved = network_url(&tool, &args).expect("web search fallback URL");
    assert!(resolved.starts_with("https://"));
    assert!(resolved.contains("internet+of+intelligence"));
}

#[test]
fn network_host_normalizes_case() {
    let host = network_host("https://WWW.Example.COM/path").expect("host");
    assert_eq!(host, "www.example.com");
}

#[test]
fn filesystem_scope_paths_extracts_primary_and_secondary_paths() {
    let args = json!({
        "path": "/tmp/a.txt",
        "source_path": "/tmp/src.txt",
        "destination_path": "/tmp/dst.txt",
        "destination_zip_path": "/tmp/archive.zip"
    });
    let mut paths = filesystem_scope_paths(&args);
    paths.sort();
    assert_eq!(
        paths,
        vec![
            "/tmp/a.txt".to_string(),
            "/tmp/archive.zip".to_string(),
            "/tmp/dst.txt".to_string(),
            "/tmp/src.txt".to_string()
        ]
    );
}

#[test]
fn wallet_tx_hash_prefers_tool_args_then_history_json() {
    let args = json!({ "tx_hash": "0xabc123" });
    let history = Some(r#"{"tx_hash":"0xdef456"}"#);
    assert_eq!(wallet_tx_hash(&args, history).as_deref(), Some("0xabc123"));

    let args_without_hash = json!({});
    assert_eq!(
        wallet_tx_hash(&args_without_hash, history).as_deref(),
        Some("0xdef456")
    );
}

#[test]
fn wallet_approval_ref_extracts_from_args() {
    let args = json!({ "approval_token_ref": "sha256:deadbeef" });
    assert_eq!(
        wallet_approval_token_ref(&args, None).as_deref(),
        Some("sha256:deadbeef")
    );
}

#[test]
fn wallet_eei_bundle_accepts_object_and_json_string() {
    let args_obj = json!({
        "eei_bundle": {
            "chain": "ethereum",
            "block": 12345
        }
    });
    assert!(wallet_eei_bundle(&args_obj, None).is_some());

    let args_str = json!({
        "eei_bundle": "{\"chain\":\"solana\",\"slot\":99}"
    });
    let bundle = wallet_eei_bundle(&args_str, None).expect("bundle");
    assert_eq!(bundle.get("chain").and_then(|v| v.as_str()), Some("solana"));
}
