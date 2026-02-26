#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;

mod capabilities_suite;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live internet + external inference required"]
async fn capabilities_query_suite_e2e() -> Result<()> {
    capabilities_suite::run_capabilities_suite().await
}
