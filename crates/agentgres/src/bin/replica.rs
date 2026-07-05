//! Standalone log-shipping replica for the Agentgres substrate.
//!
//! Receives batch bytes from a primary's replicate-then-ack writer and
//! appends them to its own byte-identical mux log. The directory is a
//! valid engine dir: open it with `MuxEngine::open` to replay heads/roots
//! or to serve as a recovery source.
//!
//! Env: REPLICA_ADDR (default 127.0.0.1:9931), REPLICA_DIR (required),
//! FLUSH_MS (background fdatasync interval, default 200).

use agentgres::replica::ReplicaServer;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let addr = std::env::var("REPLICA_ADDR").unwrap_or_else(|_| "127.0.0.1:9931".into());
    let dir: PathBuf = PathBuf::from(std::env::var("REPLICA_DIR").expect("REPLICA_DIR required"));
    let flush_ms: u64 = std::env::var("FLUSH_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(200);
    let server = ReplicaServer::bind(&addr, &dir, flush_ms)?;
    eprintln!("substrate-replica: listening on {} -> {}", server.local_addr()?, dir.display());
    server.serve_forever()
}
