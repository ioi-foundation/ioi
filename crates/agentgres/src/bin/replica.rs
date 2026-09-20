//! Standalone log-shipping replica for the Agentgres substrate.
//!
//! Receives batch bytes from a primary's replicate-then-ack writer and
//! appends them to its own byte-identical mux log. The directory is a
//! valid engine dir: open it with `MuxEngine::open` to replay heads/roots
//! or to serve as a recovery source.
//!
//! Env: REPLICA_ADDR (default 127.0.0.1:9931), REPLICA_DIR (required),
//! FLUSH_MS (background fdatasync interval, default 200).
//!
//! `substrate-replica promote` (M12.6, 2026-09-20): the operator-driven
//! promotion of a replica dir to the next writer epoch — opens REPLICA_DIR as
//! an engine, mints the durable `ioi.agentgres.writer-promotion.v1` record at
//! epoch+1 and prints it. A primary still at the old epoch is fenced at its
//! next handshake or mid-stream batch (INV-24 at the storage layer; the
//! System writer epoch is a separate, governed transition that this never
//! substitutes for — `agentgres/doctrine.md` § Bounded-DAS deployment binding).

use agentgres::mux::MuxEngine;
use agentgres::replica::ReplicaServer;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let dir: PathBuf = PathBuf::from(std::env::var("REPLICA_DIR").expect("REPLICA_DIR required"));
    if std::env::args().nth(1).as_deref() == Some("promote") {
        let mut engine = MuxEngine::open(&dir, true)?;
        let recorded_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let record = engine.promote(recorded_at_ms)?;
        println!("{}", serde_json::to_string_pretty(&record)?);
        return Ok(());
    }
    let addr = std::env::var("REPLICA_ADDR").unwrap_or_else(|_| "127.0.0.1:9931".into());
    let flush_ms: u64 = std::env::var("FLUSH_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let server = ReplicaServer::bind(&addr, &dir, flush_ms)?;
    eprintln!(
        "substrate-replica: listening on {} -> {}",
        server.local_addr()?,
        dir.display()
    );
    server.serve_forever()
}
