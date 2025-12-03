// Path: crates/node/src/bin/signer.rs
// [FIX] Allow unsafe code for mlockall
#![allow(unsafe_code)]

use anyhow::{anyhow, Result};
use clap::Parser;
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use dcrypt::algorithms::ByteSerializable;
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use warp::Filter;

/// Configuration for the Signer binary.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct SignerOpts {
    /// Path to the signer's persistent state file (WAL).
    #[arg(long, default_value = "signer_state.bin")]
    state_file: PathBuf,

    /// Address to listen on (e.g., 127.0.0.1:3030).
    /// SECURITY: Do not bind to public interfaces (0.0.0.0) without a firewall.
    #[arg(long, default_value = "127.0.0.1:3030")]
    listen_addr: String,

    /// Path to the private key file (raw 32-byte seed).
    /// If missing, a new key will be generated and saved.
    #[arg(long, default_value = "signer_key.seed")]
    key_file: PathBuf,
}

/// The persistent state of the Oracle.
/// Must be flushed to disk physically before signing to prevent equivocation via rollback.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct OracleState {
    last_counter: u64,
    last_trace_hash: [u8; 32],
}

struct SignerContext {
    keypair: Ed25519KeyPair,
    state: OracleState,
    file: File,
}

/// Requests sent to the Oracle from the Guardian.
#[derive(Deserialize)]
struct SignRequest {
    /// The SHA-256 hash of the payload (BlockHeader preimage).
    payload_hash: String, // Hex encoded
}

/// The Oracle's response containing the signature and the binding metadata.
#[derive(Serialize)]
struct SignResponse {
    signature: String, // Hex encoded
    counter: u64,
    trace_hash: String, // Hex encoded
}

/// Locks memory to prevent swapping sensitive keys to disk.
fn secure_memory() -> Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        let result = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn load_keypair(path: &Path) -> Result<Ed25519KeyPair> {
    if path.exists() {
        let seed = std::fs::read(path)?;
        let sk = Ed25519PrivateKey::from_bytes(&seed)?;
        Ok(Ed25519KeyPair::from_private_key(&sk)?)
    } else {
        let kp = Ed25519KeyPair::generate()?;
        let seed = kp.private_key().to_bytes();

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&seed)?;
        }
        #[cfg(not(unix))]
        std::fs::write(path, &seed)?;

        Ok(kp)
    }
}

fn load_or_init_state(path: &Path) -> Result<(OracleState, File)> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    let mut content = Vec::new();
    file.read_to_end(&mut content)?;

    if content.is_empty() {
        let initial_state = OracleState {
            last_counter: 0,
            last_trace_hash: [0u8; 32],
        };
        let bytes = bincode::serialize(&initial_state)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok((initial_state, file))
    } else {
        let state: OracleState = bincode::deserialize(&content)?;
        Ok((state, file))
    }
}

/// The core critical section.
fn perform_sign(ctx: &mut SignerContext, payload_hash_hex: String) -> Result<SignResponse> {
    let payload_hash_bytes = hex::decode(&payload_hash_hex)?;
    if payload_hash_bytes.len() != 32 {
        return Err(anyhow!("Invalid payload hash length"));
    }

    // 1. Update State in Memory
    ctx.state.last_counter += 1;

    // 2. Calculate Trace: Hash(Old_Trace || Counter || Payload_Hash)
    let mut trace_input = Vec::new();
    trace_input.extend_from_slice(&ctx.state.last_trace_hash);
    trace_input.extend_from_slice(&ctx.state.last_counter.to_be_bytes());
    trace_input.extend_from_slice(&payload_hash_bytes);

    let new_trace = Sha256::digest(&trace_input).map_err(|e| anyhow!("Hashing failed: {}", e))?;
    ctx.state.last_trace_hash = new_trace.to_bytes().try_into().unwrap();

    // 3. Persist State
    let bytes = bincode::serialize(&ctx.state)?;
    ctx.file.seek(SeekFrom::Start(0))?;
    ctx.file.write_all(&bytes)?;
    ctx.file.sync_all()?;

    // 4. Sign
    let mut sig_input = Vec::new();
    sig_input.extend_from_slice(&payload_hash_bytes);
    sig_input.extend_from_slice(&ctx.state.last_counter.to_be_bytes());
    sig_input.extend_from_slice(&ctx.state.last_trace_hash);

    let sig_bytes = ctx.keypair.private_key().sign(&sig_input)?.to_bytes();

    // [FIX] Log successful signing
    tracing::info!(
        "Signed payload {} with counter {} and trace {}",
        payload_hash_hex,
        ctx.state.last_counter,
        hex::encode(ctx.state.last_trace_hash)
    );

    Ok(SignResponse {
        signature: hex::encode(sig_bytes),
        counter: ctx.state.last_counter,
        trace_hash: hex::encode(ctx.state.last_trace_hash),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    let opts = SignerOpts::parse();

    if let Err(e) = secure_memory() {
        tracing::warn!(
            "Failed to lock memory (mlockall): {}. Secrets may swap to disk.",
            e
        );
    } else {
        tracing::info!("Memory locked successfully.");
    }

    let keypair = load_keypair(&opts.key_file)?;
    let (state, file) = load_or_init_state(&opts.state_file)?;

    tracing::info!(
        "Oracle Public Key: {}",
        hex::encode(keypair.public_key().to_bytes())
    );
    tracing::info!("Current Counter: {}", state.last_counter);

    let context = Arc::new(Mutex::new(SignerContext {
        keypair,
        state,
        file,
    }));

    let sign_route = warp::post()
        .and(warp::path("sign"))
        .and(warp::body::json())
        .map(move |req: SignRequest| {
            let ctx_clone = context.clone();
            let mut guard = ctx_clone.lock().unwrap();

            match perform_sign(&mut *guard, req.payload_hash) {
                Ok(resp) => warp::reply::json(&resp),
                Err(e) => {
                    tracing::error!("Signing failure: {}", e);
                    warp::reply::json(&serde_json::json!({ "error": e.to_string() }))
                }
            }
        });

    let addr: std::net::SocketAddr = opts.listen_addr.parse()?;
    tracing::info!("IOI Signing Oracle listening on {}", addr);

    warp::serve(sign_route).run(addr).await;

    Ok(())
}
