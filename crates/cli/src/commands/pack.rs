// Path: crates/cli/src/commands/pack.rs

use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::PathBuf;
use std::process::Command;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::codec;

#[derive(Parser, Debug)]
pub struct PackArgs {
    #[clap(long)]
    pub manifest: PathBuf,
    #[clap(long)]
    pub ui_dir: Option<PathBuf>,
    #[clap(long, default_value = "ioi-agent")]
    pub out: String,
}

pub fn run(args: PackArgs) -> Result<()> {
    println!("📦 Packaging IOI Service-as-a-Software...");

    // 1. Prepare Build Area (don't pollute src)
    let build_root = PathBuf::from("target/ioi-pack");
    if build_root.exists() { std::fs::remove_dir_all(&build_root)?; }
    std::fs::create_dir_all(&build_root)?;
    
    let assets_dir = build_root.join("assets");
    std::fs::create_dir_all(&assets_dir)?;

    // 2. Process UI Assets & Compute Merkle Root
    let mut ui_root = [0u8; 32]; // Default zero if no UI
    if let Some(ui) = args.ui_dir {
        // Copy assets
        let status = Command::new("cp").arg("-r").arg(format!("{}/.", ui.to_string_lossy())).arg(&assets_dir).status()?;
        if !status.success() { return Err(anyhow!("Failed to copy UI")); }
        
        // Compute Simple Merkle Root of assets (for integrity)
        ui_root = compute_dir_hash(&assets_dir)?;
    } else {
        // Dummy index.html
        std::fs::write(assets_dir.join("index.html"), "<h1>Headless Agent</h1>")?;
    }

    // 3. Load & Patch Manifest
    let content = std::fs::read_to_string(&args.manifest)?;
    let mut manifest: ioi_types::app::agentic::AgentManifest = toml::from_str(&content)?;
    
    // Inject UI Integrity Root
    manifest.ui_assets_root = ui_root;
    
    // Save patched manifest
    let patched_manifest_path = build_root.join("manifest.toml");
    std::fs::write(&patched_manifest_path, toml::to_string(&manifest)?)?;

    // 4. Calculate Final Asset Hash (This is what licenses unlock)
    let asset_bytes = codec::to_bytes_canonical(&manifest).unwrap();
    let asset_hash = sha256(&asset_bytes)?;
    println!("🔑 Asset Hash: 0x{}", hex::encode(asset_hash));

    // 5. Compile
    println!("🔨 Compiling...");
    let status = Command::new("cargo")
        .args(&["build", "--release", "--bin", "ioi-agent"])
        // Pass paths via ENV
        .env("IOI_PACK_MANIFEST", patched_manifest_path)
        .env("IOI_PACK_ASSETS", assets_dir) 
        .status()?;

    if !status.success() { return Err(anyhow!("Compilation failed")); }

    // 6. Output
    let target = PathBuf::from("target/release/ioi-agent");
    std::fs::copy(&target, &args.out)?;
    println!("✅ Built executable: ./{}", args.out);

    Ok(())
}

fn compute_dir_hash(_path: &std::path::Path) -> Result<[u8; 32]> {
    // Simple mock hash for demonstration. 
    // In prod, walk dir, hash files, sort hashes, hash list.
    // For now, return a placeholder to satisfy the type.
    Ok([0xAA; 32]) 
}