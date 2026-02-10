// Path: crates/node/build.rs

use std::env;
use std::path::Path;
use std::fs;

fn main() {
    println!("cargo:rerun-if-env-changed=IOI_PACK_MANIFEST");
    println!("cargo:rerun-if-env-changed=IOI_PACK_ASSETS");

    // If packing, read from env. If not (normal build), use defaults/dummy.
    let manifest_path = env::var("IOI_PACK_MANIFEST").unwrap_or_else(|_| "presets/default_agent_workflow.toml".to_string());
    
    // [FIX] Prefix with underscore to silence unused variable warning
    let _assets_path = env::var("IOI_PACK_ASSETS").unwrap_or_else(|_| "src/embedded_assets".to_string());
    
    // Validate existence (fail build if packing but missing files)
    if env::var("IOI_PACK_MANIFEST").is_ok() && !Path::new(&manifest_path).exists() {
        panic!("IOI Pack Error: Manifest file not found at {}", manifest_path);
    }
    
    // Copy to OUT_DIR for inclusion by the binary
    // This allows including assets without mutating the source tree during build
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_manifest = Path::new(&out_dir).join("embedded_manifest.toml");
    
    if Path::new(&manifest_path).exists() {
        fs::copy(&manifest_path, &dest_manifest).expect("Failed to copy manifest");
    } else {
        // Create dummy for default build
        fs::write(&dest_manifest, "").unwrap();
    }
    
    // Note: rust-embed handles the assets folder via #[folder = "..."] attribute in code.
    // Ideally we'd dynamically set that path, but rust-embed macro runs before build script output is available in code attributes in some cases.
    // Standard workaround: Symlink or Copy the target assets to a fixed location expected by the macro, 
    // OR just ensure the macro points to `target/ioi-pack/assets` and we populate that.
    
    // For this implementation, we assume `pack` populates `target/ioi-pack/assets` 
    // and the macro points there.
}