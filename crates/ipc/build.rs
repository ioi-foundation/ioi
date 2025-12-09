// Path: crates/ipc/build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Control plane (unchanged)
    tonic_build::compile_protos("proto/control.proto")?;

    // Compile blockchain and public together to allow relative resolution
    tonic_build::configure().compile(
        &["proto/blockchain.proto", "proto/public.proto"],
        &["proto"],
    )?;

    Ok(())
}
