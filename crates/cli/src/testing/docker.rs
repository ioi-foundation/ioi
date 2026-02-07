// Path: crates/cli/src/testing/docker.rs

use anyhow::{anyhow, Result};
// [FIX] Update imports
use bollard::{image::BuildImageOptions, Docker};
use bytes::Bytes;
use futures_util::StreamExt;
// [FIX] We can pass bytes directly to build_image in newer bollard, it takes Into<Body>
// use http_body_util::{Either, Full}; 
use std::path::Path;
use tar::Builder;
use tokio::sync::OnceCell;

// --- Docker Configuration ---
pub(crate) const DOCKER_IMAGE_TAG: &str = "ioi-node:e2e";
pub(crate) static DOCKER_BUILD_CHECK: OnceCell<()> = OnceCell::const_new();

/// Checks if the test Docker image exists and builds it if it doesn't.
pub(crate) async fn ensure_docker_image_exists() -> Result<()> {
    let docker = Docker::connect_with_local_defaults()?;
    match docker.inspect_image(DOCKER_IMAGE_TAG).await {
        Ok(_) => {
            println!(
                "--- Docker image '{}' found locally. Skipping build. ---",
                DOCKER_IMAGE_TAG
            );
            return Ok(());
        }
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => {
            println!(
                "--- Docker image '{}' not found. Building... ---",
                DOCKER_IMAGE_TAG
            );
        }
        Err(e) => return Err(e.into()),
    };

    let context_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let tar_bytes = {
        let mut bytes = Vec::new();
        {
            let mut ar = Builder::new(&mut bytes);
            ar.append_dir_all(".", context_dir)?;
            ar.finish()?;
        }
        bytes
    };
    // bollard expects Into<Either<Full<Bytes>, StreamBody<...>>>.
    // Use a single Full body from the in-memory tar.
    // [FIX] Pass Bytes directly. Bollard handles the body conversion.
    let image_body = Bytes::from(tar_bytes);

    // [FIX] Use struct init
    let options = BuildImageOptions {
        dockerfile: "crates/node/Dockerfile".to_string(),
        t: DOCKER_IMAGE_TAG.to_string(),
        rm: true,
        ..Default::default()
    };

    let mut build_stream = docker.build_image(options, None, Some(image_body));
    while let Some(chunk) = build_stream.next().await {
        match chunk {
            Ok(info) => {
                if let Some(stream_content) = info.stream {
                    print!("{}", stream_content);
                }
                if let Some(err) = info.error {
                    return Err(anyhow!("Image build error: {}", err));
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    println!("--- Docker image built successfully. ---");
    Ok(())
}