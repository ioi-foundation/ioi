//! Standard validator binary

use depin_sdk_core::validator::{Container, ValidatorModel};
use depin_sdk_validator::standard::StandardValidator;
use std::env;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    let container_type = if args.len() > 1 { &args[1] } else { "all" };

    // Default config directory is ./config
    let config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| "./config".to_string());

    println!("Starting DePIN SDK Standard Validator");
    println!("Container type: {}", container_type);
    println!("Config directory: {}", config_dir);

    match container_type {
        "guardian" => {
            // Start only the guardian container
            let path = Path::new(&config_dir);
            let guardian =
                depin_sdk_validator::common::GuardianContainer::new(path.join("guardian.toml"))?;
            guardian.start()?;

            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
        "orchestration" => {
            // Start only the orchestration container
            let path = Path::new(&config_dir);
            let orchestration = depin_sdk_validator::standard::OrchestrationContainer::new(
                path.join("orchestration.toml"),
            )?;
            orchestration.start()?;

            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
        "workload" => {
            // Start only the workload container
            let path = Path::new(&config_dir);
            let workload =
                depin_sdk_validator::standard::WorkloadContainer::new(path.join("workload.toml"))?;
            workload.start()?;

            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
        // Fixed: Separate "all" case from wildcard pattern to avoid Clippy warning
        "all" => {
            // Start the full validator
            let path = Path::new(&config_dir);
            let validator = StandardValidator::new(path)?;
            validator.start()?;

            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
        _ => {
            // Default to full validator for any other input
            let path = Path::new(&config_dir);
            let validator = StandardValidator::new(path)?;
            validator.start()?;

            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}