//! Tests for common validator components

use super::guardian::GuardianContainer;
use super::security::SecurityChannel;
// FIX: Import the traits to make their methods available.
use depin_sdk_core::validator::{Container, GuardianContainer as GuardianContainerTrait};
use std::path::Path;

#[tokio::test]
async fn test_guardian_container() {
    let config_path = Path::new("test_config.toml");
    // FIX: The constructor now returns a Result, so we need to unwrap it.
    let guardian = GuardianContainer::new(config_path).unwrap();

    // Initial state
    assert!(!guardian.is_running());

    // Start the container
    guardian.start().await.unwrap();
    assert!(guardian.is_running());

    // Test trait methods
    guardian.start_boot().unwrap();
    let attestation_result = guardian.verify_attestation().unwrap();
    assert!(attestation_result);

    // Stop the container
    guardian.stop().await.unwrap();
    assert!(!guardian.is_running());
}

#[test]
fn test_security_channel() {
    let channel = SecurityChannel::new("test_source", "test_destination");

    assert_eq!(channel.source, "test_source");
    assert_eq!(channel.destination, "test_destination");
    assert_eq!(channel.channel_id, "test_source:test_destination");

    // Test establish
    channel.establish().unwrap();

    // Test send and receive
    let data = vec![1, 2, 3, 4];
    channel.send(&data).unwrap();

    let received = channel.receive(10).unwrap();
    // In our implementation, receive returns empty data for testing
    assert_eq!(received.len(), 0);
}
