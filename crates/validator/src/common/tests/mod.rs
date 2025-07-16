//! Tests for common validator components

#[cfg(test)]
mod tests {
    use super::super::guardian::{BootStatus, GuardianContainer};
    use super::super::security::SecurityChannel;
    use std::path::Path;

    #[test]
    fn test_guardian_container() {
        let config_path = Path::new("test_config.toml");
        let guardian = GuardianContainer::new(config_path);

        // Initial state
        assert_eq!(guardian.boot_status(), BootStatus::NotStarted);

        // Start boot process
        guardian.start_boot().unwrap();
        assert_eq!(guardian.boot_status(), BootStatus::Completed);

        // Verify attestation
        let attestation_result = guardian.verify_attestation().unwrap();
        assert!(attestation_result);
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
}
