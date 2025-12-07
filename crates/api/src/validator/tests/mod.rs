// Path: crates/api/src/validator/tests/mod.rs
//! Tests for validator architecture trait definitions

#[cfg(test)]
mod tests {
    use crate::validator::container::GuardianContainer;
    use crate::validator::{Container, ValidatorModel, ValidatorType};
    use async_trait::async_trait;
    use ioi_types::config::ValidatorRole;
    use ioi_types::error::ValidatorError;

    // Mock container implementation for testing
    #[derive(Debug)]
    struct MockContainer {
        id: &'static str,
        running: bool,
    }

    impl MockContainer {
        fn new(id: &'static str) -> Self {
            Self { id, running: false }
        }
    }

    #[async_trait]
    impl Container for MockContainer {
        fn id(&self) -> &'static str {
            self.id
        }

        fn is_running(&self) -> bool {
            self.running
        }

        async fn start(&self, _listen_addr: &str) -> Result<(), ValidatorError> {
            Ok(())
        }

        async fn stop(&self) -> Result<(), ValidatorError> {
            Ok(())
        }
    }

    // Mock guardian container implementation for testing
    #[derive(Debug)]
    struct MockGuardianContainer {
        container: MockContainer,
    }

    impl MockGuardianContainer {
        fn new(id: &'static str) -> Self {
            Self {
                container: MockContainer::new(id),
            }
        }
    }

    #[async_trait]
    impl Container for MockGuardianContainer {
        fn id(&self) -> &'static str {
            self.container.id()
        }

        fn is_running(&self) -> bool {
            self.container.is_running()
        }

        async fn start(&self, addr: &str) -> Result<(), ValidatorError> {
            self.container.start(addr).await
        }

        async fn stop(&self) -> Result<(), ValidatorError> {
            self.container.stop().await
        }
    }

    impl GuardianContainer for MockGuardianContainer {
        fn start_boot(&self) -> Result<(), ValidatorError> {
            Ok(())
        }

        fn verify_attestation(&self) -> Result<bool, ValidatorError> {
            Ok(true)
        }
    }

    // Mock validator model implementation for testing
    struct MockStandardValidator {
        guardian: MockGuardianContainer,
        orchestration: MockContainer,
        workload: MockContainer,
        running: bool,
        role: ValidatorRole,
    }

    impl MockStandardValidator {
        fn new() -> Self {
            Self {
                guardian: MockGuardianContainer::new("guardian"),
                orchestration: MockContainer::new("orchestration"),
                workload: MockContainer::new("workload"),
                running: false,
                role: ValidatorRole::Consensus,
            }
        }
    }

    impl ValidatorModel for MockStandardValidator {
        type WorkloadContainerType = MockContainer;

        fn start(&self) -> Result<(), ValidatorError> {
            // Note: In real impl these are async, but ValidatorModel::start is sync
            // typically spawning tasks. For mock we just return Ok.
            Ok(())
        }

        fn stop(&self) -> Result<(), ValidatorError> {
            Ok(())
        }

        fn is_running(&self) -> bool {
            self.running
        }

        fn validator_type(&self) -> ValidatorType {
            ValidatorType::Standard
        }

        fn role(&self) -> ValidatorRole {
            self.role.clone()
        }

        fn workload_container(&self) -> &Self::WorkloadContainerType {
            &self.workload
        }
    }

    // Mock hybrid validator implementation for testing
    struct MockHybridValidator {
        guardian: MockGuardianContainer,
        orchestration: MockContainer,
        workload: MockContainer,
        interface: MockContainer,
        api: MockContainer,
        running: bool,
        role: ValidatorRole,
    }

    impl MockHybridValidator {
        fn new() -> Self {
            Self {
                guardian: MockGuardianContainer::new("guardian"),
                orchestration: MockContainer::new("orchestration"),
                workload: MockContainer::new("workload"),
                interface: MockContainer::new("interface"),
                api: MockContainer::new("api"),
                running: false,
                role: ValidatorRole::Consensus,
            }
        }
    }

    impl ValidatorModel for MockHybridValidator {
        type WorkloadContainerType = MockContainer;

        fn start(&self) -> Result<(), ValidatorError> {
            Ok(())
        }

        fn stop(&self) -> Result<(), ValidatorError> {
            Ok(())
        }

        fn is_running(&self) -> bool {
            self.running
        }

        fn validator_type(&self) -> ValidatorType {
            ValidatorType::Hybrid
        }

        fn role(&self) -> ValidatorRole {
            self.role.clone()
        }

        fn workload_container(&self) -> &Self::WorkloadContainerType {
            &self.workload
        }
    }

    #[tokio::test]
    async fn test_container() {
        let container = MockContainer::new("test-container");

        assert_eq!(container.id(), "test-container");
        assert!(!container.is_running());

        container.start("addr").await.unwrap();
        container.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_guardian_container() {
        let guardian = MockGuardianContainer::new("guardian");

        assert_eq!(guardian.id(), "guardian");
        assert!(!guardian.is_running());

        guardian.start("addr").await.unwrap();
        guardian.start_boot().unwrap();
        assert!(guardian.verify_attestation().unwrap());
        guardian.stop().await.unwrap();
    }

    #[test]
    fn test_standard_validator() {
        let validator = MockStandardValidator::new();

        assert_eq!(validator.validator_type(), ValidatorType::Standard);
        assert_eq!(validator.role(), ValidatorRole::Consensus);
        assert!(!validator.is_running());

        validator.start().unwrap();
        validator.stop().unwrap();
    }

    #[test]
    fn test_hybrid_validator() {
        let validator = MockHybridValidator::new();

        assert_eq!(validator.validator_type(), ValidatorType::Hybrid);
        assert_eq!(validator.role(), ValidatorRole::Consensus);
        assert!(!validator.is_running());

        validator.start().unwrap();
        validator.stop().unwrap();
    }

    #[test]
    fn test_validator_role_defaults() {
        let v1 = MockStandardValidator::new();
        assert_eq!(v1.role(), ValidatorRole::Consensus);
    }
}
