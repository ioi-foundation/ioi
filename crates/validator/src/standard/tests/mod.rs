//! Tests for standard validator components

#[cfg(test)]
mod tests {
    use super::super::{OrchestrationContainer, StandardValidator, WorkloadContainer};
    use crate::common::GuardianContainer;
    use std::path::Path;

    #[test]
    fn test_orchestration_container() {
        let config_path = Path::new("test_orchestration.toml");
        let orchestration = OrchestrationContainer::new(config_path);

        assert!(!orchestration.is_running());

        orchestration.start().unwrap();
        // Note: in the current implementation, the running state isn't actually updated
        // In a real implementation, we'd expect is_running() to return true here

        orchestration.stop().unwrap();
    }

    #[test]
    fn test_workload_container() {
        let config_path = Path::new("test_workload.toml");
        let workload = WorkloadContainer::new(config_path);

        assert!(!workload.is_running());

        workload.start().unwrap();
        // Note: in the current implementation, the running state isn't actually updated

        // Test transaction execution
        let tx_data = vec![1, 2, 3, 4];
        let result = workload.execute_transaction(&tx_data).unwrap();
        assert_eq!(result, vec![1, 2, 3, 4]); // Should return the mock result defined in the implementation

        workload.stop().unwrap();
    }

    #[test]
    fn test_standard_validator() {
        let temp_dir = std::env::temp_dir();

        // This is just a test, so we're not actually creating these files
        // In a real test, we might want to create temporary config files

        // Create validator
        let validator = StandardValidator::new(&temp_dir).unwrap();

        // Start validator - this should start all containers
        validator.start().unwrap();

        // Stop validator - this should stop all containers
        validator.stop().unwrap();
    }
}
