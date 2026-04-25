use anyhow::{anyhow, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverAuthorityContext {
    pub runtime_profile: String,
    pub authority_context_present: bool,
}

impl DriverAuthorityContext {
    pub fn from_env() -> Self {
        let runtime_profile = std::env::var("IOI_RUNTIME_PROFILE")
            .unwrap_or_else(|_| "dev".to_string())
            .trim()
            .to_ascii_lowercase();
        let authority_context_present = std::env::var("IOI_DRIVER_AUTHORITY_CONTEXT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .is_some()
            || std::env::var("IOI_INVOCATION_ENVELOPE_REF")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .is_some();
        Self {
            runtime_profile,
            authority_context_present,
        }
    }

    pub fn is_fail_closed_profile(&self) -> bool {
        matches!(
            self.runtime_profile.as_str(),
            "production" | "marketplace" | "validator"
        )
    }
}

pub fn assert_raw_driver_allowed(driver: &str, operation: &str) -> Result<()> {
    validate_driver_authority(&DriverAuthorityContext::from_env(), driver, operation)
}

pub fn validate_driver_authority(
    context: &DriverAuthorityContext,
    driver: &str,
    operation: &str,
) -> Result<()> {
    if context.is_fail_closed_profile() && !context.authority_context_present {
        return Err(anyhow!(
            "ERROR_CLASS=PolicyBlocked driver_authority_missing driver={} operation={} profile={}",
            driver,
            operation,
            context.runtime_profile
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_profile_rejects_raw_driver_without_authority() {
        let context = DriverAuthorityContext {
            runtime_profile: "production".to_string(),
            authority_context_present: false,
        };
        let error = validate_driver_authority(&context, "terminal", "execute")
            .expect_err("production must reject raw driver calls");
        assert!(error.to_string().contains("driver_authority_missing"));
    }

    #[test]
    fn production_profile_accepts_driver_with_authority_context() {
        let context = DriverAuthorityContext {
            runtime_profile: "production".to_string(),
            authority_context_present: true,
        };
        validate_driver_authority(&context, "terminal", "execute").expect("authority accepted");
    }
}
