use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfile {
    Dev,
    Test,
    LocalProduct,
    Production,
    Marketplace,
    Validator,
}

impl RuntimeProfile {
    pub fn fail_closed(self) -> bool {
        matches!(self, Self::Production | Self::Marketplace | Self::Validator)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeProfileConfig {
    pub profile: RuntimeProfile,
    pub browser_no_sandbox_enabled: bool,
    pub dev_filesystem_mcp_enabled: bool,
    pub unverified_mcp_allowed: bool,
    pub unconfined_mcp_allowed: bool,
    pub unconfined_plugin_allowed: bool,
    pub unconfined_connector_allowed: bool,
    pub receipt_strictness_enabled: bool,
    pub external_approval_enforced: bool,
}

impl RuntimeProfileConfig {
    pub fn strict(profile: RuntimeProfile) -> Self {
        Self {
            profile,
            browser_no_sandbox_enabled: false,
            dev_filesystem_mcp_enabled: false,
            unverified_mcp_allowed: false,
            unconfined_mcp_allowed: false,
            unconfined_plugin_allowed: false,
            unconfined_connector_allowed: false,
            receipt_strictness_enabled: true,
            external_approval_enforced: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeProfileViolation {
    pub key: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStartupVerification {
    Verified,
    Failed { reason: String },
    Unavailable { reason: String },
    NotRequired { reason: String },
}

impl RuntimeStartupVerification {
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::Failed {
            reason: reason.into(),
        }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    pub fn is_verified_or_not_required(&self) -> bool {
        matches!(self, Self::Verified | Self::NotRequired { .. })
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Verified => None,
            Self::Failed { reason }
            | Self::Unavailable { reason }
            | Self::NotRequired { reason } => Some(reason.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStartupGateInput {
    pub profile_config: RuntimeProfileConfig,
    pub license: RuntimeStartupVerification,
    pub security_attestation: RuntimeStartupVerification,
    pub policy_config: RuntimeStartupVerification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStartupGateFailure {
    pub key: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStartupGateReport {
    pub profile: RuntimeProfile,
    pub fail_closed: bool,
    pub allowed: bool,
    pub failures: Vec<RuntimeStartupGateFailure>,
    pub warnings: Vec<RuntimeStartupGateFailure>,
}

impl RuntimeStartupGateReport {
    pub fn into_result(self) -> Result<Self, Self> {
        if self.allowed {
            Ok(self)
        } else {
            Err(self)
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeProfileValidator;

impl RuntimeProfileValidator {
    pub fn validate(config: &RuntimeProfileConfig) -> Result<(), Vec<RuntimeProfileViolation>> {
        if !config.profile.fail_closed() {
            return Ok(());
        }

        let mut violations = Vec::new();
        push_if(
            &mut violations,
            config.browser_no_sandbox_enabled,
            "browser_no_sandbox_enabled",
            "production profiles require browser sandboxing",
        );
        push_if(
            &mut violations,
            config.dev_filesystem_mcp_enabled,
            "dev_filesystem_mcp_enabled",
            "production profiles reject development filesystem MCP servers",
        );
        push_if(
            &mut violations,
            config.unverified_mcp_allowed,
            "unverified_mcp_allowed",
            "production profiles reject unverified MCP servers",
        );
        push_if(
            &mut violations,
            config.unconfined_mcp_allowed,
            "unconfined_mcp_allowed",
            "production profiles reject unconfined MCP servers",
        );
        push_if(
            &mut violations,
            config.unconfined_plugin_allowed,
            "unconfined_plugin_allowed",
            "production profiles reject unconfined plugins",
        );
        push_if(
            &mut violations,
            config.unconfined_connector_allowed,
            "unconfined_connector_allowed",
            "production profiles reject unconfined connectors",
        );
        push_if(
            &mut violations,
            !config.receipt_strictness_enabled,
            "receipt_strictness_enabled",
            "production profiles require strict receipt settlement",
        );
        push_if(
            &mut violations,
            !config.external_approval_enforced,
            "external_approval_enforced",
            "production profiles require external approval enforcement",
        );

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }

    pub fn evaluate_startup_gate(input: RuntimeStartupGateInput) -> RuntimeStartupGateReport {
        let fail_closed = input.profile_config.profile.fail_closed();
        let mut failures = Vec::new();
        let mut warnings = Vec::new();

        if let Err(violations) = Self::validate(&input.profile_config) {
            for violation in violations {
                failures.push(RuntimeStartupGateFailure {
                    key: format!("profile.{}", violation.key),
                    reason: violation.reason.to_string(),
                });
            }
        }

        push_startup_verification(
            "license",
            input.license,
            fail_closed,
            &mut failures,
            &mut warnings,
        );
        push_startup_verification(
            "security_attestation",
            input.security_attestation,
            fail_closed,
            &mut failures,
            &mut warnings,
        );
        push_startup_verification(
            "policy_config",
            input.policy_config,
            fail_closed,
            &mut failures,
            &mut warnings,
        );

        RuntimeStartupGateReport {
            profile: input.profile_config.profile,
            fail_closed,
            allowed: failures.is_empty(),
            failures,
            warnings,
        }
    }
}

fn push_if(
    violations: &mut Vec<RuntimeProfileViolation>,
    condition: bool,
    key: &'static str,
    reason: &'static str,
) {
    if condition {
        violations.push(RuntimeProfileViolation { key, reason });
    }
}

fn push_startup_verification(
    key: &'static str,
    verification: RuntimeStartupVerification,
    fail_closed: bool,
    failures: &mut Vec<RuntimeStartupGateFailure>,
    warnings: &mut Vec<RuntimeStartupGateFailure>,
) {
    if verification.is_verified_or_not_required() {
        return;
    }

    let record = RuntimeStartupGateFailure {
        key: key.to_string(),
        reason: verification
            .reason()
            .unwrap_or("startup verification failed")
            .to_string(),
    };

    if fail_closed {
        failures.push(record);
    } else {
        warnings.push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate_input(
        profile: RuntimeProfile,
        license: RuntimeStartupVerification,
    ) -> RuntimeStartupGateInput {
        RuntimeStartupGateInput {
            profile_config: RuntimeProfileConfig::strict(profile),
            license,
            security_attestation: RuntimeStartupVerification::NotRequired {
                reason: "test profile does not configure remote attestation".to_string(),
            },
            policy_config: RuntimeStartupVerification::Verified,
        }
    }

    #[test]
    fn startup_gate_blocks_failed_license_in_production_profile() {
        let report = RuntimeProfileValidator::evaluate_startup_gate(gate_input(
            RuntimeProfile::Production,
            RuntimeStartupVerification::failed("license proof rejected"),
        ));

        assert!(!report.allowed);
        assert!(report.fail_closed);
        assert!(report
            .failures
            .iter()
            .any(|failure| failure.key == "license"));
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn startup_gate_warns_for_failed_license_in_dev_profile() {
        let report = RuntimeProfileValidator::evaluate_startup_gate(gate_input(
            RuntimeProfile::Dev,
            RuntimeStartupVerification::failed("license verifier unavailable"),
        ));

        assert!(report.allowed);
        assert!(!report.fail_closed);
        assert!(report.failures.is_empty());
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.key == "license"));
    }

    #[test]
    fn startup_gate_includes_profile_violations_in_fail_closed_profiles() {
        let mut profile_config = RuntimeProfileConfig::strict(RuntimeProfile::Marketplace);
        profile_config.unverified_mcp_allowed = true;

        let report = RuntimeProfileValidator::evaluate_startup_gate(RuntimeStartupGateInput {
            profile_config,
            license: RuntimeStartupVerification::Verified,
            security_attestation: RuntimeStartupVerification::NotRequired {
                reason: "marketplace binary has no remote attestation hook in this test"
                    .to_string(),
            },
            policy_config: RuntimeStartupVerification::Verified,
        });

        assert!(!report.allowed);
        assert!(report
            .failures
            .iter()
            .any(|failure| failure.key == "profile.unverified_mcp_allowed"));
    }
}
