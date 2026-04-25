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
