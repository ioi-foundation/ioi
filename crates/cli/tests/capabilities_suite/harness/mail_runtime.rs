#[derive(Debug, Clone)]
struct MailRuntimeBootstrapConfig {
    auth_mode: MailConnectorAuthMode,
    mailbox: String,
    account_email: String,
    imap_host: String,
    imap_port: u16,
    imap_tls_mode: MailConnectorTlsMode,
    smtp_host: String,
    smtp_port: u16,
    smtp_tls_mode: MailConnectorTlsMode,
    imap_username_alias: String,
    imap_secret_alias: String,
    smtp_username_alias: String,
    smtp_secret_alias: String,
    imap_username_secret_id: String,
    imap_secret_secret_id: String,
    smtp_username_secret_id: String,
    smtp_secret_secret_id: String,
    imap_username: String,
    imap_secret: String,
    smtp_username: String,
    smtp_secret: String,
}

#[derive(Debug, Clone)]
struct MailRuntimeSecretSpec {
    secret_id: String,
    alias: String,
    kind: SecretKind,
    value: String,
}

struct ScopedEnvVar {
    key: String,
    previous: Option<String>,
    restored: bool,
}

impl ScopedEnvVar {
    fn set(key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let previous = std::env::var(&key).ok();
        std::env::set_var(&key, value.into());
        Self {
            key,
            previous,
            restored: false,
        }
    }

    fn restore_now(&mut self) {
        if self.restored {
            return;
        }
        if let Some(previous) = self.previous.as_ref() {
            std::env::set_var(&self.key, previous);
        } else {
            std::env::remove_var(&self.key);
        }
        self.restored = true;
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        self.restore_now();
    }
}

fn find_workspace_file(file_name: &str) -> Option<PathBuf> {
    let mut cursor = std::env::current_dir().ok();
    while let Some(path) = cursor.clone() {
        let candidate = path.join(file_name);
        if candidate.is_file() {
            return Some(candidate);
        }
        cursor = path.parent().map(|parent| parent.to_path_buf());
    }
    None
}

fn load_env_file_if_present(file_name: &str) {
    let Some(path) = find_workspace_file(file_name) else {
        return;
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return;
    };

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || std::env::var(key).is_ok() {
            continue;
        }
        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        if !value.is_empty() {
            std::env::set_var(key, value);
        }
    }
}

pub fn load_env_from_workspace_dotenv_if_present() {
    load_env_file_if_present(".env");
}

fn required_env_value(key: &str) -> Result<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("missing required environment variable '{}'", key))
}

fn optional_env_value(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn nonempty_env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_u16_env(key: &str) -> Result<u16> {
    let raw = required_env_value(key)?;
    let value = raw
        .parse::<u16>()
        .map_err(|e| anyhow!("invalid {} '{}': {}", key, raw, e))?;
    if value == 0 {
        return Err(anyhow!("invalid {}: value must be > 0", key));
    }
    Ok(value)
}

fn parse_mail_auth_mode_env() -> Result<MailConnectorAuthMode> {
    if let Some(raw) = nonempty_env_value(MAIL_E2E_KEY_AUTH_MODE) {
        return match raw.to_ascii_lowercase().as_str() {
            "password" | "pass" => Ok(MailConnectorAuthMode::Password),
            "oauth2" | "oauth" | "xoauth2" => Ok(MailConnectorAuthMode::Oauth2),
            _ => Err(anyhow!(
                "invalid {} '{}': expected password or oauth2",
                MAIL_E2E_KEY_AUTH_MODE,
                raw
            )),
        };
    }

    let has_password = nonempty_env_value(MAIL_E2E_KEY_IMAP_PASSWORD).is_some()
        || nonempty_env_value(MAIL_E2E_KEY_SMTP_PASSWORD).is_some();
    let has_bearer = nonempty_env_value(MAIL_E2E_KEY_IMAP_BEARER_TOKEN).is_some()
        || nonempty_env_value(MAIL_E2E_KEY_SMTP_BEARER_TOKEN).is_some();
    if has_bearer && !has_password {
        Ok(MailConnectorAuthMode::Oauth2)
    } else {
        Ok(MailConnectorAuthMode::Password)
    }
}

fn parse_tls_mode_env(key: &str, default: MailConnectorTlsMode) -> Result<MailConnectorTlsMode> {
    let Some(raw) = nonempty_env_value(key) else {
        return Ok(default);
    };
    match raw.to_ascii_lowercase().as_str() {
        "plaintext" | "plain" => Ok(MailConnectorTlsMode::Plaintext),
        "starttls" | "start_tls" | "start-tls" => Ok(MailConnectorTlsMode::StartTls),
        "tls" | "ssl" => Ok(MailConnectorTlsMode::Tls),
        _ => Err(anyhow!(
            "invalid {} '{}': expected plaintext, starttls, or tls",
            key,
            raw
        )),
    }
}

fn parse_mail_runtime_bootstrap_config() -> Result<MailRuntimeBootstrapConfig> {
    let auth_mode = parse_mail_auth_mode_env()?;
    let (
        imap_secret_alias,
        smtp_secret_alias,
        imap_secret_secret_id,
        smtp_secret_secret_id,
        imap_secret,
        smtp_secret,
    ) = match auth_mode {
        MailConnectorAuthMode::Password => (
            optional_env_value(
                MAIL_E2E_KEY_IMAP_PASSWORD_ALIAS,
                MAIL_E2E_DEFAULT_IMAP_PASSWORD_ALIAS,
            ),
            optional_env_value(
                MAIL_E2E_KEY_SMTP_PASSWORD_ALIAS,
                MAIL_E2E_DEFAULT_SMTP_PASSWORD_ALIAS,
            ),
            optional_env_value(
                MAIL_E2E_KEY_IMAP_PASSWORD_SECRET_ID,
                MAIL_E2E_DEFAULT_IMAP_PASSWORD_SECRET_ID,
            ),
            optional_env_value(
                MAIL_E2E_KEY_SMTP_PASSWORD_SECRET_ID,
                MAIL_E2E_DEFAULT_SMTP_PASSWORD_SECRET_ID,
            ),
            required_env_value(MAIL_E2E_KEY_IMAP_PASSWORD)?,
            required_env_value(MAIL_E2E_KEY_SMTP_PASSWORD)?,
        ),
        MailConnectorAuthMode::Oauth2 => (
            optional_env_value(
                MAIL_E2E_KEY_IMAP_BEARER_TOKEN_ALIAS,
                MAIL_E2E_DEFAULT_IMAP_BEARER_TOKEN_ALIAS,
            ),
            optional_env_value(
                MAIL_E2E_KEY_SMTP_BEARER_TOKEN_ALIAS,
                MAIL_E2E_DEFAULT_SMTP_BEARER_TOKEN_ALIAS,
            ),
            optional_env_value(
                MAIL_E2E_KEY_IMAP_BEARER_TOKEN_SECRET_ID,
                MAIL_E2E_DEFAULT_IMAP_BEARER_TOKEN_SECRET_ID,
            ),
            optional_env_value(
                MAIL_E2E_KEY_SMTP_BEARER_TOKEN_SECRET_ID,
                MAIL_E2E_DEFAULT_SMTP_BEARER_TOKEN_SECRET_ID,
            ),
            required_env_value(MAIL_E2E_KEY_IMAP_BEARER_TOKEN)?,
            required_env_value(MAIL_E2E_KEY_SMTP_BEARER_TOKEN)?,
        ),
    };

    Ok(MailRuntimeBootstrapConfig {
        auth_mode,
        mailbox: optional_env_value(MAIL_E2E_KEY_MAILBOX, MAIL_E2E_DEFAULT_MAILBOX)
            .to_ascii_lowercase(),
        account_email: required_env_value(MAIL_E2E_KEY_ACCOUNT_EMAIL)?.to_ascii_lowercase(),
        imap_host: required_env_value(MAIL_E2E_KEY_IMAP_HOST)?.to_ascii_lowercase(),
        imap_port: parse_u16_env(MAIL_E2E_KEY_IMAP_PORT)?,
        imap_tls_mode: parse_tls_mode_env(MAIL_E2E_KEY_IMAP_TLS_MODE, MailConnectorTlsMode::Tls)?,
        smtp_host: required_env_value(MAIL_E2E_KEY_SMTP_HOST)?.to_ascii_lowercase(),
        smtp_port: parse_u16_env(MAIL_E2E_KEY_SMTP_PORT)?,
        smtp_tls_mode: parse_tls_mode_env(
            MAIL_E2E_KEY_SMTP_TLS_MODE,
            MailConnectorTlsMode::StartTls,
        )?,
        imap_username_alias: optional_env_value(
            MAIL_E2E_KEY_IMAP_USERNAME_ALIAS,
            MAIL_E2E_DEFAULT_IMAP_USERNAME_ALIAS,
        )
        .to_ascii_lowercase(),
        imap_secret_alias: imap_secret_alias.to_ascii_lowercase(),
        smtp_username_alias: optional_env_value(
            MAIL_E2E_KEY_SMTP_USERNAME_ALIAS,
            MAIL_E2E_DEFAULT_SMTP_USERNAME_ALIAS,
        )
        .to_ascii_lowercase(),
        smtp_secret_alias: smtp_secret_alias.to_ascii_lowercase(),
        imap_username_secret_id: optional_env_value(
            MAIL_E2E_KEY_IMAP_USERNAME_SECRET_ID,
            MAIL_E2E_DEFAULT_IMAP_USERNAME_SECRET_ID,
        ),
        imap_secret_secret_id,
        smtp_username_secret_id: optional_env_value(
            MAIL_E2E_KEY_SMTP_USERNAME_SECRET_ID,
            MAIL_E2E_DEFAULT_SMTP_USERNAME_SECRET_ID,
        ),
        smtp_secret_secret_id,
        imap_username: required_env_value(MAIL_E2E_KEY_IMAP_USERNAME)?,
        imap_secret,
        smtp_username: required_env_value(MAIL_E2E_KEY_SMTP_USERNAME)?,
        smtp_secret,
    })
}

fn build_mail_runtime_secret_specs(
    config: &MailRuntimeBootstrapConfig,
) -> Vec<MailRuntimeSecretSpec> {
    vec![
        MailRuntimeSecretSpec {
            secret_id: config.imap_username_secret_id.clone(),
            alias: config.imap_username_alias.clone(),
            kind: SecretKind::Custom("username".to_string()),
            value: config.imap_username.clone(),
        },
        MailRuntimeSecretSpec {
            secret_id: config.imap_secret_secret_id.clone(),
            alias: config.imap_secret_alias.clone(),
            kind: match config.auth_mode {
                MailConnectorAuthMode::Password => SecretKind::Password,
                MailConnectorAuthMode::Oauth2 => SecretKind::AccessToken,
            },
            value: config.imap_secret.clone(),
        },
        MailRuntimeSecretSpec {
            secret_id: config.smtp_username_secret_id.clone(),
            alias: config.smtp_username_alias.clone(),
            kind: SecretKind::Custom("username".to_string()),
            value: config.smtp_username.clone(),
        },
        MailRuntimeSecretSpec {
            secret_id: config.smtp_secret_secret_id.clone(),
            alias: config.smtp_secret_alias.clone(),
            kind: match config.auth_mode {
                MailConnectorAuthMode::Password => SecretKind::Password,
                MailConnectorAuthMode::Oauth2 => SecretKind::AccessToken,
            },
            value: config.smtp_secret.clone(),
        },
    ]
}

fn mail_runtime_env_bootstrap_keys() -> &'static [&'static str] {
    &[
        MAIL_E2E_KEY_AUTH_MODE,
        MAIL_E2E_KEY_MAILBOX,
        MAIL_E2E_KEY_ACCOUNT_EMAIL,
        MAIL_E2E_KEY_IMAP_HOST,
        MAIL_E2E_KEY_IMAP_PORT,
        MAIL_E2E_KEY_IMAP_TLS_MODE,
        MAIL_E2E_KEY_SMTP_HOST,
        MAIL_E2E_KEY_SMTP_PORT,
        MAIL_E2E_KEY_SMTP_TLS_MODE,
        MAIL_E2E_KEY_IMAP_USERNAME,
        MAIL_E2E_KEY_IMAP_PASSWORD,
        MAIL_E2E_KEY_IMAP_BEARER_TOKEN,
        MAIL_E2E_KEY_SMTP_USERNAME,
        MAIL_E2E_KEY_SMTP_PASSWORD,
        MAIL_E2E_KEY_SMTP_BEARER_TOKEN,
        MAIL_E2E_KEY_IMAP_USERNAME_ALIAS,
        MAIL_E2E_KEY_IMAP_PASSWORD_ALIAS,
        MAIL_E2E_KEY_IMAP_BEARER_TOKEN_ALIAS,
        MAIL_E2E_KEY_SMTP_USERNAME_ALIAS,
        MAIL_E2E_KEY_SMTP_PASSWORD_ALIAS,
        MAIL_E2E_KEY_SMTP_BEARER_TOKEN_ALIAS,
        MAIL_E2E_KEY_IMAP_USERNAME_SECRET_ID,
        MAIL_E2E_KEY_IMAP_PASSWORD_SECRET_ID,
        MAIL_E2E_KEY_IMAP_BEARER_TOKEN_SECRET_ID,
        MAIL_E2E_KEY_SMTP_USERNAME_SECRET_ID,
        MAIL_E2E_KEY_SMTP_PASSWORD_SECRET_ID,
        MAIL_E2E_KEY_SMTP_BEARER_TOKEN_SECRET_ID,
    ]
}

fn mail_runtime_env_bootstrap_configured() -> bool {
    mail_runtime_env_bootstrap_keys()
        .iter()
        .any(|key| nonempty_env_value(key).is_some())
}

fn resolve_mail_runtime_bootstrap_config() -> Result<(MailRuntimeBootstrapConfig, &'static str)> {
    if !mail_runtime_env_bootstrap_configured() {
        return Err(anyhow!(
            "mail connector runtime bootstrap requires configured MAIL_E2E_* environment variables"
        ));
    }
    parse_mail_runtime_bootstrap_config().map(|config| (config, "workspace_env"))
}

fn accumulate_environment_receipts_from_checks(
    grouped: &mut BTreeMap<String, EnvironmentReceiptAccumulator>,
    checks: &[String],
) {
    for fact in checks.iter().map(|check| parse_verification_fact(check)) {
        let Some(normalized_key) = fact.key.strip_prefix("env_evidence::") else {
            continue;
        };
        let Some(raw_value) = fact.value else {
            continue;
        };
        let value = raw_value.trim().to_string();
        let (base_key, field_kind) =
            if let Some(base) = normalized_key.strip_suffix("_probe_source") {
                (base, "probe_source")
            } else if let Some(base) = normalized_key.strip_suffix("_timestamp_ms") {
                (base, "timestamp_ms")
            } else if let Some(base) = normalized_key.strip_suffix("_satisfied") {
                (base, "satisfied")
            } else {
                (normalized_key, "observed_value")
            };

        let entry = grouped.entry(base_key.to_string()).or_default();
        match field_kind {
            "probe_source" => {
                if !value.is_empty() {
                    entry.probe_source = Some(value);
                }
            }
            "timestamp_ms" => {
                if let Ok(parsed) = value.parse::<u64>() {
                    entry.timestamp_ms = Some(parsed);
                }
            }
            "satisfied" => {
                let normalized = value.to_ascii_lowercase();
                entry.satisfied = match normalized.as_str() {
                    "true" | "1" | "yes" => Some(true),
                    "false" | "0" | "no" => Some(false),
                    _ => entry.satisfied,
                };
            }
            _ => {
                if !value.is_empty() && !entry.observed_values.contains(&value) {
                    entry.observed_values.push(value.clone());
                }
                let normalized = value.to_ascii_lowercase();
                if entry.satisfied.is_none() {
                    entry.satisfied = match normalized.as_str() {
                        "true" | "1" | "yes" => Some(true),
                        "false" | "0" | "no" => Some(false),
                        _ => None,
                    };
                }
            }
        }
    }
}

fn accumulate_environment_receipts_from_observations(
    grouped: &mut BTreeMap<String, EnvironmentReceiptAccumulator>,
    evidence: &[EnvironmentReceiptObservation],
) {
    for receipt in evidence {
        let entry = grouped.entry(receipt.key.clone()).or_default();
        for value in &receipt.observed_values {
            if !value.is_empty() && !entry.observed_values.contains(value) {
                entry.observed_values.push(value.clone());
            }
        }
        if let Some(probe_source) = receipt.probe_source.as_ref() {
            if !probe_source.trim().is_empty() {
                entry.probe_source = Some(probe_source.clone());
            }
        }
        if let Some(timestamp_ms) = receipt.timestamp_ms {
            entry.timestamp_ms = Some(timestamp_ms);
        }
        if let Some(satisfied) = receipt.satisfied {
            entry.satisfied = Some(satisfied);
        }
    }
}

fn finalize_environment_receipts(
    grouped: BTreeMap<String, EnvironmentReceiptAccumulator>,
) -> Vec<EnvironmentReceiptObservation> {
    grouped
        .into_iter()
        .map(|(key, entry)| EnvironmentReceiptObservation {
            key,
            observed_values: entry.observed_values,
            probe_source: entry.probe_source,
            timestamp_ms: entry.timestamp_ms,
            satisfied: entry.satisfied,
        })
        .collect()
}

fn derive_environment_receipts(checks: &[String]) -> Vec<EnvironmentReceiptObservation> {
    let mut grouped = BTreeMap::<String, EnvironmentReceiptAccumulator>::new();
    accumulate_environment_receipts_from_checks(&mut grouped, checks);
    finalize_environment_receipts(grouped)
}

fn merge_environment_receipts(
    existing: Vec<EnvironmentReceiptObservation>,
    checks: &[String],
) -> Vec<EnvironmentReceiptObservation> {
    let mut grouped = BTreeMap::<String, EnvironmentReceiptAccumulator>::new();
    accumulate_environment_receipts_from_observations(&mut grouped, &existing);
    accumulate_environment_receipts_from_checks(&mut grouped, checks);
    finalize_environment_receipts(grouped)
}

fn mirror_environment_receipt_checks(receipt: &EnvironmentReceiptObservation) -> Vec<String> {
    let mut checks = Vec::new();
    for value in &receipt.observed_values {
        checks.push(format!("env_evidence::{}={}", receipt.key, value));
    }
    if let Some(probe_source) = receipt.probe_source.as_ref() {
        checks.push(format!(
            "env_evidence::{}_probe_source={}",
            receipt.key, probe_source
        ));
    }
    if let Some(timestamp_ms) = receipt.timestamp_ms {
        checks.push(format!(
            "env_evidence::{}_timestamp_ms={}",
            receipt.key, timestamp_ms
        ));
    }
    if let Some(satisfied) = receipt.satisfied {
        checks.push(format!("env_evidence::{}_satisfied={}", receipt.key, satisfied));
    }
    checks
}

fn push_environment_observation(
    batch: &mut EnvironmentEvidenceBatch,
    key: impl Into<String>,
    observed_value: impl Into<String>,
) {
    let receipt = EnvironmentReceiptObservation {
        key: key.into(),
        observed_values: vec![observed_value.into()],
        probe_source: None,
        timestamp_ms: None,
        satisfied: None,
    };
    batch.checks.extend(mirror_environment_receipt_checks(&receipt));
    batch.evidence.push(receipt);
}

fn push_environment_metadata(
    batch: &mut EnvironmentEvidenceBatch,
    key: impl Into<String>,
    probe_source: Option<String>,
    timestamp_ms: Option<u64>,
    satisfied: Option<bool>,
) {
    let receipt = EnvironmentReceiptObservation {
        key: key.into(),
        observed_values: Vec::new(),
        probe_source,
        timestamp_ms,
        satisfied,
    };
    batch.checks.extend(mirror_environment_receipt_checks(&receipt));
    batch.evidence.push(receipt);
}

fn push_environment_receipt(
    batch: &mut EnvironmentEvidenceBatch,
    key: impl Into<String>,
    observed_value: impl Into<String>,
    probe_source: Option<String>,
    timestamp_ms: Option<u64>,
    satisfied: Option<bool>,
) {
    let receipt = EnvironmentReceiptObservation {
        key: key.into(),
        observed_values: vec![observed_value.into()],
        probe_source,
        timestamp_ms,
        satisfied,
    };
    batch.checks.extend(mirror_environment_receipt_checks(&receipt));
    batch.evidence.push(receipt);
}

fn extend_environment_evidence_batch(
    checks: &mut Vec<String>,
    evidence: &mut Vec<EnvironmentReceiptObservation>,
    batch: EnvironmentEvidenceBatch,
) {
    checks.extend(batch.checks);
    evidence.extend(batch.evidence);
}

fn display_optional_env_value(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "<unset>".to_string())
}

fn restore_optional_env_value(key: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
}
