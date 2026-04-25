// Path: crates/drivers/src/mcp/mod.rs

pub mod compression;
pub mod protocol;
pub mod transport;

use anyhow::{anyhow, bail, Result};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, LlmToolDefinition};
use ioi_types::app::{ActionTarget, RuntimeTarget, WorkloadSpec};
use ioi_types::config::{
    McpContainmentConfig, McpContainmentMode, McpIntegrityConfig, McpMode, McpServerSource,
    McpServerTier,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

use self::transport::{McpSpawnPolicy, McpTransport};
use crate::authority::assert_raw_driver_allowed;

#[derive(Debug, Clone, Deserialize)]
pub struct McpServerConfig {
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub tier: McpServerTier,
    pub source: McpServerSource,
    pub integrity: McpIntegrityConfig,
    pub containment: McpContainmentConfig,
    pub allowed_tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerReceipt {
    pub server_name: String,
    pub command_path: String,
    pub command_sha256: String,
    pub declared_version: Option<String>,
    pub tier: McpServerTier,
    pub source: McpServerSource,
    pub mode: McpMode,
    pub started_at_ms: u64,
    pub tools: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct McpToolExecutionOutput {
    pub server_name: String,
    pub result: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpToolRiskDomain {
    Low,
    Filesystem,
    Network,
    Execution,
    Ui,
    Wallet,
}

#[derive(Debug, Clone)]
struct PreparedServerConfig {
    command_path: PathBuf,
    command_sha256: String,
    args: Vec<String>,
    env: HashMap<String, String>,
    containment: McpContainmentConfig,
}

pub struct McpManager {
    servers: RwLock<HashMap<String, Arc<McpTransport>>>,
    tool_routing_table: RwLock<HashMap<String, String>>,
    tool_cache: RwLock<HashMap<String, Vec<LlmToolDefinition>>>,
    server_containment: RwLock<HashMap<String, McpContainmentConfig>>,
    server_receipts: RwLock<HashMap<String, McpServerReceipt>>,
}

impl McpManager {
    pub fn new() -> Self {
        Self {
            servers: RwLock::new(HashMap::new()),
            tool_routing_table: RwLock::new(HashMap::new()),
            tool_cache: RwLock::new(HashMap::new()),
            server_containment: RwLock::new(HashMap::new()),
            server_receipts: RwLock::new(HashMap::new()),
        }
    }

    pub async fn start_server(
        &self,
        name: &str,
        mode: McpMode,
        config: McpServerConfig,
    ) -> Result<()> {
        assert_raw_driver_allowed("mcp", "start_server")?;
        validate_start_policy(name, mode, &config)?;
        let prepared = prepare_server_config(name, &config)?;

        log::info!(
            "Starting MCP Server '{}': {} {:?} tier={:?} source={:?} mode={:?}",
            name,
            prepared.command_path.display(),
            prepared.args,
            config.tier,
            config.source,
            mode
        );

        let transport = McpTransport::spawn(
            prepared.command_path.to_string_lossy().to_string(),
            prepared.args.clone(),
            prepared.env.clone(),
            McpSpawnPolicy {
                containment: prepared.containment.clone(),
                mode,
            },
        )
        .await?;

        transport.initialize().await?;
        let tools = transport.list_tools().await?;

        let mut table = self.tool_routing_table.write().await;
        let mut cache = self.tool_cache.write().await;
        let mut containment = self.server_containment.write().await;
        let mut receipts = self.server_receipts.write().await;

        let mut cached_definitions = Vec::new();
        let mut tool_names = Vec::new();
        let mut registered_this_server = HashSet::new();
        let allowed_tools = normalize_allowed_tools(&config.allowed_tools);
        let mut admitted_raw_tools = HashSet::new();

        for tool in tools {
            if let Some(allowlist) = allowed_tools.as_ref() {
                if !allowlist.contains(tool.name.as_str()) {
                    tracing::info!(
                        target: "mcp",
                        server = name,
                        tool = %tool.name,
                        "Skipping MCP tool not present in allowed_tools"
                    );
                    continue;
                }
            }
            let namespaced_name = format!("{}__{}", name, tool.name);

            if AgentTool::is_reserved_tool_name(&namespaced_name) {
                return Err(anyhow!(
                    "ERROR_CLASS=PolicyBlocked MCP tool '{}' collides with reserved native tool name",
                    namespaced_name
                ));
            }
            if table.contains_key(&namespaced_name)
                || !registered_this_server.insert(namespaced_name.clone())
            {
                return Err(anyhow!(
                    "ERROR_CLASS=PolicyBlocked MCP tool '{}' collides with an existing tool registration",
                    namespaced_name
                ));
            }

            admitted_raw_tools.insert(tool.name.clone());
            let risk = classify_tool_risk(&tool.name, tool.description.as_deref());
            enforce_tool_admission_policy(&config, mode, name, &namespaced_name, risk)?;

            table.insert(namespaced_name.clone(), name.to_string());
            cached_definitions.push(LlmToolDefinition {
                name: namespaced_name.clone(),
                description: tool.description.unwrap_or_default(),
                parameters: tool.input_schema.to_string(),
            });
            tool_names.push(namespaced_name.clone());
            log::debug!("Registered MCP Tool: {}", namespaced_name);
        }
        if mode == McpMode::Production {
            if let Some(allowlist) = allowed_tools.as_ref() {
                let mut missing = allowlist
                    .iter()
                    .filter(|tool| !admitted_raw_tools.contains(*tool))
                    .cloned()
                    .collect::<Vec<_>>();
                missing.sort();
                if !missing.is_empty() {
                    return Err(anyhow!(
                        "ERROR_CLASS=PolicyBlocked MCP server '{}' did not expose required allowed_tools entries: {}",
                        name,
                        missing.join(", ")
                    ));
                }
            }
            if tool_names.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=PolicyBlocked MCP server '{}' admitted zero tools in production mode",
                    name
                ));
            }
        }

        cache.insert(name.to_string(), cached_definitions);
        containment.insert(name.to_string(), prepared.containment.clone());
        receipts.insert(
            name.to_string(),
            McpServerReceipt {
                server_name: name.to_string(),
                command_path: prepared.command_path.to_string_lossy().to_string(),
                command_sha256: prepared.command_sha256,
                declared_version: config.integrity.version.clone(),
                tier: config.tier,
                source: config.source,
                mode,
                started_at_ms: unix_ms_now(),
                tools: tool_names.clone(),
            },
        );

        let mut servers = self.servers.write().await;
        servers.insert(name.to_string(), Arc::new(transport));

        tracing::info!(
            target: "mcp",
            server = name,
            tier = ?config.tier,
            source = ?config.source,
            mode = ?mode,
            tool_count = tool_names.len(),
            "MCP server started and admitted"
        );

        Ok(())
    }

    pub async fn get_all_tools(&self) -> Vec<LlmToolDefinition> {
        let cache = self.tool_cache.read().await;
        let mut all_tools = Vec::new();
        for tools in cache.values() {
            all_tools.extend(tools.clone());
        }
        all_tools
    }

    pub async fn get_server_receipts(&self) -> Vec<McpServerReceipt> {
        let receipts = self.server_receipts.read().await;
        receipts.values().cloned().collect()
    }

    pub async fn server_receipt_for_tool(&self, namespaced_tool: &str) -> Option<McpServerReceipt> {
        let server_name = {
            let table = self.tool_routing_table.read().await;
            table.get(namespaced_tool).cloned()
        }?;
        let receipts = self.server_receipts.read().await;
        receipts.get(&server_name).cloned()
    }

    pub async fn execute_tool(&self, namespaced_tool: &str, args: Value) -> Result<String> {
        self.execute_tool_with_spec(namespaced_tool, args, None)
            .await
    }

    pub async fn execute_tool_with_result(
        &self,
        namespaced_tool: &str,
        args: Value,
        workload_spec: Option<&WorkloadSpec>,
    ) -> Result<McpToolExecutionOutput> {
        let spec = workload_spec.ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=PolicyBlocked Missing WorkloadSpec for MCP tool '{}'",
                namespaced_tool
            )
        })?;
        if !matches!(
            spec.runtime_target,
            RuntimeTarget::Adapter | RuntimeTarget::McpAdapter
        ) {
            return Err(anyhow!(
                "ERROR_CLASS=PolicyBlocked RuntimeTarget '{}' is invalid for MCP tool '{}'",
                spec.runtime_target.as_label(),
                namespaced_tool
            ));
        }

        let now_ms = unix_ms_now();
        let lease_check = spec.evaluate_lease(
            &ActionTarget::Custom(namespaced_tool.to_string()),
            None,
            now_ms,
        );
        if !lease_check.satisfied {
            return Err(anyhow!(
                "ERROR_CLASS=PolicyBlocked MCP lease validation failed for '{}': {}",
                namespaced_tool,
                lease_check
                    .reason
                    .unwrap_or_else(|| "unspecified_failure".to_string())
            ));
        }

        let table = self.tool_routing_table.read().await;
        let server_name = table.get(namespaced_tool).ok_or_else(|| {
            if AgentTool::is_reserved_tool_name(namespaced_tool) {
                anyhow!(
                    "Tool '{}' is reserved for native drivers and is not served by MCP. Native tool execution remains available even when MCP is disabled.",
                    namespaced_tool
                )
            } else {
                anyhow!(
                    "Tool '{}' not found in any active MCP server",
                    namespaced_tool
                )
            }
        })?;

        let prefix = format!("{}__", server_name);
        let raw_tool_name = namespaced_tool
            .strip_prefix(&prefix)
            .unwrap_or(namespaced_tool);

        let containment = self.server_containment.read().await;
        if let Some(policy) = containment.get(server_name) {
            enforce_runtime_containment(raw_tool_name, namespaced_tool, &args, policy)?;
        }

        let servers = self.servers.read().await;
        let transport = servers
            .get(server_name)
            .ok_or_else(|| anyhow!("MCP Server '{}' is dead or disconnected", server_name))?;

        let result = transport.call_tool(raw_tool_name, args).await?;
        Ok(McpToolExecutionOutput {
            server_name: server_name.clone(),
            result,
        })
    }

    pub async fn execute_tool_with_spec(
        &self,
        namespaced_tool: &str,
        args: Value,
        workload_spec: Option<&WorkloadSpec>,
    ) -> Result<String> {
        let result = self
            .execute_tool_with_result(namespaced_tool, args, workload_spec)
            .await?;
        Ok(result.result.to_string())
    }
}

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn validate_start_policy(name: &str, mode: McpMode, config: &McpServerConfig) -> Result<()> {
    if config.command.trim().is_empty() {
        bail!(
            "ERROR_CLASS=PolicyBlocked MCP server '{}' command is empty",
            name
        );
    }
    if config
        .allowed_tools
        .iter()
        .any(|tool| tool.trim().is_empty())
    {
        bail!(
            "ERROR_CLASS=PolicyBlocked MCP server '{}' contains empty entries in allowed_tools",
            name
        );
    }
    let mut seen_allowed = HashSet::new();
    for tool in &config.allowed_tools {
        let normalized = tool.trim();
        if !normalized.is_empty() && !seen_allowed.insert(normalized.to_string()) {
            bail!(
                "ERROR_CLASS=PolicyBlocked MCP server '{}' contains duplicate allowed_tools entry '{}'",
                name,
                normalized
            );
        }
    }

    let installer = looks_like_network_installer(&config.command, config.source);
    if mode != McpMode::Development && installer {
        bail!(
            "ERROR_CLASS=PolicyBlocked MCP server '{}' uses installer-style command '{}' outside development mode",
            name,
            config.command
        );
    }

    if mode == McpMode::Production && config.tier == McpServerTier::Unverified {
        bail!(
            "ERROR_CLASS=PolicyBlocked MCP server '{}' has unverified tier in production mode",
            name
        );
    }
    if mode == McpMode::Production && config.allowed_tools.is_empty() {
        bail!(
            "ERROR_CLASS=PolicyBlocked MCP server '{}' requires non-empty allowed_tools in production mode",
            name
        );
    }
    if mode == McpMode::Production && !cfg!(target_os = "linux") {
        bail!(
            "ERROR_CLASS=PolicyBlocked MCP production mode is currently supported only on Linux (strict containment requirement)"
        );
    }

    if mode == McpMode::Production {
        if config
            .integrity
            .version
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            bail!(
                "ERROR_CLASS=PolicyBlocked MCP server '{}' requires integrity.version in production mode",
                name
            );
        }
        if config
            .integrity
            .sha256
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            bail!(
                "ERROR_CLASS=PolicyBlocked MCP server '{}' requires integrity.sha256 in production mode",
                name
            );
        }
        if config.containment.mode != McpContainmentMode::Strict {
            bail!(
                "ERROR_CLASS=PolicyBlocked MCP server '{}' must use strict containment in production mode",
                name
            );
        }
        if config
            .containment
            .workspace_root
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            bail!(
                "ERROR_CLASS=PolicyBlocked MCP server '{}' requires containment.workspace_root in production mode",
                name
            );
        }
        if !Path::new(config.command.trim()).is_absolute() {
            bail!(
                "ERROR_CLASS=PolicyBlocked MCP server '{}' command must be an absolute path in production mode",
                name
            );
        }
    }

    if matches!(
        config.tier,
        McpServerTier::Audited | McpServerTier::Verified
    ) && (config
        .integrity
        .version
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
        || config
            .integrity
            .sha256
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty())
    {
        bail!(
            "ERROR_CLASS=PolicyBlocked MCP server '{}' tier {:?} requires integrity.version and integrity.sha256",
            name,
            config.tier
        );
    }

    if let Some(hash) = config.integrity.sha256.as_deref() {
        let valid = hash.len() == 64 && hash.chars().all(|ch| ch.is_ascii_hexdigit());
        if !valid {
            bail!(
                "ERROR_CLASS=PolicyBlocked MCP server '{}' has invalid integrity.sha256 format",
                name
            );
        }
    }

    Ok(())
}

fn prepare_server_config(name: &str, config: &McpServerConfig) -> Result<PreparedServerConfig> {
    let command_path = resolve_command_path(&config.command)?;
    let command_sha = sha256_file_hex(&command_path)?;

    if let Some(expected) = config.integrity.sha256.as_deref() {
        if !expected.eq_ignore_ascii_case(&command_sha) {
            bail!(
                "ERROR_CLASS=PolicyBlocked MCP server '{}' executable hash mismatch (expected={}, actual={})",
                name,
                expected,
                command_sha
            );
        }
    }

    let workspace_root = if let Some(root) = config.containment.workspace_root.as_deref() {
        let path = PathBuf::from(root);
        if !path.exists() {
            fs::create_dir_all(&path).map_err(|e| {
                anyhow!(
                    "Failed to create containment workspace_root '{}' for MCP server '{}': {}",
                    root,
                    name,
                    e
                )
            })?;
        }
        let canon = fs::canonicalize(&path).map_err(|e| {
            anyhow!(
                "Failed to canonicalize containment workspace_root '{}' for MCP server '{}': {}",
                root,
                name,
                e
            )
        })?;
        Some(canon.to_string_lossy().to_string())
    } else {
        None
    };

    let mut containment = config.containment.clone();
    containment.workspace_root = workspace_root;

    Ok(PreparedServerConfig {
        command_path,
        command_sha256: command_sha,
        args: config.args.clone(),
        env: config.env.clone(),
        containment,
    })
}

fn resolve_command_path(command: &str) -> Result<PathBuf> {
    let trimmed = command.trim();
    let candidate = Path::new(trimmed);

    if candidate.is_absolute() || trimmed.contains(std::path::MAIN_SEPARATOR) {
        return fs::canonicalize(candidate)
            .map_err(|e| anyhow!("Failed to resolve MCP command path '{}': {}", trimmed, e));
    }

    let path_var = std::env::var_os("PATH")
        .ok_or_else(|| anyhow!("PATH is not set; cannot resolve MCP command '{}'", trimmed))?;
    for dir in std::env::split_paths(&path_var) {
        let joined = dir.join(trimmed);
        if joined.is_file() {
            return fs::canonicalize(&joined).map_err(|e| {
                anyhow!(
                    "Failed to resolve MCP command path '{}': {}",
                    joined.display(),
                    e
                )
            });
        }
    }

    Err(anyhow!(
        "Unable to resolve MCP command '{}' from PATH",
        trimmed
    ))
}

fn sha256_file_hex(path: &Path) -> Result<String> {
    let bytes = fs::read(path).map_err(|e| {
        anyhow!(
            "Failed to read MCP command '{}' for hashing: {}",
            path.display(),
            e
        )
    })?;
    let digest = sha256(&bytes)?;
    Ok(hex::encode(digest.as_ref()))
}

fn looks_like_network_installer(command: &str, source: McpServerSource) -> bool {
    if source == McpServerSource::PackageManager {
        return true;
    }
    let base = Path::new(command.trim())
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command.trim())
        .to_ascii_lowercase();
    matches!(
        base.as_str(),
        "npx" | "npm" | "pnpm" | "yarn" | "bunx" | "pipx" | "uvx"
    )
}

// Heuristic only. Admission enforcement remains driven by explicit mode/tier/integrity/policy.
fn classify_tool_risk(tool_name: &str, description: Option<&str>) -> McpToolRiskDomain {
    let mut haystack = tool_name.to_ascii_lowercase();
    if let Some(desc) = description {
        haystack.push(' ');
        haystack.push_str(&desc.to_ascii_lowercase());
    }

    if contains_any(
        &haystack,
        &["wallet", "payment", "checkout", "sign", "seed", "key"],
    ) {
        return McpToolRiskDomain::Wallet;
    }
    if contains_any(
        &haystack,
        &[
            "exec", "shell", "command", "spawn", "process", "terminal", "run",
        ],
    ) {
        return McpToolRiskDomain::Execution;
    }
    if contains_any(
        &haystack,
        &[
            "filesystem",
            "file",
            "path",
            "directory",
            "folder",
            "read_file",
            "write_file",
        ],
    ) {
        return McpToolRiskDomain::Filesystem;
    }
    if contains_any(
        &haystack,
        &[
            "url", "http", "https", "web", "request", "fetch", "socket", "network", "dns",
        ],
    ) {
        return McpToolRiskDomain::Network;
    }
    if contains_any(
        &haystack,
        &[
            "browser", "gui", "click", "type", "window", "mouse", "keyboard", "ui",
        ],
    ) {
        return McpToolRiskDomain::Ui;
    }

    McpToolRiskDomain::Low
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn enforce_tool_admission_policy(
    config: &McpServerConfig,
    mode: McpMode,
    server_name: &str,
    tool_name: &str,
    risk: McpToolRiskDomain,
) -> Result<()> {
    if mode == McpMode::Production && config.tier == McpServerTier::Unverified {
        bail!(
            "ERROR_CLASS=PolicyBlocked MCP server '{}' is unverified and cannot admit '{}'",
            server_name,
            tool_name
        );
    }

    if mode != McpMode::Development
        && config.tier == McpServerTier::Unverified
        && risk != McpToolRiskDomain::Low
    {
        bail!(
            "ERROR_CLASS=PolicyBlocked MCP tool '{}' from server '{}' has high-risk domain {:?} with unverified tier",
            tool_name,
            server_name,
            risk
        );
    }

    Ok(())
}

fn normalize_allowed_tools(allowed_tools: &[String]) -> Option<HashSet<String>> {
    if allowed_tools.is_empty() {
        return None;
    }
    let normalized = allowed_tools
        .iter()
        .map(|tool| tool.trim())
        .filter(|tool| !tool.is_empty())
        .map(|tool| tool.to_string())
        .collect::<HashSet<_>>();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn enforce_runtime_containment(
    raw_tool_name: &str,
    namespaced_tool: &str,
    args: &Value,
    containment: &McpContainmentConfig,
) -> Result<()> {
    let lower_tool = raw_tool_name.to_ascii_lowercase();

    if !containment.allow_child_processes
        && contains_any(
            &lower_tool,
            &[
                "exec", "shell", "spawn", "process", "command", "terminal", "run",
            ],
        )
    {
        bail!(
            "ERROR_CLASS=PolicyBlocked MCP containment blocked execution-capable tool '{}'",
            namespaced_tool
        );
    }

    if !containment.allow_network_egress
        && (contains_any(
            &lower_tool,
            &[
                "http", "https", "url", "fetch", "request", "socket", "network", "dns",
            ],
        ) || json_contains_network_fields(args))
    {
        bail!(
            "ERROR_CLASS=PolicyBlocked MCP containment blocked network egress for '{}'",
            namespaced_tool
        );
    }

    if let Some(root) = containment.workspace_root.as_deref() {
        let root_path = PathBuf::from(root);
        enforce_json_path_scope(args, &root_path)?;
    }

    Ok(())
}

fn json_contains_network_fields(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, entry)| {
            let key_lower = key.to_ascii_lowercase();
            let key_is_network = key_lower.contains("url")
                || key_lower.contains("uri")
                || key_lower.contains("host")
                || key_lower.contains("domain")
                || key_lower.contains("endpoint");
            key_is_network
                && entry
                    .as_str()
                    .map(|text| !text.trim().is_empty())
                    .unwrap_or(false)
                || json_contains_network_fields(entry)
        }),
        Value::Array(items) => items.iter().any(json_contains_network_fields),
        _ => false,
    }
}

fn enforce_json_path_scope(value: &Value, workspace_root: &Path) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, entry) in map {
                let key_lower = key.to_ascii_lowercase();
                let key_is_path = key_lower == "path"
                    || key_lower.ends_with("_path")
                    || key_lower.contains("directory")
                    || key_lower.contains("folder")
                    || key_lower == "cwd"
                    || key_lower == "workspace";
                if key_is_path {
                    if let Some(path_value) = entry.as_str() {
                        ensure_path_is_scoped(path_value, workspace_root)?;
                    }
                }
                enforce_json_path_scope(entry, workspace_root)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                enforce_json_path_scope(item, workspace_root)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn ensure_path_is_scoped(path_value: &str, workspace_root: &Path) -> Result<()> {
    let candidate = Path::new(path_value.trim());
    if candidate.as_os_str().is_empty() {
        return Ok(());
    }

    let absolute = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        workspace_root.join(candidate)
    };
    let normalized = normalize_path_with_missing_segments(&absolute)?;
    let root = fs::canonicalize(workspace_root).map_err(|e| {
        anyhow!(
            "Failed to canonicalize MCP containment workspace root '{}': {}",
            workspace_root.display(),
            e
        )
    })?;

    if !normalized.starts_with(&root) {
        bail!(
            "ERROR_CLASS=PolicyBlocked MCP containment rejected out-of-scope path '{}' (workspace_root='{}')",
            path_value,
            root.display()
        );
    }

    Ok(())
}

fn normalize_path_with_missing_segments(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path).map_err(|e| {
            anyhow!(
                "Failed to canonicalize MCP path candidate '{}': {}",
                path.display(),
                e
            )
        });
    }

    let mut suffix: Vec<OsString> = Vec::new();
    let mut cursor = path.to_path_buf();
    while !cursor.exists() {
        let file_name = cursor.file_name().ok_or_else(|| {
            anyhow!(
                "Cannot normalize MCP path '{}' (missing ancestor)",
                path.display()
            )
        })?;
        suffix.push(file_name.to_os_string());
        cursor = cursor
            .parent()
            .ok_or_else(|| anyhow!("Cannot normalize MCP path '{}' (no parent)", path.display()))?
            .to_path_buf();
    }

    let mut normalized = fs::canonicalize(&cursor).map_err(|e| {
        anyhow!(
            "Failed to canonicalize MCP path ancestor '{}': {}",
            cursor.display(),
            e
        )
    })?;
    for segment in suffix.iter().rev() {
        normalized.push(segment);
    }
    Ok(normalized)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
