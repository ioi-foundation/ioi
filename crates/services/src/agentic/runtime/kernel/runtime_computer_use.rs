use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    process::Command,
    time::Duration,
};

use super::coding_tool_computer_use::computer_use_provider_registry_report;

pub const RUNTIME_COMPUTER_USE_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.computer-use-projection-request.v1";
pub const RUNTIME_COMPUTER_USE_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.computer-use-projection.v1";
pub const COMPUTER_USE_BROWSER_DISCOVERY_SCHEMA_VERSION: &str =
    "ioi.computer-use.browser-discovery.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeComputerUseProjectionRequest {
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub projection_kind: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub discovered_at: Option<String>,
    #[serde(default)]
    pub process_rows: Option<Vec<String>>,
    #[serde(default)]
    pub include_cdp_probe: bool,
    #[serde(default)]
    pub include_tab_metadata: bool,
    #[serde(default)]
    pub reveal_tab_titles: bool,
    #[serde(default)]
    pub probe_timeout_ms: Option<u64>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeComputerUseProjectionCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeComputerUseProjectionCommandError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeComputerUseProjectionCore;

#[derive(Debug, Clone)]
pub struct RuntimeComputerUseProjectionRecord {
    pub object: String,
    pub status: String,
    pub operation: String,
    pub operation_kind: String,
    pub projection_kind: String,
    pub workspace_root: Option<String>,
    pub state_dir: Option<String>,
    pub provider_registry: Option<Value>,
    pub browser_discovery: Option<Value>,
    pub record_count: usize,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

impl RuntimeComputerUseProjectionCore {
    pub fn project(
        &self,
        request: RuntimeComputerUseProjectionRequest,
    ) -> Result<RuntimeComputerUseProjectionRecord, RuntimeComputerUseProjectionCommandError> {
        let projection_kind = normalized_projection_kind(&request)?;
        let operation_kind =
            request
                .operation_kind
                .clone()
                .unwrap_or_else(|| match projection_kind.as_str() {
                    "provider_registry" => {
                        "runtime.computer_use.projection.provider_registry".to_string()
                    }
                    "browser_discovery" => {
                        "runtime.computer_use.projection.browser_discovery".to_string()
                    }
                    _ => "runtime.computer_use.projection.unknown".to_string(),
                });
        let expected_operation_kind = format!("runtime.computer_use.projection.{projection_kind}");
        if operation_kind != expected_operation_kind {
            return Err(RuntimeComputerUseProjectionCommandError::new(
                "runtime_computer_use_projection_operation_kind_mismatch",
                format!(
                    "unsupported runtime computer-use operation kind {operation_kind}; expected {expected_operation_kind}"
                ),
            ));
        }

        let mut record = RuntimeComputerUseProjectionRecord {
            object: "ioi.runtime_computer_use_projection".to_string(),
            status: "projected".to_string(),
            operation: request
                .operation
                .clone()
                .unwrap_or_else(|| "runtime_computer_use_projection".to_string()),
            operation_kind,
            projection_kind: projection_kind.clone(),
            workspace_root: optional_trimmed(request.workspace_root.as_deref()),
            state_dir: optional_trimmed(request.state_dir.as_deref()),
            provider_registry: None,
            browser_discovery: None,
            record_count: 0,
            evidence_refs: vec![
                "rust_daemon_core_runtime_computer_use_projection".to_string(),
                "computer_use_step_module_shared_provider_registry".to_string(),
            ],
            receipt_refs: vec![format!(
                "receipt_runtime_computer_use_projection_{projection_kind}"
            )],
        };

        match projection_kind.as_str() {
            "provider_registry" => {
                record.provider_registry = Some(computer_use_provider_registry_report(None));
                record.record_count = record
                    .provider_registry
                    .as_ref()
                    .and_then(|registry| registry.get("providers"))
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
            }
            "browser_discovery" => {
                record.browser_discovery = Some(browser_discovery_report(&request));
                record.record_count = record
                    .browser_discovery
                    .as_ref()
                    .and_then(|report| report.get("browser_process_count"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
                record
                    .evidence_refs
                    .push("rust_daemon_core_browser_discovery_projection".to_string());
            }
            _ => {
                return Err(RuntimeComputerUseProjectionCommandError::new(
                    "runtime_computer_use_projection_kind_invalid",
                    format!("unsupported runtime computer-use projection kind {projection_kind}"),
                ));
            }
        }
        Ok(record)
    }
}

impl RuntimeComputerUseProjectionRecord {
    pub fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_COMPUTER_USE_PROJECTION_RESULT_SCHEMA_VERSION,
            "source": "rust_runtime_computer_use_projection_api",
            "backend": "rust_policy",
            "object": self.object,
            "status": self.status,
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "projection_kind": self.projection_kind,
            "workspace_root": self.workspace_root,
            "state_dir": self.state_dir,
            "provider_registry": self.provider_registry,
            "browser_discovery": self.browser_discovery,
            "record_count": self.record_count,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
        })
    }
}

fn normalized_projection_kind(
    request: &RuntimeComputerUseProjectionRequest,
) -> Result<String, RuntimeComputerUseProjectionCommandError> {
    if let Some(value) = optional_trimmed_lower(request.projection_kind.as_deref()) {
        return match value.as_str() {
            "providers" | "provider_registry" => Ok("provider_registry".to_string()),
            "browser_discovery" => Ok("browser_discovery".to_string()),
            _ => Ok(value),
        };
    }
    let operation_kind = optional_trimmed(request.operation_kind.as_deref()).unwrap_or_default();
    if operation_kind.ends_with(".provider_registry") || operation_kind.ends_with(".providers") {
        return Ok("provider_registry".to_string());
    }
    if operation_kind.ends_with(".browser_discovery") {
        return Ok("browser_discovery".to_string());
    }
    Err(RuntimeComputerUseProjectionCommandError::new(
        "runtime_computer_use_projection_kind_required",
        "runtime computer-use projection kind is required",
    ))
}

fn browser_discovery_report(request: &RuntimeComputerUseProjectionRequest) -> Value {
    let platform = optional_trimmed(request.platform.as_deref()).unwrap_or_else(host_platform);
    let discovered_at = optional_trimmed(request.discovered_at.as_deref()).unwrap_or_else(now_utc);
    let rows = request
        .process_rows
        .clone()
        .unwrap_or_else(|| list_browser_process_rows(&platform));
    let processes = rows
        .iter()
        .filter_map(|row| parse_browser_process_row(row, &platform))
        .filter(|process| !process.is_browser_child_process)
        .collect::<Vec<_>>();
    let mut cdp_endpoints = cdp_endpoints_for_browser_processes(&processes);
    let cdp_probe_enabled = request.include_cdp_probe;
    if cdp_probe_enabled {
        cdp_endpoints = cdp_endpoints
            .into_iter()
            .map(|endpoint| {
                probe_cdp_endpoint(
                    endpoint,
                    request.include_tab_metadata,
                    request.reveal_tab_titles,
                    request.probe_timeout_ms.unwrap_or(500),
                )
            })
            .collect();
    }
    json!({
        "schema_version": COMPUTER_USE_BROWSER_DISCOVERY_SCHEMA_VERSION,
        "object": "ioi.computer_use.browser_discovery_report",
        "receipt_ref": discovery_receipt_ref(&discovered_at, &platform, &processes, &cdp_endpoints),
        "discovered_at": discovered_at,
        "platform": platform,
        "process_count": rows.len(),
        "browser_process_count": processes.len(),
        "browser_processes": processes.iter().map(BrowserProcess::to_value).collect::<Vec<_>>(),
        "cdp_endpoint_count": cdp_endpoints.len(),
        "cdp_endpoints": cdp_endpoints,
        "default_profile_remote_debugging_blockers": default_profile_remote_debugging_blockers(&processes),
        "safety": {
            "read_only": true,
            "mutated_browser_state": false,
            "copied_profiles": false,
            "copied_credentials": false,
            "raw_profile_paths_redacted": true,
            "raw_command_lines_redacted": true,
            "cdp_probe_enabled": cdp_probe_enabled,
            "cdp_probe_scope": "declared_remote_debugging_ports_only",
        },
        "recommended_next_steps": recommended_browser_discovery_next_steps(&processes, &cdp_endpoints),
    })
}

#[derive(Debug, Clone)]
struct BrowserProcess {
    process_ref: String,
    pid: u64,
    ppid: u64,
    command: String,
    browser_family: String,
    is_browser_child_process: bool,
    has_remote_debugging_port: bool,
    remote_debugging_port: Option<u16>,
    remote_debugging_address: Option<String>,
    user_data_dir_present: bool,
    user_data_dir_hash: Option<String>,
    profile_directory_present: bool,
    profile_directory_hash: Option<String>,
    profile_provenance: String,
    default_profile_cdp_refusal_risk: bool,
    cdp_status: String,
    redacted_flags: Vec<Value>,
}

impl BrowserProcess {
    fn to_value(&self) -> Value {
        json!({
            "process_ref": self.process_ref,
            "pid": self.pid,
            "ppid": self.ppid,
            "command": self.command,
            "browser_family": self.browser_family,
            "is_browser_child_process": self.is_browser_child_process,
            "has_remote_debugging_port": self.has_remote_debugging_port,
            "remote_debugging_port": self.remote_debugging_port,
            "remote_debugging_address": self.remote_debugging_address,
            "user_data_dir_present": self.user_data_dir_present,
            "user_data_dir_hash": self.user_data_dir_hash,
            "profile_directory_present": self.profile_directory_present,
            "profile_directory_hash": self.profile_directory_hash,
            "profile_provenance": self.profile_provenance,
            "default_profile_cdp_refusal_risk": self.default_profile_cdp_refusal_risk,
            "cdp_status": self.cdp_status,
            "redacted_flags": self.redacted_flags,
        })
    }
}

fn parse_browser_process_row(row: &str, platform: &str) -> Option<BrowserProcess> {
    let parsed = if platform == "win32" {
        parse_windows_process_row(row)?
    } else {
        parse_posix_process_row(row)?
    };
    let family = browser_family_for_process(&parsed.command, &parsed.args)?;
    let remote_debugging_port =
        safe_positive_u16(browser_flag_value(&parsed.args, "--remote-debugging-port").as_deref());
    let remote_debugging_address = remote_debugging_port.map(|_| {
        browser_flag_value(&parsed.args, "--remote-debugging-address")
            .unwrap_or_else(|| "127.0.0.1".to_string())
    });
    let user_data_dir = browser_flag_value(&parsed.args, "--user-data-dir");
    let profile_directory = browser_flag_value(&parsed.args, "--profile-directory");
    let is_child = format!(" {}", parsed.args).contains(" --type=");
    let process_ref = format!(
        "browser_process_{}",
        &stable_hash(&format!(
            "{}:{}:{}",
            parsed.pid, parsed.command, parsed.args
        ))[..16]
    );
    Some(BrowserProcess {
        process_ref,
        pid: parsed.pid,
        ppid: parsed.ppid,
        command: parsed.command,
        browser_family: family,
        is_browser_child_process: is_child,
        has_remote_debugging_port: remote_debugging_port.is_some(),
        remote_debugging_port,
        remote_debugging_address,
        user_data_dir_present: user_data_dir.is_some(),
        user_data_dir_hash: user_data_dir.as_deref().map(stable_hash),
        profile_directory_present: profile_directory.is_some(),
        profile_directory_hash: profile_directory.as_deref().map(stable_hash),
        profile_provenance: if user_data_dir.is_some() {
            "explicit_user_data_dir_redacted".to_string()
        } else {
            "implicit_default_profile_or_unknown".to_string()
        },
        default_profile_cdp_refusal_risk: user_data_dir.is_none()
            && remote_debugging_port.is_some(),
        cdp_status: if remote_debugging_port.is_some() {
            "declared_not_probed".to_string()
        } else {
            "not_exposed".to_string()
        },
        redacted_flags: browser_flag_summary(&parsed.args),
    })
}

struct ParsedProcessRow {
    pid: u64,
    ppid: u64,
    command: String,
    args: String,
}

fn parse_posix_process_row(text: &str) -> Option<ParsedProcessRow> {
    let mut parts = text.trim().split_whitespace();
    let pid = parts.next()?.parse::<u64>().ok()?;
    let ppid = parts.next()?.parse::<u64>().ok()?;
    let command = parts.next()?.to_string();
    let args = parts.collect::<Vec<_>>().join(" ");
    Some(ParsedProcessRow {
        pid,
        ppid,
        command,
        args,
    })
}

fn parse_windows_process_row(text: &str) -> Option<ParsedProcessRow> {
    let parts = text.split(',').collect::<Vec<_>>();
    if parts.len() < 5 || parts.first().copied() == Some("Node") {
        return None;
    }
    Some(ParsedProcessRow {
        pid: parts.get(4)?.trim().parse::<u64>().ok()?,
        ppid: parts.get(3)?.trim().parse::<u64>().ok()?,
        command: parts.get(2).copied().unwrap_or_default().trim().to_string(),
        args: parts
            .get(1..parts.len().saturating_sub(3))
            .unwrap_or(&[])
            .join(",")
            .trim()
            .to_string(),
    })
}

fn list_browser_process_rows(platform: &str) -> Vec<String> {
    let output = if platform == "win32" {
        Command::new("wmic")
            .args([
                "process",
                "get",
                "ProcessId,ParentProcessId,Name,CommandLine",
                "/FORMAT:CSV",
            ])
            .output()
    } else {
        Command::new("ps")
            .args(["-eo", "pid=,ppid=,comm=,args="])
            .output()
    };
    output
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn browser_family_for_process(command: &str, args: &str) -> Option<String> {
    let first_arg = args.split_whitespace().next().unwrap_or_default();
    let haystack = format!("{command} {first_arg}").to_ascii_lowercase();
    let families = [
        (
            "chrome",
            ["google-chrome", "google chrome", "chrome", "chrome.exe"],
        ),
        (
            "chromium",
            ["chromium", "chromium-browser", "chromium.exe", ""],
        ),
        ("brave", ["brave", "brave-browser", "brave.exe", ""]),
        ("edge", ["microsoft-edge", "msedge", "edge.exe", ""]),
        ("vivaldi", ["vivaldi", "vivaldi-bin", "vivaldi.exe", ""]),
    ];
    families.iter().find_map(|(family, patterns)| {
        patterns
            .iter()
            .filter(|pattern| !pattern.is_empty())
            .any(|pattern| haystack.contains(pattern))
            .then(|| (*family).to_string())
    })
}

fn browser_flag_value(args: &str, flag: &str) -> Option<String> {
    let tokens = args.split_whitespace().collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        if *token == flag {
            return tokens.get(index + 1).map(|value| strip_quotes(value));
        }
        if let Some(value) = token.strip_prefix(&format!("{flag}=")) {
            return Some(strip_quotes(value));
        }
    }
    None
}

fn browser_flag_summary(args: &str) -> Vec<Value> {
    [
        "--remote-debugging-port",
        "--remote-debugging-address",
        "--user-data-dir",
        "--profile-directory",
        "--app",
        "--headless",
    ]
    .iter()
    .filter_map(|flag| {
        browser_flag_value(args, flag).map(|value| {
            let redacted = if matches!(*flag, "--user-data-dir" | "--profile-directory" | "--app") {
                format!("sha256:{}", &stable_hash(&value)[..16])
            } else {
                value
            };
            json!({ "flag": flag, "value": redacted })
        })
    })
    .collect()
}

fn cdp_endpoints_for_browser_processes(processes: &[BrowserProcess]) -> Vec<Value> {
    processes
        .iter()
        .filter_map(|process| {
            let port = process.remote_debugging_port?;
            let host = endpoint_host_for_address(process.remote_debugging_address.as_deref());
            let endpoint_ref = format!(
                "cdp_endpoint_{}",
                &stable_hash(&format!("{}:{host}:{port}", process.process_ref))[..16]
            );
            Some(json!({
                "endpoint_ref": endpoint_ref,
                "process_ref": process.process_ref,
                "pid": process.pid,
                "browser_family": process.browser_family,
                "host": host,
                "port": port,
                "endpoint_url": format!("http://{host}:{port}"),
                "source": "remote_debugging_process_flag",
                "status": "declared_not_probed",
                "browser": null,
                "protocol_version": null,
                "tab_count": null,
                "tabs": [],
            }))
        })
        .collect()
}

fn probe_cdp_endpoint(
    endpoint: Value,
    include_tab_metadata: bool,
    reveal_tab_titles: bool,
    timeout_ms: u64,
) -> Value {
    let host = endpoint
        .get("host")
        .and_then(Value::as_str)
        .unwrap_or("127.0.0.1")
        .to_string();
    let port = endpoint.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
    match fetch_json_from_local_http(&host, port, "/json/version", timeout_ms) {
        Ok(version) => {
            let tabs = if include_tab_metadata {
                fetch_json_from_local_http(&host, port, "/json/list", timeout_ms)
                    .ok()
                    .map(|value| sanitize_cdp_tabs(&value, reveal_tab_titles))
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            merge_json(
                endpoint,
                json!({
                    "status": "available",
                    "browser": string_or_null(version.get("Browser")),
                    "protocol_version": string_or_null(version.get("Protocol-Version")),
                    "tab_count": tabs.len(),
                    "tabs": tabs,
                }),
            )
        }
        Err(error_summary) => merge_json(
            endpoint,
            json!({
                "status": "unreachable",
                "error_class": "CdpProbeError",
                "error_summary": error_summary,
            }),
        ),
    }
}

fn fetch_json_from_local_http(
    host: &str,
    port: u16,
    path: &str,
    timeout_ms: u64,
) -> Result<Value, String> {
    let timeout = Duration::from_millis(timeout_ms.clamp(50, 10_000));
    let address = (host, port)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .next()
        .ok_or_else(|| "no socket address resolved".to_string())?;
    let mut stream =
        TcpStream::connect_timeout(&address, timeout).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| error.to_string())?;
    if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
        return Err(response
            .lines()
            .next()
            .unwrap_or("HTTP request failed")
            .to_string());
    }
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or_else(|| "HTTP response body missing".to_string())?;
    serde_json::from_str(body).map_err(|error| error.to_string())
}

fn sanitize_cdp_tabs(value: &Value, reveal_titles: bool) -> Vec<Value> {
    value
        .as_array()
        .map(|tabs| {
            tabs.iter()
                .take(20)
                .map(|tab| {
                    let url = string_or_null(tab.get("url"));
                    let title = string_or_null(tab.get("title"));
                    json!({
                        "tab_ref": format!(
                            "cdp_tab_{}",
                            &stable_hash(&format!(
                                "{}:{}",
                                tab.get("id").and_then(Value::as_str).unwrap_or_default(),
                                url.as_deref().unwrap_or_default()
                            ))[..16]
                        ),
                        "type": string_or_null(tab.get("type")),
                        "title": if reveal_titles { title.clone() } else { None },
                        "title_hash": title.as_deref().map(stable_hash),
                        "url_origin": url.as_deref().and_then(url_origin),
                        "url_hash": url.as_deref().map(stable_hash),
                        "attached": tab.get("webSocketDebuggerUrl").and_then(Value::as_str).is_some(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn default_profile_remote_debugging_blockers(processes: &[BrowserProcess]) -> Vec<Value> {
    processes
        .iter()
        .filter(|process| process.default_profile_cdp_refusal_risk)
        .map(|process| {
            json!({
                "process_ref": process.process_ref,
                "pid": process.pid,
                "browser_family": process.browser_family,
                "reason": "remote_debugging_port_declared_without_explicit_user_data_dir",
                "recommended_branch": "request_consent_for_attach_or_controlled_relaunch_with_non_default_profile",
            })
        })
        .collect()
}

fn recommended_browser_discovery_next_steps(
    processes: &[BrowserProcess],
    cdp_endpoints: &[Value],
) -> Vec<&'static str> {
    if !cdp_endpoints.is_empty() {
        return vec![
            "Request explicit consent before attaching to any exposed CDP endpoint.",
            "Use the endpoint only through the computer-use lease and receipt spine.",
        ];
    }
    if !processes.is_empty() {
        return vec![
            "No declared CDP endpoint was discovered.",
            "Offer owned browser or consented controlled relaunch instead of mutating the user browser.",
        ];
    }
    vec![
        "No browser process was discovered.",
        "Use owned hermetic browser mode or ask the user to open a browser if attachment is required.",
    ]
}

fn discovery_receipt_ref(
    discovered_at: &str,
    platform: &str,
    processes: &[BrowserProcess],
    cdp_endpoints: &[Value],
) -> String {
    let process_refs = processes
        .iter()
        .map(|process| process.process_ref.as_str())
        .collect::<Vec<_>>();
    let endpoint_refs = cdp_endpoints
        .iter()
        .filter_map(|endpoint| endpoint.get("endpoint_ref").and_then(Value::as_str))
        .collect::<Vec<_>>();
    format!(
        "receipt_computer_use_browser_discovery_{}",
        &stable_hash(
            &json!({
                "discovered_at": discovered_at,
                "platform": platform,
                "processes": process_refs,
                "cdp_endpoints": endpoint_refs,
            })
            .to_string()
        )[..16]
    )
}

fn merge_json(base: Value, patch: Value) -> Value {
    let mut merged = base.as_object().cloned().unwrap_or_default();
    if let Some(values) = patch.as_object() {
        for (key, value) in values {
            merged.insert(key.clone(), value.clone());
        }
    }
    Value::Object(merged)
}

fn endpoint_host_for_address(address: Option<&str>) -> String {
    match address {
        Some("") | None | Some("0.0.0.0") | Some("::") => "127.0.0.1".to_string(),
        Some(value) => value.to_string(),
    }
}

fn safe_positive_u16(value: Option<&str>) -> Option<u16> {
    value?.parse::<u16>().ok().filter(|number| *number > 0)
}

fn string_or_null(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn url_origin(value: &str) -> Option<String> {
    url::Url::parse(value)
        .ok()
        .map(|url| url.origin().ascii_serialization())
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn optional_trimmed_lower(value: Option<&str>) -> Option<String> {
    optional_trimmed(value).map(|value| value.to_ascii_lowercase())
}

fn strip_quotes(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn stable_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn host_platform() -> String {
    if cfg!(target_os = "windows") {
        "win32".to_string()
    } else if cfg!(target_os = "macos") {
        "darwin".to_string()
    } else {
        "linux".to_string()
    }
}

fn now_utc() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "rust_daemon_core".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_projects_computer_use_provider_registry_from_shared_step_module_registry() {
        let record = RuntimeComputerUseProjectionCore::default()
            .project(RuntimeComputerUseProjectionRequest {
                projection_kind: Some("provider_registry".to_string()),
                ..RuntimeComputerUseProjectionRequest::default()
            })
            .expect("provider registry projection");

        assert_eq!(
            record.operation_kind,
            "runtime.computer_use.projection.provider_registry"
        );
        let registry = record.provider_registry.expect("registry");
        let provider_ids = registry["providers"]
            .as_array()
            .expect("providers")
            .iter()
            .filter_map(|provider| provider.get("provider_id").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert!(provider_ids.contains(&"ioi.computer_use.sandboxed_hosted.local_fixture"));
        assert!(provider_ids.contains(&"ioi.computer_use.sandboxed_hosted.local_container"));
        assert_eq!(
            registry["fail_closed_when_unavailable"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn rust_browser_discovery_redacts_profile_paths_and_excludes_child_processes() {
        let record = RuntimeComputerUseProjectionCore::default()
            .project(RuntimeComputerUseProjectionRequest {
                projection_kind: Some("browser_discovery".to_string()),
                platform: Some("linux".to_string()),
                discovered_at: Some("2026-05-14T00:00:00Z".to_string()),
                process_rows: Some(vec![
                    "100 1 google-chrome google-chrome --remote-debugging-port=9222 --user-data-dir=/home/alice/.config/google-chrome-debug --profile-directory=Default".to_string(),
                    "101 100 chrome chrome --type=renderer --user-data-dir=/home/alice/.config/google-chrome-debug".to_string(),
                    "200 1 chromium-browser chromium-browser --remote-debugging-port=9333".to_string(),
                    "300 1 bash bash -lc echo chrome".to_string(),
                ]),
                ..RuntimeComputerUseProjectionRequest::default()
            })
            .expect("browser discovery projection");

        assert_eq!(
            record.operation_kind,
            "runtime.computer_use.projection.browser_discovery"
        );
        let report = record.browser_discovery.expect("browser discovery");
        assert_eq!(
            report["schema_version"],
            COMPUTER_USE_BROWSER_DISCOVERY_SCHEMA_VERSION
        );
        assert_eq!(report["process_count"], 4);
        assert_eq!(report["browser_process_count"], 2);
        assert_eq!(report["cdp_endpoint_count"], 2);
        assert_eq!(
            report["browser_processes"][0]["browser_family"].as_str(),
            Some("chrome")
        );
        assert_eq!(
            report["browser_processes"][0]["remote_debugging_port"].as_u64(),
            Some(9222)
        );
        assert_eq!(
            report["browser_processes"][0]["user_data_dir_present"].as_bool(),
            Some(true)
        );
        assert_eq!(
            report["browser_processes"][1]["default_profile_cdp_refusal_risk"].as_bool(),
            Some(true)
        );
        assert_eq!(
            report["default_profile_remote_debugging_blockers"]
                .as_array()
                .expect("blockers")
                .len(),
            1
        );
        assert!(!report.to_string().contains("/home/alice"));
    }

    #[test]
    fn rust_browser_discovery_ignores_retired_request_aliases() {
        let request = serde_json::from_value::<RuntimeComputerUseProjectionRequest>(json!({
            "projection_kind": "browser_discovery",
            "platform": "linux",
            "process_rows": [],
            "includeTabs": true,
            "revealTabTitles": true,
        }))
        .expect("request");
        assert!(!request.include_tab_metadata);
        assert!(!request.reveal_tab_titles);
    }
}
