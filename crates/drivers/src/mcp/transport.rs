// Path: crates/drivers/src/mcp/transport.rs

use anyhow::{anyhow, Result};
use ioi_types::config::{McpContainmentConfig, McpContainmentMode, McpMode};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot, Mutex};

use super::protocol::MCP_PROTOCOL_VERSION;

/// The JSON-RPC error code this client answers a server-initiated primitive with. JSON-RPC reserves
/// -32000..-32099 for implementation-defined server errors; this is the estate's typed-unavailable.
pub const MCP_TYPED_UNAVAILABLE_CODE: i64 = -32001;

/// The canonical owner a server-initiated primitive WOULD normalize to, so a refusal names the thing that
/// would have to exist rather than saying only "no". The map is canon's (M01.10): every exposed MCP
/// primitive resolves to an existing canonical owner or fails typed-unavailable, and this client serves
/// tools only. `roots` is the one entry that is this client's own to serve and does not yet.
fn normalization_refusal(method: &str) -> Value {
    let (primitive, canonical_owner) = match method {
        "sampling/createMessage" => ("mcp.sampling", "ModelRoute+HarnessInvocation"),
        "elicitation/create" => ("mcp.elicitation", "typed-user-input-request"),
        "roots/list" => ("mcp.roots", "WorkspaceRootProjection"),
        "logging/setLevel" => ("mcp.logging", "RuntimeObservability"),
        method if method.starts_with("notifications/") => {
            ("mcp.notification", "RuntimeEventStream")
        }
        _ => ("mcp.unknown", "none"),
    };
    json!({
        "schema_version": "ioi.runtime.mcp-normalization-decision.v1",
        "status": "typed_unavailable",
        "primitive": primitive,
        "canonical_owner": canonical_owner,
        "canonical_backing_ref": Value::Null,
        "normalization_decision": "typed_unavailable",
        "authority_granted": false,
        "receipt_identity_granted": false,
        "source_protocol_version": MCP_PROTOCOL_VERSION,
        "policy_lease_posture": "not_minted",
        "reason": "This client implements the tool primitive only; every other MCP primitive is typed unavailable and grants no authority and no receipt identity.",
    })
}

#[derive(Debug, Clone)]
pub struct McpSpawnPolicy {
    pub containment: McpContainmentConfig,
    pub mode: McpMode,
}

/// Handles the JSON-RPC 2.0 communication over Stdio.
pub struct McpTransport {
    _child: Mutex<tokio::process::Child>,
    request_id: AtomicU64,
    tx_sender: mpsc::Sender<Value>,
    pending_requests:
        std::sync::Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>>,
}

impl McpTransport {
    pub async fn spawn(
        cmd: String,
        args: Vec<String>,
        env: HashMap<String, String>,
        policy: McpSpawnPolicy,
    ) -> Result<Self> {
        let mut command = Command::new(cmd);
        command.kill_on_drop(true);
        command.args(args);
        command.env_clear();
        command.env("PATH", "/usr/bin:/bin");
        command.env(
            "IOI_MCP_MODE",
            format!("{:?}", policy.mode).to_ascii_lowercase(),
        );

        if let Some(root) = policy.containment.workspace_root.as_deref() {
            std::fs::create_dir_all(root)?;
            let tmp_dir = std::path::Path::new(root).join(".tmp");
            std::fs::create_dir_all(&tmp_dir)?;
            command.current_dir(root);
            command.env("HOME", root);
            command.env("TMPDIR", tmp_dir.to_string_lossy().to_string());
        }

        // No ambient secret inheritance. Only explicitly configured vars are passed through.
        for (key, value) in env {
            command.env(key, value);
        }

        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        if policy.containment.mode == McpContainmentMode::Strict {
            apply_strict_containment(&mut command, &policy)?;
        } else if policy.mode == McpMode::Production {
            return Err(anyhow!(
                "ERROR_CLASS=PolicyBlocked production MCP mode requires strict containment"
            ));
        }

        let mut child = command.spawn()?;

        let stdin = child.stdin.take().ok_or(anyhow!("Failed to open stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or(anyhow!("Failed to open stdout"))?;

        let (tx, mut rx) = mpsc::channel::<Value>(32);
        // The reader task answers server-initiated requests, so it needs the writer's end too.
        let inbound_tx = tx.clone();

        let pending: std::sync::Arc<
            std::sync::Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        let pending_clone = pending.clone();

        tokio::spawn(async move {
            let mut writer = stdin;
            while let Some(msg) = rx.recv().await {
                let json_str = msg.to_string();
                if let Err(e) = writer.write_all(format!("{}\n", json_str).as_bytes()).await {
                    log::error!("MCP Write Error: {}", e);
                    break;
                }
            }
        });

        tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();

            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(json) = serde_json::from_str::<Value>(&line) {
                    let pending_id = json
                        .get("id")
                        .and_then(|i| i.as_u64())
                        .filter(|_id| json.get("method").is_none());
                    if let Some(id) = pending_id {
                        let mut map = pending_clone.lock().unwrap();
                        if let Some(sender) = map.remove(&id) {
                            if let Some(err) = json.get("error") {
                                let _ = sender.send(Err(anyhow!("MCP Error: {}", err)));
                            } else if let Some(res) = json.get("result") {
                                let _ = sender.send(Ok(res.clone()));
                            }
                        }
                        continue;
                    }
                    // A SERVER-INITIATED MESSAGE IS ANSWERED, NOT DROPPED (M01.10, R-219). This branch used
                    // to log "Auto-acking" and write nothing, and a message with no `id` never reached it at
                    // all — so `sampling/createMessage`, `elicitation/create`, `roots/list` and every
                    // `notifications/*` left the server waiting on a reply that never came. A primitive this
                    // client does not implement is TYPED UNAVAILABLE, which is a different fact from silence:
                    // the server learns the request was understood and refused, and learns which canonical
                    // owner would have to exist for it to be served. A notification carries no `id` and is
                    // therefore unanswerable by the protocol; it is counted and dropped deliberately.
                    if let Some(method) = json.get("method").and_then(Value::as_str) {
                        let decision = normalization_refusal(method);
                        match json.get("id") {
                            Some(id) if !id.is_null() => {
                                let refusal = json!({
                                    "jsonrpc": "2.0",
                                    "id": id.clone(),
                                    "error": {
                                        "code": MCP_TYPED_UNAVAILABLE_CODE,
                                        "message": format!(
                                            "{method} is not implemented by this client and is typed unavailable"
                                        ),
                                        "data": decision,
                                    },
                                });
                                if let Err(error) = inbound_tx.send(refusal).await {
                                    tracing::debug!(
                                        "MCP: could not answer server-initiated '{method}': {error}"
                                    );
                                }
                            }
                            _ => tracing::debug!(
                                "MCP: server notification '{method}' carries no id and cannot be answered; \
                                 it is dropped without being treated as admitted truth"
                            ),
                        }
                    }
                }
            }
        });

        Ok(Self {
            _child: Mutex::new(child),
            request_id: AtomicU64::new(0),
            tx_sender: tx,
            pending_requests: pending,
        })
    }

    async fn send_request(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();

        {
            let mut map = self.pending_requests.lock().unwrap();
            map.insert(id, tx);
        }

        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });

        self.tx_sender
            .send(req)
            .await
            .map_err(|_| anyhow!("MCP Server crashed (channel closed)"))?;

        match tokio::time::timeout(mcp_request_timeout(), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(anyhow!("MCP Server dropped response")),
            Err(_) => {
                let mut map = self.pending_requests.lock().unwrap();
                map.remove(&id);
                Err(anyhow!(
                    "MCP request '{}' timed out after {}s",
                    method,
                    mcp_request_timeout().as_secs()
                ))
            }
        }
    }

    pub async fn initialize(&self) -> Result<()> {
        let params = json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            // NO CAPABILITY THIS CLIENT DOES NOT SERVE (M01.10, R-219). It advertised
            // `roots: {listChanged: true}` and served no `roots/list`, so a server could reasonably ask and
            // get nothing. An empty capability object is the honest declaration.
            "capabilities": {},
            "clientInfo": { "name": "ioi-kernel", "version": "0.1.0" }
        });

        let init_fut = self.send_request("initialize", params);
        match tokio::time::timeout(std::time::Duration::from_secs(60), init_fut).await {
            Ok(Ok(result)) => {
                let negotiated = result
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("MCP Initialize response omitted protocolVersion"))?;
                if negotiated != MCP_PROTOCOL_VERSION {
                    return Err(anyhow!(
                        "MCP Initialize negotiated unsupported protocolVersion '{}'; expected '{}'",
                        negotiated,
                        MCP_PROTOCOL_VERSION
                    ));
                }
            }
            Ok(Err(e)) => return Err(anyhow!("MCP Initialize failed: {}", e)),
            Err(_) => return Err(anyhow!("MCP Initialize timed out (60s).")),
        }

        let notify = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        self.tx_sender.send(notify).await?;
        Ok(())
    }

    pub async fn list_tools(&self) -> Result<Vec<super::protocol::Tool>> {
        let res = self.send_request("tools/list", json!({})).await?;
        serde_json::from_value(res["tools"].clone()).map_err(|e| anyhow!(e))
    }

    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
        let params = json!({
            "name": name,
            "arguments": arguments
        });
        self.send_request("tools/call", params).await
    }

    /// Stop the owned MCP subprocess and fail every request that was waiting on it.
    /// `kill_on_drop` remains the last-resort containment boundary, while this
    /// explicit path makes disable/remove deterministic for the control plane.
    pub async fn shutdown(&self) -> Result<()> {
        {
            let mut pending = self.pending_requests.lock().unwrap();
            for (_, sender) in pending.drain() {
                let _ = sender.send(Err(anyhow!("MCP Server stopped")));
            }
        }

        let mut child = self._child.lock().await;
        if child.try_wait()?.is_none() {
            child.kill().await?;
        }
        Ok(())
    }
}

fn mcp_request_timeout() -> Duration {
    std::env::var("IOI_MCP_REQUEST_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(60))
}

fn apply_strict_containment(command: &mut Command, policy: &McpSpawnPolicy) -> Result<()> {
    #[cfg(unix)]
    {
        let allow_child_processes = policy.containment.allow_child_processes;
        let allow_network_egress = policy.containment.allow_network_egress;
        let mode = policy.mode;

        // Best-effort hardening at process boundary: clear env, restrict child process fan-out,
        // and disable network namespace where the kernel permits unprivileged netns unshare.
        unsafe {
            command.pre_exec(move || {
                if !allow_child_processes {
                    let nproc = libc::rlimit {
                        rlim_cur: 1,
                        rlim_max: 1,
                    };
                    if libc::setrlimit(libc::RLIMIT_NPROC, &nproc) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }

                #[cfg(target_os = "linux")]
                {
                    if !allow_network_egress && libc::unshare(libc::CLONE_NEWNET) != 0 {
                        let err = std::io::Error::last_os_error();
                        let code = err.raw_os_error().unwrap_or_default();
                        let dev_fallback = mode == McpMode::Development
                            && matches!(
                                code,
                                libc::EPERM | libc::EACCES | libc::EINVAL | libc::ENOSYS
                            );
                        if !dev_fallback {
                            return Err(err);
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    if !allow_network_egress {
                        if mode != McpMode::Development {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Unsupported,
                                "strict MCP network containment requires Linux",
                            ));
                        }
                    }
                }

                Ok(())
            });
        }
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        if !policy.containment.allow_network_egress || !policy.containment.allow_child_processes {
            if policy.mode != McpMode::Development {
                return Err(anyhow!(
                    "strict MCP containment is not fully supported on this platform"
                ));
            }
        }
        Ok(())
    }
}

#[derive(serde::Deserialize)]
pub struct McpToolInfo {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

#[cfg(test)]
mod normalization_tests {
    use super::*;
    use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
    use ioi_types::config::{McpContainmentConfig, McpContainmentMode, McpMode};
    use std::io::Write as _;

    const DECISION_CONTRACT: &str =
        "schema://ioi/components/hypervisor/mcp-primitive-normalization-decision/v1";

    /// A stub MCP server over stdio, written at test time and run by the REAL client.
    ///
    /// It answers `initialize` and `tools/list`, records every line this client sends it, and — once
    /// initialized — initiates ONE message of its own. That message is the subject: before M01.10 the
    /// client dropped it, so the stub would have waited for a reply that never came, which a server cannot
    /// tell apart from a hung client.
    const STUB: &str = r#"
const fs = require("fs");
const out = process.env.STUB_RECORD;
const initiate = JSON.parse(process.env.STUB_INITIATE);
const seen = [];
let sent = false;
const write = (o) => process.stdout.write(JSON.stringify(o) + "\n");
require("readline").createInterface({ input: process.stdin }).on("line", (line) => {
  let msg = null;
  try { msg = JSON.parse(line); } catch { return; }
  seen.push(msg);
  fs.writeFileSync(out, JSON.stringify(seen));
  if (msg.method === "initialize") {
    write({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "stub", version: "0" } } });
  } else if (msg.method === "notifications/initialized" && !sent) {
    sent = true;
    write(initiate);
  } else if (msg.method === "tools/list") {
    write({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo", description: "d", inputSchema: { type: "object" } }] } });
  } else if (msg.method === "shutdown") {
    write({ jsonrpc: "2.0", id: msg.id, result: {} });
  }
});
"#;

    fn node_binary() -> Option<String> {
        let which = std::process::Command::new("which")
            .arg("node")
            .output()
            .ok()?;
        let path = String::from_utf8(which.stdout).ok()?.trim().to_string();
        (!path.is_empty()).then_some(path)
    }

    /// Spawn the real client against the stub and hand back every line the stub received.
    ///
    /// `settled` decides when the exchange is over. The client's answer and this test's own `tools/list`
    /// are queued on the SAME writer channel from two tasks, so their order is not fixed and a fixed sleep
    /// would be a flake waiting for a loaded machine — which is exactly what it was until this leg's own
    /// gate run caught it. The wait is on the stub's record, bounded, and its expiry is a failure.
    async fn drive_stub(initiate: Value, settled: fn(&[Value]) -> bool) -> Vec<Value> {
        let node = node_binary().expect(
            "this leg drives the REAL stdio client against a stub MCP server, so it needs node on PATH; \
             a missing interpreter is a blocked RUN and must not be reported as a passing client",
        );
        let dir = std::env::temp_dir().join(format!(
            "ioi-mcp-stub-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("stub.js");
        let record = dir.join("received.json");
        std::fs::File::create(&script)
            .unwrap()
            .write_all(STUB.as_bytes())
            .unwrap();

        let mut env = HashMap::new();
        env.insert(
            "STUB_RECORD".to_string(),
            record.to_string_lossy().to_string(),
        );
        env.insert("STUB_INITIATE".to_string(), initiate.to_string());
        let policy = McpSpawnPolicy {
            containment: McpContainmentConfig {
                mode: McpContainmentMode::DeveloperUnconfined,
                allow_network_egress: false,
                allow_child_processes: false,
                workspace_root: Some(dir.to_string_lossy().to_string()),
            },
            mode: McpMode::Development,
        };
        let transport = McpTransport::spawn(
            node,
            vec![script.to_string_lossy().to_string()],
            env,
            policy,
        )
        .await
        .expect("the stub MCP server starts");
        transport.initialize().await.expect("initialize succeeds");
        // One round trip AFTER the server initiated its own message: it proves the session is still
        // usable, and it gives the client's answer time to reach the stub.
        let tools = transport
            .list_tools()
            .await
            .expect("tools/list still works");
        assert_eq!(tools.len(), 1, "the session is unusable after the exchange");
        let read_record = || -> Vec<Value> {
            std::fs::read_to_string(&record)
                .ok()
                .and_then(|text| serde_json::from_str(&text).ok())
                .unwrap_or_default()
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut seen = read_record();
        while !settled(&seen) && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
            seen = read_record();
        }
        let _ = transport.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
        seen
    }

    /// THE CLIENT ANSWERS. A server-initiated request this client does not implement comes back as a
    /// JSON-RPC error carrying the registered decision, not as silence.
    #[tokio::test]
    async fn a_server_initiated_request_is_answered_with_the_typed_refusal() {
        let seen = drive_stub(
            json!({
                "jsonrpc": "2.0",
                "id": 9001,
                "method": "sampling/createMessage",
                "params": { "messages": [] }
            }),
            |seen| {
                seen.iter()
                    .any(|m| m.get("id").and_then(Value::as_u64) == Some(9001))
            },
        )
        .await;
        let answer = seen
            .iter()
            .find(|m| m.get("id").and_then(Value::as_u64) == Some(9001))
            .unwrap_or_else(|| {
                panic!("the client never answered the server-initiated request; it saw {seen:?}")
            });
        assert_eq!(answer["jsonrpc"], "2.0");
        assert!(
            answer.get("result").is_none(),
            "a refusal must not carry a result"
        );
        assert_eq!(answer["error"]["code"], MCP_TYPED_UNAVAILABLE_CODE);
        let decision = &answer["error"]["data"];
        validate_architecture_contract(DECISION_CONTRACT, decision)
            .expect("the refusal on the wire is contract-valid");
        assert_eq!(decision["primitive"], "mcp.sampling");
        assert_eq!(decision["canonical_owner"], "ModelRoute+HarnessInvocation");
        assert_eq!(decision["authority_granted"], false);
        assert_eq!(decision["receipt_identity_granted"], false);
    }

    /// A NOTIFICATION IS NOT ANSWERED. JSON-RPC forbids replying to a message with no id, so this one is
    /// dropped deliberately — and the drop is only honest because the session keeps working, which is
    /// what the round trip inside `drive_stub` asserts.
    #[tokio::test]
    async fn a_server_notification_is_dropped_and_the_session_stays_usable() {
        // The stub sends its notification BEFORE this client's tools/list, so waiting for tools/list to be
        // recorded means the notification has already been read and the client has had its chance to
        // answer it. The negative that follows is therefore a measurement, not a guess about timing.
        let seen = drive_stub(
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": { "level": "info", "data": "hello" }
            }),
            |seen| {
                seen.iter()
                    .any(|m| m.get("method").and_then(Value::as_str) == Some("tools/list"))
            },
        )
        .await;
        assert!(
            !seen.iter().any(|m| m.get("error").is_some()),
            "the client answered a notification, which the protocol forbids: {seen:?}"
        );
        assert!(
            seen.iter()
                .any(|m| m.get("method").and_then(Value::as_str) == Some("tools/list")),
            "the session did not survive the notification: {seen:?}"
        );
    }

    /// The refusal this client writes onto the wire is the SAME registered contract the daemon's routes
    /// serve. Before M01.10 the client had no answer at all — a server-initiated primitive was dropped,
    /// which is indistinguishable from a hung client — and the two daemon answers were divergent shapes
    /// under one schema version. One contract, checked from the crate that emits it.
    #[test]
    fn every_server_initiated_refusal_is_the_registered_contract() {
        for method in [
            "sampling/createMessage",
            "elicitation/create",
            "roots/list",
            "logging/setLevel",
            "notifications/resources/updated",
            "something/nobody/has/heard/of",
        ] {
            let decision = normalization_refusal(method);
            validate_architecture_contract(DECISION_CONTRACT, &decision)
                .unwrap_or_else(|error| panic!("{method} refusal is not contract-valid: {error}"));
            assert_eq!(decision["authority_granted"], false);
            assert_eq!(decision["receipt_identity_granted"], false);
            assert_eq!(decision["canonical_backing_ref"], Value::Null);
            assert_eq!(decision["source_protocol_version"], MCP_PROTOCOL_VERSION);
        }
    }

    /// A refusal that named no owner would leave the caller unable to tell unsupported from unbuilt.
    #[test]
    fn a_refusal_names_the_owner_that_would_serve_the_primitive() {
        assert_eq!(
            normalization_refusal("sampling/createMessage")["canonical_owner"],
            "ModelRoute+HarnessInvocation"
        );
        // An unrecognised method is `mcp.unknown`, never guessed into a neighbour primitive.
        assert_eq!(
            normalization_refusal("telepathy/invoke")["primitive"],
            "mcp.unknown"
        );
    }
}
