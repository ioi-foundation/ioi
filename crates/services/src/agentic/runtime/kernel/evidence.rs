use ioi_crypto::algorithms::hash::sha256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReceiptManifestKind {
    Browser(BrowserReceiptManifest),
    Filesystem(FilesystemReceiptManifest),
    Shell(ShellReceiptManifest),
    Mcp(McpReceiptManifest),
    ComputerUse(ComputerUseReceiptManifest),
    Connector(ConnectorReceiptManifest),
}

impl ReceiptManifestKind {
    pub fn canonical_hash(&self) -> Result<[u8; 32], String> {
        canonical_hash(self)
    }

    pub fn target_label(&self) -> &'static str {
        match self {
            Self::Browser(_) => "browser",
            Self::Filesystem(_) => "filesystem",
            Self::Shell(_) => "shell",
            Self::Mcp(_) => "mcp",
            Self::ComputerUse(_) => "computer_use",
            Self::Connector(_) => "connector",
        }
    }

    pub fn missing_required_evidence(&self) -> Vec<&'static str> {
        match self {
            Self::Browser(manifest) => manifest.missing_required_evidence(),
            Self::Filesystem(manifest) => manifest.missing_required_evidence(),
            Self::Shell(manifest) => manifest.missing_required_evidence(),
            Self::Mcp(manifest) => manifest.missing_required_evidence(),
            Self::ComputerUse(manifest) => manifest.missing_required_evidence(),
            Self::Connector(manifest) => manifest.missing_required_evidence(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.missing_required_evidence().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserReceiptManifest {
    pub before_dom_hash: [u8; 32],
    pub before_screenshot_hash: [u8; 32],
    pub origin: String,
    pub url: String,
    pub selected_element_ref: String,
    pub action: String,
    pub after_dom_hash: [u8; 32],
    pub after_screenshot_hash: [u8; 32],
    pub postcondition: String,
}

impl BrowserReceiptManifest {
    fn missing_required_evidence(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        push_if_empty(&mut missing, "origin", &self.origin);
        push_if_empty(&mut missing, "url", &self.url);
        push_if_empty(
            &mut missing,
            "selected_element_ref",
            &self.selected_element_ref,
        );
        push_if_empty(&mut missing, "action", &self.action);
        push_if_empty(&mut missing, "postcondition", &self.postcondition);
        missing
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemReceiptManifest {
    pub path: String,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_hash: Option<[u8; 32]>,
    pub workspace_scope: String,
    pub postcondition: String,
}

impl FilesystemReceiptManifest {
    fn missing_required_evidence(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        push_if_empty(&mut missing, "path", &self.path);
        push_if_empty(&mut missing, "operation", &self.operation);
        push_if_empty(&mut missing, "workspace_scope", &self.workspace_scope);
        push_if_empty(&mut missing, "postcondition", &self.postcondition);
        if self.before_hash.is_none() && self.after_hash.is_none() && self.diff_hash.is_none() {
            missing.push("before_hash_or_after_hash_or_diff_hash");
        }
        missing
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellReceiptManifest {
    pub command_digest: [u8; 32],
    pub argv_hash: [u8; 32],
    pub cwd: String,
    pub env_policy_hash: [u8; 32],
    pub exit_code: i32,
    pub stdout_digest: [u8; 32],
    pub stderr_digest: [u8; 32],
    pub postcondition: String,
}

impl ShellReceiptManifest {
    fn missing_required_evidence(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        push_if_empty(&mut missing, "cwd", &self.cwd);
        push_if_empty(&mut missing, "postcondition", &self.postcondition);
        missing
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpReceiptManifest {
    pub server_identity: String,
    pub tool_name: String,
    pub tool_schema_hash: [u8; 32],
    pub request_hash: [u8; 32],
    pub response_hash: [u8; 32],
    pub roots_disclosed: Vec<String>,
    pub authorization_state: String,
    pub timeout_policy: String,
}

impl McpReceiptManifest {
    fn missing_required_evidence(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        push_if_empty(&mut missing, "server_identity", &self.server_identity);
        push_if_empty(&mut missing, "tool_name", &self.tool_name);
        push_if_empty(
            &mut missing,
            "authorization_state",
            &self.authorization_state,
        );
        push_if_empty(&mut missing, "timeout_policy", &self.timeout_policy);
        missing
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputerUseReceiptManifest {
    pub window_binding: String,
    pub foreground_app: String,
    pub before_visual_hash: [u8; 32],
    pub action: String,
    pub semantic_target_or_coordinates: String,
    pub after_visual_hash: [u8; 32],
    pub drift_check: String,
}

impl ComputerUseReceiptManifest {
    fn missing_required_evidence(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        push_if_empty(&mut missing, "window_binding", &self.window_binding);
        push_if_empty(&mut missing, "foreground_app", &self.foreground_app);
        push_if_empty(&mut missing, "action", &self.action);
        push_if_empty(
            &mut missing,
            "semantic_target_or_coordinates",
            &self.semantic_target_or_coordinates,
        );
        push_if_empty(&mut missing, "drift_check", &self.drift_check);
        missing
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorReceiptManifest {
    pub connector_id: String,
    pub operation: String,
    pub endpoint_or_resource_scope: String,
    pub request_digest: [u8; 32],
    pub response_digest: [u8; 32],
    pub auth_scope: String,
    pub postcondition: String,
}

impl ConnectorReceiptManifest {
    fn missing_required_evidence(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        push_if_empty(&mut missing, "connector_id", &self.connector_id);
        push_if_empty(&mut missing, "operation", &self.operation);
        push_if_empty(
            &mut missing,
            "endpoint_or_resource_scope",
            &self.endpoint_or_resource_scope,
        );
        push_if_empty(&mut missing, "auth_scope", &self.auth_scope);
        push_if_empty(&mut missing, "postcondition", &self.postcondition);
        missing
    }
}

fn push_if_empty<'a>(missing: &mut Vec<&'static str>, key: &'static str, value: &'a str) {
    if value.trim().is_empty() {
        missing.push(key);
    }
}

fn canonical_hash<T>(value: &T) -> Result<[u8; 32], String>
where
    T: Serialize,
{
    let canonical = serde_jcs::to_vec(value).map_err(|error| error.to_string())?;
    sha256(&canonical).map_err(|error| error.to_string())
}
