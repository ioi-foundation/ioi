use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionSurface {
    Chat,
    Workflow,
    Harness,
    Gui,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    SourceInput,
    Trigger,
    Function,
    ModelBinding,
    ModelCall,
    Parser,
    AdapterConnector,
    PluginTool,
    State,
    Decision,
    Loop,
    Barrier,
    Subgraph,
    HumanGate,
    Output,
    TestAssertion,
    Proposal,
    Unknown,
}

impl ActionKind {
    pub fn from_node_type(node_type: &str) -> Self {
        match node_type {
            "source" => Self::SourceInput,
            "trigger" => Self::Trigger,
            "function" => Self::Function,
            "model_binding" => Self::ModelBinding,
            "model_call" => Self::ModelCall,
            "parser" => Self::Parser,
            "adapter" => Self::AdapterConnector,
            "plugin_tool" => Self::PluginTool,
            "state" => Self::State,
            "decision" => Self::Decision,
            "loop" => Self::Loop,
            "barrier" => Self::Barrier,
            "subgraph" => Self::Subgraph,
            "human_gate" => Self::HumanGate,
            "output" => Self::Output,
            "test_assertion" => Self::TestAssertion,
            "proposal" => Self::Proposal,
            _ => Self::Unknown,
        }
    }

    pub fn node_type(&self) -> &'static str {
        match self {
            Self::SourceInput => "source",
            Self::Trigger => "trigger",
            Self::Function => "function",
            Self::ModelBinding => "model_binding",
            Self::ModelCall => "model_call",
            Self::Parser => "parser",
            Self::AdapterConnector => "adapter",
            Self::PluginTool => "plugin_tool",
            Self::State => "state",
            Self::Decision => "decision",
            Self::Loop => "loop",
            Self::Barrier => "barrier",
            Self::Subgraph => "subgraph",
            Self::HumanGate => "human_gate",
            Self::Output => "output",
            Self::TestAssertion => "test_assertion",
            Self::Proposal => "proposal",
            Self::Unknown => "unknown",
        }
    }

    pub fn evidence_kind(&self) -> &'static str {
        match self {
            Self::SourceInput => "source",
            Self::Trigger => "trigger",
            Self::Function => "function",
            Self::ModelBinding => "model_binding",
            Self::ModelCall => "model",
            Self::Parser => "parser",
            Self::AdapterConnector => "adapter",
            Self::PluginTool => "plugin_tool",
            Self::State => "state",
            Self::Decision => "decision",
            Self::Loop => "loop",
            Self::Barrier => "barrier",
            Self::Subgraph => "subgraph",
            Self::HumanGate => "human_gate",
            Self::Output => "output",
            Self::TestAssertion => "test_assertion",
            Self::Proposal => "proposal",
            Self::Unknown => "unknown",
        }
    }

    pub fn is_entry(&self) -> bool {
        matches!(self, Self::SourceInput | Self::Trigger)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Output)
    }

    pub fn is_interrupt(&self) -> bool {
        matches!(self, Self::HumanGate)
    }

    pub fn requires_completion_verification(&self) -> bool {
        matches!(
            self,
            Self::Function
                | Self::ModelBinding
                | Self::ModelCall
                | Self::Parser
                | Self::AdapterConnector
                | Self::PluginTool
                | Self::Subgraph
                | Self::Proposal
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionBindingRef {
    pub binding_type: String,
    pub reference: Option<String>,
    pub mock_binding: bool,
    pub side_effect_class: String,
    pub requires_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionPolicy {
    pub privileged_actions: Vec<String>,
    pub requires_approval: bool,
    pub sandbox_permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionFrame {
    pub id: String,
    pub surface: ActionSurface,
    pub kind: ActionKind,
    pub label: String,
    pub binding: Option<ActionBindingRef>,
    pub policy: ActionPolicy,
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionValidationIssue {
    pub action_id: Option<String>,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowConnectionClass {
    Control,
    Data,
    Model,
    Memory,
    Tool,
    Parser,
    State,
    Approval,
    Error,
    Retry,
    Delivery,
    Subgraph,
}

impl WorkflowConnectionClass {
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "control" => Some(Self::Control),
            "data" => Some(Self::Data),
            "model" => Some(Self::Model),
            "memory" => Some(Self::Memory),
            "tool" => Some(Self::Tool),
            "parser" => Some(Self::Parser),
            "state" => Some(Self::State),
            "approval" => Some(Self::Approval),
            "error" => Some(Self::Error),
            "retry" => Some(Self::Retry),
            "delivery" => Some(Self::Delivery),
            "subgraph" => Some(Self::Subgraph),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Data => "data",
            Self::Model => "model",
            Self::Memory => "memory",
            Self::Tool => "tool",
            Self::Parser => "parser",
            Self::State => "state",
            Self::Approval => "approval",
            Self::Error => "error",
            Self::Retry => "retry",
            Self::Delivery => "delivery",
            Self::Subgraph => "subgraph",
        }
    }
}

pub fn validate_action_edge(
    source_id: &str,
    source_kind: &ActionKind,
    target_id: &str,
    target_kind: &ActionKind,
) -> Result<(), ActionValidationIssue> {
    if source_id == target_id {
        return Err(ActionValidationIssue {
            action_id: Some(source_id.to_string()),
            code: "self_edge".to_string(),
            message: "A workflow node cannot connect to itself.".to_string(),
        });
    }
    if target_kind.is_entry() {
        return Err(ActionValidationIssue {
            action_id: Some(target_id.to_string()),
            code: "invalid_source_input_edge".to_string(),
            message:
                "Source/Input nodes are workflow entry points and cannot receive incoming edges."
                    .to_string(),
        });
    }
    if source_kind.is_terminal() {
        return Err(ActionValidationIssue {
            action_id: Some(source_id.to_string()),
            code: "invalid_output_edge".to_string(),
            message: "Output nodes are terminal workflow products and cannot send outgoing edges."
                .to_string(),
        });
    }
    Ok(())
}

pub fn validate_workflow_connection_class(
    action_id: Option<String>,
    source_class: &str,
    target_class: &str,
) -> Result<(), ActionValidationIssue> {
    let Some(source) = WorkflowConnectionClass::from_str(source_class) else {
        return Err(ActionValidationIssue {
            action_id,
            code: "unknown_connection_class".to_string(),
            message: format!("Unknown source connection class '{}'.", source_class),
        });
    };
    let Some(target) = WorkflowConnectionClass::from_str(target_class) else {
        return Err(ActionValidationIssue {
            action_id,
            code: "unknown_connection_class".to_string(),
            message: format!("Unknown target connection class '{}'.", target_class),
        });
    };
    if source != target {
        return Err(ActionValidationIssue {
            action_id,
            code: "invalid_connection_class".to_string(),
            message: format!(
                "Connection class '{}' cannot feed '{}'.",
                source.as_str(),
                target.as_str()
            ),
        });
    }
    Ok(())
}

pub fn completion_requirement_kinds(kind: &ActionKind) -> Vec<&'static str> {
    if kind.is_entry() {
        return Vec::new();
    }
    let mut requirements = vec!["execution"];
    if matches!(kind, ActionKind::Output) {
        requirements.push("output_created");
    }
    if kind.requires_completion_verification() {
        requirements.push("verification");
    }
    requirements
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substrate_classifies_workflow_node_kinds() {
        assert_eq!(
            ActionKind::from_node_type("source"),
            ActionKind::SourceInput
        );
        assert_eq!(
            ActionKind::from_node_type("model_call"),
            ActionKind::ModelCall
        );
        assert_eq!(ActionKind::from_node_type("parser"), ActionKind::Parser);
        assert_eq!(
            ActionKind::from_node_type("plugin_tool"),
            ActionKind::PluginTool
        );
        assert_eq!(ActionKind::from_node_type("trigger"), ActionKind::Trigger);
        assert_eq!(ActionKind::from_node_type("state"), ActionKind::State);
        assert_eq!(ActionKind::from_node_type("subgraph"), ActionKind::Subgraph);
        assert_eq!(ActionKind::from_node_type("proposal"), ActionKind::Proposal);
        assert_eq!(ActionKind::from_node_type("model"), ActionKind::Unknown);
    }

    #[test]
    fn substrate_edge_rules_protect_entry_and_terminal_nodes() {
        assert!(validate_action_edge(
            "source",
            &ActionKind::SourceInput,
            "function",
            &ActionKind::Function,
        )
        .is_ok());
        assert_eq!(
            validate_action_edge(
                "function",
                &ActionKind::Function,
                "source",
                &ActionKind::SourceInput,
            )
            .unwrap_err()
            .code,
            "invalid_source_input_edge"
        );
        assert_eq!(
            validate_action_edge(
                "output",
                &ActionKind::Output,
                "function",
                &ActionKind::Function,
            )
            .unwrap_err()
            .code,
            "invalid_output_edge"
        );
    }

    #[test]
    fn substrate_rejects_incompatible_connection_classes() {
        assert!(validate_workflow_connection_class(None, "tool", "tool").is_ok());
        assert_eq!(
            validate_workflow_connection_class(Some("model".to_string()), "tool", "model")
                .unwrap_err()
                .code,
            "invalid_connection_class"
        );
        assert_eq!(
            validate_workflow_connection_class(None, "telepathy", "data")
                .unwrap_err()
                .code,
            "unknown_connection_class"
        );
    }
}
