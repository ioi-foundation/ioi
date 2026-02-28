use super::{
    CapabilityId, ExecutionApplicabilityClass, IntentMatrixEntry, IntentScopeProfile,
    ProviderSelectionMode, VerificationMode,
};

pub(super) fn default_intent_matrix() -> Vec<IntentMatrixEntry> {
    vec![
IntentMatrixEntry {
    intent_id: "conversation.reply".to_string(),
    semantic_descriptor:
        "respond conversationally without executing external side effects"
            .to_string(),
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
    ],
    risk_class: "low".to_string(),
    scope: IntentScopeProfile::Conversation,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "chat".to_string(),
        "reply".to_string(),
        "explain".to_string(),
        "summarize".to_string(),
    ],
    exemplars: vec![
        "answer the user message".to_string(),
        "draft a response".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "math.eval".to_string(),
    semantic_descriptor:
        "compute deterministic arithmetic results from explicit symbolic numeric expressions using numbers operators and grouping tokens and return the evaluated value"
            .to_string(),
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
    ],
    risk_class: "low".to_string(),
    scope: IntentScopeProfile::Conversation,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "math".to_string(),
        "calculate".to_string(),
        "arithmetic".to_string(),
        "expression".to_string(),
    ],
    exemplars: vec![
        "what is 247 times 38".to_string(),
        "evaluate (12 + 8) / 5".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "web.research".to_string(),
    semantic_descriptor:
        "research live information on the web including latest news headlines and current events then synthesize sourced findings"
            .to_string(),
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("sys.time.read"),
        CapabilityId::from("web.retrieve"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::WebResearch,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::RemoteRetrieval,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "web".to_string(),
        "browse".to_string(),
        "lookup".to_string(),
        "search".to_string(),
    ],
    exemplars: vec![
        "find information online".to_string(),
        "crawl a url and summarize".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "workspace.ops".to_string(),
    semantic_descriptor:
        "inspect and modify files in the local workspace and repository checkout source tree"
            .to_string(),
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("filesystem.read"),
        CapabilityId::from("filesystem.write"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::WorkspaceOps,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "repo".to_string(),
        "workspace".to_string(),
        "codebase".to_string(),
    ],
    exemplars: vec![
        "read files in the workspace".to_string(),
        "edit code in repository".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "app.launch".to_string(),
    semantic_descriptor:
        "open launch start or foreground a named local software process identified by a program title token and make it active for interaction"
            .to_string(),
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("app.launch"),
        CapabilityId::from("ui.interact"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::AppLaunch,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::TopologyDependent,
    requires_host_discovery: Some(true),
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "host_discovery".to_string(),
        "provider_selection".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DynamicSynthesis),
    aliases: vec!["open app".to_string(), "launch".to_string()],
    exemplars: vec!["open calculator".to_string(), "launch browser".to_string()],
},
IntentMatrixEntry {
    intent_id: "ui.interaction".to_string(),
    semantic_descriptor:
        "perform direct input interactions such as click type scroll drag or keypress within an already-running focused application interface"
            .to_string(),
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("ui.interact"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::UiInteraction,
    preferred_tier: "visual_last".to_string(),
    applicability_class: ExecutionApplicabilityClass::TopologyDependent,
    requires_host_discovery: Some(true),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec![
        "host_discovery".to_string(),
        "provider_selection".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "click".to_string(),
        "tap".to_string(),
        "press".to_string(),
        "type".to_string(),
    ],
    exemplars: vec![
        "click the login button".to_string(),
        "type into the focused field".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "ui.capture_screenshot".to_string(),
    semantic_descriptor:
        "take a screenshot of my desktop or capture the current screen image and return capture confirmation without click type scroll or keypress actions"
            .to_string(),
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("ui.interact"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::UiInteraction,
    preferred_tier: "visual_last".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "screenshot".to_string(),
        "screen capture".to_string(),
        "capture desktop".to_string(),
    ],
    exemplars: vec![
        "take a screenshot of my desktop".to_string(),
        "capture my screen".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "command.probe".to_string(),
    semantic_descriptor:
        "check whether a binary or tool is available in PATH without mutating host state"
            .to_string(),
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("command.probe"),
        CapabilityId::from("conversation.reply"),
    ],
    risk_class: "low".to_string(),
    scope: IntentScopeProfile::CommandExecution,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "installed".to_string(),
        "in path".to_string(),
        "command exists".to_string(),
        "which binary".to_string(),
        "which command".to_string(),
    ],
    exemplars: vec![
        "check if a program is installed".to_string(),
        "is a tool installed on this computer".to_string(),
        "check if a command exists on this machine".to_string(),
        "find the path of a binary".to_string(),
        "verify tool availability".to_string(),
        "check a tool version".to_string(),
        "is this command available".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "system.clock.read".to_string(),
    semantic_descriptor:
        "read only this host machine local or utc clock timestamp and time-of-day"
            .to_string(),
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("command.exec"),
    ],
    risk_class: "low".to_string(),
    scope: IntentScopeProfile::CommandExecution,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![],
    exemplars: vec![
        "read the current system time".to_string(),
        "read current utc time from this machine".to_string(),
        "what time is it on this computer".to_string(),
        "get local clock time from terminal".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "command.exec".to_string(),
    semantic_descriptor:
        "execute local shell or terminal commands on the current machine for local automation tasks including file renaming batch directory transforms filename case normalization and timers"
            .to_string(),
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("command.exec"),
    ],
    risk_class: "high".to_string(),
    scope: IntentScopeProfile::CommandExecution,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::TopologyDependent,
    requires_host_discovery: Some(true),
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "host_discovery".to_string(),
        "provider_selection".to_string(),
        "provider_selection_commit".to_string(),
        "execution".to_string(),
        "verification".to_string(),
        "verification_commit".to_string(),
    ],
    required_postconditions: vec!["execution_artifact".to_string()],
    verification_mode: Some(VerificationMode::DynamicSynthesis),
    aliases: vec![
        "shell".to_string(),
        "terminal".to_string(),
        "run command".to_string(),
        "execute".to_string(),
    ],
    exemplars: vec![
        "run a command".to_string(),
        "execute this command".to_string(),
        "run a script in the terminal".to_string(),
        "run tests from the command line".to_string(),
        "build the project".to_string(),
        "install dependency".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "delegation.task".to_string(),
    semantic_descriptor:
        "delegate work to child agent sessions and aggregate worker outputs"
            .to_string(),
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("delegation.manage"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::Delegation,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::Mixed,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec!["delegate".to_string(), "sub-agent".to_string()],
    exemplars: vec![
        "delegate this task".to_string(),
        "spawn researcher agent".to_string(),
    ],
},
    ]
}
