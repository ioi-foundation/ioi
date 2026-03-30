use super::{
    CapabilityId, ExecutionApplicabilityClass, IntentMatrixEntry, IntentQueryBindingClass,
    IntentScopeProfile, ProviderSelectionMode, VerificationMode,
};

pub(super) fn default_intent_matrix() -> Vec<IntentMatrixEntry> {
    vec![
IntentMatrixEntry {
    intent_id: "conversation.reply".to_string(),
    semantic_descriptor:
        "respond conversationally without executing external side effects"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
    ],
    risk_class: "low".to_string(),
    scope: IntentScopeProfile::Conversation,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "provider_selection".to_string(),
        "provider_selection_commit".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
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
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
    ],
    risk_class: "low".to_string(),
    scope: IntentScopeProfile::Conversation,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "provider_selection".to_string(),
        "provider_selection_commit".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
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
    intent_id: "memory.recall".to_string(),
    semantic_descriptor:
        "retrieve previously stored durable memory workflow notes learned constraints or remembered project context and answer from that recalled state"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("memory.access"),
    ],
    risk_class: "low".to_string(),
    scope: IntentScopeProfile::Conversation,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "provider_selection".to_string(),
        "provider_selection_commit".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "remember".to_string(),
        "recall".to_string(),
        "memory".to_string(),
        "what did we learn".to_string(),
    ],
    exemplars: vec![
        "what do you remember about this project".to_string(),
        "search memory for the previous localai plan".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "web.research".to_string(),
    semantic_descriptor:
        "research live information on the web including latest news headlines and current events then synthesize sourced findings"
            .to_string(),
    query_binding: IntentQueryBindingClass::RemotePublicFact,
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
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "provider_selection".to_string(),
        "provider_selection_commit".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
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
        "inspect create and modify files in the local workspace and repository checkout source tree including websites landing pages static sites applications prototypes html css javascript and other shippable artifacts"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
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
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "provider_selection".to_string(),
        "provider_selection_commit".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "repo".to_string(),
        "workspace".to_string(),
        "codebase".to_string(),
        "website".to_string(),
        "landing page".to_string(),
        "static site".to_string(),
        "web app".to_string(),
        "frontend".to_string(),
        "ui implementation".to_string(),
    ],
    exemplars: vec![
        "read files in the workspace".to_string(),
        "edit code in repository".to_string(),
        "create a landing page for a tennis company in the workspace".to_string(),
        "build an html page and preview it locally".to_string(),
        "scaffold a react app in the repo".to_string(),
        "turn this brief into a shippable web page artifact".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "app.launch".to_string(),
    semantic_descriptor:
        "open launch start or foreground a named local software process identified by a program title token and make it active for interaction"
            .to_string(),
    query_binding: IntentQueryBindingClass::AppLaunchDirected,
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
    query_binding: IntentQueryBindingClass::DirectUiInput,
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
    query_binding: IntentQueryBindingClass::DesktopScreenshot,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("ui.interact"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::UiInteraction,
    preferred_tier: "visual_last".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "provider_selection".to_string(),
        "provider_selection_commit".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
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
    intent_id: "mail.read.latest".to_string(),
    semantic_descriptor:
        "read the latest message from a connected mailbox and return sender subject received metadata and body preview"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("mail.read.latest"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::Conversation,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::Mixed,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "provider_selection".to_string(),
        "provider_selection_commit".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "read email".to_string(),
        "latest email".to_string(),
        "inbox latest".to_string(),
    ],
    exemplars: vec![
        "read me the latest email i received".to_string(),
        "show the most recent inbox message".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "mail.list.recent".to_string(),
    semantic_descriptor:
        "list recent messages from a connected mailbox including sender subject and received metadata"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("mail.list.recent"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::Conversation,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::Mixed,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "provider_selection".to_string(),
        "provider_selection_commit".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "list emails".to_string(),
        "recent inbox".to_string(),
        "recent email list".to_string(),
    ],
    exemplars: vec![
        "list my recent emails".to_string(),
        "show the last 10 inbox messages".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "mail.delete.spam".to_string(),
    semantic_descriptor:
        "delete spam or junk messages from a connected mailbox using mailbox cleanup operations"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("mail.delete.spam"),
    ],
    risk_class: "high".to_string(),
    scope: IntentScopeProfile::Conversation,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::Mixed,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "provider_selection".to_string(),
        "provider_selection_commit".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "delete spam".to_string(),
        "clean junk".to_string(),
        "spam cleanup".to_string(),
    ],
    exemplars: vec![
        "delete spam emails".to_string(),
        "clean junk mailbox messages".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "mail.reply".to_string(),
    semantic_descriptor:
        "compose draft and send an email reply or outbound mailbox message with an explicit recipient subject and email body through a connected mailbox account"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("mail.reply"),
    ],
    risk_class: "high".to_string(),
    scope: IntentScopeProfile::Conversation,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::Mixed,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "provider_selection".to_string(),
        "provider_selection_commit".to_string(),
        "grounding".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
    required_postconditions: vec!["mail.reply.completed".to_string()],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "send email".to_string(),
        "draft email".to_string(),
        "compose email".to_string(),
        "outbound mailbox message".to_string(),
        "reply email".to_string(),
    ],
    exemplars: vec![
        "send an email to alex@example.com with subject Launch Update".to_string(),
        "reply to the email thread from Sam with a project update".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "automation.monitor".to_string(),
    semantic_descriptor:
        "install a durable local automation monitor that keeps checking a source on a schedule stores dedupe state and notifies later when a predicate matches"
            .to_string(),
    query_binding: IntentQueryBindingClass::DurableAutomation,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("automation.monitor.install"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::CommandExecution,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
    required_receipts: vec![
        "provider_selection".to_string(),
        "provider_selection_commit".to_string(),
        "execution".to_string(),
        "verification".to_string(),
    ],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "monitor".to_string(),
        "watch".to_string(),
        "notify me whenever".to_string(),
        "alert me if".to_string(),
    ],
    exemplars: vec![
        "monitor a site and notify me when something happens".to_string(),
        "watch a source every few minutes and alert on matches".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "model.registry.load".to_string(),
    semantic_descriptor:
        "load activate or warm an already installed local model into the kernel inference runtime so it becomes resident and ready for subsequent use"
            .to_string(),
    query_binding: IntentQueryBindingClass::ModelRegistryControl,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("model.registry.manage"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::CommandExecution,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "load model".to_string(),
        "activate model".to_string(),
        "warm model".to_string(),
        "bring model online".to_string(),
    ],
    exemplars: vec![
        "load the codex oss model into the local runtime".to_string(),
        "activate llama3.1 so it is ready for use".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "model.registry.unload".to_string(),
    semantic_descriptor:
        "unload deactivate evict or release an already loaded local model from the kernel inference runtime to free memory or vram"
            .to_string(),
    query_binding: IntentQueryBindingClass::ModelRegistryControl,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("model.registry.manage"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::CommandExecution,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "unload model".to_string(),
        "deactivate model".to_string(),
        "evict model".to_string(),
        "free vram".to_string(),
    ],
    exemplars: vec![
        "unload the whisper model from the local runtime".to_string(),
        "evict the image model to free memory".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "model.registry.install".to_string(),
    semantic_descriptor:
        "install import register or apply a local model artifact gallery entry or model package into the kernel registry and control plane"
            .to_string(),
    query_binding: IntentQueryBindingClass::ModelRegistryControl,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("model.registry.manage"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::CommandExecution,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "install model".to_string(),
        "import model".to_string(),
        "register model".to_string(),
        "apply model".to_string(),
    ],
    exemplars: vec![
        "install codex oss into the local kernel registry".to_string(),
        "import this gguf model into the local engine".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "backend.registry.manage".to_string(),
    semantic_descriptor:
        "install start stop apply delete or health-check a local inference backend or sidecar inside the kernel control plane"
            .to_string(),
    query_binding: IntentQueryBindingClass::ModelRegistryControl,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("model.registry.manage"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::CommandExecution,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "install backend".to_string(),
        "start backend".to_string(),
        "stop backend".to_string(),
        "backend health".to_string(),
    ],
    exemplars: vec![
        "install the vllm backend into the local engine".to_string(),
        "health check the whisper backend".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "gallery.sync".to_string(),
    semantic_descriptor:
        "synchronize refresh or update a local model or backend gallery catalog inside the kernel control plane"
            .to_string(),
    query_binding: IntentQueryBindingClass::ModelRegistryControl,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("model.registry.manage"),
    ],
    risk_class: "medium".to_string(),
    scope: IntentScopeProfile::CommandExecution,
    preferred_tier: "tool_first".to_string(),
    applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
    requires_host_discovery: Some(false),
    provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
    required_receipts: vec!["execution".to_string(), "verification".to_string()],
    required_postconditions: vec![],
    verification_mode: Some(VerificationMode::DeterministicCheck),
    aliases: vec![
        "sync gallery".to_string(),
        "refresh gallery".to_string(),
        "update model catalog".to_string(),
    ],
    exemplars: vec![
        "sync the primary model gallery".to_string(),
        "refresh backend catalogs from the local engine".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "media.transcribe".to_string(),
    semantic_descriptor:
        "transcribe local audio speech or spoken media into text through the kernel media substrate"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("media.transcribe"),
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
        "transcribe audio".to_string(),
        "speech to text".to_string(),
        "transcript this recording".to_string(),
    ],
    exemplars: vec![
        "transcribe this wav file".to_string(),
        "turn the meeting audio into text".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "media.synthesize".to_string(),
    semantic_descriptor:
        "generate speech or text to speech audio artifacts from text through the kernel media runtime"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("media.synthesize"),
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
        "text to speech".to_string(),
        "generate narration".to_string(),
        "synthesize voice".to_string(),
    ],
    exemplars: vec![
        "turn this script into speech".to_string(),
        "generate a spoken version of the release notes".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "media.vision".to_string(),
    semantic_descriptor:
        "inspect an image screenshot or multimodal artifact and answer about its contents through the kernel vision runtime"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("media.vision"),
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
        "inspect image".to_string(),
        "look at screenshot".to_string(),
        "vision read".to_string(),
    ],
    exemplars: vec![
        "describe what is in this image".to_string(),
        "read the screenshot and answer the question".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "media.generate.image".to_string(),
    semantic_descriptor:
        "generate edit or inpaint an image artifact from text prompts through the kernel image runtime"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("media.generate.image"),
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
        "generate image".to_string(),
        "make an image".to_string(),
        "edit image".to_string(),
    ],
    exemplars: vec![
        "generate an image of the launch poster".to_string(),
        "inpaint this screenshot background".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "media.generate.video".to_string(),
    semantic_descriptor:
        "generate a video artifact from prompts through the kernel video runtime"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("media.generate.video"),
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
        "generate video".to_string(),
        "make a video".to_string(),
        "render video".to_string(),
    ],
    exemplars: vec![
        "generate a short product teaser video".to_string(),
        "render a local video clip from this prompt".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "command.probe".to_string(),
    semantic_descriptor:
        "check whether a binary or tool is available in PATH without mutating host state"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
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
    query_binding: IntentQueryBindingClass::HostLocal,
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
    query_binding: IntentQueryBindingClass::CommandDirected,
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
    intent_id: "command.exec.install_dependency".to_string(),
    semantic_descriptor:
        "download and install a named software package dependency on this local machine using the host package manager and verify the installed binary is available"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
    required_capabilities: vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("conversation.reply"),
        CapabilityId::from("system.install_package"),
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
        "install dependency".to_string(),
        "install package".to_string(),
        "package manager".to_string(),
    ],
    exemplars: vec![
        "download and install vlc media player".to_string(),
        "install ffmpeg on this machine".to_string(),
        "install package dependency locally".to_string(),
    ],
},
IntentMatrixEntry {
    intent_id: "delegation.task".to_string(),
    semantic_descriptor:
        "delegate work to child agent sessions and aggregate worker outputs"
            .to_string(),
    query_binding: IntentQueryBindingClass::None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversation_reply_does_not_inherit_mail_grounding_contract() {
        let entry = default_intent_matrix()
            .into_iter()
            .find(|entry| entry.intent_id == "conversation.reply")
            .expect("conversation.reply entry should exist");

        assert!(
            !entry
                .required_receipts
                .iter()
                .any(|receipt| receipt == "grounding"),
            "conversation.reply should not require connector grounding receipts"
        );
        assert!(
            !entry
                .required_postconditions
                .iter()
                .any(|postcondition| postcondition == "mail.reply.completed"),
            "conversation.reply should not require mail completion postconditions"
        );
    }

    #[test]
    fn generic_mail_reply_defaults_to_dynamic_provider_selection() {
        let entry = default_intent_matrix()
            .into_iter()
            .find(|entry| entry.intent_id == "mail.reply")
            .expect("mail.reply entry should exist");

        assert_eq!(
            entry.provider_selection_mode,
            Some(ProviderSelectionMode::DynamicSynthesis)
        );
        assert!(
            entry
                .required_receipts
                .iter()
                .any(|receipt| receipt == "provider_selection"),
            "mail.reply should require provider selection receipts"
        );
        assert!(
            entry
                .required_receipts
                .iter()
                .any(|receipt| receipt == "provider_selection_commit"),
            "mail.reply should require provider selection commit receipts"
        );
        assert!(
            entry
                .required_receipts
                .iter()
                .any(|receipt| receipt == "grounding"),
            "mail.reply should require grounding receipts"
        );
        assert!(
            entry
                .required_postconditions
                .iter()
                .any(|postcondition| postcondition == "mail.reply.completed"),
            "mail.reply should require verified completion postconditions"
        );
    }

    #[test]
    fn memory_recall_defaults_to_local_memory_capability_surface() {
        let entry = default_intent_matrix()
            .into_iter()
            .find(|entry| entry.intent_id == "memory.recall")
            .expect("memory.recall entry should exist");

        assert_eq!(entry.scope, IntentScopeProfile::Conversation);
        assert!(
            entry
                .required_capabilities
                .iter()
                .any(|capability| capability.as_str() == "memory.access"),
            "memory.recall should require memory.access"
        );
        assert!(
            entry
                .required_capabilities
                .iter()
                .any(|capability| capability.as_str() == "conversation.reply"),
            "memory.recall should preserve chat completion capability"
        );
        assert_eq!(
            entry.verification_mode,
            Some(VerificationMode::DeterministicCheck)
        );
    }

    #[test]
    fn model_registry_control_intents_use_kernel_managed_capability_surface() {
        let entries = default_intent_matrix();
        for intent_id in [
            "model.registry.load",
            "model.registry.unload",
            "model.registry.install",
            "backend.registry.manage",
            "gallery.sync",
        ] {
            let entry = entries
                .iter()
                .find(|entry| entry.intent_id == intent_id)
                .unwrap_or_else(|| panic!("{intent_id} entry should exist"));

            assert_eq!(entry.scope, IntentScopeProfile::CommandExecution);
            assert_eq!(
                entry.query_binding,
                IntentQueryBindingClass::ModelRegistryControl
            );
            assert!(
                entry
                    .required_capabilities
                    .iter()
                    .any(|capability| capability.as_str() == "model.registry.manage"),
                "{intent_id} should require model.registry.manage"
            );
            assert!(
                entry
                    .required_capabilities
                    .iter()
                    .any(|capability| capability.as_str() == "conversation.reply"),
                "{intent_id} should preserve chat completion capability"
            );
            assert_eq!(
                entry.provider_selection_mode,
                Some(ProviderSelectionMode::CapabilityOnly)
            );
        }
    }

    #[test]
    fn media_generation_and_analysis_intents_use_kernel_media_capabilities() {
        let entries = default_intent_matrix();
        for (intent_id, capability) in [
            ("media.transcribe", "media.transcribe"),
            ("media.synthesize", "media.synthesize"),
            ("media.vision", "media.vision"),
            ("media.generate.image", "media.generate.image"),
            ("media.generate.video", "media.generate.video"),
        ] {
            let entry = entries
                .iter()
                .find(|entry| entry.intent_id == intent_id)
                .unwrap_or_else(|| panic!("{intent_id} entry should exist"));

            assert_eq!(entry.scope, IntentScopeProfile::CommandExecution);
            assert!(
                entry
                    .required_capabilities
                    .iter()
                    .any(|required| required.as_str() == capability),
                "{intent_id} should require {capability}"
            );
            assert!(
                entry
                    .required_capabilities
                    .iter()
                    .any(|required| required.as_str() == "conversation.reply"),
                "{intent_id} should preserve chat completion capability"
            );
            assert_eq!(
                entry.provider_selection_mode,
                Some(ProviderSelectionMode::CapabilityOnly)
            );
        }
    }
}
