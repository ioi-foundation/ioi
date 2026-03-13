use ioi_types::app::KernelEvent;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputerUseMode {
    Oracle,
    Runtime,
    Agent,
}

impl ComputerUseMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oracle => "oracle",
            Self::Runtime => "runtime",
            Self::Agent => "agent",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskSet {
    Smoke,
    Core,
    Stress,
    Catalog,
}

impl TaskSet {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Core => "core",
            Self::Stress => "stress",
            Self::Catalog => "catalog",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowedToolProfile {
    OracleBridge,
    BrowserCore,
    BrowserCoreWithSelect,
    BrowserCoreWithSelectionClipboard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalJudge {
    MiniwobReward,
    HoverShapeReceipts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeId {
    ClickButton,
    ClickLink,
    EnterText,
    FocusText,
    ChooseList,
    ClickTab,
    UseAutocomplete,
    ScrollText2,
    ClickOption,
    ClickCheckboxes,
    ClickCheckboxesTransfer,
    EnterPassword,
    LoginUser,
    FocusText2,
    EnterText2,
    ClickButtonSequence,
    ClickCollapsible,
    ClickCollapsible2,
    SearchEngine,
    HoverShape,
    DragItems,
    HighlightText,
    CopyPaste,
    FormSequence,
    FormSequence2,
    FormSequence3,
    LoginUserPopup,
    TextEditor,
    SimpleArithmetic,
    SimpleAlgebra,
    OddOrEven,
    GuessNumber,
    FindGreatest,
    FindWord,
    ReadTable,
    ReadTable2,
    PhoneBook,
    SocialMedia,
    SocialMediaAll,
    SocialMediaSome,
    StockMarket,
    EmailInbox,
    VisualAddition,
    IdentifyShape,
    CountShape,
    CountSides,
    FindMidpoint,
    SurveyOnly,
}

#[derive(Debug, Clone)]
pub struct ComputerUseCase {
    pub id: String,
    pub env_id: String,
    pub seed: u64,
    pub task_set: TaskSet,
    pub max_steps: u32,
    pub timeout_seconds: u64,
    pub allowed_tool_profile: AllowedToolProfile,
    pub expected_reward_floor: f32,
    pub expected_pass: bool,
    pub local_judge: LocalJudge,
    pub recipe: RecipeId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkSupportState {
    Passing,
    KnownGap,
    InfraBlocked,
    NotYetAttempted,
}

impl BenchmarkSupportState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passing => "passing",
            Self::KnownGap => "known_gap",
            Self::InfraBlocked => "infra_blocked",
            Self::NotYetAttempted => "not_yet_attempted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapClass {
    MissingPointerPrimitive,
    MissingSelectionPrimitive,
    MissingKeyboardPrimitive,
    MissingClipboardPrimitive,
    ObservationGap,
    VerificationGap,
    RecoveryGap,
    PlannerGap,
    InfraOrBridgeGap,
}

impl GapClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingPointerPrimitive => "missing_pointer_primitive",
            Self::MissingSelectionPrimitive => "missing_selection_primitive",
            Self::MissingKeyboardPrimitive => "missing_keyboard_primitive",
            Self::MissingClipboardPrimitive => "missing_clipboard_primitive",
            Self::ObservationGap => "observation_gap",
            Self::VerificationGap => "verification_gap",
            Self::RecoveryGap => "recovery_gap",
            Self::PlannerGap => "planner_gap",
            Self::InfraOrBridgeGap => "infra_or_bridge_gap",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BridgeField {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BridgeInteractiveElement {
    pub tag: String,
    pub id: Option<String>,
    pub selector: Option<String>,
    pub center_x: Option<i32>,
    pub center_y: Option<i32>,
    pub name: Option<String>,
    pub text: String,
    pub value: Option<String>,
    pub input_type: Option<String>,
    pub checked: Option<bool>,
    #[serde(default)]
    pub selected_labels: Vec<String>,
    #[serde(default)]
    pub class_list: Vec<String>,
    pub visible: bool,
    pub disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BridgeScrollTarget {
    pub tag: String,
    pub id: Option<String>,
    pub selector: Option<String>,
    pub center_x: Option<i32>,
    pub center_y: Option<i32>,
    pub scroll_top: f64,
    pub scroll_height: f64,
    pub client_height: f64,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BridgeInfo {
    pub reason: Option<String>,
    pub raw_reward: Option<f32>,
    pub query_text: Option<String>,
    #[serde(default)]
    pub fields: Vec<BridgeField>,
    pub page_url: Option<String>,
    pub task_ready: Option<bool>,
    pub focused_tag: Option<String>,
    pub focused_id: Option<String>,
    pub visible_text_excerpt: Option<String>,
    #[serde(default)]
    pub interactive_elements: Vec<BridgeInteractiveElement>,
    #[serde(default)]
    pub scroll_targets: Vec<BridgeScrollTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BridgeState {
    pub session_id: String,
    pub env_id: String,
    pub seed: u64,
    pub utterance: String,
    pub reward: f32,
    pub terminated: bool,
    pub truncated: bool,
    pub episode_step: u32,
    pub generation: u32,
    pub last_sync_ms: Option<u64>,
    #[serde(default)]
    pub info: BridgeInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolStepRecord {
    pub step_index: u32,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub success: bool,
    pub history_entry: Option<String>,
    pub error: Option<String>,
    pub bridge_reward: f32,
    pub bridge_terminated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleStepRecord {
    pub step_index: u32,
    pub command_type: String,
    pub payload: serde_json::Value,
    pub bridge_reward: f32,
    pub bridge_terminated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KernelBehaviorObservation {
    #[serde(default)]
    pub executed_tools: Vec<String>,
    pub action_result_count: usize,
    pub routing_receipt_count: usize,
    pub intent_receipt_count: usize,
    pub execution_contract_receipt_count: usize,
    pub workload_receipt_count: usize,
    pub workload_activity_count: usize,
    #[serde(default)]
    pub disallowed_tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArtifactBundle {
    pub artifact_root: String,
    pub bridge_state_path: Option<String>,
    pub kernel_events_path: Option<String>,
    pub json_report_path: Option<String>,
    pub markdown_summary_path: Option<String>,
    pub csv_summary_path: Option<String>,
    #[serde(default)]
    pub screenshot_paths: Vec<String>,
    #[serde(default)]
    pub snapshot_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationSummary {
    pub task_success: bool,
    pub kernel_success: bool,
    pub reward_floor_met: bool,
    pub terminated: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputerUseCaseResult {
    pub case_id: String,
    pub env_id: String,
    pub seed: u64,
    pub mode: ComputerUseMode,
    pub task_set: TaskSet,
    pub utterance: String,
    pub elapsed_ms: u128,
    pub expected_reward_floor: f32,
    pub final_reward: f32,
    pub expected_pass: bool,
    pub terminated: bool,
    pub truncated: bool,
    pub overall_pass: bool,
    #[serde(default)]
    pub tool_steps: Vec<ToolStepRecord>,
    #[serde(default)]
    pub oracle_steps: Vec<OracleStepRecord>,
    #[serde(default)]
    pub kernel_events: Vec<KernelEvent>,
    pub bridge_state: BridgeState,
    pub kernel_behavior: KernelBehaviorObservation,
    pub validation: ValidationSummary,
    pub artifacts: ArtifactBundle,
    pub failure_class: Option<String>,
    pub support_state: BenchmarkSupportState,
    pub primary_gap_class: Option<GapClass>,
    #[serde(default)]
    pub secondary_gap_tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteSummary {
    pub mode: ComputerUseMode,
    pub task_set: TaskSet,
    pub total_cases: usize,
    pub passing_cases: usize,
    pub failing_cases: usize,
    pub task_successes: usize,
    pub kernel_successes: usize,
    pub artifact_root: String,
}

#[derive(Debug, Clone)]
pub struct SuiteConfig {
    pub modes: Vec<ComputerUseMode>,
    pub task_set: TaskSet,
    pub case_filter: Option<Vec<String>>,
    pub max_cases: Option<usize>,
    pub artifact_root: std::path::PathBuf,
    pub retain_artifacts_for_all_runs: bool,
    pub require_browser_display: bool,
    pub bridge_source_dir: Option<std::path::PathBuf>,
    pub python_bin: String,
    pub fail_on_case_failure: bool,
}
