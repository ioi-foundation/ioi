use super::super::types::{AllowedToolProfile, ComputerUseCase, LocalJudge, RecipeId, TaskSet};

pub fn cases() -> Vec<ComputerUseCase> {
    vec![
        ComputerUseCase {
            id: "workflow_audit_history_network_ops".to_string(),
            env_id: "workflow-audit-history".to_string(),
            seed: 61,
            task_set: TaskSet::WorkflowAudit,
            max_steps: 24,
            timeout_seconds: 40,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowAuditHistory,
        },
        ComputerUseCase {
            id: "workflow_audit_history_billing_review".to_string(),
            env_id: "workflow-audit-history".to_string(),
            seed: 62,
            task_set: TaskSet::WorkflowAudit,
            max_steps: 24,
            timeout_seconds: 40,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowAuditHistory,
        },
    ]
}
