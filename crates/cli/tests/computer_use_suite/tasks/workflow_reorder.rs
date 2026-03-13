use super::super::types::{AllowedToolProfile, ComputerUseCase, LocalJudge, RecipeId, TaskSet};

pub fn cases() -> Vec<ComputerUseCase> {
    vec![
        ComputerUseCase {
            id: "workflow_stale_queue_reorder_network_ops".to_string(),
            env_id: "workflow-stale-queue-reorder".to_string(),
            seed: 81,
            task_set: TaskSet::WorkflowReorder,
            max_steps: 34,
            timeout_seconds: 50,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowStaleQueueReorder,
        },
        ComputerUseCase {
            id: "workflow_stale_queue_reorder_billing_review".to_string(),
            env_id: "workflow-stale-queue-reorder".to_string(),
            seed: 82,
            task_set: TaskSet::WorkflowReorder,
            max_steps: 34,
            timeout_seconds: 50,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowStaleQueueReorder,
        },
    ]
}
