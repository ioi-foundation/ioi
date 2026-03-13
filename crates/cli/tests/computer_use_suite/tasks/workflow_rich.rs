use super::super::types::{AllowedToolProfile, ComputerUseCase, LocalJudge, RecipeId, TaskSet};

pub fn cases() -> Vec<ComputerUseCase> {
    vec![
        ComputerUseCase {
            id: "workflow_queue_verification_network_ops".to_string(),
            env_id: "workflow-queue-verification".to_string(),
            seed: 51,
            task_set: TaskSet::WorkflowRich,
            max_steps: 18,
            timeout_seconds: 35,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowQueueVerification,
        },
        ComputerUseCase {
            id: "workflow_queue_verification_billing_review".to_string(),
            env_id: "workflow-queue-verification".to_string(),
            seed: 52,
            task_set: TaskSet::WorkflowRich,
            max_steps: 18,
            timeout_seconds: 35,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowQueueVerification,
        },
    ]
}
