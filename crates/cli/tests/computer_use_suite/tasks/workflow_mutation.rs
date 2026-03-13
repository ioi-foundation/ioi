use super::super::types::{AllowedToolProfile, ComputerUseCase, LocalJudge, RecipeId, TaskSet};

pub fn cases() -> Vec<ComputerUseCase> {
    vec![
        ComputerUseCase {
            id: "workflow_mutation_isolation_network_ops".to_string(),
            env_id: "workflow-mutation-isolation".to_string(),
            seed: 71,
            task_set: TaskSet::WorkflowMutation,
            max_steps: 32,
            timeout_seconds: 45,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowMutationIsolation,
        },
        ComputerUseCase {
            id: "workflow_mutation_isolation_billing_review".to_string(),
            env_id: "workflow-mutation-isolation".to_string(),
            seed: 72,
            task_set: TaskSet::WorkflowMutation,
            max_steps: 32,
            timeout_seconds: 45,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowMutationIsolation,
        },
    ]
}
