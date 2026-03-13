use super::super::types::{AllowedToolProfile, ComputerUseCase, LocalJudge, RecipeId, TaskSet};

pub fn cases() -> Vec<ComputerUseCase> {
    vec![
        ComputerUseCase {
            id: "workflow_ticket_routing_network_ops".to_string(),
            env_id: "workflow-ticket-routing".to_string(),
            seed: 41,
            task_set: TaskSet::Workflow,
            max_steps: 12,
            timeout_seconds: 25,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowTicketRouting,
        },
        ComputerUseCase {
            id: "workflow_ticket_routing_billing_review".to_string(),
            env_id: "workflow-ticket-routing".to_string(),
            seed: 42,
            task_set: TaskSet::Workflow,
            max_steps: 12,
            timeout_seconds: 25,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowTicketRouting,
        },
    ]
}
