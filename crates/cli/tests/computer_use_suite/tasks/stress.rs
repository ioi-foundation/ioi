use super::super::types::{
    AllowedToolProfile, ComputerUseCase, LocalJudge, RecipeId, TaskSet,
};

pub fn cases() -> Vec<ComputerUseCase> {
    vec![
        ComputerUseCase {
            id: "miniwob_click_collapsible_2_stress",
            env_id: "click-collapsible-2",
            seed: 301,
            task_set: TaskSet::Stress,
            max_steps: 16,
            timeout_seconds: 25,
            allowed_tool_profile: AllowedToolProfile::BrowserCore,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::MiniwobReward,
            recipe: RecipeId::ClickCollapsible2,
        },
        ComputerUseCase {
            id: "miniwob_search_engine_stress",
            env_id: "search-engine",
            seed: 302,
            task_set: TaskSet::Stress,
            max_steps: 18,
            timeout_seconds: 25,
            allowed_tool_profile: AllowedToolProfile::BrowserCore,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::MiniwobReward,
            recipe: RecipeId::SearchEngine,
        },
    ]
}
