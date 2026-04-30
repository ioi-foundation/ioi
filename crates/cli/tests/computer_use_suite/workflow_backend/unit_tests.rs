#[cfg(test)]
mod tests {
    use super::*;
    use crate::computer_use_suite::types::{AllowedToolProfile, LocalJudge, RecipeId, TaskSet};

    fn field_value<'a>(state: &'a BridgeState, key: &str) -> Option<&'a str> {
        state.info.fields.iter().find_map(|field| {
            if field.key == key {
                Some(field.value.as_str())
            } else {
                None
            }
        })
    }

    fn workflow_case(
        case_id: &str,
        env_id: &str,
        task_set: TaskSet,
        recipe: RecipeId,
    ) -> ComputerUseCase {
        ComputerUseCase {
            id: case_id.to_string(),
            env_id: env_id.to_string(),
            seed: 7,
            task_set,
            max_steps: 12,
            timeout_seconds: 25,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe,
        }
    }

    #[tokio::test]
    async fn workflow_oracle_progresses_to_confirmation() -> Result<()> {
        let mut process = WorkflowBridgeProcess::start().await?;
        let client = process.client();
        let created = client
            .create_session(&workflow_case(
                "workflow_ticket_routing_network_ops",
                "workflow-ticket-routing",
                TaskSet::Workflow,
                RecipeId::WorkflowTicketRouting,
            ))
            .await?;

        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#username", "text": "dispatch.agent" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#password", "text": "dispatch-204" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#sign-in" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_link_selector("T-204") }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#assignee", "label": "Network Ops" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#note", "text": "Escalate fiber outage to on-call" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#submit-update" }),
            )
            .await?;

        let final_state = client.state(&created.session_id).await?;
        assert!(final_state.terminated);
        assert_eq!(final_state.reward, 1.0);
        assert!(final_state
            .info
            .page_url
            .as_deref()
            .is_some_and(|url| url.contains("/confirmation")));

        process.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn workflow_queue_verification_oracle_requires_queue_revisit() -> Result<()> {
        let mut process = WorkflowBridgeProcess::start().await?;
        let client = process.client();
        let created = client
            .create_session(&workflow_case(
                "workflow_queue_verification_network_ops",
                "workflow-queue-verification",
                TaskSet::WorkflowRich,
                RecipeId::WorkflowQueueVerification,
            ))
            .await?;

        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#username", "text": "dispatch.agent" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#password", "text": "dispatch-215" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#sign-in" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#queue-search", "text": "fiber" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#queue-status-filter", "label": "Awaiting Dispatch" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#apply-filters" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_link_selector("T-215") }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#assignee", "label": "Network Ops" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#status", "label": "Escalated" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#note", "text": "Escalate fiber outage to on-call" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#review-update" }),
            )
            .await?;

        let review_state = client.state(&created.session_id).await?;
        assert!(!review_state.terminated);
        assert_eq!(
            field_value(&review_state, "active_ticket_id"),
            Some("T-215")
        );

        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#confirm-update" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#queue-link" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#queue-status-filter", "label": "Escalated" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#apply-filters" }),
            )
            .await?;

        let final_state = client.state(&created.session_id).await?;
        assert!(final_state.terminated);
        assert_eq!(final_state.reward, 1.0);
        assert_eq!(field_value(&final_state, "queue_verified"), Some("true"));
        assert!(final_state
            .info
            .page_url
            .as_deref()
            .is_some_and(|url| url.contains("/queue")));

        process.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn workflow_audit_history_oracle_requires_history_verification() -> Result<()> {
        let mut process = WorkflowBridgeProcess::start().await?;
        let client = process.client();
        let created = client
            .create_session(&workflow_case(
                "workflow_audit_history_network_ops",
                "workflow-audit-history",
                TaskSet::WorkflowAudit,
                RecipeId::WorkflowAuditHistory,
            ))
            .await?;

        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#username", "text": "dispatch.agent" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#password", "text": "dispatch-215" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#sign-in" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#queue-search", "text": "fiber" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#queue-status-filter", "label": "Awaiting Dispatch" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#apply-filters" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_link_selector("T-215") }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#assignee", "label": "Network Ops" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#status", "label": "Escalated" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#note", "text": "Escalate fiber outage to on-call" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#review-update" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#confirm-update" }),
            )
            .await?;

        let confirmation_state = client.state(&created.session_id).await?;
        assert!(!confirmation_state.terminated);
        assert_eq!(
            field_value(&confirmation_state, "history_verified"),
            Some("false")
        );

        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#history-link" }),
            )
            .await?;

        let final_state = client.state(&created.session_id).await?;
        assert!(final_state.terminated);
        assert_eq!(final_state.reward, 1.0);
        assert_eq!(field_value(&final_state, "history_verified"), Some("true"));
        assert_eq!(
            field_value(&final_state, "history_event_exists"),
            Some("true")
        );
        assert!(final_state
            .info
            .page_url
            .as_deref()
            .is_some_and(|url| url.contains("/history")));

        process.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn workflow_mutation_isolation_oracle_requires_target_and_distractor_history_checks(
    ) -> Result<()> {
        let mut process = WorkflowBridgeProcess::start().await?;
        let client = process.client();
        let created = client
            .create_session(&workflow_case(
                "workflow_mutation_isolation_network_ops",
                "workflow-mutation-isolation",
                TaskSet::WorkflowMutation,
                RecipeId::WorkflowMutationIsolation,
            ))
            .await?;

        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#username", "text": "dispatch.agent" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#password", "text": "dispatch-215" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#sign-in" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#queue-search", "text": "fiber" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#queue-status-filter", "label": "Awaiting Dispatch" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#apply-filters" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_link_selector("T-215") }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#assignee", "label": "Network Ops" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#status", "label": "Awaiting Dispatch" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#note", "text": "Escalate fiber outage to on-call" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#review-update" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#confirm-update" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#queue-link" }),
            )
            .await?;

        let queue_state = client.state(&created.session_id).await?;
        assert_eq!(field_value(&queue_state, "queue_verified"), Some("true"));
        assert_eq!(field_value(&queue_state, "history_verified"), Some("false"));
        assert_eq!(
            field_value(&queue_state, "distractor_history_verified"),
            Some("false")
        );

        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_history_link_selector("T-215") }),
            )
            .await?;

        let target_history_state = client.state(&created.session_id).await?;
        assert_eq!(
            field_value(&target_history_state, "history_verified"),
            Some("true")
        );
        assert_eq!(
            field_value(&target_history_state, "distractor_saved_update_exists"),
            Some("false")
        );

        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#queue-link" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_history_link_selector("T-204") }),
            )
            .await?;

        let final_state = client.state(&created.session_id).await?;
        assert!(final_state.terminated);
        assert_eq!(final_state.reward, 1.0);
        assert_eq!(
            field_value(&final_state, "distractor_history_verified"),
            Some("true")
        );
        assert_eq!(
            field_value(&final_state, "distractor_saved_update_exists"),
            Some("false")
        );
        assert!(final_state
            .info
            .page_url
            .as_deref()
            .is_some_and(|url| url.contains("/tickets/T-204/history")));

        process.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn workflow_stale_queue_reorder_oracle_requires_refresh_before_reorder_verification(
    ) -> Result<()> {
        let mut process = WorkflowBridgeProcess::start().await?;
        let client = process.client();
        let created = client
            .create_session(&workflow_case(
                "workflow_stale_queue_reorder_network_ops",
                "workflow-stale-queue-reorder",
                TaskSet::WorkflowReorder,
                RecipeId::WorkflowStaleQueueReorder,
            ))
            .await?;

        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#username", "text": "dispatch.agent" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#password", "text": "dispatch-215" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#sign-in" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#queue-search", "text": "fiber" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#queue-status-filter", "label": "Awaiting Dispatch" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#queue-sort", "label": "Ticket ID" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#apply-filters" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_link_selector("T-215") }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#assignee", "label": "Network Ops" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#status", "label": "Awaiting Dispatch" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#note", "text": "Escalate fiber outage to on-call" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#review-update" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#confirm-update" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#queue-link" }),
            )
            .await?;

        let stale_queue_state = client.state(&created.session_id).await?;
        assert_eq!(
            field_value(&stale_queue_state, "queue_view_fresh"),
            Some("false")
        );
        assert_eq!(
            field_value(&stale_queue_state, "queue_verified"),
            Some("false")
        );
        assert!(!stale_queue_state.terminated);

        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#queue-sort", "label": "Recently Updated" }),
            )
            .await?;

        let still_stale_state = client.state(&created.session_id).await?;
        assert_eq!(
            field_value(&still_stale_state, "queue_view_fresh"),
            Some("false")
        );
        assert_eq!(
            field_value(&still_stale_state, "queue_target_precedes_distractor"),
            Some("false")
        );

        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#apply-filters" }),
            )
            .await?;

        let refreshed_queue_state = client.state(&created.session_id).await?;
        assert_eq!(
            field_value(&refreshed_queue_state, "queue_view_fresh"),
            Some("true")
        );
        assert_eq!(
            field_value(&refreshed_queue_state, "queue_verified"),
            Some("true")
        );
        assert_eq!(
            field_value(&refreshed_queue_state, "queue_target_precedes_distractor"),
            Some("true")
        );
        assert!(!refreshed_queue_state.terminated);

        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_history_link_selector("T-204") }),
            )
            .await?;

        let final_state = client.state(&created.session_id).await?;
        assert!(final_state.terminated);
        assert_eq!(final_state.reward, 1.0);
        assert_eq!(
            field_value(&final_state, "distractor_history_verified"),
            Some("true")
        );
        assert_eq!(
            field_value(&final_state, "distractor_saved_update_exists"),
            Some("false")
        );
        assert!(final_state
            .info
            .page_url
            .as_deref()
            .is_some_and(|url| url.contains("/tickets/T-204/history")));

        process.stop().await;
        Ok(())
    }
}
