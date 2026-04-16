# Desktop Parity Validation

- prompts: 6
- passed: 6
- failed: 0
- covered questions: 50, 51, 53, 54, 55, 56, 60, 62, 75

| Prompt | Pass | Route | Output | Notes |
|---|---|---|---|---|
| What's the weather in Boston this weekend? | yes | tool_widget_weather | tool_execution | ok |
| Find three good coffee shops near downtown Portland, show them on a map, and tell me which one opens earliest. | yes | tool_widget_places | tool_execution | ok |
| Compare the Lakers and Celtics this season and tell me which team looks stronger right now. | yes | tool_widget_sports | tool_execution | ok |
| How do I make carbonara for 3 people? | yes | tool_widget_recipe | tool_execution | ok |
| Draft a professional email to my landlord asking whether the lease renewal paperwork is ready and keep it concise. | yes | communication_single_pass | tool_execution | ok |
| Plan a Saturday in Portland by comparing the weather, choosing a coffee shop downtown, and suggesting one nearby dinner spot, then turn it into a short itinerary artifact. | yes | artifact_markdown | artifact | ok |

## Details

### What's the weather in Boston this weekend?

- passed: yes
- route_family: research
- selected_route: tool_widget_weather
- output_intent: tool_execution
- primary_tools: weather_fetch
- broad_fallback_tools: web_search
- presentation_surface: weather_widget
- widget_family: weather
- source_ranking_sources: specialized_tool, conversation_context, web_search
- lane_transition_targets: research, tool_widget, conversation
- verification_required_checks: location_scope_resolved, current_conditions_available, weather_surface_rendered
- orchestration_task_count: 3
- orchestration_checkpoint_count: 2
- clarification: n/a

### Find three good coffee shops near downtown Portland, show them on a map, and tell me which one opens earliest.

- passed: yes
- route_family: research
- selected_route: tool_widget_places
- output_intent: tool_execution
- primary_tools: places_search, places_map_display_v0
- broad_fallback_tools: web_search
- presentation_surface: places_widget
- widget_family: places
- source_ranking_sources: specialized_tool, conversation_context, web_search
- lane_transition_targets: research, tool_widget, conversation
- verification_required_checks: place_category_resolved, location_scope_resolved, places_surface_rendered
- orchestration_task_count: 3
- orchestration_checkpoint_count: 2
- clarification: n/a

### Compare the Lakers and Celtics this season and tell me which team looks stronger right now.

- passed: yes
- route_family: research
- selected_route: tool_widget_sports
- output_intent: tool_execution
- primary_tools: fetch_sports_data
- broad_fallback_tools: web_search
- presentation_surface: sports_widget
- widget_family: sports
- source_ranking_sources: specialized_tool, conversation_context, web_search
- lane_transition_targets: research, tool_widget, conversation
- verification_required_checks: sports_target_resolved, latest_team_data_available, sports_surface_rendered
- orchestration_task_count: 3
- orchestration_checkpoint_count: 2
- clarification: n/a

### How do I make carbonara for 3 people?

- passed: yes
- route_family: research
- selected_route: tool_widget_recipe
- output_intent: tool_execution
- primary_tools: recipe_display_v0
- broad_fallback_tools: n/a
- presentation_surface: recipe_widget
- widget_family: recipe
- source_ranking_sources: specialized_tool, conversation_context, web_search
- lane_transition_targets: research, tool_widget, conversation
- verification_required_checks: dish_resolved, recipe_surface_rendered
- orchestration_task_count: 3
- orchestration_checkpoint_count: 2
- clarification: n/a

### Draft a professional email to my landlord asking whether the lease renewal paperwork is ready and keep it concise.

- passed: yes
- route_family: communication
- selected_route: communication_single_pass
- output_intent: tool_execution
- primary_tools: message_compose_v1
- broad_fallback_tools: n/a
- presentation_surface: communication_surface
- widget_family: message
- source_ranking_sources: direct_answer, conversation_context
- lane_transition_targets: communication
- verification_required_checks: message_channel_resolved, communication_surface_rendered
- orchestration_task_count: 3
- orchestration_checkpoint_count: 2
- clarification: n/a

### Plan a Saturday in Portland by comparing the weather, choosing a coffee shop downtown, and suggesting one nearby dinner spot, then turn it into a short itinerary artifact.

- passed: yes
- route_family: artifacts
- selected_route: artifact_markdown
- output_intent: artifact
- primary_tools: studio_renderer:markdown
- broad_fallback_tools: n/a
- presentation_surface: artifact_surface
- widget_family: weather
- source_ranking_sources: specialized_tool, conversation_context, web_search
- lane_transition_targets: artifact, research, tool_widget
- verification_required_checks: artifact_contract_recorded, artifact_surface_rendered
- orchestration_task_count: 3
- orchestration_checkpoint_count: 2
- clarification: n/a
