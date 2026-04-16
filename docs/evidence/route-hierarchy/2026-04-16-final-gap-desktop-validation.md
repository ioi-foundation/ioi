# Desktop Parity Validation

- prompts: 6
- passed: 1
- failed: 5
- covered questions: 50, 51, 53, 54, 55, 56, 60, 62, 75

| Prompt | Pass | Route | Output | Notes |
|---|---|---|---|---|
| What's the weather in Boston this weekend? | no | tool_widget_weather | tool_execution | phase: expected 'Complete', got 'Failed' |
| Find three good coffee shops near downtown Portland, show them on a map, and tell me which one opens earliest. | no | tool_widget_places | tool_execution | phase: expected 'Complete', got 'Failed' |
| Compare the Lakers and Celtics this season and tell me which team looks stronger right now. | yes | tool_widget_sports | tool_execution | ok |
| How do I make carbonara for 3 people? | no | tool_widget_recipe | tool_execution | route_family: expected 'research', got 'tool_widget' |
| Draft a professional email to my landlord asking whether the lease renewal paperwork is ready and keep it concise. | no | conversation_mail_connector_single_pass | tool_execution | phase: expected 'Complete', got 'Gate' |
| Plan a Saturday in Portland by comparing the weather, choosing a coffee shop downtown, and suggesting one nearby dinner spot, then turn it into a short itinerary artifact. | no | tool_widget_weather | tool_execution | phase: expected 'Complete', got 'Failed'; output_intent: expected 'artifact', got 'tool_execution'; artifact_output_intent: expected True, got False; presentation_surface: expected 'artifact_surface', got 'weather_widget' |

## Details

### What's the weather in Boston this weekend?

- passed: no
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
- failures:
  - phase: expected 'Complete', got 'Failed'

### Find three good coffee shops near downtown Portland, show them on a map, and tell me which one opens earliest.

- passed: no
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
- failures:
  - phase: expected 'Complete', got 'Failed'

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

- passed: no
- route_family: tool_widget
- selected_route: tool_widget_recipe
- output_intent: tool_execution
- primary_tools: recipe_display_v0
- broad_fallback_tools: n/a
- presentation_surface: recipe_widget
- widget_family: recipe
- source_ranking_sources: direct_answer, conversation_context
- lane_transition_targets: tool_widget
- verification_required_checks: dish_resolved, recipe_surface_rendered
- orchestration_task_count: 3
- orchestration_checkpoint_count: 2
- clarification: n/a
- failures:
  - route_family: expected 'research', got 'tool_widget'

### Draft a professional email to my landlord asking whether the lease renewal paperwork is ready and keep it concise.

- passed: no
- route_family: communication
- selected_route: conversation_mail_connector_single_pass
- output_intent: tool_execution
- primary_tools: connector:mail.primary, provider_route:mail_connector
- broad_fallback_tools: n/a
- presentation_surface: communication_surface
- widget_family: message
- source_ranking_sources: connector, conversation_context
- lane_transition_targets: communication, integrations, conversation
- verification_required_checks: message_channel_resolved, communication_surface_rendered
- orchestration_task_count: 3
- orchestration_checkpoint_count: 2
- clarification: Mail is available here but not connected yet. Should Studio wait for you to connect it, or should I use another source?
- failures:
  - phase: expected 'Complete', got 'Gate'

### Plan a Saturday in Portland by comparing the weather, choosing a coffee shop downtown, and suggesting one nearby dinner spot, then turn it into a short itinerary artifact.

- passed: no
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
- failures:
  - phase: expected 'Complete', got 'Failed'
  - output_intent: expected 'artifact', got 'tool_execution'
  - artifact_output_intent: expected True, got False
  - presentation_surface: expected 'artifact_surface', got 'weather_widget'
