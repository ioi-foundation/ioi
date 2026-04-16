# Desktop Parity Validation

- prompts: 2
- passed: 2
- failed: 0
- covered questions: 50, 57, 60

| Prompt | Pass | Route | Output | Notes |
|---|---|---|---|---|
| What's the weather in Boston this weekend? | yes | tool_widget_weather | tool_execution | ok |
| How about tomorrow instead? | yes | tool_widget_weather | tool_execution | ok |

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

### How about tomorrow instead?

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
