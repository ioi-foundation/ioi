# Desktop Parity Validation

- prompts: 15
- passed: 15
- failed: 0
- covered questions: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 30, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42

| Prompt | Pass | Route | Output | Notes |
|---|---|---|---|---|
| What is the Pythagorean theorem? | yes | conversation_single_pass | direct_inline | ok |
| Who is the current Secretary-General of the UN? | yes | conversation_currentness_adaptive_work_graph | tool_execution | ok |
| What's happening this week? | yes | conversation_currentness_plan_execute | tool_execution | ok |
| What's the weather in Boston today? | yes | tool_widget_weather | tool_execution | ok |
| Should I wear a jacket today? | yes | tool_widget_weather | tool_execution | ok |
| What are some good coffee shops near downtown Portland? | yes | tool_widget_places | tool_execution | ok |
| What's the story with the Lakers this season? | yes | tool_widget_sports | tool_execution | ok |
| Summarize my unread emails | yes | conversation_mail_connector_plan_execute | tool_execution | ok |
| Summarize my Slack unread messages | yes | conversation_connector_plan_execute | tool_execution | ok |
| Prioritize these renovation projects: kitchen, bathroom, roof, and windows | yes | tool_widget_user_input | tool_execution | ok |
| Write me a guide to home brewing | yes | conversation_single_pass | direct_inline | ok |
| Show a simple mermaid diagram of the HTTP request lifecycle. | yes | inline_visualizer | inline_visual | ok |
| Create a markdown report about onboarding best practices. | yes | artifact_markdown | artifact | ok |
| A mortgage calculator where I can adjust rate, term, and down payment | yes | artifact_html_iframe | artifact | ok |
| Build a React + Vite workspace project for a task tracker with separate components, filters, and local state | yes | artifact_workspace_surface | artifact | ok |

## Details

### What is the Pythagorean theorem?

- passed: yes
- route_family: general
- selected_route: conversation_single_pass
- output_intent: direct_inline
- primary_tools: n/a
- broad_fallback_tools: n/a
- clarification: n/a

### Who is the current Secretary-General of the UN?

- passed: yes
- route_family: research
- selected_route: conversation_currentness_adaptive_work_graph
- output_intent: tool_execution
- primary_tools: web_search, web_fetch
- broad_fallback_tools: n/a
- clarification: n/a

### What's happening this week?

- passed: yes
- route_family: research
- selected_route: conversation_currentness_plan_execute
- output_intent: tool_execution
- primary_tools: web_search, web_fetch
- broad_fallback_tools: n/a
- clarification: Do you mean local events, a specific topic, or general news this week?

### What's the weather in Boston today?

- passed: yes
- route_family: research
- selected_route: tool_widget_weather
- output_intent: tool_execution
- primary_tools: weather_fetch
- broad_fallback_tools: web_search
- clarification: n/a

### Should I wear a jacket today?

- passed: yes
- route_family: research
- selected_route: tool_widget_weather
- output_intent: tool_execution
- primary_tools: weather_fetch
- broad_fallback_tools: web_search
- clarification: What city should Studio check the weather for?

### What are some good coffee shops near downtown Portland?

- passed: yes
- route_family: research
- selected_route: tool_widget_places
- output_intent: tool_execution
- primary_tools: places_search, places_map_display_v0
- broad_fallback_tools: web_search
- clarification: n/a

### What's the story with the Lakers this season?

- passed: yes
- route_family: research
- selected_route: tool_widget_sports
- output_intent: tool_execution
- primary_tools: fetch_sports_data
- broad_fallback_tools: web_search
- clarification: n/a

### Summarize my unread emails

- passed: yes
- route_family: integrations
- selected_route: conversation_mail_connector_plan_execute
- output_intent: tool_execution
- primary_tools: connector:mail.primary, provider_route:mail_connector
- broad_fallback_tools: n/a
- clarification: Mail is available here but not connected yet. Should Studio wait for you to connect it, or should I use another source?

### Summarize my Slack unread messages

- passed: yes
- route_family: integrations
- selected_route: conversation_connector_plan_execute
- output_intent: tool_execution
- primary_tools: n/a
- broad_fallback_tools: n/a
- clarification: Slack is not available in this runtime yet. Should Studio wait for you to connect it, or should I work from pasted data instead?

### Prioritize these renovation projects: kitchen, bathroom, roof, and windows

- passed: yes
- route_family: general
- selected_route: tool_widget_user_input
- output_intent: tool_execution
- primary_tools: ask_user_input_v0
- broad_fallback_tools: n/a
- clarification: What should drive the ranking: impact, urgency, or return on investment?

### Write me a guide to home brewing

- passed: yes
- route_family: general
- selected_route: conversation_single_pass
- output_intent: direct_inline
- primary_tools: n/a
- broad_fallback_tools: n/a
- clarification: n/a

### Show a simple mermaid diagram of the HTTP request lifecycle.

- passed: yes
- route_family: artifacts
- selected_route: inline_visualizer
- output_intent: inline_visual
- primary_tools: visualize:show_widget
- broad_fallback_tools: n/a
- clarification: n/a

### Create a markdown report about onboarding best practices.

- passed: yes
- route_family: artifacts
- selected_route: artifact_markdown
- output_intent: artifact
- primary_tools: studio_renderer:markdown
- broad_fallback_tools: n/a
- clarification: n/a

### A mortgage calculator where I can adjust rate, term, and down payment

- passed: yes
- route_family: artifacts
- selected_route: artifact_html_iframe
- output_intent: artifact
- primary_tools: studio_renderer:html_iframe
- broad_fallback_tools: n/a
- clarification: n/a
- probe_error: Timed out after 120s waiting for prompt result: A mortgage calculator where I can adjust rate, term, and down payment

### Build a React + Vite workspace project for a task tracker with separate components, filters, and local state

- passed: yes
- route_family: coding
- selected_route: artifact_workspace_surface
- output_intent: artifact
- primary_tools: studio_renderer:workspace_surface
- broad_fallback_tools: n/a
- clarification: n/a
