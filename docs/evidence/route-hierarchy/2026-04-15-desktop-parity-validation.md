# Desktop Parity Validation

Date: 2026-04-15

Execution path:

- `AUTOPILOT_LOCAL_GPU_DEV=1 npm run dev:desktop`
- retained via `apps/autopilot/scripts/dev_start_intent_probe.py`

Retained live manifests:

- `docs/evidence/route-hierarchy/live-dev-start-targeted-recheck/2026-04-15T22-51-05Z/manifest.json`
- `docs/evidence/route-hierarchy/live-dev-start-clarify-mortgage-recheck/2026-04-15T23-09-33Z/manifest.json`
- `docs/evidence/route-hierarchy/live-dev-start-coverage-completion/2026-04-15T23-16-25Z/manifest.json`
- `docs/evidence/route-hierarchy/live-dev-start-brazil-cloudsync-recheck/2026-04-15T23-28-35Z/manifest.json`

Coverage:

- question ids covered live: `1-43`
- verdict: every Claude discovery question is now backed by at least one retained live desktop prompt in the real app lane
- supporting tests still exist for regression hardening, but they are no longer required to claim question coverage

Representative prompt outcomes:

| Prompt | Phase | Route | Outcome |
|---|---|---|---|
| `What is the Pythagorean theorem?` | `Complete` | `conversation_single_pass` | direct inline answer |
| `Who is the current president of Brazil?` | `Gate` | `conversation_currentness_adaptive_work_graph` | currentness route with approval state |
| `What's happening this week?` | `Gate` | `conversation_currentness_plan_execute` | structured clarification for ambiguous scope |
| `What's the weather in Boston today?` | `Complete` | `tool_widget_weather` | weather surface selected |
| `Should I wear a jacket today?` | `Gate` | `tool_widget_weather` | weather clarification asks for city |
| `How do I make carbonara for 3 people?` | `Complete` | `tool_widget_recipe` | recipe surface selected |
| `What are some good coffee shops near downtown Portland?` | `Complete` | `tool_widget_places` | places surface selected |
| `What's the story with the Lakers this season?` | `Complete` | `tool_widget_sports` | sports surface selected |
| `Prioritize these renovation projects: kitchen, bathroom, roof, and windows` | `Gate` | `tool_widget_user_input` | user-input clarification selected |
| `Summarize my unread emails` | `Gate` | `conversation_mail_connector_single_pass` | connector-first mail route with auth clarification |
| `What npm script launches the desktop app in this repo?` | `Complete` | `conversation_workspace_grounded_single_pass` | workspace-grounded tool execution |
| `Build a React + Vite workspace project for a task tracker with separate components, filters, and local state` | `Complete` | `artifact_workspace_surface` | workspace artifact with preview verification |
| `A mortgage calculator where I can adjust rate, term, and down payment` | `Complete` | `artifact_html_iframe` | interactive HTML artifact |
| `Build a beautiful landing page for a SaaS product called CloudSync...` | `Complete` | `artifact_html_iframe` | frontend artifact completion |
| `Create a Word document... quarterly performance` | `Complete` | `artifact_download_card` | real `docx` export lane |
| `Create a budget spreadsheet...` | `Complete` | `artifact_download_card` | real `xlsx` export lane |
| `Create a PowerPoint deck for the quarterly launch review` | `Complete` | `artifact_download_card` | real `pptx` export lane |
| `Create an ODT document... quarterly performance` | `Complete` | `artifact_download_card` | real `odt` export lane |

Behavioral conclusions:

- narrow specialized routes now beat broad inline fallbacks in the live desktop lane
- clarification and approval states now surface as `Gate` instead of misleading `Running`
- explicit Office/OpenDocument export asks now stay on the artifact download lane instead of drifting into PDF or connector hijacks
- connector-first and workspace-grounded behavior are both visible in route receipts and in the real app UI flow
- artifact materialization for HTML, workspace, and downloadable exports is proven in retained live runs rather than inferred from tests
